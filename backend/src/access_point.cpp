#include "access_point.h"
#include "decrypter.h"
#include "log_sink.h"
#include "net_card_manager.h"
#include "recording.h"
#include <algorithm>
#include <optional>
#include <semaphore.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <tins/ethernetII.h>
#include <tins/exceptions.h>
#include <tins/packet.h>
#include <tins/tins.h>

using NetworkSecurity = yarilo::AccessPoint::NetworkSecurity;
using DecryptionState = yarilo::AccessPoint::DecryptionState;
using Modulation = yarilo::AccessPoint::Modulation;
using ChannelWidth = yarilo::AccessPoint::ChannelWidth;
using wifi_standard_info = yarilo::AccessPoint::wifi_standard_info;
using recording_info = yarilo::Recording::info;

namespace yarilo {

AccessPoint::AccessPoint(const MACAddress &bssid, const SSID &ssid,
                         const std::vector<wifi_chan_info> &wifi_channels,
                         Database &db)
    : ssid(ssid), bssid(bssid), decrypter(bssid, ssid), db(db),
      wifi_channels(wifi_channels) {
  logger = log::get_logger(ssid);
  logger->debug("Station found on channel {} with addr {}",
                NetCardManager::freq_to_chan(wifi_channels[0].freq),
                bssid.to_string());
};

void AccessPoint::handle_pkt(Tins::Packet *pkt) {
  count++;
  if (pkt->pdu()->find_pdu<Tins::Dot11Data>())
    handle_data(pkt);
  else if (pkt->pdu()->find_pdu<Tins::Dot11ManagementFrame>())
    handle_management(pkt);
};

SSID AccessPoint::get_ssid() const { return ssid; }

MACAddress AccessPoint::get_bssid() const { return bssid; }

std::vector<wifi_chan_info> AccessPoint::get_wifi_channels() const {
  return wifi_channels;
}

std::vector<wifi_standard_info> AccessPoint::standards_supported() const {
  return wifi_stds_supported;
}

std::shared_ptr<PacketChannel> AccessPoint::get_decrypted_channel() {
  auto new_chan = std::make_shared<PacketChannel>();

  for (const auto &pkt : captured_packets) {
    auto data = pkt->pdu()->find_pdu<Tins::Dot11Data>();
    auto eapol = pkt->pdu()->find_pdu<Tins::RSNEAPOL>();
    if (!data || !data->find_pdu<Tins::SNAP>() || eapol)
      continue;
    new_chan->send(Recording::make_eth_packet(pkt));
  }

  converted_channels.push_back(new_chan);
  return new_chan;
}

void AccessPoint::close_all_channels() {
  for (auto &channel : converted_channels)
    channel->close();
}

DecryptionState AccessPoint::add_password(const std::string &psk) {
  if (decrypter.has_working_password())
    return DecryptionState::ALREADY_DECRYPTED;

  if (!decrypter.can_generate_keys())
    return DecryptionState::NOT_ENOUGH_DATA;

  decrypter.add_password(psk);
  if (!decrypter.has_working_password())
    return DecryptionState::INCORRECT_PASSWORD;

  decrypted_pkt_count = 0;
  for (auto &pkt : captured_packets) {
    auto data = pkt->pdu()->find_pdu<Tins::Dot11Data>();
    if (!data || !data->find_pdu<Tins::SNAP>())
      continue;

    decrypted_pkt_count++;
    update_client_metadata(*pkt);
    for (auto &chan : converted_channels)
      if (!chan->is_closed())
        chan->send(Recording::make_eth_packet(pkt));
  }

  return DecryptionState::DECRYPTED;
};

bool AccessPoint::send_deauth(const Tins::NetworkInterface &iface,
                              const MACAddress &addr) {
  if (!radio_length)
    return false;

  if (clients_security.count(addr) && clients_security[addr].pmf) {
    logger->error("Deauth request for {} denied, (PMF enforced)",
                  addr.to_string());
    return false;
  }

  if (pmf_required) {
    logger->error("Deauth request for {} denied, (PMF enforced)",
                  addr.to_string());
    return false;
  }

  if (pmf_supported)
    logger->warn(
        "Deauth may not work, protected management frames support detected");

  Tins::Dot11Deauthentication deauth;
  deauth.addr1(addr);
  deauth.addr2(bssid);
  deauth.addr3(bssid);
  deauth.reason_code(0x0008);

  Tins::RadioTap radio;
  radio.length(radio_length);
  radio.channel(radio_channel_freq, radio_channel_type);
  radio.antenna(radio_antenna);
  radio.inner_pdu(deauth);

  Tins::PacketSender sender(iface);
  sender.send(radio);
  return true;
}

bool AccessPoint::has_working_password() const {
  return decrypter.has_working_password();
}

std::vector<NetworkSecurity> AccessPoint::security_supported() const {
  return security_modes;
}

bool AccessPoint::unicast_decryption_supported() const {
  return std::find(security_modes.begin(), security_modes.end(),
                   NetworkSecurity::WPA2_Personal) != security_modes.end();
}

bool AccessPoint::group_decryption_supported() const {
  bool wpa2psk =
      std::find(security_modes.begin(), security_modes.end(),
                NetworkSecurity::WPA2_Personal) != security_modes.end();
  return wpa2psk && uses_ccmp;
}

bool AccessPoint::client_decryption_supported(const MACAddress &client) {
  if (!unicast_decryption_supported())
    return false;
  if (!clients_security.count(client))
    return false;
  return clients_security[client].pairwise_cipher ==
             Tins::RSNInformation::TKIP ||
         clients_security[client].pairwise_cipher == Tins::RSNInformation::CCMP;
}

bool AccessPoint::protected_management_supported() const {
  return pmf_supported;
}

bool AccessPoint::protected_management_required() const { return pmf_required; }

bool AccessPoint::protected_management(const MACAddress &client) {
  if (!clients_security.count(client))
    return false;
  return clients_security[client].pmf;
}

WPA2Decrypter &AccessPoint::get_decrypter() { return decrypter; }

uint32_t AccessPoint::raw_packet_count() const {
  return captured_packets.size();
}

uint32_t AccessPoint::decrypted_packet_count() const {
  return decrypted_pkt_count;
}

std::optional<recording_info>
AccessPoint::save_traffic(const std::filesystem::path &dir_path,
                          const std::string &name) {
  logger->debug("Creating a raw recording with {} packets",
                captured_packets.size());
  return Recording(dir_path, true, db, name).dump(&captured_packets);
}

std::optional<recording_info>
AccessPoint::save_decrypted_traffic(const std::filesystem::path &dir_path,
                                    const std::string &name) {
  std::shared_ptr<PacketChannel> channel = get_decrypted_channel();
  if (channel->is_closed())
    return std::nullopt;

  logger->debug("Creating a decrypted recording with {} packets",
                channel->len());
  return Recording(dir_path, false, db, name).dump(std::move(channel));
}

void AccessPoint::handle_data(Tins::Packet *pkt) {
  auto pdu = pkt->pdu();
  auto data = pdu->rfind_pdu<Tins::Dot11Data>();
  captured_packets.push_back(pkt);

  // Note some things about the radiotap header to be able to deauth our
  // clients
  auto radio = pdu->find_pdu<Tins::RadioTap>();
  if (radio) {
    radio_length = radio->length();
    radio_channel_freq = radio->channel_freq();
    radio_channel_type = radio->channel_type();
    radio_antenna = radio->antenna();
  }

  bool sent_by_client =
      (data.dst_addr() == this->bssid || !data.dst_addr().is_unicast());
  Tins::HWAddress<6> client_addr =
      (sent_by_client) ? data.src_addr() : data.dst_addr();
  if (!clients.count(client_addr)) {
    client_info info{};
    info.hwaddr = client_addr.to_string();
    if (auto radio = pkt->pdu()->find_pdu<Tins::RadioTap>()) {
      if (radio->present() & Tins::RadioTap::DBM_SIGNAL)
        info.rssi = radio->dbm_signal();

      if (radio->present() & Tins::RadioTap::DBM_NOISE)
        info.noise = radio->dbm_noise();

      if (radio->present() & Tins::RadioTap::DBM_SIGNAL &&
          radio->present() & Tins::RadioTap::DBM_NOISE)
        info.snr = info.rssi - info.noise;
    }

    clients[client_addr] = info;
  }

  if (sent_by_client) {
    clients[client_addr].sent_total++;
    if (client_addr.is_unicast())
      clients[client_addr].sent_unicast++;
  } else
    clients[client_addr].received++;

  bool decrypted = decrypter.decrypt(pkt);
  if (!decrypted)
    return;
  if (pkt->pdu()->find_pdu<Tins::SNAP>())
    decrypted_pkt_count++;
  update_client_metadata(*pkt);

  // Send the decrypted packet to every open channel
  for (auto &chan : converted_channels)
    if (!chan->is_closed())
      chan->send(Recording::make_eth_packet(pkt));
}

void AccessPoint::handle_management(Tins::Packet *pkt) {
  if (count == 1)
    captured_packets.push_back(
        pkt); // First pkt is always network ID (Beacon/ProbeResp)

  auto mgmt = pkt->pdu()->rfind_pdu<Tins::Dot11ManagementFrame>();
  if (mgmt.wep())
    pmf_supported = true;

  if (pkt->pdu()->find_pdu<Tins::Dot11ProbeResponse>() ||
      pkt->pdu()->find_pdu<Tins::Dot11Beacon>())
    wifi_channels = detect_channel_info(mgmt);

  if (!capabilities_detected &&
      (pkt->pdu()->find_pdu<Tins::Dot11ProbeResponse>() ||
       pkt->pdu()->find_pdu<Tins::Dot11Beacon>())) {
    security_modes = detect_security_modes(mgmt);
    uses_ccmp = is_ccmp(mgmt);
    pmf_supported = check_pmf_capable(mgmt);
    pmf_required = check_pmf_required(mgmt);
    wifi_stds_supported = detect_wifi_capabilities(mgmt);
    capabilities_detected = true;
  }

  auto assoc = pkt->pdu()->find_pdu<Tins::Dot11AssocRequest>();
  auto reassoc = pkt->pdu()->find_pdu<Tins::Dot11ReAssocRequest>();
  if (assoc || reassoc) {
    MACAddress client = mgmt.addr2();
    NetworkSecurity security = detect_security_modes(mgmt)[0];

    bool has_rsn_info = mgmt.search_option(Tins::Dot11::OptionTypes::RSN);
    if (!has_rsn_info) {
      client_security new_client_info{.security = security,
                                      .pmf = pmf_required};
      switch (security) {
      case NetworkSecurity::WPA:
        new_client_info.pairwise_cipher = Tins::RSNInformation::TKIP;
        break;
      case NetworkSecurity::WEP:
        new_client_info.pairwise_cipher = Tins::RSNInformation::WEP_40;
        break;
      default:
        new_client_info.pairwise_cipher = std::nullopt;
      }

      clients_security[client] = new_client_info;
      return;
    }

    Tins::RSNInformation rsn_info = mgmt.rsn_information();
    clients_security[client] = {
        .security = security,
        .is_ccmp = is_ccmp(mgmt),
        .pmf = pmf_required,
        .pairwise_cipher =
            rsn_info.pairwise_cyphers()[0], // Here we know that a cipher
                                            // suite has been selected by the
                                            // client from the available ones
    };

    return;
  };

  MACAddress client_addr;
  if (!mgmt.to_ds() && mgmt.from_ds())
    client_addr = mgmt.addr1();
  else if (mgmt.to_ds() && !mgmt.from_ds())
    client_addr = mgmt.addr2();
  else
    return;

  if (!clients.count(client_addr)) {
    client_info info{};
    info.hwaddr = client_addr.to_string();
    if (auto radio = pkt->pdu()->find_pdu<Tins::RadioTap>()) {
      if (radio->present() & Tins::RadioTap::DBM_SIGNAL)
        info.rssi = radio->dbm_signal();

      if (radio->present() & Tins::RadioTap::DBM_NOISE)
        info.noise = radio->dbm_noise();

      if (radio->present() & Tins::RadioTap::DBM_SIGNAL &&
          radio->present() & Tins::RadioTap::DBM_NOISE)
        info.snr = info.rssi - info.noise;
    }

    clients[client_addr] = info;
  }

  if (clients_security.count(client_addr) && mgmt.wep())
    clients_security[client_addr].pmf = true;
}

void AccessPoint::update_client_metadata(const Tins::Packet &pkt) {
  auto data = pkt.pdu()->find_pdu<Tins::Dot11Data>();
  auto snap = pkt.pdu()->find_pdu<Tins::SNAP>();
  if (!data || !snap)
    return;

  bool sent_by_client =
      (data->dst_addr() == bssid || !data->dst_addr().is_unicast());
  auto client_addr = (sent_by_client) ? data->src_addr() : data->dst_addr();
  if (auto udp = pkt.pdu()->find_pdu<Tins::UDP>()) {
    try {
      auto dhcp = udp->find_pdu<Tins::RawPDU>()
                      ->clone()
                      ->to<Tins::DHCP>(); // Clone so it doesn't get cleaned up
                                          // at the end of scope
      clients[client_addr].hostname = dhcp.hostname();
    } catch (const Tins::malformed_packet &exc) {
    } catch (const Tins::option_not_found &exc) {
    }
  }

  auto ip = pkt.pdu()->find_pdu<Tins::IP>();
  if (ip && clients[client_addr].ipv4.length() < 9)
    if (sent_by_client) {
      clients[client_addr].ipv4 = ip->src_addr().to_string();
    } else {
      clients[client_addr].ipv4 = ip->dst_addr().to_string();
    }

  auto ipv6 = pkt.pdu()->find_pdu<Tins::IPv6>();
  if (ipv6 && clients[client_addr].ipv6.length() < 6)
    if (sent_by_client) {
      clients[client_addr].ipv6 = ipv6->src_addr().to_string();
    } else {
      clients[client_addr].ipv6 = ipv6->dst_addr().to_string();
    }
}

std::vector<NetworkSecurity>
AccessPoint::detect_security_modes(const Tins::Dot11ManagementFrame &mgmt) {
  std::vector<NetworkSecurity> security_modes;

  for (const auto &opt : mgmt.options()) {
    if (opt.option() != 221) // Vendor specific
      continue;
    const std::vector<uint8_t> wpa_1_tag_data{
        0x00, 0x50, 0xf2,
        0x01, 0x01, 0x00}; // Microsoft Corp OUI Type: 1, WPA Version: 1
    if (std::equal(opt.data_ptr(), opt.data_ptr() + wpa_1_tag_data.size(),
                   wpa_1_tag_data.begin())) {
      security_modes.push_back(NetworkSecurity::WPA);
      break;
    }
  }

  bool has_rsn_info = mgmt.search_option(Tins::Dot11::OptionTypes::RSN);
  if (!has_rsn_info) {
    if (security_modes.size())
      return security_modes; // Only WPA

    Tins::Dot11ManagementFrame::capability_information cap;
    if (auto beacon = mgmt.find_pdu<Tins::Dot11Beacon>())
      cap = beacon->capabilities();
    if (auto probe_resp = mgmt.find_pdu<Tins::Dot11ProbeResponse>())
      cap = probe_resp->capabilities();
    security_modes.push_back((cap.privacy()) ? NetworkSecurity::WEP
                                             : NetworkSecurity::OPEN);
    return security_modes;
  }

  Tins::RSNInformation rsn_info = mgmt.rsn_information();
  std::vector<Tins::RSNInformation::AKMSuites> akm_ciphers =
      rsn_info.akm_cyphers();

  bool uses_sae_ft =
      std::find(akm_ciphers.begin(), akm_ciphers.end(),
                Tins::RSNInformation::SAE_FT) != akm_ciphers.end();
  bool uses_sae_sha256 =
      std::find(akm_ciphers.begin(), akm_ciphers.end(),
                Tins::RSNInformation::SAE_SHA256) != akm_ciphers.end();
  if (uses_sae_ft || uses_sae_sha256)
    security_modes.push_back(NetworkSecurity::WPA3_Personal);

  bool uses_psk = std::find(akm_ciphers.begin(), akm_ciphers.end(),
                            Tins::RSNInformation::PSK) != akm_ciphers.end();
  bool uses_psk_ft =
      std::find(akm_ciphers.begin(), akm_ciphers.end(),
                Tins::RSNInformation::PSK_FT) != akm_ciphers.end();
  bool uses_psk_sha256 =
      std::find(akm_ciphers.begin(), akm_ciphers.end(),
                Tins::RSNInformation::PSK_SHA256) != akm_ciphers.end();
  if (uses_psk || uses_psk_ft || uses_psk_sha256)
    security_modes.push_back(NetworkSecurity::WPA2_Personal);

  bool uses_eap_sha1 =
      std::find(akm_ciphers.begin(), akm_ciphers.end(),
                Tins::RSNInformation::EAP) != akm_ciphers.end();
  if (uses_eap_sha1)
    security_modes.push_back(NetworkSecurity::WPA2_Enterprise);

  bool uses_eap_sha256 =
      std::find(akm_ciphers.begin(), akm_ciphers.end(),
                Tins::RSNInformation::EAP_SHA256) != akm_ciphers.end();
  if (uses_eap_sha256)
    security_modes.push_back(NetworkSecurity::WPA3_Enterprise);

  return security_modes;
}

std::vector<wifi_standard_info>
AccessPoint::detect_wifi_capabilities(const Tins::Dot11ManagementFrame &mgmt) {
  std::vector<float> supported_rates = mgmt.supported_rates();
  if (mgmt.search_option(Tins::Dot11::OptionTypes::EXT_SUPPORTED_RATES)) {
    const std::vector<float> extended_rates = mgmt.extended_supported_rates();
    supported_rates.insert(supported_rates.end(), extended_rates.begin(),
                           extended_rates.end());
  }
  const std::set<float> supported_set(supported_rates.begin(),
                                      supported_rates.end());
  const std::set<float> dot11a_rates{6.0,  9.0,  12.0, 18.0,
                                     24.0, 36.0, 48.0, 54.0};
  std::vector<wifi_standard_info> result;
  bool has_dot11a_rates = std::all_of(
      dot11a_rates.begin(), dot11a_rates.end(),
      [&supported_set](float rate) { return supported_set.count(rate) > 0; });
  if (has_dot11a_rates)
    result.push_back(wifi_standard_info{
        .std = WiFiStandard::Dot11A,
        .modulation_supported = {Modulation::BPSK, Modulation::QPSK,
                                 Modulation::QAM16, Modulation::QAM64},
        .spatial_streams_supported = {1},
        .channel_widths_supported = {ChannelWidth::CHAN20},
    });

  const std::set<float> dot11b_rates{1, 2, 5.5, 11};
  bool has_dot11b_rates = std::all_of(
      dot11b_rates.begin(), dot11b_rates.end(),
      [&supported_set](float rate) { return supported_set.count(rate) > 0; });
  result.push_back(wifi_standard_info{
      .std = WiFiStandard::Dot11B,
      .modulation_supported = {Modulation::BPSK, Modulation::QPSK,
                               Modulation::CCK},
      .spatial_streams_supported = {1},
      .channel_widths_supported = {ChannelWidth::CHAN20},
  });

  if (mgmt.search_option(
          static_cast<Tins::Dot11::OptionTypes>(47))) // Extended Rate PHY
    result.push_back(wifi_standard_info{
        .std = WiFiStandard::Dot11G,
        .modulation_supported = {Modulation::BPSK, Modulation::QPSK,
                                 Modulation::QAM16, Modulation::QAM64},
        .spatial_streams_supported = {1},
        .channel_widths_supported = {ChannelWidth::CHAN20},
    });

  // NOTE: Used https://mcsindex.com to determine data about MCS index
  const Tins::Dot11::option *dot11n_cap =
      mgmt.search_option(Tins::Dot11::OptionTypes::HT_CAPABILITY);
  if (dot11n_cap) {
    wifi_standard_info standard_info{
        .std = WiFiStandard::Dot11N,
        .channel_widths_supported{ChannelWidth::CHAN20, ChannelWidth::CHAN40}};
    std::vector<uint8_t> mcs_bitset(dot11n_cap->data_ptr() + 3,
                                    dot11n_cap->data_ptr() + 7);
    for (int i = 0; i < 4; i++) {
      if (mcs_bitset[i])
        standard_info.spatial_streams_supported.insert(
            i + 1); // 0-7 is one spatial stream, 8-15 is two, etc

      if (mcs_bitset[i] & 0b00000001)
        standard_info.modulation_supported.insert(Modulation::BPSK);
      if (mcs_bitset[i] & 0b00000110)
        standard_info.modulation_supported.insert(Modulation::QPSK);
      if (mcs_bitset[i] & 0b00011000)
        standard_info.modulation_supported.insert(Modulation::QAM16);
      if (mcs_bitset[i] & 0b11100000)
        standard_info.modulation_supported.insert(Modulation::QAM64);

      for (int j = 0; j < 8; j++)
        if (mcs_bitset[i] & (1 << j))
          standard_info.mcs_supported_idx.insert(i * 8 + j);
    }

    bool supports_transmit_beamforming = dot11n_cap->data_ptr()[24] & 0x01;
    standard_info.multi_beamformer_support = supports_transmit_beamforming;
    standard_info.single_beamformer_support = supports_transmit_beamforming;
    result.push_back(standard_info);
  }

  const Tins::Dot11::option *dot11ac_cap =
      mgmt.search_option(Tins::Dot11::OptionTypes::VHT_CAP);
  if (dot11ac_cap) {
    wifi_standard_info standard_info{
        .std = WiFiStandard::Dot11AC,
        .channel_widths_supported{ChannelWidth::CHAN20, ChannelWidth::CHAN40,
                                  ChannelWidth::CHAN80}};
    std::vector<uint8_t> data(dot11ac_cap->data_ptr(),
                              dot11ac_cap->data_ptr() +
                                  dot11ac_cap->data_size());
    if (data[0] & 0b00000100)
      standard_info.channel_widths_supported.insert(ChannelWidth::CHAN160);
    if (data[0] & 0b00001000)
      standard_info.channel_widths_supported.insert(ChannelWidth::CHAN80_80);
    standard_info.single_beamformee_support = data[1] & 0b00010000;
    standard_info.single_beamformer_support = data[1] & 0b00001000;
    standard_info.multi_beamformee_support = data[2] & 0b00010000;
    standard_info.multi_beamformer_support = data[2] & 0b00001000;

    // NOTE: I know this is incorrect according to the standards, but we will
    // assume that spatial stream capabilities are identical when sending
    // (wlan.vht.mcsset.txmcsmap) and receiving (wlan.vht.mcsset.rxmcsmap)
    //
    // Figure 9-562 IEEE 802.11-2016
    // TODO: Make this more readable with bitsets
    std::vector<uint8_t> mcs_bitset{data[4], data[5]};
    int cnt = 0;
    for (int i = 0; i < 2; i++)
      for (int j = 0; j < 4; j++) {
        cnt++;
        uint8_t first_support_bit = (1 << (2 * j));
        uint8_t second_support_bit = (1 << ((2 * j) + 1));
        uint8_t n_streams_support =
            (mcs_bitset[i] & (first_support_bit | second_support_bit)) >>
            (2 * j);
        if (n_streams_support == 3)
          continue; // Not supported

        standard_info.spatial_streams_supported.insert(cnt);
        uint8_t max_mcs_for_stream = 0;
        if (n_streams_support == 0)
          max_mcs_for_stream = 7;
        if (n_streams_support == 1)
          max_mcs_for_stream = 8;
        if (n_streams_support == 2)
          max_mcs_for_stream = 9;
        for (uint8_t n = 0; n <= max_mcs_for_stream; n++)
          standard_info.mcs_supported_idx.insert(n);
      }

    if (standard_info.mcs_supported_idx.size()) {
      standard_info.modulation_supported.insert(Modulation::BPSK);
      standard_info.modulation_supported.insert(Modulation::QPSK);
      standard_info.modulation_supported.insert(Modulation::QAM16);
      standard_info.modulation_supported.insert(Modulation::QAM64);
    }

    if (standard_info.mcs_supported_idx.contains(8) ||
        standard_info.mcs_supported_idx.contains(9))
      standard_info.modulation_supported.insert(Modulation::QAM256);

    result.push_back(standard_info);
  }

  for (const auto &opt : mgmt.options()) {
    if (opt.option() !=
        static_cast<Tins::Dot11::OptionTypes>(255)) // Extended options
      continue;

    if (opt.data_ptr()[0] != 35) // HE Capabilities Extended Tag Number
      continue;

    wifi_standard_info standard_info{
        .std = WiFiStandard::Dot11AX,
        .channel_widths_supported{ChannelWidth::CHAN20, ChannelWidth::CHAN40,
                                  ChannelWidth::CHAN80}};
    std::vector<uint8_t> data(opt.data_ptr(), opt.data_ptr() + opt.data_size());
    if (data[7] & 0b00001000)
      standard_info.channel_widths_supported.insert(ChannelWidth::CHAN160);
    if (data[7] & 0b00010000) {
      standard_info.channel_widths_supported.insert(ChannelWidth::CHAN160);
      standard_info.channel_widths_supported.insert(ChannelWidth::CHAN80_80);
    }

    standard_info.single_beamformer_support = data[10] & 0b10000000;
    standard_info.single_beamformee_support = data[11] & 0b00000001;
    standard_info.multi_beamformer_support = data[11] & 0b00000010;
    standard_info.multi_beamformee_support = data[11] & 0b00000010;

    // NOTE: I know this is incorrect according to the standards, but we will
    // assume that spatial stream capabilities are identical when sending
    // (wlan.ext_tag.he_mcs.map.tx_he_mcs_map_lte_80) and receiving
    // (wlan.ext_tag.he_mcs.map.rx_he_mcs_map_lte_80)
    //
    // Figure 9-788e IEEE 802.11ax
    // TODO: Make this more readable with bitsets
    std::vector<uint8_t> mcs_bitset{data[18], data[19]};
    int cnt = 0;
    for (int i = 0; i < 2; i++)
      for (int j = 0; j < 4; j++) {
        cnt++;
        uint8_t first_support_bit = (1 << (2 * j));
        uint8_t second_support_bit = (1 << ((2 * j) + 1));
        uint8_t n_streams_support =
            (mcs_bitset[i] & (first_support_bit | second_support_bit)) >>
            (2 * j);
        if (n_streams_support == 3)
          continue; // Not supported

        standard_info.spatial_streams_supported.insert(cnt);
        uint8_t max_mcs_for_stream = 0;
        if (n_streams_support == 0)
          max_mcs_for_stream = 7;
        if (n_streams_support == 1)
          max_mcs_for_stream = 9;
        if (n_streams_support == 2)
          max_mcs_for_stream = 11;
        for (uint8_t n = 0; n <= max_mcs_for_stream; n++)
          standard_info.mcs_supported_idx.insert(n);
      }

    if (standard_info.mcs_supported_idx.size()) {
      standard_info.modulation_supported.insert(Modulation::BPSK);
      standard_info.modulation_supported.insert(Modulation::QPSK);
      standard_info.modulation_supported.insert(Modulation::QAM16);
      standard_info.modulation_supported.insert(Modulation::QAM64);
    }

    if (standard_info.mcs_supported_idx.contains(8) ||
        standard_info.mcs_supported_idx.contains(9))
      standard_info.modulation_supported.insert(Modulation::QAM256);

    if (standard_info.mcs_supported_idx.contains(10) ||
        standard_info.mcs_supported_idx.contains(11))
      standard_info.modulation_supported.insert(Modulation::QAM1024);

    result.push_back(standard_info);
  }

  return result;
}

bool AccessPoint::check_pmf_capable(const Tins::Dot11ManagementFrame &mgmt) {
  if (!mgmt.search_option(Tins::Dot11::OptionTypes::RSN))
    return false;
  return mgmt.rsn_information().capabilities() &
         0x008; // wlan.rsn.capabilities.mfpc
}

bool AccessPoint::check_pmf_required(const Tins::Dot11ManagementFrame &mgmt) {
  if (!mgmt.search_option(Tins::Dot11::OptionTypes::RSN))
    return false;
  return mgmt.rsn_information().capabilities() &
         0x004; // // wlan.rsn.capabilities.mfpr
}

std::vector<wifi_chan_info>
AccessPoint::detect_channel_info(Tins::Dot11ManagementFrame &mgmt) {
  std::vector<wifi_chan_info> result;
  if (mgmt.search_option(Tins::Dot11::OptionTypes::DS_SET))
    result.push_back({
        .freq = NetCardManager::chan_to_freq(mgmt.ds_parameter_set()),
        .chan_type = ChannelModes::NO_HT,
    });

  if (auto ht_opt =
          mgmt.search_option(Tins::Dot11::OptionTypes::HT_OPERATION)) {
    std::vector<uint8_t> ht_info(ht_opt->data_ptr(),
                                 ht_opt->data_ptr() + ht_opt->data_size());
    wifi_chan_info chan_info = {.freq =
                                    NetCardManager::chan_to_freq(ht_info[0])};
    if (!(ht_info[1] & 4)) {
      // We know its only HT20
      chan_info.chan_type = ChannelModes::HT20;
    } else if (ht_info[1] & 3) {
      // Secondary is below primary
      chan_info.chan_type = ChannelModes::HT40MINUS;
      chan_info.center_freq1 = chan_info.freq - 10;
    } else if (ht_info[1] & 1) {
      // Secondary is above primary
      chan_info.chan_type = ChannelModes::HT40PLUS;
      chan_info.center_freq1 = chan_info.freq + 10;
    }

    result.push_back(chan_info);
  }

  if (auto vht_opt = mgmt.search_option(Tins::Dot11::OptionTypes::VHT_OP)) {
    std::vector<uint8_t> vht_info(vht_opt->data_ptr(),
                                  vht_opt->data_ptr() + vht_opt->data_size());
    switch (vht_info[0]) {
    case 0:
      // 20MHz or 40MHz bandwidth, we take the active channel from above since
      // there is no channel indication (wlan.vht.op.channelcenter0 == 0)
      break;

    case 1:
      // 80 MHz, 160 MHz, or 80+80 MHz BSS bandwidth
      if (vht_info[2]) {
        // 80+80 MHz
        result.push_back({
            .freq = NetCardManager::chan_to_freq(vht_info[1]) -
                    30, // (80/2) + 20/2 since the primary channel should
                        // be the first 20MHz segment of the 80MHz width
            .chan_type = ChannelModes::VHT80P80,
            .center_freq1 = NetCardManager::chan_to_freq(vht_info[1]),
            .center_freq2 = NetCardManager::chan_to_freq(vht_info[2]),
        });
      } else {
        // 80 MHz or 160 MHz
        result.push_back({
            .freq = NetCardManager::chan_to_freq(vht_info[1]) -
                    30, // -(80/2) + 20/2 since the primary channel should
                        // be the first 20MHz segment of the 80MHz width
            .chan_type = ChannelModes::VHT80,
            .center_freq1 = NetCardManager::chan_to_freq(vht_info[1]),
        });

        if (NetCardManager::freq_to_chan(
                NetCardManager::chan_to_freq(vht_info[1]) - 70) > 0)
          result.push_back({
              .freq = NetCardManager::chan_to_freq(vht_info[1]) -
                      70, // -(160/2) + 20/2 since the primary channel should
                          // be the first 20MHz segment of the 160MHz width
              .chan_type = ChannelModes::VHT160,
              .center_freq1 = NetCardManager::chan_to_freq(vht_info[1]),
          });
      }
      break;

    case 2:
      // 160 MHz BSS bandwidth
      result.push_back({
          .freq = NetCardManager::chan_to_freq(vht_info[1]) - 70, // See above
          .chan_type = ChannelModes::VHT160,
          .center_freq1 = NetCardManager::chan_to_freq(vht_info[1]),
      });
      break;

    case 3:
      // Non-contiguous 80+80 MHz BSS bandwidth
      result.push_back({
          .freq = NetCardManager::chan_to_freq(vht_info[1]) - 30, // See above
          .chan_type = ChannelModes::VHT80P80,
          .center_freq1 = NetCardManager::chan_to_freq(vht_info[1]),
          .center_freq2 = NetCardManager::chan_to_freq(vht_info[2]),
      });
      break;

    default:
      break;
    }
  }

  // TODO: Channel width handling for 802.11ax (HE Operation)
  return result;
}

bool AccessPoint::is_ccmp(const Tins::Dot11ManagementFrame &mgmt) const {
  bool has_rsn_info = mgmt.search_option(Tins::Dot11::OptionTypes::RSN);
  if (!has_rsn_info) {
    return false;
  }

  Tins::RSNInformation rsn_info = mgmt.rsn_information();
  Tins::RSNInformation::CypherSuites group_suite = rsn_info.group_suite();
  if (group_suite == Tins::RSNInformation::TKIP)
    return false;

  std::vector<Tins::RSNInformation::CypherSuites> pairwise_ciphers =
      rsn_info.pairwise_cyphers();
  bool supports_ccmp =
      std::find(pairwise_ciphers.begin(), pairwise_ciphers.end(),
                Tins::RSNInformation::CCMP) != pairwise_ciphers.end();
  return supports_ccmp;
}

void AccessPoint::set_vendor() {
  std::string mac_prefix = bssid.to_string().substr(0, 8);
  std::erase(mac_prefix, ':');
  std::transform(mac_prefix.begin(), mac_prefix.end(), mac_prefix.begin(),
                 ::toupper);
  oid = mac_prefix;
  vendor = db.get_vendor_name(oid);
}

std::string AccessPoint::get_vendor() const { return vendor; }
std::string AccessPoint::get_oid() const { return oid; }

} // namespace yarilo
