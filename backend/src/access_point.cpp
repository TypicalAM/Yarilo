#include "access_point.h"
#include "decrypter.h"
#include "log_sink.h"
#include "recording.h"
#include <algorithm>
#include <optional>
#include <semaphore.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <tins/ethernetII.h>
#include <tins/packet.h>
#include <tins/tins.h>

using NetworkSecurity = yarilo::AccessPoint::NetworkSecurity;
using DecryptionState = yarilo::AccessPoint::DecryptionState;
using wifi_standard_info = yarilo::AccessPoint::wifi_standard_info;
using recording_info = yarilo::Recording::info;

namespace yarilo {

AccessPoint::AccessPoint(const MACAddress &bssid, const SSID &ssid,
                         int wifi_channel)
    : ssid(ssid), bssid(bssid), decrypter(bssid, ssid) {
  logger = spdlog::get(ssid);
  if (!logger)
    logger = std::make_shared<spdlog::logger>(
        ssid, spdlog::sinks_init_list{
                  global_proto_sink,
                  std::make_shared<spdlog::sinks::stdout_color_sink_mt>()});

  logger->debug("Station found on channel {} with addr {}", wifi_channel,
                bssid.to_string());
  this->wifi_channel = wifi_channel;
};

bool AccessPoint::handle_pkt(Tins::Packet *pkt) {
  count++;
  auto pdu = pkt->pdu();
  if (pdu->find_pdu<Tins::Dot11Data>())
    return handle_data(pkt);
  if (pdu->find_pdu<Tins::Dot11ManagementFrame>())
    return handle_management(pkt);
  return true;
};

SSID AccessPoint::get_ssid() const { return ssid; }

MACAddress AccessPoint::get_bssid() const { return bssid; }

int AccessPoint::get_wifi_channel() const { return wifi_channel; }

std::vector<wifi_standard_info> AccessPoint::wifi_standards() const {
  return wifi_stds_supported;
}

std::shared_ptr<PacketChannel> AccessPoint::get_decrypted_channel() {
  auto new_chan = std::make_shared<PacketChannel>();

  for (const auto &pkt : captured_packets) {
    // Check if decrypted
    auto data = pkt->pdu()->find_pdu<Tins::Dot11Data>();
    if (!data || !data->find_pdu<Tins::SNAP>())
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

  for (auto &pkt : captured_packets) {
    auto data = pkt->pdu()->find_pdu<Tins::Dot11Data>();
    if (!data || !data->find_pdu<Tins::SNAP>())
      continue;

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

int AccessPoint::raw_packet_count() const { return captured_packets.size(); }

int AccessPoint::decrypted_packet_count() const {
  int count = 0;
  for (const auto &pkt : captured_packets)
    if (pkt->pdu()->find_pdu<Tins::SNAP>())
      count++;
  return count;
}

std::optional<recording_info>
AccessPoint::save_traffic(const std::filesystem::path &dir_path,
                          const std::string &name) {
  logger->debug("Creating a raw recording with {} packets",
                captured_packets.size());

  Recording rec(dir_path, true);
  rec.set_name(name);
  return rec.dump(&captured_packets);
}

std::optional<recording_info>
AccessPoint::save_decrypted_traffic(const std::filesystem::path &dir_path,
                                    const std::string &name) {
  std::shared_ptr<PacketChannel> channel = get_decrypted_channel();
  if (channel->is_closed())
    return std::nullopt;

  logger->debug("Creating a decrypted recording with {} packets",
                channel->len());

  Recording rec(dir_path, false);
  rec.set_name(name);
  return rec.dump(std::move(channel));
}

bool AccessPoint::handle_data(Tins::Packet *pkt) {
  auto pdu = pkt->pdu();
  auto data = pdu->rfind_pdu<Tins::Dot11Data>();
  captured_packets.push_back(pkt);

  // Note some things about the radiotap header to be able to deauth our
  // clients
  if (data.find_pdu<Tins::Dot11QoSData>()) {
    auto radio = pdu->find_pdu<Tins::RadioTap>();
    radio_length = radio->length();
    radio_channel_freq = radio->channel_freq();
    radio_channel_type = radio->channel_type();
    radio_antenna = radio->antenna();
  }

  bool sent_by_client = data.dst_addr() == this->bssid;
  Tins::HWAddress<6> client_addr =
      (sent_by_client) ? data.src_addr() : data.dst_addr();
  if (!clients.count(client_addr)) {
    client_info info{};
    info.hwaddr = client_addr.to_string();
    if (auto radio = pkt->pdu()->find_pdu<Tins::RadioTap>()) {
      if (radio->present() & Tins::RadioTap::DBM_SIGNAL)
        info.rrsi = radio->dbm_signal();

      if (radio->present() & Tins::RadioTap::DBM_NOISE)
        info.noise = radio->dbm_noise();

      if (radio->present() & Tins::RadioTap::DBM_SIGNAL &&
          radio->present() & Tins::RadioTap::DBM_NOISE)
        info.snr = info.rrsi - info.noise;
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
    return true;
  update_client_metadata(*pkt);

  // Send the decrypted packet to every open channel
  for (auto &chan : converted_channels)
    if (!chan->is_closed())
      chan->send(Recording::make_eth_packet(pkt));

  return true;
}

bool AccessPoint::handle_management(Tins::Packet *pkt) {
  if (count == 1)
    captured_packets.push_back(
        pkt); // First pkt is always network ID (Beacon/ProbeResp)

  auto mgmt = pkt->pdu()->rfind_pdu<Tins::Dot11ManagementFrame>();
  if (mgmt.wep())
    pmf_supported = true;

  bool has_channel_info = mgmt.search_option(Tins::Dot11::OptionTypes::DS_SET);
  if (has_channel_info)
    wifi_channel = mgmt.ds_parameter_set();

  if (!security_detected && (pkt->pdu()->find_pdu<Tins::Dot11Beacon>() ||
                             pkt->pdu()->find_pdu<Tins::Dot11Beacon>())) {
    security_modes = detect_security_modes(mgmt);
    uses_ccmp = is_ccmp(mgmt);
    pmf_supported = check_pmf_capable(mgmt);
    pmf_required = check_pmf_required(mgmt);
    wifi_stds_supported = detect_wifi_standards(mgmt);
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
      return true;
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

    return true;
  };

  MACAddress client_addr;
  if (!mgmt.to_ds() && mgmt.from_ds()) {
    client_addr = mgmt.addr1();
  } else if (mgmt.to_ds() && !mgmt.from_ds()) {
    client_addr = mgmt.addr2();
  } else {
    return true;
  }

  if (!clients.count(client_addr)) {
    client_info info{};
    info.hwaddr = client_addr.to_string();
    if (auto radio = pkt->pdu()->find_pdu<Tins::RadioTap>()) {
      if (radio->present() & Tins::RadioTap::DBM_SIGNAL)
        info.rrsi = radio->dbm_signal();

      if (radio->present() & Tins::RadioTap::DBM_NOISE)
        info.noise = radio->dbm_noise();

      if (radio->present() & Tins::RadioTap::DBM_SIGNAL &&
          radio->present() & Tins::RadioTap::DBM_NOISE)
        info.snr = info.rrsi - info.noise;
    }

    clients[client_addr] = info;
  }

  if (clients_security.count(client_addr) && mgmt.wep())
    clients_security[client_addr].pmf = true;
  return true;
}

void AccessPoint::update_client_metadata(const Tins::Packet &pkt) {
  auto data = pkt.pdu()->find_pdu<Tins::Dot11Data>();
  auto snap = pkt.pdu()->find_pdu<Tins::SNAP>();
  if (!data || !snap)
    return;

  bool sent_by_client = (data->dst_addr() == bssid ||
                         data->dst_addr() == MACAddress("ff:ff:ff:ff:ff:ff"));
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

std::vector<NetworkSecurity> AccessPoint::detect_security_modes(
    const Tins::Dot11ManagementFrame &mgmt) const {
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

std::vector<wifi_standard_info> AccessPoint::detect_wifi_standards(
    const Tins::Dot11ManagementFrame &mgmt) const {
  // TODO
  return {};
}

bool AccessPoint::check_pmf_capable(
    const Tins::Dot11ManagementFrame &mgmt) const {
  if (!mgmt.search_option(Tins::Dot11::OptionTypes::RSN))
    return false;
  return mgmt.rsn_information().capabilities() &
         0x008; // wlan.rsn.capabilities.mfpc
}

bool AccessPoint::check_pmf_required(
    const Tins::Dot11ManagementFrame &mgmt) const {
  if (!mgmt.search_option(Tins::Dot11::OptionTypes::RSN))
    return false;
  return mgmt.rsn_information().capabilities() &
         0x004; // // wlan.rsn.capabilities.mfpr
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

} // namespace yarilo
