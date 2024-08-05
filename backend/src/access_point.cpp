#include "access_point.h"
#include "decrypter.h"
#include <algorithm>
#include <semaphore.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <tins/tins.h>

using NetworkSecurity = yarilo::AccessPoint::NetworkSecurity;

namespace yarilo {

AccessPoint::AccessPoint(const MACAddress &bssid, const SSID &ssid,
                         int wifi_channel)
    : ssid(ssid), bssid(bssid), decrypter(bssid, ssid) {
  logger = spdlog::get(ssid);
  if (!logger)
    logger = spdlog::stdout_color_mt(ssid);
  logger->debug("Station found on channel {} with addr {}", wifi_channel,
                bssid.to_string());
  this->wifi_channel = wifi_channel;
};

bool AccessPoint::handle_pkt(Tins::Packet *pkt) {
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

std::shared_ptr<PacketChannel> AccessPoint::get_channel() {
  auto new_chan = std::make_shared<PacketChannel>();

  for (const auto &pkt : captured_packets) {
    // Check if decrypted
    auto data = pkt->pdu()->find_pdu<Tins::Dot11Data>();
    if (!data || !data->find_pdu<Tins::SNAP>())
      continue;
    new_chan->send(make_eth_packet(data));
  }

  converted_channels.push_back(new_chan);
  return new_chan;
}

void AccessPoint::close_all_channels() {
  for (auto &channel : converted_channels)
    channel->close();
}

bool AccessPoint::add_password(const std::string &psk) {
  if (decrypter.has_working_password() || !decrypter.can_generate_keys())
    return true;

  decrypter.add_password(psk);
  if (!decrypter.has_working_password())
    return false;

  for (auto &pkt : captured_packets) {
    auto data = pkt->pdu()->find_pdu<Tins::Dot11Data>();
    if (!data || !data->find_pdu<Tins::SNAP>())
      continue;

    for (auto &chan : converted_channels)
      if (!chan->is_closed())
        chan->send(make_eth_packet(data));
  }

  return true;
};

bool AccessPoint::send_deauth(const Tins::NetworkInterface &iface,
                              const MACAddress &addr) const {
  if (!radio_length)
    return false;

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

bool AccessPoint::save_decrypted_traffic(
    const std::filesystem::path &dir_path) {
  std::shared_ptr<PacketChannel> channel = get_channel();
  if (channel->is_closed())
    return false;

  auto now = std::chrono::system_clock::now();
  std::time_t currentTime = std::chrono::system_clock::to_time_t(now);
  struct std::tm *timeInfo = std::localtime(&currentTime);
  std::stringstream ss;
  ss << ssid << "-" << std::put_time(timeInfo, "%d-%m-%Y-%H:%M") << ".pcap";

  channel->lock_send(); // Lock so that no one writes to it
  std::filesystem::path path = dir_path;
  std::filesystem::path filename = path.append(ss.str());
  logger->debug("Creating a recording with {} packets: {}", channel->len(),
                filename.string());

  Tins::PacketWriter writer(filename, Tins::DataLinkType<Tins::EthernetII>());
  int count = 0;
  std::thread watcher([this, &channel, &count]() {
    while (!channel->is_empty())
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    channel->close();
    logger->trace("Channel closed, written {} packets", count);
  });

  while (!channel->is_closed()) {
    auto pkt = channel->receive();
    if (!pkt.has_value())
      break;
    count++;
    writer.write(pkt.value());
  }

  channel->unlock_send();
  watcher.join();
  logger->trace("File saved");
  return true;
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

  bool decrypted = decrypter.decrypt(pkt);
  if (!decrypted)
    return true;

  // Send the decrypted packet to every open channel
  for (auto &chan : converted_channels)
    if (!chan->is_closed())
      chan->send(make_eth_packet(&data));

  return true;
}

bool AccessPoint::handle_management(Tins::Packet *pkt) {
  auto mgmt = pkt->pdu()->rfind_pdu<Tins::Dot11ManagementFrame>();
  if (mgmt.wep())
    pmf_supported = true;

  bool has_channel_info = mgmt.search_option(Tins::Dot11::OptionTypes::DS_SET);
  if (has_channel_info)
    wifi_channel = mgmt.ds_parameter_set();

  if (!security_detected) {
    security_modes = detect_security_modes(mgmt);
    uses_ccmp = is_ccmp(mgmt);

    if (security_modes.size() == 1 &&
        (security_modes[0] == NetworkSecurity::WPA3_Personal ||
         security_modes[0] == NetworkSecurity::WPA3_Enterprise)) {
      pmf_supported = true;
    }
  }

  auto assoc = pkt->pdu()->find_pdu<Tins::Dot11AssocRequest>();
  auto reassoc = pkt->pdu()->find_pdu<Tins::Dot11ReAssocRequest>();
  if (assoc || reassoc) {
    MACAddress client = mgmt.addr2();
    NetworkSecurity security = detect_security_modes(mgmt)[0];

    bool has_rsn_info = mgmt.search_option(Tins::Dot11::OptionTypes::RSN);
    if (!has_rsn_info) {
      client_security new_client_info{.security = security};
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
        .pmf = (security == NetworkSecurity::WPA3_Personal ||
                security == NetworkSecurity::WPA3_Enterprise),
        .pairwise_cipher = rsn_info.pairwise_cyphers()[0],
    };
    return true;
  };

  MACAddress client;
  if (!mgmt.to_ds() && mgmt.from_ds()) {
    client = mgmt.addr1();
  } else if (mgmt.to_ds() && !mgmt.from_ds()) {
    client = mgmt.addr2();
  } else {
    return true;
  }

  if (clients_security.count(client) && mgmt.wep())
    clients_security[client].pmf = true;
  return true;
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

std::unique_ptr<Tins::EthernetII>
AccessPoint::make_eth_packet(Tins::Dot11Data *data) {
  // TODO: Change detection
  MACAddress dst;
  MACAddress src;

  if (data->from_ds() && !data->to_ds()) {
    dst = data->addr1();
    src = data->addr3();
  } else if (!data->from_ds() && data->to_ds()) {
    dst = data->addr3();
    src = data->addr2();
  } else {
    dst = data->addr1();
    src = data->addr2();
  }

  auto snap = data->find_pdu<Tins::SNAP>()->clone();
  auto pkt = std::make_unique<Tins::EthernetII>(dst, src);
  pkt->inner_pdu(snap->release_inner_pdu());
  return pkt;
}

} // namespace yarilo
