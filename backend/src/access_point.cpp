#include "access_point.h"
#include "decrypter.h"
#include <algorithm>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <tins/tins.h>

namespace yarilo {

AccessPoint::AccessPoint(const MACAddress &bssid, const SSID &ssid)
    : ssid(ssid), bssid(bssid), decrypter(bssid, ssid) {
  logger = spdlog::get(ssid);
  if (!logger)
    logger = spdlog::stdout_color_mt(ssid);
  logger->debug("Station found on channel {} with addr {}", wifi_channel,
                bssid.to_string());
};

bool AccessPoint::handle_pkt(Tins::Packet *pkt) {
  auto pdu = pkt->pdu();
  if (pdu->find_pdu<Tins::Dot11Data>())
    return handle_data(pkt);
  if (pdu->find_pdu<Tins::Dot11ManagementFrame>())
    return handle_management(pkt);
  return true;
};

SSID AccessPoint::get_ssid() { return ssid; }

MACAddress AccessPoint::get_bssid() { return bssid; }

int AccessPoint::get_wifi_channel() { return wifi_channel; }

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
                              const MACAddress &addr) {
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

bool AccessPoint::has_working_password() {
  return decrypter.has_working_password();
}

bool AccessPoint::decryption_support() { return decryption_supported; }

bool AccessPoint::protected_management_support() { return pmf_supported; }

WPA2Decrypter &AccessPoint::get_decrypter() { return decrypter; }

int AccessPoint::raw_packet_count() { return captured_packets.size(); }

int AccessPoint::decrypted_packet_count() {
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

  Tins::RSNInformation rsn_info = mgmt.rsn_information();
  bool group_uses_ccmp = rsn_info.group_suite() == Tins::RSNInformation::CCMP;

  std::vector<Tins::RSNInformation::CypherSuites> pairwise_ciphers =
      rsn_info.pairwise_cyphers();
  bool pairwise_supports_ccmp =
      std::find(pairwise_ciphers.begin(), pairwise_ciphers.end(),
                Tins::RSNInformation::CCMP) != pairwise_ciphers.end();

  std::vector<Tins::RSNInformation::AKMSuites> akm_ciphers =
      rsn_info.akm_cyphers();
  bool supports_psk = std::find(akm_ciphers.begin(), akm_ciphers.end(),
                                Tins::RSNInformation::PSK) != akm_ciphers.end();

  bool wpa2psk = group_uses_ccmp && pairwise_supports_ccmp && supports_psk;
  if (wpa2psk)
    decryption_supported = true;
  return true;
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
