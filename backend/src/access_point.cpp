#include "access_point.h"
#include "decrypter.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include <filesystem>
#include <iomanip>
#include <memory>
#include <netinet/in.h>
#include <optional>
#include <spdlog/logger.h>
#include <spdlog/spdlog.h>
#include <sstream>
#include <thread>
#include <tins/dot11.h>
#include <tins/eapol.h>
#include <tins/ethernetII.h>
#include <tins/hw_address.h>
#include <tins/packet.h>
#include <tins/packet_sender.h>
#include <tins/packet_writer.h>
#include <tins/pdu.h>
#include <tins/rawpdu.h>
#include <tins/snap.h>

namespace yarilo {

AccessPoint::AccessPoint(const MACAddress &bssid, const SSID &ssid,
                         int wifi_channel)
    : decrypter(bssid, ssid) {
  logger = spdlog::get(ssid);
  if (!logger)
    logger = spdlog::stdout_color_mt(ssid);
  logger->debug("Station found on channel {} with addr {}", wifi_channel,
                bssid.to_string());
  this->ssid = ssid;
  this->bssid = bssid;
  this->wifi_channel = wifi_channel;
};

bool AccessPoint::handle_pkt(Tins::Packet *pkt) {
  auto pdu = pkt->pdu();
  if (pdu->find_pdu<Tins::Dot11ManagementFrame>())
    return handle_mgmt(pkt);
  if (pdu->find_pdu<Tins::Dot11Data>())
    return handle_data(pkt);
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

bool AccessPoint::send_deauth(Tins::NetworkInterface *iface, MACAddress addr) {
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

  Tins::PacketSender sender(*iface);
  sender.send(radio);
  return true;
}

bool AccessPoint::has_working_password() {
  return decrypter.has_working_password();
}

WPA2Decrypter &AccessPoint::get_decrypter() { return decrypter; }

bool AccessPoint::management_protected() { return protected_mgmt_frames; }

void AccessPoint::update_wifi_channel(int i) { wifi_channel = i; };

int AccessPoint::raw_packet_count() { return captured_packets.size(); }

int AccessPoint::decrypted_packet_count() {
  int count = 0;
  for (const auto &pkt : captured_packets)
    if (pkt->pdu()->find_pdu<Tins::SNAP>())
      count++;
  return count;
}

bool AccessPoint::save_decrypted_traffic(std::filesystem::path dir_path) {
  std::shared_ptr<PacketChannel> channel = get_channel();
  if (channel->is_closed())
    return false;

  auto now = std::chrono::system_clock::now();
  std::time_t currentTime = std::chrono::system_clock::to_time_t(now);
  struct std::tm *timeInfo = std::localtime(&currentTime);
  std::stringstream ss;
  ss << ssid << "-" << std::put_time(timeInfo, "%d-%m-%Y-%H:%M") << ".pcap";

  channel->lock_send(); // Lock so that no one writes to it
  std::filesystem::path filename = dir_path.append(ss.str());
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

bool AccessPoint::handle_mgmt(Tins::Packet *pkt) {
  auto mgmt = pkt->pdu()->rfind_pdu<Tins::Dot11ManagementFrame>();
  switch (mgmt.subtype()) {
  case Tins::Dot11::DISASSOC:
  case Tins::Dot11::DEAUTH:
  case 13:
    // TODO: Implement the following:
    // Action Frames: Block ACK Request / Response, QoS Admission
    // Control, Radio Measurement, Spectrum Management, Fast BSS
    // Transition Channel Switch Announcement

    if (mgmt.wep())
      protected_mgmt_frames =
          true; // NOTE: This can exist on a per-client basis
  }

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
