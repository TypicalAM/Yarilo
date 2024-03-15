#include "access_point.h"
#include "client.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include <filesystem>
#include <iomanip>
#include <memory>
#include <optional>
#include <sstream>
#include <thread>
#include <tins/dot11.h>
#include <tins/eapol.h>
#include <tins/ethernetII.h>
#include <tins/hw_address.h>
#include <tins/packet_sender.h>
#include <tins/packet_writer.h>
#include <tins/pdu.h>
#include <tins/rawpdu.h>
#include <tins/snap.h>

AccessPoint::AccessPoint(const Tins::HWAddress<6> &bssid, const SSID &ssid,
                         int wifi_channel) {
  logger = spdlog::get(ssid);
  if (!logger)
    logger = spdlog::stdout_color_mt(ssid);
  logger->debug("Station found on channel {} with addr {}", wifi_channel,
                bssid.to_string());
  this->ssid = ssid;
  this->bssid = bssid;
  this->wifi_channel = wifi_channel;
};

bool AccessPoint::handle_pkt(Tins::PDU &pkt) {
  if (pkt.find_pdu<Tins::Dot11ManagementFrame>())
    return handle_mgmt(pkt);

  if (pkt.find_pdu<Tins::Dot11Data>())
    return handle_data(pkt);

  return true;
};

std::vector<std::shared_ptr<Client>> AccessPoint::get_clients() {
  std::vector<std::shared_ptr<Client>> res;
  for (const auto &pair : clients)
    res.push_back(pair.second);
  return res;
}

std::optional<std::shared_ptr<Client>>
AccessPoint::get_client(Tins::HWAddress<6> addr) {
  if (clients.find(addr) == clients.end())
    return std::nullopt;

  return clients[addr];
}

SSID AccessPoint::get_ssid() { return ssid; }

Tins::HWAddress<6> AccessPoint::get_bssid() { return bssid; }

int AccessPoint::get_wifi_channel() { return wifi_channel; }

std::shared_ptr<PacketChannel> AccessPoint::get_channel() {
  auto new_chan = std::make_shared<PacketChannel>();

  for (const auto &pkt : captured_packets) {
    // Check if decrypted
    if (!pkt->find_pdu<Tins::SNAP>() && !pkt->find_pdu<Tins::EAPOL>())
      continue;

    new_chan->send(make_eth_packet(pkt.get()));
  }

  converted_channels.push_back(new_chan);
  return new_chan;
}

bool AccessPoint::add_passwd(const std::string &psk) {
  if (working_psk)
    return true;

  this->psk = psk;
  if (clients.size() == 0)
    return true;

  bool worked = false;
  for (const auto &[addr, client] : clients) {
    if (client->is_decrypted()) {
      working_psk = true;
      return true;
    }

    if (!client->can_decrypt())
      continue;

    auto keys = client->try_decrypt(psk);
    if (!keys.has_value()) {
      logger->error("Failed decryption despite possibilities for client: {}",
                    addr.to_string());
      continue;
    }

    worked = true;
    decrypter.add_decryption_keys(keys->begin()->first, keys->begin()->second);

    for (auto &pkt : captured_packets) {
      if (pkt->find_pdu<Tins::SNAP>() || pkt->find_pdu<Tins::EAPOL>())
        continue; // Already decrypted

      // Check if we can decrypt it
      bool success = decrypter.decrypt(*pkt.get());
      if (!success)
        continue;

      // Decrypted packet, let's put it into the opened channels
      for (auto &chan : converted_channels) {
        if (chan->is_closed())
          continue;

        chan->send(make_eth_packet(pkt.get()));
      }
    }
  }

  return worked;
};

bool AccessPoint::send_deauth(Tins::NetworkInterface *iface,
                              Tins::HWAddress<6> addr) {
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

bool AccessPoint::psk_correct() { return working_psk; }

bool AccessPoint::management_protected() { return protected_mgmt_frames; }

void AccessPoint::update_wifi_channel(int i) { wifi_channel = i; };

int AccessPoint::raw_packet_count() { return captured_packets.size(); }

int AccessPoint::decrypted_packet_count() {
  int count = 0;
  for (const auto &pkt : captured_packets)
    if (pkt->find_pdu<Tins::SNAP>())
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

bool AccessPoint::handle_data(Tins::PDU &pkt) {
  // Note some things about the radiotap header to be able to deauth our clients
  if (pkt.find_pdu<Tins::Dot11QoSData>()) {
    auto radio = pkt.find_pdu<Tins::RadioTap>();
    radio_length = radio->length();
    radio_channel_freq = radio->channel_freq();
    radio_channel_type = radio->channel_type();
    radio_antenna = radio->antenna();
  }

  // Check if this packet by a known client
  auto dot11 = pkt.rfind_pdu<Tins::Dot11Data>();
  Tins::HWAddress<6> addr = determine_client(dot11);
  if (addr.is_unicast() && clients.find(addr) == clients.end())
    clients[addr] = std::make_shared<Client>(bssid, ssid, addr);

  // Check if this is an authentication packet
  if (pkt.find_pdu<Tins::RSNEAPOL>()) {
    clients[addr]->add_handshake(dot11);
    return true;
  }

  // Check if the payload is encrypted
  if (!pkt.find_pdu<Tins::RawPDU>() || !dot11.wep()) {
    captured_packets.push_back(std::unique_ptr<Tins::Dot11Data>(dot11.clone()));
    return true;
  }

  // It's encrypted, let's try to decrypt!
  bool decrypted = decrypter.decrypt(pkt);
  if (!decrypted) {
    captured_packets.push_back(std::unique_ptr<Tins::Dot11Data>(dot11.clone()));
    return true;
  }

  // Decrypted packet, let's put it into the opened channels
  for (auto &chan : converted_channels) {
    if (chan->is_closed())
      continue;

    chan->send(make_eth_packet(pkt.find_pdu<Tins::Dot11Data>()));
  }

  captured_packets.push_back(std::unique_ptr<Tins::Dot11Data>(dot11.clone()));
  return true;
}

bool AccessPoint::handle_mgmt(Tins::PDU &pkt) {
  auto mgmt = pkt.rfind_pdu<Tins::Dot11ManagementFrame>();
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

Tins::HWAddress<6> AccessPoint::determine_client(const Tins::Dot11Data &dot11) {
  Tins::HWAddress<6> dst;
  Tins::HWAddress<6> src;

  if (dot11.from_ds() && !dot11.to_ds()) {
    dst = dot11.addr1();
    src = dot11.addr3();
  } else if (!dot11.from_ds() && dot11.to_ds()) {
    dst = dot11.addr3();
    src = dot11.addr2();
  } else {
    dst = dot11.addr1();
    src = dot11.addr2();
  }

  if (src == bssid)
    return dst;

  if (dst == bssid)
    return src;

  return dst;
}

std::unique_ptr<Tins::EthernetII>
AccessPoint::make_eth_packet(Tins::Dot11Data *dot11) {
  Tins::HWAddress<6> dst;
  Tins::HWAddress<6> src;

  if (dot11->from_ds() && !dot11->to_ds()) {
    dst = dot11->addr1();
    src = dot11->addr3();
  } else if (!dot11->from_ds() && dot11->to_ds()) {
    dst = dot11->addr3();
    src = dot11->addr2();
  } else {
    dst = dot11->addr1();
    src = dot11->addr2();
  }

  auto snap = dot11->find_pdu<Tins::SNAP>()->clone();
  auto pkt = std::make_unique<Tins::EthernetII>(dst, src);
  pkt->inner_pdu(snap->release_inner_pdu());
  return pkt;
}
