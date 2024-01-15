#include "access_point.h"
#include "client.h"
#include <iostream>
#include <memory>
#include <optional>
#include <ostream>
#include <tins/dot11.h>
#include <tins/eapol.h>
#include <tins/ethernetII.h>
#include <tins/hw_address.h>
#include <tins/packet_sender.h>
#include <tins/pdu.h>
#include <tins/rawpdu.h>
#include <tins/snap.h>

AccessPoint::AccessPoint(const Tins::HWAddress<6> &bssid, const SSID &ssid,
                         int wifi_channel) {
  this->ssid = ssid;
  this->bssid = bssid;
  this->wifi_channel = wifi_channel;
  std::cout << "New AP found! " << ssid << " with MAC " << bssid
            << " on channel " << wifi_channel << std::endl;
};

bool AccessPoint::handle_pkt(Tins::PDU &pkt) {
  // Note some things about the radiotap header to be able to deauth our clients
  if (pkt.find_pdu<Tins::Dot11QoSData>()) {
    auto radio = pkt.find_pdu<Tins::RadioTap>();
    radio_length = radio->length();
    radio_channel_freq = radio->channel_freq();
    radio_channel_type = radio->channel_type();
    radio_antenna = radio->antenna();
  }

  // Check if this is an authentication packet
  auto dot11 = pkt.rfind_pdu<Tins::Dot11Data>();
  Tins::HWAddress<6> addr = determine_client(dot11);
  if (pkt.find_pdu<Tins::RSNEAPOL>()) {
    if (clients.find(addr) == clients.end())
      clients[addr] = new Client(bssid, ssid, addr);

    clients[addr]->add_handshake(dot11);
    return true;
  }

  // Check if this packet is in our network
  if (addr.is_unicast() && clients.find(addr) == clients.end())
    clients[addr] = new Client(bssid, ssid, addr);

  // Check if the payload is encrypted
  if (!pkt.find_pdu<Tins::RawPDU>() || !dot11.wep())
    return true;

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

    auto snap_clone = pkt.find_pdu<Tins::SNAP>()->clone();
    auto converted = make_eth_packet(pkt.rfind_pdu<Tins::Dot11Data>());
    converted.inner_pdu(snap_clone->release_inner_pdu());
    chan->send(std::unique_ptr<Tins::EthernetII>(converted.clone()));
  }

  captured_packets.push_back(std::unique_ptr<Tins::Dot11Data>(dot11.clone()));
  return true;
};

std::vector<Client *> AccessPoint::get_clients() {
  std::vector<Client *> res;
  for (const auto &pair : clients)
    res.push_back(pair.second);
  return res;
}

std::optional<Client *> AccessPoint::get_client(Tins::HWAddress<6> addr) {
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

    // Decrypted packet, let's put it into the channel
    auto snap_clone = pkt->find_pdu<Tins::SNAP>()->clone();
    auto converted = make_eth_packet(*pkt);
    converted.inner_pdu(snap_clone->release_inner_pdu());
    new_chan->send(std::unique_ptr<Tins::EthernetII>(converted.clone()));
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
      std::cout << "Failed decryption despite possibilities for client: "
                << addr << std::endl;
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

        auto snap_clone = pkt->find_pdu<Tins::SNAP>()->clone();
        auto converted = make_eth_packet(*pkt);
        converted.inner_pdu(snap_clone->release_inner_pdu());
        chan->send(std::unique_ptr<Tins::EthernetII>(converted.clone()));
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

bool AccessPoint::is_psk_correct() { return working_psk; }

void AccessPoint::update_wifi_channel(int i) { wifi_channel = i; };

int AccessPoint::raw_packet_count() { return captured_packets.size(); }

int AccessPoint::decrypted_packet_count() {
  int count = 0;
  for (const auto &pkt : captured_packets)
    if (pkt->find_pdu<Tins::SNAP>())
      count++;
  return count;
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

Tins::EthernetII AccessPoint::make_eth_packet(const Tins::Dot11Data &dot11) {
  if (dot11.from_ds() && !dot11.to_ds()) {
    return Tins::EthernetII(dot11.addr1(), dot11.addr3());
  } else if (!dot11.from_ds() && dot11.to_ds()) {
    return Tins::EthernetII(dot11.addr3(), dot11.addr2());
  } else {
    return Tins::EthernetII(dot11.addr1(), dot11.addr2());
  }
}
