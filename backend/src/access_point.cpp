#include "access_point.h"
#include "channel.h"
#include "client.h"
#include <iostream>
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
  converted_channel = new Channel<Tins::EthernetII *>;
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
  if (!decrypter.decrypt(pkt)) {
    encrypted_data.push(dot11.clone());
  } else {
    auto snap = pkt.rfind_pdu<Tins::SNAP>();
    auto converted = make_eth_packet(dot11);
    converted.inner_pdu(snap.release_inner_pdu());
    converted_channel->send(converted.clone());
  }

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

Channel<Tins::EthernetII *> *AccessPoint::get_channel() {
  return converted_channel;
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

    while (!encrypted_data.empty()) {
      Tins::Dot11Data *pkt = std::move(encrypted_data.front());
      encrypted_data.pop();

      if (decrypter.decrypt(*pkt)) {
        // Decrypted
        auto snap = pkt->rfind_pdu<Tins::SNAP>();
        auto converted = make_eth_packet(pkt->rfind_pdu<Tins::Dot11Data>());
        converted.inner_pdu(snap.release_inner_pdu());
        converted_channel->send(converted.clone());
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

int AccessPoint::raw_packet_count() { return encrypted_data.size(); }

int AccessPoint::decrypted_packet_count() {
  return encrypted_data.size();
} // TODO

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
