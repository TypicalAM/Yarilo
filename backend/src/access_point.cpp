#include "access_point.h"
#include "channel.h"
#include "client.h"
#include <iostream>
#include <optional>
#include <ostream>
#include <stdexcept>
#include <tins/dot11.h>
#include <tins/eapol.h>
#include <tins/ethernetII.h>
#include <tins/hw_address.h>
#include <tins/pdu.h>
#include <tins/snap.h>

AccessPoint::AccessPoint(const Tins::Dot11Beacon &beacon) {
  ssid = beacon.ssid();
  bssid = beacon.addr3(); // TODO: DS
  wifi_channel = 0;       // TODO
  converted_channel = new Channel<Tins::EthernetII *>;
  std::cout << "New AP found! " << ssid << " with MAC " << bssid << std::endl;
};

AccessPoint::AccessPoint(const Tins::Dot11ProbeResponse &probe_resp) {
  ssid = probe_resp.ssid();
  bssid = probe_resp.addr3();
  wifi_channel = 0;
  converted_channel = new Channel<Tins::EthernetII *>;
  std::cout << "New AP found! " << ssid << " with MAC " << bssid << std::endl;
};

bool AccessPoint::in_network(const Tins::Dot11Data &dot11) {
  return dot11.bssid_addr() == bssid;
}

bool AccessPoint::handle_pkt(Tins::PDU &pkt) {
  auto dot11 = pkt.rfind_pdu<Tins::Dot11Data>();

  // Check if this is an authentication packet
  if (dot11.find_pdu<Tins::RSNEAPOL>()) {
    Tins::HWAddress<6> addr = determine_client(dot11);
    if (clients.find(addr) == clients.end())
      clients[addr] = new Client(bssid, ssid, addr);

    clients[addr]->add_handshake(dot11);
    return true;
  }

  // Try to decrypt the packet
  bool success = decrypter.decrypt(pkt);
  if (!success) {
    raw_data.push(dot11.clone());
    return true;
  }

  auto snap = pkt.rfind_pdu<Tins::SNAP>();
  auto converted = make_eth_packet(dot11);
  converted.inner_pdu(snap.release_inner_pdu());
  converted_channel->send(converted.clone());
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

void AccessPoint::add_passwd(const std::string &psk) {
  this->psk = psk;

  for (const auto &[addr, client] : clients) {
    if (!client->can_decrypt())
      continue;

    auto keys = client->try_decrypt(psk);
    if (!keys.has_value()) {
      std::cout << "Failed decryption despite possibilities for client: "
                << addr << std::endl;
      continue;
    }

    decrypter.add_decryption_keys(keys->begin()->first, keys->begin()->second);

    // TODO: I know this sucks
    int q_size = raw_data.size();
    int i = 0;
    while (!raw_data.empty()) {
      Tins::Dot11Data *pkt = std::move(raw_data.front());
      raw_data.pop();

      if (!decrypter.decrypt(*pkt)) {
        // We didn't decrypt, push the packet back
        raw_data.push(std::move(pkt));
      } else {
        // Decrypted
        auto snap = pkt->rfind_pdu<Tins::SNAP>();
        auto converted = make_eth_packet(pkt->rfind_pdu<Tins::Dot11Data>());
        converted.inner_pdu(snap.release_inner_pdu());
        converted_channel->send(converted.clone());
      }

      i++;
      if (i == q_size)
        break;
    }
  }
};

Tins::HWAddress<6> AccessPoint::determine_client(const Tins::Dot11Data &dot11) {
  Tins::HWAddress<6> from;
  Tins::HWAddress<6> to;

  if (dot11.from_ds() && !dot11.to_ds()) {
    from = dot11.addr1();
    to = dot11.addr3();
  } else if (!dot11.from_ds() && dot11.to_ds()) {
    from = dot11.addr3();
    to = dot11.addr2();
  } else {
    from = dot11.addr1();
    to = dot11.addr2();
  }

  if (from == bssid)
    return to;
  if (to == bssid)
    return from;

  throw std::runtime_error("incorrect ap identification");
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
