#include "access_point.h"
#include "client.h"
#include <iostream>
#include <optional>
#include <ostream>
#include <stdexcept>
#include <tins/dot11.h>
#include <tins/eapol.h>
#include <tins/hw_address.h>
#include <tins/pdu.h>

AccessPoint::AccessPoint(const Tins::Dot11Beacon &beacon) {
  ssid = beacon.ssid();
  bssid = beacon.addr3(); // TODO: DS
};

bool AccessPoint::in_network(const Tins::Dot11Data &dot11) {
  return dot11.bssid_addr() == bssid;
}

bool AccessPoint::handle_pkt(const Tins::PDU &pkt) {
  auto dot11 = pkt.rfind_pdu<Tins::Dot11Data>();

  // Check if the user is saved within the network
  Tins::HWAddress<6> addr = determine_client(dot11);
  if (clients.find(addr) == clients.end())
    clients[addr] = new Client(bssid, ssid, addr);

  // Check if this is an authentication packet
  if (dot11.find_pdu<Tins::RSNEAPOL>()) {
    clients[addr]->add_handshake(dot11);
    return true;
  }

  clients[addr]->add_data(dot11);
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

void AccessPoint::add_passwd(const std::string &psk) {
  this->psk = psk;

  for (const auto &[addr, client] : clients) {
    if (!client->can_decrypt())
      continue;

    if (client->try_decrypt(psk))
      std::cout << "Failed decryption despite possibilities for client: "
                << addr << std::endl;
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

  std::cout << "Packet from: " << from << " to " << to << std::endl;
  if (from == bssid)
    return to;
  if (to == bssid)
    return from;

  throw std::runtime_error("incorrect ap identification");
}
