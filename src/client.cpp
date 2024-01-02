#include "client.h"
#include <iostream>
#include <tins/eapol.h>

Client::Client(const Tins::HWAddress<6> &bssid, const SSID &ssid,
               const Tins::HWAddress<6> &addr) {
  this->bssid = bssid;
  this->ssid = ssid;
  this->addr = addr;
};

void Client::add_data(Tins::Dot11Data &dot11) {
  if (!decrypted) {
    raw_data.push(dot11.clone());
    return;
  }

  bool success = decrypter.decrypt(dot11);
  if (!success)
    return;

  auto snap = dot11.rfind_pdu<Tins::SNAP>();
  auto converted = make_eth_packet(dot11);
  converted.inner_pdu(snap.release_inner_pdu());
  channel->send(converted.clone());
};

void Client::add_handshake(const Tins::Dot11Data &dot11) {
  auto eapol = dot11.rfind_pdu<Tins::RSNEAPOL>();
  if (auth_data.size() == 4)
    auth_data = data_queue();

  int key_num = deduce_handshake_num(eapol);
  std::cout << ssid << " caught handshake: " << key_num << " out of 4 "
            << std::endl;
  if (key_num == 1) {
    if (!auth_data.empty())
      auth_data = data_queue();
    auth_data.push(dot11.clone());
    return;
  }

  if (auth_data.empty())
    return;

  auto prev_key = auth_data.back();
  int prev_key_num =
      deduce_handshake_num(prev_key->rfind_pdu<Tins::RSNEAPOL>());
  if (prev_key_num != key_num - 1) {
    auth_data = data_queue();
    return;
  }

  auth_data.push(dot11.clone());
}

bool Client::can_decrypt() {
  return auth_data.size() == 4; // The decrypter can deduce the network from a
                                // beacon and analyze the 4-way EAPOl handshake
}

bool Client::try_decrypt(const std::string &psk) {
  if (!can_decrypt()) // lol
    return false;

  // We create a fake decrypter to make sure the handshake & PSK create
  // a valid keypair! We will transfer the keys in a while.
  Tins::Crypto::WPA2Decrypter fake_decrypter;
  fake_decrypter.add_ap_data(psk, ssid, bssid);

  for (int i = 0; i < 4; i++) {
    Tins::Dot11Data *pkt = std::move(auth_data.front());
    auth_data.pop();
    fake_decrypter.decrypt(*pkt);
    auth_data.push(std::move(pkt));
  }

  if (fake_decrypter.get_keys().size() == 0) {
    std::cout << "Handshakes didn't generate a keypair for ssid: " << ssid
              << std::endl;
    return false;
  }

  // Transfer the keys to the real decrypter
  // TODO: Cleanup the handshakes and stuff
  decrypted = true;
  auto keys = fake_decrypter.get_keys().begin();
  decrypter.add_decryption_keys(keys->first, keys->second);

  // Convert all the old packets lol
  while (!raw_data.empty()) {
    auto pkt = *std::move(raw_data.front());
    if (!decrypter.decrypt(pkt)) {
      raw_data.pop();
      continue;
    }

    auto dot11 = pkt.rfind_pdu<Tins::Dot11Data>();
    auto snap = pkt.rfind_pdu<Tins::SNAP>();
    auto converted = make_eth_packet(dot11);
    converted.inner_pdu(snap.release_inner_pdu());
    channel->send(converted.clone());
    raw_data.pop();
  }

  return true;
};

Channel<Tins::EthernetII *> *Client::get_channel() { return channel; }

bool Client::is_decrypted() { return decrypted; }

int Client::deduce_handshake_num(Tins::RSNEAPOL &rsn) {
  if (rsn.replay_counter() == 0) {
    return rsn.key_mic() == 0 ? 1 : 2;
  }

  for (int i = 0; i < rsn.nonce_size; i++)
    if (rsn.nonce()[i] != 0)
      return 3;

  return 4;
}

Tins::EthernetII Client::make_eth_packet(const Tins::Dot11Data &dot11) {
  if (dot11.from_ds() && !dot11.to_ds()) {
    return Tins::EthernetII(dot11.addr1(), dot11.addr3());
  } else if (!dot11.from_ds() && dot11.to_ds()) {
    return Tins::EthernetII(dot11.addr3(), dot11.addr2());
  } else {
    return Tins::EthernetII(dot11.addr1(), dot11.addr2());
  }
}
