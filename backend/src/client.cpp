#include "client.h"
#include "absl/strings/str_format.h"
#include <iostream>
#include <optional>
#include <spdlog/spdlog.h>
#include <tins/eapol.h>

namespace yarilo {

Client::Client(const Tins::HWAddress<6> &bssid, const SSID &ssid,
               const Tins::HWAddress<6> &addr) {
  logger = spdlog::get(ssid);
  logger->debug("Found new client, addr: {}", addr.to_string());
  this->bssid = bssid;
  this->ssid = ssid;
  this->addr = addr;
};

void Client::add_handshake(const Tins::Dot11Data &dot11) {
  auto eapol = dot11.rfind_pdu<Tins::RSNEAPOL>();
  if (auth_data.size() == 4)
    auth_data = data_queue();

  int key_num = deduce_handshake_num(eapol);
  logger->info("Caught handshake {} out of 4 on {}", key_num, addr.to_string());
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
  if (prev_key_num != key_num - 1 && prev_key_num != key_num) {
    auth_data = data_queue();
    return;
  }

  auth_data.push(dot11.clone());
}

bool Client::can_decrypt() {
  return auth_data.size() == 4; // The decrypter can deduce the network from a
                                // beacon and analyze the 4-way EAPOl handshake
}

std::optional<Tins::Crypto::WPA2Decrypter::keys_map>
Client::try_decrypt(const std::string &psk) {
  if (!can_decrypt()) {
    logger->error("Cannot start decryption on {}", addr.to_string());
    return std::nullopt;
  }

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
    logger->error("Handshakes didn't generate a keypair on {}",
                  addr.to_string());
    return std::nullopt;
  }

  // Transfer the keys to the real decrypter
  logger->info("Handshakes generated a keypair on {}", addr.to_string());
  decrypted = true;
  return fake_decrypter.get_keys();
};

bool Client::is_decrypted() { return decrypted; }

int Client::deduce_handshake_num(Tins::RSNEAPOL &eapol) {
  if (eapol.key_t() && eapol.key_ack() && !eapol.key_mic() && !eapol.install())
    return 1;

  if (eapol.key_t() && !eapol.key_ack() && eapol.key_mic() && !eapol.install())
    return !eapol.secure() ? 2 : 4;

  if (eapol.key_t() && eapol.key_ack() && eapol.key_mic() && eapol.install())
    return 3;

  return 0;
}

Tins::HWAddress<6> Client::get_addr() { return addr; }

int Client::get_key_num() { return auth_data.size(); }

} // namespace yarilo
