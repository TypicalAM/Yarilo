#include "client.h"
#include "decrypter.h"
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

void Client::add_handshake(Tins::PDU &pkt) {
  auto eapol = pkt.rfind_pdu<Tins::RSNEAPOL>();
  if (auth_data.size() == 4)
    auth_data = data_queue();

  int key_num = WPA2Decrypter::eapol_pairwise_hs_num(eapol);
  logger->info("Caught handshake {} out of 4 on {}", key_num, addr.to_string());
  if (key_num == 1) {
    if (!auth_data.empty())
      auth_data = data_queue();
    auth_data.push(pkt.clone());
    return;
  }

  if (auth_data.empty())
    return;

  auto prev_key = auth_data.back();
  int prev_key_num = WPA2Decrypter::eapol_pairwise_hs_num(
      prev_key->rfind_pdu<Tins::RSNEAPOL>());
  if (prev_key_num != key_num - 1 && prev_key_num != key_num) {
    auth_data = data_queue();
    return;
  }

  auth_data.push(pkt.clone());
}

bool Client::can_decrypt() {
  return auth_data.size() == 4; // The decrypter can deduce the network from a
                                // beacon and analyze the 4-way EAPOl handshake
}

std::optional<Client::decryption_keys>
Client::try_decrypt(const std::string &psk) {
  if (!can_decrypt()) {
    logger->error("Cannot start decryption on {}", addr.to_string());
    return std::nullopt;
  }

  WPA2Decrypter fake_decrypter;
  for (int i = 0; i < 4; i++) {
    auto pkt = std::move(auth_data.front());
    auth_data.pop();
    fake_decrypter.add_key_msg(i + 1, *pkt);
    auth_data.push(std::move(pkt));
  }
  fake_decrypter.add_ap_data(psk, ssid, bssid);

  if (fake_decrypter.unicast_keys().size() == 0) {
    logger->error("Handshakes didn't generate a keypair on {}",
                  addr.to_string());
    return std::nullopt;
  }

  // Transfer the keys to the real decrypter
  logger->info("Handshakes generated a keypair on {}", addr.to_string());
  decrypted = true;
  return std::make_pair(fake_decrypter.unicast_keys(),
                        fake_decrypter.group_key());
};

bool Client::is_decrypted() { return decrypted; }

Tins::HWAddress<6> Client::get_addr() { return addr; }

int Client::get_key_num() { return auth_data.size(); }

} // namespace yarilo
