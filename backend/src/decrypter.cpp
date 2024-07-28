#include "decrypter.h"
#include "client.h"
#include <fmt/core.h>
#include <tins/eapol.h>
#include <utility>

namespace yarilo {

bool WPA2Decrypter::decrypt(Tins::PDU &pdu) {
  auto dot11 = pdu.find_pdu<Tins::Dot11Data>();
  if (!dot11)
    return false;

  Tins::HWAddress<6> src;
  Tins::HWAddress<6> dst;
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

  if (src.is_unicast() && dst.is_unicast())
    return unicast_decrypter.decrypt(pdu);

  return group_decrypter.decrypt(pdu);
}

void WPA2Decrypter::add_key_msg(int num, const Tins::PDU &pdu) {
  // TODO: Invalidate any differing session handshakes
  auto eapol = pdu.find_pdu<Tins::RSNEAPOL>();
  if (!eapol)
    return;
  if (num > 4 || eapol_pairwise_hs_num(*eapol) != num)
    return;
  handshakes[num - 1] = pdu.clone();
  return;
}

void WPA2Decrypter::add_group_key_msg(int num, const Tins::PDU &pdu) {
  auto eapol = pdu.find_pdu<Tins::RSNEAPOL>();
  if (!eapol)
    return;

  if (num != eapol_pairwise_hs_num(*eapol))
    return;

  group_decrypter.add_handshake(num, pdu);
}

int WPA2Decrypter::key_msg_count() const {
  for (int i = 0; i < 4; i++)
    if (!handshakes[i])
      return i;
  return 4;
}

void WPA2Decrypter::add_ap_data(const std::string &psk, SSID ssid,
                                Tins::HWAddress<6> bssid) {
  this->psk = psk;
  unicast_decrypter.add_ap_data(psk, ssid, bssid);

  // If we have 4 handshakes, we can try to generate unicast and
  // broadcast/multicast keys
  // TODO: Same when adding a new handshake
  if (key_msg_count() != 4)
    return;

  unicast_keys_map keys = unicast_decrypter.get_keys();
  unicast_decrypter.decrypt(*handshakes[0]->clone());
  unicast_decrypter.decrypt(*handshakes[1]->clone());
  unicast_decrypter.decrypt(*handshakes[2]->clone());
  unicast_decrypter.decrypt(*handshakes[3]->clone());
  unicast_keys_map new_keys = unicast_decrypter.get_keys();
  if (new_keys.size() != keys.size() + 1)
    return;

  std::pair<unicast_addr_pair, unicast_session_keys> new_key;
  for (const auto &[addr, session_keys] : new_keys)
    if (keys.find(addr) == keys.end()) {
      new_key = std::make_pair(addr, session_keys);
      break;
    }

  auto third_handshake = *handshakes[2]->find_pdu<Tins::RSNEAPOL>();
  working_psk = group_decrypter.ccmp_decrypt_key_data(third_handshake,
                                                      new_key.second.get_ptk());
}

void WPA2Decrypter::add_group_key(const WPA2Decrypter::gtk_type &key) {
  group_decrypter.add_gtk(key);
}

WPA2Decrypter::gtk_type WPA2Decrypter::group_key() const {
  return group_decrypter.gtk();
}

void WPA2Decrypter::add_unicast_keys(const unicast_addr_pair &addresses,
                                     const unicast_session_keys &session_keys) {
  unicast_decrypter.add_decryption_keys(addresses, session_keys);
}

WPA2Decrypter::unicast_keys_map WPA2Decrypter::unicast_keys() const {
  return unicast_decrypter.get_keys();
}

int WPA2Decrypter::eapol_pairwise_hs_num(const Tins::RSNEAPOL &eapol) {
  if (eapol.key_t() && eapol.key_ack() && !eapol.key_mic() && !eapol.install())
    return 1;

  if (eapol.key_t() && !eapol.key_ack() && eapol.key_mic() && !eapol.install())
    return !eapol.secure() ? 2 : 4;

  if (eapol.key_t() && eapol.key_ack() && eapol.key_mic() && eapol.install())
    return 3;

  return 0;
}

int WPA2Decrypter::eapol_group_hs_num(const Tins::RSNEAPOL &eapol) {
  if (!eapol.key_t() && eapol.encrypted() && eapol.key_ack())
    return 1;

  if (!eapol.key_t() && !eapol.encrypted() && !eapol.key_ack())
    return 2;

  return 0;
}

} // namespace yarilo
