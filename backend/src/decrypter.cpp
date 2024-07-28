#include "decrypter.h"
#include <fmt/core.h>
#include <tins/dot11.h>
#include <tins/eapol.h>

namespace yarilo {

WPA2Decrypter::WPA2Decrypter(const MACAddress &bssid, const SSID &ssid)
    : bssid(bssid), ssid(ssid) {}

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

  // Method implementation
  return false;
}

// Password related
bool WPA2Decrypter::can_decrypt() const {
  // Method implementation
  return false;
}

bool WPA2Decrypter::add_password(const std::string psk) {
  // Method implementation
  return false;
}

bool WPA2Decrypter::has_working_password() const {
  // Method implementation
  return false;
}

std::optional<std::string> WPA2Decrypter::get_password() const {
  // Method implementation
  return std::nullopt;
}

// Clients
std::set<MACAddress> WPA2Decrypter::get_clients() {
  // Method implementation
  return {};
}

// Windows
std::optional<client_window>
WPA2Decrypter::get_current_client_window(const MACAddress &client) const {
  // Method implementation
  return std::nullopt;
}

std::optional<std::vector<client_window>>
WPA2Decrypter::get_all_client_windows(const MACAddress &client) const {
  // Method implementation
  return std::nullopt;
}

group_window WPA2Decrypter::get_current_group_window() const {
  // Method implementation
  return group_window();
}

std::vector<group_window> WPA2Decrypter::get_all_group_windows() const {
  // Method implementation
  return {};
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
