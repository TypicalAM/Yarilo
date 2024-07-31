#include "decrypter.h"
#include <fmt/core.h>
#include <optional>
#include <tins/dot11.h>
#include <tins/eapol.h>
#include <tins/rawpdu.h>

namespace yarilo {

WPA2Decrypter::WPA2Decrypter(const MACAddress &bssid, const SSID &ssid)
    : bssid(bssid), ssid(ssid) {}

bool WPA2Decrypter::decrypt(Tins::Packet *pkt) {
  // TODO: Support mgmt frames
  auto data = pkt->pdu()->find_pdu<Tins::Dot11Data>();
  if (!data)
    return false;

  MACAddress src;
  MACAddress dst;
  if (data->from_ds() && !data->to_ds()) {
    dst = data->addr1();
    src = data->addr3();
  } else if (!data->from_ds() && data->to_ds()) {
    dst = data->addr3();
    src = data->addr2();
  } else {
    dst = data->addr1();
    src = data->addr2();
  }

  if (!src.is_unicast() || !dst.is_unicast())
    return decrypt_group(pkt);

  MACAddress client = (dst == bssid) ? src : dst;
  return decrypt_unicast(pkt, client);
}

bool WPA2Decrypter::can_decrypt() const {
  if (working_psk)
    return true;
  for (const auto &[_, windows] : client_windows)
    if (windows.back().auth_packets.size() == 4)
      return true;
  return false;
}

bool WPA2Decrypter::add_password(const std::string psk) {
  // TODO
  return false;
}

bool WPA2Decrypter::has_working_password() const { return working_psk; }

std::optional<std::string> WPA2Decrypter::get_password() const {
  if (psk == "")
    return std::nullopt;
  return psk;
}

std::set<MACAddress> WPA2Decrypter::get_clients() {
  std::set<MACAddress> clients;
  for (const auto &[client, _] : client_windows)
    clients.insert(client);
  return clients;
}

std::optional<client_window>
WPA2Decrypter::get_current_client_window(const MACAddress &client) {
  if (!client_windows.count(client))
    return std::nullopt;
  return client_windows[client].back();
}

std::optional<std::vector<client_window>>
WPA2Decrypter::get_all_client_windows(const MACAddress &client) {
  if (!client_windows.count(client))
    return std::nullopt;
  return client_windows[client];
}

group_window WPA2Decrypter::get_current_group_window() const {
  return group_windows.back();
}

std::vector<group_window> WPA2Decrypter::get_all_group_windows() const {
  return group_windows;
}

bool WPA2Decrypter::decrypt_unicast(Tins::Packet *pkt,
                                    const MACAddress &client) {
  // todo
  return true;
}

bool WPA2Decrypter::decrypt_group(Tins::Packet *pkt) {
  // todo
  return true;
}

std::optional<uint8_t>
WPA2Decrypter::eapol_pairwise_hs_num(const Tins::RSNEAPOL &eapol) {
  if (eapol.key_t() && eapol.key_ack() && !eapol.key_mic() && !eapol.install())
    return 1;
  if (eapol.key_t() && !eapol.key_ack() && eapol.key_mic() && !eapol.install())
    return !eapol.secure() ? 2 : 4;
  if (eapol.key_t() && eapol.key_ack() && eapol.key_mic() && eapol.install())
    return 3;
  return std::nullopt;
}

std::optional<uint8_t>
WPA2Decrypter::eapol_group_hs_num(const Tins::RSNEAPOL &eapol) {
  if (!eapol.key_t() && eapol.encrypted() && eapol.key_ack())
    return 1;
  if (!eapol.key_t() && !eapol.encrypted() && !eapol.key_ack())
    return 2;
  return std::nullopt;
}

} // namespace yarilo
