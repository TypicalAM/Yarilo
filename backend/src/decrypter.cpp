#include "decrypter.h"
#include "group_decrypter.h"
#include <fmt/core.h>
#include <optional>
#include <tins/dot11.h>
#include <tins/eapol.h>

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
  for (const auto &[_, windows] : client_windows)
    if (windows.back().auth_packets.size() == 4)
      return true;
  return false;
}

bool WPA2Decrypter::add_password(const std::string psk) {
  bool worked = false;
  for (const auto &[client, windows] : client_windows)
    if (windows.back().auth_packets.size() == 4 && try_generate_keys(client))
      return true;
  return worked;
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
  if (client_windows.count(client) == 0)
    client_windows[client].push_back(
        {.start = pkt->timestamp(), .client = client});

  auto data = pkt->pdu()->rfind_pdu<Tins::Dot11Data>();
  auto eapol = data.find_pdu<Tins::RSNEAPOL>();
  if (!eapol) {
    client_window current_window = client_windows[client].back();
    current_window.count++;
    current_window.packets.push_back(pkt);
    return unicast_decrypter.decrypt(*pkt->pdu());
  }

  // We have an EAPOL packet, it can start a new window
  std::optional<uint8_t> key_num = eapol_pairwise_hs_num(*eapol);
  if (!key_num.has_value())
    return false;

  client_window current_window = client_windows[client].back();
  bool correct = client_hs_sequence_correct(current_window, pkt);
  if (!correct) {
    // New window has to be created, we broke the last one
    current_window.end = current_window.packets.back()->timestamp();
    current_window.ended = true;
    client_windows[client].push_back({
        .start = pkt->timestamp(),
        .count = 1,
        .client = client,
        .packets = {pkt},
        .auth_packets = {pkt},
    });
    return true;
  }

  current_window.count++;
  current_window.packets.push_back(pkt);
  if (eapol_pairwise_hs_num(*eapol) != 4)
    return true;

  if (psk != "")
    return try_generate_keys(client); // If we have a password candidate we
                                      // should try to generate keys
  return true;
}

bool WPA2Decrypter::decrypt_group(Tins::Packet *pkt) {
  if (!group_windows.size()) {
    group_windows.push_back({.start = pkt->timestamp()});
    return true;
  }

  group_window current_window = group_windows.back();
  bool decrypted = group_decrypter.decrypt(*pkt->pdu());
  if (!decrypted) {
    current_window.count++;
    current_window.packets.push_back(pkt);
    return true;
  }

  auto eapol = pkt->pdu()->find_pdu<Tins::RSNEAPOL>();
  if (!eapol) {
    current_window.count++;
    current_window.packets.push_back(pkt);
    return true;
  }

  std::optional<uint8_t> key_num = eapol_group_hs_num(*eapol);
  if (key_num.has_value())
    return false;

  bool correct = group_hs_sequence_correct(current_window, pkt);
  if (!correct) {
    current_window.end = current_window.packets.back()->timestamp();
    current_window.ended = true;
    group_windows.push_back({
        .start = pkt->timestamp(),
        .count = 1,
        .packets = {pkt},
        .auth_packets = {pkt},
    });
    return true;
  }

  std::vector<uint8_t> ptk;
  for (const auto &[_, windows] : client_windows)
    if (windows.back().auth_packets.size() == 4)
      ptk = windows.back().ptk;
  if (!group_decrypter.ccmp_decrypt_key_data(*eapol, ptk))
    return false; // Incorrect KEK
  current_window.gtk = group_decrypter.gtk();
  current_window.auth_packets.push_back(pkt);
  return true;
}

bool WPA2Decrypter::client_hs_sequence_correct(const client_window &window,
                                               Tins::Packet *pkt) const {
  auto eapol = pkt->pdu()->find_pdu<Tins::RSNEAPOL>();
  std::optional<uint8_t> key_num = eapol_pairwise_hs_num(*eapol);
  if (key_num.has_value())
    return false;

  if (key_num == 1)
    return window.auth_packets.size() == 0;

  if (window.auth_packets.size() != key_num.value() - 1)
    return false;

  for (int i = 0; i < key_num; i++) {
    auto previous_eapol =
        window.auth_packets[i]->pdu()->find_pdu<Tins::RSNEAPOL>();
    if (!previous_eapol)
      return false;
    std::optional<uint8_t> previous_key_num =
        eapol_pairwise_hs_num(*previous_eapol);
    if (!previous_key_num.has_value() || i + 1 != previous_key_num.value())
      return false;
  }

  return true;
}

bool WPA2Decrypter::group_hs_sequence_correct(const group_window &window,
                                              Tins::Packet *pkt) const {
  auto eapol = pkt->pdu()->find_pdu<Tins::RSNEAPOL>();
  std::optional<uint8_t> key_num = eapol_group_hs_num(*eapol);
  if (key_num.has_value())
    return false;

  if (key_num == 1)
    return window.auth_packets.size() == 0;

  if (window.auth_packets.size() != 1)
    return false;

  auto previous_eapol =
      window.auth_packets[0]->pdu()->find_pdu<Tins::RSNEAPOL>();
  if (!previous_eapol)
    return false;

  std::optional<uint8_t> previous_key_num = eapol_group_hs_num(*previous_eapol);
  if (!previous_key_num.has_value() || previous_key_num != 1)
    return false;
  return true;
}

bool WPA2Decrypter::try_generate_keys(const MACAddress &client) {
  client_window current_window = client_windows[client].back();
  if (current_window.auth_packets.size() != 4)
    return false;

  Tins::Crypto::WPA2Decrypter fake_decrypter;
  fake_decrypter.add_ap_data(psk, ssid, bssid);
  for (const auto &auth_pkt : current_window.auth_packets)
    fake_decrypter.decrypt(*auth_pkt->pdu());
  Tins::Crypto::WPA2Decrypter::keys_map keys = fake_decrypter.get_keys();
  if (keys.size() == 0)
    return false; // Wrong PSK

  working_psk = true;
  unicast_decrypter.add_ap_data(psk, ssid, bssid);
  unicast_decrypter.add_decryption_keys(keys.begin()->first,
                                        keys.begin()->second);
  current_window.ptk = keys.begin()->second.get_ptk();

  auto third_pkt =
      current_window.auth_packets[2]->pdu()->find_pdu<Tins::RSNEAPOL>();
  bool success =
      group_decrypter.ccmp_decrypt_key_data(*third_pkt, current_window.ptk);
  if (!success)
    return true; // No key in the third message

  std::vector<uint8_t> gtk = group_decrypter.gtk();
  group_window current_group_window = group_windows.back();
  if (current_group_window.gtk == gtk)
    return true; // TODO: Can we compare vec<uint8>?
  current_group_window.end =
      (current_group_window.packets.size())
          ? current_group_window.packets.back()->timestamp()
          : current_group_window.start;
  current_group_window.ended = true;
  group_windows.push_back({
      .start = current_window.auth_packets[0]->timestamp(),
      .gtk = gtk,
  });
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
