#include "decrypter.h"
#include <fmt/core.h>
#include <optional>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <sstream>
#include <tins/dot11.h>
#include <tins/eapol.h>
#include <tins/rawpdu.h>

namespace yarilo {

std::string readable_hex(const std::vector<uint8_t> &vec) {
  std::stringstream ss;
  for (uint8_t val : vec)
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(val)
       << " ";
  return ss.str();
}

WPA2Decrypter::WPA2Decrypter(const MACAddress &bssid, const SSID &ssid)
    : bssid(bssid), ssid(ssid) {
  logger = spdlog::get(ssid);
  if (!logger)
    logger = spdlog::stdout_color_mt(ssid);
}

bool WPA2Decrypter::decrypt(Tins::Packet *pkt) {
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

void WPA2Decrypter::add_password(const std::string psk) {
  if (working_psk || !can_decrypt())
    return;

  std::vector<client_window *> complete_handshake_windows;
  for (auto &[addr, windows] : client_windows)
    if (windows.size())
      for (int i = 0; i < windows.size(); i++)
        if (windows[i].auth_packets.size() == 4)
          complete_handshake_windows.push_back(&windows[i]);

  this->psk = psk;
  for (auto window : complete_handshake_windows)
    try_generate_keys(*window);
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
  auto data = pkt->pdu()->rfind_pdu<Tins::Dot11Data>();
  if (data.wep()) {
    if (!client_windows.count(client) || !client_windows[client].size())
      return true; // Can't generate a PTK for this packet even if we had the
                   // password

    client_window current_window = client_windows[client].back();
    if (current_window.ended)
      return true;

    if (current_window.decrypted)
      unicast_decrypter.decrypt(*pkt->pdu());
    current_window.count++;
    current_window.packets.push_back(pkt);
    return true;
  }

  auto eapol = data.find_pdu<Tins::RSNEAPOL>();
  if (!eapol)
    return true;

  std::optional<uint16_t> key_num = eapol_pairwise_hs_num(*eapol);
  if (!key_num.has_value())
    return false; // Unicast EAPOL packet but not a connection handshake?

  if (!client_handshakes.count(client)) {
    if (key_num.value() != 1)
      return true;

    if (client_windows.count(client)) {
      client_window previous_window = client_windows[client].back();
      previous_window.end = (previous_window.packets.size())
                                ? previous_window.packets.back()->timestamp()
                                : previous_window.start;
      previous_window.ended = true;
    }

    logger->info("Caught pairwise handshake message 1 of 4 ({})",
                 client.to_string());
    client_handshakes[client] = {pkt};
    return true;
  }

  std::vector<Tins::Packet *> &handshakes = client_handshakes[client];
  if (handshakes.size() == 4) {
    client_handshakes.erase(client);
    if (key_num.value() == 1)
      client_handshakes[client] = {pkt};
    return true;
  }
  if (key_num.value() != 4) {
    if (key_num.value() - 1 > handshakes.size()) {
      client_handshakes.erase(client);
      return true; // We skipped a message somehow, invalidate the messages
    }

    auto previous_eapol = handshakes.back()->pdu()->rfind_pdu<Tins::RSNEAPOL>();
    if (key_num.value() == handshakes.size()) {
      if (previous_eapol.replay_counter() >= eapol->replay_counter())
        return true; // Most likely a transmission error, assume that the
                     // previous packet is correct. The handshakes will be
                     // cleared on auth anyway.

      logger->info(
          "Caught pairwise handshake message {} of 4 ({}) [RETRANSMISSION]",
          key_num.value(), client.to_string());
      handshakes[key_num.value() - 1] = pkt;
      return true;
    }

    uint8_t prev_key_num = eapol_pairwise_hs_num(previous_eapol).value();
    if (prev_key_num + 1 != key_num.value())
      return true;

    logger->info("Caught pairwise handshake message {} of 4 ({})",
                 key_num.value(), client.to_string());
    handshakes.push_back(pkt);
    return true;
  }

  if (handshakes.size() != 3) {
    client_handshakes[client].clear();
    logger->info(
        "Cleared pairwise handshake queue - out of order transmission ({})",
        client.to_string());
    return true;
  }

  handshakes.push_back(pkt);
  client_window new_window{
      .start = handshakes[0]->timestamp(),
      .client = client,
  };
  for (const auto auth_pkt : handshakes) {
    new_window.packets.push_back(auth_pkt);
    new_window.auth_packets.push_back(auth_pkt);
  }

  client_windows[client].push_back(new_window);
  client_handshakes.erase(client);
  logger->info("Caught pairwise handshake message 4 of 4 ({})",
               client.to_string());
  logger->info("Pairwise handshake complete ({})", client.to_string());
  try_generate_keys(client_windows[client].back());
  return true;
}

void WPA2Decrypter::try_generate_keys(client_window &window) {
  if (!working_psk && psk == "")
    return;

  Tins::Crypto::WPA2Decrypter fake_decrypter;
  fake_decrypter.add_ap_data(psk, ssid, bssid);
  for (auto auth_pkt : window.auth_packets) {
    fake_decrypter.decrypt(*auth_pkt->pdu());
  }
  auto keys = fake_decrypter.get_keys();
  if (!keys.size()) {
    psk = "";
    working_psk = false;
    return;
  }

  working_psk = true;
  window.decrypted = true;
  window.ptk = keys.begin()->second.get_ptk();
  logger->info("Generated a new pairwise key ({}): {}",
               window.client.to_string(), readable_hex(window.ptk));

  auto third_eapol = window.auth_packets[2]->pdu()->rfind_pdu<Tins::RSNEAPOL>();
  std::optional<std::vector<uint8_t>> gtk =
      decrypt_key_data(third_eapol, window.ptk);
  if (!gtk.has_value()) {
    logger->error(
        "Failed to exctract GTK key data from 3rd pairwise auth packet");
    return;
  }

  // TODO: Pass over every encrypted group message to hopefully decrypt it
  group_windows.push_back({
      .start = window.auth_packets[3]->timestamp(),
      .decrypted = true,
      .gtk = gtk.value(),
  });
}

bool WPA2Decrypter::decrypt_group(Tins::Packet *pkt) {
  if (!group_windows.size())
    group_windows.push_back({.start = pkt->timestamp()});

  group_window current_window = group_windows.back();
  auto data = pkt->pdu()->rfind_pdu<Tins::Dot11Data>();
  if (!data.wep()) {
    current_window.count++;
    current_window.packets.push_back(pkt);
    return true; // Not encrypted, no need to sweat
  }

  if (!working_psk) {
    current_window.count++;
    current_window.packets.push_back(pkt);
    return true; // No working password supplied, no chance at decryption yet,
                 // we store in case rekeys do not happen at client connections
                 // and then we could be able to decrypt retrospectively using
                 // using the 3rd message from the pairwise handshake
  }

  auto raw = pkt->pdu()->rfind_pdu<Tins::RawPDU>();
  bool worked = false;
  group_window *working_window = &current_window;
  for (size_t i = group_windows.size(); i-- > 0;) {
    Tins::SNAP *snap = decrypt_group_data(data, raw, group_windows[i].gtk);
    if (!snap)
      continue;

    worked = true;
    data.inner_pdu(snap);
    data.wep(0);
    worked = true;
    working_window = &group_windows[i];
    break;
  }

  auto eapol = pkt->pdu()->find_pdu<Tins::RSNEAPOL>();
  if (!eapol) {
    working_window->packets.push_back(pkt);
    working_window->count++;
    if (working_window->ended) {
      // There might have been a group rekey and not all devices responded with
      // the 2nd handshake, that's why despite maybe having two new EAPOL
      // messages we receive a message with an old key
      working_window->end = pkt->timestamp();
    }

    return true; // Normal packet decrypted using a known key
  }

  std::optional<uint8_t> key_num = eapol_group_hs_num(*eapol);
  if (!key_num.has_value())
    return false; // Protected EAPOL packet but not a group rekey message?
                  // Probably a transmission error, not worth keeping
                  // internally

  MACAddress target_client =
      data.addr3(); // Since the group rekey occurs only when all STA's
                    // (clients) send the second handshake, we still need to
                    // determine the target of the handshake
  if (key_num.value() == 1) {
    if (!group_rekey_first_messages.count(target_client)) {
      group_rekey_first_messages[target_client] = pkt;
      return true; // Wait for the second handshake to complete on any client
    }

    auto previous_eapol = group_rekey_first_messages[target_client]
                              ->pdu()
                              ->rfind_pdu<Tins::RSNEAPOL>();
    if (previous_eapol.replay_counter() >= eapol->replay_counter())
      return true; // Most likely a transmission error, assume that the
                   // previous packet is correct. The handshakes will be cleared
                   // on any successful rekey anyway.

    group_rekey_first_messages[target_client] = pkt;
    return true; // Wait for the second handshake to complete on any client
  }

  if (!group_rekey_first_messages.count(target_client))
    return true; // We might have missed the first message, too bad! We can only
                 // hope to capture it from another client. TODO (maybe): Since
                 // we know we missed they key message on this client, we can
                 // try other clients just for the key

  auto prev_pkt = group_rekey_first_messages[target_client];
  auto previous_eapol = prev_pkt->pdu()->rfind_pdu<Tins::RSNEAPOL>();
  if (previous_eapol.replay_counter() >= eapol->replay_counter())
    return true; // See message 1 replay counter check

  // We must have at least one working PTK, find it
  const std::vector<uint8_t> *ptk;
  for (const auto &[addr, windows] : client_windows)
    if (windows.size())
      for (const auto &window : windows)
        if (window.decrypted)
          ptk = &window.ptk;

  std::optional<std::vector<uint8_t>> gtk =
      decrypt_key_data(previous_eapol, *ptk);
  if (!gtk.has_value())
    return false; // Unable to get the key data from the first message,
                  // handshake did not complete somehow

  current_window.ended = true;
  current_window.end = (current_window.packets.size())
                           ? current_window.packets.back()->timestamp()
                           : current_window.start;
  group_windows.push_back({
      .start = prev_pkt->timestamp(),
      .decrypted = true,
      .packets = {prev_pkt, pkt},
      .auth_packets = {prev_pkt, pkt},
      .gtk = gtk.value(),
  });
  group_rekey_first_messages
      .clear(); // We are sure we have the newest key possible
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
