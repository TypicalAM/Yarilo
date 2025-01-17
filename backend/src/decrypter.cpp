#include "decrypter.h"
#include "log_sink.h"
#include <iomanip>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <sstream>
#include <tins/dot11.h>
#include <tins/eapol.h>
#include <tins/rawpdu.h>

using group_window = yarilo::WPA2Decrypter::group_window;
using client_window = yarilo::WPA2Decrypter::client_window;

namespace yarilo {

WPA2Decrypter::WPA2Decrypter(const MACAddress &bssid, const SSID &ssid)
    : bssid(bssid), ssid(ssid) {
  logger = log::get_logger(ssid);
}

bool WPA2Decrypter::decrypt(Tins::Packet *pkt) {
  auto data = pkt->pdu()->find_pdu<Tins::Dot11Data>();
  if (!data)
    return false;

  // NOTE: Why are we judging based on the transmitter and the receiver and not
  // based on the source and destination address? Because we can have local hops
  // in the network - the easiest example would be a client wanting to transmit
  // a broadcast message, despite the destination address being broadcast, the
  // client must encrypt it with PTK (transmitter is client, receiver is AP),
  // send it to the AP, then AP encrypts with GTK (transmitter is AP, receiver
  // == destination == broadcast)
  MACAddress transmitter = data->addr2();
  if (transmitter == bssid && !data->dst_addr().is_unicast())
    return decrypt_group(pkt);

  MACAddress receiver = data->addr1();
  MACAddress client = (transmitter == bssid) ? receiver : transmitter;
  return decrypt_unicast(pkt, client);
}

bool WPA2Decrypter::can_generate_keys() const {
  if (working_psk)
    return true;
  for (const auto &[_, windows] : client_windows)
    if (windows.back().auth_packets.size() == 4)
      return true;
  return false;
}

void WPA2Decrypter::add_password(const std::string &psk) {
  if (working_psk || !can_generate_keys())
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

std::set<MACAddress> WPA2Decrypter::get_clients() const {
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

std::optional<uint8_t>
WPA2Decrypter::get_current_eapol_count(const MACAddress &client) {
  if (!client_handshakes.count(client))
    return std::nullopt;
  return client_handshakes[client].size();
}

group_window WPA2Decrypter::get_current_group_window() const {
  return group_windows.back();
}

std::vector<group_window> WPA2Decrypter::get_all_group_windows() const {
  return group_windows;
}

uint32_t WPA2Decrypter::count_all_group_windows() const {
  return group_windows.size();
}

std::optional<std::string>
WPA2Decrypter::extract_hc22000(const client_window &client) {
  if (client.auth_packets.size() == 0)
    return std::nullopt;

  // Look for PMKID in the first EAPOL message
  auto first_msg = client.auth_packets[0]->pdu()->rfind_pdu<Tins::RSNEAPOL>();
  bool has_pmkid = false;
  std::vector<uint8_t> pmkid(16);
  for (uint8_t i = 0; i < first_msg.wpa_length(); i++) {
    uint8_t tag_number = first_msg.key()[i];
    uint8_t tag_length = first_msg.key()[i + 1];
    if (tag_number != 221) {
      // Jump over this tag
      i += tag_length + 1;
      continue;
    }

    // Last 16 bytes are the PMKID
    for (int j = 0; j < 16; j++)
      pmkid[j] = first_msg.key()[i + tag_length - 14 + j];
    has_pmkid = true;
  }

  // Format: https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2
  std::stringstream ss;
  if (has_pmkid) {
    ss << "WPA*01*";
    ss << readable_hex(pmkid) << "*"; // PMKID field
    ss << readable_hex(std::vector<uint8_t>(bssid.begin(), bssid.end()))
       << "*"; // AP address field
    ss << readable_hex(
              std::vector<uint8_t>(client.client.begin(), client.client.end()))
       << "*"; // Client address field
    ss << readable_hex(std::vector<uint8_t>(ssid.begin(), ssid.end()))
       << "***"; // ESSID field
    ss << "01";  // Message pair bitmask field
  }

  if (client.auth_packets.size() < 2) {
    if (!has_pmkid)
      return std::nullopt;
    return ss.str();
  }

  if (has_pmkid)
    ss << "\n";

  ss << "WPA*02*";
  auto second_msg = client.auth_packets[1]->pdu()->rfind_pdu<Tins::RSNEAPOL>();
  std::vector<uint8_t> mic(second_msg.mic(),
                           second_msg.mic() + second_msg.mic_size);
  ss << readable_hex(mic) << "*"; // Message integrity check field
  ss << readable_hex(std::vector<uint8_t>(bssid.begin(), bssid.end()))
     << "*"; // AP address field
  ss << readable_hex(
            std::vector<uint8_t>(client.client.begin(), client.client.end()))
     << "*"; // Client address field
  ss << readable_hex(std::vector<uint8_t>(ssid.begin(), ssid.end()))
     << "*"; // ESSID field
  ss << readable_hex(
            std::vector<uint8_t>(first_msg.nonce(),
                                 first_msg.nonce() + first_msg.nonce_size))
     << "*"; // AP nonce field
  ss << readable_hex(second_msg.serialize())
     << "*";  // EAPOL 2-nd message serialized
  ss << "02"; // Message pair bitmask field
  return ss.str();
}

std::string WPA2Decrypter::readable_hex(const std::vector<uint8_t> &vec) {
  std::stringstream ss;
  for (uint8_t val : vec)
    ss << std::hex << std::setw(2) << std::setfill('0')
       << static_cast<int>(val);
  return ss.str();
}

bool WPA2Decrypter::decrypt_unicast(Tins::Packet *pkt,
                                    const MACAddress &client) {
  if (client_handshakes.count(client)) {
    time_t first_handshake_ts =
        client_handshakes[client].front()->timestamp().seconds();
    time_t current_packet_ts = pkt->timestamp().seconds();
    if (current_packet_ts - first_handshake_ts > handshake_timeout_seconds) {
      client_handshakes.erase(client);
      logger->warn("Pairwise handshake timeout on {} ({} seconds)",
                   client.to_string(), handshake_timeout_seconds);
    }
  }

  auto data = pkt->pdu()->rfind_pdu<Tins::Dot11Data>();
  if (data.wep()) {
    if (!client_windows.count(client) || !client_windows[client].size())
      return false; // Can't generate a PTK for this packet even if we had the
                    // password

    client_window &current_window = client_windows[client].back();
    if (current_window.ended)
      return false;

    if (current_window.decrypted) {
      unicast_decrypter.decrypt(*pkt->pdu());
      auto eapol = pkt->pdu()->find_pdu<Tins::RSNEAPOL>();
      if (eapol) {
        if (eapol->key_t()) {
          logger->error("Encrypted pairwise handshake detected, ignoring");
          return true;
        }

        return handle_group_eapol(pkt, client);
      }
    }

    current_window.packets.push_back(pkt);
    return true;
  }

  if (data.find_pdu<Tins::RSNEAPOL>())
    return handle_pairwise_eapol(pkt, client);

  return true;
}

bool WPA2Decrypter::handle_pairwise_eapol(Tins::Packet *pkt,
                                          const MACAddress &client) {
  auto data = pkt->pdu()->rfind_pdu<Tins::Dot11Data>();
  auto eapol = data.rfind_pdu<Tins::RSNEAPOL>();
  std::optional<uint16_t> key_num = eapol_pairwise_hs_num(eapol);
  if (!key_num.has_value())
    return false; // Unicast EAPOL packet but not a connection handshake?

  if (client_windows.count(client) && !client_windows[client].back().ended) {
    logger->warn("Handshakes detected on an ongoing window, closing at {}",
                 client.to_string());
    client_window &previous_window = client_windows[client].back();
    previous_window.end = (previous_window.packets.size())
                              ? previous_window.packets.back()->timestamp()
                              : previous_window.start;
    previous_window.ended = true;
  }

  if (!client_handshakes.count(client)) {
    if (key_num.value() != 1) {
      logger->warn(
          "Caught pairwise handshake out of order {} of 4, discarding at {}",
          key_num.value(), client.to_string());
      return true;
    }

    logger->debug("Caught pairwise handshake message 1 of 4 at {}",
                  client.to_string());
    client_handshakes[client] = {pkt};
    return true;
  }

  std::vector<Tins::Packet *> &handshakes = client_handshakes[client];
  if (handshakes.size() == 4) {
    logger->warn("Caught excessive pairwise handshake message {} of 4, "
                 "discarding at {}",
                 key_num.value(), client.to_string());
    client_handshakes.erase(client);
    if (key_num.value() == 1) {
      logger->debug("Caught pairwise handshake message 1 of 4 at {}",
                    client.to_string());
      client_handshakes[client] = {pkt};
    }

    return true;
  }

  if (key_num.value() != 4) {
    if (key_num.value() - 1 > handshakes.size()) {
      logger->warn("Caught skipped pairwise handshake message {} of 4, "
                   "discarding at {}",
                   key_num.value(), client.to_string());
      client_handshakes.erase(client);
      return true; // We couldn't catch the intermittent handshake, invalidate
    }

    auto previous_eapol = handshakes.back()->pdu()->rfind_pdu<Tins::RSNEAPOL>();
    if (key_num.value() == handshakes.size()) {
      // This message is likely
      // 1) Part of a different handshake session
      // 2) Replayed, in which case the replay counter must be higher than the
      // replay counter of the previous message
      if (previous_eapol.replay_counter() >= eapol.replay_counter()) {
        logger->warn("Caught handshake mismatch {} of 4, discarding at {}",
                     key_num.value(), client.to_string());
        client_handshakes.erase(client);

        if (key_num.value() == 1) {
          logger->debug("Caught pairwise handshake message 1 of 4 at {}",
                        client.to_string());
          client_handshakes[client] = {pkt};
        }

        return true;
      }

      logger->debug("Caught replayed pairwise handshake message {} of 4 at {}",
                    key_num.value(), client.to_string());
      handshakes[key_num.value() - 1] = pkt;
      return true;
    }

    uint8_t prev_key_num = eapol_pairwise_hs_num(previous_eapol).value();
    if (prev_key_num + 1 != key_num.value()) {
      logger->warn("Caught out of sequence pairwise handshake message {} of "
                   "4, discarding at {}",
                   key_num.value(), client.to_string());
      client_handshakes.erase(client);
      return true;
    }

    if (key_num.value() == 3) {
      // ANonce should be the same in messages 1 and 3
      auto first_eapol = handshakes.front()->pdu()->rfind_pdu<Tins::RSNEAPOL>();
      for (size_t i = 0; i < first_eapol.nonce_size; i++)
        if (first_eapol.nonce()[i] != eapol.nonce()[i]) {
          logger->warn("Caught pairwise handshake failing nonce check on "
                       "message 3 of 4 at {}",
                       client.to_string());
          client_handshakes.erase(client);
          return true;
        }
    }

    logger->debug("Caught pairwise handshake message {} of 4 at {}",
                  key_num.value(), client.to_string());
    handshakes.push_back(pkt);
    return true;
  }

  if (handshakes.size() != 3) {
    logger->warn(
        "Caught out of order handshake message 4 of 4, discarding at {}",
        client.to_string());
    client_handshakes[client].clear();
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
  logger->debug("Caught pairwise handshake message 4 of 4 at {}",
                client.to_string());
  logger->info("Pairwise handshake complete at {}", client.to_string());
  try_generate_keys(client_windows[client].back());
  return true;
}

bool WPA2Decrypter::handle_group_eapol(Tins::Packet *pkt,
                                       const MACAddress &client) {
  auto data = pkt->pdu()->rfind_pdu<Tins::Dot11Data>();
  auto eapol = data.rfind_pdu<Tins::RSNEAPOL>();
  std::optional<uint8_t> key_num = eapol_group_hs_num(eapol);
  if (!key_num.has_value())
    return false; // Protected EAPOL packet but not a group rekey message?

  MACAddress target_client =
      data.addr3(); // Since the group rekey occurs only when all STA's
                    // (clients) send the second handshake, we still need to
                    // determine the target of the handshake
  if (key_num.value() == 1) {
    if (!group_rekey_first_messages.count(target_client)) {
      group_rekey_first_messages[target_client] = pkt;
      logger->debug("Caught group handshake message 1 of 2 ({})",
                    client.to_string());
      return true; // Wait for the second handshake to complete on any client
    }

    auto previous_eapol = group_rekey_first_messages[target_client]
                              ->pdu()
                              ->rfind_pdu<Tins::RSNEAPOL>();
    if (previous_eapol.replay_counter() >= eapol.replay_counter()) {
      logger->debug("Caught group handshake message 1 of 2"
                    "[HANDSHAKE MISMATCH]",
                    key_num.value(), client.to_string());
      logger->debug("Caught group handshake message 1 of 2 ({})",
                    client.to_string());
      group_rekey_first_messages[target_client] = pkt;
      return true;
    }

    group_rekey_first_messages[target_client] = pkt;
    logger->debug("Caught group handshake message 1 of 2 ({}) [REPLAYED]",
                  client.to_string());
    return true; // Wait for the second handshake to complete on any client
  }

  if (!group_rekey_first_messages.count(target_client)) {
    logger->debug("Caught group handshake message 2 of 2 ({}) [OUT OF ORDER]",
                  client.to_string());
    return true; // We might have missed the first message, too bad! We can
                 // only hope to capture it from another client.
  }

  logger->debug("Caught group handshake message 2 of 2 ({})",
                client.to_string());
  auto prev_pkt = group_rekey_first_messages[target_client];
  auto previous_eapol = prev_pkt->pdu()->rfind_pdu<Tins::RSNEAPOL>();

  // We must have at least one working PTK since we extracted the GTK key data
  bool found = false;
  gtk_type gtk;
  for (const auto &[addr, windows] : client_windows) {
    if (!windows.size())
      continue;

    for (const auto &window : windows) {
      if (!window.decrypted)
        continue;

      std::optional<gtk_type> gtk =
          extract_key_data(previous_eapol, window.ptk);
      if (!gtk.has_value())
        continue;

      found = true;
      gtk = std::move(gtk.value());
    }
  }

  if (!found)
    return false; // Unable to get the key data from the first message,
                  // handshake did not complete somehow
  logger->info("Extracted a new group key from a group handshake ({}): {}",
               client.to_string(), readable_hex(gtk));
  group_window &current_window = group_windows.back();
  current_window.ended = true;
  current_window.end = (current_window.packets.size())
                           ? current_window.packets.back()->timestamp()
                           : current_window.start;
  group_windows.push_back({
      .start = prev_pkt->timestamp(),
      .decrypted = true,
      .packets = {prev_pkt, pkt},
      .auth_packets = {prev_pkt, pkt},
      .gtk = gtk,
  });
  group_rekey_first_messages.clear();
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

  auto addresses = keys.begin()->first;
  auto session_keys = keys.begin()->second;
  unicast_decrypter.add_ap_data(psk, ssid, bssid);
  unicast_decrypter.add_decryption_keys(addresses, session_keys);
  working_psk = true;
  window.decrypted = true;
  window.ptk = session_keys.get_ptk();
  logger->info("Generated a new pairwise key ({}): {}",
               window.client.to_string(), readable_hex(window.ptk));

  // What can we do here
  // We can certainly decrypt any packet in this client window SO FAR
  // There can be group handshakes here, we can also gain a GTK here
  auto third_eapol = window.auth_packets[2]->pdu()->rfind_pdu<Tins::RSNEAPOL>();
  std::optional<gtk_type> gtk = extract_key_data(third_eapol, window.ptk);
  if (!gtk.has_value()) {
    logger->error(
        "Failed to extract GTK key data from 3rd pairwise auth packet");
    return;
  }

  logger->info("Extracted a new group key from a pairwise handshake ({}): {}",
               window.client.to_string(), readable_hex(gtk.value()));
  try_insert_gtk(gtk.value(), window.auth_packets[3]->timestamp());

  Tins::RSNEAPOL *first_msg = nullptr;
  for (auto &pkt : window.packets) {
    auto data = pkt->pdu()->find_pdu<Tins::Dot11Data>();
    if (!data || !data->wep())
      continue;

    bool decrypted = unicast_decrypter.decrypt(*pkt->pdu());
    if (!decrypted)
      continue;

    auto eapol = pkt->pdu()->find_pdu<Tins::RSNEAPOL>();
    if (!eapol)
      continue;

    if (eapol->key_t()) {
      logger->warn("Encrypted pairwise handshake detected, ignoring");
      continue;
    }

    std::optional<uint8_t> key_num = eapol_group_hs_num(*eapol);
    if (!key_num.has_value())
      continue;

    if (key_num.value() == 1) {
      if (!first_msg) {
        first_msg = eapol;
        logger->debug("Caught group handshake message 1 of 2 ({}) [OLD]",
                      window.client.to_string());
        continue;
      }

      if (first_msg->replay_counter() >= eapol->replay_counter()) {
        logger->debug(
            "Caught group handshake message 1 of 2 ({}) [OLD] [REPLAYED]",
            window.client.to_string());
        continue;
      }

      first_msg = eapol;
      logger->debug(
          "Caught group handshake message 1 of 2 ({}) [OLD] [RETRANSMISSION]",
          window.client.to_string());
      continue;
    }

    if (!first_msg) {
      logger->debug(
          "Caught group handshake message 2 of 2 ({}) [OLD] [OUT OF ORDER]",
          window.client.to_string());
      continue;
    }

    logger->debug("Caught group handshake message 2 of 2 ({}) [OLD]",
                  window.client.to_string());
    std::optional<gtk_type> rekey_gtk =
        extract_key_data(*first_msg, window.ptk);
    if (!rekey_gtk.has_value())
      continue;

    logger->info(
        "Extracted a new group key from a group handshake ({}) [OLD]: {}",
        window.client.to_string(), readable_hex(rekey_gtk.value()));
    try_insert_gtk(rekey_gtk.value(), pkt->timestamp());
  }
}

bool WPA2Decrypter::decrypt_group(Tins::Packet *pkt) {
  if (!group_windows.size())
    group_windows.push_back({.start = pkt->timestamp()});

  group_window &current_window = group_windows.back();
  auto data = pkt->pdu()->rfind_pdu<Tins::Dot11Data>();
  if (!data.wep()) {
    current_window.packets.push_back(pkt);
    return true; // Not encrypted, no need to sweat
  }

  if (!working_psk) {
    current_window.packets.push_back(pkt);
    return true; // No working password supplied, no chance at decryption yet,
                 // we store in case rekeys do not happen at client
                 // connections and then we could be able to decrypt
                 // retrospectively using using the 3rd message from the
                 // pairwise handshake
  }

  auto raw = pkt->pdu()->rfind_pdu<Tins::RawPDU>();
  group_window &working_window = current_window;
  for (size_t i = group_windows.size(); i-- > 0;) {
    if (!group_windows[i].decrypted)
      continue;

    Tins::SNAP *snap = decrypt_group_data(data, raw, group_windows[i].gtk);
    if (!snap)
      continue;

    data.inner_pdu(snap);
    data.wep(0);
    working_window = group_windows[i];
    break;
  }

  working_window.packets.push_back(pkt);
  if (working_window.ended) {
    // There might have been a group rekey and not all devices responded with
    // the 2nd handshake, that's why despite maybe having two new EAPOL
    // messages we receive a message with an old key
    working_window.end = pkt->timestamp();
  }
  return true; // Normal packet decrypted using a known key
}

void WPA2Decrypter::try_insert_gtk(const gtk_type &gtk,
                                   const Tins::Timestamp &ts) {
  std::vector<group_window *> non_decrypted_windows;
  for (int i = 0; i < group_windows.size(); i++)
    if (!group_windows[i].decrypted)
      non_decrypted_windows.push_back(&group_windows[i]);

  if (!non_decrypted_windows.size()) {
    if (group_windows.size()) {
      group_window &latest_window = group_windows.back();
      latest_window.ended = true;
      latest_window.end = ts;
    }

    group_windows.push_back({.start = ts, .decrypted = true, .gtk = gtk});
    return;
  }

  for (int i = 0; i < non_decrypted_windows.size(); i++) {
    group_window *oldest = non_decrypted_windows[i];
    int window_start_idx = -1;
    int window_end_idx = -1;
    for (int i = 0; i < oldest->packets.size(); i++) {
      auto data = oldest->packets[i]->pdu()->find_pdu<Tins::Dot11Data>();
      if (!data || !data->wep())
        continue;

      auto raw = data->rfind_pdu<Tins::RawPDU>();
      Tins::SNAP *snap = decrypt_group_data(*data, raw, gtk);
      if (!snap) {
        if (window_start_idx == -1)
          continue;
        window_end_idx = i;
        break;
      }

      data->inner_pdu(snap);
      data->wep(0);
      if (window_start_idx == -1)
        window_start_idx = i;
    }
    logger->trace("Window started at {} and ended at {}", window_start_idx,
                  window_end_idx);

    if (window_start_idx == -1)
      continue;

    if (window_end_idx == -1) {
      logger->debug("Ongoing range group window decryption from {}",
                    oldest->start.seconds());
      oldest->decrypted = true;
      oldest->gtk = gtk;
      return;
    }

    if (window_start_idx == 0 && window_end_idx == oldest->packets.size() - 1) {
      logger->trace("Full range group window decryption between {} and {}",
                    oldest->start.seconds(), oldest->end.seconds());
      oldest->decrypted = true;
      oldest->gtk = gtk;
      return;
    }

    // TODO: started = 0, end early, started late, end == size, needs testing
  }
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
