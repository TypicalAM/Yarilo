#include "decrypter.h"
#include "log_sink.h"
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <tins/dot11.h>
#include <tins/rawpdu.h>

using group_window = yarilo::WPA2Decrypter::group_window;
using client_window = yarilo::WPA2Decrypter::client_window;

namespace yarilo {

WPA2Decrypter::WPA2Decrypter(const MACAddress &bssid, const SSID &ssid)
    : bssid(bssid), ssid(ssid) {
  logger = spdlog::get(ssid);
  if (!logger)
    logger = std::make_shared<spdlog::logger>(
        ssid, spdlog::sinks_init_list{
                  global_proto_sink,
                  std::make_shared<spdlog::sinks::stdout_color_sink_mt>()});
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
  if (transmitter == bssid && !data->dst_addr().is_unicast()) {
    return decrypt_group(pkt);
  }

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

group_window WPA2Decrypter::get_current_group_window() const {
  return group_windows.back();
}

std::vector<group_window> WPA2Decrypter::get_all_group_windows() const {
  return group_windows;
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
  auto data = pkt->pdu()->rfind_pdu<Tins::Dot11Data>();
  if (data.wep()) {
    if (!client_windows.count(client) || !client_windows[client].size())
      return true; // Can't generate a PTK for this packet even if we had the
                   // password

    client_window &current_window = client_windows[client].back();
    if (current_window.ended)
      return true;

    if (current_window.decrypted) {
      unicast_decrypter.decrypt(*pkt->pdu());
      auto eapol = pkt->pdu()->find_pdu<Tins::RSNEAPOL>();
      if (eapol) {
        if (eapol->key_t()) {
          logger->warn("Encrypted pairwise handshake detected, ignoring");
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

  if (!client_handshakes.count(client)) {
    if (client_windows.count(client)) {
      logger->info("Handshakes detected on an ongoing window, closing ({})",
                   client.to_string());
      client_window &previous_window = client_windows[client].back();
      previous_window.end = (previous_window.packets.size())
                                ? previous_window.packets.back()->timestamp()
                                : previous_window.start;
      previous_window.ended = true;
    }

    if (key_num.value() != 1) {
      logger->debug(
          "Caught pairwise handshake message {} of 4 ({}) [OUT OF ORDER]",
          key_num.value(), client.to_string());
      return true;
    }

    logger->debug("Caught pairwise handshake message 1 of 4 ({})",
                  client.to_string());
    client_handshakes[client] = {pkt};
    return true;
  }

  std::vector<Tins::Packet *> &handshakes = client_handshakes[client];
  if (handshakes.size() == 4) {
    logger->debug("Caught pairwise handshake message {} of 4 ({}) [EXCESSIVE]",
                  key_num.value(), client.to_string());
    client_handshakes.erase(client);
    if (key_num.value() == 1) {
      logger->debug("Caught pairwise handshake message 1 of 4 ({})",
                    client.to_string());
      client_handshakes[client] = {pkt};
    }
    return true;
  }

  if (key_num.value() != 4) {
    if (key_num.value() - 1 > handshakes.size()) {
      logger->debug("Caught pairwise handshake message {} of 4 ({}) [SKIPPED]",
                    key_num.value(), client.to_string());
      client_handshakes.erase(client);
      return true; // We skipped a message somehow, invalidate the messages
    }

    auto previous_eapol = handshakes.back()->pdu()->rfind_pdu<Tins::RSNEAPOL>();
    if (key_num.value() == handshakes.size()) {
      if (previous_eapol.replay_counter() >= eapol.replay_counter()) {
        logger->debug("Caught group handshake message {} of 4 ({}) [REPLAYED]",
                      key_num.value(), client.to_string());
        return true; // Most likely a transmission error, assume that the
                     // previous packet is correct. The handshakes will be
                     // cleared on auth anyway.
      }

      logger->debug(
          "Caught pairwise handshake message {} of 4 ({}) [RETRANSMISSION]",
          key_num.value(), client.to_string());
      handshakes[key_num.value() - 1] = pkt;
      return true;
    }

    uint8_t prev_key_num = eapol_pairwise_hs_num(previous_eapol).value();
    if (prev_key_num + 1 != key_num.value()) {
      logger->debug("Caught pairwise handshake message {} of 4 ({}) [IGNORING]",
                    key_num.value(), client.to_string());
      return true;
    }

    logger->debug("Caught pairwise handshake message {} of 4 ({})",
                  key_num.value(), client.to_string());
    handshakes.push_back(pkt);
    return true;
  }

  if (handshakes.size() != 3) {
    client_handshakes[client].clear();
    logger->debug(
        "Caught pairwise handshake message 4 of 4 ({}) [OUT OF ORDER]",
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
  logger->debug("Caught pairwise handshake message 4 of 4 ({})",
                client.to_string());
  logger->info("Pairwise handshake complete ({})", client.to_string());
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
                  // Probably a transmission error, not worth keeping
                  // internally

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
      logger->debug("Caught group handshake message 1 of 2 ({}) [REPLAYED]",
                    client.to_string());
      return true; // Most likely a transmission error, assume that the
                   // previous packet is correct. The handshakes will be cleared
                   // on any successful rekey anyway.
    }

    group_rekey_first_messages[target_client] = pkt;
    logger->debug("Caught group handshake message 1 of 2 ({}) [RETRANSMISSION]",
                  client.to_string());
    return true; // Wait for the second handshake to complete on any client
  }

  if (!group_rekey_first_messages.count(target_client)) {
    logger->debug("Caught group handshake message 2 of 2 ({}) [OUT OF ORDER]",
                  client.to_string());
    return true; // We might have missed the first message, too bad! We can only
                 // hope to capture it from another client.
  }

  logger->debug("Caught group handshake message 2 of 2 ({})",
                client.to_string());
  auto prev_pkt = group_rekey_first_messages[target_client];
  auto previous_eapol = prev_pkt->pdu()->rfind_pdu<Tins::RSNEAPOL>();
  if (previous_eapol.replay_counter() < eapol.replay_counter()) {
    logger->debug("Caught group handshake message 2 of 2 ({}) [REPLAYED]",
                  client.to_string());
    return true; // See message 1 replay counter check
  }

  // We must have at least one working PTK, find it
  const ptk_type *ptk;
  for (const auto &[addr, windows] : client_windows)
    if (windows.size())
      for (const auto &window : windows)
        if (window.decrypted)
          ptk = &window.ptk;

  std::optional<gtk_type> gtk = exctract_key_data(previous_eapol, *ptk);
  if (!gtk.has_value())
    return false; // Unable to get the key data from the first message,
                  // handshake did not complete somehow
  logger->info("Exctracted a new group key from a group handshake ({}): {}",
               client.to_string(), readable_hex(gtk.value()));
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
      .gtk = gtk.value(),
  });
  group_rekey_first_messages
      .clear(); // We are sure we have the newest key possible
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
  std::optional<gtk_type> gtk = exctract_key_data(third_eapol, window.ptk);
  if (!gtk.has_value()) {
    logger->error(
        "Failed to exctract GTK key data from 3rd pairwise auth packet");
    return;
  }

  logger->info("Exctracted a new group key from a pairwise handshake ({}): {}",
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
        exctract_key_data(*first_msg, window.ptk);
    if (!rekey_gtk.has_value())
      continue;

    logger->info(
        "Exctracted a new group key from a group handshake ({}) [OLD]: {}",
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
