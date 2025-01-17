#include "sniffer.h"
#include "access_point.h"
#include "decrypter.h"
#include "log_sink.h"
#include "net_card_manager.h"
#include "recording.h"
#include <absl/strings/str_format.h>
#include <memory>
#include <net/if.h>
#include <optional>
#include <spdlog/spdlog.h>
#include <string>
#include <tins/packet.h>
#include <tins/sniffer.h>

using phy_info = yarilo::NetCardManager::phy_info;
using iface_state = yarilo::NetCardManager::iface_state;
using recording_info = yarilo::Recording::info;
using DataLinkType = yarilo::Recording::DataLinkType;

namespace yarilo {

MACAddress Sniffer::NoAddress("00:00:00:00:00:00");

Sniffer::Sniffer(std::unique_ptr<Tins::FileSniffer> sniffer,
                 const std::filesystem::path &filepath, Database &db)
    : db(db) {
  logger = log::get_logger(filepath.stem().string());
  this->sniffer = std::move(sniffer);
  this->finished = false;
  this->filepath = filepath;
}

Sniffer::Sniffer(std::unique_ptr<Tins::Sniffer> sniffer,
                 const Tins::NetworkInterface &iface, Database &db)
    : db(db) {
  logger = log::get_logger(iface.name());
  this->send_iface = iface;
  this->iface_name = iface.name();
  this->filemode = false;
  this->sniffer = std::move(sniffer);
  this->finished = false;
  this->net_manager.connect();
}

void Sniffer::start() {
  std::thread([this]() {
    auto start = std::chrono::high_resolution_clock::now();
    for (Tins::SnifferIterator it = sniffer->begin(); it != sniffer->end();
         ++it)
      Sniffer::handle_pkt(*it);

    std::chrono::duration<double> duration =
        std::chrono::high_resolution_clock::now() - start;
    int seconds = static_cast<int>(duration.count());
    if (seconds != 0)
      logger->info(
          "Finished processing packets, captured {} packets in {} seconds, "
          "which is {} pps",
          count, seconds, count / seconds);
    else
      logger->info("Finished processing {} packets in 0 seconds", count);
  }).detach();

  if (filemode)
    return;

  // Test-run the hopper
  std::optional<iface_state> iface_details =
      net_manager.net_iface_details(send_iface.name());
  if (!iface_details.has_value()) {
    logger->critical("Invalid interface for sniffing");
    finished = true;
    return;
  }

  std::optional<phy_info> phy_details =
      net_manager.phy_details(iface_details->phy_idx);
  if (!phy_details.has_value()) {
    logger->critical("Cannot access phy interface details");
    finished = true;
    return;
  }

  std::vector<uint32_t> channels;
  for (const auto freq : phy_details->frequencies)
    if (freq <= 2484) // 2.4GHz band
      channels.emplace_back(NetCardManager::freq_to_chan(freq));
  std::sort(channels.begin(), channels.end());

  std::stringstream ss;
  for (const auto chan : channels)
    ss << chan << " ";
  logger->debug("Using channel set [ {}]", ss.str());

  bool switched =
      net_manager.set_phy_channel(iface_details->phy_idx, channels[0]);
  if (!switched) {
    logger->critical("Cannot switch phy interface channel");
    finished = true;
    return;
  }

  std::thread(&Sniffer::hopper, this, iface_details->phy_idx, channels)
      .detach();
}

std::set<Sniffer::network_name> Sniffer::all_networks() {
  std::set<Sniffer::network_name> nets;
  for (const auto &[addr, ap] : aps)
    nets.insert(std::make_pair(addr, ap->get_ssid()));
  return nets;
}

std::optional<MACAddress> Sniffer::get_bssid(const SSID &ssid) {
  for (const auto &[bssid, ap] : aps)
    if (ap->get_ssid() == ssid)
      return bssid;
  return std::nullopt;
}

std::optional<std::shared_ptr<AccessPoint>>
Sniffer::get_network(const SSID &ssid) {
  auto bssid = get_bssid(ssid);
  if (!bssid.has_value())
    return std::nullopt;
  return get_network(bssid.value());
}

std::optional<std::shared_ptr<AccessPoint>>
Sniffer::get_network(const MACAddress &bssid) {
  if (!aps.count(bssid))
    return std::nullopt;
  return aps[bssid];
}

void Sniffer::add_ignored_network(const SSID &ssid) {
  auto bssid = get_bssid(ssid);
  if (!bssid.has_value()) {
    ignored_nets_ssid_only.insert(ssid);
    return;
  }

  if (aps.count(bssid.value()))
    aps.erase(bssid.value());

  ignored_nets[bssid.value()] = ssid;
}

void Sniffer::add_ignored_network(const MACAddress &bssid) {
  if (!aps.count(bssid)) {
    ignored_nets_bssid_only.insert(bssid);
    return;
  }

  std::string ssid = aps[bssid].get()->get_ssid();
  ignored_nets[bssid] = ssid;
  aps.erase(bssid);
}

std::unordered_map<MACAddress, SSID> Sniffer::ignored_networks() {
  return ignored_nets;
}

void Sniffer::shutdown() {
  finished = true;
  for (auto &[_, ap] : aps)
    ap->close_all_channels();

  // Unblock the sniffer iterator
  // TODO: Theoretically this method should be called from the same thread which
  // the Tins::SnifferIterator was called
  sniffer->stop_sniff();
}

std::optional<std::string> Sniffer::iface() {
  if (filemode)
    return std::nullopt;
  return iface_name;
}

std::optional<std::filesystem::path> Sniffer::file() {
  if (!filemode)
    return std::nullopt;
  return filepath;
}

std::optional<uint32_t> Sniffer::focus_network(const SSID &ssid) {
  std::optional<MACAddress> bssid = get_bssid(ssid);
  if (!bssid.has_value())
    return std::nullopt;
  return focus_network(bssid.value());
}

std::optional<uint32_t> Sniffer::focus_network(const MACAddress &bssid) {
  if (!aps.count(bssid))
    return std::nullopt;

  scan_mode = FOCUSED;
  focused = bssid;
  logger->debug("Starting focusing on channel {} with ssid: {}",
                aps[bssid]->get_wifi_channel(), aps[bssid]->get_ssid());
  return aps[bssid]->get_wifi_channel();
}

std::optional<std::shared_ptr<AccessPoint>> Sniffer::focused_network() {
  if (scan_mode != FOCUSED)
    return std::nullopt;
  if (!aps.count(focused))
    return std::nullopt;
  return aps[focused];
}

void Sniffer::stop_focus() {
  scan_mode = GENERAL;
  logger->debug("Stopped focusing {}", focused.to_string());
  focused = NoAddress;
  return;
}

std::optional<recording_info>
Sniffer::save_traffic(const std::filesystem::path &dir_path,
                      const std::string &name) {
  logger->debug("Creating a raw recording with {} packets", packets.size());
  Recording rec(dir_path, true, db, name);

  auto channel = std::make_unique<PacketChannel>();
  for (const auto &pkt : packets)
    channel->send(std::make_unique<Tins::Packet>(pkt));

  auto recording_info_opt = rec.dump(std::move(channel));
  if (!recording_info_opt.has_value()) {
    logger->error("Failed to create recording");
    return std::nullopt;
  }
  auto recording_info = recording_info_opt.value();

  // db
  for (const auto &[addr, ap] : aps) {
    auto net_to_db = ap;
    auto decrypter = ap->get_decrypter();
    std::string sec_vector;
    ap->set_vendor();
    for (const auto &sec : net_to_db->security_supported()) {
      sec_vector += absl::StrFormat("%d ", static_cast<uint32_t>(sec));
    }
    auto group_windows = decrypter.get_all_group_windows();
    auto clients_addr = ap->get_clients();

    // inserts
    bool insert_success = db.insert_network(
        net_to_db->get_ssid(), net_to_db->get_bssid().to_string(),
        decrypter.get_password().value_or("Unknown"),
        net_to_db->raw_packet_count(), net_to_db->decrypted_packet_count(),
        decrypter.count_all_group_windows(), sec_vector,
        recording_info.get_uuid(), 0, net_to_db->get_oid());
    for (const auto &window : group_windows) {
      db.insert_group_window(net_to_db->get_bssid().to_string(),
                             window.start.seconds(), window.end.seconds(),
                             window.packets.size() +
                                 window.auth_packets.size());
    }
    for (const auto &addr : clients_addr) {
      auto client_info = ap->get_client(addr);
      db.insert_client(client_info->hwaddr, client_info->sent_total,
                       client_info->sent_unicast,
                       net_to_db->get_bssid().to_string());
      auto client_windows_opt = decrypter.get_all_client_windows(addr);
      if (client_windows_opt.has_value()) {
        const auto &client_windows = client_windows_opt.value();
        for (const auto &window : client_windows) {
          db.insert_client_window(
              client_info->hwaddr, net_to_db->get_bssid().to_string(),
              window.start.seconds(), window.end.seconds(),
              window.packets.size() + window.auth_packets.size());
        }
      }
    }
  }
  return recording_info;
}

std::optional<recording_info>
Sniffer::save_decrypted_traffic(const std::filesystem::path &dir_path,
                                const std::string &name) {
  Recording rec(dir_path, false, db, name);

  auto channel = std::make_unique<PacketChannel>();
  for (auto &pkt : packets) {
    auto data = pkt.pdu()->find_pdu<Tins::Dot11Data>();
    auto eapol = pkt.pdu()->find_pdu<Tins::RSNEAPOL>();
    if (!data || !data->find_pdu<Tins::SNAP>() || eapol)
      continue;
    channel->send(Recording::make_eth_packet(&pkt));
  }

  logger->debug("Creating a decrypted recording with {} packets",
                channel->len());

  auto recording_info_opt = rec.dump(std::move(channel));
  if (!recording_info_opt.has_value()) {
    logger->error("Failed to create recording");
    return std::nullopt;
  }
  auto recording_info = recording_info_opt.value();

  // db
  for (const auto &[addr, ap] : aps) {
    auto net_to_db = ap;
    auto decrypter = ap->get_decrypter();
    std::string sec_vector;
    ap->set_vendor();
    for (const auto &sec : net_to_db->security_supported()) {
      sec_vector += absl::StrFormat("%d ", static_cast<uint32_t>(sec));
    }
    auto group_windows = decrypter.get_all_group_windows();
    auto clients_addr = ap->get_clients();

    // inserts
    bool insert_success = db.insert_network(
        net_to_db->get_ssid(), net_to_db->get_bssid().to_string(),
        decrypter.get_password().value_or("Unknown"),
        net_to_db->raw_packet_count(), net_to_db->decrypted_packet_count(),
        decrypter.count_all_group_windows(), sec_vector,
        recording_info.get_uuid(), 0, net_to_db->get_oid());
    for (const auto &window : group_windows) {
      db.insert_group_window(net_to_db->get_bssid().to_string(),
                             window.start.seconds(), window.end.seconds(),
                             window.packets.size() +
                                 window.auth_packets.size());
    }
    for (const auto &addr : clients_addr) {
      auto client_info = ap->get_client(addr);
      db.insert_client(client_info->hwaddr, client_info->sent_total,
                       client_info->sent_unicast,
                       net_to_db->get_bssid().to_string());
      auto client_windows_opt = decrypter.get_all_client_windows(addr);
      if (client_windows_opt.has_value()) {
        const auto &client_windows = client_windows_opt.value();
        for (const auto &window : client_windows) {
          db.insert_client_window(
              client_info->hwaddr, net_to_db->get_bssid().to_string(),
              window.start.seconds(), window.end.seconds(),
              window.packets.size() + window.auth_packets.size());
        }
      }
    }
  }

  return recording_info;
}

void Sniffer::hopper(int phy_idx, const std::vector<uint32_t> &channels) {
  while (!finished) {
    if (scan_mode == GENERAL) {
      current_channel += (channels.size() % 5) ? 5 : 4;
      if (current_channel >= channels.size())
        current_channel -= channels.size();
      current_channel = channels[current_channel];
    } else {
      auto it = std::find(channels.begin(), channels.end(),
                          aps[focused]->get_wifi_channel());
      if (it == channels.end()) {
        logger->error("Failure while switching channel to {} (channel not in "
                      "operational range), falling back to general scan",
                      aps[focused]->get_wifi_channel());
        scan_mode = GENERAL;
        focused = NoAddress;
        continue;
      }

      current_channel = *it;
    }

    bool success = net_manager.set_phy_channel(phy_idx, current_channel);
    if (!success) {
      logger->error("Failure while switching channel to {}", current_channel);
      return;
    }

    auto duration =
        std::chrono::milliseconds((scan_mode == GENERAL) ? 300 : 1500);
    std::this_thread::sleep_for(duration); // (a kid named) Linger
  }
}

void Sniffer::handle_pkt(Tins::Packet &pkt) {
  count++;
  if (pkt.pdu()->find_pdu<Tins::Dot11Data>())
    handle_data(pkt);
  else if (pkt.pdu()->find_pdu<Tins::Dot11ManagementFrame>())
    handle_management(pkt);
}

void Sniffer::handle_data(Tins::Packet &pkt) {
  auto data = pkt.pdu()->rfind_pdu<Tins::Dot11Data>();
  if (data.subtype() & 4)
    return; // Disard non-data packets

  for (const auto &[addr, ap] : aps)
    if (addr == data.bssid_addr())
      ap->handle_pkt(save_pkt(pkt));
}

void Sniffer::handle_management(Tins::Packet &pkt) {
  auto mgmt = pkt.pdu()->rfind_pdu<Tins::Dot11ManagementFrame>();

  MACAddress bssid;
  if (!mgmt.to_ds() && !mgmt.from_ds())
    bssid = mgmt.addr3();
  else if (!mgmt.to_ds() && mgmt.from_ds())
    bssid = mgmt.addr2();
  else if (mgmt.to_ds() && !mgmt.from_ds())
    bssid = mgmt.addr1();
  else
    bssid = mgmt.addr3();
  if (!bssid.is_unicast())
    return;

  bool has_ssid_info = mgmt.search_option(Tins::Dot11::OptionTypes::SSID);
  if (has_ssid_info) {
    for (const auto ssid : ignored_nets_ssid_only)
      if (ssid == mgmt.ssid()) {
        ignored_nets[bssid] = mgmt.ssid();
        ignored_nets_ssid_only.erase(ssid);
        return;
      }

    for (const auto &addr : ignored_nets_bssid_only)
      if (addr == bssid) {
        ignored_nets[bssid] = mgmt.ssid();
        ignored_nets_bssid_only.erase(bssid);
        return;
      }

    for (const auto &[addr, ssid] : ignored_nets)
      if (bssid != addr && ssid == mgmt.ssid()) {
        ignored_nets[bssid] = ssid;
        return;
      }
  }

  if (ignored_nets.count(bssid) || ignored_nets_bssid_only.count(bssid))
    return;

  if (!aps.count(bssid) && (pkt.pdu()->find_pdu<Tins::Dot11Beacon>() ||
                            pkt.pdu()->find_pdu<Tins::Dot11ProbeResponse>())) {
    bool has_channel_info =
        mgmt.search_option(Tins::Dot11::OptionTypes::DS_SET);
    SSID ssid = (has_ssid_info) ? mgmt.ssid() : bssid.to_string();
    int channel;
    if (has_channel_info) {
      channel = mgmt.ds_parameter_set();
    } else {
      auto radio = pkt.pdu()->find_pdu<Tins::RadioTap>();
      channel =
          (radio) ? NetCardManager::freq_to_chan(radio->channel_freq()) : 1;
    }

    aps[bssid] = std::make_shared<AccessPoint>(bssid, ssid, channel, db);
    aps[bssid]->handle_pkt(save_pkt(pkt));
    return;
  }

  if (aps.count(bssid))
    aps[bssid]->handle_pkt(&pkt);
}

Tins::Packet *Sniffer::save_pkt(Tins::Packet &pkt) {
  packets.push_back(pkt); // Calls PDU::clone on the packets PDU* member.
  return &packets.back();
}

std::optional<std::string>
Sniffer::detect_interface(std::shared_ptr<spdlog::logger> log,
                          const std::string &ifname) {
  // Try to detect the phy in which the logical device is located
  NetCardManager nm;
  nm.connect();

  std::optional<iface_state> iface_details = nm.net_iface_details(ifname);
  if (!iface_details.has_value()) {
    log->error(
        absl::StrFormat("No logical interface with name \'%s\'", ifname));
    nm.disconnect();
    return std::nullopt;
  }

  if (iface_details->type != NL80211_IFTYPE_MONITOR) {
    // Try to detect suitable interface in this phy
    log->info("The supplied interface isn't a monitor mode one, searching in "
              "the same phy");
    std::optional<phy_info> phy_details =
        nm.phy_details(iface_details->phy_idx);
    if (!phy_details.has_value()) {
      log->error("No phy with name phy{}", iface_details->phy_idx);
      nm.disconnect();
      return std::nullopt;
    }

    if (!phy_details->can_monitor) {
      log->error("Physical interface phy{} doesn't support monitor mode",
                 iface_details->phy_idx);
      nm.disconnect();
      return std::nullopt;
    }

    std::string suitable_ifname = "";
    for (const auto candidate : nm.net_interfaces()) {
      std::optional<iface_state> iface_details =
          nm.net_iface_details(candidate);
      if (!iface_details.has_value())
        continue;

      if (iface_details->type == NL80211_IFTYPE_MONITOR) {
        char *name;
        if_indextoname(iface_details->logic_idx, name);
        suitable_ifname = name;
        break;
      }
    }

    if (suitable_ifname.empty()) {
      log->error("Cannot find suitable interface for monitor mode on phy{}",
                 iface_details->phy_idx);
      nm.disconnect();
      return std::nullopt;
    }

    log->info("Found suitable logical interface {} on phy{}", suitable_ifname,
              iface_details->phy_idx);
    nm.disconnect();
    return suitable_ifname;
  }

  log->debug("Found interface {} in monitor mode", ifname);
  nm.disconnect();
  return ifname;
}

} // namespace yarilo
