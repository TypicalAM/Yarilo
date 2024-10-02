#include "sniffer.h"
#include "decrypter.h"
#include "recording.h"
#include <absl/strings/str_format.h>
#include <memory>
#include <net/if.h>
#include <optional>
#include <spdlog/spdlog.h>
#include <tins/packet.h>
#include <tins/sniffer.h>

using phy_info = yarilo::NetCardManager::phy_info;
using iface_state = yarilo::NetCardManager::iface_state;

namespace yarilo {

Sniffer::Sniffer(std::unique_ptr<Tins::FileSniffer> sniffer,
                 const std::filesystem::path &filepath) {
  logger = spdlog::get(filepath.stem().string());
  if (!logger)
    logger = spdlog::stdout_color_mt(filepath.stem().string());
  this->sniffer = std::move(sniffer);
  this->finished = false;
  this->filepath = filepath;
}

Sniffer::Sniffer(std::unique_ptr<Tins::Sniffer> sniffer,
                 const Tins::NetworkInterface &iface) {
  logger = spdlog::get(iface.name());
  if (!logger)
    logger = spdlog::stdout_color_mt(iface.name());
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
    sniffer->sniff_loop(
        std::bind(&Sniffer::handle_pkt, this, std::placeholders::_1));
    std::chrono::duration<double> duration =
        std::chrono::high_resolution_clock::now() - start;
    int seconds = static_cast<int>(duration.count());
    if (seconds != 0) {
      logger->info(
          "Finished processing packets, captured {} packets in {} seconds, "
          "which is {} pps",
          this->count, seconds, this->count / seconds);
    } else {
      logger->info("Finished processing packets in 0 seconds");
    }
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
      channels.emplace_back((freq == 2484) ? 14 : (freq - 2412) / 5 + 1);
  std::sort(channels.begin(), channels.end());

  std::stringstream ss;
  for (const auto chan : channels)
    ss << chan << " ";
  logger->trace("Using channel set [ {}]", ss.str());

  bool swtiched =
      net_manager.set_phy_channel(iface_details->phy_idx, channels[0]);
  if (!swtiched) {
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
  ignored_net_names.insert(ssid);

  auto bssid = get_bssid(ssid);
  if (!bssid.has_value())
    return;

  ignored_net_addrs.insert(bssid.value());
  if (aps.count(bssid.value()))
    aps.erase(bssid.value());
}

std::set<SSID> Sniffer::ignored_network_names() { return ignored_net_names; }

std::set<MACAddress> Sniffer::ignored_network_addresses() {
  return ignored_net_addrs;
}

void Sniffer::shutdown() {
  logger->info("Stopping the sniffer");
  finished = true;
  for (auto &[_, ap] : aps)
    ap->close_all_channels();
}

std::optional<std::string> Sniffer::iface() {
  if (!filemode)
    return std::nullopt;
  return iface_name;
}

std::optional<std::filesystem::path> Sniffer::file() {
  if (!filemode)
    return std::nullopt;
  return filepath;
}

bool Sniffer::focus_network(const SSID &ssid) {
  std::optional<MACAddress> bssid = get_bssid(ssid);
  if (!bssid.has_value() || !aps.count(bssid.value()))
    return false;

  scan_mode = FOCUSED;
  focused = bssid.value();
  logger->debug("Starting focusing ssid: {}", ssid);
  return true;
}

bool Sniffer::focus_network(const MACAddress &bssid) {
  if (!aps.count(bssid))
    return false;

  scan_mode = FOCUSED;
  focused = bssid;
  logger->debug("Starting focusing ssid: {}", aps[bssid]->get_ssid());
  return true;
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
  logger->debug("Stopped focusing ssid: {}", aps[focused]->get_ssid());
  focused = "";
  return;
}

std::optional<uint32_t>
Sniffer::save_traffic(const std::filesystem::path &dir_path) {
  logger->debug("Creating a raw recording with {} packets", packets.size());
  Recording rec(dir_path, true);

  auto channel = std::make_unique<PacketChannel>();
  for (const auto &pkt : packets)
    channel->send(std::make_unique<Tins::Packet>(pkt));
  return rec.dump(std::move(channel));
}

std::optional<uint32_t>
Sniffer::save_decrypted_traffic(const std::filesystem::path &dir_path) {
  Recording rec(dir_path, false);

  auto channel = std::make_unique<PacketChannel>();
  for (auto &pkt : packets) {
    // Check if decrypted
    auto data = pkt.pdu()->find_pdu<Tins::Dot11Data>();
    if (!data || !data->find_pdu<Tins::SNAP>())
      continue;
    channel->send(Recording::make_eth_packet(&pkt));
  }

  logger->debug("Creating a decrypted recording with {} packets",
                channel->len());
  return rec.dump(std::move(channel));
}

void Sniffer::hopper(int phy_idx, const std::vector<uint32_t> &channels) {
  while (!finished) {
    if (scan_mode == GENERAL) {
      current_channel += (channels.size() % 5) ? 5 : 4;
      if (current_channel >= channels.size())
        current_channel -= channels.size();
    }

    bool success =
        net_manager.set_phy_channel(phy_idx, channels[current_channel]);
    if (!success) {
      logger->error("Failure while switching channel to {}",
                    channels[current_channel]);
      return;
    }

    logger->trace("Switched to channel {}", channels[current_channel]);

    auto duration =
        std::chrono::milliseconds((scan_mode == GENERAL) ? 300 : 1500);
    std::this_thread::sleep_for(duration); // (a kid named) Linger

#ifdef MAYHEM
    // Show that we are scanning
    if (led_on) {
      std::lock_guard<std::mutex> lock(*led_lock);
      if (leds->size() < 100)
        leds->push(YELLOW_LED);
    }
#endif
  }
}

#ifdef MAYHEM
void Sniffer::start_led(std::mutex *mtx, std::queue<LEDColor> *colors) {
  led_on = true;
  led_lock = mtx;
  leds = colors;
}

void Sniffer::stop_led() {
  led_on = false;

  std::lock_guard<std::mutex> lock(*led_lock);
  while (!leds->empty())
    leds->pop(); // empty the leds queue
};

void Sniffer::start_mayhem() {
  if (mayhem_on)
    return;

  mayhem_on = true;
  auto mayhem = [this]() {
    while (mayhem_on && !finished) {
      for (auto &[addr, ap] : aps)
        ap->send_deauth(this->send_iface, MACAddress("ff:ff:ff:ff:ff:ff"));

      if (led_on) {
        std::lock_guard<std::mutex> lock(*led_lock);
        if (leds->size() < 100)
          leds->push(RED_LED);
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    };
  };

  std::thread(mayhem).detach();
};

void Sniffer::stop_mayhem() { mayhem_on = false; }
#endif

bool Sniffer::handle_pkt(Tins::Packet &pkt) {
  count++;
  if (finished) {
    logger->info("Packet handling loop finished");
    return false;
  }

  Tins::PDU *pdu = pkt.pdu();
  if (pdu->find_pdu<Tins::Dot11Data>())
    return handle_data(pkt);
  if (pdu->find_pdu<Tins::Dot11ManagementFrame>())
    return handle_management(pkt);
  return true;
}

bool Sniffer::handle_data(Tins::Packet &pkt) {
  auto data = pkt.pdu()->rfind_pdu<Tins::Dot11Data>();
  for (const auto &[addr, ap] : aps)
    if (addr == data.bssid_addr()) {
      return ap->handle_pkt(save_pkt(pkt));
    }

  return true;
}

bool Sniffer::handle_management(Tins::Packet &pkt) {
  auto mgmt = pkt.pdu()->rfind_pdu<Tins::Dot11ManagementFrame>();

  MACAddress bssid;
  if (!mgmt.to_ds() && !mgmt.from_ds()) {
    bssid = mgmt.addr3();
  } else if (!mgmt.to_ds() && mgmt.from_ds()) {
    bssid = mgmt.addr2();
  } else if (mgmt.to_ds() && !mgmt.from_ds()) {
    bssid = mgmt.addr1();
  } else {
    bssid = mgmt.addr3();
  }

  if (ignored_net_addrs.count(bssid))
    return true;

  bool has_ssid_info = mgmt.search_option(Tins::Dot11::OptionTypes::SSID);
  if (has_ssid_info && ignored_net_names.count(mgmt.ssid())) {
    ignored_net_addrs.insert(bssid);
    return true;
  }

  if (!aps.count(bssid) && (pkt.pdu()->find_pdu<Tins::Dot11Beacon>() ||
                            pkt.pdu()->find_pdu<Tins::Dot11ProbeResponse>())) {
    bool has_channel_info =
        mgmt.search_option(Tins::Dot11::OptionTypes::DS_SET);
    SSID ssid = (has_ssid_info) ? mgmt.ssid() : bssid.to_string();
    int channel = (has_channel_info) ? mgmt.ds_parameter_set() : 1;
    aps[bssid] = std::make_shared<AccessPoint>(bssid, ssid, channel);
    return aps[bssid]->handle_pkt(save_pkt(pkt));
  }

  if (aps.count(bssid))
    return aps[bssid]->handle_pkt(&pkt);

  return true;
}

Tins::Packet *Sniffer::save_pkt(Tins::Packet &pkt) {
  packets.reserve(1024);  // TODO: More permanent solution with arenas
  packets.push_back(pkt); // Calls PDU::clone on the packets PDU* member.
  return &packets.back();
}

std::vector<std::string>
Sniffer::available_recordings(const std::filesystem::path &save_path) {
  std::vector<std::string> result;

  for (const auto &entry : std::filesystem::directory_iterator(save_path)) {
    std::string filename = entry.path().filename().string();
    logger->debug("Adding file to recordings: {}", filename);
    result.push_back(filename);
  }

  return result;
}

bool Sniffer::recording_exists(const std::filesystem::path &save_path,
                               const std::string &filename) {
  std::filesystem::path path = save_path;
  std::filesystem::path filepath = path.append(filename);
  return std::filesystem::exists(filepath);
}

std::optional<std::unique_ptr<PacketChannel>>
Sniffer::get_recording_stream(const std::filesystem::path &save_path,
                              const std::string &filename) {
  if (!recording_exists(save_path, filename))
    return std::nullopt;

  std::filesystem::path path = save_path;
  std::string filepath = path.append(filename);
  std::unique_ptr<Tins::FileSniffer> temp_sniff;

  try {
    temp_sniff = std::make_unique<Tins::FileSniffer>(filepath);
  } catch (Tins::pcap_error &e) {
    logger->error("Cannot init sniffer for getting recording {}", e.what());
    return std::nullopt;
  }

  logger->debug("Loading file from path: {}", filepath);
  auto chan = std::make_unique<PacketChannel>();
  int pkt_count = 0;

  temp_sniff->sniff_loop([&chan, &pkt_count, this](Tins::Packet &pkt) {
    auto eth = pkt.pdu()->find_pdu<Tins::EthernetII>();
    if (!eth)
      return true;

    pkt_count++;
    chan->send(std::make_unique<Tins::Packet>(pkt));
    return true;
  });

  return chan;
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
