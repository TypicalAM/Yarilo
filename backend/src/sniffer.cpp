#include "sniffer.h"
#include "access_point.h"
#include "channel.h"
#include "net_card_manager.h"
#include <absl/strings/str_format.h>
#include <algorithm>
#include <chrono>
#include <fcntl.h>
#include <filesystem>
#include <functional>
#include <iostream>
#include <memory>
#include <net/if.h>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>
#include <tins/eapol.h>
#include <tins/exceptions.h>
#include <tins/hw_address.h>
#include <tins/packet.h>
#include <tins/pdu.h>
#include <tins/sniffer.h>
#include <tins/tins.h>
#include <unistd.h>
#include <utility>

namespace yarilo {

Sniffer::Sniffer(std::unique_ptr<Tins::BaseSniffer> sniffer,
                 Tins::NetworkInterface iface) {
  logger = spdlog::stdout_color_mt("Sniffer");
  this->send_iface = iface;
  this->filemode = false;
  this->sniffer = std::move(sniffer);
  this->finished.store(false);
  this->net_manager.connect();
}

Sniffer::Sniffer(std::unique_ptr<Tins::BaseSniffer> sniffer) {
  logger = spdlog::stdout_color_mt("Sniffer");
  this->sniffer = std::move(sniffer);
  this->finished.store(false);
}

void Sniffer::run() {
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
    finished.store(true);
    return;
  }

  std::string phy_name = absl::StrFormat("phy%d", iface_details->phy_idx);
  std::optional<phy_iface> phy_details = net_manager.phy_details(phy_name);
  if (!phy_details.has_value()) {
    logger->critical("Cannot access phy interface details");
    finished.store(true);
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

  bool swtiched = net_manager.set_phy_channel(phy_name, channels[0]);
  if (!swtiched) {
    logger->critical("Cannot switch phy interface channel");
    finished.store(true);
    return;
  }

  std::thread(&Sniffer::hopper, this, phy_name, channels).detach();
}

bool Sniffer::handle_pkt(Tins::Packet &pkt) {
  count++;
  if (finished.load()) {
    logger->info("Packet handling loop finished");
    return false;
  }

  Tins::PDU *pdu = pkt.pdu();
  if (pdu->find_pdu<Tins::Dot11Beacon>())
    return handle_beacon(pkt);
  if (pdu->find_pdu<Tins::Dot11ProbeResponse>())
    return handle_probe_response(pkt);
  if (pdu->find_pdu<Tins::Dot11Data>())
    return handle_data(pkt);
  if (pdu->find_pdu<Tins::Dot11ManagementFrame>())
    return handle_management(pkt);
  return true;
}

bool Sniffer::handle_beacon(Tins::Packet &pkt) {
  auto beacon = pkt.pdu()->rfind_pdu<Tins::Dot11Beacon>();
  SSID ssid = beacon.ssid();
  if (ignored_nets.find(ssid) != ignored_nets.end())
    return true;

  // NOTE: We are not taking the channel from the frequency here! It would be
  // the frequency of the beacon/proberesp packet and NOT necessarily the
  // network itself, there is a chance we get a "DS Parameter: active channel"
  // tagged param in the management packet body
  bool has_channel = beacon.search_option(Tins::Dot11::OptionTypes::DS_SET);
  int current_wifi_channel = has_channel ? beacon.ds_parameter_set() : 1;

  // TODO: Does wlan.fixed.capabilities.spec_man matter here?
  Tins::HWAddress<6> bssid = beacon.addr3();
  if (aps.find(ssid) == aps.end()) {
    aps[ssid] =
        std::make_shared<AccessPoint>(bssid, ssid, current_wifi_channel);
  } else if (has_channel) {
    aps[ssid]->update_wifi_channel(current_wifi_channel);
  }

  return true;
}

bool Sniffer::handle_probe_response(Tins::Packet &pkt) {
  auto probe_resp = pkt.pdu()->rfind_pdu<Tins::Dot11ProbeResponse>();
  SSID ssid = probe_resp.ssid();
  if (ignored_nets.find(ssid) != ignored_nets.end())
    return true;

  bool has_channel = probe_resp.search_option(Tins::Dot11::OptionTypes::DS_SET);
  int current_wifi_channel = has_channel ? probe_resp.ds_parameter_set() : 1;

  // TODO: Does wlan.fixed.capabilities.spec_man matter here?
  Tins::HWAddress<6> bssid = probe_resp.addr3();
  if (aps.find(ssid) == aps.end()) {
    aps[ssid] =
        std::make_shared<AccessPoint>(bssid, ssid, current_wifi_channel);
  } else if (has_channel) {
    aps[ssid]->update_wifi_channel(current_wifi_channel);
  }
  return true;
}

bool Sniffer::handle_data(Tins::Packet &pkt) {
  auto data = pkt.pdu()->rfind_pdu<Tins::Dot11Data>();
  for (const auto &[_, ap] : aps)
    if (ap->get_bssid() == data.bssid_addr()) {
      return ap->handle_pkt(save_pkt(pkt));
    }

  return true;
}

bool Sniffer::handle_management(Tins::Packet &pkt) {
  auto mgmt = pkt.pdu()->rfind_pdu<Tins::Dot11ManagementFrame>();
  Tins::HWAddress<6> bssid;

  if ((mgmt.from_ds() && !mgmt.to_ds()) || (!mgmt.from_ds() && mgmt.to_ds())) {
    bssid = mgmt.addr3();
  } else
    return true;

  for (const auto &[_, ap] : aps)
    if (ap->get_bssid() == bssid)
      return ap->handle_pkt(save_pkt(pkt));

  return true;
}

Tins::Packet *Sniffer::save_pkt(Tins::Packet &pkt) {
  packets.reserve(1024);  // TODO: More permanent solution with arenas
  packets.push_back(pkt); // Calls PDU::clone on the packets PDU* member.
  return &packets.back();
}

std::set<SSID> Sniffer::all_networks() {
  std::set<SSID> res;

  for (const auto &[_, ap] : aps)
    res.insert(ap->get_ssid());

  return res;
}

std::optional<std::shared_ptr<AccessPoint>> Sniffer::get_network(SSID ssid) {
  if (aps.find(ssid) == aps.end())
    return std::nullopt;

  return aps[ssid];
}

void Sniffer::add_ignored_network(SSID ssid) {
  ignored_nets.insert(ssid);
  if (aps.find(ssid) != aps.end())
    aps.erase(ssid);
}

std::set<SSID> Sniffer::ignored_networks() { return ignored_nets; }

void Sniffer::stop() { finished.store(true); }

bool Sniffer::focus_network(SSID ssid) {
  scan_mode.store(FOCUSED);
  if (aps.find(ssid) == aps.end())
    return false;

  focused = ssid;
  logger->debug("Starting focusing ssid: {}", ssid);
  return true;
}

std::optional<std::shared_ptr<AccessPoint>> Sniffer::focused_network() {
  if (scan_mode.load() || focused.empty())
    return std::nullopt;

  if (aps.find(focused) == aps.end())
    return std::nullopt;

  return aps[focused];
}

void Sniffer::stop_focus() {
  scan_mode.store(GENERAL);
  logger->debug("Stopped focusing ssid: {}", focused);
  focused = "";
  return;
}

void Sniffer::hopper(const std::string &phy_name,
                     const std::vector<uint32_t> &channels) {
  while (!finished.load()) {
    if (scan_mode.load() == GENERAL) {
      current_channel += (channels.size() % 5) ? 5 : 4;
      if (current_channel >= channels.size())
        current_channel -= channels.size();
    }

    bool success =
        net_manager.set_phy_channel(phy_name, channels[current_channel]);
    if (!success) {
      logger->error("Failure while switching channel to {}",
                    channels[current_channel]);
      return;
    }

    logger->trace("Switched to channel {}", channels[current_channel]);

    auto duration =
        std::chrono::milliseconds((scan_mode.load() == GENERAL) ? 300 : 1500);
    std::this_thread::sleep_for(duration); // (a kid named) Linger

#ifdef MAYHEM
    // Show that we are scanning
    if (led_on.load()) {
      std::lock_guard<std::mutex> lock(*led_lock);
      if (leds->size() < 100)
        leds->push(YELLOW_LED);
    }
#endif
  }
}

std::vector<std::string>
Sniffer::available_recordings(std::filesystem::path save_path) {
  std::vector<std::string> result;

  for (const auto &entry : std::filesystem::directory_iterator(save_path)) {
    std::string filename = entry.path().filename().string();
    logger->debug("Adding file to recordings: {}", filename);
    result.push_back(filename);
  }

  return result;
}

bool Sniffer::recording_exists(std::filesystem::path save_path,
                               std::string filename) {
  std::filesystem::path filepath = save_path.append(filename);
  return std::filesystem::exists(filepath);
}

std::optional<std::unique_ptr<PacketChannel>>
Sniffer::get_recording_stream(std::filesystem::path save_path,
                              std::string filename) {
  if (!recording_exists(save_path, filename))
    return std::nullopt;

  std::string filepath = save_path.append(filename);
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

  temp_sniff->sniff_loop([&chan, &pkt_count, this](Tins::PDU &pkt) {
    auto eth = pkt.find_pdu<Tins::EthernetII>();
    if (eth == nullptr)
      return true;

    pkt_count++;
    chan->send(std::unique_ptr<Tins::EthernetII>(eth->clone()));
    return true;
  });

  return chan;
}

#ifdef MAYHEM
void Sniffer::start_led(std::mutex *mtx, std::queue<LEDColor> *colors) {
  led_on.store(true);
  led_lock = mtx;
  leds = colors;
}

void Sniffer::stop_led() {
  led_on.store(false);

  std::lock_guard<std::mutex> lock(*led_lock);
  while (!leds->empty())
    leds->pop(); // empty the leds queue
};

void Sniffer::start_mayhem() {
  if (mayhem_on.load())
    return;

  mayhem_on.store(true);
  auto mayhem = [this]() {
    while (mayhem_on.load()) {
      for (auto &[ssid, ap] : aps)
        ap->send_deauth(&this->send_iface, BROADCAST_ADDR);

      if (led_on.load()) {
        std::lock_guard<std::mutex> lock(*led_lock);
        if (leds->size() < 100)
          leds->push(RED_LED);
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    };
  };

  std::thread(mayhem).detach();
};

void Sniffer::stop_mayhem() { mayhem_on.store(false); }
#endif

std::optional<std::string>
Sniffer::detect_interface(std::shared_ptr<spdlog::logger> log,
                          std::string ifname) {
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
    std::string phy_name = absl::StrFormat("phy%d", iface_details->phy_idx);
    std::optional<phy_iface> phy_details = nm.phy_details(phy_name);
    if (!phy_details.has_value()) {
      log->error("No phy with name {}", phy_name);
      nm.disconnect();
      return std::nullopt;
    }

    if (!phy_details->can_monitor) {
      log->error("Physical interface {} doesn't support monitor mode",
                 phy_name);
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
      log->error("Cannot find suitable interface for monitor mode on phy {}",
                 phy_name);
      nm.disconnect();
      return std::nullopt;
    }

    log->info("Found suitable logical interface {} on phy {}", suitable_ifname,
              phy_name);
    nm.disconnect();
    return suitable_ifname;
  }

  log->debug("Found interface {} in monitor mode", ifname);
  nm.disconnect();
  return ifname;
}

} // namespace yarilo
