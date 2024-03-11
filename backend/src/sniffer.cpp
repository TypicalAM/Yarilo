#include "sniffer.h"
#include "access_point.h"
#include "channel.h"
#include <absl/strings/str_format.h>
#include <chrono>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
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

Sniffer::Sniffer(std::unique_ptr<Tins::BaseSniffer> sniffer,
                 Tins::NetworkInterface iface) {
  logger = spdlog::stdout_color_mt("Sniffer");
  this->send_iface = iface;
  this->filemode = false;
  this->sniffer = std::move(sniffer);
  this->end.store(false);
}

Sniffer::Sniffer(std::unique_ptr<Tins::BaseSniffer> sniffer) {
  logger = spdlog::stdout_color_mt("Sniffer");
  this->sniffer = std::move(sniffer);
  this->end.store(false);
}

void Sniffer::run() {
  std::thread([this]() {
    sniffer->sniff_loop(
        std::bind(&Sniffer::handle_pkt, this, std::placeholders::_1));
  }).detach();

  if (!filemode)
    std::thread(&Sniffer::hopping_thread, this).detach();
}

bool Sniffer::handle_pkt(Tins::PDU &pkt) {
  count++;
  if (end.load())
    return false;

  Tins::HWAddress<6> bssid;
  SSID ssid;
  auto beacon = pkt.find_pdu<Tins::Dot11Beacon>();
  auto probe_resp = pkt.find_pdu<Tins::Dot11ProbeResponse>();
  if (beacon || probe_resp) {
    ssid = beacon ? beacon->ssid() : probe_resp->ssid();
    if (ignored_networks.find(ssid) != ignored_networks.end())
      return true;

    // NOTE: We are not taking the channel from the frequency here! It would be
    // the frequency of the beacon/proberesp packet and NOT necessarily the
    // network itself, there is a chance we get a "DS Parameter: active channel"
    // tagged param in the management packet body

    // TODO: Does wlan.fixed.capabilities.spec_man matter here?
    int current_wifi_channel =
        beacon ? beacon->ds_parameter_set() : probe_resp->ds_parameter_set();

    bssid = beacon ? beacon->addr3() : probe_resp->addr3();
    if (aps.find(ssid) == aps.end()) {
      aps[ssid] =
          std::make_shared<AccessPoint>(bssid, ssid, current_wifi_channel);
    } else {
      aps[ssid]->update_wifi_channel(current_wifi_channel);
    }
  }

  // Now we know it's a "personalized" packet and likely not spam
  auto dot11 = pkt.find_pdu<Tins::Dot11Data>();
  if (dot11)
    for (const auto &[_, ap] : aps)
      if (ap->get_bssid() == dot11->bssid_addr())
        return ap->handle_pkt(pkt);

  auto mgmt = pkt.find_pdu<Tins::Dot11ManagementFrame>();
  if (mgmt) {
    Tins::HWAddress<6> bssid;

    if (mgmt->from_ds() && !mgmt->to_ds()) {
      bssid = mgmt->addr3();
    } else if (!mgmt->from_ds() && mgmt->to_ds()) {
      bssid = mgmt->addr3();
    } else
      return true;

    for (const auto &[_, ap] : aps)
      if (ap->get_bssid() == bssid)
        return ap->handle_pkt(pkt);
  }

  return true;
}

std::set<SSID> Sniffer::get_networks() {
  std::set<SSID> res;

  for (const auto &[_, ap] : aps)
    res.insert(ap->get_ssid());

  return res;
}

std::optional<std::shared_ptr<AccessPoint>> Sniffer::get_ap(SSID ssid) {
  if (aps.find(ssid) == aps.end())
    return std::nullopt;

  return aps[ssid];
}

void Sniffer::add_ignored_network(SSID ssid) {
  ignored_networks.insert(ssid);
  if (aps.find(ssid) != aps.end())
    aps.erase(ssid);
}

std::set<SSID> Sniffer::get_ignored_networks() { return ignored_networks; }

void Sniffer::end_capture() { end.store(true); }

bool Sniffer::focus_network(SSID ssid) {
  scan_mode.store(FOCUSED);
  if (aps.find(ssid) == aps.end())
    return false;

  focused_network = ssid;
  logger->debug("Starting focusing ssid: {}", ssid);
  return true;
}

std::optional<std::shared_ptr<AccessPoint>> Sniffer::get_focused_network() {
  if (scan_mode.load() || focused_network.empty())
    return std::nullopt;

  if (aps.find(focused_network) == aps.end())
    return std::nullopt;

  return aps[focused_network];
}

void Sniffer::stop_focus() {
  scan_mode.store(GENERAL);
  logger->debug("Stopped focusing ssid: {}", focused_network);
  focused_network = "";
  return;
}

void Sniffer::hopping_thread() {
  while (!end.load()) {
    if (scan_mode.load() == GENERAL) {
      current_channel += 4;
      if (current_channel > 10)
        current_channel = current_channel - 10;
    }

    std::string command = absl::StrFormat("iw dev %s set channel %d",
                                          send_iface.name(), current_channel);
    int status = std::system(command.c_str());
    auto duration =
        std::chrono::milliseconds((scan_mode.load() == GENERAL) ? 300 : 1500);
    std::this_thread::sleep_for(duration); // (a kid named) Linger

    // Check if the iw command failed/was interrupted since it should already be
    // done by now
    if (!WIFEXITED(status)) {
      logger->error("iw was interrupted");
      throw std::runtime_error("channel change interrupted");
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) != EXIT_SUCCESS) {
      logger->error("iw exited abnormally, status: {}", WEXITSTATUS(status));
      throw std::runtime_error("channel change failed");
    }

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
Sniffer::get_recordings(std::filesystem::path save_path) {
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
