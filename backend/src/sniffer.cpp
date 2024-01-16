
#include "sniffer.h"
#include "access_point.h"
#include "channel.h"
#include <absl/strings/str_format.h>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <set>
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

Sniffer::Sniffer(Tins::BaseSniffer *sniffer, Tins::NetworkInterface iface) {
  this->send_iface = iface;
  this->filemode = false;
  this->sniffer = sniffer;
  this->end.store(false);
}

Sniffer::Sniffer(Tins::BaseSniffer *sniffer) {
  this->sniffer = sniffer;
  this->end.store(false);
}

void Sniffer::run() {
  std::thread([this]() {
    sniffer->sniff_loop(
        std::bind(&Sniffer::callback, this, std::placeholders::_1));
  }).detach();

  if (!filemode)
    std::thread(&Sniffer::hopping_thread, this).detach();
}

bool Sniffer::callback(Tins::PDU &pkt) {
  count++;
  if (end.load())
    return false;

  auto dot11 = pkt.find_pdu<Tins::Dot11Data>();
  if (dot11) {
    for (const auto &[_, ap] : aps)
      if (ap->get_bssid() == dot11->bssid_addr())
        return ap->handle_pkt(pkt);

    // TODO: Data before beacon, happens rarely
    return true;
  }

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
      aps[ssid] = new AccessPoint(bssid, ssid, current_wifi_channel);
    } else {
      aps[ssid]->update_wifi_channel(current_wifi_channel);
    }
  }

  return true;
}

std::set<SSID> Sniffer::get_networks() {
  std::set<SSID> res;

  for (const auto &[_, ap] : aps)
    res.insert(ap->get_ssid());

  return res;
}

std::optional<AccessPoint *> Sniffer::get_ap(SSID ssid) {
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
  std::cout << "Starting focusing network with ssid " << ssid << std::endl;
  return true;
}

std::optional<AccessPoint *> Sniffer::get_focused_network() {
  if (scan_mode.load() || focused_network.empty())
    return std::nullopt;

  if (aps.find(focused_network) == aps.end())
    return std::nullopt;

  return aps[focused_network];
}

void Sniffer::stop_focus() {
  scan_mode.store(GENERAL);
  std::cout << "Stopping focusing network with ssid " << focused_network
            << std::endl;
  focused_network = "";
  return;
}

void Sniffer::hopping_thread() {
  while (!end.load()) {
    if (scan_mode.load() == GENERAL) {
      current_channel += 5;
      if (current_channel > 13)
        current_channel = current_channel - 13;
      std::string command = absl::StrFormat("iw dev %s set channel %d",
                                            send_iface.name(), current_channel);
      std::system(command.c_str());
      std::this_thread::sleep_for(std::chrono::duration<int, std::milli>(
          100)); // (a kid named) Linger for 100ms
    } else {
      current_channel = aps[focused_network]->get_wifi_channel();
      std::string command = absl::StrFormat("iw dev %s set channel %d",
                                            send_iface.name(), current_channel);
      std::system(command.c_str());
      std::this_thread::sleep_for(std::chrono::duration<int, std::milli>(
          500)); // Changing channels while focusing on a network is much less
                 // common
    }

#ifdef MAYHEM
    toggle_yellow_led(); // Show that we are scanning
#endif
  }
}

std::vector<std::string> Sniffer::get_recordings() {
  const std::string dir_path = "/opt/sniff"; // TODO: WHAT DIRECTORY
  std::vector<std::string> result;

  for (const auto &entry : std::filesystem::directory_iterator(dir_path)) {
    std::string filename = entry.path().filename().string();
    std::cout << "Adding file to recordings: " << filename << std::endl;
    result.push_back(filename);
  }

  return result;
}

std::pair<std::unique_ptr<PacketChannel>, int>
Sniffer::get_recording_stream(std::string filename) {
  const std::string dir_path = "/opt/sniff"; // TODO: WHAT DIRECTORY
  std::string filepath = dir_path + "/" + filename;
  Tins::FileSniffer temp_sniff = Tins::FileSniffer(filepath);
  std::cout << "Loading file from path: " << filepath << std::endl;
  auto chan = std::make_unique<PacketChannel>();

  int pkt_count = 0;
  temp_sniff.sniff_loop([&chan, &pkt_count](Tins::PDU &pkt) {
    pkt_count++;
    chan->send(std::unique_ptr<Tins::EthernetII>(
        pkt.find_pdu<Tins::EthernetII>()->clone()));
    return true;
  });

  return std::make_pair(std::move(chan), pkt_count);
}

#ifdef MAYHEM
bool Sniffer::open_led_fifo(const std::string &filename) {
  std::cout << "Opening led FIFO" << std::endl;
  if (access(filename.c_str(), F_OK) == -1) {
    std::cerr << "Error opening FIFO: " << strerror(errno) << std::endl;
    return false;
  }

  // Open the FIFO for reading and writing
  led_fd = open(filename.c_str(), O_RDWR);
  if (led_fd == -1) {
    std::cerr << "Error opening FIFO: " << strerror(errno) << std::endl;
    return false;
  }

  std::cout << "Opened" << std::endl;
  return true;
};

bool Sniffer::open_topgun_fifo(const std::string &filename) {
  std::cout << "Opening topgun FIFO" << std::endl;
  if (access(filename.c_str(), F_OK) == -1) {
    std::cerr << "Error opening FIFO: " << strerror(errno) << std::endl;
    return false;
  }

  // Open the FIFO for reading
  topgun_fd = open(filename.c_str(), O_RDWR);
  if (topgun_fd == -1) {
    std::cerr << "Error opening FIFO: " << strerror(errno) << std::endl;
    return false;
  }

  std::cout << "Opened" << std::endl;
  return true;
};

void Sniffer::toggle_yellow_led() {
  char command = yellow_led ? YELLOW_OFF : YELLOW_ON;
  write(led_fd, &command, sizeof(command));
  yellow_led = !yellow_led;
  std::cout << "New yellow led state: " << yellow_led << std::endl;
}

void Sniffer::toggle_red_red() {
  char command = red_led ? RED_OFF : RED_ON;
  write(led_fd, &command, sizeof(command));
  red_led = !red_led;
  std::cout << "New red led state: " << red_led << std::endl;
}

void Sniffer::readloop_topgun() {
  std::cout << "Readloop opened" << std::endl;
  char command;

  while (!end.load()) {
    if (read(topgun_fd, &command, 1) == -1) {
      std::cerr << "Error while reading topgun " << strerror(errno)
                << std::endl;
      break;
    }

    if (command == START_MAYHEM) {
      toggle_red_red();
      std::cout << "Starting mayhem" << std::endl;
    } else if (command == STOP_MAYHEM) {
      toggle_red_red();
      std::cout << "Stopping mayhem" << std::endl;
    }
  }

  std::cout << "Readloop ended" << std::endl;
}

#endif
