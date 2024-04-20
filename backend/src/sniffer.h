#ifndef SNIFF_SNIFFER
#define SNIFF_SNIFFER

#include "access_point.h"
#include "net_card_manager.h"
#include <atomic>
#include <filesystem>
#include <memory>
#include <set>
#include <string>
#include <tins/crypto.h>
#include <tins/network_interface.h>
#include <tins/pdu.h>
#include <tins/sniffer.h>
#include <unordered_map>

namespace yarilo {

#ifdef MAYHEM
enum LEDColor {
  RED_LED,
  YELLOW_LED,
  GREEN_LED,
};
#endif

enum ScanMode {
  FOCUSED, // We are focused on one network and following it's channel
  GENERAL  // We are hopping through the spectrum
};

class Sniffer {
public:
  Sniffer(std::unique_ptr<Tins::BaseSniffer> sniffer);
  Sniffer(std::unique_ptr<Tins::BaseSniffer> sniffer,
          Tins::NetworkInterface iface);

  void run();
  bool handle_pkt(Tins::PDU &pkt);
  std::set<SSID> get_networks();
  std::optional<std::shared_ptr<AccessPoint>> get_ap(SSID ssid);
  // Ignore network and delete any ap with this name from the list
  void add_ignored_network(SSID ssid);
  std::set<SSID> get_ignored_networks();
  void end_capture();
  bool focus_network(SSID ssid); // focus network
  std::optional<std::shared_ptr<AccessPoint>> get_focused_network();
  void stop_focus();
  void hopping_thread(const std::string &phy_name,
                      const std::vector<uint32_t> &channels);
  std::vector<std::string> get_recordings(std::filesystem::path save_path);
  bool recording_exists(std::filesystem::path save_path, std::string filename);
  std::optional<std::unique_ptr<PacketChannel>>
  get_recording_stream(std::filesystem::path save_path, std::string filename);
  std::set<int> available_channels();

  static std::string detect_interface(std::shared_ptr<spdlog::logger> log,
                                      std::string ifname);

  ~Sniffer() { net_manager.disconnect(); }

#ifdef MAYHEM
  void start_led(std::mutex *mtx, std::queue<LEDColor> *colors);
  void stop_led();
  void start_mayhem();
  void stop_mayhem();
#endif

private:
  std::shared_ptr<spdlog::logger> logger;
  std::atomic<ScanMode> scan_mode = GENERAL;

  NetCardManager net_manager;
  SSID focused_network = "";
  bool filemode = true;
  int count = 0;
  int current_channel = 1;
  std::unique_ptr<Tins::Crypto::WPA2Decrypter> decrypter;
  std::unordered_map<SSID, std::shared_ptr<AccessPoint>> aps;
  Tins::NetworkInterface send_iface;
  std::set<SSID> ignored_networks;
  std::unique_ptr<Tins::BaseSniffer> sniffer;
  std::atomic<bool> finished;

#ifdef MAYHEM
  std::atomic<bool> led_on = false;
  std::atomic<bool> mayhem_on = false;
  std::queue<LEDColor> *leds;
  std::mutex *led_lock;
#endif
};

} // namespace yarilo

#endif // SNIFF_SNIFFER
