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
#include <tins/packet.h>
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
  FOCUSED, // We are focused on one network and following its channel
  GENERAL  // We are hopping through the spectrum
};

class Sniffer {
public:
  /**
   * A constructor to create the Sniffer without network card support
   * @param[in] sniffer `Tins::FileSniffer` instance
   */
  Sniffer(std::unique_ptr<Tins::BaseSniffer> sniffer);

  /**
   * A constructor to create the Sniffer with network card support
   * @param[in] sniffer `Tins::Sniffer` instance
   * @param[in] iface Network interface to use
   */
  Sniffer(std::unique_ptr<Tins::BaseSniffer> sniffer,
          Tins::NetworkInterface iface);

  /**
   * Run the sniffer
   */
  void run();

  /**
   * Get the available networks, use the `get_network` method to get a specific
   * network
   * @return SSIDs of available networks
   */
  std::set<SSID> all_networks();

  /**
   * Get the details of a network network, use the `all_networks` method to get
   * all the network names
   * @param[in] ssid Service set identifier of the network
   * @return `AccessPoint` information if the SSID exists, nullopt otherwise
   */
  std::optional<std::shared_ptr<AccessPoint>> get_network(SSID ssid);

  /**
   * Ignore network and delete any access point with this name from the list
   * @param[in] ssid Service set identifier of the network
   */
  void add_ignored_network(SSID ssid);

  /**
   * Get the ignored networks
   * @return SSIDs of ignored networks
   */
  std::set<SSID> ignored_networks();

  /**
   * Stop the sniffer
   */
  void stop();

  /**
   * Focus a specific network
   * @param[in] ssid Service set identifier of the network
   * @return True if the operation was successful, false otherwise
   */
  bool focus_network(SSID ssid);

  /**
   * Get the focused network
   * @return Focused network if focusing is enabled, nullopt otherwise
   */
  std::optional<std::shared_ptr<AccessPoint>> focused_network();

  /**
   * Stop focusing the current focused network
   */
  void stop_focus();

  /**
   * Get the recordings available in the saves directory
   * @param[in] save_path Path where the recordings are stored
   * @return Recording filenames to choose from
   */
  std::vector<std::string>
  available_recordings(std::filesystem::path save_path);

  /**
   * Check if a recording exists and is valid
   * @param[in] save_patth Path where the recordings are stored
   * @param[in] filename Name of the recording
   * @return True if the recording exists, false otherwise
   */
  bool recording_exists(std::filesystem::path save_path, std::string filename);

  /**
   * Get the packet stream for a specific recording
   * @param[in] save_patth Path where the recordings are stored
   * @param[in] filename Name of the recording
   * @return Channel of packets if the recording exists and is valid, nullopt
   * otherwise
   */
  std::optional<std::unique_ptr<PacketChannel>>
  get_recording_stream(std::filesystem::path save_path, std::string filename);

  /**
   * Try to detect if a logical interface is suitable for sniffing. If the
   * supplied logical interface fails, searching in the same phy might yield a
   * suitable interface
   * @param[in] log Logger to use
   * @param[in] ifname Logical interface name
   * @return Logical interface to sniff on if available, nullopt otherwise
   */
  static std::optional<std::string>
  detect_interface(std::shared_ptr<spdlog::logger> log, std::string ifname);

  ~Sniffer() { net_manager.disconnect(); }

#ifdef MAYHEM
  // TODO: Move to channels?
  void start_led(std::mutex *mtx, std::queue<LEDColor> *colors);
  void stop_led();
  void start_mayhem();
  void stop_mayhem();
#endif

private:
  /**
   * Handle an incoming packet
   * @param[in] pkt Packet to be processed
   * @return True if sniffing should be continued
   */
  bool handle_pkt(Tins::Packet &pkt);

  /**
   * Handle a 802.11 beacon packet. A beacon packet is sent by an AP to
   * broadcast its capabilities and allow users to detect the network.
   * @param[in] pkt Packet to be processed
   * @return True if sniffing should be continued
   */
  bool handle_beacon(Tins::Packet &pkt);

  /**
   * Handle a 802.11 probe response packet. It is a response to a probe request
   * packet broadcast by a client to discover networks. It has roughly the same
   * info as a beacon packet.
   * @param[in] pkt Packet to be processed
   * @return True if sniffing should be continued
   */
  bool handle_probe_response(Tins::Packet &pkt);

  /**
   * Handle a 802.11 data packet.
   * @param[in] pkt Packet to be processed
   * @return True if sniffing should be continued
   */
  bool handle_data(Tins::Packet &pkt);

  /**
   * Handle a 802.11 management packet.
   * @param[in] pkt Packet to be processed
   * @return True if sniffing should be continued
   */
  bool handle_management(Tins::Packet &pkt);

  /**
   * Save a packet internally for persistence. This is because libtins deletes
   * its packets after handle_pkt is done
   * @param[in] pkt Packet to be saved
   * @return Pointer to the saved packet
   */
  Tins::Packet *save_pkt(Tins::Packet &pkt);

  /**
   * Try to optimally hop through the available channels
   * @param[in] phy_name Physical interface to switch channels on
   * @param[in] channels Channels available for hopping
   */
  void hopper(const std::string &phy_name,
              const std::vector<uint32_t> &channels);

  std::shared_ptr<spdlog::logger> logger;
  std::vector<Tins::Packet> packets;
  std::atomic<ScanMode> scan_mode = GENERAL;

  NetCardManager net_manager;
  SSID focused = "";
  bool filemode = true;
  int count = 0;
  int current_channel = 1;
  std::unique_ptr<Tins::Crypto::WPA2Decrypter> decrypter;
  std::unordered_map<SSID, std::shared_ptr<AccessPoint>> aps;
  Tins::NetworkInterface send_iface;
  std::set<SSID> ignored_nets;
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
