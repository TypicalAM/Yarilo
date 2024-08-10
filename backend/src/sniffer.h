#ifndef SNIFF_SNIFFER
#define SNIFF_SNIFFER

#include "access_point.h"
#include "net_card_manager.h"
#include <tins/network_interface.h>
#include <tins/sniffer.h>

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

/**
 * @brief Packet sniffer and handler in charge of tracking, information
 * gathering and decrypting passing data
 */
class Sniffer {
public:
  typedef std::pair<MACAddress, SSID> network_name;

  /**
   * A constructor to create the Sniffer without network card support
   * @param[in] sniffer `Tins::FileSniffer` instance
   */
  Sniffer(std::unique_ptr<Tins::FileSniffer> sniffer,
          const std::filesystem::path &filepath);

  /**
   * A constructor to create the Sniffer with network card support
   * @param[in] sniffer `Tins::Sniffer` instance
   * @param[in] iface Network interface to use
   */
  Sniffer(std::unique_ptr<Tins::Sniffer> sniffer,
          const Tins::NetworkInterface &iface);

  /**
   * Run the sniffer
   */
  void start();

  /**
   * Get the available networks, use `get_network` to get a specific network
   * @return names of available networks along with their BSSID
   */
  std::set<network_name> all_networks();

  /**
   * Find the first network with the given SSID
   * @param[in] ssid SSID of the searched network
   * @return BSSID of the taget network
   */
  std::optional<MACAddress> get_bssid(const SSID &ssid);

  /**
   * Get the details of a network by SSID, use `all_networks` to get all the
   * network names. In the case of multiple APs with the same SSID, the first
   * one is chosen
   * @param[in] ssid of the network
   * @return `AccessPoint` information if the SSID exists, nullopt otherwise
   */
  std::optional<std::shared_ptr<AccessPoint>> get_network(const SSID &ssid);

  /**
   * Get the details of a network by BSSID, use `all_networks` to get all the
   * network names
   * @param[in] bssid of the network
   * @return `AccessPoint` information if the BSSID exists, nullopt otherwise
   */
  std::optional<std::shared_ptr<AccessPoint>>
  get_network(const MACAddress &bssid);

  /**
   * Ignore network and delete any access point by name with this name from the
   * list
   * @param[in] ssid SSID of the network to ignore
   */
  void add_ignored_network(const SSID &ssid);

  /**
   * Get the ignored networks by SSID
   * @return ssids of ignored networks
   */
  std::set<SSID> ignored_network_names();

  /**
   * Get the ignored networks by BSSID
   * @return Hardware addresses of ignored networks
   */
  std::set<MACAddress> ignored_network_addresses();

  /**
   * Stop the sniffer
   */
  void shutdown();

  /**
   * Get the used interface (if applicable)
   * @return Used net logical interface
   */
  std::optional<std::string> iface();

  /**
   * Get the used filepath (if applicable)
   * @return Used filepath
   */
  std::optional<std::filesystem::path> file();

  /**
   * Focus a specific network by SSID
   * @param[in] ssid Sevice set identifier of the network to be focused
   * (network name)
   * @return True if the operation was successful, false otherwise
   */
  bool focus_network(const SSID &ssid);

  /**
   * Focus a specific network by BSSID
   * @param[in] bssid Basic sevice set identifier of the network to be focused
   * (network addr)
   * @return True if the operation was successful, false otherwise
   */
  bool focus_network(const MACAddress &bssid);

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
   * Save all traffic (in 802.11 data link)
   * @param[in] directory in which the recording should live
   * @return optionally number of packets saved
   */
  std::optional<uint32_t> save_traffic(const std::filesystem::path &save_path);

  /**
   * Save decrypted traffic
   * @param[in] directory in which the recording should live
   * @return optionally number of packets saved
   */
  std::optional<uint32_t>
  save_decrypted_traffic(const std::filesystem::path &save_path);

  /**
   * Get the recordings available in the saves directory
   * @param[in] save_path Path where the recordings are stored
   * @return Recording filenames to choose from
   */
  std::vector<std::string>
  available_recordings(const std::filesystem::path &save_path);

  /**
   * Check if a recording exists and is valid
   * @param[in] save_patth Path where the recordings are stored
   * @param[in] filename Name of the recording
   * @return True if the recording exists, false otherwise
   */
  bool recording_exists(const std::filesystem::path &save_path,
                        const std::string &filename);

  /**
   * Get the packet stream for a specific recording
   * @param[in] save_patth Path where the recordings are stored
   * @param[in] filename Name of the recording
   * @return Channel of packets if the recording exists and is valid, nullopt
   * otherwise
   */
  std::optional<std::unique_ptr<PacketChannel>>
  get_recording_stream(const std::filesystem::path &save_path,
                       const std::string &filename);

  /**
   * Try to detect if a logical interface is suitable for sniffing. If the
   * supplied logical interface fails, searching in the same phy might yield a
   * suitable interface
   * @param[in] log Logger to use
   * @param[in] ifname Logical interface name
   * @return Logical interface to sniff on if available, nullopt otherwise
   */
  static std::optional<std::string>
  detect_interface(std::shared_ptr<spdlog::logger> log,
                   const std::string &ifname);

  ~Sniffer() {
    if (!filemode)
      net_manager.disconnect();
  }

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
  MACAddress focused;
  bool filemode = true;
  int count = 0;
  int current_channel = 1;
  std::unique_ptr<Tins::Crypto::WPA2Decrypter> decrypter;
  std::map<MACAddress, std::shared_ptr<AccessPoint>> aps;
  Tins::NetworkInterface send_iface;
  std::string iface_name = "";
  std::filesystem::path filepath;
  std::set<SSID> ignored_net_names;
  std::set<MACAddress> ignored_net_addrs;
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
