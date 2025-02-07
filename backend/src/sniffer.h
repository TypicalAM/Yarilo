#ifndef SNIFF_SNIFFER
#define SNIFF_SNIFFER

#include "access_point.h"
#include "database.h"
#include "decrypter.h"
#include "net_card_manager.h"
#include "recording.h"
#include <list>
#include <tins/network_interface.h>
#include <tins/sniffer.h>
#include <unordered_map>

namespace yarilo {
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
          const std::filesystem::path &filepath, Database &db);

  /**
   * A constructor to create the Sniffer with network card support
   * @param[in] sniffer `Tins::Sniffer` instance
   * @param[in] iface Network interface to use
   */
  Sniffer(std::unique_ptr<Tins::Sniffer> sniffer,
          const Tins::NetworkInterface &iface, Database &db);

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
   * @return BSSID of the target network
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
   * Ignore network and delete any access point with this SSID
   * @param[in] ssid SSID of the network to ignore
   */
  void add_ignored_network(const SSID &ssid);

  /**
   * Ignore network and delete any access point with this address
   * @param[in] bssid Address of the network to ignore
   */
  void add_ignored_network(const MACAddress &bssid);

  /**
   * Get the ignored networks
   * @return ssids of ignored networks
   */
  std::unordered_map<MACAddress, SSID> ignored_networks();

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
   * Focus a specific network by BSSID
   * @param[in] bssid Basic service set identifier of the network to be focused
   * (network addr)
   * @return Optionally return the channel that the network is on
   */
  std::optional<wifi_chan_info> focus_network(const MACAddress &bssid);

  /**
   * Get the focused network
   * @return Focused network if focusing is enabled, nullopt otherwise
   */
  std::optional<std::shared_ptr<AccessPoint>> focused_network();

  /**
   * Get the focused frequency
   * @return The wifi channel that is focused
   */
  std::optional<wifi_chan_info> focused_frequency();

  /**
   * Stop focusing the current focused network
   */
  void stop_focus();

  /**
   * Save all traffic (in 802.11 data link)
   * @param[in] directory in which the recording should live
   * @param[in] name of the recording
   * @return An optional containing some info about the recording.
   */
  std::optional<Recording::info>
  save_traffic(const std::filesystem::path &saves_path,
               const std::string &name);

  /**
   * Save decrypted traffic
   * @param[in] directory in which the recording should live
   * @param[in] name of the recording
   * @return An optional containing some info about the recording.
   */
  std::optional<Recording::info>
  save_decrypted_traffic(const std::filesystem::path &save_path,
                         const std::string &name);

  /**
   * Get the recordings available in the saves directory
   * @param[in] save_path Path where the recordings are stored
   * @return Recording filenames to choose from
   */
  static std::vector<Recording::info>
  available_recordings(const std::filesystem::path &save_path);

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

private:
  /**
   * Handle an incoming packet
   * @param[in] pkt Packet to be processed
   */
  void handle_pkt(Tins::Packet &pkt);

  /**
   * Handle a 802.11 data packet.
   * @param[in] pkt Packet to be processed
   */
  void handle_data(Tins::Packet &pkt);

  /**
   * Handle a 802.11 management packet.
   * @param[in] pkt Packet to be processed
   */
  void handle_management(Tins::Packet &pkt);

  /**
   * Save a packet internally for persistence. This is because libtins deletes
   * its packets after handle_pkt is done
   * @param[in] pkt Packet to be saved
   * @return Pointer to the saved packet
   */
  Tins::Packet *save_pkt(Tins::Packet &pkt);

  /**
   * Try to optimally hop through the available primary channels
   * @param[in] channels Channels available for hopping
   */
  void hopper(const std::vector<uint32_t> &channels);

  std::shared_ptr<spdlog::logger> logger;
  std::list<Tins::Packet> packets;
  std::atomic<ScanMode> scan_mode = GENERAL;

  NetCardManager net_manager;
  MACAddress focused;
  bool filemode = true;
  int count = 0;
  wifi_chan_info current_channel;
  std::unique_ptr<Tins::Crypto::WPA2Decrypter> decrypter;
  std::unordered_map<MACAddress, std::shared_ptr<AccessPoint>> aps;
  Tins::NetworkInterface send_iface;
  std::string iface_name = "";
  uint8_t phy_index = 0;
  std::filesystem::path filepath;
  std::unordered_map<MACAddress, SSID> ignored_nets;
  std::set<MACAddress> ignored_nets_bssid_only; // Wait for SSID to show up
  std::set<SSID> ignored_nets_ssid_only;        // Wait for BSSID to show up
  std::unique_ptr<Tins::BaseSniffer> sniffer;
  std::atomic<bool> finished;
  Database &db;
};

} // namespace yarilo

#endif // SNIFF_SNIFFER
