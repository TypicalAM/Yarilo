#ifndef SNIFF_AP
#define SNIFF_AP

#include "channel.h"
#include "decrypter.h"
#include "net.h"
#include "recording.h"
#include <filesystem>
#include <optional>
#include <tins/ethernetII.h>
#include <tins/ip_address.h>
#include <tins/tins.h>
#include <vector>

#include "database.h"

namespace yarilo {

/**
 * @brief Access Point in a basic service set (BSS) network
 */
class AccessPoint {
public:
  /**
   * @brief Network security protocol used. A network can support multiple ways
   * to connect and secure data
   */
  enum class NetworkSecurity {
    OPEN,
    WEP,
    WPA,
    WPA2_Personal,
    WPA2_Enterprise,
    WPA3_Personal,
    WPA3_Enterprise,
  };

  /**
   * @brief Current state of decryption
   */
  enum class DecryptionState {
    DECRYPTED,
    NOT_ENOUGH_DATA,
    INCORRECT_PASSWORD,
    ALREADY_DECRYPTED,
  };

  /*
   * @brief WiFi standard that is supported by an access point, there can be
   * many of them for a given access point
   */
  enum class WiFiStandard {
    Dot11A,  // Legacy standards
    Dot11B,  // Legacy standards
    Dot11G,  // Legacy standards
    Dot11N,  // Wi-Fi 4 or HT (High Throughput)
    Dot11AC, // Wi-Fi 5 or HVT (Very High Throughput)
    Dot11AX, // Wi-Fi 6 or HE (High Efficiency)
  };

  /*
   * @brief WiFi modulation type used
   */
  enum class Modulation {
    CCK,   // Complementary code keying (802.11b)
    BPSK,  // Binary phase shift keying
    QPSK,  // Quadrature phase shift keying
    QAM16, // Quadrature amplitude modulation
    QAM64,
    QAM256,
    QAM1024,
  };

  /*
   * @brief WiFi channel width used
   */
  enum class ChannelWidth {
    CHAN20,
    CHAN40,
    CHAN80,
    CHAN80_80,
    CHAN160,
  };

  /**
   * @brief WiFi standard capabilities for the network
   */
  struct wifi_standard_info {
    WiFiStandard std;
    bool single_beamformer_support;
    bool single_beamformee_support;
    bool multi_beamformer_support;
    bool multi_beamformee_support;
    std::set<uint8_t> mcs_supported_idx; // Indices of MCS
    std::set<Modulation> modulation_supported;
    std::set<uint8_t>
        spatial_streams_supported; // Spatial stream configurations for MIMO,
                                   // for example 3 means that the network
                                   // supports 3 spatial streams, or 3x3
    std::set<ChannelWidth> channel_widths_supported;
  };

  /**
   * @brief Radio information
   */
  struct radio_info {
    int8_t rssi;
    int8_t noise;
    int8_t snr;
  };

  /**
   * @brief Client information
   */
  struct client_info {
    MACAddress hwaddr;
    std::string hostname;
    Tins::IPv4Address ipv4;
    Tins::IPv6Address ipv6;
    uint32_t sent_unicast;
    uint32_t sent_total;
    uint32_t received;
    radio_info radio;
    bool router;
  };

  /**
   * @brief Connection security info of a specific client
   */
  struct client_security {
    NetworkSecurity security;
    bool is_ccmp = false;
    bool pmf = false;
    std::optional<Tins::RSNInformation::CypherSuites> pairwise_cipher;
  };

  /**
   * A constructor which creates the access point based on AP data
   * @param[in] bssid hwaddr of the network
   * @param[in] ssid name of the network
   * @param[in] wifi_channels wifi channels for this network
   */
  AccessPoint(const MACAddress &bssid, const SSID &ssid,
              const std::vector<net::wifi_chan_info> &wifi_channels,
              Database &db);

  /**
   * A method for handling incoming packets inside this network, if you
   * don't know if the packet belongs to this network check the bssid
   */
  void handle_pkt(Tins::Packet *pkt);

  /**
   * A method for adding the wifi password key. Decryption of packets
   * requires a 4-way handshake. If the password is present, the user packets
   * will be decrypted using this key.
   * @param[in] psk network key
   * @return State of decryption after the password is applied
   */
  DecryptionState add_password(const std::string &psk);

  /**
   * Get this networks SSID
   * @return the ssid of the network
   */
  SSID get_ssid() const;

  /**
   * Get this networks BSSID (MAC of the station)
   * @return the BSSID of the network
   */
  MACAddress get_bssid() const;

  /**
   * Get this networks wifi channel
   * @return the wifi channels that the network supports
   */
  std::vector<net::wifi_chan_info> get_wifi_channels() const;

  /**
   * Get standard capabilities
   * @return Available standards and their possible settings
   */
  std::vector<wifi_standard_info> standards_supported() const;

  /**
   * Get the converted data channel for this network
   */
  std::shared_ptr<PacketChannel> get_decrypted_channel();

  /**
   * Close all channels
   */
  void close_all_channels();

  /**
   * Send a deauthentication request via a sender to an addr to kick it off this
   * network
   * @param[in] iface network interface to use
   * @param[in] addr hardware address of the target device
   * @return True if the packet was sent, False if 802.11w usage was detected on
   * this client
   */
  bool send_deauth(const Tins::NetworkInterface &iface, const MACAddress &addr);

  /**
   * Get if the network already has a working psk (one that generated a valid
   * keypair)
   * @return True if one psk already works
   */
  bool has_working_password() const;

  /**
   * Get supported security modes (e.g. WPA2-PSK)
   * @return List of supported security modes
   */
  std::vector<NetworkSecurity> security_supported() const;

  /**
   * Get if the network has unicast decryption support
   * @return True if the network supports being decrypted
   */
  bool unicast_decryption_supported() const;

  /**
   * Get if the network has group decryption support
   * @return True if the network supports being decrypted
   */
  bool group_decryption_supported() const;

  /**
   * Get if this client has unicast decryption support
   * @return True if the client supports being decrypted
   */
  bool client_decryption_supported(const MACAddress &client);

  /*
   * Get if the network can protect its management frames
   * @return True if 802.11w is in place
   */
  bool protected_management_supported() const;

  /*
   * Get if the network must protect its management frames
   * @return True if 802.11w is in place
   */
  bool protected_management_required() const;

  /*
   * Get if the network protects its management frames for a specific client
   * @return True if 802.11w is enforced for a client
   */
  bool protected_management(const MACAddress &client);

  /**
   * Get the radio information for the AP
   * @return current radio quality information
   */
  radio_info get_radio() const;

  /**
   * Get the multicast groups detected on this AP
   * @return a set of hardware addresses of the multicast groups along with
   * their frame counts
   */
  std::unordered_map<MACAddress, uint32_t> get_multicast_groups() const;

  /**
   * Get the decrypter
   * @return The WPA2 decrypter
   */
  WPA2Decrypter &get_decrypter();

  /**
   * Get the available users information
   * @return The map of available clients of the access point
   */
  const std::set<MACAddress> get_clients() {
    std::set<MACAddress> result;
    for (const auto &[addr, _] : clients)
      result.insert(addr);
    return result;
  }

  /**
   * Get info about a client
   * @return Optionally return the information about a client
   */
  const std::optional<client_info> get_client(MACAddress addr) {
    if (!clients.count(addr))
      return std::nullopt;
    return clients[addr];
  }

  /**
   * Get a client's security details
   * @return Optionally return the security information about a client
   */
  const std::optional<client_security> get_client_security(MACAddress addr) {
    if (!clients_security.count(addr))
      return std::nullopt;
    return clients_security[addr];
  }

  /**
   * Unencrypted packets count
   * @return count of raw data packets in the queue
   */
  uint32_t raw_packet_count() const;

  /**
   * Decrypted packets data count
   * @return count of decrypted data packets in the queue
   */
  uint32_t decrypted_packet_count() const;

  /**
   * Save all traffic (in 802.11 data link)
   * @param[in] directory in which the recording should live
   * @param[in] name user-defined filename
   * @param[in] raw whether to safe raw traffic
   * @return An optional containing some info about the recording.
   */
  std::optional<Recording::info>
  save_traffic(const std::filesystem::path &save_path, const std::string &name);

  /**
   * Save decrypted traffic
   * @param[in] directory in which the recording should live
   * @param[in] name user-defined filename
   * @return An optional containing some info about the recording.
   */
  std::optional<Recording::info>
  save_decrypted_traffic(const std::filesystem::path &save_path,
                         const std::string &name);

  /**
   * Set the vendor of the access point based on the OID.txt file
   */
  void set_vendor();

  /**
   * Get the vendor of the access point
   * @return The vendor of the access point
   */
  std::string get_vendor() const;

  /**
   * Get the OID of the access point
   * @return The OID of the access point
   */
  std::string get_oid() const;

  /**
   * Detect the security described in this management packet
   * @param[in] mgmt A reference to a management packet
   */
  static std::vector<NetworkSecurity>
  detect_security_modes(const Tins::Dot11ManagementFrame &mgmt);

  /**
   * Detect network capabilities described in this management packet
   * @param[in] mgmt A reference to a management packet
   */
  static std::vector<wifi_standard_info>
  detect_wifi_capabilities(const Tins::Dot11ManagementFrame &mgmt);

  /**
   * Check if the management packet supports Protected Management Frames (PMF).
   * @param[in] mgmt A reference to a management packet.
   * @return true if the packet is capable of PMF, false otherwise.
   */
  static bool check_pmf_capable(const Tins::Dot11ManagementFrame &mgmt);

  /**
   * Check if the management packet requires Protected Management Frames (PMF).
   * @param[in] mgmt A reference to a management packet.
   * @return true if the packet requires PMF, false otherwise.
   */
  static bool check_pmf_required(const Tins::Dot11ManagementFrame &mgmt);

  /**
   * Check the operating frequency of an access point
   * @param[in] mgmt A reference to a management packet.
   * @return channel information for supported standards
   */
  static std::vector<net::wifi_chan_info>
  detect_channel_info(Tins::Dot11ManagementFrame &mgmt);

private:
  /**
   * Handling "802.11 Data" packets inside this network
   * @param[in] pkt A pointer to a saved packet
   */
  void handle_data(Tins::Packet *pkt);

  /**
   * Handling "802.11 Data" packets inside this network
   * @param[in] pkt A pointer to a saved packet
   */
  void handle_management(Tins::Packet *pkt);

  /**
   * Update the client info with the metadata found in the packet, does not
   * update sent/received count
   * @param[in] pkt A decrypted packet
   */
  void update_client_metadata(const Tins::Packet &pkt);

  /**
   * Detect if the used cipher is CCMP
   * @param[in] mgtm A reference to a management packet
   */
  bool is_ccmp(const Tins::Dot11ManagementFrame &mgmt) const;

  /**
   * Fill in the radio details from a radiotap header
   * @param[in] radio A reference to a radiotap header
   * @return Radio information structure, empty if there is no information
   */
  radio_info fill_radio_info(const Tins::RadioTap &radio) const;

  uint32_t count = 0;
  uint32_t decrypted_pkt_count = 0;
  std::shared_ptr<spdlog::logger> logger;
  const SSID ssid;
  const MACAddress bssid;
  std::vector<net::wifi_chan_info> wifi_channels;
  std::vector<Tins::Packet *> captured_packets;
  WPA2Decrypter decrypter;
  std::vector<std::shared_ptr<PacketChannel>> converted_channels;
  std::vector<wifi_standard_info> wifi_stds_supported;

  // Used for deauth, we need to "copy" the behaviour of the radiotap layer
  uint8_t radio_length = 0;
  uint8_t radio_channel_freq = 0;
  uint8_t radio_channel_type = 0;
  uint8_t radio_antenna = 0;

  bool capabilities_detected = false;
  std::vector<NetworkSecurity> security_modes;
  bool pmf_supported = false; // 802.11w
  bool pmf_required = false;  // 802.11w
  bool uses_ccmp = false;
  radio_info ap_radio;
  std::unordered_map<MACAddress, uint32_t> multicast_groups;
  std::unordered_map<MACAddress, client_info> clients;
  std::unordered_map<MACAddress, client_security> clients_security;
  std::set<Tins::IPv4Address> router_candidates_ipv4;
  MACAddress gateway_address;
  Database &db;
  std::string vendor;
  std::string oid;
};

} // namespace yarilo

#endif // SNIFF_AP
