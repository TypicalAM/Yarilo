#ifndef SNIFF_AP
#define SNIFF_AP

#include "channel.h"
#include "decrypter.h"
#include "recording.h"
#include <filesystem>
#include <optional>
#include <tins/ethernetII.h>
#include <tins/tins.h>
#include <vector>

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

  /**
   * @brief Client information
   */
  struct client_info {
    std::string hwaddr;
    std::string hostname;
    std::string ipv4;
    std::string ipv6;
    uint32_t sent_unicast;
    uint32_t sent_total;
    uint32_t received;
    uint32_t rrsi;
    uint32_t noise;
    uint32_t snr;
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
   * @param[in] wifi_channel wifi channel for this network
   */
  AccessPoint(const MACAddress &bssid, const SSID &ssid, int wifi_channel);

  /**
   * A method for handling incoming packets inside this network, if you
   * don't know if the packet belongs to this network check the bssid
   * @param[in] pkt A reference to the packet
   */
  bool handle_pkt(Tins::Packet *pkt);

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
   * @return the wifi channel of the network
   */
  int get_wifi_channel() const;

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
  int raw_packet_count() const;

  /**
   * Decrypted packets data count
   * @return count of decrypted data packets in the queue
   */
  int decrypted_packet_count() const;

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

private:
  /**
   * Handling "802.11 Data" packets inside this network
   * @param[in] pkt A pointer to a saved packet
   */
  bool handle_data(Tins::Packet *pkt);

  /**
   * Handling "802.11 Data" packets inside this network
   * @param[in] pkt A pointer to a saved packet
   */
  bool handle_management(Tins::Packet *pkt);

  /**
   * Detect the security described in this management packet
   * @param[in] mgtm A reference to a management packet
   */
  std::vector<NetworkSecurity>
  detect_security_modes(const Tins::Dot11ManagementFrame &mgmt) const;

  /**
   * Check if the management packet supports Protected Management Frames (PMF).
   * @param[in] mgmt A reference to a management packet.
   * @return true if the packet is capable of PMF, false otherwise.
   */
  bool check_pmf_capable(const Tins::Dot11ManagementFrame &mgmt) const;

  /**
   * Check if the management packet requires Protected Management Frames (PMF).
   * @param[in] mgmt A reference to a management packet.
   * @return true if the packet requires PMF, false otherwise.
   */
  bool check_pmf_required(const Tins::Dot11ManagementFrame &mgmt) const;

  /**
   * Detect if the used cipher is CCMP
   * @param[in] mgtm A reference to a management packet
   */
  bool is_ccmp(const Tins::Dot11ManagementFrame &mgmt) const;

  int count = 0;
  std::shared_ptr<spdlog::logger> logger;
  const SSID ssid;
  const MACAddress bssid;
  int wifi_channel = 0;
  std::vector<Tins::Packet *> captured_packets;
  WPA2Decrypter decrypter;
  std::vector<std::shared_ptr<PacketChannel>> converted_channels;

  // Used for deauth, we need to "copy" the behaviour of the radiotap layer
  uint8_t radio_length = 0;
  uint8_t radio_channel_freq = 0;
  uint8_t radio_channel_type = 0;
  uint8_t radio_antenna = 0;

  bool security_detected = false;
  std::vector<NetworkSecurity> security_modes;
  bool pmf_supported = false; // 802.11w
  bool pmf_required = false;  // 802.11w
  bool uses_ccmp = false;
  std::unordered_map<MACAddress, client_info> clients;
  std::unordered_map<MACAddress, client_security> clients_security;
};

} // namespace yarilo

#endif // SNIFF_AP
