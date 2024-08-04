#ifndef SNIFF_AP
#define SNIFF_AP

#include "channel.h"
#include "decrypter.h"
#include <filesystem>
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
   * @brief Connection security info of a specific client
   */
  struct client_security {
    NetworkSecurity security;
    bool is_ccmp = false;
    bool pmf_enforced = false;
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
   * @return True if there wasn't any client or if the encryption succeeded on
   * one of the clients. False if the password didn't generate any valid keys
   * from existing users.
   */
  bool add_password(const std::string &psk);

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
   * Set this networks wifi channel
   * @param[in] the new wifi channel of the network
   */
  void set_wifi_channel(int wifi_channel) {
    this->wifi_channel = wifi_channel;
  };

  /**
   * Get the converted data channel for this network
   * TODO: Add timing info
   */
  std::shared_ptr<PacketChannel> get_channel();

  /**
   * Send a deauthentication request via a sender to an addr to kick it off this
   * network
   * @param[in] iface network interface to use
   * @param[in] addr hardware address of the target device
   * @return True if the packet was sent, False if the device doesn't exist, or
   * other error
   */
  bool send_deauth(const Tins::NetworkInterface &iface,
                   const MACAddress &addr) const;

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
  std::vector<NetworkSecurity> supported_security() const;

  /**
   * Get if the network has unicast decryption support
   * @return True if the network supports being decrypted
   */
  bool unicast_decryption_support() const;

  /**
   * Get if the network has group decryption support
   * @return True if the network supports being decrypted
   */
  bool group_decryption_support() const;

  /**
   * Get if this client has unicast decryption support
   * @return True if the client supports being decrypted
   */
  bool client_decryption_support(const MACAddress &client);

  /*
   * Get if the network protects its management frames
   * @return True if 802.11w is in place
   */
  bool protected_management_support() const;

  /*
   * Get if the network protects its management frames for a specific client
   * @return True if 802.11w is enforced for a client
   */
  bool protected_management_enforced(const MACAddress &client);

  /**
   * Get the decrypter
   * @return The WPA2 decrypter
   */
  WPA2Decrypter &get_decrypter();

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
   * Save decrypted traffic
   * @param[in] directory in which the recording should live
   * @return True if the traffic was saved successfully
   */
  bool save_decrypted_traffic(const std::filesystem::path &save_path);

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
   * Detect if the used cipher is CCMP
   * @param[in] mgtm A reference to a management packet
   */
  bool is_ccmp(const Tins::Dot11ManagementFrame &mgmt) const;

  /**
   * Create an ethernet packet based on the decrypted 802.11 packet
   * @param[in] data The 802.11 packet to convert
   * @return The converted ethernet packet
   */
  static std::unique_ptr<Tins::EthernetII>
  make_eth_packet(Tins::Dot11Data *data);

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
  bool pmf_supported = false; // Protected management frames - 802.11w
  bool uses_ccmp = false;
  std::map<MACAddress, client_security> clients_security;
};

} // namespace yarilo

#endif // SNIFF_AP
