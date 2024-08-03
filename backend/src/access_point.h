#ifndef SNIFF_AP
#define SNIFF_AP

#include "channel.h"
#include "decrypter.h"
#include <filesystem>
#include <spdlog/logger.h>
#include <tins/dot11.h>
#include <tins/eapol.h>
#include <tins/ethernetII.h>
#include <tins/hw_address.h>
#include <tins/network_interface.h>
#include <tins/pdu.h>
#include <tins/tins.h>

namespace yarilo {

/**
 * @brief Access Point in a basic service set (BSS) network
 */
class AccessPoint {
public:
  /**
   * A constructor which creates the access point based on AP data
   * @param[in] bssid hwaddr of the network
   * @param[in] ssid name of the network
   * @param[in] wifi_channel channel of the network (1-14)
   */
  AccessPoint(const Tins::HWAddress<6> &bssid, const SSID &ssid,
              int wifi_channel);

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
  SSID get_ssid();

  /**
   * Get this networks BSSID (MAC of the station)
   * @return the BSSID of the network
   */
  Tins::HWAddress<6> get_bssid();

  /**
   * Get this networks wifi channel
   * @return the wifi channel of the network
   */
  int get_wifi_channel();

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
  bool send_deauth(Tins::NetworkInterface *iface, Tins::HWAddress<6> addr);

  /**
   * Get if the network already has a working psk (one that generated a valid
   * keypair)
   * @return True if one psk already works
   */
  bool has_working_password();

  /**
   * Get the decrypter
   * @return The WPA2 decrypter
   */
  WPA2Decrypter &get_decrypter();

  /*
   * Get if the network protects its management frames
   * @return True if 802.11w is in place
   */
  bool management_protected();

  /**
   * Update the desired channel of the access point
   * @param[in] channel wifi channel to use
   */
  void update_wifi_channel(int i);

  /**
   * Unencrypted packets count
   * @return count of raw data packets in the queue
   */
  int raw_packet_count();

  /**
   * Decrypted packets data count
   * @return count of decrypted data packets in the queue
   */
  int decrypted_packet_count();

  /**
   * Save decrypted traffic
   * @param[in] directory in which the recording should live
   * @return True if the traffic was saved successfully
   */
  bool save_decrypted_traffic(std::filesystem::path save_path);

private:
  std::shared_ptr<spdlog::logger> logger;
  SSID ssid;
  Tins::HWAddress<6> bssid;
  int wifi_channel = 0;
  std::vector<Tins::Packet *> captured_packets;
  WPA2Decrypter decrypter;
  std::vector<std::shared_ptr<PacketChannel>> converted_channels;

  // Used for deauth, we need to "copy" the behaviour of the radiotap layer
  uint8_t radio_length = 0;
  uint8_t radio_channel_freq = 0;
  uint8_t radio_channel_type = 0;
  uint8_t radio_antenna = 0;

  // Determine if we can spoof deauth packets, 802.11w
  bool protected_mgmt_frames = false;

  /**
   * A method for handling "802.11 Data" packets inside this network
   * @param[in] pkt A pointer to a saved packet
   */
  bool handle_data(Tins::Packet *pkt);

  /**
   * A method for handling "802.11 Management" packets inside this network
   * @param[in] pkt A pointer to a saved packet
   */
  bool handle_mgmt(Tins::Packet *pkt);

  /**
   * Get a specific client (sender or receiver) based on the 802.11 address data
   * inside a network
   * @param[in] data The 802.11 data packet to analyze
   * @return The client hardware address
   */
  Tins::HWAddress<6> determine_client(const Tins::Dot11Data &data);

  /**
   * Create an ethernet packet based on the decrypted 802.11 packet
   * @param[in] data The 802.11 packet to convert
   * @return The converted ethernet packet
   */
  static std::unique_ptr<Tins::EthernetII>
  make_eth_packet(Tins::Dot11Data *data);
};

} // namespace yarilo

#endif // SNIFF_AP
