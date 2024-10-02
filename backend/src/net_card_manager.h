#ifndef SNIFF_NET_CARD_MANAGER
#define SNIFF_NET_CARD_MANAGER

#include "netlink/attr.h"
#include "netlink/handlers.h"
#include "netlink/netlink.h"
#include <linux/nl80211.h>
#include <memory>
#include <optional>
#include <set>
#include <spdlog/logger.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <string>

namespace yarilo {

/**
 * @brief Netlink socket family callback handler for asynchronous
 * communication
 */
class NetlinkCallback {
public:
  /**
   * A constructor which creates the netlink callback, the message for which
   * this callback is created should be sent beforehand
   * @param[in] sock active netlink socket for nl80211
   */
  NetlinkCallback(nl_sock *sock) { this->sock = sock; };

  /**
   * Attach a function to be executed after a message response is received
   * @param[in] func callback function to be executed: int (nl_msg *msg, void
   * *arg)
   * @param[in] arg argument to be passed in to the callback
   */
  void attach(nl_recvmsg_msg_cb_t func, void *arg);

  /**
   * Block until the callback finishes execution
   * @return result of the callback, negative values signify errors
   */
  int wait();

private:
  static int finish(nl_msg *msg, void *arg);
  static int error(sockaddr_nl *nla, nlmsgerr *err, void *arg);
  static int ack(nl_msg *msg, void *arg);

  nl_sock *sock = nullptr;
  nl_cb *callback = nullptr;
  int result = 1;
};

/**
 * @brief Manager for network card information gathering and state control
 */
class NetCardManager {
public:
  enum ChannelModes {
    NO_HT,     // Channel does not support High Throughput (HT) mode.
    HT20,      // Channel does support HT mode with a channel width of 20 MHz.
    HT40MINUS, // Channel does support HT mode with a channel width of 40 MHz,
               // where the secondary channel is below the primary channel.
    HT40PLUS,  // Channel does support HT mode with a channel width of 40 MHz,
               // where the secondary channel is above the primary channel.
    VHT80,     // Channel does support Very High Throughput (VHT) mode with a
               // channel width of 80 MHz
    VHT80P80,  // Channel does support Very High Throughput (VHT) mode with a
               // channel width of 80 MHz and also supports an additional 80 MHz
               // channel (80+80 MHz)
    VHT160     // Channel does support VHT mode with a channel width of 160 MHz
  };

  enum FcsState { FCS_ALL, FCS_VALID, FCS_INVALID };

  /**
   * @brief Physical network interface (e.g. phy0) capability info
   */
  struct phy_info {
    std::string ifname;             // Interface name
    std::set<uint32_t> frequencies; // Supported frequencies
    bool can_set_freq;  // Can it set frequencies?, we cannot jump if it doesn't
    bool can_check_fcs; // Can it check the Frame Check Sequence
    int channel_opts;   // All available channel options, see ChannelModes
    int can_monitor;    // Supports monitor mode

    bool operator<(const phy_info &other) const {
      return ifname < other.ifname;
    }
  };

  /**
   * @brief Logical network interface (e.g. wlan0) data
   */
  struct iface_state {
    int type;               // (virtual) interface type, see nl80211_iftype
    int phy_idx;            // Physical index
    int logic_idx;          // Logical index
    int freq;               // Current working frequency
    ChannelModes chan_type; // Current channel type
    int center_freq1;       // Primary center frequency
    int center_freq2; // Secondary center frequency in cases of bonded channels.
    FcsState fcs_state; // Validation state of the Frame Check Sequence
  };

  /**
   * Basic constructor for logger initialisation
   */
  NetCardManager() {
    logger = spdlog::get("net");
    if (!logger)
      logger = spdlog::stdout_color_mt("net");
  }

  /**
   * Connect to the nl80211 netlink socket
   * @return True if the connection succeeded, false otherwise
   */
  bool connect();

  /**
   * Disconnect from the nl80211 netlink socket
   */
  void disconnect();

  /**
   * Get available logical interfaces (for example `wlp1s0`)
   * @return Set of available network interfaces
   */
  static std::set<std::string> net_interfaces();

  /**
   * Get available physical interfaces (for example `phy0`)
   * @return Set of available network interfaces
   */
  std::set<std::string> phy_interfaces() const;

  /**
   * Get the details for a particular physical interface, like the available
   * frequencies and monitor mode support. For details see `phy_iface`
   * @param[in] phy_idx Index of the physical interface (for example `0` for
   * `phy0`)
   * @return Optionally return details of an interface
   */
  std::optional<phy_info> phy_details(int phy_idx) const;

  /**
   * Get the details for a particular logical interface. For details see
   * `iface_state`
   * @param[in] ifname Name of the logical interface (for example `wlp1s0`)
   * @return Optionally return details of an interface
   */
  std::optional<iface_state> net_iface_details(const std::string &ifname) const;

  /**
   * Set the physical focused channel of an interface, other programs can
   * interfere with this setting, overriding it. It helps to have other programs
   * like `NetworkManager` or `wpa_supplicant` disabled, or the `phy` excluded
   * in their settings
   * @param[in] phy_idx Index of the physical interface (for example `0` for
   * `phy0`)
   * @param[in] chan target channel, supports only channels below 14 (2.4GHz
   * band)
   * @return True if the operation succeeded, false otherwise
   */
  bool set_phy_channel(int phy_idx, int chan) const;

  /**
   * Get the channel from a specific frequency
   * @param[in] freq frequency
   * @return wifi channel number
   */
  static int freq_to_chan(int freq);

  /**
   * Get the frequency from a specific wifi channel
   * @param[in] chan wifi channel
   * @return frequency
   */
  static int chan_to_freq(int chan);

  ~NetCardManager() {
    if (sock)
      nl_socket_free(this->sock);
  }

private:
  static int phy_interfaces_callback(nl_msg *msg, void *arg);
  static int phy_details_callback(nl_msg *msg, void *arg);
  static int net_iface_details_callback(nl_msg *msg, void *arg);

  std::shared_ptr<spdlog::logger> logger;
  nl_sock *sock = nullptr;
  int sock_id = -1;
};

} // namespace yarilo

#endif // SNIFF_NET_CARD_MANAGER
