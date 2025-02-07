#ifndef SNIFF_NET
#define SNIFF_NET

#include <cstdint>
#include <string>
#include <tins/hw_address.h>

namespace yarilo {

typedef std::string SSID;
typedef Tins::HWAddress<6> MACAddress;

namespace net {

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

inline std::string readable_chan_type(ChannelModes mode) {
  switch (mode) {
  case NO_HT:
    return "No HT";
  case HT20:
    return "HT20";
  case HT40MINUS:
    return "HT40-";
  case HT40PLUS:
    return "HT40+";
  case VHT80:
    return "VHT80";
  case VHT80P80:
    return "VHT80+80";
  case VHT160:
    return "VHT160";
  default:
    return "Unknown Mode";
  }
}

enum FcsState { FCS_ALL, FCS_VALID, FCS_INVALID };

/**
 * @brief Wi-Fi channel information
 */
struct wifi_chan_info {
  uint32_t freq;          // Current working frequency
  ChannelModes chan_type; // Current channel width
  uint32_t center_freq1;  // Primary center frequency
  uint32_t
      center_freq2; // Secondary center frequency in cases of bonded channels.

  bool operator==(const wifi_chan_info &other) const {
    return freq == other.freq && chan_type == other.chan_type;
  }
};

// We are ignoring 802.11ax D6.1 27.3.23.2 and Annex E
inline uint32_t freq_to_chan(uint32_t freq) {
  if (freq < 1000)
    return 0;
  else if (freq == 2484)
    return 14;
  else if (freq < 2484)
    return (freq - 2407) / 5;
  else if (freq >= 4910 && freq <= 4980)
    return (freq - 4000) / 5;
  else if (freq < 5950)
    return (freq - 5000) / 5;
  else if (freq <= 45000) /* DMG band lower limit */
    /* see 802.11ax D6.1 27.3.23.2 */
    return (freq - 5950) / 5;
  return 0;
}

// We are ignoring 802.11ax D6.1 27.3.23.2 and Annex E
inline uint32_t chan_to_freq(uint32_t chan) {
  if (chan <= 0)
    return 0;
  else if (chan == 14)
    return 2484;
  else if (chan < 14)
    return 2407 + (chan * 5);
  else if (chan >= 34 && chan <= 64)
    return 5000 + (chan * 5);
  else if (chan >= 100 && chan <= 144)
    return 5000 + (chan * 5);
  else if (chan >= 149 && chan <= 165)
    return 5000 + (chan * 5);
  return 0;
}

}; // namespace net

} // namespace yarilo

#endif // SNIFF_NET
