#ifndef SNIFF_RECORDING
#define SNIFF_RECORDING

#include "channel.h"
#include <filesystem>
#include <memory>
#include <optional>
#include <spdlog/logger.h>
#include <tins/snap.h>

namespace yarilo {

/**
 * @brief Recordings utility class
 */
class Recording {
public:
  /**
   * Constructs a new Recording object.
   * @param[in] save_dir The directory where the recordings will be saved.
   * @param[in] dump_raw A boolean indicating whether to dump raw packet data.
   */
  Recording(const std::filesystem::path &save_dir, bool dump_raw);

  /**
   * Sets the base name for the recording.
   * @param[in] basename The base name to be used for the recording file (for
   * example the AP name)
   */
  void set_name(const std::string &basename) { this->basename = basename; }

  /**
   * Dumps the packets from the given PacketChannel to a recording file.
   * @param[in] channel A shared pointer to the PacketChannel containing the
   * packets to dump.
   * @return An optional containing the number of packets dumped, or
   * std::nullopt if the operation failed.
   */
  std::optional<uint32_t> dump(std::shared_ptr<PacketChannel> channel) const;

  /**
   * Dumps the packets from the given packet vector to a recording file.
   * @param[in] channel A shared pointer to the PacketChannel containing the
   * packets to dump.
   * @return An optional containing the number of packets dumped, or
   * std::nullopt if the operation failed.
   */
  std::optional<uint32_t> dump(std::vector<Tins::Packet *> *packets) const;

  /**
   * Create an ethernet packet based on the decrypted 802.11 data packet
   * @param[in] pkt The 802.11 Data packet to convert
   * @return The converted ethernet packet
   */
  static std::unique_ptr<Tins::Packet> make_eth_packet(Tins::Packet *pkt);

private:
  /*
   * Generates a filename for the recording file.
   * @return The generated filename as a path object.
   */
  std::filesystem::path generate_filename() const;

  std::shared_ptr<spdlog::logger> logger;
  const std::filesystem::path save_dir;
  const bool dump_raw = false;
  std::string basename = "recording";
};

} // namespace yarilo

#endif // SNIFF_RECORDING
