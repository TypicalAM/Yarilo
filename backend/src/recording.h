#ifndef SNIFF_RECORDING
#define SNIFF_RECORDING

#include "channel.h"
#include "uuid.h"
#include <filesystem>
#include <memory>
#include <optional>
#include <spdlog/logger.h>
#include <tins/snap.h>

#include "database.h"

namespace yarilo {

/**
 * @brief Recordings utility class
 */
class Recording {
public:
  /**
   * @brief data link of a saved recording
   */
  enum class DataLinkType {
    RADIOTAP,
    RAW80211,
    ETH2,
  };

  /**
   * @brief Information about a saved recording
   */
  struct info {
    uuid::UUIDv4 uuid;
    std::string filename;
    std::string display_name;
    DataLinkType datalink;
    uint32_t count;

    uuid::UUIDv4 get_uuid() const { return uuid; }
  };

  /**
   * Constructs a new Recording object.
   * @param[in] save_dir The directory where the recordings will be saved.
   * @param[in] dump_raw A boolean indicating whether to dump raw packet data.
   */
  Recording(const std::filesystem::path &save_dir, bool dump_raw, Database &db);

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
   * @return An optional containing some info about the recording.
   */
  std::optional<info> dump(std::shared_ptr<PacketChannel> channel) const;

  /**
   * Dumps the packets from the given packet vector to a recording file.
   * @param[in] channel A shared pointer to the PacketChannel containing the
   * packets to dump.
   * @return An optional containing some info about the recording.
   */
  std::optional<info> dump(std::vector<Tins::Packet *> *packets) const;

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
  uuid::UUIDv4 uuid;
  Database &db;
};

} // namespace yarilo

#endif // SNIFF_RECORDING
