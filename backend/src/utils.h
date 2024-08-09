#ifndef SNIFF_UTILS
#define SNIFF_UTILS

#include "channel.h"
#include "decrypter.h"
#include <filesystem>
#include <memory>
#include <optional>
#include <tins/data_link_type.h>
#include <tins/ethernetII.h>
#include <tins/packet_writer.h>
#include <tins/snap.h>

namespace yarilo {

/**
 * @brief Recordings utility class
 */
class Recording {
public:
  Recording(const std::filesystem::path &save_dir, bool dump_raw)
      : save_dir(save_dir), dump_raw(dump_raw) {}

  void set_name(const std::string &basename) { this->basename = basename; }

  std::optional<uint32_t> dump(std::shared_ptr<PacketChannel> channel) {
    if (channel->is_closed())
      return std::nullopt;

    channel->lock_send();
    std::unique_ptr<Tins::PacketWriter> writer;
    if (dump_raw) {
      writer = std::make_unique<Tins::PacketWriter>(
          generate_path().string(), Tins::DataLinkType<Tins::Dot11>());
    } else {
      writer = std::make_unique<Tins::PacketWriter>(
          generate_path().string(), Tins::DataLinkType<Tins::EthernetII>());
    }

    uint32_t count = 0;
    std::thread watcher([this, &channel, &count]() {
      while (!channel->is_empty())
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      channel->close();
    });

    while (!channel->is_closed()) {
      auto pkt = channel->receive();
      if (!pkt.has_value())
        break;
      count++;
      writer->write(pkt.value());
    }

    channel->unlock_send();
    watcher.join();
    return count;
  }

  std::optional<uint32_t> dump(std::vector<Tins::Packet *> *packets) {
    const auto path = generate_path();
    std::unique_ptr<Tins::PacketWriter> writer;
    if (dump_raw) {
      writer = std::make_unique<Tins::PacketWriter>(
          generate_path().string(), Tins::DataLinkType<Tins::Dot11>());
    } else {
      writer = std::make_unique<Tins::PacketWriter>(
          generate_path().string(), Tins::DataLinkType<Tins::EthernetII>());
    }

    uint32_t count = 0;
    for (const auto &pkt : *packets) {
      count++;
      writer->write(pkt);
    }

    return true;
  }

  /**
   * Create an ethernet packet based on the decrypted 802.11 data packet
   * @param[in] pkt The 802.11 Data packet to convert
   * @return The converted ethernet packet
   */

  static std::unique_ptr<Tins::Packet> make_eth_packet(Tins::Packet *pkt) {
    auto data = pkt->pdu()->rfind_pdu<Tins::Dot11Data>();
    auto eth2 = Tins::EthernetII(data.dst_addr(), data.src_addr());
    if (data.find_pdu<Tins::SNAP>())
      eth2 /= *data.find_pdu<Tins::SNAP>()->inner_pdu();
    else
      eth2 /= *data.inner_pdu();
    return std::make_unique<Tins::Packet>(eth2, pkt->timestamp());
  }

private:
  std::filesystem::path generate_path() {
    auto now = std::chrono::system_clock::now();
    std::time_t currentTime = std::chrono::system_clock::to_time_t(now);
    struct std::tm *timeInfo = std::localtime(&currentTime);
    std::stringstream ss;
    ss << basename << "-" << std::put_time(timeInfo, "%d-%m-%Y-%H:%M")
       << ".pcap";

    std::filesystem::path new_path = save_dir;
    new_path.append(ss.str());
    return new_path;
  }

  const std::filesystem::path save_dir;
  const bool dump_raw = false;
  std::string basename = "recording";
};

} // namespace yarilo

#endif
