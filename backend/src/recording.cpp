#include "recording.h"
#include "log_sink.h"
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <tins/dot11.h>
#include <tins/tins.h>

using recording_info = yarilo::Recording::info;

namespace yarilo {

Recording::Recording(const std::filesystem::path &save_dir, bool dump_raw, Database &db)
    : save_dir(save_dir), dump_raw(dump_raw), db(db) {
  logger = log::get_logger("Recorder");
  uuid = uuid::generate_v4();
}

std::optional<recording_info>
Recording::dump(std::shared_ptr<PacketChannel> channel) const {
  if (channel->is_closed())
    return std::nullopt;
  logger->trace("Creating a recording using a channel");

  auto lock = channel->lock_send();
  std::unique_ptr<Tins::PacketWriter> writer;
  DataLinkType datalink = DataLinkType::RAW80211;
  std::filesystem::path path = save_dir / generate_filename();

  uint32_t count = 0;
  try {
    if (dump_raw) {
      // Determine if we want to use radiotap or dot11
      bool uses_radiotap = false;
      if (channel->len() && !channel->is_closed()) {
        auto pkt = channel->receive();
        if (pkt.has_value()) {
          if (pkt.value()->pdu()->find_pdu<Tins::RadioTap>()) {
            writer = std::make_unique<Tins::PacketWriter>(
                path.string(), Tins::DataLinkType<Tins::RadioTap>());
            count++;
            writer->write(*pkt.value()->pdu());
            uses_radiotap = true;
          }
        }
      }

      if (!uses_radiotap)
        writer = std::make_unique<Tins::PacketWriter>(
            path.string(), Tins::DataLinkType<Tins::Dot11>());

      datalink =
          (uses_radiotap) ? DataLinkType::RADIOTAP : DataLinkType::RAW80211;
      logger->trace("Using raw link type: {}",
                    (uses_radiotap) ? "radiotap" : "802.11");
    } else {
      logger->trace("Using decrypted link type: Ethernet II");
      writer = std::make_unique<Tins::PacketWriter>(
          path.string(), Tins::DataLinkType<Tins::EthernetII>());
      datalink = DataLinkType::ETH2;
    }
  } catch (const Tins::pcap_error &e) {
    logger->error("Error while initializing: {}", e.what());
    return std::nullopt;
  }

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
    writer->write(*pkt.value()->pdu());
  }

  watcher.join();
  logger->trace("Done");

  if (!db.insert_recording(uuid, generate_filename(), path.string(), 0, 0)) {
    logger->error("Failed to insert recording into database");
    return std::nullopt;
  }

  return recording_info{.uuid = uuid,
                        .filename = path.filename().string(),
                        .display_name = path.filename().string(),
                        .datalink = datalink,
                        .count = count}; // TODO: Better display name
}

std::optional<recording_info>
Recording::dump(std::vector<Tins::Packet *> *packets) const {
  logger->trace("Creating a recording using a vector");
  std::filesystem::path path = save_dir / generate_filename();
  DataLinkType datalink = DataLinkType::RAW80211;

  std::unique_ptr<Tins::PacketWriter> writer;
  try {
    if (dump_raw) {
      // Determine if we want to use radiotap or dot11
      bool uses_radiotap = false;
      if (packets->size()) {
        if ((*packets)[0]->pdu()->find_pdu<Tins::RadioTap>()) {
          writer = std::make_unique<Tins::PacketWriter>(
              path.string(), Tins::DataLinkType<Tins::RadioTap>());
          uses_radiotap = true;
        }
      }

      if (!uses_radiotap)
        writer = std::make_unique<Tins::PacketWriter>(
            path.string(), Tins::DataLinkType<Tins::Dot11>());

      datalink =
          (uses_radiotap) ? DataLinkType::RADIOTAP : DataLinkType::RAW80211;
      logger->trace("Using raw link type: {}",
                    (uses_radiotap) ? "radiotap" : "802.11");
    } else {
      datalink = DataLinkType::ETH2;
      logger->trace("Using decrypted link type: Ethernet II");
      writer = std::make_unique<Tins::PacketWriter>(
          path.string(), Tins::DataLinkType<Tins::EthernetII>());
    }
  } catch (const Tins::pcap_error &e) {
    logger->error("Error while initializing: {}", e.what());
    return std::nullopt;
  }

  uint32_t count = packets->size();
  for (const auto &pkt : *packets) {
    writer->write(*pkt->pdu());

  }
  logger->trace("Done");
  return recording_info{.uuid = uuid,
                        .filename = path.filename().string(),
                        .display_name = path.filename().string(),
                        .datalink = datalink,
                        .count = count}; // TODO: Better display name
}

std::unique_ptr<Tins::Packet> Recording::make_eth_packet(Tins::Packet *pkt) {
  auto data = pkt->pdu()->rfind_pdu<Tins::Dot11Data>();
  auto eth2 = Tins::EthernetII(data.dst_addr(), data.src_addr());
  if (data.find_pdu<Tins::SNAP>())
    eth2 /= *data.find_pdu<Tins::SNAP>()->inner_pdu();
  else
    eth2 /= *data.inner_pdu();
  return std::make_unique<Tins::Packet>(eth2, pkt->timestamp());
}

std::filesystem::path Recording::generate_filename() const {
  auto now = std::chrono::system_clock::now();
  std::time_t currentTime = std::chrono::system_clock::to_time_t(now);
  struct std::tm *timeInfo = std::localtime(&currentTime);
  std::stringstream ss;
  ss << basename << " " << uuid << " "
     << std::put_time(timeInfo, "%d-%m-%Y-%H:%M") << ".pcapng";

  return ss.str();
}

} // namespace yarilo
