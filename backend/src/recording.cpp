#include "recording.h"
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <tins/dot11.h>
#include <tins/tins.h>

namespace yarilo {

Recording::Recording(const std::filesystem::path &save_dir, bool dump_raw)
    : save_dir(save_dir), dump_raw(dump_raw) {
  logger = spdlog::get("Recorder");
  if (!logger)
    logger = spdlog::stdout_color_mt("Recorder");
}

std::optional<uint32_t>
Recording::dump(std::shared_ptr<PacketChannel> channel) const {
  if (channel->is_closed())
    return std::nullopt;
  logger->trace("Creating a recording using a channel");

  auto lock = channel->lock_send();
  std::unique_ptr<Tins::PacketWriter> writer;

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
                generate_filename().string(),
                Tins::DataLinkType<Tins::RadioTap>());
            count++;
            writer->write(*pkt.value()->pdu());
            uses_radiotap = true;
          }
        }
      }

      if (!uses_radiotap)
        writer = std::make_unique<Tins::PacketWriter>(
            generate_filename().string(), Tins::DataLinkType<Tins::Dot11>());

      logger->trace("Using raw link type: {}",
                    (uses_radiotap) ? "radiotap" : "802.11");
    } else {
      logger->trace("Using decrypted link type: Ethernet II");
      writer = std::make_unique<Tins::PacketWriter>(
          generate_filename().string(), Tins::DataLinkType<Tins::EthernetII>());
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
  return count;
}

std::optional<uint32_t>
Recording::dump(std::vector<Tins::Packet *> *packets) const {
  logger->trace("Creating a recording using a vector");
  std::unique_ptr<Tins::PacketWriter> writer;
  try {
    if (dump_raw) {
      // Determine if we want to use radiotap or dot11
      bool uses_radiotap = false;
      if (packets->size()) {
        if ((*packets)[0]->pdu()->find_pdu<Tins::RadioTap>()) {
          writer = std::make_unique<Tins::PacketWriter>(
              generate_filename().string(),
              Tins::DataLinkType<Tins::RadioTap>());
          uses_radiotap = true;
        }
      }

      if (!uses_radiotap)
        writer = std::make_unique<Tins::PacketWriter>(
            generate_filename().string(), Tins::DataLinkType<Tins::Dot11>());
      logger->trace("Using raw link type: {}",
                    (uses_radiotap) ? "radiotap" : "802.11");
    } else {
      logger->trace("Using decrypted link type: Ethernet II");
      writer = std::make_unique<Tins::PacketWriter>(
          generate_filename().string(), Tins::DataLinkType<Tins::EthernetII>());
    }
  } catch (const Tins::pcap_error &e) {
    logger->error("Error while initializing: {}", e.what());
    return std::nullopt;
  }

  uint32_t count = 0;
  for (const auto &pkt : *packets) {
    count++;
    writer->write(*pkt->pdu());
  }

  logger->trace("Done");
  return count;
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
  ss << basename << "-" << std::put_time(timeInfo, "%d-%m-%Y-%H:%M")
     << ".pcapng";

  std::filesystem::path new_path = save_dir;
  new_path.append(ss.str());
  return new_path;
}

} // namespace yarilo
