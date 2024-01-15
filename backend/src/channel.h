#ifndef SNIFF_CHANNEL
#define SNIFF_CHANNEL

#include <atomic>
#include <condition_variable>
#include <optional>
#include <queue>
#include <tins/ethernetII.h>

class PacketChannel {
public:
  PacketChannel() : closed(false) {}

  void send(std::unique_ptr<Tins::EthernetII> pkt) {
    {
      std::unique_lock<std::mutex> lock(mtx);
      decrypted_packets.push(std::move(pkt));
    }
    cv.notify_one();
  }

  std::optional<std::unique_ptr<Tins::EthernetII>> receive() {
    std::unique_lock<std::mutex> lock(mtx);
    cv.wait(lock,
            [this] { return !decrypted_packets.empty() || closed.load(); });
    if (closed.load())
      return std::nullopt;

    std::unique_ptr<Tins::EthernetII> value =
        std::move(decrypted_packets.front());
    decrypted_packets.pop();
    return value;
  }

  void close() {
    closed.store(true);
    cv.notify_one();
  }

  bool is_closed() { return closed.load(); }

private:
  std::queue<std::unique_ptr<Tins::EthernetII>> decrypted_packets;
  std::mutex mtx;
  std::condition_variable cv;
  std::atomic<bool> closed;
};

#endif // SNIFF_CHANNEL
