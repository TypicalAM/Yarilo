#ifndef SNIFF_CHANNEL
#define SNIFF_CHANNEL

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <queue>
#include <tins/ethernetII.h>

namespace yarilo {

class PacketChannel {
public:
  /**
   * Create a packet channel
   */
  PacketChannel() : closed(false) {}

  /**
   * Send a packet through the channel
   * @param[in] pkt Ethernet packet to send
   */
  void send(std::unique_ptr<Tins::EthernetII> pkt) {
    std::unique_lock<std::mutex> send_lock(send_mtx);
    {
      std::unique_lock<std::mutex> lock(mtx);
      decrypted_packets.push(std::move(pkt));
    }
    cv.notify_one();
  }

  /**
   * Receive a packet from the channel, blocks until a packet arrives, or the
   * channel is closed
   * @return Packet or nullopt in the case of a channel close
   */
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

  /**
   * Close the channel and notify all blocked subscribers
   */
  void close() {
    closed.store(true);
    cv.notify_one();
  }

  /**
   * Get the channels closed state
   * @return True if the channel is closed
   */
  bool is_closed() { return closed.load(); }

  /**
   * Get the channels queue emptiness state
   * @return True if the packet queue is empty
   */
  bool is_empty() { return decrypted_packets.empty(); }

  /**
   * Get the queue length
   * @return Number of packets waiting in the queue
   */
  size_t len() { return decrypted_packets.size(); }

  /**
   * Lock the queue for sending, useful for making sure that packets will not
   * come in a critical section
   */
  void lock_send() { send_mtx.lock(); }

  /**
   * Unlock the queue for sending, useful for making sure that packets will not
   * come in a critical section
   */
  void unlock_send() { send_mtx.unlock(); }

private:
  std::queue<std::unique_ptr<Tins::EthernetII>> decrypted_packets;
  std::mutex mtx;
  std::mutex send_mtx;
  std::condition_variable cv;
  std::atomic<bool> closed;
};

} // namespace yarilo

#endif // SNIFF_CHANNEL
