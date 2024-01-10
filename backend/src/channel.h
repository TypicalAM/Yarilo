#ifndef SNIFF_CHANNEL
#define SNIFF_CHANNEL

#include <atomic>
#include <condition_variable>
#include <optional>
#include <queue>

template <typename T> class Channel {
public:
  Channel() : closed(false) {}

  void send(const T &value) {
    {
      std::unique_lock<std::mutex> lock(mutex_);
      queue_.push(value);
    }
    condition_.notify_one();
  }

  std::optional<T> receive() {
    std::unique_lock<std::mutex> lock(mutex_);
    condition_.wait(lock, [this] { return !queue_.empty() || closed.load(); });
    if (closed.load())
      return std::nullopt;

    T value = queue_.front();
    queue_.pop();
    return value;
  }

  void close() {
    closed.store(true);
    condition_.notify_one();
  }

private:
  std::queue<T> queue_;
  std::mutex mutex_;
  std::condition_variable condition_;
  std::atomic<bool> closed;
};

#endif // SNIFF_CHANNEL
