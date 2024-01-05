#ifndef SNIFF_CHANNEL
#define SNIFF_CHANNEL

#include <condition_variable>
#include <optional>
#include <queue>

template <typename T> class Channel {
public:
  void send(const T &value) {
    {
      std::unique_lock<std::mutex> lock(mutex_);
      queue_.push(value);
    }
    condition_.notify_one();
  }

  std::optional<T> receive() {
    std::unique_lock<std::mutex> lock(mutex_);
    condition_.wait(lock, [this] { return !queue_.empty() || closed; });
    if (closed)
      return std::nullopt; // In the case we are closed while waiting!

    T value = queue_.front();
    queue_.pop();
    return value;
  }

  void close() {
    closed = true;
    condition_.notify_one();
  }

private:
  std::queue<T> queue_;
  std::mutex mutex_;
  std::condition_variable condition_;
  bool closed;
};

#endif // SNIFF_CHANNEL
