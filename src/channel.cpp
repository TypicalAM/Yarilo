#include <condition_variable>
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

  T receive() {
    std::unique_lock<std::mutex> lock(mutex_);
    condition_.wait(lock, [this] { return !queue_.empty(); });

    T value = queue_.front();
    queue_.pop();
    return value;
  }

private:
  std::queue<T> queue_;
  std::mutex mutex_;
  std::condition_variable condition_;
};
