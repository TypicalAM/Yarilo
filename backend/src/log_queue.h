#ifndef SNIFF_LOG_QUEUE
#define SNIFF_LOG_QUEUE

#include "proto/service.pb.h"
#include <condition_variable>
#include <mutex>
#include <vector>

namespace yarilo {

/**
 * @brief A queue for storing log entries with thread-safe operations.
 *
 * This class implements a bounded queue that supports thread-safe insertion
 * and fetching of log entries.
 */
class LogQueue {
public:
  /**
   * Constructs a LogQueue with a specified maximum size.
   * @param[in] queueMaxSize Maximum size of the log queue.
   */
  LogQueue(uint64_t queueMaxSize) : queueMaxSize(queueMaxSize), stopped(false) {
    queue.reserve(queueMaxSize);
  }

  /**
   * @brief Inserts a log entry into the queue.
   * If the queue is full, it replaces the last item in the queue.
   * This method does not wait and handles the insertion or replacement immediately.
   * @param[in] item Pointer to the log entry to be inserted.
   * @return True if the insertion was successful.
   */
  bool insert(proto::LogEntry *item) {
    {
      std::unique_lock<std::mutex> lock(queueMutex);
      if (stopped)
        return false;

      if (queue.size() >= queueMaxSize)
        queue.back() = item;
      else
        queue.emplace_back(item);
    }

    cvFetch.notify_all();
    return true;
  }

  /**
   * @brief Fetches all log entries from the queue.
   * This method blocks until there are items available to fetch or the queue is stopped.
   * @param[out] refFetchedItems Reference to a vector that will store fetched entries.
   * @return True if fetching was successful, false if stopped or empty.
   */
  bool fetch_all(std::vector<proto::LogEntry *> &refFetchedItems) {
    {
      std::unique_lock<std::mutex> lock(queueMutex);
      cvFetch.wait(lock, [&]() { return stopped || !queue.empty(); });
      if (stopped)
        return false;

      refFetchedItems = std::move(queue);
      queue.clear();
    }

    cvInsert.notify_all();
    return true;
  }

  /**
   * @brief Stops the queue.
   * This will unblock all waiting threads and prevent further operations.
   */
  void stop() {
    {
      std::unique_lock<std::mutex> lock(queueMutex);
      stopped = true;
    }

    cvFetch.notify_all();
    cvInsert.notify_all();
  }

  /**
   * @brief Checks if the queue has been stopped.
   * @return True if the queue is stopped, otherwise false.
   */
  bool is_stopped() { return stopped; }

private:
  std::vector<proto::LogEntry *> queue;
  uint64_t queueMaxSize;
  std::mutex queueMutex;
  std::condition_variable cvFetch;
  std::condition_variable cvInsert;
  bool stopped;
};

} // namespace yarilo

#endif // SNIFF_LOG_QUEUE
