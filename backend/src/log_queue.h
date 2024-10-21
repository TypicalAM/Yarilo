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
  LogQueue(uint64_t queueMaxSize) : queueMaxSize(queueMaxSize) {
    queue.reserve(queueMaxSize);
  }

  /**
   * @brief Inserts a log entry into the queue.
   * This method blocks until space is available in the queue. 
   * @param[in] item Pointer to the log entry to be inserted.
   * @return True if the insertion was successful, false if timed out.
   */
  bool insert(proto::LogEntry *item) {
    {
      std::unique_lock<std::mutex> lock(queueMutex);
      if (!cvInsert.wait_for(lock, std::chrono::seconds(2),
                             [&queue = queue, &queueMaxSize = queueMaxSize] {
                               return queue.size() < queueMaxSize;
                             }))
        return false;
      queue.emplace_back(item);
    }

    cvFetch.notify_all();
    return true;
  }

  /**
   * @brief Fetches all log entries from the queue.
   * This method blocks until there are items available to fetch.
   * @param[out] refFetchedItems Reference to a vector that will store fetched entries.
   * @return True if fetching was successful, false if timed out.
   */
  bool fetch_all(std::vector<proto::LogEntry *> &refFetchedItems) {
    {
      std::unique_lock<std::mutex> lock(queueMutex);
      if (!cvFetch.wait_for(lock, std::chrono::seconds(2),
                            [&queue = queue] { return !queue.empty(); }))
        return false;
      refFetchedItems = std::move(queue);
      queue.clear();
    }

    cvInsert.notify_all();
    return true;
  }

private:
  std::vector<proto::LogEntry *> queue;
  uint64_t queueMaxSize;
  std::mutex queueMutex;
  std::condition_variable cvFetch;
  std::condition_variable cvInsert;
};

} // namespace yarilo

#endif // SNIFF_LOG_QUEUE