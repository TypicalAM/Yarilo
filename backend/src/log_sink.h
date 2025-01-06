#ifndef SNIFF_LOG_SINK
#define SNIFF_LOG_SINK

#include "log_queue.h"
#include "proto/service.pb.h"
#include <google/protobuf/util/time_util.h>
#include <spdlog/details/null_mutex.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/base_sink.h>
#include <spdlog/sinks/sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

namespace yarilo {

namespace log {

/**
 * @brief A sink for logging messages in a protobuf format.
 *
 * This class is a template-based sink that can be used with different types of
 * mutexes (standard or null mutex). It stores log entries in a queue and
 * provides access to the stored entries.
 *
 * @tparam Mutex The type of mutex used for thread-safety.
 */
template <typename Mutex>
class ProtoSink : public spdlog::sinks::base_sink<Mutex> {
public:
  /**
   * @brief Constructs a ProtoSink with a maximum number of entries.
   * @param[in] max_entries Maximum number of log entries to store in the queue.
   */
  ProtoSink(uint64_t max_entries = 50)
      : max_entries(max_entries), queue(max_entries) {}

  ~ProtoSink() override = default;

  /**
   * @brief Retrieves all log entries from the sink.
   * This method locks the sink, fetches all entries, and returns them.
   * @return A vector of pointers to log entries stored in the queue.
   */
  std::vector<proto::LogEntry *> get_entries() {
    std::lock_guard<Mutex> lock(spdlog::sinks::base_sink<Mutex>::mutex_);
    std::vector<proto::LogEntry *> result;
    queue.fetch_all(result);
    return result;
  }

  /**
   * @brief Stops the sink and all waiting clients.
   */
  void stop() { queue.stop(); }

  /**
   * @brief Checks if the sink is stopped.
   * @return True if the sink is stopped.
   */
  bool is_stopped() { return queue.is_stopped(); }

protected:
  /**
   * @brief Processes and stores a log message.
   * @param[in] msg The log message to be processed.
   */
  void sink_it_(const spdlog::details::log_msg &msg) override {
    auto entry = std::make_unique<proto::LogEntry>();
    auto timestamp = std::make_unique<google::protobuf::Timestamp>(
        google::protobuf::util::TimeUtil::NanosecondsToTimestamp(
            msg.time.time_since_epoch().count()));
    entry->set_allocated_timestamp(timestamp.release());
    entry->set_scope(
        std::string(msg.logger_name.begin(), msg.logger_name.end()));
    entry->set_payload(std::string(msg.payload.begin(), msg.payload.end()));

    switch (msg.level) {
    case spdlog::level::level_enum::trace:
      entry->set_level(proto::LogEntry::TRACE);
      break;

    case spdlog::level::level_enum::debug:
      entry->set_level(proto::LogEntry::DEBUG);
      break;

    case spdlog::level::level_enum::info:
      entry->set_level(proto::LogEntry::INFO);
      break;

    case spdlog::level::level_enum::warn:
      entry->set_level(proto::LogEntry::WARN);
      break;

    case spdlog::level::level_enum::err:
      entry->set_level(proto::LogEntry::ERR);
      break;

    case spdlog::level::level_enum::critical:
      entry->set_level(proto::LogEntry::CRITICAL);
      break;
    }

    queue.insert(entry.release());
  }

  void flush_() override {}

private:
  LogQueue queue;
  uint64_t max_entries;
};

/**
 * @brief Mutex-based ProtoSink for multi-threaded environments.
 */
using ProtoSinkMt = ProtoSink<std::mutex>;

/**
 * @brief Null mutex-based ProtoSink for single-threaded environments.
 */
using ProtoSinkSt = ProtoSink<spdlog::details::null_mutex>;

/**
 * @brief Sink storing messages in a proto format
 */
extern std::shared_ptr<ProtoSinkMt> global_proto_sink;

/**
 * @brief Yarilo log level
 */
extern spdlog::level::level_enum global_log_level;

/**
 * Get a named logger with a colored sink and a proto one
 * @param[in] name The name that the logger should use, multiple places can use
 * the same logger name
 */
std::shared_ptr<spdlog::logger> get_logger(const std::string &name);

} // namespace log

} // namespace yarilo

#endif // SNIFF_LOG_SINK
