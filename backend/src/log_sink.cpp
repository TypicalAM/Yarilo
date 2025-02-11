#include "log_sink.h"
#include <memory>

namespace yarilo {

namespace log {

std::shared_ptr<ProtoSinkMt> global_proto_sink =
    std::make_shared<ProtoSinkMt>(50);

spdlog::level::level_enum global_log_level = spdlog::level::info;

std::shared_ptr<spdlog::logger> get_logger(const std::string &name) {
  auto color_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
  std::string sink_name = name;
  if (sink_name.size() > 25)
    sink_name = sink_name.substr(0, 25);

  std::shared_ptr<spdlog::logger> logger = spdlog::get(sink_name);
  if (!logger) {
    logger = std::make_shared<spdlog::logger>(
        sink_name,
        spdlog::sinks_init_list{global_proto_sink, std::move(color_sink)});
    logger->set_level(global_log_level);
  }

  return logger;
}

} // namespace log

} // namespace yarilo
