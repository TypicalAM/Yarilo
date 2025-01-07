#include "log_sink.h"
#include "service.h"
#include <absl/flags/flag.h>
#include <absl/flags/internal/flag.h>
#include <absl/flags/parse.h>
#include <absl/flags/usage.h>
#include <absl/strings/str_format.h>
#include <csignal>
#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/server_builder.h>
#include <memory>
#include <optional>
#include <spdlog/common.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <tins/utils/routing_utils.h>

static std::unique_ptr<grpc::Server> server;
static std::unique_ptr<yarilo::Service> service;
static std::atomic<bool> shutdown_required = false;
static std::mutex shutdown_mtx;
static std::condition_variable shutdown_cv;

ABSL_FLAG(std::optional<std::string>, sniff_file, std::nullopt,
          "Create a FileSniffer from this file on startup");
ABSL_FLAG(std::optional<std::string>, iface, std::nullopt,
          "Create an InterfaceSniffer from this file on startup");
ABSL_FLAG(std::string, host, "0.0.0.0", "Host for the gRPC server");
ABSL_FLAG(uint32_t, port, 9090, "Port for the gRPC server");
ABSL_FLAG(std::string, save_path, "/opt/yarilo/saves",
          "Directory to discover and save packet captures");
ABSL_FLAG(std::string, db_file, "/opt/yarilo/db.sqlite3",
          "Path to the database file");
ABSL_FLAG(std::string, oid_file, "/opt/yarilo/src/backend/data/oid.txt",
          "Path to the OIDs list for MAC vendor lookup");
ABSL_FLAG(bool, save_on_shutdown, false,
          "Dump all packets on program termination");
ABSL_FLAG(std::string, log_level, "info", "Log level (debug, info, trace)");
ABSL_FLAG(std::vector<std::string>, ignore_bssids, {},
          "Access point hardware addresses to ignore on startup");
ABSL_FLAG(
    std::string, battery_file, "/tmp/battery_level",
    "Path to the battery percentage file (only with battery support enabled)");

bool set_log_level() {
  std::string log_level = absl::GetFlag(FLAGS_log_level);
  if (log_level == "info") {
    yarilo::log::global_log_level = spdlog::level::info;
  } else if (log_level == "debug") {
    yarilo::log::global_log_level = spdlog::level::debug;
  } else if (log_level == "trace") {
    yarilo::log::global_log_level = spdlog::level::trace;
  } else {
    spdlog::critical("Unexpected log level: {}", log_level);
    return false;
  }

  return true;
}

std::optional<std::filesystem::path>
init_saves(std::shared_ptr<spdlog::logger> log) {
  std::filesystem::path saves = absl::GetFlag(FLAGS_save_path);
  if (!std::filesystem::exists(saves)) {
    log->info("Saves path not found, creating");
    try {
      std::filesystem::create_directories(saves);
    } catch (const std::runtime_error &e) {
      log->critical("Cannot create saves directory at {}, {}", saves.string(),
                    e.what());
      return std::nullopt;
    }
  } else if (!std::filesystem::is_directory(saves)) {
    log->critical("Saves path {} is not a directory!", saves.string());
    return std::nullopt;
  }

  return saves;
}

std::optional<std::filesystem::path>
init_oid_file(std::shared_ptr<spdlog::logger> log) {
  std::filesystem::path oid_file = absl::GetFlag(FLAGS_oid_file);
  if (!std::filesystem::exists(oid_file)) {
    log->critical("No OID seed file provided at {}, use the one provided "
                  "with the repository source",
                  oid_file.string());
    return std::nullopt;
  }

  return oid_file;
}

std::optional<std::filesystem::path>
init_battery_file(std::shared_ptr<spdlog::logger> log) {
#ifndef BATTERY_SUPPORT
  return "/dev/null";
#else
  std::filesystem::path battery_file = absl::GetFlag(FLAGS_battery_file);
  if (!std::filesystem::exists(battery_file)) {
    log->critical("Battery file {} doesn't exist!", battery_file.string());
    return std::nullopt;
  }

  return battery_file;
#endif // BATTERY_SUPPORT
}

bool init_first_sniffer(std::shared_ptr<spdlog::logger> log) {
  std::optional<std::string> net_iface_name = absl::GetFlag(FLAGS_iface);
  std::optional<std::string> filename = absl::GetFlag(FLAGS_sniff_file);

  if (net_iface_name.has_value() && filename.has_value()) {
    log->error("Incorrect usage, both filename and network card interface was "
               "specified");
    return false;
  }

  if (!net_iface_name.has_value() && !filename.has_value()) {
    log->info("No sniffers initialized");
    return true;
  }

  if (filename.has_value())
    return service->add_file_sniffer(filename.value()).has_value();
  return service->add_iface_sniffer(net_iface_name.value()).has_value();
}

void handle_signal(int sig) {
  const std::lock_guard lock(shutdown_mtx);
  shutdown_required = true;
  shutdown_cv.notify_one();
}

void shutdown_check() {
  std::unique_lock<std::mutex> lock(shutdown_mtx);
  shutdown_cv.wait(lock, []() { return shutdown_required.load(); });
  yarilo::log::global_proto_sink->stop();
  service->shutdown();
  server->Shutdown();
}

int main(int argc, char *argv[]) {
  absl::SetProgramUsageMessage(
      absl::StrCat("packet sniffer designed "
                   "for capturing and decrypting wireless "
                   "network traffic\n\n",
                   "Sample usage:\n  ", argv[0],
                   " --iface=wlp5s0f4u2 \\\n    "
                   "--save_path=/opt/yarilo/saves \\\n    "
                   "--db_file=/opt/yarilo/saves \\\n    "
                   "--log_level=trace"));
  absl::ParseCommandLine(argc, argv);

  if (!set_log_level())
    return 1;

  auto logger = yarilo::log::get_logger("Yarilo");
  logger->info("Starting Yarilo");

  std::vector<yarilo::MACAddress> ignored_bssids{};
  for (const auto &addr : absl::GetFlag(FLAGS_ignore_bssids))
    ignored_bssids.emplace_back(addr);

  std::optional<std::filesystem::path> saves_path = init_saves(logger);
  if (!saves_path.has_value())
    return 1;

  std::filesystem::path db_file = absl::GetFlag(FLAGS_db_file);

  std::optional<std::filesystem::path> battery_file = init_battery_file(logger);
  if (!battery_file.has_value())
    return 1;

  std::optional<std::filesystem::path> oid_file = init_oid_file(logger);
  if (!oid_file.has_value())
    return 1;

  yarilo::Service::config cfg{
      .save_on_shutdown = absl::GetFlag(FLAGS_save_on_shutdown),
      .saves_path = saves_path.value(),
      .db_file = db_file,
      .oid_file = oid_file.value(),
      .battery_file_path = battery_file.value(),
      .ignored_bssids = ignored_bssids,
  };

  try {
    service = std::make_unique<yarilo::Service>(cfg);
    if (!init_first_sniffer(logger))
      return 1;

    std::string server_address = absl::StrFormat(
        "%s:%d", absl::GetFlag(FLAGS_host), absl::GetFlag(FLAGS_port));
    logger->info("Server address: {}", server_address);
    grpc::EnableDefaultHealthCheckService(true);
    grpc::reflection::InitProtoReflectionServerBuilderPlugin();
    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(service.get());

    std::signal(SIGINT, handle_signal);
    std::signal(SIGHUP, handle_signal);
    std::signal(SIGTERM, handle_signal);
    std::signal(SIGQUIT, handle_signal);
    std::thread t(shutdown_check);
    server = builder.BuildAndStart();
    t.join();
  } catch (const std::exception &e) {
    logger->critical("Encountered critical error: {}", e.what());
    return 1;
  }

  return 0;
};
