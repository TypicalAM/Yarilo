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
#include <tins/utils/routing_utils.h>

#define DEFAULT_IFACE "wlan0"

ABSL_FLAG(std::optional<std::string>, sniff_file, std::nullopt,
          "Filename to sniff on");
ABSL_FLAG(std::string, iface, DEFAULT_IFACE,
          "Network interface card to use when listening or emitting packets. "
          "Mutually exclusive with the filename option.");
ABSL_FLAG(uint32_t, port, 9090, "Port to serve the grpc server on");
ABSL_FLAG(std::string, save_path, "/opt/yarlilo/saves",
          "Directory that saves will reside in");
ABSL_FLAG(std::string, log_level, "info", "Log level (debug, info, trace)");

std::optional<std::shared_ptr<spdlog::logger>> init_logger() {
  std::string log_level = absl::GetFlag(FLAGS_log_level);
  auto log = spdlog::stdout_color_mt("base");
  if (log_level == "info") {
    spdlog::set_level(spdlog::level::info);
  } else if (log_level == "debug") {
    spdlog::set_level(spdlog::level::debug);
  } else if (log_level == "trace") {
    spdlog::set_level(spdlog::level::trace);
  } else {
    spdlog::set_level(spdlog::level::info);
    log->critical("Unexpected log level: {}", log_level);
    return std::nullopt;
  }
  return log;
}

std::optional<std::unique_ptr<yarilo::Service>>
init_service(std::shared_ptr<spdlog::logger> log) {
  std::string iface_candidate = absl::GetFlag(FLAGS_iface);
  std::optional<std::string> filename = absl::GetFlag(FLAGS_sniff_file);

  if (iface_candidate != DEFAULT_IFACE && filename.has_value()) {
    log->error("Incorrect usage, both filename and network card interface was "
               "specified");
    return std::nullopt;
  }

  std::unique_ptr<yarilo::Service> service;
  if (filename.has_value()) {
    log->info("Sniffing using filename: {}", filename.value());
    try {
      auto sniffer = std::make_unique<Tins::FileSniffer>(filename.value());
      service = std::make_unique<yarilo::Service>(std::move(sniffer));
    } catch (const Tins::pcap_error &e) {
      log->error("Error while initializing the sniffer: {}", e.what());
      return std::nullopt;
    }

    return service;
  }

  std::optional<std::string> iface =
      yarilo::Sniffer::detect_interface(log, iface_candidate);
  if (!iface.has_value()) {
    log->critical("Didn't find suitable interface, bailing out");
    return std::nullopt;
  }

  log->info("Sniffing using interface: {}", iface.value());

  std::set<std::string> interfaces = Tins::Utils::network_interfaces();
  if (!interfaces.count(iface.value())) {
    log->critical("There is no available interface by that name: {}",
                  iface.value());
    return std::nullopt;
  }

  try {
    auto sniffer = std::make_unique<Tins::Sniffer>(iface.value());
    service = std::make_unique<yarilo::Service>(
        std::move(sniffer), Tins::NetworkInterface(iface.value()));
  } catch (const Tins::pcap_error &e) {
    log->error("Error while initializing the sniffer: {}", e.what());
    return std::nullopt;
  }

  return service;
};

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

static std::unique_ptr<grpc::Server> server;
static std::unique_ptr<yarilo::Service> service;
static std::atomic<bool> shutdown_required = false;
static std::mutex shutdown_mtx;
static std::condition_variable shutdown_cv;

void handle_signal(int sig) {
  const std::lock_guard lock(shutdown_mtx);
  shutdown_required.store(true);
  shutdown_cv.notify_one();
}

void shutdown_check() {
  std::unique_lock<std::mutex> lock(shutdown_mtx);
  shutdown_cv.wait(lock, []() { return shutdown_required.load(); });
  server->Shutdown();
  service->shutdown();
}

int main(int argc, char *argv[]) {
  absl::SetProgramUsageMessage(
      absl::StrCat("packet sniffer designed "
                   "for capturing and decrypting encrypted wireless "
                   "network traffic\n\n",
                   "Sample usage:\n  ", argv[0],
                   " --iface=wlp5s0f4u2 \\\n    "
                   "--save_path=/opt/yarilo/saves \\\n    "
                   "--log_level=trace"));
  absl::ParseCommandLine(argc, argv);

  auto log_opt = init_logger();
  if (!log_opt.has_value())
    return 1;
  auto log = log_opt.value();

  log->info("Starting Yarilo");

#ifdef MAYHEM
  log->info("Mayhem enabled, use the appropriate endpoints to toggle it");
#endif

  auto saves_opt = init_saves(log);
  if (!saves_opt.has_value())
    return 1;
  auto saves = saves_opt.value();

  auto service_opt = init_service(log);
  if (!service_opt.has_value())
    return 1;
  service = std::move(service_opt.value());
  log->info("Using save path: {}", saves.string());

  service->add_save_path(saves);
  std::string server_address =
      absl::StrFormat("0.0.0.0:%d", absl::GetFlag(FLAGS_port));

  grpc::EnableDefaultHealthCheckService(true);
  grpc::reflection::InitProtoReflectionServerBuilderPlugin();
  grpc::ServerBuilder builder;
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  builder.RegisterService(service.get());
  log->info("Serving on port {}", absl::GetFlag(FLAGS_port));

  std::signal(SIGINT, handle_signal);
  std::signal(SIGQUIT, handle_signal);
  std::signal(SIGTERM, handle_signal);
  std::thread t(shutdown_check);
  server = builder.BuildAndStart();
  service->start();
  t.join();
  return 0;
};
