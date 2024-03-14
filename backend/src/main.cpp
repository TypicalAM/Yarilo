#include "net_card_manager.h"
#include "service.h"
#include <absl/flags/flag.h>
#include <absl/flags/internal/flag.h>
#include <absl/flags/parse.h>
#include <absl/flags/usage.h>
#include <absl/strings/str_format.h>
#include <cstdint>
#include <filesystem>
#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/server_builder.h>
#include <memory>
#include <optional>
#include <pcap/pcap.h>
#include <spdlog/common.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <sstream>
#include <string>
#include <tins/ethernetII.h>
#include <tins/ip.h>
#include <tins/network_interface.h>
#include <tins/sniffer.h>
#include <tins/tcp.h>
#include <tins/udp.h>
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

std::optional<std::unique_ptr<Service>>
init_service(std::shared_ptr<spdlog::logger> log) {
  std::unique_ptr<Service> service;
  std::unique_ptr<Tins::BaseSniffer> sniffer;

  std::string iface = absl::GetFlag(FLAGS_iface);
  std::optional<std::string> filename = absl::GetFlag(FLAGS_sniff_file);

  if (iface != DEFAULT_IFACE && filename.has_value()) {
    log->error("Incorrect usage, both filename and network card interface was "
               "specified");
    return std::nullopt;
  }

  if (filename.has_value()) {
    log->info("Sniffing using filename: {}", filename.value());
    try {
      sniffer = std::make_unique<Tins::FileSniffer>(filename.value());
    } catch (const Tins::pcap_error &e) {
      log->error("Error while initializing the sniffer: {}", e.what());
      return std::nullopt;
    }
    service = std::make_unique<Service>(std::move(sniffer));
    return service;
  }

  log->info("Sniffing using interface: {}", iface);

  std::set<std::string> interfaces = Tins::Utils::network_interfaces();
  if (interfaces.find(iface) == interfaces.end()) {
    log->critical("There is no available interface by that name: {}", iface);
    return std::nullopt;
  }

  Tins::SnifferConfiguration config;
  config.set_rfmon(true);

  try {
    sniffer = std::make_unique<Tins::Sniffer>(iface, config);
  } catch (const Tins::pcap_error &e) {
    log->error("Error while initializing the sniffer: {}", e.what());
    return std::nullopt;
  }

  service = std::make_unique<Service>(std::move(sniffer),
                                      Tins::NetworkInterface(iface));
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

void manager_test(std::shared_ptr<spdlog::logger> log) {
  NetCardManager nm;
  nm.connect();

  for (const auto phy_name : nm.phy_interfaces()) {
    auto phy = nm.phy_details(phy_name);
    log->info(
        "Physical interface: {}, supports {} frequencies and monitor mode: {}",
        phy->ifname, phy->frequencies.size(), phy->can_monitor);
    std::stringstream ss;
    for (const auto freq : phy->frequencies)
      ss << freq << " ";
    log->info(ss.str());
  }

  auto ifnames = nm.net_interfaces();
  for (const auto ifname : ifnames) {
    auto details = nm.net_iface_details(ifname);
    if (details.has_value()) {
      log->info("Interface {} (allocated to phy {} at {}) - has an active "
                "frequency of {} and is of type: {}",
                ifname, details.value().phy_idx, details.value().logic_idx,
                details.value().freq, details.value().type);
      nl80211_iftype mytype;
    }
  }

  nm.disconnect();
};

int main(int argc, char *argv[]) {
  absl::SetProgramUsageMessage(
      absl::StrCat("Captures and decrypts packets. Sample usage:\n", argv[0],
                   "--iface=wlp5s0f3u2"));
  absl::ParseCommandLine(argc, argv);

  auto log_opt = init_logger();
  if (!log_opt.has_value())
    return 1;
  auto log = log_opt.value();

  log->info("Starting Yarilo");
  manager_test(log);
  log->info("Done");
  return 0;

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
  auto service = std::move(service_opt.value());
  log->info("Using save path: {}", saves.string());

  service->add_save_path(saves);
  std::string server_address =
      absl::StrFormat("0.0.0.0:%d", absl::GetFlag(FLAGS_port));

  grpc::EnableDefaultHealthCheckService(true);
  grpc::reflection::InitProtoReflectionServerBuilderPlugin();
  grpc::ServerBuilder builder;
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  builder.RegisterService(service.get());
  std::unique_ptr<grpc::Server> srv = builder.BuildAndStart();
  log->info("Serving on port {}", absl::GetFlag(FLAGS_port));
  service->start_sniffer();
  srv->Wait();
  return 0;
};
