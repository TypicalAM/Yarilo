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
#include <spdlog/common.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <string>
#include <tins/ethernetII.h>
#include <tins/ip.h>
#include <tins/network_interface.h>
#include <tins/sniffer.h>
#include <tins/tcp.h>
#include <tins/udp.h>

#define DEFAULT_IFACE "wlan0"

ABSL_FLAG(std::optional<std::string>, sniff_file, std::nullopt,
          "Filename to sniff on");
ABSL_FLAG(std::string, iface, DEFAULT_IFACE,
          "Network interface card to use when listening or emitting packets. "
          "Mutually exclusive with the filename option.");
ABSL_FLAG(uint32_t, port, 9090, "Port to serve the grpc server on");
ABSL_FLAG(std::string, save_path, "/opt/yarlilo/saves",
          "Directory that saves will reside in");

int main(int argc, char *argv[]) {
  absl::SetProgramUsageMessage(absl::StrCat(
      "Captures something.  Sample usage:\n", argv[0], "--iface=wlp5s0f3u2"));
  absl::ParseCommandLine(argc, argv);

  spdlog::set_level(spdlog::level::trace);
  auto base = spdlog::stdout_color_mt("base");
  base->info("Starting Yarilo");

#ifdef MAYHEM
  base->info("Mayhem enabled, use the appropriate endpoints to toggle it");
#endif

  std::filesystem::path saves = absl::GetFlag(FLAGS_save_path);
  if (!std::filesystem::exists(saves)) {
    base->info("Saves path not found, creating");
    if (!std::filesystem::create_directory(saves)) {
      base->critical("Cannot create saves directory at {}", saves.string());
      return -1;
    }

  } else if (!std::filesystem::is_directory(saves)) {
    base->critical("Saves path {} is not a directory!", saves.string());
    return -1;
  }
  base->info("Using save path: {}", saves.string());

  std::unique_ptr<Service> service;
  std::unique_ptr<Tins::BaseSniffer> sniffer;

  std::string iface = absl::GetFlag(FLAGS_iface);
  std::optional<std::string> filename = absl::GetFlag(FLAGS_sniff_file);
  if (iface != DEFAULT_IFACE && filename.has_value()) {
    base->error("Incorrect usage, both filename and network card interface was "
                "specified");
    exit(1);
  }

  if (iface != DEFAULT_IFACE ||
      (iface == DEFAULT_IFACE && !filename.has_value())) {
    base->info("Sniffing using interface: {}", iface);
    // We default to listening on the interface
    try {
      sniffer = std::make_unique<Tins::Sniffer>(iface);
    } catch (Tins::pcap_error &e) {
      base->error("Error while initializing the sniffer: {}", e.what());
      exit(1);
    }
    service = std::make_unique<Service>(std::move(sniffer),
                                        Tins::NetworkInterface(iface));
  }

  if (filename.has_value()) {
    base->info("Sniffing using filename: {}", filename.value());
    try {
      sniffer = std::make_unique<Tins::FileSniffer>(filename.value());
    } catch (Tins::pcap_error &e) {
      base->error("Error while initializing the sniffer: {}", e.what());
      exit(1);
    }
    service = std::make_unique<Service>(std::move(sniffer));
  }

  service->add_save_path(saves);
  std::string server_address =
      absl::StrFormat("0.0.0.0:%d", absl::GetFlag(FLAGS_port));

  grpc::EnableDefaultHealthCheckService(true);
  grpc::reflection::InitProtoReflectionServerBuilderPlugin();
  grpc::ServerBuilder builder;
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  builder.RegisterService(service.get());
  std::unique_ptr<grpc::Server> srv = builder.BuildAndStart();
  base->info("Serving on port {}", absl::GetFlag(FLAGS_port));
  service->start_sniffer();
  srv->Wait();
  return 0;
};
