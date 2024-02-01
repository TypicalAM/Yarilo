#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/flags/usage.h"
#include "service.h"
#include <absl/flags/internal/flag.h>
#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/server_builder.h>
#include <iostream>
#include <string>
#include <tins/ethernetII.h>
#include <tins/ip.h>
#include <tins/network_interface.h>
#include <tins/sniffer.h>
#include <tins/tcp.h>
#include <tins/udp.h>

ABSL_FLAG(std::string, filename, "pcap/wpa_induction.pcap",
          "Filename to use (sets file mode on)");
ABSL_FLAG(std::string, iface, "wlan0", "Monitor mode interface to listen on");
ABSL_FLAG(
    bool, fromfile, true,
    "Whether to use the file capture mode (instead of the live capture one)");

int main(int argc, char *argv[]) {
  absl::SetProgramUsageMessage(
      absl::StrCat("Captures something.  Sample usage:\n", argv[0],
                   " --fromfile=no --iface=wlp5s0f3u2"));

  absl::ParseCommandLine(argc, argv);

#ifdef MAYHEM
  std::cout << "Mayhem enabled, use the appropriate endpoints to toggle it"
            << std::endl;
#endif

  Service *service;
  Tins::BaseSniffer *sniffer;
  if (absl::GetFlag(FLAGS_fromfile)) {
    sniffer = new Tins::FileSniffer(absl::GetFlag(FLAGS_filename));
    service = new Service(sniffer);
  } else {
    std::string iface = absl::GetFlag(FLAGS_iface);
    sniffer = new Tins::Sniffer(iface);
    service = new Service(sniffer, Tins::NetworkInterface(iface));
    std::cout << "Using interface " << iface << std::endl;
  }

  int port = 9090;
  std::string server_address = absl::StrFormat("0.0.0.0:%d", port);

  grpc::EnableDefaultHealthCheckService(true);
  grpc::reflection::InitProtoReflectionServerBuilderPlugin();
  grpc::ServerBuilder builder;
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());

  // Register "service" as the instance through which we'll communicate with
  // clients. In this case it corresponds to an *synchronous* service.
  builder.RegisterService(service);

  // Finally assemble the server.
  std::unique_ptr<grpc::Server> srv = builder.BuildAndStart();
  std::cout << "Serving on " << port << std::endl;
  srv->Wait();
  return 0;
};
