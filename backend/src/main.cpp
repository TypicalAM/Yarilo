#include "sniffer.h"
#include <iostream>
#include <string>
#include <thread>
#include <tins/ethernetII.h>
#include <tins/ip.h>
#include <tins/sniffer.h>
#include <tins/tcp.h>
#include <tins/udp.h>

#include "absl/flags/parse.h"
#include "absl/strings/str_format.h"

#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>

enum class Mode { INTERFACE, FILE };

struct args {
  Mode mode;
  std::string value;
};

args parse_args(int argc, char *argv[]) {
  args args;

  if (argc < 3) {
    std::cerr << "Usage: " << argv[0] << " <interface|file> <value>"
              << std::endl;
    exit(1);
  }

  std::string modeStr = argv[1];
  if (modeStr == "interface" || modeStr == "if") {
    args.mode = Mode::INTERFACE;
  } else if (modeStr == "file") {
    args.mode = Mode::FILE;
  } else {
    std::cerr << "Invalid mode. Use 'interface', 'if' or 'file'." << std::endl;
    exit(1);
  }

  args.value = argv[2];
  return args;
}

int main2(int argc, char *argv[]) {
  args cfg = parse_args(argc, argv);

  Tins::BaseSniffer *sniffer;
  if (cfg.mode == Mode::FILE) {
    sniffer = new Tins::FileSniffer(cfg.value);
  } else {
    sniffer = new Tins::Sniffer(cfg.value);
  }

  Sniffer sniffinson(sniffer);
  // live_decrypter.ignore_network("Coherer");
  std::thread(&Sniffer::run, &sniffinson).detach();
  std::cout << "Press any key" << std::endl;
  std::cin.ignore();
  std::cout << "Detected networks" << std::endl;
  std::set<SSID> nets = sniffinson.get_networks();
  SSID ssid;
  for (const auto &net : nets) {
    std::cout << net << std::endl;
    if (net[0] == 'S' && net[1] == 'c')
      ssid = net;
  }

  auto net = sniffinson.get_ap(ssid);
  if (!net.has_value()) {
    std::cout << "Didn't find network" << std::endl;
    return -1;
  }

  net.value()->add_passwd("MlodyBoss1");
  auto channel = net.value()->get_channel();
  while (true) {
    Tins::EthernetII *pkt = channel->receive();
    auto tcp = pkt->find_pdu<Tins::TCP>();
    if (tcp) {
      auto ip = pkt->find_pdu<Tins::IP>();
      std::cout << "TCP packet from " << ip->src_addr() << ":" << tcp->sport()
                << " to " << ip->dst_addr() << ":" << tcp->dport() << std::endl;
    }

    auto udp = pkt->find_pdu<Tins::UDP>();
    if (udp) {
      auto ip = pkt->find_pdu<Tins::IP>();
      std::cout << "UDP packet from " << ip->src_addr() << ":" << udp->sport()
                << " to " << ip->dst_addr() << ":" << udp->dport() << std::endl;
    }
  }

  return 0;
};

#include "packets.grpc.pb.h"

class GreeterServiceImpl final : public Greeter::Service {
  grpc::Status SayHello(grpc::ServerContext *context,
                        const HelloRequest *request,
                        HelloReply *reply) override {
    std::string prefix("Hello ");
    reply->set_message(prefix + request->name());
    return grpc::Status::OK;
  }
};

void RunServer(uint16_t port) {
  std::string server_address = absl::StrFormat("0.0.0.0:%d", port);
  GreeterServiceImpl service;

  grpc::EnableDefaultHealthCheckService(true);
  grpc::reflection::InitProtoReflectionServerBuilderPlugin();
  grpc::ServerBuilder builder;
  // Listen on the given address without any authentication mechanism.
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  // Register "service" as the instance through which we'll communicate with
  // clients. In this case it corresponds to an *synchronous* service.
  builder.RegisterService(&service);
  // Finally assemble the server.
  std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
  std::cout << "Server listening on " << server_address << std::endl;

  // Wait for the server to shutdown. Note that some other thread must be
  // responsible for shutting down the server for this call to ever return.
  server->Wait();
}

class GreeterClient {
public:
  GreeterClient(std::shared_ptr<grpc::Channel> channel)
      : stub_(Greeter::NewStub(channel)) {}

  // Assembles the client's payload, sends it and presents the response back
  // from the server.
  std::string SayHello(const std::string &user) {
    // Data we are sending to the server.
    HelloRequest request;
    request.set_name(user);

    // Container for the data we expect from the server.
    HelloReply reply;

    // Context for the client. It could be used to convey extra information to
    // the server and/or tweak certain RPC behaviors.
    grpc::ClientContext context;

    // The actual RPC.
    grpc::Status status = stub_->SayHello(&context, request, &reply);

    // Act upon its status.
    if (status.ok()) {
      return reply.message();
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return "RPC failed";
    }
  }

private:
  std::unique_ptr<Greeter::Stub> stub_;
};

int main(int argc, char *argv[]) {
  if (argc > 1) {
    RunServer(2137);
  } else {
    GreeterClient greeter(grpc::CreateChannel(
        "localhost:2137", grpc::InsecureChannelCredentials()));
    std::string user("world");
    std::string reply = greeter.SayHello(user);
    std::cout << "Greeter received: " << reply << std::endl;
  }
}
