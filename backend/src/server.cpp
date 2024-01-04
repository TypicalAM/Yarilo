#include "server.h"
#include "service.h"
#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/server_builder.h>

Server::Server(uint16_t port, Tins::BaseSniffer *sniffer) {
  std::string server_address = absl::StrFormat("0.0.0.0:%d", port);

  Service service(sniffer);
  grpc::EnableDefaultHealthCheckService(true);
  grpc::reflection::InitProtoReflectionServerBuilderPlugin();
  grpc::ServerBuilder builder;
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());

  // Register "service" as the instance through which we'll communicate with
  // clients. In this case it corresponds to an *synchronous* service.
  builder.RegisterService(&service);

  // Finally assemble the server.
  srv = builder.BuildAndStart();
  std::cout << "Serving on " << port << std::endl;
  srv->Wait();
}
