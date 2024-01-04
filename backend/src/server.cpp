#include "server.h"
#include "service.h"
#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/server_builder.h>

Server::Server(uint16_t port) {
  std::string server_address = absl::StrFormat("0.0.0.0:%d", port);

  grpc::EnableDefaultHealthCheckService(true);
  grpc::reflection::InitProtoReflectionServerBuilderPlugin();
  grpc::ServerBuilder builder;
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());

  // Register "service" as the instance through which we'll communicate with
  // clients. In this case it corresponds to an *synchronous* service.
  Service service;
  builder.RegisterService(&service);

  // Finally assemble the server.
  srv = builder.BuildAndStart();
  std::cout << "Serving on " << port << std::endl;
}

void Server::wait() {
  // Wait for the server to shutdown. Note that some other thread must be
  // responsible for shutting down the server for this call to ever return.
  srv->Wait();
}
