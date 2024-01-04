#include "service.h"

grpc::Status Service::SayHello(grpc::ServerContext *context,
                               const HelloRequest *request, HelloReply *reply) {
  std::string prefix("Hello my dear");
  reply->set_message(prefix + request->name());
  return grpc::Status::OK;
}
