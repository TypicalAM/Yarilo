#include "service.h"

Service::Service(Tins::BaseSniffer *sniffer) {
  sniffinson = new Sniffer(sniffer);
  std::thread(&Sniffer::run, sniffinson).detach();
}

grpc::Status Service::SayHello(grpc::ServerContext *context,
                               const HelloRequest *request, HelloReply *reply) {
  std::string prefix("Hello my dear");
  reply->set_message(prefix + request->name());
  return grpc::Status::OK;
}

grpc::Status Service::GetAccessPoint(grpc::ServerContext *context,
                                     const GetAPRequest *request, AP *reply) {
  auto ap = sniffinson->get_ap(request->ssid());
  if (!ap.has_value())
    return grpc::Status::CANCELLED;

  reply->set_name(ap.value()->get_ssid()); // TODO: just a test
  reply->set_bssid("ff:ff:ff:ff:ff:ff");
  reply->set_channel(0);
  return grpc::Status::OK;
}
