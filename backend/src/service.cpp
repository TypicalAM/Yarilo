#include "service.h"
#include <grpcpp/support/status.h>

Service::Service(Tins::BaseSniffer *sniffer) {
  sniffinson = new Sniffer(sniffer);
  std::thread(&Sniffer::run, sniffinson).detach();
}

grpc::Status Service::GetAccessPoint(grpc::ServerContext *context,
                                     const GetAPRequest *request, AP *reply) {
  std::optional<AccessPoint *> ap_option = sniffinson->get_ap(request->ssid());
  if (!ap_option.has_value())
    return grpc::Status::CANCELLED;

  AccessPoint *ap = ap_option.value();
  reply->set_name(ap->get_ssid()); // TODO: just a test
  reply->set_bssid(ap->get_bssid().to_string());
  reply->set_channel(ap->get_wifi_channel());
  return grpc::Status::OK;
}

grpc::Status Service::GetAllAccessPoints(grpc::ServerContext *context,
                                         const Empty *request,
                                         SSIDList *reply) {
  std::set<SSID> names = sniffinson->get_networks();
  for (const auto &name : names) {
    auto new_name = reply->add_names();
    *new_name = std::string(name);
  }

  return grpc::Status::OK;
};

grpc::Status Service::ProvidePassword(grpc::ServerContext *context,
                                      const PSKRequest *request,
                                      PSKResponse *reply) {
  std::optional<AccessPoint *> ap = sniffinson->get_ap(request->ssid());
  if (!ap.has_value()) {
    reply->set_success(false);
    return grpc::Status::OK;
  }

  ap.value()->add_passwd(request->passwd()); // TODO: Validation logic?
  reply->set_success(true);
  return grpc::Status::OK;
};
