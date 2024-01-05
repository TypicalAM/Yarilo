#include "service.h"
#include "packets.pb.h"
#include <grpcpp/support/status.h>
#include <memory>
#include <optional>
#include <tins/ip.h>
#include <tins/tcp.h>
#include <tins/udp.h>

Service::Service(Tins::BaseSniffer *sniffer) {
  sniffinson = new Sniffer(sniffer);
  std::thread(&Sniffer::run, sniffinson).detach();
}

grpc::Status Service::GetAccessPoint(grpc::ServerContext *context,
                                     const NetworkName *request, AP *reply) {
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
                                         AvailableNetworks *reply) {
  std::set<SSID> names = sniffinson->get_networks();
  for (const auto &name : names) {
    auto new_name = reply->add_names();
    *new_name = std::string(name);
  }

  return grpc::Status::OK;
};

grpc::Status Service::ProvidePassword(grpc::ServerContext *context,
                                      const DecryptRequest *request,
                                      DecryptResponse *reply) {
  std::optional<AccessPoint *> ap = sniffinson->get_ap(request->ssid());
  if (!ap.has_value()) {
    reply->set_success(false);
    return grpc::Status::OK;
  }

  ap.value()->add_passwd(request->passwd()); // TODO: Validation logic?
  reply->set_success(true);
  return grpc::Status::OK;
};

grpc::Status Service::GetDecryptedPackets(grpc::ServerContext *context,
                                          const NetworkName *request,
                                          grpc::ServerWriter<Packet> *writer) {
  std::optional<AccessPoint *> ap = sniffinson->get_ap(request->ssid());
  if (!ap.has_value())
    return grpc::Status::CANCELLED;

  int i = 0; // TODO: Make channel close automatically or client cancel
  Channel<Tins::EthernetII *> *channel = ap.value()->get_channel();
  while (true) {
    Tins::EthernetII *pkt = channel->receive();
    auto ip = pkt->find_pdu<Tins::IP>();
    if (!ip)
      continue;

    i++;
    if (i > 25)
      return grpc::Status::OK;

    auto tcp = pkt->find_pdu<Tins::TCP>();
    auto udp = pkt->find_pdu<Tins::UDP>();
    if (!tcp && !udp)
      continue;

    auto from = std::make_unique<User>();
    from->set_ipv4address(ip->src_addr().to_string());
    from->set_macaddress(pkt->src_addr().to_string());
    from->set_port(tcp ? tcp->sport() : udp->sport());

    auto to = std::make_unique<User>();
    to->set_ipv4address(ip->dst_addr().to_string());
    to->set_macaddress(pkt->dst_addr().to_string());
    to->set_port(tcp ? tcp->dport() : udp->dport());

    auto packet = std::make_unique<Packet>();
    packet->set_protocol(tcp ? "TCP" : "UDP");
    packet->set_allocated_from(from.release());
    packet->set_allocated_to(to.release());

    // std::string data =
    //     tcp ? std::string(tcp->serialize().begin(), tcp->serialize().end())
    //         : std::string(udp->serialize().begin(), udp->serialize().end());
    // packet.set_data(data);
    //
    writer->Write(*packet);
  }
}
