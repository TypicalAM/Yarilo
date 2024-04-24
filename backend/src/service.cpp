#include "service.h"
#include "access_point.h"
#include "packets.pb.h"
#include "sniffer.h"
#include <absl/strings/str_format.h>
#include <chrono>
#include <cstdint>
#include <grpcpp/server_context.h>
#include <grpcpp/support/status.h>
#include <memory>
#include <optional>
#include <thread>
#include <tins/ip.h>
#include <tins/network_interface.h>
#include <tins/packet_sender.h>
#include <tins/pdu.h>
#include <tins/tcp.h>
#include <tins/udp.h>
#include <vector>

namespace yarilo {
using grpc::ServerContext;

Service::Service(std::unique_ptr<Tins::BaseSniffer> sniffer,
                 Tins::NetworkInterface net_iface) {
  logger = spdlog::stdout_color_mt("Service");
  filemode = false;
  iface = net_iface;
  sniffinson = std::make_unique<Sniffer>(std::move(sniffer), iface);
}

Service::Service(std::unique_ptr<Tins::BaseSniffer> sniffer) {
  logger = spdlog::stdout_color_mt("Service");
  sniffinson = std::make_unique<Sniffer>(std::move(sniffer));
}

void Service::start_sniffer() { sniffinson->run(); }

void Service::add_save_path(std::filesystem::path path) {
  this->save_path = path;
}

grpc::Status Service::GetAllAccessPoints(grpc::ServerContext *context,
                                         const proto::Empty *request,
                                         proto::NetworkList *reply) {
  std::set<SSID> names = sniffinson->all_networks();
  for (const auto &name : names) {
    auto new_name = reply->add_names();
    *new_name = std::string(name);
  }

  return grpc::Status::OK;
};

grpc::Status Service::GetAccessPoint(grpc::ServerContext *context,
                                     const proto::NetworkName *request,
                                     proto::NetworkInfo *reply) {
  auto ap_option = sniffinson->get_network(request->ssid());
  if (!ap_option.has_value())
    return grpc::Status(grpc::StatusCode::NOT_FOUND,
                        "No network with this ssid");

  std::shared_ptr<AccessPoint> ap = ap_option.value();
  reply->set_name(ap->get_ssid());
  reply->set_bssid(ap->get_bssid().to_string());
  reply->set_channel(ap->get_wifi_channel());
  reply->set_encrypted_packet_count(ap->raw_packet_count());
  reply->set_decrypted_packet_count(ap->decrypted_packet_count());

  std::vector<std::shared_ptr<Client>> clients = ap->get_clients();
  for (const auto &client : clients) {
    proto::ClientInfo *info = reply->add_clients();
    info->set_addr(client->get_addr().to_string());
    info->set_is_decrypted(client->is_decrypted());
    info->set_handshake_num(client->get_key_num());
    info->set_can_decrypt(client->can_decrypt());
  }

  return grpc::Status::OK;
}

grpc::Status Service::FocusNetwork(grpc::ServerContext *context,
                                   const proto::NetworkName *request,
                                   proto::Empty *reply) {
  if (!sniffinson->get_network(request->ssid()).has_value())
    return grpc::Status(grpc::StatusCode::NOT_FOUND,
                        "No network with this ssid");

  bool success = sniffinson->focus_network(request->ssid());
  if (!success)
    return grpc::Status(grpc::StatusCode::INTERNAL,
                        "Unable to scan the network");
  return grpc::Status::OK;
}

grpc::Status Service::GetFocusState(grpc::ServerContext *context,
                                    const proto::Empty *request,
                                    proto::FocusState *reply) {
  auto ap = sniffinson->focused_network();
  bool focused = ap.has_value();

  reply->set_focused(focused);
  if (focused) {
    auto name = new proto::NetworkName();
    name->set_ssid(ap.value()->get_ssid());
    reply->set_allocated_name(name);
  };

  return grpc::Status::OK;
}

grpc::Status Service::StopFocus(grpc::ServerContext *context,
                                const proto::Empty *request,
                                proto::Empty *reply) {
  sniffinson->stop_focus();
  return grpc::Status::OK;
}

grpc::Status Service::ProvidePassword(ServerContext *context,
                                      const proto::DecryptRequest *request,
                                      proto::Empty *reply) {
  auto ap = sniffinson->get_network(request->ssid());
  if (!ap.has_value())
    return grpc::Status(grpc::StatusCode::NOT_FOUND,
                        "No network with this ssid");

  if (ap.value()->psk_correct())
    return grpc::Status(grpc::StatusCode::ALREADY_EXISTS, "Already decrypted");

  bool success = ap.value()->add_passwd(request->passwd());
  if (!success)
    return grpc::Status(grpc::StatusCode::UNKNOWN,
                        "Wrong password or no data to decrypt");

  return grpc::Status::OK;
};

grpc::Status
Service::GetDecryptedPackets(grpc::ServerContext *context,
                             const proto::NetworkName *request,
                             grpc::ServerWriter<proto::Packet> *writer) {
  auto ap = sniffinson->get_network(request->ssid());
  if (!ap.has_value())
    return grpc::Status(grpc::StatusCode::NOT_FOUND,
                        "No network with this ssid");

  // Make sure to cancel when the user cancels!
  std::shared_ptr<PacketChannel> channel = ap.value()->get_channel();
  std::thread([context, channel]() {
    while (true) {
      if (context->IsCancelled()) {
        channel->close();
        return;
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
  }).detach();

  logger->trace("Streaming packets");
  while (!channel->is_closed()) {
    std::optional<std::unique_ptr<Tins::EthernetII>> pkt_opt =
        channel->receive();
    if (!pkt_opt.has_value()) {
      logger->trace("Stream has been cancelled");
      return grpc::Status::OK;
    }

    std::unique_ptr<Tins::EthernetII> pkt = std::move(pkt_opt.value());
    auto ip = pkt->find_pdu<Tins::IP>();
    if (!ip)
      continue;

    auto tcp = pkt->find_pdu<Tins::TCP>();
    auto udp = pkt->find_pdu<Tins::UDP>();
    if (!tcp && !udp)
      continue;

    auto from = std::make_unique<proto::User>();
    from->set_ipv4address(ip->src_addr().to_string());
    from->set_macaddress(pkt->src_addr().to_string());
    from->set_port(tcp ? tcp->sport() : udp->sport());

    auto to = std::make_unique<proto::User>();
    to->set_ipv4address(ip->dst_addr().to_string());
    to->set_macaddress(pkt->dst_addr().to_string());
    to->set_port(tcp ? tcp->dport() : udp->dport());

    auto packet = std::make_unique<proto::Packet>();
    packet->set_protocol(tcp ? "TCP" : "UDP");
    packet->set_allocated_from(from.release());
    packet->set_allocated_to(to.release());

    std::vector<uint8_t> data =
        tcp ? tcp->clone()->serialize() : udp->clone()->serialize();
    std::string to_send(data.begin(), data.end());
    packet->set_data(to_send);
    writer->Write(*packet);
  }

  return grpc::Status::OK;
};

grpc::Status Service::DeauthNetwork(grpc::ServerContext *context,
                                    const proto::DeauthRequest *request,
                                    proto::Empty *reply) {
  auto ap = sniffinson->get_network(request->network().ssid());
  if (!ap.has_value())
    return grpc::Status(grpc::StatusCode::NOT_FOUND,
                        "No network with this ssid");

  bool pmf = ap.value()->management_protected();
  if (pmf)
    return grpc::Status(grpc::StatusCode::UNAVAILABLE,
                        "Target network uses protected management frames");

  bool success = ap.value()->send_deauth(&iface, request->user_addr());
  if (!success)
    return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION,
                        "Not enough information to send the packet");

  return grpc::Status::OK;
};

grpc::Status Service::IgnoreNetwork(grpc::ServerContext *context,
                                    const proto::NetworkName *request,
                                    proto::Empty *reply) {
  auto ap = sniffinson->focused_network();
  if (ap.has_value() && ap.value()->get_ssid() == request->ssid())
    sniffinson->stop_focus();

  sniffinson->add_ignored_network(request->ssid());
  return grpc::Status::OK;
};

grpc::Status Service::GetIgnoredNetworks(grpc::ServerContext *context,
                                         const proto::Empty *request,
                                         proto::NetworkList *reply) {
  for (const auto &ssid : sniffinson->ignored_networks())
    *reply->add_names() = ssid;
  return grpc::Status::OK;
};

grpc::Status Service::SaveDecryptedTraffic(grpc::ServerContext *context,
                                           const proto::NetworkName *request,
                                           proto::Empty *response) {
  auto ap = sniffinson->get_network(request->ssid());
  if (!ap.has_value())
    return grpc::Status(grpc::StatusCode::NOT_FOUND,
                        "No network with this ssid");

  bool saved = ap.value()->save_decrypted_traffic(save_path);
  if (!saved)
    return grpc::Status(grpc::StatusCode::INTERNAL,
                        "Cannot save decrypted traffic");

  return grpc::Status::OK;
};

grpc::Status Service::GetAvailableRecordings(grpc::ServerContext *context,
                                             const proto::Empty *request,
                                             proto::RecordingsList *response) {
  for (const auto &recording : sniffinson->available_recordings(save_path)) {
    proto::File *file = response->add_files();
    file->set_name(recording);
  }

  return grpc::Status::OK;
};

grpc::Status Service::LoadRecording(grpc::ServerContext *context,
                                    const proto::File *request,
                                    grpc::ServerWriter<proto::Packet> *writer) {
  if (!sniffinson->recording_exists(save_path, request->name()))
    return grpc::Status(grpc::StatusCode::NOT_FOUND,
                        "No recording with that name");

  auto stream = sniffinson->get_recording_stream(save_path, request->name());
  if (!stream.has_value())
    return grpc::Status(grpc::StatusCode::INTERNAL, "Failed to get the stream");

  auto channel = std::move(stream.value());
  logger->debug("Got stream with {} packets", channel->len());
  int iter_count = 0;

  while (iter_count != channel->len()) {
    iter_count++;
    std::optional<std::unique_ptr<Tins::EthernetII>> pkt_opt =
        channel->receive();
    if (!pkt_opt.has_value())
      return grpc::Status::OK;

    std::unique_ptr<Tins::EthernetII> pkt = std::move(pkt_opt.value());
    auto ip = pkt->find_pdu<Tins::IP>();
    if (!ip)
      continue;

    auto tcp = pkt->find_pdu<Tins::TCP>();
    auto udp = pkt->find_pdu<Tins::UDP>();
    if (!tcp && !udp)
      continue;

    auto from = std::make_unique<proto::User>();
    from->set_ipv4address(ip->src_addr().to_string());
    from->set_macaddress(pkt->src_addr().to_string());
    from->set_port(tcp ? tcp->sport() : udp->sport());

    auto to = std::make_unique<proto::User>();
    to->set_ipv4address(ip->dst_addr().to_string());
    to->set_macaddress(pkt->dst_addr().to_string());
    to->set_port(tcp ? tcp->dport() : udp->dport());

    auto packet = std::make_unique<proto::Packet>();
    packet->set_protocol(tcp ? "TCP" : "UDP");
    packet->set_allocated_from(from.release());
    packet->set_allocated_to(to.release());

    std::vector<uint8_t> data =
        tcp ? tcp->clone()->serialize() : udp->clone()->serialize();
    std::string to_send(data.begin(), data.end());
    packet->set_data(to_send);

    writer->Write(*packet);
  }

  return grpc::Status::OK;
};

grpc::Status Service::SetMayhemMode(grpc::ServerContext *context,
                                    const proto::NewMayhemState *request,
                                    proto::Empty *response) {
  if (!this->iface)
    return grpc::Status(grpc::StatusCode::UNAVAILABLE,
                        "Not listening on a live interface");
#ifndef MAYHEM
  logger->error("Tried to access rpc SetMayhemMode when mayhem is disabled!");
  return grpc::Status(grpc::StatusCode::UNAVAILABLE, "Mayhem support disabled");
#else
  logger->trace("Set mayhem hit");

  bool turn_on = request->state();
  if (turn_on) {
    if (mayhem_on.load()) {
      logger->warn("Already in mayhem");
      return grpc::Status(grpc::StatusCode::ALREADY_EXISTS,
                          "We are already in Mayhem");
    }
    mayhem_on.store(true);
    sniffinson->start_mayhem();
    return grpc::Status::OK;
  }

  if (!mayhem_on.load())
    return grpc::Status(grpc::StatusCode::ALREADY_EXISTS,
                        "We are already out of Mayhem");

  mayhem_on.store(false);
  sniffinson->stop_mayhem();
  return grpc::Status::OK;
#endif
};

grpc::Status Service::GetLED(grpc::ServerContext *context,
                             const proto::Empty *request,
                             grpc::ServerWriter<proto::LEDState> *writer) {
  if (!this->iface)
    return grpc::Status(grpc::StatusCode::UNAVAILABLE,
                        "Not listening on a live interface");
#ifndef MAYHEM
  logger->error("Tried to access rpc GetLED when mayhem is disabled!");
  return grpc::Status(grpc::StatusCode::UNAVAILABLE, "Mayhem support disabled");
#else
  logger->trace("Get led hit");
  if (led_on.load()) {
    logger->warn("Already streaming LEDs");
    return grpc::Status(grpc::StatusCode::ALREADY_EXISTS,
                        "We are already streaming LED's");
  }
  led_on.store(true);

  std::mutex led_lock;
  std::queue<LEDColor> led_queue;
  sniffinson->start_led(&led_lock, &led_queue);

  int red_on = false;
  int yellow_on = false;
  int green_on = false;

  while (led_on.load() && !context->IsCancelled()) {
    led_lock.lock();
    if (led_queue.empty()) {
      led_lock.unlock();
      continue;
    }

    LEDColor color = led_queue.front();
    led_queue.pop();
    led_lock.unlock();

    proto::LEDState nls;
    switch (color) {
    case RED_LED:
      red_on = !red_on;
      nls.set_color(proto::RED);
      nls.set_state(red_on);
      break;
    case YELLOW_LED:
      yellow_on = !yellow_on;
      nls.set_color(proto::YELLOW);
      nls.set_state(yellow_on);
      break;
    case GREEN_LED:
      green_on = !green_on;
      nls.set_color(proto::GREEN);
      nls.set_state(green_on);
      break;
    }

    writer->Write(nls);
  }

  led_on.store(false);
  sniffinson->stop_led();
  logger->trace("LED streaming stopped");
  return grpc::Status::OK;
#endif
};

} // namespace yarilo
