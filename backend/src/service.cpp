#include "service.h"
#include "access_point.h"
#include "database.h"
#include "decrypter.h"
#include "formatter.h"
#include "log_sink.h"
#include "proto/service.pb.h"
#include "recording.h"
#include "uuid.h"
#include <cstdint>
#include <google/protobuf/timestamp.pb.h>
#include <google/protobuf/util/time_util.h>
#include <grpcpp/support/status.h>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tins/ethernetII.h>
#include <tins/hw_address.h>
#include <tins/ip.h>
#include <tins/network_interface.h>
#include <tins/packet.h>
#include <tins/packet_sender.h>
#include <tins/pdu.h>
#include <tins/sniffer.h>
#include <tins/tcp.h>
#include <tins/tins.h>
#include <tins/utils/routing_utils.h>

using client_window = yarilo::WPA2Decrypter::client_window;
using group_window = yarilo::WPA2Decrypter::group_window;
using client_info = yarilo::AccessPoint::client_info;
using DecryptionState = yarilo::AccessPoint::DecryptionState;
using TimeUtil = google::protobuf::util::TimeUtil;
using recording_info = yarilo::Recording::info;
using Timestamp = google::protobuf::Timestamp;

namespace yarilo {

Service::Service(const config &cfg) : cfg(cfg), db(cfg.db_file) {
  logger = log::get_logger("Service");
  logger->info("Created a service using:\n\tSave path: {}\n\tDatabase path {}",
               cfg.saves_path.string(), cfg.db_file.string());

  if (!db.initialize()) {
    logger->error("Failed to initialize the database. Aborting.");
    throw std::runtime_error("Database fail.");
  }

  if (!cfg.oid_file.string().empty()) {
    if (!db.load_vendors(cfg.oid_file.string()))
      throw std::runtime_error("Database fail.");
  } else {
    if (!db.check_vendors())
      throw std::runtime_error("Database fail.");
  }

  clean_save_dir();
}

std::optional<uuid::UUIDv4>
Service::add_file_sniffer(const std::filesystem::path &file) {
  uuid::UUIDv4 id = uuid::generate_v4();

  try {
    sniffers[id] = std::make_unique<Sniffer>(
        std::make_unique<Tins::FileSniffer>(file.string()), file, db);
    sniffers[id]->start();
    for (const auto &addr : cfg.ignored_bssids)
      sniffers[id]->add_ignored_network(addr);
  } catch (const Tins::pcap_error &e) {
    logger->error("Error while initializing the sniffer: {}", e.what());
    return std::nullopt;
  }

  logger->info("Added new sniffer: FileSniffer ({}) - {}", file.string(), id);
  return id;
}

std::optional<uuid::UUIDv4>
Service::add_iface_sniffer(const std::string &iface_name) {
  std::optional<std::string> iface =
      yarilo::Sniffer::detect_interface(this->logger, iface_name);
  if (!iface.has_value()) {
    logger->error("Didn't find suitable interface");
    return std::nullopt;
  }

  logger->info("Sniffing using interface: {}", iface.value());

  std::set<std::string> interfaces = Tins::Utils::network_interfaces();
  if (!interfaces.count(iface.value())) {
    logger->error("There is no available interface by that name: {}",
                  iface.value());
    return std::nullopt;
  }

  uuid::UUIDv4 id = uuid::generate_v4();

  try {
    sniffers[id] = std::make_unique<Sniffer>(
        std::make_unique<Tins::Sniffer>(iface.value()),
        Tins::NetworkInterface(iface.value()), db);
    sniffers[id]->start();
    for (const auto &addr : cfg.ignored_bssids)
      sniffers[id]->add_ignored_network(addr);
  } catch (const Tins::pcap_error &e) {
    logger->error("Error while initializing the sniffer: {}", e.what());
    return std::nullopt;
  }

  logger->info("Added new sniffer: InterfaceSniffer ({})", iface.value());
  return id;
}

void Service::shutdown() {
  logger->info("Cauguht deadly signal, forcing all sniffers to stop");
  if (cfg.save_on_shutdown) {
    logger->debug("Dumping on shutdown enabled! Dumping packets all sniffers");
    for (auto &[_, sniffer] : sniffers)
      sniffer->save_traffic(cfg.saves_path, "Shutdown Save");
    logger->trace("Dumping recordings finished");
  }

  stopping = true;
  std::this_thread::sleep_for(
      std::chrono::milliseconds(300)); // Let the service end in peace
  logger->debug("Notifying the sniffers of termination");
  for (auto &[_, sniffer] : sniffers)
    sniffer->shutdown();
}

void Service::clean_save_dir() {
  bool save_any = false;
  std::stringstream filenames;

  for (const auto &entry :
       std::filesystem::directory_iterator(cfg.saves_path)) {
    if (!entry.is_regular_file() ||
        db.recording_exists_path(entry.path().string()))
      continue;

    if (!entry.path().has_extension() ||
        !(entry.path().extension() == ".pcap" ||
          entry.path().extension() == ".pcapng")) {
      continue;
    }

    save_any = true;
    std::string filename = entry.path().stem().string();
    filenames << filename << " ";

    proto::DataLinkType detected = proto::DataLinkType::UNKNOWN;
    Tins::FileSniffer data_link_tester(entry.path());
    Tins::PtrPacket pkt = data_link_tester.next_packet();
    if (pkt)
      if (pkt.pdu()->find_pdu<Tins::EthernetII>())
        detected = proto::DataLinkType::ETH2;
      else if (pkt.pdu()->find_pdu<Tins::RadioTap>())
        detected = proto::DataLinkType::RADIOTAP;
      else
        detected = proto::DataLinkType::RAW80211;

    if (!db.insert_recording(uuid::generate_v4(), "Automatic - " + filename,
                             entry.path().string(), -1, -1, detected))
      logger->error("Couldn't insert automatic recording into the database {}",
                    filename);
  }

  if (save_any)
    logger->debug("Automatically indexed recordings: [ {}]", filenames.str());
}

grpc::Status Service::SnifferCreate(grpc::ServerContext *context,
                                    const proto::SnifferCreateRequest *request,
                                    proto::SnifferID *reply) {
  if (request->is_file_based()) {
    if (!db.recording_exists(request->recording_uuid()))
      return grpc::Status(grpc::StatusCode::NOT_FOUND,
                          "No recording with this uuid");

    std::vector<std::string> recording =
        db.get_recording(request->recording_uuid());
    if (!recording.size())
      return grpc::Status(grpc::StatusCode::NOT_FOUND,
                          "No recording with this uuid");

    std::optional<uuid::UUIDv4> id = add_file_sniffer(recording[2]);
    if (!id.has_value())
      return grpc::Status(grpc::StatusCode::INTERNAL,
                          "Unable to create the sniffer");

    reply->set_sniffer_uuid(id.value());
    return grpc::Status::OK;
  }

  for (const auto &[_, sniffer] : sniffers) {
    std::optional<std::string> net_iface_name = sniffer->iface();
    if (net_iface_name.has_value() &&
        net_iface_name.value() == request->net_iface_name())
      return grpc::Status(grpc::StatusCode::ALREADY_EXISTS,
                          "There already exists a sniffer on this interface");
  }

  std::optional<uuid::UUIDv4> id = add_iface_sniffer(request->net_iface_name());
  if (!id.has_value())
    return grpc::Status(grpc::StatusCode::INTERNAL,
                        "Unable to create the sniffer");

  reply->set_sniffer_uuid(id.value());
  return grpc::Status::OK;
}

grpc::Status Service::SnifferDestroy(grpc::ServerContext *context,
                                     const proto::SnifferID *request,
                                     proto::Empty *reply) {
  if (!sniffers.count(request->sniffer_uuid()))
    return grpc::Status(grpc::StatusCode::NOT_FOUND, "No sniffer with this id");
  sniffers[request->sniffer_uuid()]->shutdown();
  erased_sniffers[request->sniffer_uuid()] =
      std::move(sniffers[request->sniffer_uuid()]);
  sniffers.erase(request->sniffer_uuid());
  return grpc::Status::OK;
}

grpc::Status Service::SnifferList(grpc::ServerContext *context,
                                  const proto::Empty *request,
                                  proto::SnifferListResponse *reply) {
  for (const auto &[uuid, sniffer] : sniffers) {
    proto::SnifferInfo *new_info = reply->add_sniffers();

    bool is_file_based = sniffer->file().has_value();
    if (is_file_based) {
      new_info->set_filename(sniffer->file()->filename().string());
    } else {
      new_info->set_net_iface_name(sniffer->iface().value());
    }

    new_info->set_uuid(uuid);
    new_info->set_is_file_based(is_file_based);
  }

  return grpc::Status::OK;
}

grpc::Status Service::AccessPointList(grpc::ServerContext *context,
                                      const proto::SnifferID *request,
                                      proto::APListResponse *reply) {
  if (!sniffers.count(request->sniffer_uuid()))
    return grpc::Status(grpc::StatusCode::NOT_FOUND, "No sniffer with this id");
  Sniffer *sniffer = sniffers[request->sniffer_uuid()].get();

  for (const auto &[bssid, ssid] : sniffer->all_networks()) {
    proto::BasicNetworkInfo *new_net = reply->add_nets();
    new_net->set_bssid(bssid.to_string());
    new_net->set_ssid(ssid);
  }

  return grpc::Status::OK;
}

grpc::Status Service::AccessPointGet(grpc::ServerContext *context,
                                     const proto::APGetRequest *request,
                                     proto::APGetResponse *reply) {
  if (!sniffers.count(request->sniffer_uuid()))
    return grpc::Status(grpc::StatusCode::NOT_FOUND, "No sniffer with this id");
  Sniffer *sniffer = sniffers[request->sniffer_uuid()].get();

  auto ap_option = sniffer->get_network(MACAddress(request->bssid()));
  if (!ap_option.has_value())
    return grpc::Status(grpc::StatusCode::NOT_FOUND,
                        "No network with this bssid");

  std::shared_ptr<AccessPoint> ap = ap_option.value();
  auto ap_info = std::make_unique<proto::AccessPointInfo>();

  ap_info->set_ssid(ap->get_ssid());
  ap_info->set_bssid(ap->get_bssid().to_string());
  ap_info->set_channel(ap->get_wifi_channel());
  ap_info->set_encrypted_packet_count(ap->raw_packet_count() -
                                      ap->decrypted_packet_count());
  ap_info->set_decrypted_packet_count(ap->decrypted_packet_count());
  ap_info->set_pmf_capable(ap->protected_management_supported());
  ap_info->set_pmf_required(ap->protected_management_required());
  for (const auto &sec : ap->security_supported())
    ap_info->add_security(static_cast<proto::NetworkSecurity>(sec));

  auto radio = std::make_unique<proto::RadioInfo>();
  radio->set_rssi(ap->get_radio().rssi);
  radio->set_noise(ap->get_radio().noise);
  radio->set_snr(ap->get_radio().snr);
  ap_info->set_allocated_radio_info(radio.release());

  for (const auto &[addr, count] : ap->get_multicast_groups()) {
    auto new_group = ap_info->add_multicast_groups();
    new_group->set_addr(addr.to_string());
    new_group->set_count(count);
  }

  for (const auto &standard : ap->standards_supported()) {
    auto new_standard = ap_info->add_supported_standards();
    new_standard->set_std(static_cast<proto::WiFiStandard>(standard.std));
    new_standard->set_single_beamformer_support(
        standard.single_beamformer_support);
    new_standard->set_single_beamformee_support(
        standard.single_beamformee_support);
    new_standard->set_multi_beamformer_support(
        standard.multi_beamformer_support);
    new_standard->set_multi_beamformee_support(
        standard.multi_beamformee_support);
    for (const auto &mcs : standard.mcs_supported_idx)
      new_standard->add_mcs_supported_idx(mcs);
    for (const auto &mod : standard.modulation_supported)
      new_standard->add_modulation_supported(
          static_cast<proto::Modulation>(mod));
    for (const auto &spatial : standard.spatial_streams_supported)
      new_standard->add_spatial_streams_supported(spatial);
    for (const auto &width : standard.channel_widths_supported)
      new_standard->add_channel_widths_supported(
          static_cast<proto::ChannelWidth>(width));
  }

  WPA2Decrypter &decrypter = ap->get_decrypter();
  for (const auto &client_addr : ap->get_clients()) {
    auto info = ap_info->add_clients();
    std::optional<client_info> client = ap->get_client(client_addr);
    info->set_hwaddr(client->hwaddr.to_string());
    info->set_hostname(client->hostname);
    info->set_ipv4(client->ipv4);
    info->set_ipv6(client->ipv6);
    info->set_sent_unicast(client->sent_unicast);
    info->set_sent_total(client->sent_total);
    info->set_received(client->received);
    info->set_pmf_active(ap->get_client_security(client_addr)->pmf);
    info->set_router(client->router);

    auto radio = std::make_unique<proto::RadioInfo>();
    radio->set_rssi(client->radio.rssi);
    radio->set_noise(client->radio.noise);
    radio->set_snr(client->radio.snr);
    info->set_allocated_radio_info(radio.release());

    std::optional<uint8_t> eapol_count =
        decrypter.get_current_eapol_count(client_addr);
    info->set_current_eapol_pkt_count(
        (eapol_count.has_value()) ? eapol_count.value() : 0);

    std::optional<std::vector<client_window>> windows =
        decrypter.get_all_client_windows(client_addr);
    if (!windows.has_value() || !windows->size())
      continue;

    for (const auto &window : windows.value()) {
      proto::ClientWindow *new_window = info->add_windows();
      auto start =
          std::make_unique<Timestamp>(TimeUtil::MicrosecondsToTimestamp(
              window.start.seconds() * 1000000 + window.start.microseconds()));
      new_window->set_allocated_start(start.release());
      auto end = std::make_unique<Timestamp>(TimeUtil::MicrosecondsToTimestamp(
          window.end.seconds() * 1000000 + window.end.microseconds()));
      new_window->set_allocated_end(end.release());
      new_window->set_ended(window.ended);
      new_window->set_decrypted(window.decrypted);
      new_window->set_packet_count(window.packets.size());
      new_window->set_auth_packet_count(window.auth_packets.size());
      new_window->set_ptk(WPA2Decrypter::readable_hex(window.ptk));
    }
  }

  for (const auto window : decrypter.get_all_group_windows()) {
    auto new_window = ap_info->add_group_windows();
    auto start = std::make_unique<Timestamp>(TimeUtil::MicrosecondsToTimestamp(
        window.start.seconds() * 1000000 + window.start.microseconds()));
    new_window->set_allocated_start(start.release());
    auto end = std::make_unique<Timestamp>(TimeUtil::MicrosecondsToTimestamp(
        window.end.seconds() * 1000000 + window.end.microseconds()));
    new_window->set_allocated_end(end.release());

    new_window->set_ended(window.ended);
    new_window->set_decrypted(window.decrypted);
    new_window->set_packet_count(window.packets.size());
    new_window->set_auth_packet_count(window.auth_packets.size());
    new_window->set_gtk(WPA2Decrypter::readable_hex(window.gtk));
  }

  reply->set_allocated_ap(ap_info.release());
  return grpc::Status::OK;
}

grpc::Status Service::AccessPointProvidePassword(
    grpc::ServerContext *context,
    const proto::APProvidePasswordRequest *request,
    proto::APProvidePasswordResponse *reply) {
  if (!sniffers.count(request->sniffer_uuid()))
    return grpc::Status(grpc::StatusCode::NOT_FOUND, "No sniffer with this id");
  Sniffer *sniffer = sniffers[request->sniffer_uuid()].get();

  auto ap = sniffer->get_network(MACAddress(request->bssid()));
  if (!ap.has_value())
    return grpc::Status(grpc::StatusCode::NOT_FOUND,
                        "No network with this bssid");

  if (ap.value()->has_working_password()) {
    reply->set_state(proto::APProvidePasswordResponse::ALREADY_DECRYPTED);
    return grpc::Status::OK;
  }

  DecryptionState state = ap.value()->add_password(request->password());
  switch (state) {
  case DecryptionState::DECRYPTED:
    reply->set_state(proto::APProvidePasswordResponse::DECRYPTED);
    break;

  case DecryptionState::NOT_ENOUGH_DATA:
    reply->set_state(proto::APProvidePasswordResponse::NOT_ENOUGH_DATA);
    break;

  case DecryptionState::INCORRECT_PASSWORD:
    reply->set_state(proto::APProvidePasswordResponse::INCORRECT_PASSWORD);
    break;

  case DecryptionState::ALREADY_DECRYPTED:
    reply->set_state(proto::APProvidePasswordResponse::ALREADY_DECRYPTED);
    break;
  }

  return grpc::Status::OK;
};

grpc::Status Service::AccessPointGetDecryptedStream(
    grpc::ServerContext *context,
    const proto::APGetDecryptedStreamRequest *request,
    grpc::ServerWriter<proto::Packet> *writer) {
  if (!sniffers.count(request->sniffer_uuid()))
    return grpc::Status(grpc::StatusCode::NOT_FOUND, "No sniffer with this id");
  Sniffer *sniffer = sniffers[request->sniffer_uuid()].get();

  auto ap = sniffer->get_network(MACAddress(request->bssid()));
  if (!ap.has_value())
    return grpc::Status(grpc::StatusCode::NOT_FOUND,
                        "No network with this bssid");

  // Make sure to cancel when the user cancels!
  std::shared_ptr<PacketChannel> channel = ap.value()->get_decrypted_channel();
  std::thread([context, channel, this]() {
    while (!stopping) {
      if (context->IsCancelled()) {
        logger->trace("Stream has been cancelled");
        channel->close();
        return;
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }
  }).detach();

  logger->debug("Packet stream started for {}", context->peer());

  while (!channel->is_closed()) {
    std::optional<std::unique_ptr<Tins::Packet>> pkt = channel->receive();
    if (!pkt.has_value()) {
      logger->debug("Packet stream ended for {}", context->peer());
      return grpc::Status::OK;
    }

    writer->Write(PacketFormatter::format(std::move(pkt.value()),
                                          request->include_payload()));
  }

  logger->debug("Packet stream ended for {}", context->peer());
  return grpc::Status::OK;
};

grpc::Status Service::AccessPointDeauth(grpc::ServerContext *context,
                                        const proto::APDeauthRequest *request,
                                        proto::Empty *reply) {
  if (!sniffers.count(request->sniffer_uuid()))
    return grpc::Status(grpc::StatusCode::NOT_FOUND, "No sniffer with this id");
  Sniffer *sniffer = sniffers[request->sniffer_uuid()].get();

  auto ap = sniffer->get_network(MACAddress(request->bssid()));
  if (!ap.has_value())
    return grpc::Status(grpc::StatusCode::NOT_FOUND,
                        "No network with this bssid");

  std::optional<std::string> iface = sniffer->iface();
  if (!iface.has_value())
    return grpc::Status(
        grpc::StatusCode::UNAVAILABLE,
        "This sniffer doesn't have a network interface attached");

  if (ap.value()->protected_management_required())
    return grpc::Status(grpc::StatusCode::UNAVAILABLE,
                        "Target network uses protected management frames");

  bool sent =
      ap.value()->send_deauth(iface.value(), MACAddress("ff:ff:ff:ff:ff:ff"));
  if (!sent)
    return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION,
                        "Not enough radio information to send the packet");

  return grpc::Status::OK;
};

grpc::Status
Service::AccessPointDeauthClient(grpc::ServerContext *context,
                                 const proto::APDeauthClientRequest *request,
                                 proto::Empty *reply) {
  if (!sniffers.count(request->sniffer_uuid()))
    return grpc::Status(grpc::StatusCode::NOT_FOUND, "No sniffer with this id");
  Sniffer *sniffer = sniffers[request->sniffer_uuid()].get();

  auto ap = sniffer->get_network(MACAddress(request->bssid()));
  if (!ap.has_value())
    return grpc::Status(grpc::StatusCode::NOT_FOUND,
                        "No network with this bssid");

  if (ap.value()->protected_management_required())
    return grpc::Status(grpc::StatusCode::UNAVAILABLE,
                        "Target network uses protected management frames");

  std::optional<std::string> iface = sniffer->iface();
  if (!iface.has_value())
    return grpc::Status(
        grpc::StatusCode::UNAVAILABLE,
        "This sniffer doesn't have a network interface attached");

  bool sent = ap.value()->send_deauth(iface.value(),
                                      MACAddress(request->client_addr()));
  if (!sent)
    return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION,
                        "Not enough radio information to send the packet");

  return grpc::Status::OK;
};

grpc::Status Service::AccessPointGetHash(grpc::ServerContext *context,
                                         const proto::APGetHashRequest *request,
                                         proto::APGetHashResponse *reply) {
  if (!sniffers.count(request->sniffer_uuid()))
    return grpc::Status(grpc::StatusCode::NOT_FOUND, "No sniffer with this id");
  Sniffer *sniffer = sniffers[request->sniffer_uuid()].get();

  auto ap = sniffer->get_network(MACAddress(request->bssid()));
  if (!ap.has_value())
    return grpc::Status(grpc::StatusCode::NOT_FOUND,
                        "No network with this bssid");

  if (!ap.value()->get_client(MACAddress(request->client_addr())).has_value())
    return grpc::Status(grpc::StatusCode::NOT_FOUND,
                        "No client with this address");

  auto decrypter = ap.value()->get_decrypter();
  auto windows =
      decrypter.get_all_client_windows(MACAddress(request->client_addr()));
  if (!windows.has_value())
    return grpc::Status(grpc::StatusCode::NOT_FOUND,
                        "Client has no decryption windows available");

  for (const auto &window : windows.value()) {
    std::optional<std::string> data = decrypter.extract_hc22000(window);
    if (!data.has_value())
      continue;

    reply->set_hc22000(data.value());
    return grpc::Status::OK;
  }

  return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION,
                      "Not enough keydata to extract information");
}

grpc::Status Service::AccessPointIgnore(grpc::ServerContext *context,
                                        const proto::APIgnoreRequest *request,
                                        proto::Empty *reply) {
  if (!sniffers.count(request->sniffer_uuid()))
    return grpc::Status(grpc::StatusCode::NOT_FOUND, "No sniffer with this id");
  Sniffer *sniffer = sniffers[request->sniffer_uuid()].get();

  std::optional<std::shared_ptr<AccessPoint>> focused =
      sniffer->focused_network();
  if (focused.has_value())
    if ((request->use_ssid() &&
         focused.value()->get_ssid() == request->ssid()) ||
        (!request->use_ssid() &&
         focused.value()->get_bssid() == request->bssid()))
      sniffer->stop_focus(); // Stop focusing if the user requested to ignore
                             // the currently focused network

  for (const auto &[bssid, ssid] : sniffer->ignored_networks())
    if ((request->use_ssid() && ssid == request->ssid()) ||
        (!request->use_ssid() && bssid == request->bssid()))
      return grpc::Status(grpc::StatusCode::ALREADY_EXISTS,
                          "Already ignoring this network");

  if (request->use_ssid())
    sniffer->add_ignored_network(request->ssid());
  else
    sniffer->add_ignored_network(MACAddress(request->bssid()));
  return grpc::Status::OK;
};

grpc::Status Service::AccessPointListIgnored(grpc::ServerContext *context,
                                             const proto::SnifferID *request,
                                             proto::APListResponse *reply) {
  if (!sniffers.count(request->sniffer_uuid()))
    return grpc::Status(grpc::StatusCode::NOT_FOUND, "No sniffer with this id");
  Sniffer *sniffer = sniffers[request->sniffer_uuid()].get();

  for (const auto &[bssid, ssid] : sniffer->ignored_networks()) {
    proto::BasicNetworkInfo *new_net = reply->add_nets();
    new_net->set_bssid(bssid.to_string());
    new_net->set_ssid(ssid);
  }

  return grpc::Status::OK;
};

grpc::Status Service::AccessPointCreateRecording(
    grpc::ServerContext *context,
    const proto::APCreateRecordingRequest *request,
    proto::APCreateRecordingResponse *reply) {
  if (!sniffers.count(request->sniffer_uuid()))
    return grpc::Status(grpc::StatusCode::NOT_FOUND, "No sniffer with this id");
  Sniffer *sniffer = sniffers[request->sniffer_uuid()].get();

  auto ap = sniffer->get_network(MACAddress(request->bssid()));
  if (!ap.has_value())
    return grpc::Status(grpc::StatusCode::NOT_FOUND,
                        "No network with this bssid");

  std::optional<recording_info> rec_info;
  if (request->raw())
    rec_info = ap.value()->save_traffic(cfg.saves_path, request->name());
  else
    rec_info =
        ap.value()->save_decrypted_traffic(cfg.saves_path, request->name());
  if (!rec_info.has_value())
    return grpc::Status(grpc::StatusCode::INTERNAL,
                        "Cannot save decrypted traffic");

  reply->set_uuid(rec_info.value().uuid);
  reply->set_packet_count(rec_info.value().count);
  return grpc::Status::OK;
}

grpc::Status Service::FocusStart(grpc::ServerContext *context,
                                 const proto::FocusStartRequest *request,
                                 proto::FocusStartResponse *reply) {
  if (!sniffers.count(request->sniffer_uuid()))
    return grpc::Status(grpc::StatusCode::NOT_FOUND, "No sniffer with this id");
  Sniffer *sniffer = sniffers[request->sniffer_uuid()].get();

  auto ap = sniffer->get_network(MACAddress(request->bssid()));
  if (!ap.has_value())
    return grpc::Status(grpc::StatusCode::NOT_FOUND,
                        "No network with this bssid");

  std::optional<uint32_t> channel =
      sniffer->focus_network(MACAddress(request->bssid()));
  if (!channel.has_value())
    return grpc::Status(grpc::StatusCode::INTERNAL,
                        "Unable to focus the network");
  reply->set_channel(channel.value());
  return grpc::Status::OK;
}

grpc::Status Service::FocusGetActive(grpc::ServerContext *context,
                                     const proto::SnifferID *request,
                                     proto::FocusGetActiveResponse *reply) {
  if (!sniffers.count(request->sniffer_uuid()))
    return grpc::Status(grpc::StatusCode::NOT_FOUND, "No sniffer with this id");
  Sniffer *sniffer = sniffers[request->sniffer_uuid()].get();

  std::optional<std::shared_ptr<AccessPoint>> ap = sniffer->focused_network();
  if (!ap.has_value())
    return grpc::Status(grpc::StatusCode::NOT_FOUND,
                        "Not focusing any network");

  reply->set_bssid(ap.value()->get_bssid().to_string());
  reply->set_ssid(ap.value()->get_ssid());
  reply->set_channel(ap.value()->get_wifi_channel());
  return grpc::Status::OK;
}

grpc::Status Service::FocusStop(grpc::ServerContext *context,
                                const proto::SnifferID *request,
                                proto::Empty *reply) {
  if (!sniffers.count(request->sniffer_uuid()))
    return grpc::Status(grpc::StatusCode::NOT_FOUND, "No sniffer with this id");
  Sniffer *sniffer = sniffers[request->sniffer_uuid()].get();

  std::optional<std::shared_ptr<AccessPoint>> focused =
      sniffer->focused_network();
  if (!focused.has_value())
    return grpc::Status(grpc::StatusCode::NOT_FOUND,
                        "Not focusing any network");

  sniffer->stop_focus();
  return grpc::Status::OK;
}

grpc::Status
Service::RecordingCreate(grpc::ServerContext *context,
                         const proto::RecordingCreateRequest *request,
                         proto::RecordingCreateResponse *reply) {
  if (!sniffers.count(request->sniffer_uuid()))
    return grpc::Status(grpc::StatusCode::NOT_FOUND, "No sniffer with this id");
  Sniffer *sniffer = sniffers[request->sniffer_uuid()].get();
  std::optional<recording_info> rec_info;
  if (request->raw())
    rec_info = sniffer->save_traffic(cfg.saves_path, request->name());
  else
    rec_info = sniffer->save_decrypted_traffic(cfg.saves_path, request->name());
  if (!rec_info.has_value())
    return grpc::Status(grpc::StatusCode::INTERNAL,
                        "Cannot save decrypted traffic");
  reply->set_uuid(rec_info.value().uuid);
  reply->set_packet_count(rec_info.value().count);
  return grpc::Status::OK;
}

grpc::Status Service::RecordingList(grpc::ServerContext *context,
                                    const proto::RecordingListRequest *request,
                                    proto::RecordingListResponse *reply) {
  auto recordings = db.get_recordings();
  logger->debug("Got {} recordings from the database", recordings.size());

  std::set<proto::DataLinkType> allowed_types;
  for (const auto &type : request->allowed_types())
    allowed_types.insert(static_cast<proto::DataLinkType>(type));

  for (const auto &rec : recordings) {
    proto::DataLinkType data_link =
        static_cast<proto::DataLinkType>(std::stoi(rec[5]));
    if (!allowed_types.contains(data_link))
      continue;

    proto::Recording *info = reply->add_recordings();
    info->set_uuid(rec[0]);
    info->set_filename(rec[2]);
    info->set_display_name(rec[1]);
    info->set_datalink(data_link);
  }

  logger->debug("Returned {} filtered recordings", reply->recordings_size());
  return grpc::Status::OK;
}

grpc::Status Service::RecordingLoadDecrypted(
    grpc::ServerContext *context,
    const proto::RecordingLoadDecryptedRequest *request,
    grpc::ServerWriter<proto::Packet> *writer) {
  if (!db.recording_exists(request->uuid()))
    return grpc::Status(grpc::StatusCode::NOT_FOUND,
                        "No recording with this UUID");

  auto stream = get_recording_stream(request->uuid());
  if (!stream.has_value())
    return grpc::Status(grpc::StatusCode::INTERNAL, "Failed to get the stream");

  auto channel = std::move(stream.value());
  logger->debug("Packet stream started for {} ({} packets)", context->peer(),
                channel->len());
  size_t length = channel->len();
  for (size_t i = 0; i < length; i++) {
    std::optional<std::unique_ptr<Tins::Packet>> pkt = channel->receive();
    if (!pkt.has_value()) {
      logger->debug("Packet stream ended for {}", context->peer());
      return grpc::Status::OK;
    }

    writer->Write(PacketFormatter::format(std::move(pkt.value()),
                                          request->include_payload()));
  }

  logger->debug("Packet stream ended for {}", context->peer());
  return grpc::Status::OK;
};

grpc::Status
Service::NetworkInterfaceList(grpc::ServerContext *context,
                              const proto::Empty *request,
                              proto::NetworkInterfaceListResponse *reply) {
  for (const auto &iface : Tins::Utils::network_interfaces())
    *reply->add_ifaces() = std::string(iface);
  return grpc::Status::OK;
}

grpc::Status
Service::LogGetStream(grpc::ServerContext *context, const proto::Empty *request,
                      grpc::ServerWriter<proto::LogEntry> *writer) {
  logger->trace("Log stream started for {}", context->peer());

  while (!stopping && !context->IsCancelled() &&
         !log::global_proto_sink->is_stopped()) {
    auto entries = log::global_proto_sink->get_entries();
    for (const auto &entry : entries)
      writer->Write(*entry);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }

  logger->trace("Log stream ended for {}", context->peer());
  return grpc::Status::OK;
};

grpc::Status Service::BatteryGetLevel(grpc::ServerContext *context,
                                      const proto::Empty *request,
                                      proto::BatteryGetLevelResponse *reply) {
#ifndef BATTERY_SUPPORT
  logger->error("Attempted to check battery levels despite no battery support "
                "compiled in");
  return grpc::Status(grpc::StatusCode::UNIMPLEMENTED,
                      "Battery level checking is disabled in this build");
#else
  std::ifstream file(cfg.battery_file_path.string());
  if (!file.is_open()) {
    logger->error("Battery file {} is already open",
                  cfg.battery_file_path.string());
    grpc::Status(grpc::StatusCode::UNIMPLEMENTED,
                 "Unable to open battery file");
  }

  std::string line;
  if (!std::getline(file, line)) {
    logger->error("Battery file {} is invalid", cfg.battery_file_path.string());
    grpc::Status(grpc::StatusCode::UNIMPLEMENTED, "Battery file invalid");
  }

  try {
    // Convert the string to a float
    float batteryLevel = std::stof(line);
    if (batteryLevel < 1.0 || batteryLevel > 100.0) {
      logger->error(
          "Battery file {} is invalid: battery level out of range ({})",
          cfg.battery_file_path.string(), batteryLevel);
      return grpc::Status(grpc::StatusCode::UNIMPLEMENTED,
                          "Battery file invalid");
    }

    reply->set_percentage(batteryLevel);
    return grpc::Status::OK;
  } catch (const std::invalid_argument &e) {
    logger->error("Battery file {} is invalid: {}",
                  cfg.battery_file_path.string(), e.what());
    return grpc::Status(grpc::StatusCode::UNIMPLEMENTED,
                        "Battery file invalid");
  } catch (const std::out_of_range &e) {
    logger->error("Battery file {} is invalid: {}",
                  cfg.battery_file_path.string(), e.what());
    return grpc::Status(grpc::StatusCode::UNIMPLEMENTED,
                        "Battery file invalid");
  }
#endif // BATTERY_SUPPORT
}

std::optional<std::unique_ptr<PacketChannel>>
Service::get_recording_stream(const uuid::UUIDv4 &uuid) {
  if (!db.recording_exists(uuid))
    return std::nullopt;

  auto rec_info = db.get_recording(uuid);
  std::string filename = rec_info[1];
  std::filesystem::path path = cfg.saves_path;
  std::string filepath = rec_info[2];
  std::unique_ptr<Tins::FileSniffer> temp_sniff;

  try {
    temp_sniff = std::make_unique<Tins::FileSniffer>(filepath);
  } catch (Tins::pcap_error &e) {
    return std::nullopt;
  }

  auto chan = std::make_unique<PacketChannel>();

  temp_sniff->sniff_loop([&chan](Tins::Packet &pkt) {
    if (!pkt.pdu()->find_pdu<Tins::EthernetII>())
      return true;

    chan->send(std::make_unique<Tins::Packet>(pkt));
    return true;
  });

  return chan;
}

} // namespace yarilo
