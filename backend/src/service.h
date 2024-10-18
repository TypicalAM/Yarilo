#ifndef SNIFF_SERVICE
#define SNIFF_SERVICE

#include "proto/service.grpc.pb.h"
#include "proto/service.pb.h"
#include "sniffer.h"
#include "uuid.h"
#include <filesystem>
#include <grpcpp/server_context.h>
#include <grpcpp/support/sync_stream.h>
#include <optional>
#include <tins/sniffer.h>
#include <unordered_map>

namespace yarilo {

/**
 * @brief Service delivering an external gRPC API
 */
class Service : public proto::Sniffer::Service {
public:
  Service(const std::filesystem::path &save_path,
          const std::filesystem::path &sniff_path);

  std::optional<uuid::UUIDv4>
  add_file_sniffer(const std::filesystem::path &file);
  std::optional<uuid::UUIDv4> add_iface_sniffer(const std::string &iface_name);
  void shutdown();

  grpc::Status SnifferCreate(grpc::ServerContext *context,
                             const proto::SnifferCreateRequest *request,
                             proto::SnifferID *reply) override;

  grpc::Status SnifferDestroy(grpc::ServerContext *context,
                              const proto::SnifferID *request,
                              proto::Empty *reply) override;

  grpc::Status SnifferList(grpc::ServerContext *context,
                           const proto::Empty *request,
                           proto::SnifferListResponse *reply) override;

  grpc::Status AccessPointList(grpc::ServerContext *context,
                               const proto::SnifferID *request,
                               proto::APListResponse *reply) override;

  grpc::Status AccessPointGet(grpc::ServerContext *context,
                              const proto::APGetRequest *request,
                              proto::APGetResponse *reply) override;

  grpc::Status
  AccessPointProvidePassword(grpc::ServerContext *context,
                             const proto::APProvidePasswordRequest *request,
                             proto::APProvidePasswordResponse *reply) override;

  grpc::Status AccessPointGetDeryptedStream(
      grpc::ServerContext *context,
      const proto::APGetDeryptedStreamRequest *request,
      grpc::ServerWriter<proto::Packet> *writer) override;

  grpc::Status AccessPointDeauth(grpc::ServerContext *context,
                                 const proto::APDeauthRequest *request,
                                 proto::Empty *reply) override;

  grpc::Status
  AccessPointDeauthClient(grpc::ServerContext *context,
                          const proto::APDeauthClientRequest *request,
                          proto::Empty *reply) override;

  grpc::Status AccessPointIgnore(grpc::ServerContext *context,
                                 const proto::APIgnoreRequest *request,
                                 proto::Empty *reply) override;

  grpc::Status AccessPointListIgnored(grpc::ServerContext *context,
                                      const proto::SnifferID *request,
                                      proto::APListResponse *reply) override;

  grpc::Status
  AccessPointCreateRecording(grpc::ServerContext *context,
                             const proto::APCreateRecordingRequest *request,
                             proto::APCreateRecordingResponse *reply) override;

  grpc::Status FocusStart(grpc::ServerContext *context,
                          const proto::FocusStartRequest *request,
                          proto::FocusStartResponse *reply) override;

  grpc::Status FocusGetActive(grpc::ServerContext *context,
                              const proto::SnifferID *request,
                              proto::FocusGetActiveResponse *reply) override;

  grpc::Status FocusStop(grpc::ServerContext *context,
                         const proto::SnifferID *request,
                         proto::Empty *reply) override;

  grpc::Status RecordingCreate(grpc::ServerContext *context,
                               const proto::RecordingCreateRequest *request,
                               proto::RecordingCreateResponse *reply) override;

  grpc::Status RecordingList(grpc::ServerContext *context,
                             const proto::RecordingListRequest *request,
                             proto::RecordingListResponse *reply) override;

  grpc::Status
  RecordingLoadDecrypted(grpc::ServerContext *context,
                         const proto::RecordingLoadDecryptedRequest *request,
                         grpc::ServerWriter<proto::Packet> *writer) override;

  grpc::Status
  NetworkInterfaceList(grpc::ServerContext *context,
                       const proto::Empty *request,
                       proto::NetworkInterfaceListResponse *reply) override;

private:
  std::unordered_map<uuid::UUIDv4, std::unique_ptr<Sniffer>> sniffers;
  std::unordered_map<uuid::UUIDv4, std::unique_ptr<Sniffer>>
      erased_sniffers; // Kept for shutdown logic
  std::shared_ptr<spdlog::logger> logger;
  const std::filesystem::path save_path;
  const std::filesystem::path sniff_path;
};

} // namespace yarilo

#endif // SNIFF_SERVICE
