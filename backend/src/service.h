#ifndef SNIFF_SERVICE
#define SNIFF_SERVICE

#include "packets.grpc.pb.h"
#include "packets.pb.h"
#include "sniffer.h"
#include <filesystem>
#include <grpcpp/support/sync_stream.h>
#include <tins/sniffer.h>

namespace yarilo {

/**
 * @brief Service delivering an external gRPC API
 */
class Service : public proto::Sniffer::Service {
public:
  Service(const std::filesystem::path &save_path,
          const std::filesystem::path &sniff_path);

  bool add_file_sniffer(const std::filesystem::path &file);
  bool add_iface_sniffer(const std::string &iface_name);
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

  grpc::Status SniffFileList(grpc::ServerContext *context,
                             const proto::Empty *request,
                             proto::SniffFileListResponse *reply) override;

  grpc::Status
  SniffInterfaceList(grpc::ServerContext *context, const proto::Empty *request,
                     proto::SniffInterfaceListResponse *reply) override;

  grpc::Status GetAllAccessPoints(grpc::ServerContext *context,
                                  const proto::SnifferID *request,
                                  proto::NetworkList *reply) override;

  grpc::Status GetAccessPoint(grpc::ServerContext *context,
                              const proto::NetworkName *request,
                              proto::NetworkInfo *reply) override;

  grpc::Status FocusNetwork(grpc::ServerContext *context,
                            const proto::NetworkName *request,
                            proto::Empty *reply) override;

  grpc::Status GetFocusState(grpc::ServerContext *context,
                             const proto::SnifferID *request,
                             proto::FocusState *reply) override;

  grpc::Status StopFocus(grpc::ServerContext *context,
                         const proto::SnifferID *request,
                         proto::Empty *reply) override;

  grpc::Status ProvidePassword(grpc::ServerContext *context,
                               const proto::DecryptRequest *request,
                               proto::Empty *reply) override;

  grpc::Status
  GetDecryptedPackets(grpc::ServerContext *context,
                      const proto::NetworkName *request,
                      grpc::ServerWriter<proto::Packet> *writer) override;

  grpc::Status DeauthNetwork(grpc::ServerContext *context,
                             const proto::DeauthRequest *request,
                             proto::Empty *reply) override;

  grpc::Status IgnoreNetwork(grpc::ServerContext *context,
                             const proto::NetworkName *request,
                             proto::Empty *reply) override;

  grpc::Status GetIgnoredNetworks(grpc::ServerContext *context,
                                  const proto::SnifferID *request,
                                  proto::NetworkList *reply) override;

  grpc::Status SaveDecryptedTraffic(grpc::ServerContext *context,
                                    const proto::NetworkName *request,
                                    proto::Empty *reply) override;

  grpc::Status GetAvailableRecordings(grpc::ServerContext *context,
                                      const proto::Empty *request,
                                      proto::RecordingsList *reply) override;

  grpc::Status
  LoadRecording(grpc::ServerContext *context, const proto::File *request,
                grpc::ServerWriter<proto::Packet> *writer) override;

  grpc::Status SetMayhemMode(grpc::ServerContext *context,
                             const proto::NewMayhemState *request,
                             proto::Empty *reply) override;

  grpc::Status GetLED(grpc::ServerContext *context,
                      const proto::SnifferID *request,
                      grpc::ServerWriter<proto::LEDState> *writer) override;

private:
  std::vector<std::unique_ptr<Sniffer>> sniffers;
  std::vector<std::unique_ptr<Sniffer>>
      erased_sniffers; // Kept for shutdown logic
  std::shared_ptr<spdlog::logger> logger;
  const std::filesystem::path save_path;
  const std::filesystem::path sniff_path;

#ifdef MAYHEM
  std::atomic<bool> led_on = false;
  std::atomic<bool> mayhem_on = false;
#endif
};

} // namespace yarilo

#endif // SNIFF_SERVICE
