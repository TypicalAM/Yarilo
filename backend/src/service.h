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
  Service();
  Service(std::unique_ptr<Tins::FileSniffer>);
  Service(std::unique_ptr<Tins::Sniffer>, const Tins::NetworkInterface &iface);

  void start();
  void shutdown();
  void add_save_path(const std::filesystem::path &path);

  grpc::Status GetAllAccessPoints(grpc::ServerContext *context,
                                  const proto::SnifferID *request,
                                  proto::NetworkList *response) override;

  grpc::Status GetAccessPoint(grpc::ServerContext *context,
                              const proto::NetworkName *request,
                              proto::NetworkInfo *response) override;

  grpc::Status FocusNetwork(grpc::ServerContext *context,
                            const proto::NetworkName *request,
                            proto::Empty *response) override;

  grpc::Status GetFocusState(grpc::ServerContext *context,
                             const proto::SnifferID *request,
                             proto::FocusState *response) override;

  grpc::Status StopFocus(grpc::ServerContext *context,
                         const proto::SnifferID *request,
                         proto::Empty *response) override;

  grpc::Status ProvidePassword(grpc::ServerContext *context,
                               const proto::DecryptRequest *request,
                               proto::Empty *response) override;

  grpc::Status
  GetDecryptedPackets(grpc::ServerContext *context,
                      const proto::NetworkName *request,
                      grpc::ServerWriter<proto::Packet> *writer) override;

  grpc::Status DeauthNetwork(grpc::ServerContext *context,
                             const proto::DeauthRequest *request,
                             proto::Empty *response) override;

  grpc::Status IgnoreNetwork(grpc::ServerContext *context,
                             const proto::NetworkName *request,
                             proto::Empty *response) override;

  grpc::Status GetIgnoredNetworks(grpc::ServerContext *context,
                                  const proto::SnifferID *request,
                                  proto::NetworkList *response) override;

  grpc::Status SaveDecryptedTraffic(grpc::ServerContext *context,
                                    const proto::NetworkName *request,
                                    proto::Empty *response) override;

  grpc::Status GetAvailableRecordings(grpc::ServerContext *context,
                                      const proto::Empty *request,
                                      proto::RecordingsList *response) override;

  grpc::Status
  LoadRecording(grpc::ServerContext *context, const proto::File *request,
                grpc::ServerWriter<proto::Packet> *writer) override;

  grpc::Status SetMayhemMode(grpc::ServerContext *context,
                             const proto::NewMayhemState *request,
                             proto::Empty *response) override;

  grpc::Status GetLED(grpc::ServerContext *context,
                      const proto::SnifferID *request,
                      grpc::ServerWriter<proto::LEDState> *writer) override;

private:
  std::vector<std::unique_ptr<Sniffer>> sniffers;
  std::shared_ptr<spdlog::logger> logger;
  bool filemode = true;
  Tins::NetworkInterface iface;
  std::filesystem::path save_path = "/tmp/yarilo";

#ifdef MAYHEM
  std::atomic<bool> led_on = false;
  std::atomic<bool> mayhem_on = false;
#endif
};

} // namespace yarilo

#endif // SNIFF_SERVICE
