#ifndef SNIFF_SERVICE
#define SNIFF_SERVICE

#include "packets.grpc.pb.h"
#include "packets.pb.h"
#include "sniffer.h"
#include <filesystem>
#include <grpcpp/support/sync_stream.h>
#include <memory>
#include <tins/sniffer.h>

namespace yarilo {

class Service : public yarilo::proto::Sniffer::Service {
public:
  Service(std::unique_ptr<Tins::BaseSniffer>);
  Service(std::unique_ptr<Tins::BaseSniffer>, Tins::NetworkInterface iface);

  void start_sniffer();

  void add_save_path(std::filesystem::path path);

  grpc::Status
  GetAllAccessPoints(grpc::ServerContext *context,
                     const yarilo::proto::Empty *request,
                     yarilo::proto::NetworkList *response) override;

  grpc::Status GetAccessPoint(grpc::ServerContext *context,
                              const yarilo::proto::NetworkName *request,
                              yarilo::proto::NetworkInfo *response) override;

  grpc::Status FocusNetwork(grpc::ServerContext *context,
                            const yarilo::proto::NetworkName *request,
                            yarilo::proto::Empty *response) override;

  grpc::Status GetFocusState(grpc::ServerContext *context,
                             const yarilo::proto::Empty *request,
                             yarilo::proto::FocusState *response) override;

  grpc::Status StopFocus(grpc::ServerContext *context,
                         const yarilo::proto::Empty *request,
                         yarilo::proto::Empty *response) override;

  grpc::Status ProvidePassword(grpc::ServerContext *context,
                               const yarilo::proto::DecryptRequest *request,
                               yarilo::proto::Empty *response) override;

  grpc::Status GetDecryptedPackets(
      grpc::ServerContext *context, const yarilo::proto::NetworkName *request,
      grpc::ServerWriter<yarilo::proto::Packet> *writer) override;

  grpc::Status DeauthNetwork(grpc::ServerContext *context,
                             const yarilo::proto::DeauthRequest *request,
                             yarilo::proto::Empty *response) override;

  grpc::Status IgnoreNetwork(grpc::ServerContext *context,
                             const yarilo::proto::NetworkName *request,
                             yarilo::proto::Empty *response) override;

  grpc::Status
  GetIgnoredNetworks(grpc::ServerContext *context,
                     const yarilo::proto::Empty *request,
                     yarilo::proto::NetworkList *response) override;

  grpc::Status SaveDecryptedTraffic(grpc::ServerContext *context,
                                    const yarilo::proto::NetworkName *request,
                                    yarilo::proto::Empty *response) override;

  grpc::Status
  GetAvailableRecordings(grpc::ServerContext *context,
                         const yarilo::proto::Empty *request,
                         yarilo::proto::RecordingsList *response) override;

  grpc::Status
  LoadRecording(grpc::ServerContext *context,
                const yarilo::proto::File *request,
                grpc::ServerWriter<yarilo::proto::Packet> *writer) override;

  grpc::Status SetMayhemMode(grpc::ServerContext *context,
                             const yarilo::proto::NewMayhemState *request,
                             yarilo::proto::Empty *response) override;

  grpc::Status
  GetLED(grpc::ServerContext *context, const yarilo::proto::Empty *request,
         grpc::ServerWriter<yarilo::proto::LEDState> *writer) override;

private:
  std::shared_ptr<spdlog::logger> logger;
  bool filemode = true;
  std::unique_ptr<Sniffer> sniffinson;
  Tins::NetworkInterface iface;
  std::filesystem::path save_path;

#ifdef MAYHEM
  std::atomic<bool> led_on = false;
  std::atomic<bool> mayhem_on = false;
#endif
};

} // namespace yarilo

#endif // SNIFF_SERVICE
