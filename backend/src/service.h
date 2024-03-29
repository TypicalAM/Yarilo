#ifndef SNIFF_SERVICE
#define SNIFF_SERVICE

#include "packets.grpc.pb.h"
#include "packets.pb.h"
#include "sniffer.h"
#include <filesystem>
#include <grpcpp/support/sync_stream.h>
#include <memory>
#include <tins/sniffer.h>

class Service : public Sniffinson::Service {
public:
  Service(std::unique_ptr<Tins::BaseSniffer>);
  Service(std::unique_ptr<Tins::BaseSniffer>, Tins::NetworkInterface iface);

  void start_sniffer();

  void add_save_path(std::filesystem::path path);

  grpc::Status GetAllAccessPoints(grpc::ServerContext *context,
                                  const Empty *request,
                                  NetworkList *response) override;

  grpc::Status GetAccessPoint(grpc::ServerContext *context,
                              const NetworkName *request,
                              NetworkInfo *response) override;

  grpc::Status FocusNetwork(grpc::ServerContext *context,
                            const NetworkName *request,
                            Empty *response) override;

  grpc::Status GetFocusState(grpc::ServerContext *context, const Empty *request,
                             FocusState *response) override;

  grpc::Status StopFocus(grpc::ServerContext *context, const Empty *request,
                         Empty *response) override;

  grpc::Status ProvidePassword(grpc::ServerContext *context,
                               const DecryptRequest *request,
                               Empty *response) override;

  grpc::Status GetDecryptedPackets(grpc::ServerContext *context,
                                   const ::NetworkName *request,
                                   grpc::ServerWriter<Packet> *writer) override;

  grpc::Status DeauthNetwork(grpc::ServerContext *context,
                             const DeauthRequest *request,
                             Empty *response) override;

  grpc::Status IgnoreNetwork(grpc::ServerContext *context,
                             const NetworkName *request,
                             Empty *response) override;

  grpc::Status GetIgnoredNetworks(grpc::ServerContext *context,
                                  const Empty *request,
                                  NetworkList *response) override;

  grpc::Status SaveDecryptedTraffic(grpc::ServerContext *context,
                                    const NetworkName *request,
                                    Empty *response) override;

  grpc::Status GetAvailableRecordings(grpc::ServerContext *context,
                                      const Empty *request,
                                      RecordingsList *response) override;

  grpc::Status LoadRecording(grpc::ServerContext *context, const File *request,
                             grpc::ServerWriter<Packet> *writer) override;

  grpc::Status SetMayhemMode(grpc::ServerContext *context,
                             const NewMayhemState *request,
                             Empty *response) override;

  grpc::Status GetLED(grpc::ServerContext *context, const Empty *request,
                      grpc::ServerWriter<LEDState> *writer) override;

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

#endif // SNIFF_SERVICE
