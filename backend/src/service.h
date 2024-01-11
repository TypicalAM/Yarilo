#ifndef SNIFF_SERVICE
#define SNIFF_SERVICE

#include "packets.grpc.pb.h"
#include "packets.pb.h"
#include "sniffer.h"
#include <grpcpp/support/sync_stream.h>
#include <tins/sniffer.h>

class Service : public Sniffinson::Service {
public:
  Service(Tins::BaseSniffer *sniffer);
  Service(Tins::BaseSniffer *sniffer, Tins::NetworkInterface iface);

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
                               DecryptResponse *response) override;
  grpc::Status
  GetDecryptedPackets(grpc::ServerContext *context,
                      const ::NetworkName *request,
                      grpc::ServerWriter<::Packet> *writer) override;
  grpc::Status DeauthNetwork(grpc::ServerContext *context,
                             const NetworkName *request,
                             Empty *response) override;
  grpc::Status IgnoreNetwork(grpc::ServerContext *context,
                             const NetworkName *request,
                             Empty *response) override;
  grpc::Status GetIgnoredNetworks(grpc::ServerContext *context,
                                  const Empty *request,
                                  NetworkList *response) override;

private:
  bool filemode = true;
  Sniffer *sniffinson;
  Tins::NetworkInterface iface;
};

#endif // SNIFF_SERVICE
