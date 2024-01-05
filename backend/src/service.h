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

  grpc::Status GetAccessPoint(grpc::ServerContext *context,
                              const NetworkName *request,
                              APInfo *reply) override;

  grpc::Status GetAllAccessPoints(grpc::ServerContext *context,
                                  const Empty *request,
                                  NetworkList *reply) override;

  grpc::Status ProvidePassword(grpc::ServerContext *context,
                               const DecryptRequest *request,
                               DecryptResponse *reply) override;

  grpc::Status GetDecryptedPackets(grpc::ServerContext *context,
                                   const NetworkName *request,
                                   grpc::ServerWriter<Packet> *writer) override;

  grpc::Status IgnoreNetwork(grpc::ServerContext *context,
                             const NetworkName *request, Empty *reply) override;

  grpc::Status GetIgnoredNetworks(grpc::ServerContext *context,
                                  const Empty *request,
                                  NetworkList *reply) override;

  grpc::Status DeauthNetwork(grpc::ServerContext *context,
                             const NetworkName *request, Empty *reply) override;

private:
  Sniffer *sniffinson;
};

#endif // SNIFF_SERVICE
