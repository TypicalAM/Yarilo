#ifndef SNIFF_SERVICE
#define SNIFF_SERVICE

#include "packets.grpc.pb.h"
#include "packets.pb.h"
#include "sniffer.h"
#include <grpcpp/support/sync_stream.h>
#include <tins/sniffer.h>

class Service : public Greeter::Service {
public:
  Service(Tins::BaseSniffer *sniffer);

  grpc::Status GetAccessPoint(grpc::ServerContext *context,
                              const GetAPRequest *request, AP *reply) override;

  grpc::Status GetAllAccessPoints(grpc::ServerContext *context,
                                  const Empty *request,
                                  SSIDList *reply) override;

  grpc::Status ProvidePassword(grpc::ServerContext *context,
                               const PSKRequest *request,
                               PSKResponse *reply) override;
  grpc::Status GetDecryptedPackets(grpc::ServerContext *context,
                                   const PacketRequest *request,
                                   grpc::ServerWriter<Packet> *writer) override;

private:
  Sniffer *sniffinson;
};

#endif // SNIFF_SERVICE
