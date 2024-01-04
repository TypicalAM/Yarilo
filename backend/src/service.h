#ifndef SNIFF_SERVICE
#define SNIFF_SERVICE

#include "packets.grpc.pb.h"
#include "packets.pb.h"
#include "sniffer.h"
#include <tins/sniffer.h>

class Service : public Greeter::Service {
public:
  Service(Tins::BaseSniffer *sniffer);

  grpc::Status SayHello(grpc::ServerContext *context,
                        const HelloRequest *request,
                        HelloReply *reply) override;

  grpc::Status GetAccessPoint(grpc::ServerContext *context,
                              const GetAPRequest *request, AP *reply) override;

  grpc::Status GetAllAccessPoints(grpc::ServerContext *context,
                                  const Empty *request,
                                  SSIDList *reply) override;

private:
  Sniffer *sniffinson;
};

#endif // SNIFF_SERVICE
