#ifndef SNIFF_SERVICE
#define SNIFF_SERVICE

#include "packets.grpc.pb.h"

class Service : public Greeter::Service {
  grpc::Status SayHello(grpc::ServerContext *context,
                        const HelloRequest *request,
                        HelloReply *reply) override;
};

#endif // SNIFF_SERVICE
