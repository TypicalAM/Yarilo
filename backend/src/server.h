#ifndef SNIFF_SERVER
#define SNIFF_SERVER

#include <cstdint>
#include <grpcpp/server.h>
#include <memory>
#include <tins/sniffer.h>

class Server {
public:
  Server(uint16_t port, Tins::BaseSniffer *sniffer);

private:
  std::unique_ptr<grpc::Server> srv;
};

#endif // SNIFF_SERVER
