#ifndef SNIFF_SERVER
#define SNIFF_SERVER

#include <cstdint>
#include <grpcpp/server.h>
#include <memory>

class Server {
public:
  Server(uint16_t port);
  void wait();

private:
  std::unique_ptr<grpc::Server> srv;
};

#endif // SNIFF_SERVER
