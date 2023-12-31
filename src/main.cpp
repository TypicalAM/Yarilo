#include "livedecrypt.cpp"
#include <tins/sniffer.h>

int main(int argc, char *argv[]) {
  Tins::BaseSniffer mysniff = Tins::FileSniffer("pcap/wpa_induction.pcap");
  LiveDecrypter ldec(&mysniff);
  ldec.run();

  std::cout << "Networks found: " << std::endl;
  for (auto &item : ldec.get_detected_networks()) {
    ldec.add_password(item, "Induction");
    std::cout << "Network: " << item << std::endl;
  }

  std::queue<Tins::EthernetII *> processed = ldec.get_processed();
  std::cout << "Got " << processed.size() << " processed ethernet packets"
            << std::endl;

  int total_tcp = 0;
  while (!processed.empty()) {
    auto pkt = std::move(processed.front());
    auto ip = pkt->find_pdu<Tins::IP>();
    if (ip) {
      auto tcp = pkt->find_pdu<Tins::TCP>();
      if (tcp) {
        std::cout << "Found tcp packet from " << ip->src_addr() << ":"
                  << tcp->sport() << " to " << ip->dst_addr() << ":"
                  << tcp->dport() << std::endl;
        total_tcp++;
      }
    };

    processed.pop();
  }

  return 0;
}
