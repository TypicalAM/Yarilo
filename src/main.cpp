#include "livedecrypt.cpp"
#include <iostream>
#include <tins/sniffer.h>

int main(int argc, char *argv[]) {
  Tins::BaseSniffer mysniff = Tins::FileSniffer("pcap/wpa_induction.pcap");
  LiveDecrypter ldec(&mysniff);
  ldec.run(); // This is non-blocking, just setting the callback!

  SSID example_ssid = ldec.get_detected_networks()[0];
  bool can_add = ldec.can_add_password(example_ssid);
  if (!can_add) {
    std::cerr << "Cannot add passwd" << std::endl;
    return -1;
  }

  bool added = ldec.add_password(example_ssid, "Induction");
  if (!added) {
    std::cerr << "Password not added" << std::endl;
    return -1;
  }

  std::optional<eth_queue> converted = ldec.get_converted(example_ssid);
  if (!converted.has_value()) {
    std::cerr << "Failed to process packets" << std::endl;
    return -1;
  }

  std::cout << "Got " << converted->size() << " processed ethernet packets"
            << std::endl;

  int total_tcp = 0;
  while (!converted->empty()) {
    auto pkt = std::move(converted->front());
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

    converted->pop();
  }

  return 0;
}
