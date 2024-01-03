#include "sniffer.h"
#include <iostream>
#include <ratio>
#include <string>
#include <thread>
#include <tins/ethernetII.h>
#include <tins/ip.h>
#include <tins/sniffer.h>
#include <tins/tcp.h>
#include <tins/udp.h>

enum class Mode { INTERFACE, FILE };

struct args {
  Mode mode;
  std::string value;
};

args parse_args(int argc, char *argv[]) {
  args args;

  if (argc < 3) {
    std::cerr << "Usage: " << argv[0] << " <interface|file> <value>"
              << std::endl;
    exit(1);
  }

  std::string modeStr = argv[1];
  if (modeStr == "interface" || modeStr == "if") {
    args.mode = Mode::INTERFACE;
  } else if (modeStr == "file") {
    args.mode = Mode::FILE;
  } else {
    std::cerr << "Invalid mode. Use 'interface', 'if' or 'file'." << std::endl;
    exit(1);
  }

  args.value = argv[2];
  return args;
}

int main(int argc, char *argv[]) {
  args cfg = parse_args(argc, argv);

  Tins::BaseSniffer *sniffer;
  if (cfg.mode == Mode::FILE) {
    sniffer = new Tins::FileSniffer(cfg.value);
  } else {
    sniffer = new Tins::Sniffer(cfg.value);
  }

  Sniffer sniffinson(sniffer);
  // live_decrypter.ignore_network("Coherer");
  std::thread(&Sniffer::run, &sniffinson).detach();
  std::this_thread::sleep_for(std::chrono::duration<int, std::milli>(200));
  std::cout << "Detected networks" << std::endl;
  std::set<SSID> nets = sniffinson.get_networks();
  SSID ssid;
  for (const auto &net : nets) {
    std::cout << net << std::endl;
    if (net[0] == 'C' && net[1] == 'o')
      ssid = net;
  }

  auto net = sniffinson.get_ap(ssid);
  if (!net.has_value()) {
    std::cout << "Didn't find network" << std::endl;
    return -1;
  }

  net.value()->add_passwd("Induction");
  auto channel = net.value()->get_channel();
  while (true) {
    Tins::EthernetII *pkt = channel->receive();
    auto tcp = pkt->find_pdu<Tins::TCP>();
    if (tcp) {
      auto ip = pkt->find_pdu<Tins::IP>();
      std::cout << "TCP packet from " << ip->src_addr() << ":" << tcp->sport()
                << " to " << ip->dst_addr() << ":" << tcp->dport() << std::endl;
    }

    auto udp = pkt->find_pdu<Tins::UDP>();
    if (udp) {
      auto ip = pkt->find_pdu<Tins::IP>();
      std::cout << "UDP packet from " << ip->src_addr() << ":" << udp->sport()
                << " to " << ip->dst_addr() << ":" << udp->dport() << std::endl;
    }
  }

  return 0;
}
