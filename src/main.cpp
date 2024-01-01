#include "livedecrypt.cpp"
#include <iostream>
#include <ratio>
#include <string>
#include <thread>
#include <tins/sniffer.h>
#include <vector>

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

  LiveDecrypter live_decrypter(sniffer);
  std::thread(&LiveDecrypter::run, &live_decrypter).detach();
  std::this_thread::sleep_for(std::chrono::duration<int, std::milli>(200));
  live_decrypter.end_capture();
  delete sniffer;

  std::cout << "Detected networks" << std::endl;
  std::vector<SSID> nets = live_decrypter.get_detected_networks();
  for (const auto &net : nets) {
    std::cout << "SSID: " << net << std::endl;
  }

  SSID example_ssid = live_decrypter.get_detected_networks()[0];
  bool can_add = live_decrypter.can_add_password(example_ssid);
  if (!can_add) {
    std::cerr << "Cannot add passwd" << std::endl;
    return -1;
  }

  bool added = live_decrypter.add_password(example_ssid, "MlodyBoss1");
  if (!added) {
    std::cerr << "Password not added" << std::endl;
    return -1;
  }

  std::optional<eth_queue> converted =
      live_decrypter.get_converted(example_ssid);
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
