#include "server.h"
#include "sniffer.h"
#include <iostream>
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
#ifdef MAYHEM
  std::cout << "Mayhem enabled" << std::endl;
#endif

  args cfg = parse_args(argc, argv);

  Tins::BaseSniffer *sniffer;
  if (cfg.mode == Mode::FILE) {
    sniffer = new Tins::FileSniffer(cfg.value);
  } else {
    sniffer = new Tins::Sniffer(cfg.value);
  }

  Server srv(9090, sniffer);
  return 0;
};
