#include "sniffer.h"
#include <iostream>
#include <ratio>
#include <string>
#include <thread>
#include <tins/sniffer.h>

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
  return -1;
  return 0;
}
