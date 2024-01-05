#ifndef SNIFF_SNIFFER
#define SNIFF_SNIFFER

#include "access_point.h"
#include <atomic>
#include <set>
#include <tins/crypto.h>
#include <tins/pdu.h>
#include <tins/sniffer.h>
#include <unordered_map>

class Sniffer {
public:
  Sniffer(Tins::BaseSniffer *sniffer);
  void run();
  bool callback(Tins::PDU &pkt);
  std::set<SSID> get_networks();
  std::optional<AccessPoint *> get_ap(SSID ssid);
  // Ignore network and delete any ap with this name from the list
  void add_ignored_network(SSID ssid);
  std::set<SSID> get_ignored_networks();
  void end_capture();

private:
  int count = 0;
  Tins::Crypto::WPA2Decrypter *decrypter;
  std::unordered_map<SSID, AccessPoint *> aps;
  std::string send_iface;
  std::set<SSID> ignored_networks;
  Tins::BaseSniffer *sniffer;
  std::atomic<bool> end;
};

#endif // SNIFF_SNIFFER
