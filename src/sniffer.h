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
  void end_capture();

private:
  int count = 0;
  Tins::Crypto::WPA2Decrypter *decrypter;
  std::unordered_map<SSID, AccessPoint *> aps;
  std::string send_iface;
  Tins::BaseSniffer *sniffer;
  std::atomic<bool> end;
};

#endif // SNIFF_SNIFFER
