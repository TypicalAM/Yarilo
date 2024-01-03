
#include "sniffer.h"
#include "access_point.h"
#include <functional>
#include <iostream>
#include <optional>
#include <ostream>
#include <set>
#include <tins/exceptions.h>
#include <tins/packet.h>
#include <tins/pdu.h>

Sniffer::Sniffer(Tins::BaseSniffer *sniffer) {
  this->sniffer = sniffer;
  this->end.store(false);
}

void Sniffer::run() {
  auto pkt_callback =
      std::bind(&Sniffer::callback, this, std::placeholders::_1);
  sniffer->sniff_loop(pkt_callback);
}

bool Sniffer::callback(Tins::PDU &pkt) {
  count++;
  if (end.load())
    return false;

  if (pkt.find_pdu<Tins::Dot11Data>()) {
    auto dot11 = pkt.rfind_pdu<Tins::Dot11Data>();

    for (const auto &[_, ap] : aps)
      if (ap->in_network(dot11))
        return ap->handle_pkt(pkt);

    // TODO: Data before beacon, happens rarely
    return true;
  }

  if (pkt.find_pdu<Tins::Dot11Beacon>()) {
    auto beacon = pkt.rfind_pdu<Tins::Dot11Beacon>();

    if (aps.find(beacon.ssid()) == aps.end())
      aps[beacon.ssid()] = new AccessPoint(beacon);

    return true;
  }

  if (pkt.find_pdu<Tins::Dot11ProbeResponse>()) {
    auto probe = pkt.rfind_pdu<Tins::Dot11ProbeResponse>();
    std::cout << "New probe resp with ssid " << probe.ssid() << std::endl;

    if (aps.find(probe.ssid()) == aps.end())
      aps[probe.ssid()] = new AccessPoint(probe);

    return true;
  }

  return true;
}

std::set<SSID> Sniffer::get_networks() {
  std::set<SSID> res;

  for (const auto &[_, ap] : aps)
    res.insert(ap->get_ssid());

  return res;
}

std::optional<AccessPoint *> Sniffer::get_ap(SSID ssid) {
  if (aps.find(ssid) == aps.end())
    return std::nullopt;

  return aps[ssid];
}

void Sniffer::end_capture() { end.store(true); }
