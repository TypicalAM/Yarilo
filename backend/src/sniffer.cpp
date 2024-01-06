
#include "sniffer.h"
#include "access_point.h"
#include <functional>
#include <optional>
#include <set>
#include <tins/exceptions.h>
#include <tins/hw_address.h>
#include <tins/packet.h>
#include <tins/pdu.h>
#include <tins/tins.h>

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

  auto dot11 = pkt.find_pdu<Tins::Dot11Data>();
  auto qos = pkt.find_pdu<Tins::Dot11QoSData>();
  if (dot11 || qos) {
    Tins::HWAddress<6> bssid = dot11 ? dot11->bssid_addr() : qos->bssid_addr();

    for (const auto &[_, ap] : aps)
      if (ap->get_bssid() == bssid)
        return ap->handle_pkt(pkt);

    // TODO: Data before beacon, happens rarely
    return true;
  }

  Tins::HWAddress<6> bssid;
  SSID ssid;

  auto beacon = pkt.find_pdu<Tins::Dot11Beacon>();
  auto probe_resp = pkt.find_pdu<Tins::Dot11ProbeResponse>();
  if (beacon || probe_resp) {
    ssid = beacon ? beacon->ssid() : probe_resp->ssid();
    if (ignored_networks.find(ssid) != ignored_networks.end())
      return true;

    int channel = 0;
    auto radio = pkt.find_pdu<Tins::RadioTap>();
    if (radio)
      channel = (radio->channel_freq() - 2412) / 5 +
                1; // Basic channel freq calculation

    bssid = beacon ? beacon->addr3() : probe_resp->addr3();
    if (aps.find(ssid) == aps.end())
      aps[ssid] = new AccessPoint(bssid, ssid, channel);
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

void Sniffer::add_ignored_network(SSID ssid) {
  ignored_networks.insert(ssid);
  if (aps.find(ssid) != aps.end())
    aps.erase(ssid);
}

std::set<SSID> Sniffer::get_ignored_networks() { return ignored_networks; }

void Sniffer::end_capture() { end.store(true); }
