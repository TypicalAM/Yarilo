#ifndef SNIFF_FORMATTER
#define SNIFF_FORMATTER

#include "proto/service.pb.h"
#include <tins/arp.h>
#include <tins/dhcp.h>
#include <tins/dhcpv6.h>
#include <tins/dns.h>
#include <tins/ethernetII.h>
#include <tins/icmp.h>
#include <tins/icmpv6.h>
#include <tins/ip.h>
#include <tins/ipv6.h>
#include <tins/packet.h>
#include <tins/rawpdu.h>
#include <tins/tcp.h>
#include <tins/udp.h>

namespace yarilo {

class PacketFormatter {
public:
  static proto::Packet format(std::unique_ptr<Tins::Packet> pkt,
                              bool with_payload);

private:
  static void add_raw(proto::Packet *pkt, Tins::RawPDU *raw_pdu,
                      bool with_payload);
  static void add_arp(proto::Packet *pkt, Tins::ARP *arp_pdu);
  static void add_ip(proto::Packet *pkt, Tins::IP *ip_pdu, bool with_payload);
  static void add_ipv6(proto::Packet *pkt, Tins::IPv6 *ipv6_pdu,
                       bool with_payload);
  static proto::ICMP *format_ICMP(Tins::ICMP *icmp_pdu);
  static proto::ICMPv6 *format_ICMPv6(Tins::ICMPv6 *icmpv6_pdu);
  static proto::DNS *format_DNS(Tins::DNS *dns_pdu);
  static proto::DHCP *format_DHCP(Tins::DHCP *dhcp_pdu);
  static proto::DHCPv6 *format_DHCPv6(Tins::DHCPv6 *dhcpv6_pdu);
  static proto::TCP *format_TCP(Tins::TCP *tcp_pdu);
  static proto::UDP *format_UDP(Tins::UDP *udp_pdu);
};

} // namespace yarilo

#endif // SNIFF_FORMATTER
