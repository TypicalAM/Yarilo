#include "formatter.h"
#include "packets.pb.h"
#include <tins/arp.h>
#include <tins/dhcp.h>
#include <tins/dhcpv6.h>
#include <tins/dns.h>
#include <tins/ethernetII.h>
#include <tins/exceptions.h>
#include <tins/icmp.h>
#include <tins/icmpv6.h>
#include <tins/ip.h>
#include <tins/ipv6.h>
#include <tins/rawpdu.h>
#include <tins/tcp.h>
#include <tins/udp.h>

namespace yarilo {

proto::Packet PacketFormatter::format(std::unique_ptr<Tins::Packet> pkt,
                                      bool with_payload) {
  auto eth2 = pkt->pdu()->rfind_pdu<Tins::EthernetII>();
  proto::Packet result;
  result.set_src(eth2.src_addr().to_string());
  result.set_dst(eth2.dst_addr().to_string());

  if (auto arp = pkt->pdu()->find_pdu<Tins::ARP>()) {
    add_arp(&result, arp);
    return result;
  }

  if (auto ip = pkt->pdu()->find_pdu<Tins::IP>()) {
    add_ip(&result, ip, with_payload);
    return result;
  }

  if (auto ipv6 = pkt->pdu()->find_pdu<Tins::IPv6>()) {
    add_ipv6(&result, ipv6, with_payload);
    return result;
  }

  auto raw = pkt->pdu()->find_pdu<Tins::RawPDU>();
  add_raw(&result, raw, with_payload);
  return result;
}

void PacketFormatter::add_raw(proto::Packet *pkt, Tins::RawPDU *raw_pdu,
                              bool with_payload) {
  auto raw = std::make_unique<proto::Raw>();
  if (with_payload) {
    std::vector<uint8_t> data = raw_pdu->clone()->serialize();
    raw->set_payload(std::string(data.begin(), data.end()));
  }

  pkt->set_protocol(proto::Protocol::PROTO_RAW);
  pkt->set_allocated_raw(raw.release());
}

void PacketFormatter::add_arp(proto::Packet *pkt, Tins::ARP *arp_pdu) {
  auto arp = std::make_unique<proto::ARP>();
  arp->set_sender_ip_address(arp_pdu->sender_ip_addr().to_string());
  arp->set_sender_mac_address(arp_pdu->sender_hw_addr().to_string());
  arp->set_target_ip_address(arp_pdu->target_ip_addr().to_string());
  arp->set_target_mac_address(arp_pdu->target_hw_addr().to_string());

  pkt->set_protocol(proto::Protocol::PROTO_ARP);
  pkt->set_allocated_arp(arp.release());
}

proto::ICMP *PacketFormatter::format_ICMP(Tins::ICMP *icmp_pdu) {
  auto icmp = std::make_unique<proto::ICMP>();
  icmp->set_code(icmp_pdu->code());
  switch (icmp_pdu->type()) {
  case Tins::ICMP::ECHO_REPLY:
    icmp->set_type(proto::ICMP::ECHO_REPLY);
    break;

  case Tins::ICMP::DEST_UNREACHABLE:
    icmp->set_type(proto::ICMP::DESTINATION_UNREACHABLE);
    break;

  case Tins::ICMP::ECHO_REQUEST:
    icmp->set_type(proto::ICMP::ECHO_REQUEST);
    break;

  case Tins::ICMP::TIME_EXCEEDED:
    icmp->set_type(proto::ICMP::TIME_EXCEEDED);
    break;

  default:
    icmp->set_type(proto::ICMP::OTHER);
  }

  return icmp.release();
}

proto::ICMPv6 *PacketFormatter::format_ICMPv6(Tins::ICMPv6 *icmpv6_pdu) {
  auto icmpv6 = std::make_unique<proto::ICMPv6>();
  icmpv6->set_type(static_cast<proto::ICMPv6::Type>(icmpv6_pdu->type()));
  icmpv6->set_code(icmpv6_pdu->code());
  icmpv6->set_checksum(icmpv6_pdu->checksum());
  return icmpv6.release();
}

proto::DNS *PacketFormatter::format_DNS(Tins::DNS *dns_pdu) {
  auto dns = std::make_unique<proto::DNS>();
  dns->set_id(dns_pdu->id());
  dns->set_qr(dns_pdu->type());

  for (const auto query : dns_pdu->queries()) {
    proto::DNS_Question *question = dns->add_questions();
    question->set_name(query.dname());
    question->set_type(query.query_type());
  }

  for (const auto &answer : dns_pdu->answers()) {
    proto::DNS_ResourceRecord *record = dns->add_answers();
    record->set_name(answer.dname());
    record->set_type(answer.query_type());
    record->set_data(answer.data());
  }

  return dns.release();
}

proto::DHCP *PacketFormatter::format_DHCP(Tins::DHCP *dhcp_pdu) {
  auto dhcp = std::make_unique<proto::DHCP>();
  dhcp->set_message_type(dhcp_pdu->type());
  dhcp->set_transaction_id(dhcp_pdu->xid());
  dhcp->set_client_ip_address(dhcp_pdu->ciaddr().to_string());
  dhcp->set_client_mac_address(dhcp_pdu->chaddr().to_string());
  dhcp->set_your_ip_address(dhcp_pdu->yiaddr().to_string());
  dhcp->set_server_ip_address(dhcp_pdu->siaddr().to_string());
  return dhcp.release();
}

proto::DHCPv6 *PacketFormatter::format_DHCPv6(Tins::DHCPv6 *dhcpv6_pdu) {
  auto dhcpv6 = std::make_unique<proto::DHCPv6>();
  dhcpv6->set_message_type(dhcpv6_pdu->msg_type());
  dhcpv6->set_transaction_id(dhcpv6_pdu->transaction_id());
  for (const auto &opt : dhcpv6_pdu->options()) {
    proto::DHCPv6_Option *option = dhcpv6->add_options();
    option->set_option_code(opt.option());
    option->set_option_length(opt.data_size());
    option->set_option_data(
        std::string(opt.data_ptr(), opt.data_ptr() + opt.data_size()));
  }

  return dhcpv6.release();
}

void PacketFormatter::add_ip(proto::Packet *pkt, Tins::IP *ip_pdu,
                             bool with_payload) {
  auto ip = std::make_unique<proto::IP>();
  ip->set_source_address(ip_pdu->src_addr().to_string());
  ip->set_destination_address(ip_pdu->dst_addr().to_string());
  ip->set_ttl(ip_pdu->ttl());
  ip->set_protocol(ip_pdu->protocol());
  ip->set_total_length(ip_pdu->tot_len());

  if (with_payload) {
    std::vector<uint8_t> data = ip_pdu->clone()->serialize();
    ip->set_payload(std::string(data.begin(), data.end()));
  }

  if (auto icmp_pdu = ip_pdu->find_pdu<Tins::ICMP>()) {
    auto icmp = format_ICMP(icmp_pdu);
    ip->set_next_protocol(proto::Protocol::PROTO_ICMP);
    ip->set_allocated_icmp(icmp);
  } else if (auto tcp_pdu = ip_pdu->find_pdu<Tins::TCP>()) {
    auto tcp = format_TCP(tcp_pdu);
    ip->set_next_protocol(proto::Protocol::PROTO_TCP);
    ip->set_allocated_tcp(tcp);
  } else if (auto udp_pdu = ip_pdu->find_pdu<Tins::UDP>()) {
    auto udp = format_UDP(udp_pdu);
    ip->set_next_protocol(proto::Protocol::PROTO_UDP);
    ip->set_allocated_udp(udp);
  } else
    ip->set_next_protocol(proto::Protocol::PROTO_RAW);

  pkt->set_protocol(proto::Protocol::PROTO_IP);
  pkt->set_allocated_ip(ip.release());
}

void PacketFormatter::add_ipv6(proto::Packet *pkt, Tins::IPv6 *ipv6_pdu,
                               bool with_payload) {
  auto ipv6 = std::make_unique<proto::IPv6>();
  ipv6->set_source_address(ipv6_pdu->src_addr().to_string());
  ipv6->set_destination_address(ipv6_pdu->dst_addr().to_string());
  ipv6->set_hop_limit(ipv6_pdu->hop_limit());
  ipv6->set_next_header(ipv6_pdu->next_header());
  ipv6->set_payload_length(ipv6_pdu->payload_length());

  if (with_payload) {
    std::vector<uint8_t> data = ipv6_pdu->clone()->serialize();
    ipv6->set_payload(std::string(data.begin(), data.end()));
  }

  if (auto icmpv6_pdu = ipv6_pdu->find_pdu<Tins::ICMPv6>()) {
    auto icmpv6 = format_ICMPv6(icmpv6_pdu);
    ipv6->set_next_protocol(proto::Protocol::PROTO_ICMPv6);
    ipv6->set_allocated_icmpv6(icmpv6);
  } else if (auto tcp_pdu = ipv6_pdu->find_pdu<Tins::TCP>()) {
    auto tcp = format_TCP(tcp_pdu);
    ipv6->set_next_protocol(proto::Protocol::PROTO_TCP);
    ipv6->set_allocated_tcp(tcp);
  } else if (auto udp_pdu = ipv6_pdu->find_pdu<Tins::UDP>()) {
    auto udp = format_UDP(udp_pdu);
    ipv6->set_next_protocol(proto::Protocol::PROTO_UDP);
    ipv6->set_allocated_udp(udp);
  } else
    ipv6->set_next_protocol(proto::Protocol::PROTO_RAW);

  pkt->set_protocol(proto::Protocol::PROTO_IPv6);
  pkt->set_allocated_ipv6(ipv6.release());
}

proto::TCP *PacketFormatter::format_TCP(Tins::TCP *tcp_pdu) {
  auto tcp = std::make_unique<proto::TCP>();
  tcp->set_source_port(tcp_pdu->sport());
  tcp->set_destination_port(tcp_pdu->dport());
  tcp->set_sequence_number(tcp_pdu->seq());
  tcp->set_acknowledgment_number(tcp_pdu->ack_seq());
  tcp->set_window_size(tcp_pdu->window());
  tcp->set_syn(tcp_pdu->flags() & Tins::TCP::SYN);
  tcp->set_ack(tcp_pdu->flags() & Tins::TCP::ACK);
  tcp->set_fin(tcp_pdu->flags() & Tins::TCP::FIN);
  return tcp.release();
}

proto::UDP *PacketFormatter::format_UDP(Tins::UDP *udp_pdu) {
  auto udp = std::make_unique<proto::UDP>();
  udp->set_source_port(udp_pdu->sport());
  udp->set_destination_port(udp_pdu->dport());

  try {
    auto dns = udp_pdu->find_pdu<Tins::RawPDU>()->to<Tins::DNS>();
    udp->set_next_protocol(proto::Protocol::PROTO_DNS);
    udp->set_allocated_dns(format_DNS(&dns));
    return udp.release();
  } catch (const Tins::malformed_packet &exc) {
  }

  try {
    auto dhcp = udp_pdu->find_pdu<Tins::RawPDU>()->to<Tins::DHCP>();
    udp->set_next_protocol(proto::Protocol::PROTO_DHCP);
    udp->set_allocated_dhcp(format_DHCP(&dhcp));
    return udp.release();
  } catch (const Tins::malformed_packet &exc) {
  }

  try {
    auto dhcpv6 = udp_pdu->find_pdu<Tins::RawPDU>()->to<Tins::DHCPv6>();
    udp->set_next_protocol(proto::Protocol::PROTO_DHCPv6);
    udp->set_allocated_dhcpv6(format_DHCPv6(&dhcpv6));
    return udp.release();
  } catch (const Tins::malformed_packet &exc) {
  }

  return udp.release();
}

} // namespace yarilo
