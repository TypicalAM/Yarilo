#include <cstddef>
#include <cstring>
#include <iostream>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <optional>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <string>

enum class Protocol {
  TCP,
  UDP,
  ICMP,
  ARP,
  UNKNOWN,
};

class Packet {
private:
  Protocol protocol;
  char *data;
  size_t data_len;
  in_addr src_ip;
  uint src_port;
  in_addr dst_ip;
  uint dst_port;

public:
  std::string source_ip() {
    std::string result(inet_ntoa(src_ip));
    result += ":" + std::to_string(src_port);
    return result;
  }

  std::string dest_ip() {
    std::string result(inet_ntoa(dst_ip));
    result += ":" + std::to_string(dst_port);
    return result;
  }

  std::string readable() {
    std::string readable = "From " + source_ip() + " to " + dest_ip() + " via ";
    switch (protocol) {
    case Protocol::TCP:
      readable += "TCP";
      break;
    case Protocol::UDP:
      readable += "UDP";
      break;
    case Protocol::ICMP:
      readable += "ICMP";
      break;
    case Protocol::ARP:
      readable += "ARP";
      break;
    case Protocol::UNKNOWN:
      readable += "UNKNOWN";
      break;
    }
    readable += " with " + std::to_string(data_len) + " bytes of data";
    return readable;
  }

  Packet(Protocol protocol, char *data, size_t data_len, in_addr source_ip,
         int source_port, in_addr dest_ip, int dest_port) {
    this->protocol = protocol;
    this->data = new char[data_len];
    this->data_len = data_len;
    this->src_ip = source_ip;
    this->src_port = source_port;
    this->dst_ip = dest_ip;
    this->dst_port = dest_port;

    // Copy this since libpcap can free the buffer
    // after the callback returns
    strcpy(this->data, data);
  }
};

void test(u_char *_, const struct pcap_pkthdr *h, const u_char *bytes) {
  if (h == NULL) {
    std::cout << "empty header" << std::endl;
    return;
  }

  struct ether_header *eptr = (struct ether_header *)bytes;
  switch (ntohs(eptr->ether_type)) {
  case ETHERTYPE_IP: {
    std::cout << "Packet ether: to "
              << ether_ntoa((const struct ether_addr *)&eptr->ether_shost)
              << ":"
              << ether_ntoa((const struct ether_addr *)&eptr->ether_dhost)
              << std::endl;

    struct ip *ip_header = (struct ip *)(bytes + sizeof(struct ether_header));
    uint ip_header_len = ip_header->ip_hl * 4;

    if (ip_header->ip_p == IPPROTO_UDP) {
      in_addr src_ip = ip_header->ip_src;
      in_addr dst_ip = ip_header->ip_dst;
      char *data = (char *)(bytes + sizeof(struct ether_header) +
                            ip_header_len + sizeof(struct udphdr));
      size_t data_len = h->len - sizeof(struct ether_header) - ip_header_len -
                        sizeof(struct udphdr);
      udphdr *udp_header =
          (udphdr *)(bytes + sizeof(struct ether_header) + ip_header_len);
      uint src_port = ntohs(udp_header->source);
      uint dst_port = ntohs(udp_header->dest);
      Packet packet(Protocol::UDP, data, data_len, src_ip, src_port, dst_ip,
                    dst_port);
      std::cout << packet.readable() << std::endl;
    } else if (ip_header->ip_p == IPPROTO_TCP) {
      in_addr src_ip = ip_header->ip_src;
      in_addr dst_ip = ip_header->ip_dst;
      char *data = (char *)(bytes + sizeof(struct ether_header) +
                            ip_header_len + sizeof(struct tcphdr));
      size_t data_len = h->len - sizeof(struct ether_header) - ip_header_len -
                        sizeof(struct tcphdr);
      tcphdr *tcp_header =
          (tcphdr *)(bytes + sizeof(struct ether_header) + ip_header_len);
      uint src_port = ntohs(tcp_header->source);
      uint dst_port = ntohs(tcp_header->dest);
      Packet packet(Protocol::TCP, data, data_len, src_ip, src_port, dst_ip,
                    dst_port);
      std::cout << packet.readable() << std::endl << std::endl;
    }

    break;
  }

  case ETHERTYPE_ARP:
    std::cout << "ARP packet\n" << std::endl;
    break;

  default:
    std::cout << "Unknown packet\n" << std::endl;
  }
}

std::optional<pcap_if_t> find_appropriate_device() {
  char error_buf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs;
  if (pcap_findalldevs(&alldevs, error_buf) == PCAP_ERROR) {
    std::cerr << "Error in pcap_findalldevs: " << error_buf << std::endl;
    return std::nullopt;
  }

  bool found = false;
  pcap_if_t device;
  while (true) {
    if (alldevs->next == NULL)
      break;
    std::string name(alldevs->name);
    if (name.length() > 3 && name.substr(name.length() - 3) == "4s0") {
      found = true;
      device = *alldevs;
    }

    alldevs = alldevs->next;
  }

  pcap_freealldevs(alldevs);
  if (!found) {
    return std::nullopt;
  } else {
    return device;
  }
}

int main(int argc, char **argv) {
  auto device = find_appropriate_device();
  if (!device.has_value()) {
    std::cerr << "No suitable device found" << std::endl;
    return -1;
  }

  std::cout << "Found dev: " << device->name << std::endl;
  char error_buffer[PCAP_ERRBUF_SIZE];
  auto handle = pcap_open_live(device->name, BUFSIZ, 0, -1, error_buffer);
  if (handle == NULL) {
    std::cerr << "Cannot start sniffing: " << error_buffer << std::endl;
    return -1;
  }

  pcap_loop(handle, 10, test, NULL);
  pcap_close(handle);
  return 0;
}
