#include <IPv4Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <ProtocolType.h>
#include <iostream>

int main(int argc, char *argv[]) {
  pcpp::PcapFileReaderDevice reader("handshake.pcap");
  if (!reader.open()) {
    std::cerr << "Error opening the pcap file" << std::endl;
    return 1;
  }

  pcpp::RawPacket rawPacket;
  while (reader.getNextPacket(rawPacket)) {
    pcpp::Packet parsedPacket(&rawPacket);
    // In the case of our example file, we can verify the lengths (same as
    // in wireshark)
    std::cout << parsedPacket.getLastLayer()->toString() << std::endl;
  }

  reader.close();
  return 0;
}
