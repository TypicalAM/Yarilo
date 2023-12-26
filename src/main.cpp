#include "ManagementLayer.h"
#include "RadiotapLayer.h"
#include <Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <ProtocolType.h>
#include <RawPacket.h>
#include <cstdint>
#include <iostream>
#include <ostream>
#include <string>

void ProcessRawPacket(pcpp::RawPacket *rawPacket) {
  uint8_t *raw = (uint8_t *)rawPacket->getRawData();
  size_t len = rawPacket->getRawDataLen();
  pcpp::Layer *radio = new RadiotapLayer(raw, len, nullptr);
  pcpp::Layer *mgmt = new ManagementLayer(
      raw + radio->getHeaderLen(), len - radio->getHeaderLen(), radio, nullptr);

  pcpp::Packet pkt;
  pkt.addLayer(radio);
  pkt.addLayer(mgmt);
  std::cout << pkt.toString() << std::endl;
}

int main(int argc, char *argv[]) {
  pcpp::PcapFileReaderDevice reader("pcap/wpa_induction.pcap");
  if (!reader.open()) {
    std::cerr << "Error opening the pcap file" << std::endl;
    return 1;
  }

  pcpp::RawPacket rawPacket;
  while (reader.getNextPacket(rawPacket)) {
    ProcessRawPacket(&rawPacket);
    break;
  }

  reader.close();
  return 0;
}
