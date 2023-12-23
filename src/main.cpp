#include "Layer.h"
#include <Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <ProtocolType.h>
#include <cstdint>
#include <cstring>
#include <endian.h>
#include <format>
#include <iostream>
#include <ostream>
#include <string>

/**
 * @struct radhdr
 * Represents a Radiotap protocol header
 */
#pragma pack(push, 1)
struct radhdr {
  u_int8_t it_version; /* set to 0 */
  u_int8_t it_pad;
  u_int16_t it_len;     /* entire length */
  u_int32_t it_present; /* fields present */
};
#pragma pack(pop)

class RadiotapLayer : public pcpp::Layer {
public:
  RadiotapLayer(uint8_t *data, size_t dataLen, Layer *prevLayer,
                pcpp::Packet *packet)
      : pcpp::Layer(data, dataLen, prevLayer, packet) {
    initLayerInPacket();
  };

  radhdr *getRadioHeader() const { return (radhdr *)m_Data; }

  void initLayerInPacket() {
    size_t totalLen = le16toh(getRadioHeader()->it_len);
    if (totalLen < m_DataLen)
      m_DataLen = totalLen;
  }

  void parseNextLayer() override{};

  size_t getHeaderLen() const override { return getRadioHeader()->it_len; };

  void computeCalculateFields() override{
      // TODO: Do we really need anything here?
  };

  std::string toString() const override {
    return std::format("Radiotap header v{}, Length {}",
                       getRadioHeader()->it_version, getRadioHeader()->it_len);
  };

  pcpp::OsiModelLayer getOsiModelLayer() const override {
    return pcpp::OsiModelPhysicalLayer;
  }
};

int main(int argc, char *argv[]) {
  pcpp::PcapFileReaderDevice reader("wpa-induction.pcap");
  if (!reader.open()) {
    std::cerr << "Error opening the pcap file" << std::endl;
    return 1;
  }

  pcpp::RawPacket rawPacket;
  while (reader.getNextPacket(rawPacket)) {
    pcpp::Packet packet;
    std::cout << (packet.getFirstLayer() == nullptr) << std::endl;
    size_t len = rawPacket.getRawDataLen();
    uint8_t *data = new uint8_t[len];
    std::memcpy(data, rawPacket.getRawData(), len);

    // no previous layer, don't associate ownwership with a packet
    packet.addLayer(new RadiotapLayer(data, len, nullptr, nullptr));
    std::cout << packet.toString() << std::endl;
    break;
  }

  reader.close();
  return 0;
}
