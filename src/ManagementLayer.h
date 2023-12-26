#ifndef SNIFFSNIFF_MANAGEMENTLAYER_H
#define SNIFFSNIFF_MANAGEMENTLAYER_H

#include <Layer.h>
#include <cstdint>
#include <cstring>

#include <iomanip>
#include <iostream>
#include <string>
#include <sys/types.h>

void printHex(uint8_t *data, int i) {
  for (int j = 0; j < i; ++j) {
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(data[j]);
    std::cout << " ";
  }
  std::cout << std::endl;
}

/**
 * @struct machdr
 * Represents a 802.11 Management Access Control header
 */
#pragma pack(push, 1)
struct machdr {
  uint16_t frameControl; // Frame Control
  uint16_t durationId;   // Duration/ID
  uint8_t receiverAddr[6];
  uint8_t transmitterAddr[6];
  uint8_t destinationAddr[6];
  uint16_t sequenceControl;
};

/**
 * @struct fcs
 * Represents a 802.11 Frame Check Sequence field
 */
struct fcs {
  uint32_t fcs;
};
#pragma pack(pop)

enum MacFrameType { DATA = 0, BEACON = 8, PROBE_REQ = 1, PROBE_RESP = 2 };

class ManagementLayer : public pcpp::Layer {
public:
  ManagementLayer(uint8_t *rawData, size_t rawDataLen, pcpp::Layer *prevLayer,
                  pcpp::Packet *packet)
      : Layer() {
    m_PrevLayer = prevLayer;
    m_Packet = packet;

    uint16_t frameCtl = ((machdr *)rawData)->frameControl;
    uint8_t frameSubtype = static_cast<uint8_t>((frameCtl & 0x00FF) >> 4);
    switch (frameSubtype) {
    case 8:
      subtype = 8;
    default:
      // TODO: Handle non-mandatory fields, subtype differences
      m_DataLen = sizeof(machdr);
      m_Data = new uint8_t[sizeof(machdr)];
      std::memcpy(m_Data, rawData, m_DataLen);
    }
  };

  machdr *getMACHeader() { return (machdr *)m_Data; }

  void parseNextLayer() override{
      // TODO
  };

  size_t getHeaderLen() const override { return sizeof(machdr); };

  void computeCalculateFields() override {
    // TODO: Do we really need anything here?
  }

  std::string toString() const override {
    switch (subtype) {
    case 8:
      return "IEEE 802.11 Beacon frame";

    default:
      return "IEEE 802.11 Unknown";
    }
  }

  pcpp::OsiModelLayer getOsiModelLayer() const override {
    return pcpp::OsiModelPhysicalLayer;
  }

private:
  int subtype;
};

#endif // SNIFFSNIFF_MANAGEMENTLAYER_H
