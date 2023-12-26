#ifndef SNIFFSNIFF_RADIOTAPLAYER_H
#define SNIFFSNIFF_RADIOTAPLAYER_H

#include "ManagementLayer.h"

#include <Layer.h>
#include <cstdint>
#include <cstring>
#include <endian.h>
#include <format>

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
  RadiotapLayer(uint8_t *rawData, size_t rawDataLen, pcpp::Packet *packet)
      : pcpp::Layer() {
    m_DataLen = rawDataLen;
    m_PrevLayer = nullptr;

    size_t totalLen = le16toh(((radhdr *)rawData)->it_len);
    if (totalLen < m_DataLen)
      m_DataLen = totalLen;

    m_Data = new uint8_t[rawDataLen];
    std::memcpy(m_Data, rawData, m_DataLen);
  };

  radhdr *getRadioHeader() const { return (radhdr *)m_Data; }

  void parseNextLayer() override{};

  size_t getHeaderLen() const override {
    return le16toh(getRadioHeader()->it_len);
  };

  void computeCalculateFields() override{
      // TODO: Do we really need anything here?
  };

  std::string toString() const override {
    return std::format("Radiotap header v{}, Length {}",
                       getRadioHeader()->it_version, getHeaderLen());
  };

  pcpp::OsiModelLayer getOsiModelLayer() const override {
    return pcpp::OsiModelPhysicalLayer;
  }
};

#endif // SNIFFSNIFF_RADIOTAPLAYER_H
