#ifndef SNIFFSNIFF_RADIOTAPLAYER_H
#define SNIFFSNIFF_RADIOTAPLAYER_H

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

/**
 * @class RadiotapLayer
 * Represents a radiotap protocol layer
 */
class RadiotapLayer : public pcpp::Layer {
public:
  /**
   * A constructor that creates the layer from an existing packet raw data
   * @param[in] rawData A pointer to the raw data (will be casted to @ref
   * radhdr). This rawdata is copied.
   * @param[in] rawDataLen Size of the data in bytes
   * @param[in] packet A pointer to the Packet instance where layer will be
   * stored in
   */
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

  /**
   * Get a pointer to the radiotap header. Notice this points directly to the
   * data, so every change will change the actual packet data
   * @return A pointer to the @ref radhdr
   */
  radhdr *getRadioHeader() const { return (radhdr *)m_Data; }

  // implement abstract methods

  /**
   * Currently identifies the following next layers:
   * - TODO
   * Otherwise sets PayloadLayer (TODO)
   */
  void parseNextLayer() override{};

  /**
   * @return Size of the radiotap header (including additional extensions if
   * they exist)
   */
  size_t getHeaderLen() const override {
    return le16toh(getRadioHeader()->it_len);
  };

  /**
   * Calculate the following fields:
   * - TODO
   */
  void computeCalculateFields() override{};

  std::string toString() const override {
    return std::format("Radiotap header v{}, Length {}",
                       getRadioHeader()->it_version, getHeaderLen());
  };

  pcpp::OsiModelLayer getOsiModelLayer() const override {
    return pcpp::OsiModelPhysicalLayer;
  }

  /**
   * A static method that validates the input data
   * @param[in] data The pointer to the beginning of a byte stream of IP packet
   * @param[in] dataLen The length of the byte stream
   * @return True if the data is valid and can represent an radiotap packet
   */
  static inline bool isDataValid(const uint8_t *data, size_t dataLen) {
    // TODO: Better detection
    return dataLen <= sizeof(radhdr);
  }
};

#endif // SNIFFSNIFF_RADIOTAPLAYER_H
