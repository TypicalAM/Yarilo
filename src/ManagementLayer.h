#ifndef SNIFFSNIFF_MANAGEMENTLAYER_H
#define SNIFFSNIFF_MANAGEMENTLAYER_H

#include <Layer.h>
#include <cstdint>
#include <cstring>

#include <string>
#include <sys/types.h>

/**
 * @struct framectl
 * Represents a 802.11 Frame Control (2 octets)
 */
#pragma pack(push, 1)
struct framectl {
  uint16_t protocolVersion : 2; // Protocol Version
  uint16_t type : 2;            // Type
  uint16_t subtype : 4;         // Subtype
  uint16_t toDS : 1;            // To DS
  uint16_t fromDS : 1;          // From DS
  uint16_t moreFragments : 1;   // More fragments
  uint16_t retry : 1;           // Retry
  uint16_t powerMgmt : 1;       // Power Management
  uint16_t moreData : 1;        // More data
  uint16_t protectedFrame : 1;  // Protected frame
  uint16_t htcOrder : 1;        // +HTC/Order
};

/**
 * @struct machdr
 * Represents a 802.11 Management Access Control header
 */
struct machdr {
  framectl frameControl; // Frame Control
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

/**
 * An enum for all managed MAC frame types
 */
enum MacFrameType {
  MANAGEMENT = 0,
  CONTROL = 1,
  DATA = 2,
};

/**
 * An enum for all managed management frame subtypes
 */
enum ManagementFrameSubtypes {
  ASSOCIATIONREQUEST = 0,
  ASSOCIATIONRESPONSE = 1,
  REASSOCIATIONREQUEST = 2,
  REASSOCIATIONRESPONSE = 3,
  PROBEREQUEST = 4,
  PROBERESPONSE = 5,
  BEACON = 8,
  ANNOUNCEMENTTRAFFICINDICATIONMAP = 9,
  DISASSOCIATION = 10,
  AUTHENTICATION = 11,
  DEAUTHENTICATION = 12,
  ACTION = 13,
};

/**
 * An enum for all managed control frame subtypes
 */
enum ControlFrameSubtypes {
  BLOCKACKREQUEST = 8,
  BLOCKACK = 9,
  PSPOLL = 10,
  READYTOSEND = 11,
  CLEARTOSEND = 12,
  ACK = 13,
  CFEND = 14,
  CFENDCFACK = 15
};

/**
 * An enum for all managed data frame subtypes
 */
enum DataFrameSubtypes {
  DATASUB = 0,
  DATACFACK = 1,
  DATACFPOLL = 2,
  DATACFACKCFPOLL = 3,
  NULLSUB = 4,
  CFACK = 5,
  CFPOLL = 6,
  CFACKCFPOLL = 7,
  QOSDATA = 8,
  QOSDATACFACK = 9,
  QOSDATACFPOLL = 10,
  QOSDATACFACKCFPOLL = 11,
  QOSNULL = 12,
  QOSCFPOLL = 14,
  QOSCFACKCFPOLL = 15
};

/**
 * @class MangementLayer
 * Represents a IEEE 802.11 management layer. Read about the possible
 * frame subtypes at:
 * https://en.wikipedia.org/wiki/IEEE_802.11#Management_frames
 */
class ManagementLayer : public pcpp::Layer {
public:
  /**
   * A constructor that creates the layer from an existing packet raw data
   * @param[in] rawData A pointer to the raw data (will be casted to @ref
   * radhdr). This rawdata is copied.
   * @param[in] rawDataLen Size of the data in bytes
   * @param[in] prevLayer A pointer to the previous layer
   * @param[in] packet A pointer to the Packet instance where layer will be
   * stored in
   */
  ManagementLayer(uint8_t *rawData, size_t rawDataLen, pcpp::Layer *prevLayer,
                  pcpp::Packet *packet)
      : Layer() {
    m_PrevLayer = prevLayer;
    m_Packet = packet;

    framectl frameCtl = ((machdr *)rawData)->frameControl;
    switch (frameCtl.type) {
    case MANAGEMENT:
    case CONTROL:
    case DATA:
    default:
      // TODO: Handle non-mandatory fields, subtype differences
      m_DataLen = sizeof(machdr);
      m_Data = new uint8_t[sizeof(machdr)];
      std::memcpy(m_Data, rawData, m_DataLen);
    }
  };

  /**
   * Get a pointer to the MAC header. Notice this points directly to the
   * data, so every change will change the actual packet data
   * @return A pointer to the @ref machdr
   */
  machdr *getMACHeader() const { return (machdr *)m_Data; }

  // implement abstract methods

  /**
   * Currently identifies the following next layers:
   * - TODO
   * Otherwise sets PayloadLayer (TODO)
   */
  void parseNextLayer() override{};

  /**
   * @return Size of the MAC header. This is dependant on the frame type/subtype
   * TODO
   */
  size_t getHeaderLen() const override { return sizeof(machdr); };

  /**
   * Calculate the following fields:
   * - TODO
   */
  void computeCalculateFields() override {}

  std::string toString() const override {
    std::string base("IEEE 802.11");

    switch (getMACHeader()->frameControl.type) {
    case MANAGEMENT:
      switch (getMACHeader()->frameControl.subtype) {
      case PROBEREQUEST:
        return base + " Probe request";
      case PROBERESPONSE:
        return base + " Probe response";
      case BEACON:
        return base + " Beacon frame";
      };
    case DATA:
      return base + " Data";
    case CONTROL:
      switch (getMACHeader()->frameControl.subtype) {
      case ACK:
        return base + " Acknowledgement";
      }
    default:
      return "IEEE 802.11 Unknown";
    }
  }

  pcpp::OsiModelLayer getOsiModelLayer() const override {
    return pcpp::OsiModelPhysicalLayer;
  }
};

#endif // SNIFFSNIFF_MANAGEMENTLAYER_H
