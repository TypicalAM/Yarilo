#include <cstdint>
#include <iomanip>
#include <iostream>
#include <tins/dhcp.h>
#include <tins/ethernetII.h>
#include <tins/hw_address.h>
#include <tins/macros.h>
#include <tins/packet_writer.h>
#include <tins/pdu.h>
#include <tins/snap.h>
#include <tins/sniffer.h>
#include <tins/tins.h>

void printHex(uint8_t *data, int i) {
  for (int j = 1; j < i + 1; ++j) {
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(data[j - 1]) << std::dec;
    std::cout << " ";
    if (j % 8 == 0 && j != 0) {
      std::cout << "  ";
    }
    if (j % 16 == 0 && j != 0) {
      std::cout << std::endl;
    }
  }
  std::cout << std::endl;
}

Tins::EthernetII make_eth_packet(Tins::Dot11Data &dot11) {
  if (dot11.from_ds() && !dot11.to_ds()) {
    return Tins::EthernetII(dot11.addr1(), dot11.addr3());
  } else if (!dot11.from_ds() && dot11.to_ds()) {
    return Tins::EthernetII(dot11.addr3(), dot11.addr2());
  } else {
    return Tins::EthernetII(dot11.addr1(), dot11.addr2());
  }
}

class TestingDecrypter {
public:
  TestingDecrypter()
      : test("00:0c:41:82:b2:55"),
        writer("/tmp/test.pcap", Tins::DataLinkType<Tins::EthernetII>()) {
    dec = Tins::Crypto::WEPDecrypter();
    dec.add_password(test, "");
    dec2 = Tins::Crypto::WPA2Decrypter();
    dec2.add_ap_data("Induction", "Coherer");
    dec2.handshake_captured_callback([](const std::string &hello,
                                        const Tins::HWAddress<6> &hw,
                                        const Tins::HWAddress<6> &hw2) {
      std::cout << "Handshake captured" << std::endl;
    });

    Tins::FileSniffer sniffer("pcap/wpa_induction.pcap");
    sniffer.sniff_loop(
        Tins::make_sniffer_handler(this, &TestingDecrypter::callback));
  }

  bool callback(Tins::PDU &pkt) {
    count++;

    bool decrypted = dec2.decrypt(pkt);
    Tins::Dot11Data *dot11 = pkt.find_pdu<Tins::Dot11Data>();
    if (!dot11) {
      return true;
    }

    if (!decrypted) {
      // std::cout << "Found a non-decypted data frame: FUCK" << std::endl;
      return true;
    }

    Tins::SNAP *snap = pkt.find_pdu<Tins::SNAP>();
    if (!snap) {
      std::cout << "Decrypted packet but snap doesn't exist" << std::endl;
      return false;
    }

    auto converted = make_eth_packet(*dot11);
    converted.inner_pdu(snap->release_inner_pdu());
    writer.write(converted);
    std::cout << "PACKET #" << count
              << " DECRYPTED, SNAP DETECTED, CONVERTED TO ETHSTREAM "
              << deccount << std::endl;
    deccount++;
    return true;
  };

private:
  Tins::Crypto::WEPDecrypter dec;
  Tins::Crypto::WPA2Decrypter dec2;
  int count = 0;
  int deccount = 0;
  const Tins::HWAddress<6> test;
  Tins::PacketWriter writer;
};

int main(int argc, char *argv[]) {
  std::cout << "Starting..." << std::endl;
  TestingDecrypter lol;
  return 0;
}
