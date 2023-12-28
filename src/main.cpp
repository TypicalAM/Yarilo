#include <cstdint>
#include <iomanip>
#include <iostream>
#include <tins/dhcp.h>
#include <tins/ethernetII.h>
#include <tins/hw_address.h>
#include <tins/macros.h>
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
  TestingDecrypter() : test("00:0c:41:82:b2:55") {
    dec = Tins::Crypto::WEPDecrypter();
    dec.add_password(test, "Induction");
    Tins::FileSniffer sniffer("pcap/wpa_induction.pcap");
    sniffer.sniff_loop(
        Tins::make_sniffer_handler(this, &TestingDecrypter::callback));
  }

  bool callback(Tins::PDU &pkt) {
    count++;

    if (count != 99)
      return true;

    Tins::Dot11Data *dot11 = pkt.find_pdu<Tins::Dot11Data>();
    if (!dot11)
      return true;

    Tins::HWAddress<6> addr;
    if (!dot11->from_ds() && !dot11->to_ds()) {
      addr = dot11->addr3();
    } else if (!dot11->from_ds() && dot11->to_ds()) {
      addr = dot11->addr1();
    } else if (dot11->from_ds() && !dot11->to_ds()) {
      addr = dot11->addr2();
    } else {
      addr = dot11->addr3();
    }

    std::cout << count << " eq: " << test.to_string() << std::endl;

    bool decrypted = dec.decrypt(pkt);
    if (!decrypted) {
      std::cout << "Unable to decrypt packet " << count << std::endl;
      return false;
    }

    std::cout << "Decrypted packet: " << count << std::endl;
    Tins::SNAP *snap = pkt.find_pdu<Tins::SNAP>();
    if (!snap) {
      std::cout << "Decrypted packet but snap doesn't exist" << std::endl;
      return false;
    } else {
      std::cout << "SNAP Exists, cool" << std::endl;
      return true;
    }
  };

private:
  Tins::Crypto::WEPDecrypter dec;
  int count = 0;
  const Tins::HWAddress<6> test;
};

int main(int argc, char *argv[]) {
  std::cout << "Starting..." << std::endl;
  TestingDecrypter lol;
  return 0;
}
