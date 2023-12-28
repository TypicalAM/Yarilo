#include <cstdint>
#include <iomanip>
#include <iostream>
#include <tins/dhcp.h>
#include <tins/ethernetII.h>
#include <tins/hw_address.h>
#include <tins/macros.h>
#include <tins/pdu.h>
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
  TestingDecrypter() {
    const Tins::HWAddress<6> bssid("00:0c:41:82:b2:55");
    const std::string passwd("Induction");
    Tins::Crypto::WEPDecrypter decrypter;
    dec.add_password(bssid, passwd);

    Tins::FileSniffer sniffer("pcap/wpa_induction.pcap");
    sniffer.sniff_loop(
        Tins::make_sniffer_handler(this, &TestingDecrypter::callback));
  }

  bool callback(Tins::PDU &pkt) {
    count++;
    std::vector<uint8_t> buffer = pkt.serialize();
    std::cout << "This is packet: " << count << " with encrypted size "
              << buffer.size() << std::endl;
    printHex(buffer.data(), buffer.size());
    dec.decrypt(pkt);
    Tins::Dot11Data *data = pkt.find_pdu<Tins::Dot11Data>();
    if (!data)
      return true;

    std::vector<uint8_t> bufferDec = pkt.serialize();
    if (count != 209)
      return true;

    std::cout << "This is packet: " << count << " with unencrypted size "
              << bufferDec.size() << std::endl;
    printHex(bufferDec.data(), bufferDec.size());
    return false;
  };

private:
  Tins::Crypto::WEPDecrypter dec;
  int count = 0;
};

int main(int argc, char *argv[]) {
  std::cout << "Starting..." << std::endl;
  TestingDecrypter lol;
  return 0;
}
