#include <iostream>
#include <ostream>
#include <queue>
#include <tins/dhcp.h>
#include <tins/eapol.h>
#include <tins/ethernetII.h>
#include <tins/hw_address.h>
#include <tins/ip.h>
#include <tins/macros.h>
#include <tins/packet_writer.h>
#include <tins/pdu.h>
#include <tins/rawpdu.h>
#include <tins/snap.h>
#include <tins/sniffer.h>
#include <tins/tins.h>
#include <unordered_set>

class LiveDecrypter {
public:
  LiveDecrypter(Tins::BaseSniffer *sniffer) {
    this->sniffer = sniffer;
    decrypter.handshake_captured_callback([](const std::string &hello,
                                             const Tins::HWAddress<6> &hw,
                                             const Tins::HWAddress<6> &hw2) {
      std::cout << "Handshake captured for network: " << hello << std::endl;
    });

    decrypter.ap_found_callback(
        [](const std::string &hello, const Tins::HWAddress<6> &hw) {
          std::cout << "AP found: " << hello << std::endl;
        });
  }

  void run() {
    sniffer->sniff_loop(
        Tins::make_sniffer_handler(this, &LiveDecrypter::callback));
  }

  std::unordered_set<std::string> get_detected_networks() {
    return detected_networks;
  }

  bool add_password(const std::string &ssid, const std::string &passwd) {
    decrypter.add_ap_data(passwd, ssid);

    // Decrypt the waiting queue? i guess
    while (!bc_que.empty()) {
      decrypter.decrypt(*std::move(bc_que.front()));
      bc_que.pop();
    }

    while (!auth_queue.empty()) {
      decrypter.decrypt(*std::move(auth_queue.front()));
      auth_queue.pop();
    }

    std::cout << "Using keys: " << std::endl;
    for (const auto &pair : decrypter.get_keys())
      std::cout << "Pair: " << pair.first.first << pair.first.second
                << std::endl;

    while (!raw_data_queue.empty()) {
      auto pkt = *std::move(raw_data_queue.front());
      bool decrypted = decrypter.decrypt(pkt);

      if (!decrypted) {
        raw_data_queue.pop();
        continue;
      }

      auto dot11 = pkt.rfind_pdu<Tins::Dot11Data>();
      auto snap = pkt.rfind_pdu<Tins::SNAP>();
      auto converted = make_eth_packet(dot11);
      converted.inner_pdu(snap.release_inner_pdu());
      processed_queue.push(converted.clone());
      raw_data_queue.pop();
    }

    return true;
  };

  std::queue<Tins::EthernetII *> get_processed() { return processed_queue; };

private:
  std::unordered_set<std::string> detected_networks;
  std::queue<Tins::Dot11Data *> auth_queue;
  std::queue<Tins::Dot11Beacon *> bc_que;
  std::queue<Tins::Dot11Data *> raw_data_queue;
  std::queue<Tins::EthernetII *> processed_queue;

  Tins::BaseSniffer *sniffer;
  Tins::Crypto::WPA2Decrypter decrypter;
  int raw_count = 0;

  bool callback(Tins::PDU &pkt) {
    raw_count++;
    Tins::Dot11Data *dot11 = pkt.find_pdu<Tins::Dot11Data>();
    if (raw_count == 500)
      return false;

    if (!dot11) {
      // If this isn't a data packet to be decrypted, we can at least look for
      // the network SSID
      Tins::Dot11Beacon *beacon = pkt.find_pdu<Tins::Dot11Beacon>();
      if (beacon) {
        detected_networks.insert(beacon->ssid());
        bc_que.push(beacon->clone());
      }

      return true;
    }

    // If the traffic is not decrypted yet we will get rawdata, otherwise
    // probably some auth packets
    if (dot11->find_pdu<Tins::RSNEAPOL>()) {
      auth_queue.push(dot11->clone());
      std::cout << "Captured a handshake!" << std::endl;
      return true;
    }

    // Let's actually ensure it's rawdata cuz idk
    if (dot11->find_pdu<Tins::RawPDU>())
      raw_data_queue.push(dot11->clone());

    return true;
  };

  static Tins::EthernetII make_eth_packet(Tins::Dot11Data &dot11) {
    if (dot11.from_ds() && !dot11.to_ds()) {
      return Tins::EthernetII(dot11.addr1(), dot11.addr3());
    } else if (!dot11.from_ds() && dot11.to_ds()) {
      return Tins::EthernetII(dot11.addr3(), dot11.addr2());
    } else {
      return Tins::EthernetII(dot11.addr1(), dot11.addr2());
    }
  }
};
