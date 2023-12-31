#include <iostream>
#include <optional>
#include <queue>
#include <tins/tins.h>
#include <unordered_map>
#include <vector>

typedef std::string SSID;
typedef std::queue<Tins::Dot11Data *> data_queue;
typedef std::queue<Tins::EthernetII *> eth_queue;
typedef std::queue<Tins::Dot11Beacon *> beacon_queue;

class LiveDecrypter {
public:
  LiveDecrypter(Tins::BaseSniffer *sniffer) {
    this->sniffer = sniffer;

    auto handshake_callback = std::bind(
        &LiveDecrypter::handshake_captured_callback, this,
        std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
    decrypter.handshake_captured_callback(handshake_callback);

    auto ap_callback = std::bind(&LiveDecrypter::ap_found_callback, this,
                                 std::placeholders::_1, std::placeholders::_2);
    decrypter.ap_found_callback(ap_callback);
  }

  void run() {
    sniffer->sniff_loop(
        std::bind(&LiveDecrypter::sniff_callback, this, std::placeholders::_1));
  }

  std::vector<SSID> get_detected_networks() {
    std::vector<SSID> res;
    for (const auto &net : is_decrypted)
      res.push_back(net.first);
    return res;
  }

  bool can_add_password(SSID ssid) {
    if (beacons.find(ssid) == beacons.end() || beacons[ssid].empty())
      return false;

    if (handshakes.find(ssid) == handshakes.end() ||
        handshakes[ssid].size() != 4)
      return false;

    return true; // The decrypter can deduce the network from a beacon and
                 // analyze the 4-way EAPOl handshake
  }

  bool add_password(SSID ssid, const std::string &passwd) {
    if (!can_add_password(ssid)) // lol
      return false;

    decrypter.add_ap_data(passwd, ssid);
    is_decrypted[ssid] = true;

    // Decrypt the beacon queue? i guess
    while (!beacons[ssid].empty()) {
      decrypter.decrypt(*std::move(beacons[ssid].front()));
      beacons[ssid].pop();
    }
    beacons.erase(ssid); // No need for the beacon packets anymore

    while (!handshakes[ssid].empty()) {
      decrypter.decrypt(*std::move(handshakes[ssid].front()));
      handshakes[ssid].pop();
    }
    handshakes.erase(ssid); // No need for the handshake packets anymore

    // TODO: Make sure new keys are genereated
    std::cout << "Using keys: " << std::endl;
    for (const auto &pair : decrypter.get_keys())
      std::cout << "Pair between " << pair.first.first << " and "
                << pair.first.second << std::endl;

    // Convert all the old packets lol
    while (!raw_data_pkts[ssid].empty()) {
      auto pkt = *std::move(raw_data_pkts[ssid].front());
      bool decrypted = decrypter.decrypt(pkt);

      if (!decrypted) {
        raw_data_pkts[ssid].pop();
        continue;
      }

      auto dot11 = pkt.rfind_pdu<Tins::Dot11Data>();
      auto snap = pkt.rfind_pdu<Tins::SNAP>();
      auto converted = make_eth_packet(dot11);
      converted.inner_pdu(snap.release_inner_pdu());
      converted_pkts[ssid].push(converted.clone());
      raw_data_pkts[ssid].pop();
    }

    return true;
  };

  std::optional<eth_queue> get_converted(SSID ssid) {
    if (is_decrypted.find(ssid) == is_decrypted.end() || !is_decrypted[ssid])
      return std::nullopt;

    return converted_pkts[ssid];
  };

private:
  std::unordered_map<SSID, Tins::HWAddress<6>>
      ap_bssid; // TODO: Multiple bssids can be the same ssid (fuck)
  std::unordered_map<SSID, bool> is_decrypted;
  std::unordered_map<SSID, data_queue> handshakes;
  std::unordered_map<SSID, beacon_queue> beacons;
  std::unordered_map<SSID, data_queue> raw_data_pkts;
  std::unordered_map<SSID, eth_queue> converted_pkts;

  Tins::BaseSniffer *sniffer;
  Tins::Crypto::WPA2Decrypter decrypter;
  int raw_count = 0;

  void ap_found_callback(const std::string &ssid,
                         const Tins::HWAddress<6> &addr) {
    std::cout << "Decrypter discovered AP: " << ssid << " with BSSID: " << addr
              << std::endl;
  }

  void handshake_captured_callback(const std::string &ssid,
                                   const Tins::HWAddress<6> &hw,
                                   const Tins::HWAddress<6> &hw2) {
    std::cout << "Decrypter caught full WPA2 handshake on AP: " << ssid
              << " between " << hw << " and " << hw2
              << ". You can now start decrypting the traffic" << std::endl;
  }

  bool sniff_callback(Tins::PDU &pkt) {
    raw_count++;
    if (raw_count == 500)
      return false;

    if (pkt.find_pdu<Tins::Dot11Data>())
      return handle_dot11(pkt);

    if (pkt.find_pdu<Tins::Dot11Beacon>())
      return handle_beacon(pkt);

    return true;
  };

  bool handle_dot11(Tins::PDU &pkt) {
    auto dot11 = pkt.rfind_pdu<Tins::Dot11Data>();
    auto ssid = get_ssid(dot11);
    if (!ssid.has_value()) {
      std::cout << "Found a SNA <-> Non-SNA packet at: " << raw_count
                << std::endl;
      return true; // TODO: This is an orphan packet, we should handle that
                   // somehow?;
    }

    if (dot11.find_pdu<Tins::RSNEAPOL>()) {
      // This is an EAPOL handshake packet
      handshakes[ssid.value()].push(dot11.clone());
      std::cout << "Captured key: " << handshakes[ssid.value()].size()
                << " of 4 for ssid " << ssid.value() << std::endl;
      return true;
    }

    // Now we should have a RAWPDU. Let's actually make sure cuz idk
    if (!dot11.find_pdu<Tins::RawPDU>()) {
      return true;
    }

    // If we don't yet have the password, pass it on
    if (!is_decrypted[ssid.value()] || !decrypter.decrypt(pkt)) {
      raw_data_pkts[ssid.value()].push(dot11.clone());
      return true;
    }

    // Decrypted!
    auto snap = pkt.rfind_pdu<Tins::SNAP>();
    auto converted = make_eth_packet(dot11);
    converted.inner_pdu(snap.release_inner_pdu());
    converted_pkts[ssid.value()].push(converted.clone());
    return true;
  }

  bool handle_beacon(Tins::PDU &pkt) {
    // Check if we actually detected this network before?
    auto beacon = pkt.rfind_pdu<Tins::Dot11Beacon>();
    if (is_decrypted[beacon.ssid()])
      return true; // If it's already decrypted we don't need to do anything

    if (!beacons[beacon.ssid()].empty())
      return true; // If we already have some beacon packets, it's cool

    ap_bssid[beacon.ssid()] =
        beacon.addr3(); // TODO: Does TO/FROM DS matter here? Probably
    beacons[beacon.ssid()].push(beacon.clone());
    return true;
  }

  std::optional<SSID> get_ssid(Tins::Dot11Data &dot11) {
    Tins::HWAddress<6> from;
    Tins::HWAddress<6> to;

    if (dot11.from_ds() && !dot11.to_ds()) {
      from = dot11.addr1();
      to = dot11.addr3();
    } else if (!dot11.from_ds() && dot11.to_ds()) {
      from = dot11.addr3();
      to = dot11.addr2();
    } else {
      from = dot11.addr1();
      to = dot11.addr2();
    };

    for (const auto &pair : ap_bssid)
      if (dot11.bssid_addr() == pair.second || from == pair.second ||
          to == pair.second)
        return pair.first;

    return std::nullopt;
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
