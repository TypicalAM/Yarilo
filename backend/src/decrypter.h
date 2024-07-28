#ifndef SNIFF_DECRYPTER
#define SNIFF_DECRYPTER

#include "group_decrypter.h"
#include <optional>
#include <set>
#include <tins/crypto.h>
#include <tins/eapol.h>
#include <tins/hw_address.h>
#include <tins/packet.h>
#include <tins/pdu.h>
#include <tins/snap.h>
#include <tins/timestamp.h>
#include <vector>

namespace yarilo {

typedef std::string SSID;
typedef Tins::HWAddress<6> MACAddress;

struct client_window {
  Tins::Timestamp start;
  Tins::Timestamp end;
  bool ended = false;
  uint16_t count = 0;
  MACAddress client;
  std::vector<Tins::Packet *> packets;
  std::vector<uint8_t> ptk;
};

struct group_window {
  Tins::Timestamp start;
  Tins::Timestamp end;
  bool ended = false;
  uint16_t count = 0;
  std::vector<Tins::Packet *> packets;
  std::vector<uint8_t> gtk;
};

// Decrypts both unicast and multicast traffic
class WPA2Decrypter {
public:
  WPA2Decrypter(const MACAddress &bssid, const SSID &ssid);

  // Decryption
  bool decrypt(Tins::PDU &pdu);

  // Password related
  bool can_decrypt() const;
  bool add_password(const std::string psk);
  bool has_working_password() const;
  std::optional<std::string> get_password() const;

  // Clients
  std::set<MACAddress> get_clients();

  // Windows
  std::optional<client_window>
  get_current_client_window(const MACAddress &client) const;
  std::optional<std::vector<client_window>>
  get_all_client_windows(const MACAddress &client) const;
  group_window get_current_group_window() const;
  std::vector<group_window> get_all_group_windows() const;

private:
  /**
   * Deduce the handshake number from a pairwise handhshake packet
   * @param[in] rsn A reference to the EAPOL handshake packet
   * @return Auth packet number between 1-4
   */
  static int eapol_pairwise_hs_num(const Tins::RSNEAPOL &eapol);

  /**
   * Deduce the handshake number from a group handhshake packet
   * @param[in] rsn A reference to the EAPOL handshake packet
   * @return Auth packet number between 1-4
   */
  static int eapol_group_hs_num(const Tins::RSNEAPOL &eapol);

  const SSID ssid;
  const Tins::HWAddress<6> bssid;
  std::string psk = "";
  bool working_psk = false;
  WPA2GroupDecrypter group_decrypter;
  std::map<MACAddress, std::vector<client_window>> client_windows;
  std::vector<client_window> group_windows;
  Tins::Crypto::WPA2Decrypter unicast_decrypter;
};

} // namespace yarilo

#endif // SNIFF_DECRYPTER
