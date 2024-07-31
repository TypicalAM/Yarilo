#ifndef SNIFF_DECRYPTER
#define SNIFF_DECRYPTER

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
  bool decrypted = false;
  uint16_t count = 0;
  MACAddress client;
  std::vector<Tins::Packet *> packets;
  std::vector<Tins::Packet *> auth_packets;
  std::vector<uint8_t> ptk;
};

struct group_window {
  Tins::Timestamp start;
  Tins::Timestamp end;
  bool ended = false;
  bool decrypted = false;
  uint16_t count = 0;
  std::vector<Tins::Packet *> packets;
  std::vector<Tins::Packet *> auth_packets;
  std::vector<uint8_t> gtk;
};

// Decrypts both unicast and multicast traffic
class WPA2Decrypter {
public:
  WPA2Decrypter(const MACAddress &bssid, const SSID &ssid);

  // Decryption
  bool decrypt(Tins::Packet *pkt);

  // Password related
  bool can_decrypt() const;
  bool add_password(const std::string psk);
  bool has_working_password() const;
  std::optional<std::string> get_password() const;

  // Clients
  std::set<MACAddress> get_clients();

  // Windows
  std::optional<client_window>
  get_current_client_window(const MACAddress &client);
  std::optional<std::vector<client_window>>
  get_all_client_windows(const MACAddress &client);
  group_window get_current_group_window() const;
  std::vector<group_window> get_all_group_windows() const;

private:
  bool decrypt_unicast(Tins::Packet *pkt, const MACAddress &client);
  bool decrypt_group(Tins::Packet *pkt);
  bool client_hs_sequence_correct(const client_window &window,
                                  Tins::Packet *pkt) const;
  bool group_hs_sequence_correct(const group_window &window,
                                 Tins::Packet *pkt) const;
  bool try_generate_keys(const MACAddress &client);
  Tins::SNAP *decrypt_group_data(const Tins::Dot11Data &data, Tins::RawPDU &raw,
                                 const std::vector<uint8_t> &gtk);
  std::optional<std::vector<uint8_t>>
  decrypt_key_data(const Tins::RSNEAPOL &eapol,
                   const std::vector<uint8_t> &ptk);

  /**
   * Deduce the handshake number from a pairwise handhshake packet
   * @param[in] rsn A reference to the EAPOL handshake packet
   * @return Auth packet number between 1-4
   */
  static std::optional<uint8_t>
  eapol_pairwise_hs_num(const Tins::RSNEAPOL &eapol);

  /**
   * Deduce the handshake number from a group handhshake packet
   * @param[in] rsn A reference to the EAPOL handshake packet
   * @return Auth packet number between 1-4
   */
  static std::optional<uint8_t> eapol_group_hs_num(const Tins::RSNEAPOL &eapol);

  const SSID ssid;
  const Tins::HWAddress<6> bssid;
  std::string psk = "";
  bool working_psk = false;
  std::map<MACAddress, std::vector<client_window>> client_windows;
  std::vector<group_window> group_windows;
  Tins::Crypto::WPA2Decrypter unicast_decrypter;
};

} // namespace yarilo

#endif // SNIFF_DECRYPTER
