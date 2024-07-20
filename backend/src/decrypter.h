#ifndef SNIFF_DECRYPTER
#define SNIFF_DECRYPTER

#include "group_decrypter.h"
#include <array>
#include <tins/crypto.h>
#include <tins/eapol.h>
#include <tins/hw_address.h>
#include <tins/pdu.h>
#include <tins/snap.h>

namespace yarilo {

typedef std::string SSID;

// Decrypts both unicast and multicast traffic
class WPA2Decrypter {
public:
  typedef Tins::Crypto::WPA2Decrypter::addr_pair unicast_addr_pair;
  typedef Tins::Crypto::WPA2::SessionKeys unicast_session_keys;
  typedef std::map<unicast_addr_pair, unicast_session_keys> unicast_keys_map;
  typedef WPA2GroupDecrypter::gtk_type gtk_type;

  WPA2Decrypter(){};

  bool decrypt(Tins::PDU &pdu);
  void add_key_msg(int num, const Tins::PDU &pdu);
  int key_msg_count() const; // TODO, multiple sessions
  void add_ap_data(const std::string &psk, SSID ssid, Tins::HWAddress<6> bssid);
  void add_group_key(const gtk_type &key);
  gtk_type group_key() const;
  void add_unicast_keys(const unicast_addr_pair &addresses,
                        const unicast_session_keys &session_keys);
  unicast_keys_map unicast_keys() const;

  /**
   * Deduce the handshake number from a packet
   * @param[in] rsn A reference to the EAPOL handshake packet
   * @return Auth packet number between 1-4
   */
  static int eapol_handshake_num(const Tins::RSNEAPOL &eapol);

private:
  std::array<Tins::PDU *, 4> handshakes; // TODO: Maybe use RSNHandshakeCapturer
  SSID ssid = "";
  Tins::HWAddress<6> bssid;
  std::string psk = "";
  bool working_psk = false;

  WPA2GroupDecrypter group_decrypter;
  Tins::Crypto::WPA2Decrypter unicast_decrypter;
};

} // namespace yarilo

#endif // SNIFF_DECRYPTER
