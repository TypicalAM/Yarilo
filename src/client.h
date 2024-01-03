#ifndef SNIFF_CLIENT
#define SNIFF_CLIENT

#include "channel.h"
#include <optional>
#include <queue>
#include <tins/crypto.h>
#include <tins/dot11.h>
#include <tins/eapol.h>
#include <tins/ethernetII.h>
#include <tins/hw_address.h>
#include <tins/snap.h>

typedef std::queue<Tins::Dot11Data *> data_queue;
typedef std::string SSID;

class Client {
public:
  Client(const Tins::HWAddress<6> &bssid, const SSID &ssid,
         const Tins::HWAddress<6> &addr);

  void add_handshake(const Tins::Dot11Data &dot11);
  bool can_decrypt();
  bool is_decrypted();
  std::optional<Tins::Crypto::WPA2Decrypter::keys_map>
  try_decrypt(const std::string &psk);

private:
  Tins::HWAddress<6> bssid;
  SSID ssid;
  Tins::HWAddress<6> addr;
  data_queue auth_data;

  bool decrypted = false;
  static int deduce_handshake_num(Tins::RSNEAPOL &rsn);
};

#endif // SNIFF_CLIENT
