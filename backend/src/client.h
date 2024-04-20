#ifndef SNIFF_CLIENT
#define SNIFF_CLIENT

#include <memory>
#include <optional>
#include <queue>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <tins/crypto.h>
#include <tins/dot11.h>
#include <tins/eapol.h>
#include <tins/ethernetII.h>
#include <tins/hw_address.h>
#include <tins/snap.h>

namespace yarilo {

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
  Tins::HWAddress<6> get_addr();
  int get_key_num();

private:
  std::shared_ptr<spdlog::logger> logger;
  Tins::HWAddress<6> bssid;
  SSID ssid;
  Tins::HWAddress<6> addr;
  data_queue auth_data;
  bool decrypted = false;

  static int deduce_handshake_num(Tins::RSNEAPOL &rsn);
};

} // namespace yarilo

#endif // SNIFF_CLIENT
