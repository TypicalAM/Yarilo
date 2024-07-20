#ifndef SNIFF_GROUP_DECRYPTER
#define SNIFF_GROUP_DECRYPTER

#include <tins/crypto.h>
#include <tins/eapol.h>
#include <tins/snap.h>

namespace yarilo {

class WPA2GroupDecrypter {
public:
  const int RSN_GTK_TAG = 221;
  const int GTK_SIZE = 16;

  typedef std::vector<uint8_t> gtk_type;

  WPA2GroupDecrypter();
  bool decrypt(Tins::PDU &pdu);
  Tins::SNAP *ccmp_decrypt_group(const Tins::Dot11Data &dot11,
                                 Tins::RawPDU &raw) const;
  bool ccmp_decrypt_key_data(const Tins::RSNEAPOL &eapol,
                             std::vector<uint8_t> kek);
  void add_gtk(const gtk_type &gtk) { gtk_ = gtk; };
  gtk_type gtk() const { return gtk_; };

private:
  gtk_type gtk_;
};

} // namespace yarilo

#endif // SNIFF_GROUP_DECRYPTER
