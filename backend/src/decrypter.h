#ifndef SNIFF_DECRYPTER
#define SNIFF_DECRYPTER

#include <optional>
#include <set>
#include <spdlog/logger.h>
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

/**
 * @brief Decrypts unicast, multicast and broadcast WPA2 packets
 */
class WPA2Decrypter {
public:
  typedef std::vector<uint8_t> ptk_type;
  typedef std::vector<uint8_t> gtk_type;

  /**
   * @brief Represents a client window for tracking packet data within an
   * encryption window. This window is defined as the state between successful
   * 4-way handshakes between the supplicant (client) and the authenticator
   */
  struct client_window {
    Tins::Timestamp start;
    Tins::Timestamp end;
    bool ended = false;
    bool decrypted = false;
    uint16_t count = 0;
    MACAddress client;
    std::vector<Tins::Packet *> packets;
    std::vector<Tins::Packet *> auth_packets;
    ptk_type ptk;
  };

  /**
   * @brief Represents a group window for tracking multicast packet data. This
   * window is defined as the state between successful group key rotations
   */
  struct group_window {
    Tins::Timestamp start;
    Tins::Timestamp end;
    bool ended = false;
    bool decrypted = false;
    uint16_t count = 0;
    std::vector<Tins::Packet *> packets;
    std::vector<Tins::Packet *> auth_packets;
    gtk_type gtk;
  };

  /**
   * Constructor for WPA2Decrypter
   * @param[in] bssid The MAC address of the access point
   * @param[in] ssid The SSID of the network
   */
  WPA2Decrypter(const MACAddress &bssid, const SSID &ssid);

  /**
   * Decrypts the given packet
   * @param[in] pkt Pointer to the packet to decrypt
   * @return True if decryption was successful, false otherwise
   */
  bool decrypt(Tins::Packet *pkt);

  /**
   * Checks if the decrypter is ready to generate
   * @return True if a valid password has been provided OR a complete handshake
   * occured and the decrypter is ready for the password
   */
  bool can_generate_keys() const;

  /**
   * Adds a password for decryption
   * @param[in] psk The password (pre-shared key) to add
   */
  void add_password(const std::string psk);

  /**
   * Checks if a working password has been set
   * @return True if password which generated valid keys is available, false
   * otherwise
   */
  bool has_working_password() const;

  /**
   * Retrieves the current password if available
   * @return An optional containing the password if set, otherwise an empty
   * optional
   */
  std::optional<std::string> get_password() const;

  /**
   * Retrieves the set of clients connected to the network
   * @return A set of MAC addresses representing the clients
   */
  std::set<MACAddress> get_clients();

  /**
   * Retrieves the current client window for the specified client
   * @param[in] client The MAC address of the client
   * @return An optional containing the client window if found, otherwise an
   * empty optional
   */
  std::optional<client_window>
  get_current_client_window(const MACAddress &client);

  /**
   * Retrieves all client windows for the specified client
   * @param[in] client The MAC address of the client
   * @return An optional containing a vector of client windows if found,
   * otherwise an empty optional
   */
  std::optional<std::vector<client_window>>
  get_all_client_windows(const MACAddress &client);

  /**
   * Retrieves the current group window
   * @return The current group window
   */
  group_window get_current_group_window() const;

  /**
   * Retrieves all group windows
   * @return A vector of all group windows
   */
  std::vector<group_window> get_all_group_windows() const;

private:
  /**
   * Decrypts a unicast packet for a specific client
   * @param[in] pkt Pointer to the packet to decrypt
   * @param[in] client The MAC address of the client
   * @return True if decryption was successful, false otherwise
   */
  bool decrypt_unicast(Tins::Packet *pkt, const MACAddress &client);

  /**
   * Handles a pairwise EAPOL packet for a specific client
   * @param[in] pkt Pointer to the packet to handle
   * @param[in] client The MAC address of the client
   * @return True if handling was successful, false otherwise
   */
  bool handle_pairwise_eapol(Tins::Packet *pkt, const MACAddress &client);

  /**
   * Handles a group EAPOL packet for a specific client
   * @param[in] pkt Pointer to the packet to handle
   * @param[in] client The MAC address of the client
   * @return True if handling was successful, false otherwise
   */
  bool handle_group_eapol(Tins::Packet *pkt, const MACAddress &client);

  /**
   * Attempts to generate keys for a client window based on the avilable
   * data. Decrypts retrospective pairwise data if necessary and handles group
   * rekeying
   * @param[in] window Reference to the client window to update with generated
   * keys
   */
  void try_generate_keys(client_window &window);

  /**
   * Decrypts a group packet (encrypted with GTK)
   * @param[in] pkt Pointer to the packet to decrypt
   * @return True if decryption was successful, false otherwise
   */
  bool decrypt_group(Tins::Packet *pkt);

  /**
   * Attempts to insert a GTK into the available group windows, alligning them
   * if necessary
   * @param[in] gtk The GTK to insert
   * @param[in] ts The timestamp associated with the GTK
   */
  void try_insert_gtk(const gtk_type &gtk, const Tins::Timestamp &ts);

  /**
   * Decrypts raw group data for a specific window
   * @param[in] data The data frame to decrypt
   * @param[in] raw The raw PDU
   * @param[in] gtk The GTK to use for decryption
   * @return Pointer to the decrypted SNAP frame
   */
  Tins::SNAP *decrypt_group_data(const Tins::Dot11Data &data, Tins::RawPDU &raw,
                                 const gtk_type &gtk);

  /**
   * Exctracts key data from an EAPOL handshake packet
   * @param[in] eapol The 3rd pairwise or 1st group EAPOL packet containing the
   * key data
   * @param[in] ptk The PTK to use for decryption
   * @return An optional containing the decrypted GTK if successful, otherwise
   * an empty optional
   */
  std::optional<gtk_type> exctract_key_data(const Tins::RSNEAPOL &eapol,
                                            const ptk_type &ptk);

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

  std::shared_ptr<spdlog::logger> logger;
  std::map<MACAddress, Tins::Packet *> group_rekey_first_messages;
  std::map<MACAddress, std::vector<Tins::Packet *>> client_handshakes;
  const SSID ssid;
  const MACAddress bssid;
  std::string psk = "";
  bool working_psk = false;
  std::map<MACAddress, std::vector<client_window>> client_windows;
  std::vector<group_window> group_windows;
  Tins::Crypto::WPA2Decrypter unicast_decrypter;
};

} // namespace yarilo

#endif // SNIFF_DECRYPTER
