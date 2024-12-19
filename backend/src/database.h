#ifndef DATABASE_H
#define DATABASE_H

#include <spdlog/logger.h>
#include <sqlite3.h>
#include <string>
#include <vector>

#include "uuid.h"

class Database {
public:
  explicit Database(const std::string &db_path);
  ~Database();

  bool initialize();
  bool execute_query(const std::string &query);
  std::vector<std::vector<std::string>> select_query(const std::string &query);
  bool check_vendors(bool seeding = false);
  bool insert_recording(const std::string &uuid,
                        const std::string &display_name,
                        const std::string &file_path, int64_t start,
                        int64_t end);
  std::vector<std::vector<std::string>> get_recordings();
  std::vector<std::string> get_recording(const std::string &uuid);
  bool delete_recording(const std::string &uuid) const;
  bool recording_exists_in_db(const std::string &uuid,
                              const std::string &file_path);
  bool recording_exists_in_db(const std::string &file_path);
  bool load_vendors(const std::string &OID_path);
  bool insert_vendors(
      const std::vector<std::pair<std::string, std::string>> &vendors);
  std::vector<std::vector<std::string>> get_vendors();
  std::string get_vendor_name(const std::string &oid);
  bool vendor_exists(const std::string &oid);
  bool insert_network(const std::string &ssid, const std::string &bssid,
                      const std::string &psk, uint32_t total_packet_count,
                      uint32_t decrypted_packet_count,
                      uint32_t group_packet_count, const std::string &security,
                      std::string recording_id, uint32_t group_rekeys,
                      const std::string &vendor_oid);
  std::vector<std::vector<std::string>> get_networks();
  bool insert_group_window(const std::string &network_id, uint64_t start,
                           uint64_t end, uint32_t packet_count);
  std::vector<std::vector<std::string>> get_group_windows();
  bool insert_client(const std::string &address, uint32_t packet_count,
                     uint32_t decrypted_packet_count,
                     const std::string &network_id);
  std::vector<std::vector<std::string>> get_clients();
  bool insert_client_window(const std::string &client_address,
                            const std::string &network_id, uint64_t start,
                            uint64_t end, uint32_t packet_count);
  std::vector<std::vector<std::string>> get_client_windows();
  bool refresh_database();

private:
  sqlite3 *db;
  std::shared_ptr<spdlog::logger> logger;
  std::string db_path;
  const std::string schema = R"(
CREATE TABLE IF NOT EXISTS Vendors (
    oid TEXT PRIMARY KEY,          -- MAC address prefix (first 3 bytes)
    name TEXT                      -- Vendor name
);

CREATE TABLE IF NOT EXISTS Recordings (
    id TEXT PRIMARY KEY,
    display_name TEXT,
    file_path TEXT,
    start INTEGER,                 -- Start time (TODO)
    end INTEGER                    -- End time (TODO)
);

CREATE TABLE IF NOT EXISTS Networks (
    ssid TEXT,
    bssid TEXT PRIMARY KEY,
    psk TEXT,
    total_packet_count INTEGER,
    decrypted_packet_count INTEGER,
    group_packet_count INTEGER,
    security TEXT,                 -- Numbers separated by space (ex. "3 4")
    recording_id TEXT,
    group_rekeys INTEGER,          -- (TODO)
    vendor_oid TEXT,
    FOREIGN KEY (vendor_oid) REFERENCES Vendors(oid),
    FOREIGN KEY (recording_id) REFERENCES Recordings(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS GroupDecryptionWindow (
    network_bssid TEXT,
    start INTEGER,
    end INTEGER,
    packet_count INTEGER,
    FOREIGN KEY (network_bssid) REFERENCES Networks(bssid) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS Clients (
    address TEXT PRIMARY KEY,
    packet_count INTEGER,
    decrypted_packet_count INTEGER, -- Not sure if this is collected
    network_bssid TEXT,
    FOREIGN KEY (network_bssid) REFERENCES Networks(bssid) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ClientDecryptionWindow (
    client_address TEXT,
    network_bssid TEXT,
    start INTEGER,
    end INTEGER,
    packet_count INTEGER,
    FOREIGN KEY (client_address) REFERENCES Clients(address) ON DELETE CASCADE,
    FOREIGN KEY (network_bssid) REFERENCES Networks(bssid) ON DELETE CASCADE
);
)";
};

#endif // DATABASE_H