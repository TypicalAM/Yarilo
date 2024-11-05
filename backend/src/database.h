#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>
#include <string>
#include <vector>

#include "uuid.h"

class Database {
public:
    explicit Database(const std::string &db_name);
    ~Database();

    bool initialize();
    bool execute_query(const std::string &query);
    std::vector<std::vector<std::string>> select_query(const std::string &query);
    bool insert_recording(const std::string &uuid, const std::string &display_name, const std::string &file_path, int64_t start, int64_t end);
    std::vector<std::vector<std::string>> get_recordings();
    std::vector<std::string> get_recording(const std::string &uuid);
    bool recording_exists(const std::string &uuid, const std::string &file_path);
    bool insert_vendor(const std::string &oid, const std::string &name);
    std::vector<std::vector<std::string>> get_vendors();
    bool insert_network(const std::string &ssid, const std::string &bssid, const std::string &psk, uint32_t total_packet_count, uint32_t decrypted_packet_count, uint32_t group_packet_count, const std::string &security, std::string recording_id, uint32_t group_rekeys, const std::string &vendor_oid);
    std::vector<std::vector<std::string>> get_networks();
    bool insert_group_window(const std::string& network_id, uint64_t start, uint64_t end, uint32_t packet_count);
    std::vector<std::vector<std::string>> get_group_windows();
    bool insert_client(const std::string &address, uint32_t packet_count, uint32_t decrypted_packet_count, const std::string &network_id);
    std::vector<std::vector<std::string>> get_clients();
    bool insert_client_window(const std::string &client_address, const std::string &network_id, uint64_t start, uint64_t end, uint32_t packet_count);
    std::vector<std::vector<std::string>> get_client_windows();

private:
    sqlite3 *db;
    std::string db_name;
};

#endif // DATABASE_H