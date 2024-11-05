#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>
#include <string>
#include <vector>

class Database {
public:
    explicit Database(const std::string &db_name);
    ~Database();

    bool initialize();
    bool execute_query(const std::string &query);
    std::vector<std::vector<std::string>> select_query(const std::string &query);
    bool insert_recording(const std::string &display_name, const std::string &file_path, int64_t start, int64_t end);
    std::vector<std::vector<std::string>> get_recordings();
    bool insert_vendor(const std::string &oid, const std::string &name, const std::string &address);
    std::vector<std::vector<std::string>> get_vendors();
    bool insert_network(const std::string &ssid, const std::string &bssid, const std::string &psk, int total_packet_count, int decrypted_packet_count, int group_packet_count, const std::string &security, int recording_id, int group_rekeys, const std::string &vendor_oid);
    std::vector<std::vector<std::string>> get_networks();

private:
    sqlite3 *db;
    std::string db_name;
};

#endif // DATABASE_H