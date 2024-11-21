#include "database.h"
#include <iostream>

Database::Database(const std::string &db_name) : db(nullptr), db_name(db_name) {}

Database::~Database() {
    if (db) {
        sqlite3_close(db);
    }
}
//Przy tworzeniu nagrania bedzie robiony snapshot do bazy danych
bool Database::initialize() {
    int rc = sqlite3_open(db_name.c_str(), &db);
    if (rc) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    std::string schema = R"(
        CREATE TABLE IF NOT EXISTS Vendors ( --manufacturer, client and router
            oid TEXT PRIMARY KEY,           --mac address prefix (first 3 bytes)
            name TEXT                    --name of the vendor
        );

        CREATE TABLE IF NOT EXISTS Recordings (
            id INTEGER PRIMARY KEY,
            display_name TEXT,
            file_path TEXT,
            start INTEGER,          --start time of the recording
            end INTEGER             --end time of the recording
        );

        CREATE TABLE IF NOT EXISTS Networks (
            id INTEGER PRIMARY KEY,
            ssid TEXT,
            bssid TEXT,
            psk TEXT,
            total_packet_count INTEGER,
            decrypted_packet_count INTEGER,
            group_packet_count INTEGER,
            security TEXT,              --maybe int
            recording_id INTEGER,
            group_rekeys INTEGER,
            vendor_oid TEXT,
            FOREIGN KEY (vendor_oid) REFERENCES Vendors(oid),
            FOREIGN KEY (recording_id) REFERENCES Recordings(id)
        );

        CREATE TABLE IF NOT EXISTS GroupDecryptionWindow (
            network_id INTEGER,
            start INTEGER,
            end INTEGER,
            packet_count INTEGER,
            FOREIGN KEY (network_id) REFERENCES Networks(id)
        );

        CREATE TABLE IF NOT EXISTS Clients (
            id INTEGER PRIMARY KEY,
            address TEXT,
            packet_count INTEGER,
            decrypted_packet_count INTEGER,
            network_id INTEGER,
            FOREIGN KEY (network_id) REFERENCES Networks(id)
        );

        CREATE TABLE IF NOT EXISTS ClientDecryptionWindow (
            client_id INTEGER,
            network_id INTEGER,
            start INTEGER,
            end INTEGER,
            packet_count INTEGER,
            FOREIGN KEY (client_id) REFERENCES Clients(id),
            FOREIGN KEY (network_id) REFERENCES Networks(id)
        );
    )";

    return execute_query(schema);
}

bool Database::execute_query(const std::string &query) {
    char *errmsg = nullptr;
    int rc = sqlite3_exec(db, query.c_str(), nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << errmsg << std::endl;
        sqlite3_free(errmsg);
        return false;
    }
    return true;
}

std::vector<std::vector<std::string>> Database::select_query(const std::string &query) {
    std::vector<std::vector<std::string>> results;
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to execute query: " << sqlite3_errmsg(db) << std::endl;
        return results;
    }

    int cols = sqlite3_column_count(stmt);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::vector<std::string> row;
        for (int col = 0; col < cols; col++) {
            const char *val = reinterpret_cast<const char *>(sqlite3_column_text(stmt, col));
            row.push_back(val ? val : "");
        }
        results.push_back(row);
    }

    sqlite3_finalize(stmt);
    return results;
}

//RECORDINGS
bool Database::insert_recording(const std::string &display_name, const std::string &file_path, int64_t start, int64_t end) {
    std::string query = "INSERT INTO Recordings (display_name, file_path, start, end) VALUES ('" + display_name + "', '" + file_path + "', " + std::to_string(start) + ", " + std::to_string(end) + ");";
    return execute_query(query);
}

std::vector<std::vector<std::string>> Database::get_recordings() {
    std::string query = "SELECT * FROM Recordings;";
    return select_query(query);
}

bool Database::recording_exists(const std::string &uuid, const std::string &file_path) {
    std::string query = "SELECT COUNT(*) FROM Recordings WHERE id = '" + uuid + "' AND file_path = '" + file_path + "';";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to execute query: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    bool exists = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        exists = sqlite3_column_int(stmt, 0) > 0;
    }

    sqlite3_finalize(stmt);
    return exists;
}

//VENDORS
bool Database::insert_vendor(const std::string &oid, const std::string &name, const std::string &address) {
    std::string query = "INSERT INTO Vendors (oid, name, address) VALUES ('" + oid + "', '" + name + "', '" + address + "');";
    return execute_query(query);
}

std::vector<std::vector<std::string>> Database::get_vendors() {
    std::string query = "SELECT * FROM Vendors;";
    return select_query(query);
}

//NETWORKS
bool Database::insert_network(const std::string &ssid, const std::string &bssid, const std::string &psk, int total_packet_count, int decrypted_packet_count, int group_packet_count, const std::string &security, int recording_id, int group_rekeys, const std::string &vendor_oid) {
    //check if the network with the BSSID already exists
    std::string check_query = "SELECT COUNT(*) FROM Networks WHERE bssid = '" + bssid + "';";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, check_query.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to execute query: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    bool exists = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        exists = sqlite3_column_int(stmt, 0) > 0;
    }
    sqlite3_finalize(stmt);

    if (exists) {
        return true;
    }

    std::string query = "INSERT INTO Networks (ssid, bssid, psk, total_packet_count, decrypted_packet_count, group_packet_count, security, recording_id, group_rekeys, vendor_oid) VALUES ('" + ssid + "', '" + bssid + "', '" + psk + "', " + std::to_string(total_packet_count) + ", " + std::to_string(decrypted_packet_count) + ", " + std::to_string(group_packet_count) + ", '" + security + "', " + std::to_string(recording_id) + ", " + std::to_string(group_rekeys) + ", '" + vendor_oid + "');";
    return execute_query(query);
}

std::vector<std::vector<std::string>> Database::get_networks() {
    std::string query = "SELECT * FROM Networks;";
    return select_query(query);
}
