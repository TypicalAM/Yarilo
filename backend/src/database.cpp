#include "database.h"
#include <iostream>
#include <spdlog/logger.h>

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
        CREATE TABLE IF NOT EXISTS Vendors (
            oid TEXT PRIMARY KEY,           --mac address prefix (first 3 bytes)
            name TEXT                    --name of the vendor
        );

        CREATE TABLE IF NOT EXISTS Recordings (
            id TEXT PRIMARY KEY,
            display_name TEXT,
            file_path TEXT,
            start INTEGER,          --todo
            end INTEGER             --todo
        );

        CREATE TABLE IF NOT EXISTS Networks (
            id INTEGER PRIMARY KEY,
            ssid TEXT,
            bssid TEXT,
            psk TEXT,
            total_packet_count INTEGER,
            decrypted_packet_count INTEGER,
            group_packet_count INTEGER,
            security TEXT,              --numbers separated by space (ex. 3 4)
            recording_id TEXT,
            group_rekeys INTEGER,       --todo
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
            decrypted_packet_count INTEGER, --nie wiem czy to jest zbierane
            network_id INTEGER,
            FOREIGN KEY (network_id) REFERENCES Networks(id)
        );

        CREATE TABLE IF NOT EXISTS ClientDecryptionWindow (
            client_address TEXT,
            network_id INTEGER,
            start INTEGER,
            end INTEGER,
            packet_count INTEGER,
            FOREIGN KEY (client_address) REFERENCES Clients(address),
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
bool Database::insert_recording(const std::string &uuid, const std::string &display_name, const std::string &file_path, int64_t start, int64_t end) {
    const std::string query = "INSERT INTO Recordings (id, display_name, file_path, start, end) VALUES ('" + uuid + "', '" + display_name + "', '" + file_path + "', " + std::to_string(start) + ", " + std::to_string(end) + ");";
    return execute_query(query);
}

std::vector<std::vector<std::string>> Database::get_recordings() {
    std::string query = "SELECT * FROM Recordings;";
    return select_query(query);
}

std::vector<std::string> Database::get_recording(const std::string &uuid) {
    std::string query = "SELECT * FROM Recordings WHERE id = '" + uuid + "';";
    std::vector<std::vector<std::string>> result = select_query(query);
    if (result.empty()) {
        return {};
    }
    return result[0];
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
bool Database::insert_vendor(const std::string &oid, const std::string &name) {
    std::string check_query = "SELECT COUNT(*) FROM Vendors WHERE oid = '" + oid + "';";
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
        return true; //vendor already exists
    }

    std::string query = "INSERT INTO Vendors (oid, name) VALUES ('" + oid + "', '" + name + "');";
    return execute_query(query);
}

std::vector<std::vector<std::string>> Database::get_vendors() {
    std::string query = "SELECT * FROM Vendors;";
    return select_query(query);
}

//NETWORKS
bool Database::insert_network(const std::string &ssid, const std::string &bssid, const std::string &psk, uint32_t total_packet_count, uint32_t decrypted_packet_count, uint32_t group_packet_count, const std::string &security, const std::string recording_id, uint32_t group_rekeys, const std::string &vendor_oid) {
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

    std::string query = "INSERT INTO Networks (ssid, bssid, psk, total_packet_count, decrypted_packet_count, group_packet_count, security, recording_id, group_rekeys, vendor_oid) VALUES ('" + ssid + "', '" + bssid + "', '" + psk + "', " + std::to_string(total_packet_count) + ", " + std::to_string(decrypted_packet_count) + ", " + std::to_string(group_packet_count) + ", '" + security + "', '" + recording_id + "', " + std::to_string(group_rekeys) + ", '" + vendor_oid + "');";
    return execute_query(query);
}

std::vector<std::vector<std::string>> Database::get_networks() {
    std::string query = "SELECT * FROM Networks;";
    return select_query(query);
}

//GROUP WINDOWS
bool Database::insert_group_window(const std::string& network_id, uint64_t start, uint64_t end, uint32_t packet_count) {
    //check if the combination of start, end, and count already exists
    std::string check_query = "SELECT COUNT(*) FROM GroupDecryptionWindow WHERE start = " + std::to_string(start) + " AND end = " + std::to_string(end) + " AND packet_count = " + std::to_string(packet_count) + ";";
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
        return true; //combination already exists
    }

    std::string query = "INSERT INTO GroupDecryptionWindow (network_id, start, end, packet_count) VALUES ('" + network_id + "', " + std::to_string(start) + ", " + std::to_string(end) + ", " + std::to_string(packet_count) + ");";
    return execute_query(query);
}

std::vector<std::vector<std::string>> Database::get_group_windows() {
    std::string query = "SELECT * FROM GroupDecryptionWindow;";
    return select_query(query);
}

//CLIENTS
bool Database::insert_client(const std::string &address, uint32_t packet_count, uint32_t decrypted_packet_count, const std::string &network_id) {
    //check if the client with the address already exists
    std::string check_query = "SELECT COUNT(*) FROM Clients WHERE address = '" + address + "';";
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

    std::string query = "INSERT INTO Clients (address, packet_count, decrypted_packet_count, network_id) VALUES ('" + address + "', " + std::to_string(packet_count) + ", " + std::to_string(decrypted_packet_count) + ", '" + network_id + "');";
    return execute_query(query);
}

std::vector<std::vector<std::string>> Database::get_clients() {
    std::string query = "SELECT * FROM Clients;";
    return select_query(query);
}

//CLIENT WINDOWS
bool Database::insert_client_window(const std::string &client_address, const std::string &network_id, uint64_t start, uint64_t end, uint32_t packet_count) {
    std::string check_query = "SELECT COUNT(*) FROM ClientDecryptionWindow WHERE start = " + std::to_string(start) + " AND end = " + std::to_string(end) + " AND packet_count = " + std::to_string(packet_count) + ";";
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
        return true; //combination already exists
    }

    std::string query = "INSERT INTO ClientDecryptionWindow (client_address, network_id, start, end, packet_count) VALUES ('" + client_address + "', '" + network_id + "', " + std::to_string(start) + ", " + std::to_string(end) + ", " + std::to_string(packet_count) + ");";
    return execute_query(query);
}

std::vector<std::vector<std::string>> Database::get_client_windows() {
    std::string query = "SELECT * FROM ClientDecryptionWindow;";
    return select_query(query);
}