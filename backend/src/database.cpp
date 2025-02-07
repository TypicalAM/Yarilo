#include "database.h"
#include "decrypter.h"
#include "log_sink.h"
#include <fstream>

namespace yarilo {

Database::Database(const std::string &db_path) : db(nullptr), db_path(db_path) {
  logger = yarilo::log::get_logger("Database");
}

Database::~Database() {
  if (db) {
    sqlite3_close(db);
  }
}
bool Database::initialize() {
  int rc = sqlite3_open(db_path.c_str(), &db);
  if (rc) {
    logger->error("Failed to open database: {}", sqlite3_errmsg(db));
    return false;
  }

  if (!execute_query(schema)) {
    logger->error("Failed to create database schema.");
    return false;
  }

  sqlite3_exec(db, "PRAGMA foreign_keys = ON;", nullptr, nullptr, nullptr);
  logger->info("Database initialized successfully");
  return refresh_database();
}

bool Database::execute_query(const std::string &query) {
  char *errmsg = nullptr;
  int rc = sqlite3_exec(db, query.c_str(), nullptr, nullptr, &errmsg);
  if (rc != SQLITE_OK) {
    logger->error("Failed to execute query: {}", errmsg);
    sqlite3_free(errmsg);
    return false;
  }
  return true;
}

std::vector<std::vector<std::string>>
Database::select_query(const std::string &query) {
  std::vector<std::vector<std::string>> results;
  sqlite3_stmt *stmt;
  int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK) {
    logger->error("Failed to execute select query: {}", sqlite3_errmsg(db));
    return results;
  }

  int cols = sqlite3_column_count(stmt);
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    std::vector<std::string> row;
    for (int col = 0; col < cols; col++) {
      const char *val =
          reinterpret_cast<const char *>(sqlite3_column_text(stmt, col));
      row.push_back(val ? val : "");
    }
    results.push_back(row);
  }

  sqlite3_finalize(stmt);
  return results;
}

bool Database::check_vendors(bool seeding) {
  std::string query = "SELECT COUNT(*) FROM Vendors LIMIT 1;";
  sqlite3_stmt *stmt;
  int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK) {
    logger->error("Failed to execute query: {}", sqlite3_errmsg(db));
    return false;
  }

  bool exists = false;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    exists = sqlite3_column_int(stmt, 0) > 0;
  }

  sqlite3_finalize(stmt);
  if (!exists && !seeding)
    logger->error("No vendors in the database.");

  return exists;
}

bool Database::insert_recording(const uuid::UUIDv4 &uuid,
                                const std::string &display_name,
                                const std::string &file_path, int64_t start,
                                int64_t end, proto::DataLinkType data_link) {
  const std::string query = "INSERT INTO Recordings (id, display_name, "
                            "file_path, start, end, data_link) VALUES ('" +
                            uuid + "', '" + display_name + "', '" + file_path +
                            "', " + std::to_string(start) + ", " +
                            std::to_string(end) + ", " +
                            std::to_string(data_link) + ");";
  return execute_query(query);
}

std::vector<std::vector<std::string>> Database::get_recordings() {
  std::string query = "SELECT * FROM Recordings;";
  return select_query(query);
}

std::vector<std::string> Database::get_recording(const uuid::UUIDv4 &uuid) {
  std::string query = "SELECT * FROM Recordings WHERE id = '" + uuid + "';";
  std::vector<std::vector<std::string>> result = select_query(query);
  if (result.empty()) {
    return {};
  }
  return result[0];
}

bool Database::recording_exists(const uuid::UUIDv4 &uuid) {
  std::string query =
      "SELECT COUNT(*) FROM Recordings WHERE id= '" + uuid + "';";
  sqlite3_stmt *stmt;
  int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK) {
    logger->error("Failed to execute query: {}", sqlite3_errmsg(db));
    return false;
  }

  bool exists = false;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    exists = sqlite3_column_int(stmt, 0) > 0;
  }

  sqlite3_finalize(stmt);
  return exists;
}

bool Database::recording_exists_path(const std::string &file_path) {
  std::string query =
      "SELECT COUNT(*) FROM Recordings WHERE file_path = '" + file_path + "';";
  sqlite3_stmt *stmt;
  int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK) {
    logger->error("Failed to execute query: {}", sqlite3_errmsg(db));
    return false;
  }

  bool exists = false;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    exists = sqlite3_column_int(stmt, 0) > 0;
  }

  sqlite3_finalize(stmt);
  return exists;
}

bool Database::delete_recording(const uuid::UUIDv4 &uuid) const {
  std::vector<std::string> queries = {
      "DELETE FROM ClientDecryptionWindow WHERE client_address IN (SELECT "
      "address FROM Clients WHERE network_bssid IN (SELECT bssid FROM Networks "
      "WHERE recording_id = ?));",
      "DELETE FROM GroupDecryptionWindow WHERE network_bssid IN (SELECT bssid "
      "FROM Networks WHERE recording_id = ?);",
      "DELETE FROM Clients WHERE network_bssid IN (SELECT bssid FROM Networks "
      "WHERE recording_id = ?);",
      "DELETE FROM Networks WHERE recording_id = ?;",
      "DELETE FROM Recordings WHERE id = ?;"};

  for (const auto &query : queries) {
    sqlite3_stmt *stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
      logger->error("Failed to prepare delete recording statement: {}",
                    sqlite3_errmsg(db));
      return false;
    }

    sqlite3_bind_text(stmt, 1, uuid.c_str(), -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
      logger->error("Failed to execute delete recording statement: {}",
                    sqlite3_errmsg(db));
      return false;
    }
  }

  return true;
}

bool Database::load_vendors(const std::string &file_path) {
  if (check_vendors(true)) {
    logger->info("Vendors table not empty in the database. Not seeding.");
    return true;
  }
  std::ifstream file(file_path);
  if (!file.is_open()) {
    logger->error("Failed to open vendors seeding file: {}", file_path);
    return false;
  }

  std::string line;
  std::vector<std::pair<std::string, std::string>> vendors;
  std::unordered_set<std::string> seen_oids;

  while (std::getline(file, line)) {
    if (line.find("base 16") == std::string::npos) {
      continue;
    }
    std::string mac_prefix = line.substr(0, 6);
    if (line.find(mac_prefix) != std::string::npos &&
        !seen_oids.contains(mac_prefix)) {
      std::string vendor = line.substr(22);
      vendors.emplace_back(mac_prefix, vendor);
      seen_oids.insert(mac_prefix);
    }
  }

  if (!insert_vendors(vendors)) {
    logger->error("Failed to insert vendors from OID file.");
    return false;
  }

  logger->info("Vendors loaded from OID file successfully.");
  return true;
}

bool Database::insert_vendors(
    const std::vector<std::pair<std::string, std::string>> &vendors) {
  char *errmsg = nullptr;
  int rc = sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, &errmsg);
  if (rc != SQLITE_OK) {
    logger->error("Failed to begin transaction: {}", errmsg);
    sqlite3_free(errmsg);
    return false;
  }

  std::string query = "INSERT INTO Vendors (oid, name) VALUES (?, ?);";
  sqlite3_stmt *stmt;
  rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK) {
    logger->error("Failed to prepare statement: {}", sqlite3_errmsg(db));
    return false;
  }

  for (const auto &vendor : vendors) {
    sqlite3_bind_text(stmt, 1, vendor.first.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, vendor.second.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
      logger->error("Failed to execute statement: {}", sqlite3_errmsg(db));
      sqlite3_finalize(stmt);
      sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
      return false;
    }

    sqlite3_reset(stmt);
  }

  sqlite3_finalize(stmt);

  rc = sqlite3_exec(db, "COMMIT;", nullptr, nullptr, &errmsg);
  if (rc != SQLITE_OK) {
    logger->error("Failed to commit transaction: {}", errmsg);
    sqlite3_free(errmsg);
    return false;
  }

  return true;
}

std::vector<std::vector<std::string>> Database::get_vendors() {
  std::string query = "SELECT * FROM Vendors;";
  return select_query(query);
}

std::string Database::get_vendor_name(const MACAddress &addr) {
  std::string mac_prefix = addr.to_string().substr(0, 8);
  std::erase(mac_prefix, ':');
  std::transform(mac_prefix.begin(), mac_prefix.end(), mac_prefix.begin(),
                 ::toupper);

  std::string query =
      "SELECT name FROM Vendors WHERE oid = '" + mac_prefix + "';";
  std::vector<std::vector<std::string>> result = select_query(query);
  if (result.empty())
    return "";
  return result[0][0];
}

std::string Database::get_vendor_name(const std::string &oid) {
  std::string query = "SELECT name FROM Vendors WHERE oid = '" + oid + "';";
  std::vector<std::vector<std::string>> result = select_query(query);
  if (result.empty()) {
    return "";
  }
  return result[0][0];
}

bool Database::vendor_exists(const std::string &oid) {
  if (get_vendor_name(oid).empty()) {
    return false;
  }
  return true;
}

bool Database::insert_network(const std::string &ssid, const std::string &bssid,
                              const std::string &psk,
                              uint32_t total_packet_count,
                              uint32_t decrypted_packet_count,
                              uint32_t group_packet_count,
                              const std::string &security,
                              std::string recording_id, uint32_t group_rekeys,
                              const std::string &vendor_oid) {
  std::string check_query = "SELECT COUNT(*) FROM Networks WHERE bssid = ?;";
  sqlite3_stmt *stmt;
  int rc = sqlite3_prepare_v2(db, check_query.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK) {
    logger->error("Failed to execute query: {}", sqlite3_errmsg(db));
    return false;
  }
  sqlite3_bind_text(stmt, 1, bssid.c_str(), -1, SQLITE_STATIC);
  bool exists = false;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    exists = sqlite3_column_int(stmt, 0) > 0;
  }
  sqlite3_finalize(stmt);

  if (exists) {
    return true;
  }

  if (!vendor_exists(vendor_oid)) {
    insert_vendors({{vendor_oid, "Unknown"}});
  }

  std::string query =
      "INSERT INTO Networks (ssid, bssid, psk, total_packet_count, "
      "decrypted_packet_count, group_packet_count, security, recording_id, "
      "group_rekeys, vendor_oid) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
  rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK) {
    logger->error("Failed to prepare statement: {}", sqlite3_errmsg(db));
    return false;
  }

  sqlite3_bind_text(stmt, 1, ssid.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 2, bssid.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 3, psk.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_int(stmt, 4, total_packet_count);
  sqlite3_bind_int(stmt, 5, decrypted_packet_count);
  sqlite3_bind_int(stmt, 6, group_packet_count);
  sqlite3_bind_text(stmt, 7, security.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 8, recording_id.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_int(stmt, 9, group_rekeys);
  sqlite3_bind_text(stmt, 10, vendor_oid.c_str(), -1, SQLITE_STATIC);

  rc = sqlite3_step(stmt);
  if (rc != SQLITE_DONE) {
    logger->error("Failed to execute statement: {}", sqlite3_errmsg(db));
    sqlite3_finalize(stmt);
    return false;
  }

  sqlite3_finalize(stmt);
  return true;
}

bool Database::insert_group_window(const std::string &network_id,
                                   uint64_t start, uint64_t end,
                                   uint32_t packet_count) {
  std::string check_query =
      "SELECT COUNT(*) FROM GroupDecryptionWindow WHERE start = " +
      std::to_string(start) + " AND end = " + std::to_string(end) +
      " AND packet_count = " + std::to_string(packet_count) + ";";
  sqlite3_stmt *stmt;
  int rc = sqlite3_prepare_v2(db, check_query.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK) {
    logger->error("Failed to execute query: {}", sqlite3_errmsg(db));
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

  std::string query = "INSERT INTO GroupDecryptionWindow (network_bssid, "
                      "start, end, packet_count) VALUES ('" +
                      network_id + "', " + std::to_string(start) + ", " +
                      std::to_string(end) + ", " +
                      std::to_string(packet_count) + ");";
  return execute_query(query);
}

std::vector<std::vector<std::string>> Database::get_group_windows() {
  std::string query = "SELECT * FROM GroupDecryptionWindow;";
  return select_query(query);
}

bool Database::insert_client(const std::string &address, uint32_t packet_count,
                             uint32_t decrypted_packet_count,
                             const std::string &network_id) {
  std::string check_query =
      "SELECT COUNT(*) FROM Clients WHERE address = '" + address + "';";
  sqlite3_stmt *stmt;
  int rc = sqlite3_prepare_v2(db, check_query.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK) {
    logger->error("Failed to execute query: {}", sqlite3_errmsg(db));
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

  std::string query = "INSERT INTO Clients (address, packet_count, "
                      "decrypted_packet_count, network_bssid) VALUES ('" +
                      address + "', " + std::to_string(packet_count) + ", " +
                      std::to_string(decrypted_packet_count) + ", '" +
                      network_id + "');";
  return execute_query(query);
}

std::vector<std::vector<std::string>> Database::get_clients() {
  std::string query = "SELECT * FROM Clients;";
  return select_query(query);
}

bool Database::insert_client_window(const std::string &client_address,
                                    const std::string &network_id,
                                    uint64_t start, uint64_t end,
                                    uint32_t packet_count) {
  std::string check_query =
      "SELECT COUNT(*) FROM ClientDecryptionWindow WHERE start = " +
      std::to_string(start) + " AND end = " + std::to_string(end) +
      " AND packet_count = " + std::to_string(packet_count) + ";";
  sqlite3_stmt *stmt;
  int rc = sqlite3_prepare_v2(db, check_query.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK) {
    logger->error("Failed to execute query: {}", sqlite3_errmsg(db));
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

  std::string query = "INSERT INTO ClientDecryptionWindow (client_address, "
                      "network_bssid, start, end, packet_count) VALUES ('" +
                      client_address + "', '" + network_id + "', " +
                      std::to_string(start) + ", " + std::to_string(end) +
                      ", " + std::to_string(packet_count) + ");";
  return execute_query(query);
}

std::vector<std::vector<std::string>> Database::get_client_windows() {
  std::string query = "SELECT * FROM ClientDecryptionWindow;";
  return select_query(query);
}

bool Database::refresh_database() {
  std::vector<std::vector<std::string>> recordings = get_recordings();
  for (const auto &recording : recordings) {
    std::string file_path = recording[2];
    std::ifstream file(file_path);
    if (!file.is_open()) {
      std::string uuid = recording[0];
      logger->debug(
          "Recording with uuid: {} does not exist, deleting from database",
          uuid);
      if (!delete_recording(uuid)) {
        logger->error("Failed to delete recording with uuid: {}", uuid);
        return false;
      }
    }
  }
  return true;
}

} // namespace yarilo
