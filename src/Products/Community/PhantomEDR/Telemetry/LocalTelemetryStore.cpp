/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * ============================================================================
 * ShadowStrike – PhantomEDR Local Telemetry Store Implementation
 * ============================================================================
 *
 * @file LocalTelemetryStore.cpp
 * @brief SQLite-backed ITelemetryStore for the Community edition.
 *
 * ARCHITECTURE:
 * - PIMPL pattern via LocalTelemetryStoreImpl (free class, not nested)
 * - Dedicated SQLite connection with WAL for concurrent reads
 * - Background maintenance thread for retention / storage-cap enforcement
 * - Atomic statistics tracking; std::shared_mutex for DB access
 * - All SQL uses parameterised bindings — no string interpolation
 *
 * DATABASE SCHEMA:
 * - telemetry_events : primary event table with JSON payload & metadata
 * - Indices on timestamp, category, severity, process_id, mitre_attack_id
 *
 * PERFORMANCE TARGETS:
 * - Single insert   : < 2 ms
 * - Batch insert     : < 10 ms for 100 rows
 * - Filtered query   : < 50 ms for 1 000 rows
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 */

#include "pch.h"
#include "LocalTelemetryStore.hpp"

// ============================================================================
// ADDITIONAL INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"

#include <SQLiteCpp/SQLiteCpp.h>
#include <nlohmann/json.hpp>

#include <condition_variable>
#include <filesystem>
#include <mutex>
#include <shared_mutex>
#include <thread>

namespace fs = std::filesystem;

// ============================================================================
// ANONYMOUS NAMESPACE – CONSTANTS & HELPERS
// ============================================================================

namespace {

using namespace ShadowStrike::Products::PhantomEDR::Telemetry;
using ShadowStrike::Utils::Logger;

// -- Schema version ----------------------------------------------------------
constexpr uint32_t kSchemaVersion = 1;

// -- Safety caps -------------------------------------------------------------
constexpr size_t   kMaxStringLength     = 32768;          // 32 KB per string
constexpr size_t   kMaxPayloadJsonBytes = 1 * 1024 * 1024; // 1 MB
constexpr size_t   kMaxMetadataJsonBytes= 64 * 1024;       // 64 KB
constexpr size_t   kMaxBatchSize        = 10000;
constexpr uint32_t kMaxQueryResults     = 100000;
constexpr size_t   kMaxRegistryValueData= 1 * 1024 * 1024; // 1 MB
constexpr size_t   kMaxDnsResponses     = 256;
constexpr int      kMaintenanceIntervalSec = 300;          // 5 minutes

// -- SQL DDL -----------------------------------------------------------------

constexpr std::string_view kSqlCreateTable = R"(
    CREATE TABLE IF NOT EXISTS telemetry_events (
        event_id            INTEGER PRIMARY KEY,
        timestamp_ns        INTEGER NOT NULL,
        category            INTEGER NOT NULL,
        severity            INTEGER NOT NULL,
        process_id          INTEGER,
        parent_process_id   INTEGER,
        thread_id           INTEGER,
        process_name        TEXT,
        process_path        TEXT,
        user_name           TEXT,
        session_id          TEXT,
        mitre_attack_id     TEXT,
        payload_json        TEXT NOT NULL,
        metadata_json       TEXT
    );
)";

constexpr std::string_view kSqlCreateIndices = R"(
    CREATE INDEX IF NOT EXISTS idx_telem_timestamp ON telemetry_events(timestamp_ns);
    CREATE INDEX IF NOT EXISTS idx_telem_category  ON telemetry_events(category);
    CREATE INDEX IF NOT EXISTS idx_telem_severity  ON telemetry_events(severity);
    CREATE INDEX IF NOT EXISTS idx_telem_process   ON telemetry_events(process_id);
    CREATE INDEX IF NOT EXISTS idx_telem_mitre     ON telemetry_events(mitre_attack_id);
)";

constexpr std::string_view kSqlCreateVersion = R"(
    CREATE TABLE IF NOT EXISTS schema_version (
        version     INTEGER PRIMARY KEY,
        created_at  INTEGER NOT NULL
    );
)";

constexpr std::string_view kSqlInsertEvent = R"(
    INSERT INTO telemetry_events
        (event_id, timestamp_ns, category, severity,
         process_id, parent_process_id, thread_id,
         process_name, process_path, user_name,
         session_id, mitre_attack_id,
         payload_json, metadata_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
)";

constexpr std::string_view kSqlSelectById = R"(
    SELECT event_id, timestamp_ns, category, severity,
           process_id, parent_process_id, thread_id,
           process_name, process_path, user_name,
           session_id, mitre_attack_id,
           payload_json, metadata_json
    FROM telemetry_events
    WHERE event_id = ?;
)";

constexpr std::string_view kSqlCount = R"(
    SELECT COUNT(*) FROM telemetry_events;
)";

constexpr std::string_view kSqlMaxEventId = R"(
    SELECT MAX(event_id) FROM telemetry_events;
)";

constexpr std::string_view kSqlPurge = R"(
    DELETE FROM telemetry_events WHERE timestamp_ns < ?;
)";

// ============================================================================
// STRING CONVERSION HELPERS (UTF-16 <-> UTF-8)
// ============================================================================

[[nodiscard]] std::string WideToUtf8(const std::wstring& wide) {
    if (wide.empty()) return {};
    const int len = ::WideCharToMultiByte(
        CP_UTF8, 0,
        wide.data(), static_cast<int>(wide.size()),
        nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string out(static_cast<size_t>(len), '\0');
    ::WideCharToMultiByte(
        CP_UTF8, 0,
        wide.data(), static_cast<int>(wide.size()),
        out.data(), len, nullptr, nullptr);
    return out;
}

[[nodiscard]] std::wstring Utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return {};
    const int len = ::MultiByteToWideChar(
        CP_UTF8, 0,
        utf8.data(), static_cast<int>(utf8.size()),
        nullptr, 0);
    if (len <= 0) return {};
    std::wstring out(static_cast<size_t>(len), L'\0');
    ::MultiByteToWideChar(
        CP_UTF8, 0,
        utf8.data(), static_cast<int>(utf8.size()),
        out.data(), len);
    return out;
}

// -- Hex encoding for binary registry data -----------------------------------

[[nodiscard]] std::string BytesToHex(const std::vector<uint8_t>& bytes) {
    static constexpr char kHexChars[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const auto b : bytes) {
        out.push_back(kHexChars[(b >> 4) & 0x0F]);
        out.push_back(kHexChars[b & 0x0F]);
    }
    return out;
}

[[nodiscard]] std::vector<uint8_t> HexToBytes(const std::string& hex) {
    std::vector<uint8_t> out;
    if (hex.size() % 2 != 0 || hex.size() > kMaxRegistryValueData * 2)
        return out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        auto nibbleHi = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
            return 0;
        };
        out.push_back(static_cast<uint8_t>((nibbleHi(hex[i]) << 4) | nibbleHi(hex[i + 1])));
    }
    return out;
}

[[nodiscard]] std::string SafeGetText(SQLite::Statement& stmt, int col) {
    if (stmt.getColumn(col).isNull()) return {};
    const char* raw = stmt.getColumn(col).getText();
    return raw ? std::string(raw) : std::string{};
}

// ============================================================================
// TIME CONVERSION HELPERS
// ============================================================================

[[nodiscard]] int64_t TimePointToNanos(std::chrono::system_clock::time_point tp) {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               tp.time_since_epoch())
        .count();
}

[[nodiscard]] std::chrono::system_clock::time_point NanosToTimePoint(int64_t ns) {
    return std::chrono::system_clock::time_point(
        std::chrono::duration_cast<std::chrono::system_clock::duration>(
            std::chrono::nanoseconds(ns)));
}

// ============================================================================
// JSON SERIALIZATION — PAYLOAD
// ============================================================================

[[nodiscard]] nlohmann::json SerializeProcessPayload(const ProcessEventData& d) {
    nlohmann::json j;
    j["_payloadType"]      = "process";
    j["subType"]           = static_cast<uint8_t>(d.subType);
    j["commandLine"]       = WideToUtf8(d.commandLine);
    j["imageHash"]         = d.imageHash;
    j["parentImageHash"]   = d.parentImageHash;
    j["integrityLevel"]    = d.integrityLevel;
    j["isElevated"]        = d.isElevated;
    j["isSystem"]          = d.isSystem;
    j["targetProcessName"] = WideToUtf8(d.targetProcessName);
    j["targetProcessId"]   = d.targetProcessId;
    return j;
}

[[nodiscard]] nlohmann::json SerializeFilePayload(const FileEventData& d) {
    nlohmann::json j;
    j["_payloadType"]   = "file";
    j["subType"]        = static_cast<uint8_t>(d.subType);
    j["filePath"]       = WideToUtf8(d.filePath);
    j["oldFilePath"]    = WideToUtf8(d.oldFilePath);
    j["fileHash"]       = d.fileHash;
    j["fileSize"]       = d.fileSize;
    j["fileAttributes"] = d.fileAttributes;
    return j;
}

[[nodiscard]] nlohmann::json SerializeRegistryPayload(const RegistryEventData& d) {
    nlohmann::json j;
    j["_payloadType"] = "registry";
    j["subType"]      = static_cast<uint8_t>(d.subType);
    j["keyPath"]      = WideToUtf8(d.keyPath);
    j["valueName"]    = WideToUtf8(d.valueName);
    j["valueType"]    = d.valueType;
    j["valueData"]    = BytesToHex(d.valueData);
    j["oldValueData"] = BytesToHex(d.oldValueData);
    return j;
}

[[nodiscard]] nlohmann::json SerializeNetworkPayload(const NetworkEventData& d) {
    nlohmann::json j;
    j["_payloadType"]      = "network";
    j["subType"]           = static_cast<uint8_t>(d.subType);
    j["localAddr"]         = d.localAddr;
    j["localPort"]         = d.localPort;
    j["remoteAddr"]        = d.remoteAddr;
    j["remotePort"]        = d.remotePort;
    j["protocol"]          = d.protocol;
    j["bytesTransferred"]  = d.bytesTransferred;
    j["dnsQuery"]          = d.dnsQuery;
    j["dnsResponse"]       = d.dnsResponse;
    return j;
}

[[nodiscard]] std::string SerializePayload(const EventPayload& payload) {
    nlohmann::json j = std::visit([](auto&& arg) -> nlohmann::json {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, std::monostate>)
            return nlohmann::json{{"_payloadType", "none"}};
        else if constexpr (std::is_same_v<T, ProcessEventData>)
            return SerializeProcessPayload(arg);
        else if constexpr (std::is_same_v<T, FileEventData>)
            return SerializeFilePayload(arg);
        else if constexpr (std::is_same_v<T, RegistryEventData>)
            return SerializeRegistryPayload(arg);
        else if constexpr (std::is_same_v<T, NetworkEventData>)
            return SerializeNetworkPayload(arg);
        else
            return nlohmann::json{{"_payloadType", "unknown"}};
    }, payload);

    std::string result = j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    if (result.size() > kMaxPayloadJsonBytes) {
        Logger::Warn("Telemetry payload JSON exceeds {} byte cap, truncating",
                     kMaxPayloadJsonBytes);
        result.resize(kMaxPayloadJsonBytes);
    }
    return result;
}

// ============================================================================
// JSON DESERIALIZATION — PAYLOAD
// ============================================================================

[[nodiscard]] ProcessEventData DeserializeProcessPayload(const nlohmann::json& j) {
    ProcessEventData d;
    d.subType           = static_cast<ProcessEventType>(j.value("subType", 0));
    d.commandLine       = Utf8ToWide(j.value("commandLine", ""));
    d.imageHash         = j.value("imageHash", "");
    d.parentImageHash   = j.value("parentImageHash", "");
    d.integrityLevel    = j.value("integrityLevel", 0u);
    d.isElevated        = j.value("isElevated", false);
    d.isSystem          = j.value("isSystem", false);
    d.targetProcessName = Utf8ToWide(j.value("targetProcessName", ""));
    d.targetProcessId   = j.value("targetProcessId", 0u);
    return d;
}

[[nodiscard]] FileEventData DeserializeFilePayload(const nlohmann::json& j) {
    FileEventData d;
    d.subType        = static_cast<FileEventType>(j.value("subType", 0));
    d.filePath       = Utf8ToWide(j.value("filePath", ""));
    d.oldFilePath    = Utf8ToWide(j.value("oldFilePath", ""));
    d.fileHash       = j.value("fileHash", "");
    d.fileSize       = j.value("fileSize", uint64_t{0});
    d.fileAttributes = j.value("fileAttributes", 0u);
    return d;
}

[[nodiscard]] RegistryEventData DeserializeRegistryPayload(const nlohmann::json& j) {
    RegistryEventData d;
    d.subType   = static_cast<RegistryEventType>(j.value("subType", 0));
    d.keyPath   = Utf8ToWide(j.value("keyPath", ""));
    d.valueName = Utf8ToWide(j.value("valueName", ""));
    d.valueType = j.value("valueType", 0u);
    if (j.contains("valueData") && j["valueData"].is_string())
        d.valueData = HexToBytes(j["valueData"].get<std::string>());
    if (j.contains("oldValueData") && j["oldValueData"].is_string())
        d.oldValueData = HexToBytes(j["oldValueData"].get<std::string>());
    return d;
}

[[nodiscard]] NetworkEventData DeserializeNetworkPayload(const nlohmann::json& j) {
    NetworkEventData d;
    d.subType          = static_cast<NetworkEventType>(j.value("subType", 0));
    d.localAddr        = j.value("localAddr", "");
    d.localPort        = j.value("localPort", uint16_t{0});
    d.remoteAddr       = j.value("remoteAddr", "");
    d.remotePort       = j.value("remotePort", uint16_t{0});
    d.protocol         = j.value("protocol", uint16_t{0});
    d.bytesTransferred = j.value("bytesTransferred", uint64_t{0});
    d.dnsQuery         = j.value("dnsQuery", "");
    if (j.contains("dnsResponse") && j["dnsResponse"].is_array()) {
        for (size_t i = 0; i < j["dnsResponse"].size() && i < kMaxDnsResponses; ++i) {
            if (j["dnsResponse"][i].is_string())
                d.dnsResponse.push_back(j["dnsResponse"][i].get<std::string>());
        }
    }
    return d;
}

[[nodiscard]] EventPayload DeserializePayload(const std::string& json) {
    if (json.empty()) return std::monostate{};
    try {
        auto j = nlohmann::json::parse(json);
        const auto type = j.value("_payloadType", "");

        if (type == "process")  return DeserializeProcessPayload(j);
        if (type == "file")     return DeserializeFilePayload(j);
        if (type == "registry") return DeserializeRegistryPayload(j);
        if (type == "network")  return DeserializeNetworkPayload(j);
        return std::monostate{};
    } catch (const nlohmann::json::exception& ex) {
        Logger::Warn("Failed to deserialize telemetry payload JSON: {}", ex.what());
        return std::monostate{};
    }
}

// ============================================================================
// JSON SERIALIZATION — METADATA MAP
// ============================================================================

[[nodiscard]] std::string SerializeMetadata(
    const std::unordered_map<std::string, std::string>& metadata)
{
    if (metadata.empty()) return {};
    nlohmann::json j(metadata);
    std::string result = j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    if (result.size() > kMaxMetadataJsonBytes) {
        Logger::Warn("Telemetry metadata JSON exceeds {} byte cap", kMaxMetadataJsonBytes);
        return {};
    }
    return result;
}

[[nodiscard]] std::unordered_map<std::string, std::string>
DeserializeMetadata(const std::string& json) {
    if (json.empty()) return {};
    try {
        auto j = nlohmann::json::parse(json);
        std::unordered_map<std::string, std::string> out;
        out.reserve(j.size());
        for (auto it = j.begin(); it != j.end(); ++it) {
            if (it.value().is_string())
                out.emplace(it.key(), it.value().get<std::string>());
        }
        return out;
    } catch (const nlohmann::json::exception& ex) {
        Logger::Warn("Failed to deserialize telemetry metadata JSON: {}", ex.what());
        return {};
    }
}

} // anonymous namespace

// ============================================================================
// IMPLEMENTATION CLASS — LocalTelemetryStoreImpl
// ============================================================================

namespace ShadowStrike::Products::PhantomEDR::Telemetry {

class LocalTelemetryStoreImpl final {
public:
    LocalTelemetryStoreImpl() = default;
    ~LocalTelemetryStoreImpl();

    // Non-copyable, non-movable
    LocalTelemetryStoreImpl(const LocalTelemetryStoreImpl&) = delete;
    LocalTelemetryStoreImpl& operator=(const LocalTelemetryStoreImpl&) = delete;
    LocalTelemetryStoreImpl(LocalTelemetryStoreImpl&&) = delete;
    LocalTelemetryStoreImpl& operator=(LocalTelemetryStoreImpl&&) = delete;

    // -- Public interface (called by LocalTelemetryStore forwarding layer) ----

    [[nodiscard]] bool Initialize(const StoreConfig& config);
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    [[nodiscard]] bool Store(TelemetryEvent&& event);
    [[nodiscard]] bool StoreBatch(std::vector<TelemetryEvent>&& events);

    [[nodiscard]] QueryResult Query(const QueryParams& params);
    [[nodiscard]] std::optional<TelemetryEvent> GetById(uint64_t eventId);

    [[nodiscard]] uint64_t PurgeOlderThan(std::chrono::system_clock::time_point cutoff);
    [[nodiscard]] uint64_t GetEventCount() const;
    [[nodiscard]] uint64_t GetStorageSizeBytes() const;
    [[nodiscard]] TelemetryStats GetStats() const;
    void ResetStats();

private:
    // -- Internal helpers ----------------------------------------------------
    [[nodiscard]] bool InitializeSchema();
    [[nodiscard]] bool RecoverEventIdCounter();
    [[nodiscard]] bool InsertEvent(const TelemetryEvent& event);
    [[nodiscard]] TelemetryEvent ReadEvent(SQLite::Statement& stmt) const;
    void MaintenanceLoop();

    // -- State ---------------------------------------------------------------
    mutable std::shared_mutex m_dbMutex;
    std::unique_ptr<SQLite::Database> m_database;
    StoreConfig m_config;
    std::atomic<bool> m_initialized{false};

    // Monotonic event-id counter
    std::atomic<uint64_t> m_nextEventId{1};

    // Maintenance thread
    std::thread              m_maintenanceThread;
    std::mutex               m_maintenanceMtx;
    std::condition_variable  m_maintenanceCv;
    std::atomic<bool>        m_shutdownRequested{false};
    std::chrono::system_clock::time_point m_lastVacuumTime{};

    // Statistics (atomics for lock-free reads)
    std::atomic<uint64_t> m_eventsReceived{0};
    std::atomic<uint64_t> m_eventsStored{0};
    std::atomic<uint64_t> m_eventsDropped{0};
    std::atomic<uint64_t> m_eventsFiltered{0};
    std::atomic<uint64_t> m_purgeCount{0};
    std::array<std::atomic<uint64_t>, kEventCategoryCount> m_eventsByCategory;
};

// ============================================================================
// LocalTelemetryStoreImpl — DESTRUCTOR
// ============================================================================

LocalTelemetryStoreImpl::~LocalTelemetryStoreImpl() {
    Shutdown();
}

// ============================================================================
// LocalTelemetryStoreImpl — LIFECYCLE
// ============================================================================

bool LocalTelemetryStoreImpl::Initialize(const StoreConfig& config) {
    if (m_initialized.load(std::memory_order_acquire)) {
        Logger::Warn("LocalTelemetryStore::Initialize called on already-initialized instance");
        return false;
    }

    // Validate configuration
    if (config.dbPath.empty()) {
        Logger::Error("LocalTelemetryStore: database path is empty");
        return false;
    }
    if (config.retentionDays == 0) {
        Logger::Error("LocalTelemetryStore: retentionDays must be > 0");
        return false;
    }

    m_config = config;

    // Ensure parent directory exists
    try {
        const auto parentDir = m_config.dbPath.parent_path();
        if (!parentDir.empty() && !fs::exists(parentDir)) {
            fs::create_directories(parentDir);
            Logger::Info("LocalTelemetryStore: created directory {}",
                         parentDir.string());
        }
    } catch (const fs::filesystem_error& ex) {
        Logger::Error("LocalTelemetryStore: failed to create parent directory – {}",
                      ex.what());
        return false;
    }

    // Open dedicated SQLite connection
    try {
        std::unique_lock lock(m_dbMutex);
        m_database = std::make_unique<SQLite::Database>(
            m_config.dbPath.string(),
            SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE);

        // -- PRAGMA configuration ------------------------------------------------
        if (m_config.walMode) {
            m_database->exec("PRAGMA journal_mode = WAL;");
        }
        m_database->exec("PRAGMA synchronous  = NORMAL;");
        m_database->exec("PRAGMA temp_store   = MEMORY;");
        m_database->exec("PRAGMA page_size    = 4096;");
        m_database->exec("PRAGMA cache_size   = -16000;"); // ~16 MB
        m_database->exec("PRAGMA busy_timeout = 30000;");
        m_database->exec("PRAGMA foreign_keys = ON;");

        if (!InitializeSchema()) {
            Logger::Error("LocalTelemetryStore: schema initialisation failed");
            m_database.reset();
            return false;
        }

        if (!RecoverEventIdCounter()) {
            Logger::Error("LocalTelemetryStore: failed to recover event-id counter");
            m_database.reset();
            return false;
        }
    } catch (const SQLite::Exception& ex) {
        Logger::Error("LocalTelemetryStore: SQLite open error – code={} msg={}",
                      ex.getErrorCode(), ex.what());
        m_database.reset();
        return false;
    }

    // Zero per-category counters
    for (auto& a : m_eventsByCategory)
        a.store(0, std::memory_order_relaxed);

    m_lastVacuumTime = std::chrono::system_clock::now();

    // Start background maintenance
    m_shutdownRequested.store(false, std::memory_order_release);
    m_maintenanceThread = std::thread([this] { MaintenanceLoop(); });

    m_initialized.store(true, std::memory_order_release);
    Logger::Info("LocalTelemetryStore initialised – db={} retention={}d maxSize={} MB",
                 m_config.dbPath.string(),
                 m_config.retentionDays,
                 m_config.maxStorageSizeBytes / (1024ULL * 1024ULL));
    return true;
}

void LocalTelemetryStoreImpl::Shutdown() {
    if (!m_initialized.exchange(false, std::memory_order_acq_rel))
        return;

    // Signal maintenance thread to stop
    m_shutdownRequested.store(true, std::memory_order_release);
    m_maintenanceCv.notify_all();

    if (m_maintenanceThread.joinable())
        m_maintenanceThread.join();

    // Close database
    {
        std::unique_lock lock(m_dbMutex);
        m_database.reset();
    }

    Logger::Info("LocalTelemetryStore shut down");
}

bool LocalTelemetryStoreImpl::IsInitialized() const noexcept {
    return m_initialized.load(std::memory_order_acquire);
}

// ============================================================================
// LocalTelemetryStoreImpl — SCHEMA BOOTSTRAP
// ============================================================================

bool LocalTelemetryStoreImpl::InitializeSchema() {
    // Caller must hold m_dbMutex exclusively
    try {
        m_database->exec(std::string(kSqlCreateTable));
        m_database->exec(std::string(kSqlCreateIndices));
        m_database->exec(std::string(kSqlCreateVersion));

        // Upsert schema version
        SQLite::Statement versionStmt(
            *m_database,
            "INSERT OR REPLACE INTO schema_version (version, created_at) VALUES (?, ?);");
        versionStmt.bind(1, static_cast<int>(kSchemaVersion));
        versionStmt.bind(2, static_cast<int64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()));
        versionStmt.exec();
        return true;
    } catch (const SQLite::Exception& ex) {
        Logger::Error("LocalTelemetryStore schema creation failed – code={} msg={}",
                      ex.getErrorCode(), ex.what());
        return false;
    }
}

bool LocalTelemetryStoreImpl::RecoverEventIdCounter() {
    // Caller must hold m_dbMutex exclusively
    try {
        SQLite::Statement stmt(*m_database, std::string(kSqlMaxEventId));
        if (stmt.executeStep() && !stmt.getColumn(0).isNull()) {
            const auto maxId = static_cast<uint64_t>(stmt.getColumn(0).getInt64());
            m_nextEventId.store(maxId + 1, std::memory_order_relaxed);
            Logger::Debug("LocalTelemetryStore: recovered event-id counter at {}",
                          maxId + 1);
        }
        return true;
    } catch (const SQLite::Exception& ex) {
        Logger::Error("LocalTelemetryStore: event-id recovery failed – {}", ex.what());
        return false;
    }
}

// ============================================================================
// LocalTelemetryStoreImpl — WRITE OPERATIONS
// ============================================================================

bool LocalTelemetryStoreImpl::InsertEvent(const TelemetryEvent& event) {
    // Caller must hold m_dbMutex exclusively
    try {
        SQLite::Statement stmt(*m_database, std::string(kSqlInsertEvent));

        stmt.bind(1, static_cast<int64_t>(event.eventId));
        stmt.bind(2, TimePointToNanos(event.timestamp));
        stmt.bind(3, static_cast<int>(event.category));
        stmt.bind(4, static_cast<int>(event.severity));
        stmt.bind(5, static_cast<int>(event.processId));
        stmt.bind(6, static_cast<int>(event.parentProcessId));
        stmt.bind(7, static_cast<int>(event.threadId));
        stmt.bind(8, WideToUtf8(event.processName));
        stmt.bind(9, WideToUtf8(event.processPath));
        stmt.bind(10, WideToUtf8(event.userName));
        stmt.bind(11, event.sessionId);
        stmt.bind(12, event.mitreAttackId);
        stmt.bind(13, SerializePayload(event.payload));
        stmt.bind(14, SerializeMetadata(event.metadata));

        stmt.exec();
        return true;
    } catch (const SQLite::Exception& ex) {
        Logger::Error("LocalTelemetryStore: insert failed for event {} – code={} msg={}",
                      event.eventId, ex.getErrorCode(), ex.what());
        return false;
    }
}

bool LocalTelemetryStoreImpl::Store(TelemetryEvent&& event) {
    if (!IsInitialized()) {
        Logger::Error("LocalTelemetryStore::Store called before initialisation");
        return false;
    }

    m_eventsReceived.fetch_add(1, std::memory_order_relaxed);

    // Assign monotonic event id
    event.eventId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);

    // Default timestamp to now if unset
    if (event.timestamp == std::chrono::system_clock::time_point{})
        event.timestamp = std::chrono::system_clock::now();

    std::unique_lock lock(m_dbMutex);
    if (!InsertEvent(event)) {
        m_eventsDropped.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    m_eventsStored.fetch_add(1, std::memory_order_relaxed);

    const auto catIdx = static_cast<size_t>(event.category);
    if (catIdx < kEventCategoryCount)
        m_eventsByCategory[catIdx].fetch_add(1, std::memory_order_relaxed);

    return true;
}

bool LocalTelemetryStoreImpl::StoreBatch(std::vector<TelemetryEvent>&& events) {
    if (!IsInitialized()) {
        Logger::Error("LocalTelemetryStore::StoreBatch called before initialisation");
        return false;
    }

    if (events.empty()) return true;

    if (events.size() > kMaxBatchSize) {
        Logger::Warn("LocalTelemetryStore::StoreBatch capped batch from {} to {}",
                     events.size(), kMaxBatchSize);
        events.resize(kMaxBatchSize);
    }

    m_eventsReceived.fetch_add(events.size(), std::memory_order_relaxed);

    // Assign IDs and default timestamps
    for (auto& ev : events) {
        ev.eventId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
        if (ev.timestamp == std::chrono::system_clock::time_point{})
            ev.timestamp = std::chrono::system_clock::now();
    }

    std::unique_lock lock(m_dbMutex);

    uint64_t stored  = 0;
    uint64_t dropped = 0;

    try {
        SQLite::Transaction txn(*m_database);

        for (const auto& ev : events) {
            if (InsertEvent(ev)) {
                ++stored;
                const auto catIdx = static_cast<size_t>(ev.category);
                if (catIdx < kEventCategoryCount)
                    m_eventsByCategory[catIdx].fetch_add(1, std::memory_order_relaxed);
            } else {
                ++dropped;
            }
        }

        txn.commit();
    } catch (const SQLite::Exception& ex) {
        Logger::Error("LocalTelemetryStore: batch transaction failed – code={} msg={}",
                      ex.getErrorCode(), ex.what());
        m_eventsDropped.fetch_add(events.size(), std::memory_order_relaxed);
        return false;
    }

    m_eventsStored.fetch_add(stored, std::memory_order_relaxed);
    m_eventsDropped.fetch_add(dropped, std::memory_order_relaxed);

    return dropped == 0;
}

// ============================================================================
// LocalTelemetryStoreImpl — READ OPERATIONS
// ============================================================================

TelemetryEvent LocalTelemetryStoreImpl::ReadEvent(SQLite::Statement& stmt) const {
    TelemetryEvent ev;
    ev.eventId         = static_cast<uint64_t>(stmt.getColumn(0).getInt64());
    ev.timestamp       = NanosToTimePoint(stmt.getColumn(1).getInt64());
    ev.category        = static_cast<EventCategory>(stmt.getColumn(2).getInt());
    ev.severity        = static_cast<EventSeverity>(stmt.getColumn(3).getInt());
    ev.processId       = static_cast<uint32_t>(stmt.getColumn(4).getInt());
    ev.parentProcessId = static_cast<uint32_t>(stmt.getColumn(5).getInt());
    ev.threadId        = static_cast<uint32_t>(stmt.getColumn(6).getInt());
    ev.processName     = Utf8ToWide(SafeGetText(stmt, 7));
    ev.processPath     = Utf8ToWide(SafeGetText(stmt, 8));
    ev.userName        = Utf8ToWide(SafeGetText(stmt, 9));
    ev.sessionId       = SafeGetText(stmt, 10);
    ev.mitreAttackId   = SafeGetText(stmt, 11);
    ev.payload         = DeserializePayload(SafeGetText(stmt, 12));
    ev.metadata        = DeserializeMetadata(SafeGetText(stmt, 13));
    return ev;
}

std::optional<TelemetryEvent> LocalTelemetryStoreImpl::GetById(uint64_t eventId) {
    if (!IsInitialized()) {
        Logger::Error("LocalTelemetryStore::GetById called before initialisation");
        return std::nullopt;
    }

    std::unique_lock lock(m_dbMutex);
    try {
        SQLite::Statement stmt(*m_database, std::string(kSqlSelectById));
        stmt.bind(1, static_cast<int64_t>(eventId));
        if (stmt.executeStep())
            return ReadEvent(stmt);
        return std::nullopt;
    } catch (const SQLite::Exception& ex) {
        Logger::Error("LocalTelemetryStore::GetById({}) failed – code={} msg={}",
                      eventId, ex.getErrorCode(), ex.what());
        return std::nullopt;
    }
}

QueryResult LocalTelemetryStoreImpl::Query(const QueryParams& params) {
    QueryResult result;

    if (!IsInitialized()) {
        Logger::Error("LocalTelemetryStore::Query called before initialisation");
        return result;
    }

    // Cap maxResults to safety limit
    const uint32_t effectiveMax =
        (params.maxResults > 0 && params.maxResults <= kMaxQueryResults)
            ? params.maxResults
            : kMaxQueryResults;

    // Build dynamic WHERE clause with parameterised bindings
    std::string whereClause;
    std::vector<std::function<void(SQLite::Statement&, int&)>> binders;

    auto appendFilter = [&](std::string_view fragment,
                            auto binderFn) {
        whereClause += (whereClause.empty() ? " WHERE " : " AND ");
        whereClause += fragment;
        binders.emplace_back(std::move(binderFn));
    };

    if (params.category.has_value()) {
        appendFilter("category = ?",
            [cat = *params.category](SQLite::Statement& s, int& idx) {
                s.bind(idx++, static_cast<int>(cat));
            });
    }
    if (params.minSeverity.has_value()) {
        appendFilter("severity >= ?",
            [sev = *params.minSeverity](SQLite::Statement& s, int& idx) {
                s.bind(idx++, static_cast<int>(sev));
            });
    }
    if (params.processId.has_value()) {
        appendFilter("process_id = ?",
            [pid = *params.processId](SQLite::Statement& s, int& idx) {
                s.bind(idx++, static_cast<int>(pid));
            });
    }
    if (params.startTime.has_value()) {
        appendFilter("timestamp_ns >= ?",
            [ns = TimePointToNanos(*params.startTime)](SQLite::Statement& s, int& idx) {
                s.bind(idx++, ns);
            });
    }
    if (params.endTime.has_value()) {
        appendFilter("timestamp_ns <= ?",
            [ns = TimePointToNanos(*params.endTime)](SQLite::Statement& s, int& idx) {
                s.bind(idx++, ns);
            });
    }
    if (params.mitreAttackId.has_value()) {
        appendFilter("mitre_attack_id = ?",
            [mid = *params.mitreAttackId](SQLite::Statement& s, int& idx) {
                s.bind(idx++, mid);
            });
    }
    if (params.processNamePattern.has_value()) {
        appendFilter("process_name LIKE ?",
            [pat = WideToUtf8(*params.processNamePattern)](SQLite::Statement& s, int& idx) {
                s.bind(idx++, pat);
            });
    }

    std::unique_lock lock(m_dbMutex);
    try {
        // --- Total count ---
        {
            std::string countSql = "SELECT COUNT(*) FROM telemetry_events" + whereClause + ";";
            SQLite::Statement countStmt(*m_database, countSql);
            int bindIdx = 1;
            for (auto& binder : binders)
                binder(countStmt, bindIdx);
            if (countStmt.executeStep())
                result.totalCount = static_cast<uint64_t>(countStmt.getColumn(0).getInt64());
        }

        // --- Paged data ---
        {
            std::string dataSql =
                "SELECT event_id, timestamp_ns, category, severity,"
                "       process_id, parent_process_id, thread_id,"
                "       process_name, process_path, user_name,"
                "       session_id, mitre_attack_id,"
                "       payload_json, metadata_json"
                " FROM telemetry_events"
                + whereClause
                + " ORDER BY timestamp_ns DESC"
                  " LIMIT ? OFFSET ?;";

            SQLite::Statement dataStmt(*m_database, dataSql);
            int bindIdx = 1;
            for (auto& binder : binders)
                binder(dataStmt, bindIdx);
            dataStmt.bind(bindIdx++, static_cast<int>(effectiveMax));
            dataStmt.bind(bindIdx++, static_cast<int>(params.offset));

            result.events.reserve(
                static_cast<size_t>(std::min<uint64_t>(effectiveMax, result.totalCount)));

            while (dataStmt.executeStep())
                result.events.emplace_back(ReadEvent(dataStmt));
        }

        result.hasMore =
            (static_cast<uint64_t>(params.offset) + result.events.size()) < result.totalCount;

    } catch (const SQLite::Exception& ex) {
        Logger::Error("LocalTelemetryStore::Query failed – code={} msg={}",
                      ex.getErrorCode(), ex.what());
    }

    return result;
}

// ============================================================================
// LocalTelemetryStoreImpl — MAINTENANCE
// ============================================================================

uint64_t LocalTelemetryStoreImpl::PurgeOlderThan(
    std::chrono::system_clock::time_point cutoff)
{
    if (!IsInitialized()) {
        Logger::Error("LocalTelemetryStore::PurgeOlderThan called before initialisation");
        return 0;
    }

    const int64_t cutoffNs = TimePointToNanos(cutoff);

    std::unique_lock lock(m_dbMutex);
    try {
        SQLite::Statement stmt(*m_database, std::string(kSqlPurge));
        stmt.bind(1, cutoffNs);
        const int rows = stmt.exec();
        const auto purged = static_cast<uint64_t>(rows);

        if (purged > 0) {
            m_purgeCount.fetch_add(purged, std::memory_order_relaxed);
            Logger::Info("LocalTelemetryStore: purged {} events older than cutoff", purged);
        }

        // Periodic VACUUM
        const auto now = std::chrono::system_clock::now();
        const auto hoursSinceVacuum =
            std::chrono::duration_cast<std::chrono::hours>(now - m_lastVacuumTime).count();
        if (purged > 0 &&
            static_cast<uint32_t>(hoursSinceVacuum) >= m_config.vacuumIntervalHours) {
            Logger::Debug("LocalTelemetryStore: running VACUUM");
            m_database->exec("VACUUM;");
            m_lastVacuumTime = now;
        }

        return purged;
    } catch (const SQLite::Exception& ex) {
        Logger::Error("LocalTelemetryStore::PurgeOlderThan failed – code={} msg={}",
                      ex.getErrorCode(), ex.what());
        return 0;
    }
}

uint64_t LocalTelemetryStoreImpl::GetEventCount() const {
    if (!IsInitialized()) return 0;

    std::unique_lock lock(m_dbMutex);
    try {
        SQLite::Statement stmt(*m_database, std::string(kSqlCount));
        if (stmt.executeStep())
            return static_cast<uint64_t>(stmt.getColumn(0).getInt64());
    } catch (const SQLite::Exception& ex) {
        Logger::Error("LocalTelemetryStore::GetEventCount failed – {}", ex.what());
    }
    return 0;
}

uint64_t LocalTelemetryStoreImpl::GetStorageSizeBytes() const {
    if (!IsInitialized()) return 0;

    std::unique_lock lock(m_dbMutex);
    try {
        SQLite::Statement pageCountStmt(*m_database, "PRAGMA page_count;");
        SQLite::Statement pageSizeStmt(*m_database, "PRAGMA page_size;");

        uint64_t pageCount = 0;
        uint64_t pageSize  = 0;

        if (pageCountStmt.executeStep())
            pageCount = static_cast<uint64_t>(pageCountStmt.getColumn(0).getInt64());
        if (pageSizeStmt.executeStep())
            pageSize = static_cast<uint64_t>(pageSizeStmt.getColumn(0).getInt64());

        return pageCount * pageSize;
    } catch (const SQLite::Exception& ex) {
        Logger::Error("LocalTelemetryStore::GetStorageSizeBytes failed – {}", ex.what());
    }
    return 0;
}

// ============================================================================
// LocalTelemetryStoreImpl — STATISTICS
// ============================================================================

TelemetryStats LocalTelemetryStoreImpl::GetStats() const {
    TelemetryStats stats;
    stats.eventsReceived  = m_eventsReceived.load(std::memory_order_relaxed);
    stats.eventsStored    = m_eventsStored.load(std::memory_order_relaxed);
    stats.eventsDropped   = m_eventsDropped.load(std::memory_order_relaxed);
    stats.eventsFiltered  = m_eventsFiltered.load(std::memory_order_relaxed);
    stats.purgeCount      = m_purgeCount.load(std::memory_order_relaxed);

    for (size_t i = 0; i < kEventCategoryCount; ++i)
        stats.eventsByCategory[i] = m_eventsByCategory[i].load(std::memory_order_relaxed);

    stats.storageUsedBytes = GetStorageSizeBytes();
    return stats;
}

void LocalTelemetryStoreImpl::ResetStats() {
    m_eventsReceived.store(0, std::memory_order_relaxed);
    m_eventsStored.store(0, std::memory_order_relaxed);
    m_eventsDropped.store(0, std::memory_order_relaxed);
    m_eventsFiltered.store(0, std::memory_order_relaxed);
    m_purgeCount.store(0, std::memory_order_relaxed);
    for (auto& a : m_eventsByCategory)
        a.store(0, std::memory_order_relaxed);
}

// ============================================================================
// LocalTelemetryStoreImpl — BACKGROUND MAINTENANCE THREAD
// ============================================================================

void LocalTelemetryStoreImpl::MaintenanceLoop() {
    Logger::Debug("LocalTelemetryStore: maintenance thread started");

    while (!m_shutdownRequested.load(std::memory_order_acquire)) {
        // Sleep with interruptible wait
        {
            std::unique_lock lock(m_maintenanceMtx);
            m_maintenanceCv.wait_for(
                lock,
                std::chrono::seconds(kMaintenanceIntervalSec),
                [this] { return m_shutdownRequested.load(std::memory_order_acquire); });
        }

        if (m_shutdownRequested.load(std::memory_order_acquire))
            break;

        // -- Retention-based purge -----------------------------------------------
        if (m_config.retentionDays > 0) {
            const auto cutoff =
                std::chrono::system_clock::now()
                    - std::chrono::hours(
                          static_cast<uint64_t>(m_config.retentionDays) * 24ULL);
            const auto purged = PurgeOlderThan(cutoff);
            if (purged > 0)
                Logger::Info("LocalTelemetryStore maintenance: retention purge removed {} events",
                             purged);
        }

        // -- Storage-cap enforcement ---------------------------------------------
        const auto currentSize = GetStorageSizeBytes();
        if (currentSize > m_config.maxStorageSizeBytes) {
            Logger::Warn("LocalTelemetryStore: storage {} bytes exceeds cap {} bytes, "
                         "purging oldest events",
                         currentSize, m_config.maxStorageSizeBytes);

            // Remove oldest 10% by timestamp
            std::unique_lock lock(m_dbMutex);
            try {
                const auto eventCount = [&]() -> uint64_t {
                    SQLite::Statement stmt(*m_database, std::string(kSqlCount));
                    if (stmt.executeStep())
                        return static_cast<uint64_t>(stmt.getColumn(0).getInt64());
                    return 0;
                }();

                if (eventCount > 0) {
                    const auto purgeTarget = std::max<uint64_t>(eventCount / 10, 1);

                    std::string purgeSql =
                        "DELETE FROM telemetry_events WHERE event_id IN "
                        "(SELECT event_id FROM telemetry_events "
                        "ORDER BY timestamp_ns ASC LIMIT ?);";

                    SQLite::Statement purgeStmt(*m_database, purgeSql);
                    purgeStmt.bind(1, static_cast<int64_t>(purgeTarget));
                    const auto deleted = static_cast<uint64_t>(purgeStmt.exec());
                    m_purgeCount.fetch_add(deleted, std::memory_order_relaxed);

                    Logger::Info("LocalTelemetryStore: cap-enforcement purged {} events",
                                 deleted);
                }
            } catch (const SQLite::Exception& ex) {
                Logger::Error("LocalTelemetryStore: cap-enforcement purge failed – {}",
                              ex.what());
            }
        }
    }

    Logger::Debug("LocalTelemetryStore: maintenance thread exiting");
}

// ============================================================================
// LocalTelemetryStore — FORWARDING LAYER
// ============================================================================

LocalTelemetryStore::LocalTelemetryStore()
    : m_impl(std::make_unique<LocalTelemetryStoreImpl>()) {}

LocalTelemetryStore::~LocalTelemetryStore() = default;

bool LocalTelemetryStore::Initialize(const StoreConfig& config) {
    return m_impl->Initialize(config);
}

void LocalTelemetryStore::Shutdown() {
    m_impl->Shutdown();
}

bool LocalTelemetryStore::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

bool LocalTelemetryStore::Store(TelemetryEvent&& event) {
    return m_impl->Store(std::move(event));
}

bool LocalTelemetryStore::StoreBatch(std::vector<TelemetryEvent>&& events) {
    return m_impl->StoreBatch(std::move(events));
}

QueryResult LocalTelemetryStore::Query(const QueryParams& params) {
    return m_impl->Query(params);
}

std::optional<TelemetryEvent> LocalTelemetryStore::GetById(uint64_t eventId) {
    return m_impl->GetById(eventId);
}

uint64_t LocalTelemetryStore::PurgeOlderThan(
    std::chrono::system_clock::time_point cutoff)
{
    return m_impl->PurgeOlderThan(cutoff);
}

uint64_t LocalTelemetryStore::GetEventCount() const {
    return m_impl->GetEventCount();
}

uint64_t LocalTelemetryStore::GetStorageSizeBytes() const {
    return m_impl->GetStorageSizeBytes();
}

TelemetryStats LocalTelemetryStore::GetStats() const {
    return m_impl->GetStats();
}

void LocalTelemetryStore::ResetStats() {
    m_impl->ResetStats();
}

} // namespace ShadowStrike::Products::PhantomEDR::Telemetry
