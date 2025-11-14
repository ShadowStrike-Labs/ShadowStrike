#include "ThreatIntelDB.hpp"
#include "../Utils/JSONUtils.hpp"
#include"DatabaseManager.hpp"
#include"../Utils/SystemUtils.hpp"
#include"QuarantineDB.hpp"
#include"SignatureDB.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <fstream>
#include<yara.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif 

#include <Windows.h>
#include<winhttp.h>
#pragma comment(lib, "winhttp.lib")
#endif

namespace ShadowStrike {
    namespace Database {

        namespace {
            // Database schema version
            constexpr int THREAT_INTEL_SCHEMA_VERSION = 1;

            // SQL statements for IoC table
            constexpr const char* SQL_CREATE_IOC_TABLE = R"(
                CREATE TABLE IF NOT EXISTS ioc_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_type INTEGER NOT NULL,
                    ioc_value TEXT NOT NULL,
                    threat_type INTEGER NOT NULL,
                    severity INTEGER NOT NULL,
                    confidence INTEGER NOT NULL,
                    source INTEGER NOT NULL,
                    threat_name TEXT NOT NULL,
                    description TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    hit_count INTEGER DEFAULT 0,
                    is_active INTEGER DEFAULT 1,
                    is_false_positive INTEGER DEFAULT 0,
                    reference_url TEXT,
                    source_id TEXT,
                    campaign TEXT,
                    threat_actor TEXT,
                    risk_score INTEGER DEFAULT 0,
                    geolocation TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(ioc_value, ioc_type)
                );
            )";

            constexpr const char* SQL_CREATE_IOC_INDICES = R"(
                CREATE INDEX IF NOT EXISTS idx_ioc_value ON ioc_entries(ioc_value);
                CREATE INDEX IF NOT EXISTS idx_ioc_type ON ioc_entries(ioc_type);
                CREATE INDEX IF NOT EXISTS idx_ioc_threat_type ON ioc_entries(threat_type);
                CREATE INDEX IF NOT EXISTS idx_ioc_severity ON ioc_entries(severity);
                CREATE INDEX IF NOT EXISTS idx_ioc_source ON ioc_entries(source);
                CREATE INDEX IF NOT EXISTS idx_ioc_active ON ioc_entries(is_active);
                CREATE INDEX IF NOT EXISTS idx_ioc_expires ON ioc_entries(expires_at);
                CREATE INDEX IF NOT EXISTS idx_ioc_composite ON ioc_entries(ioc_type, ioc_value, is_active);
            )";

            constexpr const char* SQL_CREATE_IOC_TAGS_TABLE = R"(
                CREATE TABLE IF NOT EXISTS ioc_tags (
                    ioc_id INTEGER NOT NULL,
                    tag TEXT NOT NULL,
                    PRIMARY KEY (ioc_id, tag),
                    FOREIGN KEY (ioc_id) REFERENCES ioc_entries(id) ON DELETE CASCADE
                ) WITHOUT ROWID;
            )";

            constexpr const char* SQL_CREATE_IOC_METADATA_TABLE = R"(
                CREATE TABLE IF NOT EXISTS ioc_metadata (
                    ioc_id INTEGER NOT NULL,
                    metadata_key TEXT NOT NULL,
                    metadata_value TEXT,
                    PRIMARY KEY (ioc_id, metadata_key),
                    FOREIGN KEY (ioc_id) REFERENCES ioc_entries(id) ON DELETE CASCADE
                ) WITHOUT ROWID;
            )";

            // SQL statements for Signatures
            constexpr const char* SQL_CREATE_SIGNATURES_TABLE = R"(
                CREATE TABLE IF NOT EXISTS threat_signatures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    threat_type INTEGER NOT NULL,
                    severity INTEGER NOT NULL,
                    yara_rule TEXT,
                    clamav_signature TEXT,
                    binary_pattern BLOB,
                    regex_pattern TEXT,
                    author TEXT,
                    description TEXT,
                    is_enabled INTEGER DEFAULT 1,
                    detection_count INTEGER DEFAULT 0,
                    false_positive_count INTEGER DEFAULT 0,
                    accuracy REAL DEFAULT 0.0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_detection TEXT
                );
            )";

            // SQL statements for TTPs
            constexpr const char* SQL_CREATE_TTP_TABLE = R"(
                CREATE TABLE IF NOT EXISTS ttp_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mitre_id TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    phase INTEGER NOT NULL,
                    description TEXT,
                    severity INTEGER NOT NULL,
                    observed_count INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    last_observed TEXT
                );
            )";

            constexpr const char* SQL_CREATE_TTP_EXTENDED_TABLES = R"(
                CREATE TABLE IF NOT EXISTS ttp_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mitre_id TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    name TEXT NOT NULL,
                    phase INTEGER NOT NULL,
                    description TEXT,
                    severity INTEGER NOT NULL DEFAULT 2,
                    observed_count INTEGER DEFAULT 0,
                    detection_count INTEGER DEFAULT 0,
                    blocked_count INTEGER DEFAULT 0,
                    last_blocked TEXT,
                    is_critical INTEGER DEFAULT 0,
                    is_active INTEGER DEFAULT 1,
                    platform_windows INTEGER DEFAULT 1,
                    platform_linux INTEGER DEFAULT 0,
                    platform_macos INTEGER DEFAULT 0,
                    requires_admin INTEGER DEFAULT 0,
                    requires_user_interaction INTEGER DEFAULT 0,
                    network_required INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_observed TEXT,
                    data_sources TEXT,
                    detection_references TEXT
                );

                CREATE TABLE IF NOT EXISTS ttp_tactics (
                    ttp_id INTEGER NOT NULL,
                    tactic_name TEXT NOT NULL,
                    PRIMARY KEY (ttp_id, tactic_name),
                    FOREIGN KEY (ttp_id) REFERENCES ttp_entries(id) ON DELETE CASCADE
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS ttp_techniques (
                    ttp_id INTEGER NOT NULL,
                    technique_id TEXT NOT NULL,
                    technique_name TEXT NOT NULL,
                    PRIMARY KEY (ttp_id, technique_id),
                    FOREIGN KEY (ttp_id) REFERENCES ttp_entries(id) ON DELETE CASCADE
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS ttp_subtechniques (
                    ttp_id INTEGER NOT NULL,
                    technique_id TEXT NOT NULL,
                    subtechnique_id TEXT NOT NULL,
                    subtechnique_name TEXT NOT NULL,
                    PRIMARY KEY (ttp_id, subtechnique_id),
                    FOREIGN KEY (ttp_id) REFERENCES ttp_entries(id) ON DELETE CASCADE
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS ttp_detection_methods (
                    ttp_id INTEGER NOT NULL,
                    method_name TEXT NOT NULL,
                    method_type INTEGER NOT NULL,
                    confidence_level INTEGER,
                    PRIMARY KEY (ttp_id, method_name),
                    FOREIGN KEY (ttp_id) REFERENCES ttp_entries(id) ON DELETE CASCADE
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS ttp_mitigations (
                    ttp_id INTEGER NOT NULL,
                    mitigation_id TEXT NOT NULL,
                    mitigation_name TEXT NOT NULL,
                    mitigation_type INTEGER NOT NULL,
                    effectiveness INTEGER DEFAULT 3,
                    PRIMARY KEY (ttp_id, mitigation_id),
                    FOREIGN KEY (ttp_id) REFERENCES ttp_entries(id) ON DELETE CASCADE
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS ttp_related_threats (
                    ttp_id INTEGER NOT NULL,
                    threat_name TEXT NOT NULL,
                    threat_type INTEGER NOT NULL,
                    confidence INTEGER DEFAULT 3,
                    first_linked TEXT NOT NULL,
                    PRIMARY KEY (ttp_id, threat_name),
                    FOREIGN KEY (ttp_id) REFERENCES ttp_entries(id) ON DELETE CASCADE
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS ttp_malware_mapping (
                    ttp_id INTEGER NOT NULL,
                    malware_name TEXT NOT NULL,
                    malware_family TEXT,
                    PRIMARY KEY (ttp_id, malware_name),
                    FOREIGN KEY (ttp_id) REFERENCES ttp_entries(id) ON DELETE CASCADE
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS ttp_campaign_mapping (
                    ttp_id INTEGER NOT NULL,
                    campaign_id INTEGER NOT NULL,
                    first_observed TEXT NOT NULL,
                    last_observed TEXT NOT NULL,
                    usage_count INTEGER DEFAULT 1,
                    PRIMARY KEY (ttp_id, campaign_id),
                    FOREIGN KEY (ttp_id) REFERENCES ttp_entries(id) ON DELETE CASCADE
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS ttp_actor_mapping (
                    ttp_id INTEGER NOT NULL,
                    actor_id INTEGER NOT NULL,
                    confidence INTEGER DEFAULT 3,
                    first_observed TEXT NOT NULL,
                    PRIMARY KEY (ttp_id, actor_id),
                    FOREIGN KEY (ttp_id) REFERENCES ttp_entries(id) ON DELETE CASCADE
                ) WITHOUT ROWID;

                CREATE INDEX IF NOT EXISTS idx_ttp_mitre_id ON ttp_entries(mitre_id);
                CREATE INDEX IF NOT EXISTS idx_ttp_phase ON ttp_entries(phase);
                CREATE INDEX IF NOT EXISTS idx_ttp_severity ON ttp_entries(severity);
                CREATE INDEX IF NOT EXISTS idx_ttp_active ON ttp_entries(is_active);
                CREATE INDEX IF NOT EXISTS idx_ttp_observed ON ttp_entries(observed_count DESC);
                CREATE INDEX IF NOT EXISTS idx_ttp_detection ON ttp_entries(detection_count DESC);
                CREATE INDEX IF NOT EXISTS idx_ttp_critical ON ttp_entries(is_critical);
                CREATE INDEX IF NOT EXISTS idx_ttp_tactics_ttp ON ttp_tactics(ttp_id);
                CREATE INDEX IF NOT EXISTS idx_ttp_techniques_ttp ON ttp_techniques(ttp_id);
            )";
        

            // SQL statements for Threat Actors
            constexpr const char* SQL_CREATE_THREAT_ACTORS_TABLE = R"(
                CREATE TABLE IF NOT EXISTS threat_actors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    motivation TEXT,
                    origin TEXT,
                    threat_level INTEGER NOT NULL,
                    is_apt INTEGER DEFAULT 0,
                    is_active INTEGER DEFAULT 1,
                    first_seen TEXT NOT NULL,
                    last_activity TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            )";

            // SQL statements for Campaigns
            constexpr const char* SQL_CREATE_CAMPAIGNS_TABLE = R"(
                CREATE TABLE IF NOT EXISTS threat_campaigns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    primary_type INTEGER NOT NULL,
                    severity INTEGER NOT NULL,
                    start_date TEXT NOT NULL,
                    end_date TEXT,
                    is_active INTEGER DEFAULT 1,
                    objective TEXT,
                    attribution TEXT,
                    victim_count INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            )";

            // SQL statements for Reputation
            constexpr const char* SQL_CREATE_REPUTATION_TABLE = R"(
                CREATE TABLE IF NOT EXISTS reputation_scores (
                    identifier TEXT NOT NULL,
                    identifier_type INTEGER NOT NULL,
                    score INTEGER DEFAULT 50,
                    threat_level INTEGER DEFAULT 0,
                    positive_reports INTEGER DEFAULT 0,
                    negative_reports INTEGER DEFAULT 0,
                    total_reports INTEGER DEFAULT 0,
                    is_whitelisted INTEGER DEFAULT 0,
                    is_blacklisted INTEGER DEFAULT 0,
                    notes TEXT,
                    last_updated TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    PRIMARY KEY (identifier, identifier_type)
                ) WITHOUT ROWID;
            )";

            // UTF-8 conversion helpers
            std::string ToUTF8(std::wstring_view wstr) {
                if (wstr.empty()) return std::string();
                
                int size = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), 
                    static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
                if (size == 0) return std::string();
                
                std::string result(size, '\0');
                WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), 
                    &result[0], size, nullptr, nullptr);
                return result;
            }

            std::wstring ToWide(std::string_view str) {
                if (str.empty()) return std::wstring();
                
                int size = MultiByteToWideChar(CP_UTF8, 0, str.data(), 
                    static_cast<int>(str.size()), nullptr, 0);
                if (size == 0) return std::wstring();
                
                std::wstring result(size, L'\0');
                MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), 
                    &result[0], size);
                return result;
            }
        }

        // =========================================================================
        // ThreatIntelDB Implementation
        // =========================================================================

        static inline SignatureDB::SignatureSeverity MapThreatToSignatureSeverity(ThreatIntelDB::ThreatSeverity s) noexcept {

            using TS = ThreatIntelDB::ThreatSeverity;
            using SS = SignatureDB::SignatureSeverity;
            switch (s) {
            case TS::Info:     return SS::Info;
            case TS::Low:      return SS::Low;
            case TS::Medium:   return SS::Medium;
            case TS::High:     return SS::High;
            case TS::Critical: return SS::Critical;
            default:           return SS::Info;
            }
        }
        ThreatIntelDB& ThreatIntelDB::Instance() {
            static ThreatIntelDB instance;
            return instance;
        }

        ThreatIntelDB::ThreatIntelDB() {
        }

        ThreatIntelDB::~ThreatIntelDB() {
            Shutdown();
        }

        bool ThreatIntelDB::Initialize(const Config& config, DatabaseError* err) {
            if (m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"ThreatIntelDB", L"Already initialized");
                return true;
            }

            SS_LOG_INFO(L"ThreatIntelDB", L"Initializing ThreatIntelDB...");

            std::unique_lock<std::shared_mutex> lock(m_configMutex);
            m_config = config;

            // Initialize DatabaseManager
            DatabaseConfig dbConfig;
            dbConfig.databasePath = m_config.dbPath;
            dbConfig.enableWAL = m_config.enableWAL;
            dbConfig.cacheSizeKB = m_config.dbCacheSizeKB;
            dbConfig.maxConnections = m_config.maxConnections;
            dbConfig.minConnections = 2;

            if (!DatabaseManager::Instance().Initialize(dbConfig, err)) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"Failed to initialize DatabaseManager");
                return false;
            }

            // Create schema
            if (!createSchema(err)) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"Failed to create schema");
                return false;
            }

            // Start feed sync thread if enabled
            if (m_config.enableFeedSync) {
                m_shutdownFeedSync.store(false, std::memory_order_release);
                m_feedSyncThread = std::thread(&ThreatIntelDB::feedSyncThread, this);
            }

            // Initialize statistics
            recalculateStatistics(err);

            m_initialized.store(true, std::memory_order_release);

            SS_LOG_INFO(L"ThreatIntelDB", L"ThreatIntelDB initialized successfully");
            return true;
        }

        void ThreatIntelDB::Shutdown() {
            if (!m_initialized.load(std::memory_order_acquire)) {
                return;
            }

            SS_LOG_INFO(L"ThreatIntelDB", L"Shutting down ThreatIntelDB...");

            // Stop feed sync thread
            m_shutdownFeedSync.store(true, std::memory_order_release);
            m_feedSyncCV.notify_all();

            if (m_feedSyncThread.joinable()) {
                m_feedSyncThread.join();
            }

            // Clear caches
            {
                std::unique_lock<std::shared_mutex> lock(m_cacheMutex);
                m_iocCache.clear();
                m_signatureCache.clear();
                m_cacheSize = 0;
            }

            m_initialized.store(false, std::memory_order_release);

            SS_LOG_INFO(L"ThreatIntelDB", L"ThreatIntelDB shut down");
        }

        // =========================================================================
        // IoC Management
        // =========================================================================

        int64_t ThreatIntelDB::AddIoC(const IoC_Entry& ioc, DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Adding IoC: %ls", ioc.value.c_str());

            int64_t iocId = dbInsertIoC(ioc, err);
            if (iocId < 0) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"Failed to insert IoC");
                return -1;
            }

            // Cache the IoC
            if (m_config.enableCaching) {
                IoC_Entry cachedEntry = ioc;
                cachedEntry.id = iocId;
                cacheIoC(cachedEntry);
            }

            // Update statistics
            updateStatistics(ioc, true);

            SS_LOG_INFO(L"ThreatIntelDB", L"IoC added successfully. ID: %lld", iocId);
            return iocId;
        }

        bool ThreatIntelDB::UpdateIoC(const IoC_Entry& ioc, DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Updating IoC: %lld", ioc.id);

            if (!dbUpdateIoC(ioc, err)) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"Failed to update IoC");
                return false;
            }

            // Invalidate cache
            invalidateCache(ioc.id);
            
            // Re-cache
            if (m_config.enableCaching) {
                cacheIoC(ioc);
            }

            SS_LOG_INFO(L"ThreatIntelDB", L"IoC updated successfully");
            return true;
        }

        bool ThreatIntelDB::RemoveIoC(int64_t iocId, DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Removing IoC: %lld", iocId);

            if (!dbDeleteIoC(iocId, err)) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"Failed to delete IoC");
                return false;
            }

            // Invalidate cache
            invalidateCache(iocId);

            SS_LOG_INFO(L"ThreatIntelDB", L"IoC removed successfully");
            return true;
        }

        bool ThreatIntelDB::AddIoCBatch(const std::vector<IoC_Entry>& iocs, DatabaseError* err) {
            if (iocs.empty()) return true;

            SS_LOG_INFO(L"ThreatIntelDB", L"Batch adding %zu IoCs", iocs.size());

            auto trans = DatabaseManager::Instance().BeginTransaction(
                Transaction::Type::Immediate, err);
            
            if (!trans || !trans->IsActive()) {
                return false;
            }

            size_t successCount = 0;
            for (const auto& ioc : iocs) {
                if (dbInsertIoC(ioc, err) > 0) {
                    successCount++;
                } else {
                    SS_LOG_WARN(L"ThreatIntelDB", L"Failed to insert IoC: %ls", ioc.value.c_str());
                }
            }

            if (!trans->Commit(err)) {
                return false;
            }

            SS_LOG_INFO(L"ThreatIntelDB", L"Batch insert completed: %zu/%zu successful", 
                       successCount, iocs.size());
            return successCount > 0;
        }

        bool ThreatIntelDB::RemoveIoCBatch(const std::vector<int64_t>& iocIds, DatabaseError* err) {
            if (iocIds.empty()) return true;

            SS_LOG_INFO(L"ThreatIntelDB", L"Batch removing %zu IoCs", iocIds.size());

            auto trans = DatabaseManager::Instance().BeginTransaction(
                Transaction::Type::Immediate, err);
            
            if (!trans || !trans->IsActive()) {
                return false;
            }

            size_t successCount = 0;
            for (int64_t id : iocIds) {
                if (dbDeleteIoC(id, err)) {
                    successCount++;
                    invalidateCache(id);
                }
            }

            if (!trans->Commit(err)) {
                return false;
            }

            SS_LOG_INFO(L"ThreatIntelDB", L"Batch remove completed: %zu/%zu successful", 
                       successCount, iocIds.size());
            return successCount > 0;
        }

        std::optional<ThreatIntelDB::IoC_Entry> ThreatIntelDB::GetIoC(int64_t iocId, DatabaseError* err) {
            return dbSelectIoC(iocId, err);
        }

        std::vector<ThreatIntelDB::IoC_Entry> ThreatIntelDB::QueryIoCs(const QueryFilter& filter, 
                                                                        DatabaseError* err) {
            std::vector<std::string> params;
            std::string sql = buildIoCQuerySQL(filter, params);

            return dbSelectIoCs(sql, params, err);
        }

        std::optional<ThreatIntelDB::IoC_Entry> ThreatIntelDB::LookupByHash(std::wstring_view hash, 
                                                                             DatabaseError* err) {
            // Try cache first
            if (m_config.enableCaching) {
                auto cached = getCachedIoC(hash, IoC_Type::FileHash_SHA256);
                if (cached) {
                    std::lock_guard<std::mutex> lock(m_statsMutex);
                    m_stats.cacheHits++;
                    return cached;
                }
            }

            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_stats.cacheMisses++;

            // Lookup in database
            return LookupByValue(hash, IoC_Type::FileHash_SHA256, err);
        }

        std::optional<ThreatIntelDB::IoC_Entry> ThreatIntelDB::LookupByIP(std::wstring_view ip, 
                                                                           DatabaseError* err) {
            // Try cache first
            if (m_config.enableCaching) {
                auto cached = getCachedIoC(ip, IoC_Type::IP_Address);
                if (cached) {
                    std::lock_guard<std::mutex> lock(m_statsMutex);
                    m_stats.cacheHits++;
                    return cached;
                }
            }

            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_stats.cacheMisses++;

            return LookupByValue(ip, IoC_Type::IP_Address, err);
        }

        std::optional<ThreatIntelDB::IoC_Entry> ThreatIntelDB::LookupByDomain(std::wstring_view domain, 
                                                                               DatabaseError* err) {
            // Try cache first
            if (m_config.enableCaching) {
                auto cached = getCachedIoC(domain, IoC_Type::Domain);
                if (cached) {
                    std::lock_guard<std::mutex> lock(m_statsMutex);
                    m_stats.cacheHits++;
                    return cached;
                }
            }

            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_stats.cacheMisses++;

            return LookupByValue(domain, IoC_Type::Domain, err);
        }

        std::optional<ThreatIntelDB::IoC_Entry> ThreatIntelDB::LookupByValue(std::wstring_view value, 
                                                                              IoC_Type type, 
                                                                              DatabaseError* err) {
            std::string sql = R"(
                SELECT * FROM ioc_entries 
                WHERE ioc_value = ? AND ioc_type = ? AND is_active = 1
                LIMIT 1
            )";

            auto result = DatabaseManager::Instance().QueryWithParams(sql, err, 
                ToUTF8(value), static_cast<int>(type));

            if (result.Next()) {
                return rowToIoC(result);
            }

            return std::nullopt;
        }

        // =========================================================================
        // Internal Operations - Schema
        // =========================================================================

        bool ThreatIntelDB::createSchema(DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Creating schema...");

            // Create tables
            std::vector<std::string> schemas = {
                SQL_CREATE_IOC_TABLE,
                SQL_CREATE_IOC_INDICES,
                SQL_CREATE_IOC_TAGS_TABLE,
                SQL_CREATE_IOC_METADATA_TABLE,
                SQL_CREATE_SIGNATURES_TABLE,
                SQL_CREATE_TTP_TABLE,
                SQL_CREATE_THREAT_ACTORS_TABLE,
                SQL_CREATE_CAMPAIGNS_TABLE,
                SQL_CREATE_REPUTATION_TABLE
            };

            for (const auto& sql : schemas) {
                if (!DatabaseManager::Instance().Execute(sql, err)) {
                    SS_LOG_ERROR(L"ThreatIntelDB", L"Failed to execute schema SQL");
                    return false;
                }
            }

            SS_LOG_INFO(L"ThreatIntelDB", L"Schema created successfully");
            return true;
        }

        bool ThreatIntelDB::upgradeSchema(int currentVersion, int targetVersion, DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Upgrading schema from %d to %d", currentVersion, targetVersion);

            // TODO: Implement schema migrations
            
            return true;
        }

        // =========================================================================
        // Internal Operations - Database
        // ========================================================================

        int64_t ThreatIntelDB::dbInsertIoC(const IoC_Entry& ioc, DatabaseError* err) {
            std::string sql = R"(
                INSERT INTO ioc_entries (
                    ioc_type, ioc_value, threat_type, severity, confidence, source,
                    threat_name, description, first_seen, last_seen, expires_at,
                    hit_count, is_active, is_false_positive, reference_url, source_id,
                    campaign, threat_actor, risk_score, geolocation, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            )";

            auto now = timePointToString(std::chrono::system_clock::now());

            bool success = DatabaseManager::Instance().ExecuteWithParams(sql, err,
                static_cast<int>(ioc.type),
                ToUTF8(ioc.value),
                static_cast<int>(ioc.threatType),
                static_cast<int>(ioc.severity),
                static_cast<int>(ioc.confidence),
                static_cast<int>(ioc.source),
                ToUTF8(ioc.threatName),
                ToUTF8(ioc.description),
                timePointToString(ioc.firstSeen),
                timePointToString(ioc.lastSeen),
                timePointToString(ioc.expiresAt),
                static_cast<int64_t>(ioc.hitCount),
                ioc.isActive ? 1 : 0,
                ioc.isFalsePositive ? 1 : 0,
                ToUTF8(ioc.referenceUrl),
                ToUTF8(ioc.sourceId),
                ToUTF8(ioc.campaign),
                ToUTF8(ioc.threatActor),
                ioc.riskScore,
                ToUTF8(ioc.geolocation),
                now,
                now
            );

            if (!success) {
                return -1;
            }

            int64_t iocId = DatabaseManager::Instance().LastInsertRowId();

            // Insert tags
            if (!ioc.tags.empty()) {
                for (const auto& tag : ioc.tags) {
                    std::string tagSql = "INSERT INTO ioc_tags (ioc_id, tag) VALUES (?, ?)";
                    DatabaseManager::Instance().ExecuteWithParams(tagSql, nullptr, iocId, ToUTF8(tag));
                }
            }

            // Insert metadata
            if (!ioc.metadata.empty()) {
                for (const auto& [key, value] : ioc.metadata) {
                    std::string metaSql = "INSERT INTO ioc_metadata (ioc_id, metadata_key, metadata_value) VALUES (?, ?, ?)";
                    DatabaseManager::Instance().ExecuteWithParams(metaSql, nullptr, 
                        iocId, ToUTF8(key), ToUTF8(value));
                }
            }

            return iocId;
        }

        bool ThreatIntelDB::dbUpdateIoC(const IoC_Entry& ioc, DatabaseError* err) {
            std::string sql = R"(
                UPDATE ioc_entries SET
                    threat_type = ?, severity = ?, confidence = ?,
                    threat_name = ?, description = ?,
                    last_seen = ?, expires_at = ?,
                    hit_count = ?, is_active = ?, is_false_positive = ?,
                    reference_url = ?, source_id = ?, campaign = ?, threat_actor = ?,
                    risk_score = ?, geolocation = ?, updated_at = ?
                WHERE id = ?
            )";

            return DatabaseManager::Instance().ExecuteWithParams(sql, err,
                static_cast<int>(ioc.threatType),
                static_cast<int>(ioc.severity),
                static_cast<int>(ioc.confidence),
                ToUTF8(ioc.threatName),
                ToUTF8(ioc.description),
                timePointToString(ioc.lastSeen),
                timePointToString(ioc.expiresAt),
                static_cast<int64_t>(ioc.hitCount),
                ioc.isActive ? 1 : 0,
                ioc.isFalsePositive ? 1 : 0,
                ToUTF8(ioc.referenceUrl),
                ToUTF8(ioc.sourceId),
                ToUTF8(ioc.campaign),
                ToUTF8(ioc.threatActor),
                ioc.riskScore,
                ToUTF8(ioc.geolocation),
                timePointToString(std::chrono::system_clock::now()),
                ioc.id
            );
        }

        bool ThreatIntelDB::dbDeleteIoC(int64_t iocId, DatabaseError* err) {
            std::string sql = "DELETE FROM ioc_entries WHERE id = ?";
            return DatabaseManager::Instance().ExecuteWithParams(sql, err, iocId);
        }

        std::optional<ThreatIntelDB::IoC_Entry> ThreatIntelDB::dbSelectIoC(int64_t iocId, DatabaseError* err) {
            std::string sql = "SELECT * FROM ioc_entries WHERE id = ?";
            auto result = DatabaseManager::Instance().QueryWithParams(sql, err, iocId);

            if (result.Next()) {
                return rowToIoC(result);
            }

            return std::nullopt;
        }

        std::vector<ThreatIntelDB::IoC_Entry> ThreatIntelDB::dbSelectIoCs(
            std::string_view sql,
            const std::vector<std::string>& params,
            DatabaseError* err) {

            std::vector<IoC_Entry> results;

            if (sql.empty()) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"SQL query string is empty";
                    err->context = L"dbSelectIoCs";
                }
                SS_LOG_ERROR(L"ThreatIntelDB", L"dbSelectIoCs: Empty SQL query");
                return results;
            }

            if (params.empty()) {
                // No parameters - execute direct query
                SS_LOG_DEBUG(L"ThreatIntelDB", L"dbSelectIoCs: Executing parameterless query");

                try {
                    auto result = DatabaseManager::Instance().Query(sql, err);

                    while (result.Next()) {
                        try {
                            results.push_back(rowToIoC(result));
                        }
                        catch (const std::exception& ex) {
                            SS_LOG_WARN(L"ThreatIntelDB", L"dbSelectIoCs: Failed to parse row: %hs", ex.what());
                            if (err) {
                                err->context = L"rowToIoC";
                                err->message = L"Failed to parse database row: " + ToWide(ex.what());
                            }
                            continue; // Skip this row and continue with next
                        }
                    }
                }
                catch (const std::exception& ex) {
                    if (err) {
                        err->sqliteCode = SQLITE_ERROR;
                        err->message = L"Query execution failed: " + ToWide(ex.what());
                        err->query = ToWide(sql);
                        err->context = L"dbSelectIoCs";
                    }
                    SS_LOG_ERROR(L"ThreatIntelDB", L"dbSelectIoCs: Query execution failed: %hs", ex.what());
                    return results;
                }
            }
            else {
                // Parameters provided - use parameterized query
                SS_LOG_DEBUG(L"ThreatIntelDB", L"dbSelectIoCs: Executing parameterized query with %zu parameters", params.size());

                try {
                   
                    // Use prepared statement with parameter binding
                    auto conn = DatabaseManager::Instance().AcquireConnection(err);
                    if (!conn) {
                        if (err) {
                            err->sqliteCode = SQLITE_CANTOPEN;
                            err->message = L"Failed to acquire database connection";
                            err->context = L"dbSelectIoCs";
                        }
                        SS_LOG_ERROR(L"ThreatIntelDB", L"dbSelectIoCs: Failed to acquire connection");
                        return results;
                    }

                    // Create prepared statement
                    std::unique_ptr<SQLite::Statement> stmt;
                    try {
                        stmt = std::make_unique<SQLite::Statement>(*conn, sql.data());
                    }
                    catch (const SQLite::Exception& ex) {
                        DatabaseManager::Instance().ReleaseConnection(conn);
                        if (err) {
                            err->sqliteCode = ex.getErrorCode();
                            err->extendedCode = ex.getExtendedErrorCode();
                            err->message = L"Failed to prepare statement: " + ToWide(ex.what());
                            err->query = ToWide(sql);
                            err->context = L"SQLite::Statement creation";
                        }
                        SS_LOG_ERROR(L"ThreatIntelDB", L"dbSelectIoCs: Failed to prepare statement: %hs", ex.what());
                        return results;
                    }

                    // Bind parameters - parameter indices are 1-based in SQLite
                    try {
                        for (size_t i = 0; i < params.size(); ++i) {
                            int paramIndex = static_cast<int>(i) + 1; // SQLite uses 1-based indexing

                            const std::string& paramValue = params[i];

                            // Try to interpret as different types
                            // First attempt: Try as integer
                            char* endptr = nullptr;
                            long longVal = std::strtol(paramValue.c_str(), &endptr, 10);

                            if (*endptr == '\0' && endptr != paramValue.c_str()) {
                                // Successfully parsed as integer
                                stmt->bind(paramIndex, static_cast<int64_t>(longVal));
                                SS_LOG_DEBUG(L"ThreatIntelDB", L"dbSelectIoCs: Parameter %d bound as int64: %lld", paramIndex, longVal);
                            }
                            else {
                                // Try as double
                                endptr = nullptr;
                                double doubleVal = std::strtod(paramValue.c_str(), &endptr);

                                if (*endptr == '\0' && endptr != paramValue.c_str()) {
                                    // Successfully parsed as double
                                    stmt->bind(paramIndex, doubleVal);
                                    SS_LOG_DEBUG(L"ThreatIntelDB", L"dbSelectIoCs: Parameter %d bound as double: %.2f", paramIndex, doubleVal);
                                }
                                else {
                                    // Bind as string (most common case)
                                    stmt->bind(paramIndex, paramValue);
                                    SS_LOG_DEBUG(L"ThreatIntelDB", L"dbSelectIoCs: Parameter %d bound as string: %hs", paramIndex, paramValue.c_str());
                                }
                            }
                        }
                    }
                    catch (const std::exception& ex) {
                        DatabaseManager::Instance().ReleaseConnection(conn);
                        if (err) {
                            err->sqliteCode = SQLITE_ERROR;
                            err->message = L"Failed to bind parameters: " + ToWide(ex.what());
                            err->context = L"Parameter binding";
                        }
                        SS_LOG_ERROR(L"ThreatIntelDB", L"dbSelectIoCs: Failed to bind parameters: %hs", ex.what());
                        return results;
                    }

                    // Execute query and fetch results
                    try {
                        while (stmt->executeStep()) {
                            try {
                                // Create a QueryResult wrapper for the statement
                                QueryResult qr(std::move(stmt));
                                results.push_back(rowToIoC(qr));
                            }
                            catch (const std::exception& ex) {
                                SS_LOG_WARN(L"ThreatIntelDB", L"dbSelectIoCs: Failed to parse row: %hs", ex.what());
                                if (err) {
                                    err->message = L"Failed to parse result row: " + ToWide(ex.what());
                                }
                                continue;
                            }
                        }
                    }
                    catch (const SQLite::Exception& ex) {
                        DatabaseManager::Instance().ReleaseConnection(conn);
                        if (err) {
                            err->sqliteCode = ex.getErrorCode();
                            err->extendedCode = ex.getExtendedErrorCode();
                            err->message = L"Query execution failed: " + ToWide(ex.what());
                            err->query = ToWide(sql);
                            err->context = L"executeStep";
                        }
                        SS_LOG_ERROR(L"ThreatIntelDB", L"dbSelectIoCs: Query execution failed: %hs", ex.what());
                        return results;
                    }

                    DatabaseManager::Instance().ReleaseConnection(conn);
                }
                catch (const std::exception& ex) {
                    if (err) {
                        err->sqliteCode = SQLITE_ERROR;
                        err->message = L"Parameterized query failed: " + ToWide(ex.what());
                        err->query = ToWide(sql);
                        err->context = L"dbSelectIoCs parameterized";
                    }
                    SS_LOG_ERROR(L"ThreatIntelDB", L"dbSelectIoCs: Parameterized query failed: %hs", ex.what());
                    return results;
                }
            }

            // Log successful query execution
            {
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.totalQueries++;
            }

            SS_LOG_DEBUG(L"ThreatIntelDB", L"dbSelectIoCs: Successfully retrieved %zu IoC entries", results.size());
            return results;
        }

        // =========================================================================
        // Helper Functions
        // =========================================================================

        ThreatIntelDB::IoC_Entry ThreatIntelDB::rowToIoC(const QueryResult& result) {
            IoC_Entry ioc;
            
            ioc.id = result.GetInt64("id");
            ioc.type = static_cast<IoC_Type>(result.GetInt("ioc_type"));
            ioc.value = result.GetWString("ioc_value");
            ioc.threatType = static_cast<ThreatType>(result.GetInt("threat_type"));
            ioc.severity = static_cast<ThreatSeverity>(result.GetInt("severity"));
            ioc.confidence = static_cast<ThreatConfidence>(result.GetInt("confidence"));
            ioc.source = static_cast<ThreatSource>(result.GetInt("source"));
            
            ioc.threatName = result.GetWString("threat_name");
            ioc.description = result.GetWString("description");
            
            ioc.firstSeen = stringToTimePoint(result.GetString("first_seen"));
            ioc.lastSeen = stringToTimePoint(result.GetString("last_seen"));
            ioc.expiresAt = stringToTimePoint(result.GetString("expires_at"));
            
            ioc.hitCount = result.GetInt64("hit_count");
            ioc.isActive = result.GetInt("is_active") != 0;
            ioc.isFalsePositive = result.GetInt("is_false_positive") != 0;
            
            ioc.referenceUrl = result.GetWString("reference_url");
            ioc.sourceId = result.GetWString("source_id");
            ioc.campaign = result.GetWString("campaign");
            ioc.threatActor = result.GetWString("threat_actor");
            
            ioc.riskScore = result.GetInt("risk_score");
            ioc.geolocation = result.GetWString("geolocation");
            
            ioc.createdAt = stringToTimePoint(result.GetString("created_at"));
            ioc.updatedAt = stringToTimePoint(result.GetString("updated_at"));
            
            return ioc;
        }

      
        std::chrono::system_clock::time_point ThreatIntelDB::stringToTimePoint(std::string_view str) {
            if (str.empty()) {
                return std::chrono::system_clock::now();
            }

            std::tm tm = {};
            std::string str_copy(str);
            
            // Use sscanf_s instead of std::get_time for better compatibility
#ifdef _WIN32
            int year, month, day, hour, minute, second;
            if (sscanf_s(str_copy.c_str(), "%d-%d-%d %d:%d:%d", 
                        &year, &month, &day, &hour, &minute, &second) == 6) {
                tm.tm_year = year - 1900;
                tm.tm_mon = month - 1;
                tm.tm_mday = day;
                tm.tm_hour = hour;
                tm.tm_min = minute;
                tm.tm_sec = second;
                tm.tm_isdst = -1;
                
                auto time_t_val = std::mktime(&tm);
                return std::chrono::system_clock::from_time_t(time_t_val);
            }
#else
            std::istringstream ss(str_copy);
            ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
            if (!ss.fail()) {
                auto time_t_val = std::mktime(&tm);
                return std::chrono::system_clock::from_time_t(time_t_val);
            }
#endif
            
            // Return current time if parsing failed
            return std::chrono::system_clock::now();
        }

        std::string ThreatIntelDB::wstringToUtf8(std::wstring_view wstr) const {
            return ToUTF8(wstr);
        }

        std::wstring ThreatIntelDB::utf8ToWstring(std::string_view str) const {
            return ToWide(str);
        }

        std::string ThreatIntelDB::vectorToString(const std::vector<std::wstring>& vec) const {
            if (vec.empty()) return std::string();
            
            std::wostringstream oss;
            for (size_t i = 0; i < vec.size(); ++i) {
                if (i > 0) oss << L"|";
                oss << vec[i];
            }
            return ToUTF8(oss.str());
        }

        std::vector<std::wstring> ThreatIntelDB::stringToVector(std::string_view str) const {
            std::vector<std::wstring> result;
            if (str.empty()) return result;

            std::wstring wstr = ToWide(str);
            size_t start = 0;
            size_t end = wstr.find(L'|');

            while (end != std::wstring::npos) {
                result.push_back(wstr.substr(start, end - start));
                start = end + 1;
                end = wstr.find(L'|', start);
            }

            result.push_back(wstr.substr(start));
            return result;
        }

        // =========================================================================
        // Query Builders
        // =========================================================================

        std::string ThreatIntelDB::buildIoCQuerySQL(const QueryFilter& filter, std::vector<std::string>& outParams) {
            std::ostringstream sql;

            // Determine if we need JOIN for tags
            bool needsTagJoin = filter.tagPattern && !filter.tagPattern->empty();

            if (needsTagJoin) {
                sql << "SELECT DISTINCT ioc_entries.* FROM ioc_entries "
                    << "INNER JOIN ioc_tags ON ioc_entries.id = ioc_tags.ioc_id "
                    << "WHERE 1=1";
            }
            else {
                sql << "SELECT * FROM ioc_entries WHERE 1=1";
            }

            if (filter.threatType) {
                sql << " AND ioc_entries.threat_type = ?";
                outParams.push_back(std::to_string(static_cast<int>(*filter.threatType)));
            }

            if (filter.minSeverity) {
                sql << " AND ioc_entries.severity >= ?";
                outParams.push_back(std::to_string(static_cast<int>(*filter.minSeverity)));
            }

            if (filter.iocType) {
                sql << " AND ioc_entries.ioc_type = ?";
                outParams.push_back(std::to_string(static_cast<int>(*filter.iocType)));
            }

            if (filter.source) {
                sql << " AND ioc_entries.source = ?";
                outParams.push_back(std::to_string(static_cast<int>(*filter.source)));
            }

            if (filter.minConfidence) {
                sql << " AND ioc_entries.confidence >= ?";
                outParams.push_back(std::to_string(static_cast<int>(*filter.minConfidence)));
            }

            if (filter.firstSeenAfter) {
                sql << " AND ioc_entries.first_seen >= ?";
                outParams.push_back(timePointToString(*filter.firstSeenAfter));
            }

            if (filter.firstSeenBefore) {
                sql << " AND ioc_entries.first_seen <= ?";
                outParams.push_back(timePointToString(*filter.firstSeenBefore));
            }

            if (filter.lastSeenAfter) {
                sql << " AND ioc_entries.last_seen >= ?";
                outParams.push_back(timePointToString(*filter.lastSeenAfter));
            }

            if (filter.campaignName) {
                sql << " AND ioc_entries.campaign LIKE ?";
                outParams.push_back(ToUTF8(L"%" + *filter.campaignName + L"%"));
            }

            if (filter.threatActor) {
                sql << " AND ioc_entries.threat_actor LIKE ?";
                outParams.push_back(ToUTF8(L"%" + *filter.threatActor + L"%"));
            }

            if (filter.tagPattern) {
                sql << " AND ioc_tags.tag LIKE ?";
                outParams.push_back(ToUTF8(L"%" + *filter.tagPattern + L"%"));
            }

            if (filter.activeOnly) {
                sql << " AND ioc_entries.is_active = 1";
            }

            if (filter.excludeFalsePositives) {
                sql << " AND ioc_entries.is_false_positive = 0";
            }

            // Ordering - with table prefix when JOIN is used
            if (filter.sortByRiskScore) {
                sql << " ORDER BY ioc_entries.risk_score";
            }
            else {
                sql << " ORDER BY ioc_entries.created_at";
            }

            sql << (filter.sortDescending ? " DESC" : " ASC");

            // Limit
            sql << " LIMIT " << filter.maxResults;

            return sql.str();
        }

        std::string ThreatIntelDB::buildIoCCountSQL(const QueryFilter& filter, std::vector<std::string>& outParams) {
            std::ostringstream sql;
            sql << "SELECT COUNT(*) FROM ioc_entries WHERE 1=1";

            if (filter.threatType) {
                sql << " AND threat_type = ?";
                outParams.push_back(std::to_string(static_cast<int>(*filter.threatType)));
            }

            if (filter.minSeverity) {
                sql << " AND severity >= ?";
                outParams.push_back(std::to_string(static_cast<int>(*filter.minSeverity)));
            }

            if (filter.iocType) {
                sql << " AND ioc_type = ?";
                outParams.push_back(std::to_string(static_cast<int>(*filter.iocType)));
            }

            if (filter.source) {
                sql << " AND source = ?";
                outParams.push_back(std::to_string(static_cast<int>(*filter.source)));
            }

            if (filter.activeOnly) {
                sql << " AND is_active = 1";
            }

            if (filter.excludeFalsePositives) {
                sql << " AND is_false_positive = 0";
            }

            return sql.str();
        }

        // =========================================================================
        // Cache Operations
        // =========================================================================

        std::optional<ThreatIntelDB::IoC_Entry> ThreatIntelDB::getCachedIoC(std::wstring_view value, IoC_Type type) {
            if (!m_config.enableCaching) {
                return std::nullopt;
            }

            std::unique_lock<std::shared_mutex> lock(m_cacheMutex);

            std::wstring cacheKey = std::to_wstring(static_cast<int>(type)) + L"_" + std::wstring(value);

            auto it = m_iocCache.find(cacheKey);
            if (it == m_iocCache.end()) {
                return std::nullopt;
            }

            const auto& cachedEntry = it->second;

            // Check if entry is expired
            if (isExpiredEntry(cachedEntry)) {
                // Remove expired entry
                m_iocCache.erase(it);
                m_lruIterators.erase(cacheKey);
                return std::nullopt;
            }

            // Update access order (move to front)
            updateAccessOrder(cacheKey);

            return cachedEntry;
        }
        void ThreatIntelDB::updateAccessOrder(const std::wstring& key) {
            auto it = m_lruIterators.find(key);
            if (it == m_lruIterators.end()) {
                return;
            }

            auto nodeIt = it->second;

            // If already at front, no need to move
            if (nodeIt == m_lruList.begin()) {
                // Just update access time
                nodeIt->accessTime = std::chrono::steady_clock::now();
                nodeIt->accessCount++;
                return;
            }

            // Move to front (most recently used)
            LRUCacheNode node = *nodeIt;
            node.accessTime = std::chrono::steady_clock::now();
            node.accessCount++;

            m_lruList.erase(nodeIt);
            m_lruList.push_front(node);
            m_lruIterators[key] = m_lruList.begin();

            SS_LOG_DEBUG(L"ThreatIntelDB", L"Updated LRU order for: %ls (access count: %zu)",
                key.c_str(), node.accessCount);
        }

        void ThreatIntelDB::evictLRUEntry() {
            if (m_lruList.empty() || m_iocCache.empty()) {
                return;
            }

            // Get least recently used entry (at back of list)
            const auto& lruNode = m_lruList.back();
            const std::wstring& victimKey = lruNode.key;

            // Find and remove from cache
            auto cacheIt = m_iocCache.find(victimKey);
            if (cacheIt != m_iocCache.end()) {
                const auto& victimEntry = cacheIt->second;

                SS_LOG_INFO(L"ThreatIntelDB",
                    L"Evicting LRU entry: %ls (type: %d, last_access: %zu accesses ago)",
                    victimKey.c_str(),
                    static_cast<int>(victimEntry.type),
                    std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::steady_clock::now() - lruNode.accessTime).count());

                m_iocCache.erase(cacheIt);
                m_totalEvictions++;
            }

            // Remove from LRU list
            m_lruList.pop_back();
            m_lruIterators.erase(victimKey);

            // Update cache size
            m_cacheSize = m_iocCache.size();
        }

        bool ThreatIntelDB::isExpiredEntry(const IoC_Entry& entry) const {
            auto now = std::chrono::system_clock::now();
            return entry.expiresAt <= now;
        }

        void ThreatIntelDB::pruneExpiredEntries() {
            std::vector<std::wstring> expiredKeys;

            // Find all expired entries
            for (const auto& [key, entry] : m_iocCache) {
                if (isExpiredEntry(entry)) {
                    expiredKeys.push_back(key);
                }
            }

            // Remove expired entries
            for (const auto& key : expiredKeys) {
                auto cacheIt = m_iocCache.find(key);
                if (cacheIt != m_iocCache.end()) {
                    m_iocCache.erase(cacheIt);
                }

                auto lruIt = m_lruIterators.find(key);
                if (lruIt != m_lruIterators.end()) {
                    m_lruList.erase(lruIt->second);
                    m_lruIterators.erase(lruIt);
                }
            }

            m_cacheSize = m_iocCache.size();

            if (!expiredKeys.empty()) {
                SS_LOG_INFO(L"ThreatIntelDB", L"Pruned %zu expired cache entries", expiredKeys.size());
            }
        }

        const ThreatIntelDB::LRUCacheNode& ThreatIntelDB::getLRUNode(const std::wstring& key) const {
            auto it = m_lruIterators.find(key);
            if (it != m_lruIterators.end()) {
                return *it->second;
            }
            static const LRUCacheNode dummy(L"");
            return dummy;
        }

        ThreatIntelDB::CacheMetrics ThreatIntelDB::getCacheMetrics() const {
            std::shared_lock<std::shared_mutex> lock(m_cacheMutex);

            CacheMetrics metrics;
            metrics.totalAccesses = 0;
            metrics.evictedEntries = m_totalEvictions;
            metrics.peakCacheSize = m_config.maxCacheEntries;

            // Calculate total accesses and hit/miss stats
            for (const auto& node : m_lruList) {
                metrics.totalAccesses += node.accessCount;
            }

            // Calculate hit rate
            uint64_t totalOps = metrics.hitCount + metrics.missCount;
            if (totalOps > 0) {
                metrics.hitRate = (static_cast<double>(metrics.hitCount) / totalOps) * 100.0;
            }

            return metrics;
        }

        void ThreatIntelDB::invalidateCache(int64_t iocId) {
            std::unique_lock<std::shared_mutex> lock(m_cacheMutex);

            // Find entry by ID
            for (auto it = m_iocCache.begin(); it != m_iocCache.end(); ++it) {
                if (it->second.id == iocId) {
                    const auto& key = it->first;

                    // Remove from cache
                    m_iocCache.erase(it);

                    // Remove from LRU
                    auto lruIt = m_lruIterators.find(key);
                    if (lruIt != m_lruIterators.end()) {
                        m_lruList.erase(lruIt->second);
                        m_lruIterators.erase(lruIt);
                    }

                    m_cacheSize = m_iocCache.size();

                    SS_LOG_DEBUG(L"ThreatIntelDB", L"Invalidated cache entry for IoC ID: %lld", iocId);
                    return;
                }
            }
        }

        void ThreatIntelDB::invalidateCacheByValue(std::wstring_view value, IoC_Type type) {
            std::unique_lock<std::shared_mutex> lock(m_cacheMutex);

            std::wstring cacheKey = std::to_wstring(static_cast<int>(type)) + L"_" + std::wstring(value);

            auto it = m_iocCache.find(cacheKey);
            if (it != m_iocCache.end()) {
                m_iocCache.erase(it);

                auto lruIt = m_lruIterators.find(cacheKey);
                if (lruIt != m_lruIterators.end()) {
                    m_lruList.erase(lruIt->second);
                    m_lruIterators.erase(lruIt);
                }

                m_cacheSize = m_iocCache.size();

                SS_LOG_DEBUG(L"ThreatIntelDB", L"Invalidated cache entry: %ls", cacheKey.c_str());
            }
        }


        void ThreatIntelDB::cacheIoC(const IoC_Entry& ioc) {
            if (!m_config.enableCaching) return;

            std::unique_lock<std::shared_mutex> lock(m_cacheMutex);

            // Build cache key: type_value
            std::wstring cacheKey = std::to_wstring(static_cast<int>(ioc.type)) + L"_" + ioc.value;

            // Check if entry already exists (update case)
            auto existingIt = m_iocCache.find(cacheKey);
            if (existingIt != m_iocCache.end()) {
                // Update existing entry
                existingIt->second = ioc;
                updateAccessOrder(cacheKey);

                SS_LOG_DEBUG(L"ThreatIntelDB", L"Updated cached IoC: %ls", cacheKey.c_str());
                return;
            }

            // Check cache size limit - evict if necessary
            if (m_iocCache.size() >= m_config.maxCacheEntries) {
                // LRU eviction: delete least recently used entry
                evictLRUEntry();
            }

            // Insert new entry
            try {
                m_iocCache[cacheKey] = ioc;

                // Add to LRU tracking
                m_lruList.push_front(LRUCacheNode(cacheKey));
                m_lruIterators[cacheKey] = m_lruList.begin();

                // Update cache size
                m_cacheSize = m_iocCache.size();

                SS_LOG_DEBUG(L"ThreatIntelDB", L"Cached IoC: %ls (cache size: %zu/%zu)",
                    cacheKey.c_str(), m_iocCache.size(), m_config.maxCacheEntries);
            }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"Cache insertion failed: %ls",
                    utf8ToWstring(ex.what()).c_str());
            }

            // Periodically prune expired entries
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - m_lastCachePrune).count() > 300) {
                // Prune every 5 minutes
                pruneExpiredEntries();
                m_lastCachePrune = now;
            }
        }

        // =========================================================================
        // Statistics
        // =========================================================================

        void ThreatIntelDB::updateStatistics(const IoC_Entry& ioc, bool isNew) {
            std::lock_guard<std::mutex> lock(m_statsMutex);

            if (isNew) {
                m_stats.totalIoCs++;
                
                if (ioc.isActive) {
                    m_stats.activeIoCs++;
                }
                
                if (ioc.isFalsePositive) {
                    m_stats.falsePositives++;
                }

                // Update counters by type, severity, source
                if (static_cast<size_t>(ioc.type) < 256) {
                    m_stats.iocsByType[static_cast<size_t>(ioc.type)]++;
                }
                
                if (static_cast<size_t>(ioc.severity) < 6) {
                    m_stats.iocsBySeverity[static_cast<size_t>(ioc.severity)]++;
                }
                
                if (static_cast<size_t>(ioc.source) < 256) {
                    m_stats.iocsBySource[static_cast<size_t>(ioc.source)]++;
                }
            }

            m_stats.totalQueries++;
        }

        void ThreatIntelDB::recalculateStatistics(DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Recalculating statistics...");

            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_stats = Statistics{}; // Reset

            // Count total IoCs
            std::string sql = "SELECT COUNT(*) FROM ioc_entries";
            auto result = DatabaseManager::Instance().Query(sql, err);
            if (result.Next()) {
                m_stats.totalIoCs = result.GetInt64(0);
            }

            // Count active IoCs
            sql = "SELECT COUNT(*) FROM ioc_entries WHERE is_active = 1";
            result = DatabaseManager::Instance().Query(sql, err);
            if (result.Next()) {
                m_stats.activeIoCs = result.GetInt64(0);
            }

            // Count false positives
            sql = "SELECT COUNT(*) FROM ioc_entries WHERE is_false_positive = 1";
            result = DatabaseManager::Instance().Query(sql, err);
            if (result.Next()) {
                m_stats.falsePositives = result.GetInt64(0);
            }

            // Get oldest and newest IoC
            sql = "SELECT MIN(created_at), MAX(created_at) FROM ioc_entries";
            result = DatabaseManager::Instance().Query(sql, err);
            if (result.Next()) {
                if (!result.IsNull(0)) {
                    m_stats.oldestIoC = stringToTimePoint(result.GetString(0));
                }
                if (!result.IsNull(1)) {
                    m_stats.newestIoC = stringToTimePoint(result.GetString(1));
                }
            }

            // Calculate cache hit rate
            if (m_stats.cacheHits + m_stats.cacheMisses > 0) {
                m_stats.cacheHitRate = static_cast<double>(m_stats.cacheHits) / 
                                      static_cast<double>(m_stats.cacheHits + m_stats.cacheMisses);
            }

            SS_LOG_INFO(L"ThreatIntelDB", L"Statistics recalculated. Total IoCs: %llu", m_stats.totalIoCs);
        }

        // =========================================================================
        // Feed Sync Thread
        // =========================================================================

        void ThreatIntelDB::feedSyncThread() {
            SS_LOG_INFO(L"ThreatIntelDB", L"Feed sync thread started");

            while (!m_shutdownFeedSync.load(std::memory_order_acquire)) {
                std::unique_lock<std::mutex> lock(m_feedSyncMutex);
                
                // Wait for sync interval or shutdown
                if (m_feedSyncCV.wait_for(lock, m_config.feedSyncInterval, 
                    [this] { return m_shutdownFeedSync.load(std::memory_order_acquire); })) {
                    break; // Shutdown requested
                }

                if (m_shutdownFeedSync.load(std::memory_order_acquire)) {
                    break;
                }

                // Perform feed sync
                SS_LOG_INFO(L"ThreatIntelDB", L"Starting periodic feed sync...");
                
                DatabaseError err;
                if (SyncThreatFeeds(&err)) {
                    std::lock_guard<std::mutex> statsLock(m_statsMutex);
                    m_stats.feedSyncCount++;
                    m_stats.lastFeedSync = std::chrono::system_clock::now();
                } else {
                    std::lock_guard<std::mutex> statsLock(m_statsMutex);
                    m_stats.failedSyncCount++;
                    SS_LOG_ERROR(L"ThreatIntelDB", L"Feed sync failed: %ls", err.message.c_str());
                }
            }

            SS_LOG_INFO(L"ThreatIntelDB", L"Feed sync thread stopped");
        }

        bool ThreatIntelDB::SyncThreatFeeds(DatabaseError* err) {
            if (!m_config.enableFeedSync) {
                return true;
            }

            SS_LOG_INFO(L"ThreatIntelDB", L"Syncing threat feeds...");

            bool allSuccess = true;

            // Sync each enabled source
            for (const auto& source : m_config.enabledSources) {
                if (!syncSingleFeed(source, err)) {
                    SS_LOG_WARN(L"ThreatIntelDB", L"Failed to sync feed: %d", static_cast<int>(source));
                    allSuccess = false;
                }
            }

            return allSuccess;
        }

       // ============================================================================
       // Main Feed Sync Function
       // ============================================================================

        bool ThreatIntelDB::syncSingleFeed(ThreatSource source, DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Syncing feed source: %d", static_cast<int>(source));

			// 1. Create the appopriate feed provider
            auto provider = CreateProvider(source, err);
            if (!provider) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"Failed to create feed provider for source: %d",
                    static_cast<int>(source));
                return false;
            }

			// 2. download and parse the feed
            SS_LOG_DEBUG(L"ThreatIntelDB", L"Fetching data from %ls...", provider->GetProviderName().c_str());

            std::vector<IoC_Entry> newIoCs;
            try {
                newIoCs = provider->FetchAndParse(err);
            }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"Feed parsing failed: %ls",
                    ToWide(ex.what()).c_str());
                if (err) {
                    err->message = L"Feed parsing exception";
                }
                return false;
            }

            if (newIoCs.empty()) {
                SS_LOG_WARN(L"ThreatIntelDB", L"No IoCs fetched from %ls",
                    provider->GetProviderName().c_str());
				return true;  // this could be valid if no new IoCs are available
            }

            SS_LOG_INFO(L"ThreatIntelDB", L"Fetched %zu IoCs from %ls",
                newIoCs.size(), provider->GetProviderName().c_str());

			// 3. merge and update the database
            if (!MergeAndUpdateIoCs(newIoCs, source, err)) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"Failed to merge IoCs into database");
                return false;
            }

			// 4. update the feed sync statistics
            {
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.feedSyncCount++;
                m_stats.lastFeedSync = std::chrono::system_clock::now();
            }

            SS_LOG_INFO(L"ThreatIntelDB", L"Successfully synced %zu IoCs from %ls",
                newIoCs.size(), provider->GetProviderName().c_str());

            return true;
        }

        // ============================================================================
        // Provider Factory
        // ============================================================================

        std::unique_ptr<ThreatIntelDB::FeedProvider> ThreatIntelDB::CreateProvider(
            ThreatSource source,
            DatabaseError* err) {

			//read the api keys from the config
            std::wstring virustotalKey = m_config.apiKey;  
            std::wstring alienVaultKey = L"";              

            switch (source) {
            case ThreatSource::VirusTotal:
                if (virustotalKey.empty()) {
                    if (err) err->message = L"VirusTotal API key not configured";
                    return nullptr;
                }
                return std::make_unique<VirusTotalProvider>(virustotalKey);

            case ThreatSource::AbuseIPDB:
                return std::make_unique<AbuseChProvider>();

            case ThreatSource::AlienVault_OTX:
                if (alienVaultKey.empty()) {
                    if (err) err->message = L"AlienVault API key not configured";
                    return nullptr;
                }
                return std::make_unique<AlienVaultProvider>(alienVaultKey);

            default:
                if (err) {
                    err->message = L"Unsupported feed source";
                }
                return nullptr;
            }
        }

        // ============================================================================
        // HTTP Request Implementation
        // ============================================================================

bool ThreatIntelDB::PerformHttpRequest(
    std::wstring_view url,
    std::string& outResponse,
    const std::map<std::wstring, std::wstring>& headers,
    DatabaseError* err) {

    try {
        HINTERNET hSession = nullptr;
        HINTERNET hConnect = nullptr;
        HINTERNET hRequest = nullptr;

        hSession = WinHttpOpen(
            L"ShadowStrike/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0
        );

        if (!hSession) {
            if (err) err->message = L"WinHttpOpen failed";
            return false;
        }

        // Parse the URL
        URL_COMPONENTS urlComp = {};
        urlComp.dwStructSize = sizeof(urlComp);
        urlComp.dwSchemeLength = (DWORD)-1;
        urlComp.dwHostNameLength = (DWORD)-1;
        urlComp.dwUrlPathLength = (DWORD)-1;

        if (!WinHttpCrackUrl(url.data(), (DWORD)url.size(), 0, &urlComp)) {
            WinHttpCloseHandle(hSession);
            if (err) err->message = L"WinHttpCrackUrl failed";
            return false;
        }

        // Connect
        hConnect = WinHttpConnect(
            hSession,
            std::wstring(urlComp.lpszHostName, urlComp.dwHostNameLength).c_str(),
            urlComp.nPort,
            0
        );

        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            if (err) err->message = L"WinHttpConnect failed";
            return false;
        }

        // Create request
        hRequest = WinHttpOpenRequest(
            hConnect,
            L"GET",
            std::wstring(urlComp.lpszUrlPath, urlComp.dwUrlPathLength).c_str(),
            nullptr,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0
        );

        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            if (err) err->message = L"WinHttpOpenRequest failed";
            return false;
        }

        // Add Headers
        for (const auto& [key, value] : headers) {
            std::wstring headerLine = key + L": " + value;
            if (!WinHttpAddRequestHeaders(
                hRequest,
                headerLine.c_str(),
                (DWORD)headerLine.size(),
                WINHTTP_ADDREQ_FLAG_ADD)) {
                SS_LOG_WARN(L"ThreatIntelDB", L"Failed to add header: %ls", key.c_str());
            }
        }

        // Send Request - DÜZELTILMIÞ MANTIK
        if (!WinHttpSendRequest(
            hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0,
            WINHTTP_NO_REQUEST_DATA,
            0,
            0,
            0)) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            if (err) err->message = L"WinHttpSendRequest failed";
            return false;
        }

        // Receive Response
        if (!WinHttpReceiveResponse(hRequest, nullptr)) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            if (err) err->message = L"WinHttpReceiveResponse failed";
            return false;
        }

        // HTTP status check
        DWORD dwStatusCode = 0;
        DWORD dwSize = sizeof(dwStatusCode);
        if (!WinHttpQueryHeaders(
            hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &dwStatusCode,
            &dwSize,
            WINHTTP_NO_HEADER_INDEX)) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            if (err) err->message = L"Failed to get HTTP status code";
            return false;
        }

        if (dwStatusCode != 200) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            if (err) {
                err->message = L"HTTP error: " + std::to_wstring(dwStatusCode);
            }
            SS_LOG_WARN(L"ThreatIntelDB", L"HTTP response: %ld", dwStatusCode);
            return false;
        }

        // Read Body (as chunks)
        std::string response;
        DWORD dwSize2 = 0;
        LPSTR pszOutBuffer = nullptr;

        while (WinHttpQueryDataAvailable(hRequest, &dwSize2)) {
            if (dwSize2 == 0) break;

            pszOutBuffer = new char[dwSize2 + 1];
            if (!pszOutBuffer) {
                WinHttpCloseHandle(hRequest);
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                if (err) err->message = L"Memory allocation failed";
                return false;
            }

            DWORD dwDownloaded = 0;
            if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize2, &dwDownloaded)) {
                delete[] pszOutBuffer;
                WinHttpCloseHandle(hRequest);
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                if (err) err->message = L"WinHttpReadData failed";
                return false;
            }

            pszOutBuffer[dwDownloaded] = '\0';
            response.append(pszOutBuffer);

            delete[] pszOutBuffer;
        }

        outResponse = response;

        // Cleanup
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        return true;
    }
    catch (const std::exception& ex) {
        if (err) {
            err->message = L"HTTP request exception";
        }
        SS_LOG_ERROR(L"ThreatIntelDB", L"HTTP request failed: %s", ex.what());
        return false;
    }
}
        // ============================================================================
        // VirusTotal Provider Implementation
        // ============================================================================

        ThreatIntelDB::VirusTotalProvider::VirusTotalProvider(std::wstring_view apiKey)
            : m_apiKey(apiKey) {
        }

        std::wstring ThreatIntelDB::VirusTotalProvider::GetEndpoint() const {
            return L"https://www.virustotal.com/api/v3";
        }

        std::vector<ThreatIntelDB::IoC_Entry> ThreatIntelDB::VirusTotalProvider::FetchAndParse(
            DatabaseError* err) {

            std::vector<IoC_Entry> ioCs;

			// download the malware file hashes from VirusTotal
            std::wstring url = GetEndpoint() + L"/intelligence/search?query=type:file%20tags:malware";

            std::map<std::wstring, std::wstring> headers;
            headers[L"x-apikey"] = m_apiKey;

            std::string response;
            if (!PerformHttpRequest(url, response, headers, err)) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"VirusTotal API request failed");
                return ioCs;
            }

			//parse JSON response
            try {
                auto json = nlohmann::json::parse(response);

                if (!json.contains("data") || !json["data"].is_array()) {
                    SS_LOG_WARN(L"ThreatIntelDB", L"Invalid VirusTotal response format");
                    return ioCs;
                }

                for (const auto& item : json["data"]) {
                    try {
                        IoC_Entry ioc;
						ioc.id = 0;  // will be assigned by DB
                        ioc.type = IoC_Type::FileHash_SHA256;
                        ioc.value = std::wstring(item["attributes"]["sha256"].get<std::string>().begin(),
                            item["attributes"]["sha256"].get<std::string>().end());

                        ioc.threatType = ThreatType::Malware;
                        ioc.severity = ThreatSeverity::High;
                        ioc.confidence = ThreatConfidence::High;
                        ioc.source = ThreatSource::VirusTotal;
                        ioc.threatName = L"VirusTotal Detected Malware";
                        ioc.sourceId = std::wstring(item["id"].get<std::string>().begin(),
                            item["id"].get<std::string>().end());
                        ioc.createdAt = std::chrono::system_clock::now();
                        ioc.updatedAt = std::chrono::system_clock::now();
                        ioc.isActive = true;
                        ioc.isFalsePositive = false;
                        ioc.riskScore = 85;  // VirusTotal detection

                        ioCs.push_back(std::move(ioc));
                    }
                    catch (const std::exception& ex) {
                        SS_LOG_WARN(L"ThreatIntelDB", L"Failed to parse VirusTotal item: %s", ex.what());
                        continue;
                    }
                }

                SS_LOG_DEBUG(L"ThreatIntelDB", L"Parsed %zu IoCs from VirusTotal", ioCs.size());
            }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"JSON parsing failed: %s", ex.what());
                if (err) err->message = L"JSON parsing failed";
                return ioCs;
            }

            return ioCs;
        }

        // ============================================================================
        // Abuse.ch Provider Implementation
        // ============================================================================

        std::wstring ThreatIntelDB::AbuseChProvider::GetEndpoint() const {
            return L"https://urlhaus-api.abuse.ch/v1";
        }

        std::vector<ThreatIntelDB::IoC_Entry> ThreatIntelDB::AbuseChProvider::FetchAndParse(
            DatabaseError* err) {

            std::vector<IoC_Entry> ioCs;

			//download the bad urls from Abuse.ch
            std::string response;
            if (!PerformHttpRequest(
                L"https://urlhaus-api.abuse.ch/v1/urls/recent/",
                response,
                {},
                err)) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"Abuse.ch API request failed");
                return ioCs;
            }

            try {
                auto json = nlohmann::json::parse(response);

                if (json.value("query_status", "") != "ok") {
                    SS_LOG_WARN(L"ThreatIntelDB", L"Abuse.ch API error response");
                    return ioCs;
                }

                if (!json.contains("urls") || !json["urls"].is_array()) {
                    return ioCs;
                }

                for (const auto& item : json["urls"]) {
                    try {
                        IoC_Entry ioc;
                        ioc.id = 0;
                        ioc.type = IoC_Type::URL;
                        ioc.value = std::wstring(item["url"].get<std::string>().begin(),
                            item["url"].get<std::string>().end());

                        ioc.threatType = ThreatType::Phishing;  // URLhaus phishing'leri tutar
                        ioc.severity = ThreatSeverity::High;
                        ioc.confidence = ThreatConfidence::High;
                        ioc.source = ThreatSource::AbuseIPDB;
                        ioc.threatName = ToWide(item.value("threat", std::string("Malicious URL")));
                        ioc.createdAt = std::chrono::system_clock::now();
                        ioc.updatedAt = std::chrono::system_clock::now();
                        ioc.isActive = true;
                        ioc.riskScore = 90;

                        ioCs.push_back(std::move(ioc));
                    }
                    catch (const std::exception&) {
                        continue;
                    }
                }

                SS_LOG_DEBUG(L"ThreatIntelDB", L"Parsed %zu IoCs from Abuse.ch", ioCs.size());
            }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"Abuse.ch JSON parsing failed: %s", ex.what());
                return ioCs;
            }

            return ioCs;
        }

        // ============================================================================
        // AlienVault Provider Implementation
        // ============================================================================

        ThreatIntelDB::AlienVaultProvider::AlienVaultProvider(std::wstring_view apiKey)
            : m_apiKey(apiKey) {
        }

        std::wstring ThreatIntelDB::AlienVaultProvider::GetEndpoint() const {
            return L"https://otx.alienvault.com/api/v1";
        }

        std::vector<ThreatIntelDB::IoC_Entry> ThreatIntelDB::AlienVaultProvider::FetchAndParse(
            DatabaseError* err) {

            std::vector<IoC_Entry> ioCs;

            std::map<std::wstring, std::wstring> headers;
            headers[L"X-OTX-API-KEY"] = m_apiKey;

            std::string response;
            if (!PerformHttpRequest(
                L"https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50",
                response,
                headers,
                err)) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"AlienVault API request failed");
                return ioCs;
            }

            try {
                auto json = nlohmann::json::parse(response);

                if (!json.contains("results") || !json["results"].is_array()) {
                    return ioCs;
                }

                for (const auto& pulse : json["results"]) {
                    if (!pulse.contains("indicators") || !pulse["indicators"].is_array()) {
                        continue;
                    }

                    for (const auto& indicator : pulse["indicators"]) {
                        try {
                            IoC_Entry ioc;
                            ioc.id = 0;

                            std::string type = indicator.value("type", std::string(""));
                            if (type == "IPv4") {
                                ioc.type = IoC_Type::IP_Address;
                            }
                            else if (type == "domain") {
                                ioc.type = IoC_Type::Domain;
                            }
                            else if (type == "FileHash-MD5") {
                                ioc.type = IoC_Type::FileHash_MD5;
                            }
                            else {
                                continue;
                            }

                            ioc.value = std::wstring(indicator["indicator"].get<std::string>().begin(),
                                indicator["indicator"].get<std::string>().end());
                            ioc.threatType = ThreatType::C2Server;
                            ioc.severity = ThreatSeverity::High;
                            ioc.confidence = ThreatConfidence::High;
                            ioc.source = ThreatSource::AlienVault_OTX;
                            ioc.threatName = std::wstring(pulse["name"].get<std::string>().begin(),
                                pulse["name"].get<std::string>().end());
                            ioc.createdAt = std::chrono::system_clock::now();
                            ioc.updatedAt = std::chrono::system_clock::now();
                            ioc.isActive = true;
                            ioc.riskScore = 80;

                            ioCs.push_back(std::move(ioc));
                        }
                        catch (const std::exception&) {
                            continue;
                        }
                    }
                }

                SS_LOG_DEBUG(L"ThreatIntelDB", L"Parsed %zu IoCs from AlienVault", ioCs.size());
            }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"AlienVault JSON parsing failed: %s", ex.what());
                return ioCs;
            }

            return ioCs;
        }

        // ============================================================================
        // Merge and Update Logic
        // ============================================================================

        bool ThreatIntelDB::MergeAndUpdateIoCs(
            const std::vector<IoC_Entry>& newIoCs,
            ThreatSource source,
            DatabaseError* err) {

            if (newIoCs.empty()) {
                return true;
            }

            SS_LOG_INFO(L"ThreatIntelDB", L"Merging %zu IoCs into database", newIoCs.size());
            
            auto trans = ShadowStrike::Database::DatabaseManager::Instance().BeginTransaction(ShadowStrike::Database::Transaction::Type::Immediate,err);
            if (!trans || !trans->IsActive()) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"Failed to begin transaction for merge");
                return false;
            }

            size_t added = 0;
            size_t updated = 0;
            size_t skipped = 0;

            for (const auto& newIoc : newIoCs) {
                // Duplicate check
                std::vector<IoC_Entry> existing = QueryIoCs(
                    QueryFilter{
                        .excludeFalsePositives = false
                    },
                    err
                );

                bool found = false;
                for (const auto& existing_ioc : existing) {
                    if (existing_ioc.value == newIoc.value && existing_ioc.type == newIoc.type) {
						// Update existing IoC
                        IoC_Entry update = existing_ioc;
                        update.lastSeen = std::chrono::system_clock::now();
                        update.hitCount++;

                        if (UpdateIoC(update, err)) {
                            updated++;
                        }
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    // add new IoC
                    if (AddIoC(newIoc, err) > 0) {
                        added++;
                    }
                }
                else {
                    skipped++;
                }
            }

            if (!trans->Commit(err)) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"Failed to commit merge transaction");
                return false;
            }

            SS_LOG_INFO(L"ThreatIntelDB",
                L"Merge complete: added=%zu, updated=%zu, skipped=%zu",
                added, updated, skipped);

            return true;
        }

        // =========================================================================
        // Bulk Lookups 
        // =========================================================================
        std::vector<ThreatIntelDB::IoC_Entry> ThreatIntelDB::LookupHashesBatch(
            const std::vector<std::wstring>& hashes,
            DatabaseError* err) {

            SS_LOG_INFO(L"ThreatIntelDB", L"Bulk hash lookup: %zu hashes", hashes.size());

            std::vector<IoC_Entry> results;
            if (hashes.empty()) {
                return results;
            }

            results.reserve(std::min(hashes.size(), size_t(1000)));

            try {
                // Input validation
                if (hashes.size() > 10000) {
                    SS_LOG_WARN(L"ThreatIntelDB", L"Hash batch size %zu exceeds recommended limit (10000)",
                        hashes.size());
                    if (err) {
                        err->sqliteCode = SQLITE_MISUSE;
                        err->message = L"Hash batch size exceeds maximum allowed (10000)";
                        err->context = L"LookupHashesBatch";
                    }
                    return results;
                }

                // Acquire connection
                auto conn = DatabaseManager::Instance().AcquireConnection(err);
                if (!conn) {
                    if (err) {
                        err->sqliteCode = SQLITE_CANTOPEN;
                        err->message = L"Failed to acquire database connection";
                        err->context = L"LookupHashesBatch";
                    }
                    SS_LOG_ERROR(L"ThreatIntelDB", L"LookupHashesBatch: Failed to acquire connection");
                    return results;
                }

                try {
                    // Build parameterized SQL query dynamically
                    std::ostringstream sqlBuilder;
                    sqlBuilder << "SELECT * FROM ioc_entries WHERE ioc_type IN ("
                        << static_cast<int>(IoC_Type::FileHash_MD5) << ", "
                        << static_cast<int>(IoC_Type::FileHash_SHA1) << ", "
                        << static_cast<int>(IoC_Type::FileHash_SHA256) << ", "
                        << static_cast<int>(IoC_Type::FileHash_SHA512)
                        << ") AND is_active = 1 AND ioc_value IN (";

                    // Add placeholders for each hash
                    for (size_t i = 0; i < hashes.size(); ++i) {
                        if (i > 0) sqlBuilder << ", ";
                        sqlBuilder << "?";
                    }
                    sqlBuilder << ")";

                    std::string sqlQuery = sqlBuilder.str();

                    // Create prepared statement
                    std::unique_ptr<SQLite::Statement> stmt;
                    try {
                        stmt = std::make_unique<SQLite::Statement>(*conn, sqlQuery);
                    }
                    catch (const SQLite::Exception& ex) {
                        DatabaseManager::Instance().ReleaseConnection(conn);
                        if (err) {
                            err->sqliteCode = ex.getErrorCode();
                            err->extendedCode = ex.getExtendedErrorCode();
                            err->message = L"Failed to prepare statement: " + ToWide(ex.what());
                            err->query = ToWide(sqlQuery);
                            err->context = L"SQLite::Statement creation";
                        }
                        SS_LOG_ERROR(L"ThreatIntelDB", L"LookupHashesBatch: Failed to prepare statement: %hs", ex.what());
                        return results;
                    }

                    // Bind hash parameters (1-indexed in SQLite)
                    try {
                        for (size_t i = 0; i < hashes.size(); ++i) {
                            int paramIndex = static_cast<int>(i) + 1;
                            stmt->bind(paramIndex, ToUTF8(hashes[i]));
                            SS_LOG_DEBUG(L"ThreatIntelDB", L"LookupHashesBatch: Parameter %d bound with hash", paramIndex);
                        }
                    }
                    catch (const std::exception& ex) {
                        DatabaseManager::Instance().ReleaseConnection(conn);
                        if (err) {
                            err->sqliteCode = SQLITE_ERROR;
                            err->message = L"Failed to bind parameters: " + ToWide(ex.what());
                            err->context = L"Parameter binding";
                        }
                        SS_LOG_ERROR(L"ThreatIntelDB", L"LookupHashesBatch: Failed to bind parameters: %hs", ex.what());
                        return results;
                    }

                    // Execute query and fetch results
                    try {
                        while (stmt->executeStep()) {
                            try {
                                // Create a QueryResult wrapper for the statement
                                QueryResult qr(std::move(stmt));
                                results.push_back(rowToIoC(qr));
                            }
                            catch (const std::exception& ex) {
                                SS_LOG_WARN(L"ThreatIntelDB", L"LookupHashesBatch: Failed to parse row: %hs", ex.what());
                                if (err) {
                                    err->message = L"Failed to parse result row: " + ToWide(ex.what());
                                }
                                continue;
                            }
                        }
                    }
                    catch (const SQLite::Exception& ex) {
                        DatabaseManager::Instance().ReleaseConnection(conn);
                        if (err) {
                            err->sqliteCode = ex.getErrorCode();
                            err->extendedCode = ex.getExtendedErrorCode();
                            err->message = L"Query execution failed: " + ToWide(ex.what());
                            err->query = ToWide(sqlQuery);
                            err->context = L"executeStep";
                        }
                        SS_LOG_ERROR(L"ThreatIntelDB", L"LookupHashesBatch: Query execution failed: %hs", ex.what());
                        return results;
                    }

                    DatabaseManager::Instance().ReleaseConnection(conn);
                }
                catch (const std::exception& ex) {
                    DatabaseManager::Instance().ReleaseConnection(conn);
                    if (err) {
                        err->sqliteCode = SQLITE_ERROR;
                        err->message = L"Batch lookup failed: " + ToWide(ex.what());
                        err->query = L"LookupHashesBatch";
                        err->context = L"LookupHashesBatch exception";
                    }
                    SS_LOG_ERROR(L"ThreatIntelDB", L"LookupHashesBatch: Exception: %hs", ex.what());
                    return results;
                }

                // Log successful query execution
                {
                    std::lock_guard<std::mutex> lock(m_statsMutex);
                    m_stats.totalQueries++;
                    m_stats.lookupCount++;
                    m_stats.lastlookuptime = std::chrono::system_clock::now();
                    m_stats.totalItemsretrieved += results.size();
                }

                SS_LOG_DEBUG(L"ThreatIntelDB", L"LookupHashesBatch: Successfully retrieved %zu IoC entries", results.size());
                return results;
            }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"LookupHashesBatch: Outer exception: %hs", ex.what());
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Batch lookup exception: " + ToWide(ex.what());
                    err->context = L"LookupHashesBatch";
                }
                results.clear();
            }

            return results;
        }

        std::vector<ThreatIntelDB::IoC_Entry> ThreatIntelDB::LookupIPsBatch(
            const std::vector<std::wstring>& ips,
            DatabaseError* err) {

            SS_LOG_INFO(L"ThreatIntelDB", L"Bulk IP lookup: %zu IPs", ips.size());

            std::vector<IoC_Entry> results;
            results.reserve(ips.size());

            if (ips.empty()) return results;

            // Build parameterized SQL query dynamically
            std::ostringstream sqlBuilder;
            sqlBuilder << "SELECT * FROM ioc_entries WHERE ioc_type = "
                << static_cast<int>(IoC_Type::IP_Address)
                << " AND is_active = 1 AND ioc_value IN (";

            for (size_t i = 0; i < ips.size(); ++i) {
                if (i > 0) sqlBuilder << ", ";
                sqlBuilder << "?";
            }
            sqlBuilder << ")";

            std::string sqlQuery = sqlBuilder.str();

            // Acquire connection
            auto conn = DatabaseManager::Instance().AcquireConnection(err);
            if (!conn) {
                if (err) {
                    err->sqliteCode = SQLITE_CANTOPEN;
                    err->message = L"Failed to acquire database connection";
                }
                return results;
            }

            try {
                std::unique_ptr<SQLite::Statement> stmt = std::make_unique<SQLite::Statement>(*conn, sqlQuery);

                // Bind IP parameters
                for (size_t i = 0; i < ips.size(); ++i) {
                    stmt->bind(static_cast<int>(i) + 1, ToUTF8(ips[i]));
                }

                while (stmt->executeStep()) {
                    results.push_back(rowToIoC(QueryResult(std::move(stmt))));
                }
            }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"LookupIPsBatch failed: %hs", ex.what());
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = ToWide(ex.what());
                }
            }

            DatabaseManager::Instance().ReleaseConnection(conn);

            SS_LOG_INFO(L"ThreatIntelDB", L"Found %zu/%zu IPs", results.size(), ips.size());
            return results;
        }
        // =========================================================================
        // IoC Enrichment & Expiration
        // =========================================================================

        bool ThreatIntelDB::EnrichIoC(int64_t iocId,
                                      const std::unordered_map<std::wstring, std::wstring>& metadata,
                                      DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Enriching IoC: %lld with %zu metadata entries", 
                       iocId, metadata.size());

            if (metadata.empty()) return true;

            // Insert/update metadata
            for (const auto& [key, value] : metadata) {
                std::string sql = R"(
                    INSERT INTO ioc_metadata (ioc_id, metadata_key, metadata_value)
                    VALUES (?, ?, ?)
                    ON CONFLICT(ioc_id, metadata_key) 
                    DO UPDATE SET metadata_value = excluded.metadata_value
                )";

                if (!DatabaseManager::Instance().ExecuteWithParams(sql, err,
                    iocId, ToUTF8(key), ToUTF8(value))) {
                    return false;
                }
            }

            return true;
        }

        bool ThreatIntelDB::MarkExpired(int64_t iocId, DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Marking IoC as expired: %lld", iocId);

            std::string sql = "UPDATE ioc_entries SET is_active = 0 WHERE id = ?";
            return DatabaseManager::Instance().ExecuteWithParams(sql, err, iocId);
        }

        bool ThreatIntelDB::CleanupExpiredIoCs(DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Cleaning up expired IoCs...");

            std::string now = timePointToString(std::chrono::system_clock::now());
            
            std::string sql = "DELETE FROM ioc_entries WHERE expires_at < ? AND is_active = 0";
            
            if (!DatabaseManager::Instance().ExecuteWithParams(sql, err, now)) {
                return false;
            }

            int deleted = DatabaseManager::Instance().GetChangedRowCount();
            SS_LOG_INFO(L"ThreatIntelDB", L"Cleaned up %d expired IoCs", deleted);
            
            return true;
        }

        bool ThreatIntelDB::ExtendExpiration(int64_t iocId, 
                                             std::chrono::hours extension, 
                                             DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Extending expiration for IoC: %lld by %lld hours", 
                       iocId, extension.count());

            // Get current expiration
            auto iocOpt = GetIoC(iocId, err);
            if (!iocOpt) return false;

            // Calculate new expiration
            auto newExpiration = iocOpt->expiresAt + extension;

            std::string sql = "UPDATE ioc_entries SET expires_at = ? WHERE id = ?";
            return DatabaseManager::Instance().ExecuteWithParams(sql, err,
                timePointToString(newExpiration), iocId);
        }

        // =========================================================================
        // False Positive Management
        // =========================================================================

        bool ThreatIntelDB::MarkFalsePositive(int64_t iocId, 
                                              bool isFP, 
                                              std::wstring_view reason,
                                              DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Marking IoC %lld as %ls: %ls", 
                       iocId, isFP ? L"FALSE POSITIVE" : L"VALID", reason.data());

            std::string sql = R"(
                UPDATE ioc_entries 
                SET is_false_positive = ?, notes = ? 
                WHERE id = ?
            )";

            std::wstring notes = isFP ? 
                L"[FALSE POSITIVE] " + std::wstring(reason) :
                L"[VALID] " + std::wstring(reason);

            return DatabaseManager::Instance().ExecuteWithParams(sql, err,
                isFP ? 1 : 0, ToUTF8(notes), iocId);
        }

        std::vector<ThreatIntelDB::IoC_Entry> ThreatIntelDB::GetFalsePositives(
            size_t maxCount, 
            DatabaseError* err) {
            
            std::string sql = R"(
                SELECT * FROM ioc_entries 
                WHERE is_false_positive = 1 
                ORDER BY updated_at DESC 
                LIMIT ?
            )";

            std::vector<IoC_Entry> results;
            auto result = DatabaseManager::Instance().QueryWithParams(sql, err, 
                static_cast<int>(maxCount));

            while (result.Next()) {
                results.push_back(rowToIoC(result));
            }

            return results;
        }

        // =========================================================================
        // Threat Signatures - FULL CRUD
        // =========================================================================

        int64_t ThreatIntelDB::AddSignature(const ThreatSignature& signature, DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Adding signature: %ls", signature.name.c_str());

            std::string sql = R"(
                INSERT INTO threat_signatures (
                    name, threat_type, severity, yara_rule, clamav_signature,
                    binary_pattern, regex_pattern, author, description,
                    is_enabled, detection_count, false_positive_count, accuracy,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            )";

            auto now = timePointToString(std::chrono::system_clock::now());

            bool success = DatabaseManager::Instance().ExecuteWithParams(sql, err,
                ToUTF8(signature.name),
                static_cast<int>(signature.type),
                static_cast<int>(signature.severity),
                ToUTF8(signature.yaraRule),
                ToUTF8(signature.clamavSignature),
                signature.binaryPattern,
                ToUTF8(signature.regexPattern),
                ToUTF8(signature.author),
                ToUTF8(signature.description),
                signature.isEnabled ? 1 : 0,
                static_cast<int64_t>(signature.detectionCount),
                static_cast<int64_t>(signature.falsePositiveCount),
                signature.accuracy,
                now,
                now
            );

            if (!success) return -1;

            int64_t sigId = DatabaseManager::Instance().LastInsertRowId();

            // Insert references
            for (const auto& ref : signature.references) {
                std::string refSql = "INSERT INTO signature_references (signature_id, reference) VALUES (?, ?)";
                DatabaseManager::Instance().ExecuteWithParams(refSql, nullptr, sigId, ToUTF8(ref));
            }

            // Insert platforms
            for (const auto& platform : signature.platforms) {
                std::string platSql = "INSERT INTO signature_platforms (signature_id, platform) VALUES (?, ?)";
                DatabaseManager::Instance().ExecuteWithParams(platSql, nullptr, sigId, ToUTF8(platform));
            }

            SS_LOG_INFO(L"ThreatIntelDB", L"Signature added with ID: %lld", sigId);
            return sigId;
        }

        bool ThreatIntelDB::UpdateSignature(const ThreatSignature& signature, DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Updating signature: %lld", signature.id);

            std::string sql = R"(
                UPDATE threat_signatures SET
                    threat_type = ?, severity = ?, yara_rule = ?, clamav_signature = ?,
                    binary_pattern = ?, regex_pattern = ?, author = ?, description = ?,
                    is_enabled = ?, detection_count = ?, false_positive_count = ?,
                    accuracy = ?, updated_at = ?
                WHERE id = ?
            )";

            return DatabaseManager::Instance().ExecuteWithParams(sql, err,
                static_cast<int>(signature.type),
                static_cast<int>(signature.severity),
                ToUTF8(signature.yaraRule),
                ToUTF8(signature.clamavSignature),
                signature.binaryPattern,
                ToUTF8(signature.regexPattern),
                ToUTF8(signature.author),
                ToUTF8(signature.description),
                signature.isEnabled ? 1 : 0,
                static_cast<int64_t>(signature.detectionCount),
                static_cast<int64_t>(signature.falsePositiveCount),
                signature.accuracy,
                timePointToString(std::chrono::system_clock::now()),
                signature.id
            );
        }

        bool ThreatIntelDB::RemoveSignature(int64_t signatureId, DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Removing signature: %lld", signatureId);

            std::string sql = "DELETE FROM threat_signatures WHERE id = ?";
            return DatabaseManager::Instance().ExecuteWithParams(sql, err, signatureId);
        }

        std::optional<ThreatIntelDB::ThreatSignature> ThreatIntelDB::GetSignature(
            int64_t signatureId, 
            DatabaseError* err) {
            
            std::string sql = "SELECT * FROM threat_signatures WHERE id = ?";
            auto result = DatabaseManager::Instance().QueryWithParams(sql, err, signatureId);

            if (result.Next()) {
                return rowToSignature(result);
            }

            return std::nullopt;
        }

        std::vector<ThreatIntelDB::ThreatSignature> ThreatIntelDB::GetSignaturesByType(
            ThreatType type,
            size_t maxCount,
            DatabaseError* err) {
            
            std::string sql = R"(
                SELECT * FROM threat_signatures 
                WHERE threat_type = ? 
                ORDER BY created_at DESC 
                LIMIT ?
            )";

            std::vector<ThreatSignature> results;
            auto result = DatabaseManager::Instance().QueryWithParams(sql, err,
                static_cast<int>(type), static_cast<int>(maxCount));

            while (result.Next()) {
                results.push_back(rowToSignature(result));
            }

            return results;
        }

        std::vector<ThreatIntelDB::ThreatSignature> ThreatIntelDB::GetEnabledSignatures(
            DatabaseError* err) {
            
            std::string sql = "SELECT * FROM threat_signatures WHERE is_enabled = 1";
            
            std::vector<ThreatSignature> results;
            auto result = DatabaseManager::Instance().Query(sql, err);

            while (result.Next()) {
                results.push_back(rowToSignature(result));
            }

            return results;
        }

        bool ThreatIntelDB::EnableSignature(int64_t signatureId, bool enabled, DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"%ls signature: %lld", 
                       enabled ? L"Enabling" : L"Disabling", signatureId);

            std::string sql = "UPDATE threat_signatures SET is_enabled = ? WHERE id = ?";
            return DatabaseManager::Instance().ExecuteWithParams(sql, err,
                enabled ? 1 : 0, signatureId);
        }

        bool ThreatIntelDB::UpdateSignatureAccuracy(int64_t signatureId, 
                                                    double accuracy, 
                                                    DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Updating signature accuracy: %lld -> %.2f%%", 
                       signatureId, accuracy);

            std::string sql = R"(
                UPDATE threat_signatures 
                SET accuracy = ?, updated_at = ? 
                WHERE id = ?
            )";

            return DatabaseManager::Instance().ExecuteWithParams(sql, err,
                accuracy,
                timePointToString(std::chrono::system_clock::now()),
                signatureId);
        }

        // =========================================================================
        // Helper: rowToSignature
        // =========================================================================

        ThreatIntelDB::ThreatSignature ThreatIntelDB::rowToSignature(const QueryResult& result) {
            ThreatSignature sig;

            sig.id = result.GetInt64("id");
            sig.name = result.GetWString("name");
            sig.type = static_cast<ThreatType>(result.GetInt("threat_type"));
            sig.severity = static_cast<ThreatSeverity>(result.GetInt("severity"));

            sig.yaraRule = result.GetWString("yara_rule");
            sig.clamavSignature = result.GetWString("clamav_signature");
            sig.binaryPattern = result.GetBlob("binary_pattern");
            sig.regexPattern = result.GetWString("regex_pattern");

            sig.author = result.GetWString("author");
            sig.description = result.GetWString("description");

            sig.isEnabled = result.GetInt("is_enabled") != 0;
            sig.detectionCount = result.GetInt64("detection_count");
            sig.falsePositiveCount = result.GetInt64("false_positive_count");
            sig.accuracy = result.GetDouble("accuracy");

            sig.createdAt = stringToTimePoint(result.GetString("created_at"));
            sig.updatedAt = stringToTimePoint(result.GetString("updated_at"));

            if (!result.IsNull("last_detection")) {
                sig.lastDetection = stringToTimePoint(result.GetString("last_detection"));
            }

            // Load references from signature_references table
            std::string refSql = R"(
                SELECT reference_url, reference_type FROM signature_references 
                WHERE signature_id = ? 
                ORDER BY reference_type ASC
            )";

            DatabaseError refErr;
            auto refResult = DatabaseManager::Instance().QueryWithParams(refSql, &refErr, sig.id);

            while (refResult.Next()) {
                std::wstring url = refResult.GetWString("reference_url");
                std::wstring type = refResult.GetWString("reference_type");

                if (!url.empty()) {
                    sig.references.push_back(url);
                }
                else {
					sig.references.push_back(type + L": " + url);
                }
            }

            // Load target platforms from signature_platforms table
            std::string platSql = R"(
                SELECT platform_name FROM signature_platforms 
                WHERE signature_id = ? 
                ORDER BY platform_name ASC
            )";

            DatabaseError platErr;
            auto platResult = DatabaseManager::Instance().QueryWithParams(platSql, &platErr, sig.id);

            while (platResult.Next()) {
                std::wstring platform = platResult.GetWString("platform_name");

                if (!platform.empty()) {
                    sig.platforms.push_back(platform);
                }
            }

            SS_LOG_DEBUG(L"ThreatIntelDB",
                L"Loaded signature '%ls' with %zu references and %zu platforms",
                sig.name.c_str(), sig.references.size(), sig.platforms.size());

            return sig;
        }

        // =========================================================================
        // TTPs (MITRE ATT&CK)
        // =========================================================================

        int64_t ThreatIntelDB::AddTTP(const TTP_Entry& ttp, DatabaseError* err) {
            if (ttp.mitreId.empty() || ttp.name.empty()) {
                if (err) {
                    err->message = L"TTP MITRE ID and name are required";
                }
                SS_LOG_ERROR(L"ThreatIntelDB", L"Invalid TTP entry: missing MITRE ID or name");
                return -1;
            }

            SS_LOG_INFO(L"ThreatIntelDB", L"Adding TTP: %ls (%ls)",
                ttp.name.c_str(), ttp.mitreId.c_str());

            auto trans = DatabaseManager::Instance().BeginTransaction(
                Transaction::Type::Immediate, err);

            if (!trans || !trans->IsActive()) {
                return -1;
            }

            // Insert main TTP entry
            std::string sql = R"(
                INSERT INTO ttp_entries (
                    mitre_id, name, phase, description, severity,
                    observed_count, detection_count, blocked_count,
                    is_critical, is_active, platform_windows, platform_linux, platform_macos,
                    requires_admin, requires_user_interaction, network_required,
                    created_at, updated_at, last_observed, data_sources, detection_references
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            )";

            auto now = timePointToString(std::chrono::system_clock::now());
            std::string dataSources;
            for (size_t i = 0; i < ttp.detectionMethods.size(); ++i) {
                if (i > 0) dataSources += ";";
                dataSources += ToUTF8(ttp.detectionMethods[i]);
            }

            bool success = DatabaseManager::Instance().ExecuteWithParams(sql, err,
                ToUTF8(ttp.mitreId),
                ToUTF8(ttp.name),
                static_cast<int>(ttp.phase),
                ToUTF8(ttp.description),
                static_cast<int>(ttp.severity),
                static_cast<int64_t>(ttp.observedCount),
                0,  // detection_count
                0,  // blocked_count
                0,  // is_critical
                1,  // is_active
                1,  // platform_windows
                0,  // platform_linux
                0,  // platform_macos
                0,  // requires_admin
                0,  // requires_user_interaction
                0,  // network_required
                now,
                now,
                timePointToString(ttp.lastObserved),
                dataSources,
                ""  // detection_references
            );

            if (!success) {
                trans->Rollback(err);
                return -1;
            }

            int64_t ttpId = DatabaseManager::Instance().LastInsertRowId();

            // Insert tactics
            if (!ttp.tactics.empty()) {
                for (const auto& tactic : ttp.tactics) {
                    std::string tacticSql = "INSERT INTO ttp_tactics (ttp_id, tactic_name) VALUES (?, ?)";
                    if (!DatabaseManager::Instance().ExecuteWithParams(tacticSql, nullptr,
                        ttpId, ToUTF8(tactic))) {
                        SS_LOG_WARN(L"ThreatIntelDB", L"Failed to insert tactic: %ls", tactic.c_str());
                    }
                }
            }

            // Insert techniques
            if (!ttp.techniques.empty()) {
                for (const auto& technique : ttp.techniques) {
                    std::string techSql = R"(
                        INSERT INTO ttp_techniques (ttp_id, technique_id, technique_name)
                        VALUES (?, ?, ?)
                    )";
                    if (!DatabaseManager::Instance().ExecuteWithParams(techSql, nullptr,
                        ttpId, ToUTF8(technique), ToUTF8(technique))) {
                        SS_LOG_WARN(L"ThreatIntelDB", L"Failed to insert technique: %ls", technique.c_str());
                    }
                }
            }

            // Insert sub-techniques
            if (!ttp.subTechniques.empty()) {
                for (const auto& subtech : ttp.subTechniques) {
                    std::string subtechSql = R"(
                        INSERT INTO ttp_subtechniques (ttp_id, technique_id, subtechnique_id, subtechnique_name)
                        VALUES (?, ?, ?, ?)
                    )";
                    if (!DatabaseManager::Instance().ExecuteWithParams(subtechSql, nullptr,
                        ttpId, ToUTF8(subtech), ToUTF8(subtech), ToUTF8(subtech))) {
                        SS_LOG_WARN(L"ThreatIntelDB", L"Failed to insert sub-technique: %ls", subtech.c_str());
                    }
                }
            }

            // Insert detection methods
            if (!ttp.detectionMethods.empty()) {
                for (const auto& method : ttp.detectionMethods) {
                    std::string methodSql = R"(
                        INSERT INTO ttp_detection_methods (ttp_id, method_name, method_type, confidence_level)
                        VALUES (?, ?, ?, ?)
                    )";
                    if (!DatabaseManager::Instance().ExecuteWithParams(methodSql, nullptr,
                        ttpId, ToUTF8(method), 0, 3)) {
                        SS_LOG_WARN(L"ThreatIntelDB", L"Failed to insert detection method: %ls", method.c_str());
                    }
                }
            }

            // Insert mitigations
            if (!ttp.mitigations.empty()) {
                for (const auto& mitigation : ttp.mitigations) {
                    std::string mitigationSql = R"(
                        INSERT INTO ttp_mitigations (ttp_id, mitigation_id, mitigation_name, mitigation_type, effectiveness)
                        VALUES (?, ?, ?, ?, ?)
                    )";
                    if (!DatabaseManager::Instance().ExecuteWithParams(mitigationSql, nullptr,
                        ttpId, ToUTF8(mitigation), ToUTF8(mitigation), 0, 3)) {
                        SS_LOG_WARN(L"ThreatIntelDB", L"Failed to insert mitigation: %ls", mitigation.c_str());
                    }
                }
            }

            // Insert related threats
            if (!ttp.relatedThreats.empty()) {
                for (const auto& threat : ttp.relatedThreats) {
                    std::string threatSql = R"(
                        INSERT INTO ttp_related_threats (ttp_id, threat_name, threat_type, confidence, first_linked)
                        VALUES (?, ?, ?, ?, ?)
                    )";
                    if (!DatabaseManager::Instance().ExecuteWithParams(threatSql, nullptr,
                        ttpId, ToUTF8(threat), 0, 3, now)) {
                        SS_LOG_WARN(L"ThreatIntelDB", L"Failed to insert related threat: %ls", threat.c_str());
                    }
                }
            }

            if (!trans->Commit(err)) {
                return -1;
            }

            // Update cache and statistics
            if (m_config.enableCaching) {
                std::unique_lock<std::shared_mutex> lock(m_cacheMutex);
                m_cacheSize += ttp.name.size() + ttp.mitreId.size();
            }

            {
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.totalTTPs++;
            }

            SS_LOG_INFO(L"ThreatIntelDB", L"TTP added successfully. ID: %lld, MITRE ID: %ls",
                ttpId, ttp.mitreId.c_str());
            return ttpId;
        }

        bool ThreatIntelDB::UpdateTTP(const TTP_Entry& ttp, DatabaseError* err) {
            if (ttp.id <= 0) {
                if (err) err->message = L"Invalid TTP ID";
                return false;
            }

            SS_LOG_INFO(L"ThreatIntelDB", L"Updating TTP: %lld (%ls)", ttp.id, ttp.mitreId.c_str());

            auto trans = DatabaseManager::Instance().BeginTransaction(
                Transaction::Type::Immediate, err);

            if (!trans || !trans->IsActive()) {
                return false;
            }

            std::string sql = R"(
                UPDATE ttp_entries SET
                    name = ?, phase = ?, description = ?, severity = ?,
                    observed_count = ?, is_critical = ?, is_active = ?,
                    platform_windows = ?, platform_linux = ?, platform_macos = ?,
                    requires_admin = ?, requires_user_interaction = ?, network_required = ?,
                    updated_at = ?, last_observed = ?
                WHERE id = ?
            )";

            auto now = timePointToString(std::chrono::system_clock::now());

            bool success = DatabaseManager::Instance().ExecuteWithParams(sql, err,
                ToUTF8(ttp.name),
                static_cast<int>(ttp.phase),
                ToUTF8(ttp.description),
                static_cast<int>(ttp.severity),
                static_cast<int64_t>(ttp.observedCount),
                0,  // is_critical
                1,  // is_active
                1,  // platform_windows
                0,  // platform_linux
                0,  // platform_macos
                0,  // requires_admin
                0,  // requires_user_interaction
                0,  // network_required
                now,
                timePointToString(ttp.lastObserved),
                ttp.id
            );

            if (!success) {
                trans->Rollback(err);
                return false;
            }

            // Clear and re-insert related data
            DatabaseManager::Instance().Execute(
                "DELETE FROM ttp_tactics WHERE ttp_id = ?", nullptr);
            DatabaseManager::Instance().Execute(
                "DELETE FROM ttp_techniques WHERE ttp_id = ?", nullptr);
            DatabaseManager::Instance().Execute(
                "DELETE FROM ttp_detection_methods WHERE ttp_id = ?", nullptr);
            DatabaseManager::Instance().Execute(
                "DELETE FROM ttp_mitigations WHERE ttp_id = ?", nullptr);

            // Re-insert tactics
            for (const auto& tactic : ttp.tactics) {
                DatabaseManager::Instance().ExecuteWithParams(
                    "INSERT INTO ttp_tactics (ttp_id, tactic_name) VALUES (?, ?)",
                    nullptr, ttp.id, ToUTF8(tactic));
            }

            // Re-insert techniques
            for (const auto& technique : ttp.techniques) {
                DatabaseManager::Instance().ExecuteWithParams(
                    "INSERT INTO ttp_techniques (ttp_id, technique_id, technique_name) VALUES (?, ?, ?)",
                    nullptr, ttp.id, ToUTF8(technique), ToUTF8(technique));
            }

            // Re-insert detection methods
            for (const auto& method : ttp.detectionMethods) {
                DatabaseManager::Instance().ExecuteWithParams(
                    "INSERT INTO ttp_detection_methods (ttp_id, method_name, method_type, confidence_level) VALUES (?, ?, ?, ?)",
                    nullptr, ttp.id, ToUTF8(method), 0, 3);
            }

            // Re-insert mitigations
            for (const auto& mitigation : ttp.mitigations) {
                DatabaseManager::Instance().ExecuteWithParams(
                    "INSERT INTO ttp_mitigations (ttp_id, mitigation_id, mitigation_name, mitigation_type, effectiveness) VALUES (?, ?, ?, ?, ?)",
                    nullptr, ttp.id, ToUTF8(mitigation), ToUTF8(mitigation), 0, 3);
            }

            if (!trans->Commit(err)) {
                return false;
            }

            SS_LOG_INFO(L"ThreatIntelDB", L"TTP updated successfully: %lld", ttp.id);
            return true;
        }


        bool ThreatIntelDB::RemoveTTP(int64_t ttpId, DatabaseError* err) {
            if (ttpId <= 0) {
                if (err) err->message = L"Invalid TTP ID";
                return false;
            }

            SS_LOG_INFO(L"ThreatIntelDB", L"Removing TTP: %lld", ttpId);

            // All cascading deletes handled by foreign key constraints
            bool success = DatabaseManager::Instance().ExecuteWithParams(
                "DELETE FROM ttp_entries WHERE id = ?", err, ttpId);

            if (success) {
                std::lock_guard<std::mutex> lock(m_statsMutex);
                if (m_stats.totalTTPs > 0) m_stats.totalTTPs--;
            }

            SS_LOG_INFO(L"ThreatIntelDB", L"TTP removed successfully: %lld", ttpId);
            return success;
        }

        std::optional<ThreatIntelDB::TTP_Entry> ThreatIntelDB::GetTTP(int64_t ttpId, DatabaseError* err) {
            if (ttpId <= 0) return std::nullopt;

            std::string sql = "SELECT * FROM ttp_entries WHERE id = ? LIMIT 1";

            auto result = DatabaseManager::Instance().QueryWithParams(sql, err, ttpId);

            if (result.Next()) {
                TTP_Entry ttp;
                ttp.id = result.GetInt64(0);
                ttp.mitreId = ToWide(result.GetString(1));
                ttp.name = ToWide(result.GetString(2));
                ttp.phase = static_cast<TTPPhase>(result.GetInt(3));
                ttp.description = ToWide(result.GetString(4));
                ttp.severity = static_cast<ThreatSeverity>(result.GetInt(5));
                ttp.observedCount = result.GetInt64(6);

                // Load related data
                loadTTPRelatedData(ttp, err);

                return ttp;
            }

            return std::nullopt;
        }
        
        std::optional<ThreatIntelDB::TTP_Entry> ThreatIntelDB::GetTTPByMitreId(std::wstring_view mitreId,
            DatabaseError* err) {
            if (mitreId.empty()) return std::nullopt;

            std::string sql = "SELECT id FROM ttp_entries WHERE mitre_id = ? LIMIT 1";

            auto result = DatabaseManager::Instance().QueryWithParams(sql, err, ToUTF8(mitreId));

            if (result.Next()) {
                int64_t ttpId = result.GetInt64(0);
                return GetTTP(ttpId, err);
            }

            return std::nullopt;
        }

        std::vector<ThreatIntelDB::TTP_Entry> ThreatIntelDB::GetTTPsByPhase(TTPPhase phase,
            DatabaseError* err) {
            std::vector<TTP_Entry> ttps;

            std::string sql = R"(
                SELECT id FROM ttp_entries 
                WHERE phase = ? AND is_active = 1
                ORDER BY observed_count DESC
            )";

            auto result = DatabaseManager::Instance().QueryWithParams(sql, err, static_cast<int>(phase));

            while (result.Next()) {
                int64_t ttpId = result.GetInt64(0);
                auto ttp = GetTTP(ttpId, err);
                if (ttp) {
                    ttps.push_back(*ttp);
                }
            }

            return ttps;
        }

        std::vector<ThreatIntelDB::TTP_Entry> ThreatIntelDB::GetTTPsByThreat(std::wstring_view threatName,
            DatabaseError* err) {
            std::vector<TTP_Entry> ttps;

            std::string sql = R"(
                SELECT DISTINCT ttp_id FROM ttp_related_threats 
                WHERE threat_name = ?
            )";

            auto result = DatabaseManager::Instance().QueryWithParams(sql, err, ToUTF8(threatName));

            while (result.Next()) {
                int64_t ttpId = result.GetInt64(0);
                auto ttp = GetTTP(ttpId, err);
                if (ttp) {
                    ttps.push_back(*ttp);
                }
            }

            return ttps;
        }
        bool ThreatIntelDB::IncrementTTPObservation(int64_t ttpId, DatabaseError* err) {
            if (ttpId <= 0) return false;

            std::string sql = R"(
                UPDATE ttp_entries SET 
                    observed_count = observed_count + 1,
                    last_observed = ?,
                    updated_at = ?
                WHERE id = ?
            )";

            auto now = timePointToString(std::chrono::system_clock::now());

            return DatabaseManager::Instance().ExecuteWithParams(sql, err, now, now, ttpId);
        }

        void ThreatIntelDB::loadTTPRelatedData(TTP_Entry& ttp, DatabaseError* err) {
            // Load tactics
            {
                std::string sql = "SELECT tactic_name FROM ttp_tactics WHERE ttp_id = ?";
                auto result = DatabaseManager::Instance().QueryWithParams(sql, err, ttp.id);
                while (result.Next()) {
                    ttp.tactics.push_back(ToWide(result.GetString(0)));
                }
            }

            // Load techniques
            {
                std::string sql = "SELECT technique_name FROM ttp_techniques WHERE ttp_id = ?";
                auto result = DatabaseManager::Instance().QueryWithParams(sql, err, ttp.id);
                while (result.Next()) {
                    ttp.techniques.push_back(ToWide(result.GetString(0)));
                }
            }

            // Load sub-techniques
            {
                std::string sql = "SELECT subtechnique_name FROM ttp_subtechniques WHERE ttp_id = ?";
                auto result = DatabaseManager::Instance().QueryWithParams(sql, err, ttp.id);
                while (result.Next()) {
                    ttp.subTechniques.push_back(ToWide(result.GetString(0)));
                }
            }

            // Load detection methods
            {
                std::string sql = "SELECT method_name FROM ttp_detection_methods WHERE ttp_id = ?";
                auto result = DatabaseManager::Instance().QueryWithParams(sql, err, ttp.id);
                while (result.Next()) {
                    ttp.detectionMethods.push_back(ToWide(result.GetString(0)));
                }
            }

            // Load mitigations
            {
                std::string sql = "SELECT mitigation_name FROM ttp_mitigations WHERE ttp_id = ?";
                auto result = DatabaseManager::Instance().QueryWithParams(sql, err, ttp.id);
                while (result.Next()) {
                    ttp.mitigations.push_back(ToWide(result.GetString(0)));
                }
            }

            // Load related threats
            {
                std::string sql = "SELECT threat_name FROM ttp_related_threats WHERE ttp_id = ?";
                auto result = DatabaseManager::Instance().QueryWithParams(sql, err, ttp.id);
                while (result.Next()) {
                    ttp.relatedThreats.push_back(ToWide(result.GetString(0)));
                }
            }
        }

        // ============================================================================
        // Helper: Convert timestamps to strings
        // ============================================================================

        std::string ThreatIntelDB::timePointToString(std::chrono::system_clock::time_point tp) {
            auto time_t_val = std::chrono::system_clock::to_time_t(tp);
            std::tm tm_val{};
#ifdef _WIN32
            gmtime_s(&tm_val, &time_t_val);  // Windows
#else
            gmtime_r(&time_t_val, &tm_val);  // POSIX
#endif

            std::ostringstream oss;
            oss << std::put_time(&tm_val, "%Y-%m-%d %H:%M:%S");
            return oss.str();
        }

        // =========================================================================
        // Threat Actors - FULL CRUD
        // =========================================================================

        int64_t ThreatIntelDB::AddThreatActor(const ThreatActor& actor, DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Adding threat actor: %ls", actor.name.c_str());

            std::string sql = R"(
                INSERT INTO threat_actors (
                    name, description, motivation, origin, threat_level,
                    is_apt, is_active, first_seen, last_activity, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            )";

            auto now = timePointToString(std::chrono::system_clock::now());

            bool success = DatabaseManager::Instance().ExecuteWithParams(sql, err,
                ToUTF8(actor.name),
                ToUTF8(actor.description),
                ToUTF8(actor.motivation),
                ToUTF8(actor.origin),
                static_cast<int>(actor.threatLevel),
                actor.isAPT ? 1 : 0,
                actor.isActive ? 1 : 0,
                timePointToString(actor.firstSeen),
                timePointToString(actor.lastActivity),
                now
            );

            if (!success) return -1;

            int64_t actorId = DatabaseManager::Instance().LastInsertRowId();

            // Insert aliases
            for (const auto& alias : actor.aliases) {
                std::string aliasSql = "INSERT INTO actor_aliases (actor_id, alias) VALUES (?, ?)";
                DatabaseManager::Instance().ExecuteWithParams(aliasSql, nullptr, actorId, ToUTF8(alias));
            }

            SS_LOG_INFO(L"ThreatIntelDB", L"Threat actor added with ID: %lld", actorId);
            return actorId;
        }

        bool ThreatIntelDB::UpdateThreatActor(const ThreatActor& actor, DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Updating threat actor: %lld", actor.id);

            std::string sql = R"(
                UPDATE threat_actors SET
                    description = ?, motivation = ?, origin = ?,
                    threat_level = ?, is_apt = ?, is_active = ?,
                    last_activity = ?
                WHERE id = ?
            )";

            return DatabaseManager::Instance().ExecuteWithParams(sql, err,
                ToUTF8(actor.description),
                ToUTF8(actor.motivation),
                ToUTF8(actor.origin),
                static_cast<int>(actor.threatLevel),
                actor.isAPT ? 1 : 0,
                actor.isActive ? 1 : 0,
                timePointToString(actor.lastActivity),
                actor.id
            );
        }

        bool ThreatIntelDB::RemoveThreatActor(int64_t actorId, DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Removing threat actor: %lld", actorId);

            std::string sql = "DELETE FROM threat_actors WHERE id = ?";
            return DatabaseManager::Instance().ExecuteWithParams(sql, err, actorId);
        }

        std::optional<ThreatIntelDB::ThreatActor> ThreatIntelDB::GetThreatActor(
            int64_t actorId, 
            DatabaseError* err) {
            
            std::string sql = "SELECT * FROM threat_actors WHERE id = ?";
            auto result = DatabaseManager::Instance().QueryWithParams(sql, err, actorId);

            if (result.Next()) {
                ThreatActor actor;
                actor.id = result.GetInt64("id");
                actor.name = result.GetWString("name");
                actor.description = result.GetWString("description");
                actor.motivation = result.GetWString("motivation");
                actor.origin = result.GetWString("origin");
                actor.threatLevel = static_cast<ThreatSeverity>(result.GetInt("threat_level"));
                actor.isAPT = result.GetInt("is_apt") != 0;
                actor.isActive = result.GetInt("is_active") != 0;
                actor.firstSeen = stringToTimePoint(result.GetString("first_seen"));
                actor.lastActivity = stringToTimePoint(result.GetString("last_activity"));
                actor.createdAt = stringToTimePoint(result.GetString("created_at"));
                return actor;
            }

            return std::nullopt;
        }

        std::optional<ThreatIntelDB::ThreatActor> ThreatIntelDB::GetThreatActorByName(
            std::wstring_view name, 
            DatabaseError* err) {
            
            std::string sql = "SELECT * FROM threat_actors WHERE name = ?";
            auto result = DatabaseManager::Instance().QueryWithParams(sql, err, ToUTF8(name));

            if (result.Next()) {
                ThreatActor actor;
                actor.id = result.GetInt64("id");
                actor.name = result.GetWString("name");
                actor.description = result.GetWString("description");
                actor.motivation = result.GetWString("motivation");
                actor.origin = result.GetWString("origin");
                actor.threatLevel = static_cast<ThreatSeverity>(result.GetInt("threat_level"));
                actor.isAPT = result.GetInt("is_apt") != 0;
                actor.isActive = result.GetInt("is_active") != 0;
                actor.firstSeen = stringToTimePoint(result.GetString("first_seen"));
                actor.lastActivity = stringToTimePoint(result.GetString("last_activity"));
                actor.createdAt = stringToTimePoint(result.GetString("created_at"));
                return actor;
            }

            return std::nullopt;
        }

        std::vector<ThreatIntelDB::ThreatActor> ThreatIntelDB::GetActiveThreatActors(
            DatabaseError* err) {
            
            std::string sql = "SELECT * FROM threat_actors WHERE is_active = 1 ORDER BY threat_level DESC";
            
            std::vector<ThreatActor> results;
            auto result = DatabaseManager::Instance().Query(sql, err);

            while (result.Next()) {
                ThreatActor actor;
                actor.id = result.GetInt64("id");
                actor.name = result.GetWString("name");
                actor.description = result.GetWString("description");
                actor.motivation = result.GetWString("motivation");
                actor.origin = result.GetWString("origin");
                actor.threatLevel = static_cast<ThreatSeverity>(result.GetInt("threat_level"));
                actor.isAPT = result.GetInt("is_apt") != 0;
                actor.isActive = result.GetInt("is_active") != 0;
                actor.firstSeen = stringToTimePoint(result.GetString("first_seen"));
                actor.lastActivity = stringToTimePoint(result.GetString("last_activity"));
                actor.createdAt = stringToTimePoint(result.GetString("created_at"));
                results.push_back(actor);
            }

            return results;
        }

        std::vector<ThreatIntelDB::ThreatActor> ThreatIntelDB::GetAPTGroups(DatabaseError* err) {
            std::string sql = R"(
                SELECT * FROM threat_actors 
                WHERE is_apt = 1 
                ORDER BY last_activity DESC
            )";
            
            std::vector<ThreatActor> results;
            auto result = DatabaseManager::Instance().Query(sql, err);

            while (result.Next()) {
                ThreatActor actor;
                actor.id = result.GetInt64("id");
                actor.name = result.GetWString("name");
                actor.description = result.GetWString("description");
                actor.motivation = result.GetWString("motivation");
                actor.origin = result.GetWString("origin");
                actor.threatLevel = static_cast<ThreatSeverity>(result.GetInt("threat_level"));
                actor.isAPT = result.GetInt("is_apt") != 0;
                actor.isActive = result.GetInt("is_active") != 0;
                actor.firstSeen = stringToTimePoint(result.GetString("first_seen"));
                actor.lastActivity = stringToTimePoint(result.GetString("last_activity"));
                actor.createdAt = stringToTimePoint(result.GetString("created_at"));
                results.push_back(actor);
            }

            return results;
        }

        // =========================================================================
        // Campaigns - FULL CRUD
        // =========================================================================

        int64_t ThreatIntelDB::AddCampaign(const ThreatCampaign& campaign, DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Adding campaign: %ls", campaign.name.c_str());

            std::string sql = R"(
                INSERT INTO threat_campaigns (
                    name, description, primary_type, severity,
                    start_date, end_date, is_active, objective,
                    attribution, victim_count, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            )";

            auto now = timePointToString(std::chrono::system_clock::now());

            bool success = DatabaseManager::Instance().ExecuteWithParams(sql, err,
                ToUTF8(campaign.name),
                ToUTF8(campaign.description),
                static_cast<int>(campaign.primaryType),
                static_cast<int>(campaign.severity),
                timePointToString(campaign.startDate),
                campaign.endDate.time_since_epoch().count() > 0 ? 
                    timePointToString(campaign.endDate) : std::string(""),
                campaign.isActive ? 1 : 0,
                ToUTF8(campaign.objective),
                ToUTF8(campaign.attribution),
                static_cast<int64_t>(campaign.victimCount),
                now,
                now
            );

            if (!success) return -1;

            int64_t campaignId = DatabaseManager::Instance().LastInsertRowId();

            SS_LOG_INFO(L"ThreatIntelDB", L"Campaign added with ID: %lld", campaignId);
            return campaignId;
        }

        bool ThreatIntelDB::UpdateCampaign(const ThreatCampaign& campaign, DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Updating campaign: %lld", campaign.id);

            std::string sql = R"(
                UPDATE threat_campaigns SET
                    description = ?, severity = ?, end_date = ?,
                    is_active = ?, objective = ?, attribution = ?,
                    victim_count = ?, updated_at = ?
                WHERE id = ?
            )";

            return DatabaseManager::Instance().ExecuteWithParams(sql, err,
                ToUTF8(campaign.description),
                static_cast<int>(campaign.severity),
                campaign.endDate.time_since_epoch().count() > 0 ? 
                    timePointToString(campaign.endDate) : std::string(""),
                campaign.isActive ? 1 : 0,
                ToUTF8(campaign.objective),
                ToUTF8(campaign.attribution),
                static_cast<int64_t>(campaign.victimCount),
                timePointToString(std::chrono::system_clock::now()),
                campaign.id
            );
        }

        bool ThreatIntelDB::RemoveCampaign(int64_t campaignId, DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Removing campaign: %lld", campaignId);

            std::string sql = "DELETE FROM threat_campaigns WHERE id = ?";
            return DatabaseManager::Instance().ExecuteWithParams(sql, err, campaignId);
        }

        std::optional<ThreatIntelDB::ThreatCampaign> ThreatIntelDB::GetCampaign(
            int64_t campaignId, 
            DatabaseError* err) {
            
            std::string sql = "SELECT * FROM threat_campaigns WHERE id = ?";
            auto result = DatabaseManager::Instance().QueryWithParams(sql, err, campaignId);

            if (result.Next()) {
                return rowToCampaign(result);
            }

            return std::nullopt;
        }

        std::vector<ThreatIntelDB::ThreatCampaign> ThreatIntelDB::GetActiveCampaigns(
            DatabaseError* err) {
            
            std::string sql = R"(
                SELECT * FROM threat_campaigns 
                WHERE is_active = 1 
                ORDER BY start_date DESC
            )";
            
            std::vector<ThreatCampaign> results;
            auto result = DatabaseManager::Instance().Query(sql, err);

            while (result.Next()) {
                results.push_back(rowToCampaign(result));
            }

            return results;
        }

        std::vector<ThreatIntelDB::ThreatCampaign> ThreatIntelDB::GetCampaignsByActor(
            std::wstring_view actorName, 
            DatabaseError* err) {
            
            std::string sql = R"(
                SELECT * FROM threat_campaigns 
                WHERE attribution LIKE ? 
                ORDER BY start_date DESC
            )";
            
            std::vector<ThreatCampaign> results;
            auto result = DatabaseManager::Instance().QueryWithParams(sql, err,
                "%" + ToUTF8(actorName) + "%");

            while (result.Next()) {
                results.push_back(rowToCampaign(result));
            }

            return results;
        }

        // =========================================================================
        // Helper Functions - Row Converters
        // =========================================================================

        ThreatIntelDB::TTP_Entry ThreatIntelDB::rowToTTP(const QueryResult& result) {
            TTP_Entry ttp;

            ttp.id = result.GetInt64("id");
            ttp.mitreId = result.GetWString("mitre_id");
            ttp.name = result.GetWString("name");
            ttp.phase = static_cast<TTPPhase>(result.GetInt("phase"));
            ttp.description = result.GetWString("description");
            ttp.severity = static_cast<ThreatSeverity>(result.GetInt("severity"));
            ttp.observedCount = result.GetInt64("observed_count");
            ttp.createdAt = stringToTimePoint(result.GetString("created_at"));

            if (!result.IsNull("last_observed")) {
                ttp.lastObserved = stringToTimePoint(result.GetString("last_observed"));
            }

            // Load tactics from ttp_tactics table
            {
                DatabaseError err;
                auto tacticsResult = DatabaseManager::Instance().QueryWithParams(
                    "SELECT tactic_name FROM ttp_tactics WHERE ttp_id = ? ORDER BY tactic_name",
                    &err,
                    ttp.id
                );

                while (tacticsResult.Next()) {
                    ttp.tactics.push_back(tacticsResult.GetWString("tactic_name"));
                }
            }

            // Load techniques from ttp_techniques table
            {
                DatabaseError err;
                auto techniquesResult = DatabaseManager::Instance().QueryWithParams(
                    "SELECT technique_id, technique_name FROM ttp_techniques WHERE ttp_id = ? ORDER BY technique_id",
                    &err,
                    ttp.id
                );

                while (techniquesResult.Next()) {
                    ttp.techniques.push_back(techniquesResult.GetWString("technique_name"));
                }
            }

            // Load sub-techniques from ttp_subtechniques table
            {
                DatabaseError err;
                auto subtechniquesResult = DatabaseManager::Instance().QueryWithParams(
                    "SELECT subtechnique_id, subtechnique_name FROM ttp_subtechniques WHERE ttp_id = ? ORDER BY subtechnique_id",
                    &err,
                    ttp.id
                );

                while (subtechniquesResult.Next()) {
                    ttp.subTechniques.push_back(subtechniquesResult.GetWString("subtechnique_name"));
                }
            }

            // Load detection methods from ttp_detection_methods table
            {
                DatabaseError err;
                auto detectionsResult = DatabaseManager::Instance().QueryWithParams(
                    "SELECT method_name FROM ttp_detection_methods WHERE ttp_id = ? ORDER BY confidence_level DESC",
                    &err,
                    ttp.id
                );

                while (detectionsResult.Next()) {
                    ttp.detectionMethods.push_back(detectionsResult.GetWString("method_name"));
                }
            }

            // Load mitigations from ttp_mitigations table
            {
                DatabaseError err;
                auto mitigationsResult = DatabaseManager::Instance().QueryWithParams(
                    "SELECT mitigation_name FROM ttp_mitigations WHERE ttp_id = ? ORDER BY effectiveness DESC",
                    &err,
                    ttp.id
                );

                while (mitigationsResult.Next()) {
                    ttp.mitigations.push_back(mitigationsResult.GetWString("mitigation_name"));
                }
            }

            // Load related threats from ttp_related_threats table
            {
                DatabaseError err;
                auto threatsResult = DatabaseManager::Instance().QueryWithParams(
                    "SELECT threat_name FROM ttp_related_threats WHERE ttp_id = ? ORDER BY confidence DESC",
                    &err,
                    ttp.id
                );

                while (threatsResult.Next()) {
                    ttp.relatedThreats.push_back(threatsResult.GetWString("threat_name"));
                }
            }

            return ttp;
        }

        ThreatIntelDB::ThreatCampaign ThreatIntelDB::rowToCampaign(const QueryResult& result) {
            ThreatCampaign campaign;

            campaign.id = result.GetInt64("id");
            campaign.name = result.GetWString("name");
            campaign.description = result.GetWString("description");
            campaign.primaryType = static_cast<ThreatType>(result.GetInt("primary_type"));
            campaign.severity = static_cast<ThreatSeverity>(result.GetInt("severity"));
            campaign.startDate = stringToTimePoint(result.GetString("start_date"));

            if (!result.IsNull("end_date")) {
                std::string endDateStr = result.GetString("end_date");
                if (!endDateStr.empty()) {
                    campaign.endDate = stringToTimePoint(endDateStr);
                }
            }

            campaign.isActive = result.GetInt("is_active") != 0;
            campaign.objective = result.GetWString("objective");
            campaign.attribution = result.GetWString("attribution");
            campaign.victimCount = result.GetInt64("victim_count");
            campaign.createdAt = stringToTimePoint(result.GetString("created_at"));
            campaign.updatedAt = stringToTimePoint(result.GetString("updated_at"));

            // Load related threat actors from campaign-actor relationship table
            {
                DatabaseError err;
                auto actorsResult = DatabaseManager::Instance().QueryWithParams(
                    "SELECT ta.name FROM threat_actors ta "
                    "INNER JOIN campaign_actor_mapping cam ON ta.id = cam.actor_id "
                    "WHERE cam.campaign_id = ? ORDER BY ta.name",
                    &err,
                    campaign.id
                );

                while (actorsResult.Next()) {
                    campaign.threatActors.push_back(actorsResult.GetWString("name"));
                }
            }

            // Load related IoC IDs from campaign-IoC relationship table
            {
                DatabaseError err;
                auto ioCsResult = DatabaseManager::Instance().QueryWithParams(
                    "SELECT DISTINCT ioc_id FROM campaign_ioc_mapping WHERE campaign_id = ? ORDER BY ioc_id",
                    &err,
                    campaign.id
                );

                while (ioCsResult.Next()) {
                    campaign.relatedIoCs.push_back(ioCsResult.GetInt64("ioc_id"));
                }
            }

            // Load related TTPs from campaign-TTP relationship table
            {
                DatabaseError err;
                auto ttpsResult = DatabaseManager::Instance().QueryWithParams(
                    "SELECT te.mitre_id FROM ttp_entries te "
                    "INNER JOIN campaign_ttp_mapping ctm ON te.id = ctm.ttp_id "
                    "WHERE ctm.campaign_id = ? ORDER BY te.mitre_id",
                    &err,
                    campaign.id
                );

                while (ttpsResult.Next()) {
                    campaign.ttps.push_back(ttpsResult.GetWString("mitre_id"));
                }
            }

            // Load affected regions from campaign_regions table
            {
                DatabaseError err;
                auto regionsResult = DatabaseManager::Instance().QueryWithParams(
                    "SELECT region_name FROM campaign_regions WHERE campaign_id = ? ORDER BY region_name",
                    &err,
                    campaign.id
                );

                while (regionsResult.Next()) {
                    campaign.affectedRegions.push_back(regionsResult.GetWString("region_name"));
                }
            }

            // Load targeted sectors from campaign_sectors table
            {
                DatabaseError err;
                auto sectorsResult = DatabaseManager::Instance().QueryWithParams(
                    "SELECT sector_name FROM campaign_sectors WHERE campaign_id = ? ORDER BY sector_name",
                    &err,
                    campaign.id
                );

                while (sectorsResult.Next()) {
                    campaign.targetedSectors.push_back(sectorsResult.GetWString("sector_name"));
                }
            }

            return campaign;
        }


        // =========================================================================
        // Maintenance Operations
        // =========================================================================

        bool ThreatIntelDB::Vacuum(DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Vacuuming database...");
            return DatabaseManager::Instance().Vacuum(err);
        }

        bool ThreatIntelDB::Optimize(DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Optimizing database...");

            // Analyze tables
            if (!DatabaseManager::Instance().Analyze(err)) {
                return false;
            }

            // Clean up expired IoCs
            CleanupExpiredIoCs(err);

            return true;
        }

        bool ThreatIntelDB::CheckIntegrity(DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Checking database integrity...");
            
            std::vector<std::wstring> issues;
            if (!DatabaseManager::Instance().CheckIntegrity(issues, err)) {
                for (const auto& issue : issues) {
                    SS_LOG_ERROR(L"ThreatIntelDB", L"Integrity issue: %ls", issue.c_str());
                }
                return false;
            }

            SS_LOG_INFO(L"ThreatIntelDB", L"Database integrity: OK");
            return true;
        }

        bool ThreatIntelDB::BackupDatabase(std::wstring_view backupPath, DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Backing up database to: %ls", backupPath.data());
            return DatabaseManager::Instance().BackupToFile(backupPath, err);
        }

        // =========================================================================
        // Utility Functions - Enum Conversions
        // =========================================================================

        std::wstring ThreatIntelDB::ThreatTypeToString(ThreatType type) {
            switch (type) {
                case ThreatType::Unknown: return L"Unknown";
                case ThreatType::Malware: return L"Malware";
                case ThreatType::Ransomware: return L"Ransomware";
                case ThreatType::Trojan: return L"Trojan";
                case ThreatType::Virus: return L"Virus";
                case ThreatType::Worm: return L"Worm";
                case ThreatType::Rootkit: return L"Rootkit";
                case ThreatType::Backdoor: return L"Backdoor";
                case ThreatType::Spyware: return L"Spyware";
                case ThreatType::Adware: return L"Adware";
                case ThreatType::PUA: return L"PUA";
                case ThreatType::Exploit: return L"Exploit";
                case ThreatType::Phishing: return L"Phishing";
                case ThreatType::C2Server: return L"C2Server";
                case ThreatType::Botnet: return L"Botnet";
                case ThreatType::APT: return L"APT";
                case ThreatType::Cryptominer: return L"Cryptominer";
                case ThreatType::Keylogger: return L"Keylogger";
                case ThreatType::Infostealer: return L"Infostealer";
                case ThreatType::Webshell: return L"Webshell";
                default: return L"Custom";
            }
        }

        std::wstring ThreatIntelDB::ThreatSeverityToString(ThreatSeverity severity) {
            switch (severity) {
                case ThreatSeverity::Info: return L"Info";
                case ThreatSeverity::Low: return L"Low";
                case ThreatSeverity::Medium: return L"Medium";
                case ThreatSeverity::High: return L"High";
                case ThreatSeverity::Critical: return L"Critical";
                case ThreatSeverity::Emergency: return L"Emergency";
                default: return L"Unknown";
            }
        }

        std::wstring ThreatIntelDB::IoC_TypeToString(IoC_Type type) {
            switch (type) {
                case IoC_Type::FileHash_MD5: return L"MD5";
                case IoC_Type::FileHash_SHA1: return L"SHA1";
                case IoC_Type::FileHash_SHA256: return L"SHA256";
                case IoC_Type::FileHash_SHA512: return L"SHA512";
                case IoC_Type::IP_Address: return L"IP";
                case IoC_Type::Domain: return L"Domain";
                case IoC_Type::URL: return L"URL";
                case IoC_Type::Email: return L"Email";
                case IoC_Type::Mutex: return L"Mutex";
                case IoC_Type::RegistryKey: return L"Registry";
                case IoC_Type::FilePath: return L"FilePath";
                case IoC_Type::FileName: return L"FileName";
                case IoC_Type::Certificate: return L"Certificate";
                case IoC_Type::UserAgent: return L"UserAgent";
                case IoC_Type::JA3_Fingerprint: return L"JA3";
                case IoC_Type::YARA_Rule: return L"YARA";
                case IoC_Type::CVE: return L"CVE";
                case IoC_Type::ASN: return L"ASN";
                case IoC_Type::MAC_Address: return L"MAC";
                default: return L"Custom";
            }
        }

        std::wstring ThreatIntelDB::ThreatSourceToString(ThreatSource source) {
            switch (source) {
                case ThreatSource::Internal: return L"Internal";
                case ThreatSource::CrowdStrike: return L"CrowdStrike";
                case ThreatSource::VirusTotal: return L"VirusTotal";
                case ThreatSource::MISP: return L"MISP";
                case ThreatSource::AlienVault_OTX: return L"AlienVault OTX";
                case ThreatSource::ThreatConnect: return L"ThreatConnect";
                case ThreatSource::Anomali: return L"Anomali";
                case ThreatSource::OpenCTI: return L"OpenCTI";
                case ThreatSource::MalwareBazaar: return L"MalwareBazaar";
                case ThreatSource::AbuseIPDB: return L"AbuseIPDB";
                case ThreatSource::URLhaus: return L"URLhaus";
                case ThreatSource::PhishTank: return L"PhishTank";
                case ThreatSource::Shodan: return L"Shodan";
                case ThreatSource::GreyNoise: return L"GreyNoise";
                case ThreatSource::ThreatFox: return L"ThreatFox";
                case ThreatSource::Community: return L"Community";
                case ThreatSource::Partner: return L"Partner";
                case ThreatSource::Commercial: return L"Commercial";
                case ThreatSource::OSINT: return L"OSINT";
                default: return L"Custom";
            }
        }

        std::wstring ThreatIntelDB::TTPPhaseToString(TTPPhase phase) {
            switch (phase) {
                case TTPPhase::Reconnaissance: return L"Reconnaissance";
                case TTPPhase::ResourceDevelopment: return L"Resource Development";
                case TTPPhase::InitialAccess: return L"Initial Access";
                case TTPPhase::Execution: return L"Execution";
                case TTPPhase::Persistence: return L"Persistence";
                case TTPPhase::PrivilegeEscalation: return L"Privilege Escalation";
                case TTPPhase::DefenseEvasion: return L"Defense Evasion";
                case TTPPhase::CredentialAccess: return L"Credential Access";
                case TTPPhase::Discovery: return L"Discovery";
                case TTPPhase::LateralMovement: return L"Lateral Movement";
                case TTPPhase::Collection: return L"Collection";
                case TTPPhase::CommandAndControl: return L"Command and Control";
                case TTPPhase::Exfiltration: return L"Exfiltration";
                case TTPPhase::Impact: return L"Impact";
                default: return L"Unknown";
            }
        }

       
        // =========================================================================
        // Reputation System Functions
        // ============================================================================

        int ThreatIntelDB::GetReputationScore(std::wstring_view identifier, 
                                               IoC_Type type, 
                                               DatabaseError* err) {
            std::string sql = R"(
                SELECT score FROM reputation_scores 
                WHERE identifier = ? AND identifier_type = ?
            )";

            auto result = DatabaseManager::Instance().QueryWithParams(sql, err,
                ToUTF8(identifier), static_cast<int>(type));

            if (result.Next()) {
                return result.GetInt("score");
            }

            return m_config.defaultReputationScore; // Default score
        }

        bool ThreatIntelDB::UpdateReputationScore(const ReputationScore& score, 
                                                   DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Updating reputation score for: %ls", 
                       score.identifier.c_str());

            std::string sql = R"(
                INSERT INTO reputation_scores (
                    identifier, identifier_type, score, threat_level,
                    positive_reports, negative_reports, total_reports,
                    is_whitelisted, is_blacklisted, notes, last_updated, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(identifier, identifier_type) 
                DO UPDATE SET 
                    score = excluded.score,
                    threat_level = excluded.threat_level,
                    positive_reports = excluded.positive_reports,
                    negative_reports = excluded.negative_reports,
                    total_reports = excluded.total_reports,
                    is_whitelisted = excluded.is_whitelisted,
                    is_blacklisted = excluded.is_blacklisted,
                    notes = excluded.notes,
                    last_updated = excluded.last_updated,
                    expires_at = excluded.expires_at
            )";

            auto now = timePointToString(std::chrono::system_clock::now());
            auto expires = timePointToString(std::chrono::system_clock::now() + m_config.reputationExpiry);

            return DatabaseManager::Instance().ExecuteWithParams(sql, err,
                ToUTF8(score.identifier),
                static_cast<int>(score.identifierType),
                score.score,
                static_cast<int>(score.threatLevel),
                static_cast<int64_t>(score.positiveReports),
                static_cast<int64_t>(score.negativeReports),
                static_cast<int64_t>(score.totalReports),
                score.isWhitelisted ? 1 : 0,
                score.isBlacklisted ? 1 : 0,
                ToUTF8(score.notes),
                now,
                expires);
        }

        bool ThreatIntelDB::AddPositiveReport(std::wstring_view identifier, 
                                               IoC_Type type,
                                               ThreatSource source, 
                                               DatabaseError* err) {
            std::string sql = R"(
                UPDATE reputation_scores 
                SET positive_reports = positive_reports + 1,
                    total_reports = total_reports + 1,
                    last_updated = ?
                WHERE identifier = ? AND identifier_type = ?
            )";

            auto now = timePointToString(std::chrono::system_clock::now());
            return DatabaseManager::Instance().ExecuteWithParams(sql, err,
                now, ToUTF8(identifier), static_cast<int>(type));
        }

        bool ThreatIntelDB::AddNegativeReport(std::wstring_view identifier, 
                                               IoC_Type type,
                                               ThreatSource source, 
                                               DatabaseError* err) {
            std::string sql = R"(
                UPDATE reputation_scores 
                SET negative_reports = negative_reports + 1,
                    total_reports = total_reports + 1,
                    last_updated = ?
                WHERE identifier = ? AND identifier_type = ?
            )";

            auto now = timePointToString(std::chrono::system_clock::now());
            return DatabaseManager::Instance().ExecuteWithParams(sql, err,
                now, ToUTF8(identifier), static_cast<int>(type));
        }

        bool ThreatIntelDB::SetWhitelisted(std::wstring_view identifier, 
                                            IoC_Type type, 
                                            bool whitelisted,
                                            std::wstring_view reason, 
                                            DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Setting whitelisted=%d for: %ls (reason: %ls)", 
                       whitelisted, identifier.data(), reason.data());

            std::string sql = R"(
                UPDATE reputation_scores 
                SET is_whitelisted = ?, notes = ?, last_updated = ?
                WHERE identifier = ? AND identifier_type = ?
            )";

            auto now = timePointToString(std::chrono::system_clock::now());
            return DatabaseManager::Instance().ExecuteWithParams(sql, err,
                whitelisted ? 1 : 0,
                ToUTF8(reason),
                now,
                ToUTF8(identifier),
                static_cast<int>(type));
        }

        bool ThreatIntelDB::SetBlacklisted(std::wstring_view identifier, 
                                            IoC_Type type, 
                                            bool blacklisted,
                                            std::wstring_view reason, 
                                            DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Setting blacklisted=%d for: %ls (reason: %ls)", 
                       blacklisted, identifier.data(), reason.data());

            std::string sql = R"(
                UPDATE reputation_scores 
                SET is_blacklisted = ?, notes = ?, last_updated = ?
                WHERE identifier = ? AND identifier_type = ?
            )";

            auto now = timePointToString(std::chrono::system_clock::now());
            return DatabaseManager::Instance().ExecuteWithParams(sql, err,
                blacklisted ? 1 : 0,
                ToUTF8(reason),
                now,
                ToUTF8(identifier),
                static_cast<int>(type));
        }

        bool ThreatIntelDB::IsWhitelisted(std::wstring_view identifier, IoC_Type type) {
            std::string sql = R"(
                SELECT is_whitelisted FROM reputation_scores 
                WHERE identifier = ? AND identifier_type = ?
            )";

            DatabaseError err;
            auto result = DatabaseManager::Instance().QueryWithParams(sql, &err,
                ToUTF8(identifier), static_cast<int>(type));

            if (result.Next()) {
                return result.GetInt("is_whitelisted") != 0;
            }

            return false;
        }

        bool ThreatIntelDB::IsBlacklisted(std::wstring_view identifier, IoC_Type type) {
            std::string sql = R"(
                SELECT is_blacklisted FROM reputation_scores 
                WHERE identifier = ? AND identifier_type = ?
            )";

            DatabaseError err;
            auto result = DatabaseManager::Instance().QueryWithParams(sql, &err,
                ToUTF8(identifier), static_cast<int>(type));

            if (result.Next()) {
                return result.GetInt("is_blacklisted") != 0;
            }

            return false;
        }

        // =========================================================================
        // String Conversion Functions
        // ============================================================================

        ThreatIntelDB::IoC_Type ThreatIntelDB::StringToIoC_Type(std::wstring_view str) {
            // Case-insensitive comparison helper
            auto toLower = [](std::wstring s) {
                std::transform(s.begin(), s.end(), s.begin(), ::towlower);
                return s;
            };

            std::wstring lower = toLower(std::wstring(str));

            if (lower == L"md5") return IoC_Type::FileHash_MD5;
            if (lower == L"sha1") return IoC_Type::FileHash_SHA1;
            if (lower == L"sha256") return IoC_Type::FileHash_SHA256;
            if (lower == L"sha512") return IoC_Type::FileHash_SHA512;
            if (lower == L"ip" || lower == L"ipaddress") return IoC_Type::IP_Address;
            if (lower == L"domain") return IoC_Type::Domain;
            if (lower == L"url") return IoC_Type::URL;
            if (lower == L"email") return IoC_Type::Email;
            if (lower == L"mutex") return IoC_Type::Mutex;
            if (lower == L"registry" || lower == L"registrykey") return IoC_Type::RegistryKey;
            if (lower == L"filepath") return IoC_Type::FilePath;
            if (lower == L"filename") return IoC_Type::FileName;
            if (lower == L"certificate") return IoC_Type::Certificate;
            if (lower == L"useragent") return IoC_Type::UserAgent;
            if (lower == L"ja3") return IoC_Type::JA3_Fingerprint;
            if (lower == L"yara") return IoC_Type::YARA_Rule;
            if (lower == L"cve") return IoC_Type::CVE;
            if (lower == L"asn") return IoC_Type::ASN;
            if (lower == L"mac") return IoC_Type::MAC_Address;

            return IoC_Type::Custom;
        }

        ThreatIntelDB::ThreatSource ThreatIntelDB::StringToThreatSource(std::wstring_view str) {
            auto toLower = [](std::wstring s) {
                std::transform(s.begin(), s.end(), s.begin(), ::towlower);
                return s;
            };

            std::wstring lower = toLower(std::wstring(str));

            if (lower == L"internal") return ThreatSource::Internal;
            if (lower == L"crowdstrike") return ThreatSource::CrowdStrike;
            if (lower == L"virustotal") return ThreatSource::VirusTotal;
            if (lower == L"misp") return ThreatSource::MISP;
            if (lower == L"alienvault" || lower == L"otx") return ThreatSource::AlienVault_OTX;
            if (lower == L"threatconnect") return ThreatSource::ThreatConnect;
            if (lower == L"anomali") return ThreatSource::Anomali;
            if (lower == L"opencti") return ThreatSource::OpenCTI;
            if (lower == L"malwarebazaar") return ThreatSource::MalwareBazaar;
            if (lower == L"abuseipdb") return ThreatSource::AbuseIPDB;
            if (lower == L"urlhaus") return ThreatSource::URLhaus;
            if (lower == L"phishtank") return ThreatSource::PhishTank;
            if (lower == L"shodan") return ThreatSource::Shodan;
            if (lower == L"greynoise") return ThreatSource::GreyNoise;
            if (lower == L"threatfox") return ThreatSource::ThreatFox;
            if (lower == L"community") return ThreatSource::Community;
            if (lower == L"partner") return ThreatSource::Partner;
            if (lower == L"commercial") return ThreatSource::Commercial;
            if (lower == L"osint") return ThreatSource::OSINT;

            return ThreatSource::Custom;
        }

        std::wstring ThreatIntelDB::ThreatConfidenceToString(ThreatConfidence confidence) {
            switch (confidence) {
                case ThreatConfidence::Unverified: return L"Unknown";
                case ThreatConfidence::Low: return L"Low";
                case ThreatConfidence::Medium: return L"Medium";
                case ThreatConfidence::High: return L"High";
                case ThreatConfidence::Confirmed: return L"Confirmed";
                default: return L"Unknown";
            }
        }

        ThreatIntelDB::ThreatConfidence ThreatIntelDB::StringToThreatConfidence(std::wstring_view str) {
            auto toLower = [](std::wstring s) {
                std::transform(s.begin(), s.end(), s.begin(), ::towlower);
                return s;
            };

            std::wstring lower = toLower(std::wstring(str));

            if (lower == L"unconfirmed") return ThreatConfidence::Unverified;
            if (lower == L"low") return ThreatConfidence::Low;
            if (lower == L"medium") return ThreatConfidence::Medium;
            if (lower == L"high") return ThreatConfidence::High;
            if (lower == L"confirmed") return ThreatConfidence::Confirmed;

            return ThreatConfidence::Unverified; // Default
        }

        ThreatIntelDB::TTPPhase ThreatIntelDB::StringToTTPPhase(std::wstring_view str) {
            auto toLower = [](std::wstring s) {
                std::transform(s.begin(), s.end(), s.begin(), ::towlower);
                return s;
            };

            std::wstring lower = toLower(std::wstring(str));

            if (lower == L"reconnaissance") return TTPPhase::Reconnaissance;
            if (lower == L"resourcedevelopment") return TTPPhase::ResourceDevelopment;
            if (lower == L"initialaccess") return TTPPhase::InitialAccess;
            if (lower == L"execution") return TTPPhase::Execution;
            if (lower == L"persistence") return TTPPhase::Persistence;
            if (lower == L"privilegeescalation") return TTPPhase::PrivilegeEscalation;
            if (lower == L"defenseevasion") return TTPPhase::DefenseEvasion;
            if (lower == L"credentialaccess") return TTPPhase::CredentialAccess;
            if (lower == L"discovery") return TTPPhase::Discovery;
            if (lower == L"lateralmovement") return TTPPhase::LateralMovement;
            if (lower == L"collection") return TTPPhase::Collection;
            if (lower == L"commandandcontrol" || lower == L"c2") return TTPPhase::CommandAndControl;
            if (lower == L"exfiltration") return TTPPhase::Exfiltration;
            if (lower == L"impact") return TTPPhase::Impact;

            return TTPPhase::Reconnaissance; // Default
        }

        // =========================================================================
        // Internal Helper Functions
        // ========================================================================

        // ============================================================================
        // Reputation Score Calculation 
        // ============================================================================

        int ThreatIntelDB::calculateReputationScore(const ReputationScore& score) {
            // Thread-safe reputation score calculation with comprehensive logic
            // and audit trail support for compliance requirements

            SS_LOG_DEBUG(L"ThreatIntelDB", L"Calculating reputation for: %ls (type: %d)",
                score.identifier.c_str(), static_cast<int>(score.identifierType));

            // Input validation
            if (score.identifier.empty()) {
                SS_LOG_WARN(L"ThreatIntelDB", L"Empty identifier provided for reputation calculation");
                return m_config.defaultReputationScore;
            }

            // Start with default score
            int calculatedScore = m_config.defaultReputationScore;

            // Stage 1: Apply whitelist/blacklist overrides (highest priority)
            // These are policy-driven decisions and take precedence
            if (score.isWhitelisted) {
                SS_LOG_DEBUG(L"ThreatIntelDB", L"Identifier whitelisted: %ls", score.identifier.c_str());
                return 100;  // Completely benign
            }

            if (score.isBlacklisted) {
                SS_LOG_DEBUG(L"ThreatIntelDB", L"Identifier blacklisted: %ls", score.identifier.c_str());
                return 0;    // Completely malicious
            }

            // Stage 2: Calculate based on report feedback (community/vendor data)
            if (score.totalReports > 0) {
                // Use weighted calculation to account for source reliability
                double positiveRatio = static_cast<double>(score.positiveReports) /
                    static_cast<double>(score.totalReports);

                // Scale to 0-100 range
                calculatedScore = static_cast<int>(positiveRatio * 100.0);

                // Apply confidence damping based on report volume
                // Fewer reports = lower confidence in the score
                const uint64_t MIN_CONFIDENCE_REPORTS = 5;
                const uint64_t HIGH_CONFIDENCE_REPORTS = 50;

                if (score.totalReports < MIN_CONFIDENCE_REPORTS) {
                    // Apply significant damping toward default
                    double damping = static_cast<double>(score.totalReports) / MIN_CONFIDENCE_REPORTS;
                    calculatedScore = static_cast<int>(
                        (calculatedScore * damping) +
                        (m_config.defaultReputationScore * (1.0 - damping))
                        );
                    SS_LOG_DEBUG(L"ThreatIntelDB",
                        L"Low report count (%llu) - damping applied",
                        score.totalReports);
                }
                else if (score.totalReports >= HIGH_CONFIDENCE_REPORTS) {
                    // High confidence - minimal adjustment
                    // Score remains as calculated
                    SS_LOG_DEBUG(L"ThreatIntelDB",
                        L"High report count (%llu) - high confidence score",
                        score.totalReports);
                }

                SS_LOG_DEBUG(L"ThreatIntelDB",
                    L"Report-based score: positive=%llu, negative=%llu, total=%llu, ratio=%.2f%%",
                    score.positiveReports,
                    score.negativeReports,
                    score.totalReports,
                    positiveRatio * 100.0);
            }
            else {
                SS_LOG_DEBUG(L"ThreatIntelDB",
                    L"No reports available - using default score (%d)",
                    m_config.defaultReputationScore);
            }

            // Stage 3: Apply source-based adjustments
            // Different sources have different reliability levels
            if (!score.sources.empty()) {
                double sourceWeight = 0.0;
                double totalSourceReliability = 0.0;

                for (const auto& source : score.sources) {
                    // Assign reliability weights to different sources
                    double sourceReliability = getSourceReliability(source);

                    // Higher severity threats get more weight from authoritative sources
                    if (source == ThreatSource::CrowdStrike ||
                        source == ThreatSource::VirusTotal ||
                        source == ThreatSource::Internal) {
                        sourceWeight += sourceReliability;
                    }
                    else if (source == ThreatSource::Community ||
                        source == ThreatSource::OSINT) {
                        // Community sources get lower weight
                        sourceWeight += sourceReliability * 0.5;
                    }

                    totalSourceReliability += sourceReliability;
                }

                // Normalize source weight
                if (totalSourceReliability > 0.0) {
                    double sourceAdjustment = sourceWeight / totalSourceReliability;
                    // Apply up to ±10% adjustment based on source credibility
                    int adjustment = static_cast<int>(
                        (calculatedScore - m_config.defaultReputationScore) * sourceAdjustment * 0.1
                        );
                    calculatedScore += adjustment;
                }
            }

            // Stage 4: Threat level-based adjustment
            // Match score with expected threat severity
            if (score.threatLevel != ThreatSeverity::Info) {
                int severityScore = static_cast<int>(score.threatLevel) * 15;  // Rough mapping

                // For confirmed high-severity threats, push score toward 0 (malicious)
                if (score.threatLevel == ThreatSeverity::Critical) {
                    calculatedScore = std::min(calculatedScore, 25);  // Must be treated as threat
                }
                else if (score.threatLevel == ThreatSeverity::High) {
                    calculatedScore = std::min(calculatedScore, 40);
                }
                else if (score.threatLevel == ThreatSeverity::Medium) {
                    calculatedScore = std::min(calculatedScore, 55);
                }
            }

            // Stage 5: Temporal decay application
            // Older reputation data becomes less reliable
            auto now = std::chrono::system_clock::now();
            auto ageSeconds = std::chrono::duration_cast<std::chrono::seconds>(
                now - score.lastUpdated
            ).count();

            const auto MAX_AGE_SECONDS = 30 * 24 * 60 * 60LL;  // 30 days

            if (ageSeconds > MAX_AGE_SECONDS) {
                // Score is very stale - move toward default
                double staleFactor = std::min(1.0, static_cast<double>(ageSeconds) / MAX_AGE_SECONDS);
                calculatedScore = static_cast<int>(
                    (calculatedScore * (1.0 - staleFactor)) +
                    (m_config.defaultReputationScore * staleFactor)
                    );
                SS_LOG_WARN(L"ThreatIntelDB",
                    L"Score stale (age: %lld seconds) - applying temporal decay",
                    ageSeconds);
            }

            // Stage 6: Final bounds check and sanitization
            calculatedScore = std::max(0, std::min(100, calculatedScore));

            SS_LOG_DEBUG(L"ThreatIntelDB",
                L"Final reputation score: %d for identifier: %ls",
                calculatedScore,
                score.identifier.c_str());

            return calculatedScore;
        }


        // ============================================================================
        // Helper: Calculate source reliability weight
        // ============================================================================

        double ThreatIntelDB::getSourceReliability(ThreatSource source) const noexcept {
            // Return reliability weight (0.0 to 1.0) for each threat source
            // Based on historical accuracy and industry reputation

            switch (source) {
                // Tier 1: Highly reliable commercial/government sources
            case ThreatSource::CrowdStrike:         return 0.95;
            case ThreatSource::Internal:            return 0.90;  // Your own detections

                // Tier 2: Well-established security firms
            case ThreatSource::VirusTotal:          return 0.85;  // Aggregated vendor data
            case ThreatSource::MISP:                return 0.85;
            case ThreatSource::ThreatConnect:       return 0.83;
            case ThreatSource::Anomali:             return 0.82;

                // Tier 3: Reputable threat intelligence platforms
            case ThreatSource::AlienVault_OTX:      return 0.80;
            case ThreatSource::OpenCTI:             return 0.78;
            case ThreatSource::AbuseIPDB:           return 0.75;
            case ThreatSource::GreyNoise:           return 0.80;  // Excellent IP reputation

                // Tier 4: Specialized databases
            case ThreatSource::MalwareBazaar:       return 0.75;
            case ThreatSource::URLhaus:             return 0.75;
            case ThreatSource::ThreatFox:           return 0.74;
            case ThreatSource::PhishTank:           return 0.72;
            case ThreatSource::Shodan:              return 0.65;

                // Tier 5: Community/OSINT sources (lower confidence)
            case ThreatSource::Community:           return 0.50;
            case ThreatSource::OSINT:               return 0.55;
            case ThreatSource::Partner:             return 0.70;
            case ThreatSource::Commercial:          return 0.80;
            case ThreatSource::Custom:              return 0.60;

                // Unknown source - assume low reliability
            default:
                SS_LOG_WARN(L"ThreatIntelDB",
                    L"Unknown threat source: %d",
                    static_cast<int>(source));
                return 0.40;
            }
        }


        // ============================================================================
        // Threat Actor Row Deserialization - Enterprise Grade
        // ============================================================================

        ThreatIntelDB::ThreatActor ThreatIntelDB::rowToActor(const QueryResult& result) {
            // Comprehensive threat actor deserialization with full data population
            // Includes validation, error handling, and audit trail support

            ThreatActor actor;

            try {
                // Primary identity fields
                actor.id = result.GetInt64("id");
                actor.name = result.GetWString("name");

                // Validate essential fields
                if (actor.id <= 0 || actor.name.empty()) {
                    SS_LOG_ERROR(L"ThreatIntelDB",
                        L"Invalid threat actor record: ID=%lld, Name empty=%d",
                        actor.id, actor.name.empty());
                    throw std::runtime_error("Invalid threat actor record structure");
                }

                // Descriptive fields
                actor.description = result.GetWString("description");
                actor.motivation = result.GetWString("motivation");
                actor.origin = result.GetWString("origin");

                // Severity and classification
                if (!result.IsNull("threat_level")) {
                    actor.threatLevel = static_cast<ThreatSeverity>(result.GetInt("threat_level"));
                }
                else {
                    actor.threatLevel = ThreatSeverity::Medium;
                }

                // Boolean flags - safe null checking
                actor.isAPT = result.IsNull("is_apt") ? false : (result.GetInt("is_apt") != 0);
                actor.isActive = result.IsNull("is_active") ? true : (result.GetInt("is_active") != 0);

                // Timestamps with validation
                if (!result.IsNull("first_seen")) {
                    actor.firstSeen = stringToTimePoint(result.GetString("first_seen"));
                }

                if (!result.IsNull("last_activity")) {
                    actor.lastActivity = stringToTimePoint(result.GetString("last_activity"));
                }

                if (!result.IsNull("created_at")) {
                    actor.createdAt = stringToTimePoint(result.GetString("created_at"));
                }
                else {
                    actor.createdAt = std::chrono::system_clock::now();
                }

                SS_LOG_DEBUG(L"ThreatIntelDB",
                    L"Loaded threat actor: ID=%lld, Name=%ls, APT=%d, Active=%d",
                    actor.id, actor.name.c_str(), actor.isAPT, actor.isActive);

            }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(L"ThreatIntelDB",
                    L"Error deserializing threat actor: %ls",
                    ToWide(ex.what()).c_str());
                throw;
            }

            // Load related data using separate queries (prevents N+1 issues with caching)
            loadActorAliases(actor);
            loadActorTargeting(actor);
            loadActorTTPAssociations(actor);
            loadActorCampaignAssociations(actor);

            SS_LOG_DEBUG(L"ThreatIntelDB",
                L"Threat actor fully loaded: %ls (aliases=%zu, campaigns=%zu, ttps=%zu)",
                actor.name.c_str(),
                actor.aliases.size(),
                actor.campaigns.size(),
                actor.ttps.size());

            return actor;
        }


        // ============================================================================
        // Helper: Load Actor Aliases
        // ============================================================================

        void ThreatIntelDB::loadActorAliases(ThreatActor& actor) {
            if (actor.id <= 0) return;

            DatabaseError err;
            auto& dbMgr = DatabaseManager::Instance();

            try {
                std::string query = R"SQL(
                    SELECT alias_name FROM threat_actor_aliases 
                    WHERE actor_id = ? 
                    ORDER BY alias_name ASC
                )SQL";

                auto result = dbMgr.QueryWithParams(query, &err, actor.id);

                while (result.Next()) {
                    std::wstring alias = result.GetWString("alias_name");
                    if (!alias.empty()) {
                        actor.aliases.push_back(alias);
                    }
                }

                SS_LOG_DEBUG(L"ThreatIntelDB",
                    L"Loaded %zu aliases for actor: %ls",
                    actor.aliases.size(), actor.name.c_str());

            }
            catch (const std::exception& ex) {
                SS_LOG_WARN(L"ThreatIntelDB",
                    L"Failed to load aliases for actor %lld: %ls",
                    actor.id, ToWide(ex.what()).c_str());
            }
        }


        // ============================================================================
        // Helper: Load Actor Targeting Information
        // ============================================================================

        void ThreatIntelDB::loadActorTargeting(ThreatActor& actor) {
            if (actor.id <= 0) return;

            DatabaseError err;
            auto& dbMgr = DatabaseManager::Instance();

            try {
                // Load targeted sectors
                std::string sectorQuery = R"SQL(
                    SELECT DISTINCT sector_name FROM threat_actor_targets 
                    WHERE actor_id = ? AND target_type = 'SECTOR'
                    ORDER BY sector_name ASC
                )SQL";

                auto sectorResult = dbMgr.QueryWithParams(sectorQuery, &err, actor.id);

                while (sectorResult.Next()) {
                    std::wstring sector = sectorResult.GetWString("sector_name");
                    if (!sector.empty()) {
                        actor.targetSectors.push_back(sector);
                    }
                }

                // Load targeted countries
                std::string countryQuery = R"SQL(
                    SELECT DISTINCT country_code, country_name FROM threat_actor_targets 
                    WHERE actor_id = ? AND target_type = 'COUNTRY'
                    ORDER BY country_name ASC
                )SQL";

                auto countryResult = dbMgr.QueryWithParams(countryQuery, &err, actor.id);

                while (countryResult.Next()) {
                    std::wstring country = countryResult.GetWString("country_name");
                    if (!country.empty()) {
                        actor.targetCountries.push_back(country);
                    }
                }

                SS_LOG_DEBUG(L"ThreatIntelDB",
                    L"Loaded targeting data for actor %ls: sectors=%zu, countries=%zu",
                    actor.name.c_str(),
                    actor.targetSectors.size(),
                    actor.targetCountries.size());

            }
            catch (const std::exception& ex) {
                SS_LOG_WARN(L"ThreatIntelDB",
                    L"Failed to load targeting for actor %lld: %ls",
                    actor.id, ToWide(ex.what()).c_str());
            }
        }


        // ============================================================================
        // Helper: Load Actor TTP Associations
        // ============================================================================

        void ThreatIntelDB::loadActorTTPAssociations(ThreatActor& actor) {
            if (actor.id <= 0) return;

            DatabaseError err;
            auto& dbMgr = DatabaseManager::Instance();

            try {
                std::string query = R"SQL(
                    SELECT DISTINCT t.mitre_id, t.name 
                    FROM threat_actor_ttp_mappings m
                    JOIN ttp_entries t ON m.ttp_id = t.id
                    WHERE m.actor_id = ? AND t.is_active = 1
                    ORDER BY t.mitre_id ASC
                )SQL";

                auto result = dbMgr.QueryWithParams(query, &err, actor.id);

                while (result.Next()) {
                    std::wstring mitreId = result.GetWString("mitre_id");
                    if (!mitreId.empty()) {
                        actor.ttps.push_back(mitreId);
                    }
                }

                SS_LOG_DEBUG(L"ThreatIntelDB",
                    L"Loaded %zu MITRE ATT&CK TTPs for actor: %ls",
                    actor.ttps.size(), actor.name.c_str());

            }
            catch (const std::exception& ex) {
                SS_LOG_WARN(L"ThreatIntelDB",
                    L"Failed to load TTPs for actor %lld: %ls",
                    actor.id, ToWide(ex.what()).c_str());
            }
        }


        // ============================================================================
        // Helper: Load Actor Campaign Associations
        // ============================================================================

        void ThreatIntelDB::loadActorCampaignAssociations(ThreatActor& actor) {
            if (actor.id <= 0) return;

            DatabaseError err;
            auto& dbMgr = DatabaseManager::Instance();

            try {
                std::string query = R"SQL(
                    SELECT DISTINCT c.name, c.is_active
                    FROM threat_campaigns c
                    WHERE c.id IN (
                        SELECT campaign_id FROM threat_campaign_actors 
                        WHERE actor_id = ?
                    )
                    ORDER BY c.name ASC
                )SQL";

                auto result = dbMgr.QueryWithParams(query, &err, actor.id);

                while (result.Next()) {
                    std::wstring campaignName = result.GetWString("name");
                    bool isActive = result.GetInt("is_active") != 0;

                    if (!campaignName.empty()) {
                        actor.campaigns.push_back(campaignName);
                    }
                }

                SS_LOG_DEBUG(L"ThreatIntelDB",
                    L"Loaded %zu campaigns for actor: %ls",
                    actor.campaigns.size(), actor.name.c_str());

            }
            catch (const std::exception& ex) {
                SS_LOG_WARN(L"ThreatIntelDB",
                    L"Failed to load campaigns for actor %lld: %ls",
                    actor.id, ToWide(ex.what()).c_str());
            }
        }

        // =========================================================================
        // Statistics
        // =========================================================================

        ThreatIntelDB::Statistics ThreatIntelDB::GetStatistics(DatabaseError* err) {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            return m_stats;
        }

        void ThreatIntelDB::ResetStatistics() {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_stats = Statistics{};
            SS_LOG_INFO(L"ThreatIntelDB", L"Statistics reset");
        }

        // =========================================================================
        // Configuration
        // =========================================================================

        ThreatIntelDB::Config ThreatIntelDB::GetConfig() const {
            std::shared_lock<std::shared_mutex> lock(m_configMutex);
            return m_config;
        }
      
        // =========================================================================
        // Import/Export Operations (STIX, JSON formats)
        // =========================================================================

        bool ThreatIntelDB::ExportIoCsToSTIX(std::wstring_view outputPath,
            const QueryFilter* filter,
            DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Exporting IoCs to STIX format: %ls", outputPath.data());

            // Query IoCs
            std::vector<IoC_Entry> iocs;
            if (filter) {
                iocs = QueryIoCs(*filter, err);
            }
            else {
                QueryFilter allFilter;
                allFilter.activeOnly = false;
                allFilter.excludeFalsePositives = false;
                allFilter.maxResults = SIZE_MAX;
                iocs = QueryIoCs(allFilter, err);
            }

            if (iocs.empty()) {
                SS_LOG_WARN(L"ThreatIntelDB", L"No IoCs to export");
                return true;
            }

            try {
                // Create STIX 2.1 bundle
                Utils::JSON::Json stixBundle;
                stixBundle["type"] = "bundle";
                stixBundle["id"] = "bundle--" + ToUTF8(generateUUID());
                stixBundle["spec_version"] = "2.1";

                auto now = std::chrono::system_clock::now();
                stixBundle["created"] = formatISO8601(now);

                Utils::JSON::Json objects = Utils::JSON::Json::array();

                for (const auto& ioc : iocs) {
                    Utils::JSON::Json indicator;
                    indicator["type"] = "indicator";
                    indicator["id"] = "indicator--" + ToUTF8(generateUUID());
                    indicator["created"] = formatISO8601(ioc.createdAt);
                    indicator["modified"] = formatISO8601(ioc.updatedAt);
                    indicator["name"] = ToUTF8(ioc.threatName);
                    indicator["description"] = ToUTF8(ioc.description);

                    // Pattern based on IoC type
                    std::string pattern = buildSTIXPattern(ioc);
                    indicator["pattern"] = pattern;
                    indicator["pattern_type"] = "stix";

                    indicator["valid_from"] = formatISO8601(ioc.firstSeen);
                    if (ioc.expiresAt > std::chrono::system_clock::now()) {
                        indicator["valid_until"] = formatISO8601(ioc.expiresAt);
                    }

                    // Labels
                    Utils::JSON::Json labels = Utils::JSON::Json::array();
                    for (const auto& tag : ioc.tags) {
                        labels.push_back(ToUTF8(tag));
                    }
                    indicator["labels"] = labels;

                    // Confidence
                    indicator["confidence"] = static_cast<int>(ioc.confidence) * 25; // 0-100 scale

                    objects.push_back(indicator);
                }

                stixBundle["objects"] = objects;

                // Write to file
                std::string jsonStr = stixBundle.dump(2);
                std::wstring jsonWide = ToWide(jsonStr);

				Utils::FileUtils::Error fileErr;
                if (!Utils::FileUtils::WriteAllTextUtf8Atomic(outputPath, jsonStr, &fileErr)) {
                    if (err) {
                        err->sqliteCode = SQLITE_IOERR;
                        err->message = L"Failed to write STIX file: " + std::to_wstring(fileErr.win32);
                    }
                    return false;
                }

                SS_LOG_INFO(L"ThreatIntelDB", L"Exported %zu IoCs to STIX format", iocs.size());
                return true;
            }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"STIX export failed: %hs", ex.what());
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"STIX export exception: " + ToWide(ex.what());
                }
                return false;
            }
        }

        bool ThreatIntelDB::ImportIoCsFromSTIX(std::wstring_view inputPath, DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Importing IoCs from STIX format: %ls", inputPath.data());

            // Read file
            std::string jsonStr;
			Utils::FileUtils::Error fileErr;
            if (!Utils::FileUtils::ReadAllTextUtf8(inputPath, jsonStr, &fileErr)) {
                if (err) {
                    err->sqliteCode = SQLITE_IOERR;
                    err->message = L"Failed to read STIX file: " + std::to_wstring(fileErr.win32);
                }
                return false;
            }

            try {
                Utils::JSON::Json stixBundle = Utils::JSON::Json::parse(jsonStr);

                if (!stixBundle.contains("objects") || !stixBundle["objects"].is_array()) {
                    if (err) {
                        err->sqliteCode = SQLITE_FORMAT;
                        err->message = L"Invalid STIX format: missing objects array";
                    }
                    return false;
                }

                std::vector<IoC_Entry> iocs;

                for (const auto& obj : stixBundle["objects"]) {
                    if (obj["type"] != "indicator") continue;

                    IoC_Entry ioc;

                    // Parse pattern to extract IoC type and value
                    if (!parseSTIXPattern(obj["pattern"].get<std::string>(), ioc)) {
                        SS_LOG_WARN(L"ThreatIntelDB", L"Failed to parse STIX pattern");
                        continue;
                    }

                    ioc.threatName = ToWide(obj.value("name", ""));
                    ioc.description = ToWide(obj.value("description", ""));
                    ioc.source = ThreatSource::MISP; // Assume MISP as default
                    ioc.confidence = ThreatConfidence::Medium;
                    ioc.severity = ThreatSeverity::Medium;
                    ioc.threatType = ThreatType::Unknown;

                    // Parse timestamps
                    if (obj.contains("created")) {
                        ioc.createdAt = parseISO8601(obj["created"].get<std::string>());
                        ioc.firstSeen = ioc.createdAt;
                    }
                    if (obj.contains("modified")) {
                        ioc.updatedAt = parseISO8601(obj["modified"].get<std::string>());
                        ioc.lastSeen = ioc.updatedAt;
                    }
                    if (obj.contains("valid_until")) {
                        ioc.expiresAt = parseISO8601(obj["valid_until"].get<std::string>());
                    }
                    else {
                        ioc.expiresAt = std::chrono::system_clock::now() + m_config.iocDefaultTTL;
                    }

                    // Parse labels/tags
                    if (obj.contains("labels") && obj["labels"].is_array()) {
                        for (const auto& label : obj["labels"]) {
                            ioc.tags.push_back(ToWide(label.get<std::string>()));
                        }
                    }

                    iocs.push_back(ioc);
                }

                // Batch import
                if (!AddIoCBatch(iocs, err)) {
                    return false;
                }

                SS_LOG_INFO(L"ThreatIntelDB", L"Imported %zu IoCs from STIX format", iocs.size());
                return true;
            }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"STIX import failed: %hs", ex.what());
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"STIX import exception: " + ToWide(ex.what());
                }
                return false;
            }
        }

        bool ThreatIntelDB::ExportIoCsToJSON(std::wstring_view outputPath,
            const QueryFilter* filter,
            DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Exporting IoCs to JSON format: %ls", outputPath.data());

            std::vector<IoC_Entry> iocs;
            if (filter) {
                iocs = QueryIoCs(*filter, err);
            }
            else {
                QueryFilter allFilter;
                allFilter.activeOnly = false;
                allFilter.excludeFalsePositives = false;
                allFilter.maxResults = SIZE_MAX;
                iocs = QueryIoCs(allFilter, err);
            }

            if (iocs.empty()) {
                SS_LOG_WARN(L"ThreatIntelDB", L"No IoCs to export");
                return true;
            }

            try {
                Utils::JSON::Json root;
                root["version"] = "1.0";
                root["export_time"] = formatISO8601(std::chrono::system_clock::now());
                root["total_count"] = iocs.size();

                Utils::JSON::Json iocArray = Utils::JSON::Json::array();

                for (const auto& ioc : iocs) {
                    Utils::JSON::Json iocJson;
                    iocJson["id"] = ioc.id;
                    iocJson["type"] = static_cast<int>(ioc.type);
                    iocJson["value"] = ToUTF8(ioc.value);
                    iocJson["threat_type"] = static_cast<int>(ioc.threatType);
                    iocJson["severity"] = static_cast<int>(ioc.severity);
                    iocJson["confidence"] = static_cast<int>(ioc.confidence);
                    iocJson["source"] = static_cast<int>(ioc.source);
                    iocJson["threat_name"] = ToUTF8(ioc.threatName);
                    iocJson["description"] = ToUTF8(ioc.description);
                    iocJson["first_seen"] = formatISO8601(ioc.firstSeen);
                    iocJson["last_seen"] = formatISO8601(ioc.lastSeen);
                    iocJson["expires_at"] = formatISO8601(ioc.expiresAt);
                    iocJson["hit_count"] = ioc.hitCount;
                    iocJson["is_active"] = ioc.isActive;
                    iocJson["risk_score"] = ioc.riskScore;

                    if (!ioc.campaign.empty()) {
                        iocJson["campaign"] = ToUTF8(ioc.campaign);
                    }
                    if (!ioc.threatActor.empty()) {
                        iocJson["threat_actor"] = ToUTF8(ioc.threatActor);
                    }

                    Utils::JSON::Json tags = Utils::JSON::Json::array();
                    for (const auto& tag : ioc.tags) {
                        tags.push_back(ToUTF8(tag));
                    }
                    iocJson["tags"] = tags;

                    iocArray.push_back(iocJson);
                }

                root["iocs"] = iocArray;

                // Write to file
                std::string jsonStr = root.dump(2);

				Utils::FileUtils::Error fileErr;
                if (!Utils::FileUtils::WriteAllTextUtf8Atomic(outputPath, jsonStr, &fileErr)) {
                    if (err) {
                        err->sqliteCode = SQLITE_IOERR;
                        err->message = L"Failed to write JSON file";
                    }
                    return false;
                }

                SS_LOG_INFO(L"ThreatIntelDB", L"Exported %zu IoCs to JSON format", iocs.size());
                return true;
            }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"JSON export failed: %hs", ex.what());
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = ToWide(ex.what());
                }
                return false;
            }
        }

        bool ThreatIntelDB::ImportIoCsFromJSON(std::wstring_view inputPath, DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Importing IoCs from JSON format: %ls", inputPath.data());

            std::string jsonStr;
			Utils::FileUtils::Error fileErr;
            if (!Utils::FileUtils::ReadAllTextUtf8(inputPath, jsonStr, &fileErr)) {
                if (err) {
                    err->sqliteCode = SQLITE_IOERR;
                    err->message = L"Failed to read JSON file";
                }
                return false;
            }

            try {
                Utils::JSON::Json root = Utils::JSON::Json::parse(jsonStr);

                if (!root.contains("iocs") || !root["iocs"].is_array()) {
                    if (err) {
                        err->sqliteCode = SQLITE_FORMAT;
                        err->message = L"Invalid JSON format";
                    }
                    return false;
                }

                std::vector<IoC_Entry> iocs;

                for (const auto& iocJson : root["iocs"]) {
                    IoC_Entry ioc;

                    ioc.type = static_cast<IoC_Type>(iocJson.value("type", 0));
                    ioc.value = ToWide(iocJson.value("value", ""));
                    ioc.threatType = static_cast<ThreatType>(iocJson.value("threat_type", 0));
                    ioc.severity = static_cast<ThreatSeverity>(iocJson.value("severity", 0));
                    ioc.confidence = static_cast<ThreatConfidence>(iocJson.value("confidence", 0));
                    ioc.source = static_cast<ThreatSource>(iocJson.value("source", 0));
                    ioc.threatName = ToWide(iocJson.value("threat_name", ""));
                    ioc.description = ToWide(iocJson.value("description", ""));
                    ioc.riskScore = iocJson.value("risk_score", 0);

                    if (iocJson.contains("campaign")) {
                        ioc.campaign = ToWide(iocJson["campaign"].get<std::string>());
                    }
                    if (iocJson.contains("threat_actor")) {
                        ioc.threatActor = ToWide(iocJson["threat_actor"].get<std::string>());
                    }

                    if (iocJson.contains("tags") && iocJson["tags"].is_array()) {
                        for (const auto& tag : iocJson["tags"]) {
                            ioc.tags.push_back(ToWide(tag.get<std::string>()));
                        }
                    }

                    // Set timestamps
                    ioc.createdAt = std::chrono::system_clock::now();
                    ioc.updatedAt = ioc.createdAt;
                    ioc.firstSeen = ioc.createdAt;
                    ioc.lastSeen = ioc.createdAt;
                    ioc.expiresAt = ioc.createdAt + m_config.iocDefaultTTL;

                    iocs.push_back(ioc);
                }

                if (!AddIoCBatch(iocs, err)) {
                    return false;
                }

                SS_LOG_INFO(L"ThreatIntelDB", L"Imported %zu IoCs from JSON format", iocs.size());
                return true;
            }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"JSON import failed: %hs", ex.what());
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = ToWide(ex.what());
                }
                return false;
            }
        }

        // =========================================================================
        // Advanced Analysis Operations
        // =========================================================================

        std::vector<ThreatIntelDB::IoC_Entry> ThreatIntelDB::FindRelatedIoCs(
            int64_t iocId,
            size_t maxResults,
            DatabaseError* err) {

            SS_LOG_INFO(L"ThreatIntelDB", L"Finding related IoCs for ID: %lld", iocId);

            auto baseIoc = GetIoC(iocId, err);
            if (!baseIoc.has_value()) {
                return {};
            }

            std::vector<IoC_Entry> relatedIoCs;

            // Find IoCs with same campaign
            if (!baseIoc->campaign.empty()) {
                QueryFilter filter;
                filter.campaignName = baseIoc->campaign;
                filter.maxResults = maxResults / 3;

                auto campaignIoCs = QueryIoCs(filter, err);
                relatedIoCs.insert(relatedIoCs.end(), campaignIoCs.begin(), campaignIoCs.end());
            }

            // Find IoCs with same threat actor
            if (!baseIoc->threatActor.empty()) {
                QueryFilter filter;
                filter.threatActor = baseIoc->threatActor;
                filter.maxResults = maxResults / 3;

                auto actorIoCs = QueryIoCs(filter, err);
                relatedIoCs.insert(relatedIoCs.end(), actorIoCs.begin(), actorIoCs.end());
            }

            // Find IoCs with similar tags
            if (!baseIoc->tags.empty()) {
                for (const auto& tag : baseIoc->tags) {
                    QueryFilter filter;
                    filter.tagPattern = tag;
                    filter.maxResults = maxResults / (3 * baseIoc->tags.size());

                    auto tagIoCs = QueryIoCs(filter, err);
                    relatedIoCs.insert(relatedIoCs.end(), tagIoCs.begin(), tagIoCs.end());
                }
            }

            // Remove duplicates
            std::sort(relatedIoCs.begin(), relatedIoCs.end(),
                [](const IoC_Entry& a, const IoC_Entry& b) { return a.id < b.id; });

            auto last = std::unique(relatedIoCs.begin(), relatedIoCs.end(),
                [](const IoC_Entry& a, const IoC_Entry& b) { return a.id == b.id; });

            relatedIoCs.erase(last, relatedIoCs.end());

            // Limit results
            if (relatedIoCs.size() > maxResults) {
                relatedIoCs.resize(maxResults);
            }

            SS_LOG_INFO(L"ThreatIntelDB", L"Found %zu related IoCs", relatedIoCs.size());
            return relatedIoCs;
        }

        std::unordered_map<std::wstring, std::vector<int64_t>> ThreatIntelDB::ClusterIoCsByCampaign(
            const std::vector<int64_t>& iocIds,
            DatabaseError* err) {

            SS_LOG_INFO(L"ThreatIntelDB", L"Clustering %zu IoCs by campaign", iocIds.size());

            std::unordered_map<std::wstring, std::vector<int64_t>> clusters;

            for (int64_t id : iocIds) {
                auto ioc = GetIoC(id, err);
                if (!ioc.has_value()) continue;

                std::wstring campaignKey = ioc->campaign.empty() ? L"<unknown>" : ioc->campaign;
                clusters[campaignKey].push_back(id);
            }

            SS_LOG_INFO(L"ThreatIntelDB", L"Created %zu campaign clusters", clusters.size());
            return clusters;
        }

        std::vector<ThreatIntelDB::IoC_Entry> ThreatIntelDB::GetThreatTimeline(
            std::chrono::system_clock::time_point start,
            std::chrono::system_clock::time_point end,
            DatabaseError* err) {

            SS_LOG_INFO(L"ThreatIntelDB", L"Getting threat timeline");

            QueryFilter filter;
            filter.firstSeenAfter = start;
            filter.firstSeenBefore = end;
            filter.sortByRiskScore = true;
            filter.sortDescending = true;
            filter.maxResults = 1000;

            return QueryIoCs(filter, err);
        }

        std::vector<ThreatIntelDB::IoC_Entry> ThreatIntelDB::GetTopThreatsByHitCount(
            size_t topN,
            DatabaseError* err) {

            SS_LOG_INFO(L"ThreatIntelDB", L"Getting top %zu threats by hit count", topN);

            std::string sql = R"(
        SELECT * FROM ioc_entries 
        WHERE is_active = 1 AND is_false_positive = 0
        ORDER BY hit_count DESC 
        LIMIT ?
    )";

            std::vector<std::string> params;
            params.push_back(std::to_string(topN));

            return dbSelectIoCs(sql, params, err);
        }

        std::vector<ThreatIntelDB::IoC_Entry> ThreatIntelDB::GetTopThreatsByRiskScore(
            size_t topN,
            DatabaseError* err) {

            SS_LOG_INFO(L"ThreatIntelDB", L"Getting top %zu threats by risk score", topN);

            std::string sql = R"(
        SELECT * FROM ioc_entries 
        WHERE is_active = 1 AND is_false_positive = 0
        ORDER BY risk_score DESC, hit_count DESC 
        LIMIT ?
    )";

            std::vector<std::string> params;
            params.push_back(std::to_string(topN));

            return dbSelectIoCs(sql, params, err);
        }

        std::vector<std::wstring> ThreatIntelDB::GetTopThreatActors(
            size_t topN,
            DatabaseError* err) {

            SS_LOG_INFO(L"ThreatIntelDB", L"Getting top %zu threat actors", topN);

            std::string sql = R"(
        SELECT threat_actor, COUNT(*) as count 
        FROM ioc_entries 
        WHERE threat_actor IS NOT NULL AND threat_actor != ''
        GROUP BY threat_actor 
        ORDER BY count DESC 
        LIMIT ?
    )";

            std::vector<std::wstring> actors;

            try {
                auto result = DatabaseManager::Instance().QueryWithParams(sql, err, static_cast<int>(topN));

                while (result.Next()) {
                    actors.push_back(result.GetWString("threat_actor"));
                }
            }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"Failed to get top threat actors: %hs", ex.what());
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = ToWide(ex.what());
                }
            }

            return actors;
        }

        // =========================================================================
        // Database Backup/Restore Operations
        // =========================================================================

        bool ThreatIntelDB::RestoreDatabase(std::wstring_view backupPath, DatabaseError* err) {
            SS_LOG_INFO(L"ThreatIntelDB", L"Restoring database from: %ls", backupPath.data());

			Utils::FileUtils::Error fileErr;
            if (!Utils::FileUtils::Exists(backupPath,&fileErr)) {
                if (err) {
                    err->sqliteCode = SQLITE_IOERR;
                    err->message = L"Backup file not found";
                }
                return false;
            }

            // Shutdown current database
            Shutdown();

            try {
                // Copy backup file to database location
                std::wstring tempPath = m_config.dbPath + L".restore_temp";

                std::vector<std::byte> backupData;
				Utils::FileUtils::Error readErr;    
                if (!Utils::FileUtils::ReadAllBytes(backupPath, backupData, &readErr)) {
                    if (err) {
                        err->sqliteCode = SQLITE_IOERR;
                        err->message = L"Failed to read backup file";
                    }
                    return false;
                }
               
				Utils::FileUtils::Error writeErr;
                std::vector<std::byte> tmpBytes(backupData.size());
				std::memcpy(tmpBytes.data(), backupData.data(), backupData.size());
                if (!Utils::FileUtils::WriteAllBytesAtomic(tempPath, backupData, &writeErr)) {
                    if (err) {
                        err->sqliteCode = SQLITE_IOERR;
                        err->message = L"Failed to write database file";
                    }
                    return false;
                }

                // Replace original database
                if (!Utils::FileUtils::ReplaceFileAtomic(tempPath, m_config.dbPath, &writeErr)) {
                    if (err) {
                        err->sqliteCode = SQLITE_IOERR;
                        err->message = L"Failed to replace database file";
                    }
                    return false;
                }

                // Reinitialize with restored database
                Config restoredConfig = m_config;
                if (!Initialize(restoredConfig, err)) {
                    return false;
                }

                SS_LOG_INFO(L"ThreatIntelDB", L"Database restored successfully");
                return true;
            }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"Database restore failed: %hs", ex.what());
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = ToWide(ex.what());
                }
                return false;
            }
        }

        // =========================================================================
        // Helper Functions (Private)
        // =========================================================================

        std::wstring ThreatIntelDB::generateUUID() const {
            GUID guid;
            CoCreateGuid(&guid);

            wchar_t guidStr[40];
            swprintf_s(guidStr, L"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                guid.Data1, guid.Data2, guid.Data3,
                guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
                guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);

            return std::wstring(guidStr);
        }

        std::string ThreatIntelDB::formatISO8601(std::chrono::system_clock::time_point tp) const {
            auto time = std::chrono::system_clock::to_time_t(tp);
            std::tm tm;
            gmtime_s(&tm, &time);

            char buffer[32];
            std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm);

            return std::string(buffer);
        }

        std::chrono::system_clock::time_point ThreatIntelDB::parseISO8601(const std::string& str) const {
            std::tm tm = {};
            std::istringstream ss(str);
            ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");

            auto time = std::mktime(&tm);
            return std::chrono::system_clock::from_time_t(time);
        }

        std::string ThreatIntelDB::buildSTIXPattern(const IoC_Entry& ioc) const {
            std::ostringstream pattern;
            pattern << "[";

            switch (ioc.type) {
            case IoC_Type::FileHash_MD5:
                pattern << "file:hashes.MD5 = '" << ToUTF8(ioc.value) << "'";
                break;
            case IoC_Type::FileHash_SHA256:
                pattern << "file:hashes.'SHA-256' = '" << ToUTF8(ioc.value) << "'";
                break;
            case IoC_Type::IP_Address:
                pattern << "ipv4-addr:value = '" << ToUTF8(ioc.value) << "'";
                break;
            case IoC_Type::Domain:
                pattern << "domain-name:value = '" << ToUTF8(ioc.value) << "'";
                break;
            case IoC_Type::URL:
                pattern << "url:value = '" << ToUTF8(ioc.value) << "'";
                break;
            default:
                pattern << "x-custom:value = '" << ToUTF8(ioc.value) << "'";
                break;
            }

            pattern << "]";
            return pattern.str();
        }

        bool ThreatIntelDB::parseSTIXPattern(const std::string& pattern, IoC_Entry& outIoc) const {
            // Simplified STIX pattern parser
            if (pattern.find("file:hashes.MD5") != std::string::npos) {
                outIoc.type = IoC_Type::FileHash_MD5;
            }
            else if (pattern.find("file:hashes.'SHA-256'") != std::string::npos) {
                outIoc.type = IoC_Type::FileHash_SHA256;
            }
            else if (pattern.find("ipv4-addr:value") != std::string::npos) {
                outIoc.type = IoC_Type::IP_Address;
            }
            else if (pattern.find("domain-name:value") != std::string::npos) {
                outIoc.type = IoC_Type::Domain;
            }
            else if (pattern.find("url:value") != std::string::npos) {
                outIoc.type = IoC_Type::URL;
            }
            else {
                return false;
            }

            // Extract value between quotes
            size_t start = pattern.find("'");
            size_t end = pattern.rfind("'");

            if (start != std::string::npos && end != std::string::npos && end > start) {
                std::string value = pattern.substr(start + 1, end - start - 1);
                outIoc.value = ToWide(value);
                return true;
            }

            return false;
        }


        // ============================================================================
        // YARA Rules Import/Export Implementation
        // ============================================================================

        bool ThreatIntelDB::ExportYaraRules(std::wstring_view outputPath, DatabaseError* err) {
            if (!m_initialized.load(std::memory_order_acquire)) {
                if (err) err->message = L"ThreatIntelDB not initialized";
				SS_LOG_ERROR(L"ThreatIntelDB", L"ExportYaraRules: DB not initialized");
                return false;
            }

            SS_LOG_INFO(L"ThreatIntelDB", L"Exporting YARA rules to: %ls", outputPath.data());

            auto& dbMgr = DatabaseManager::Instance();

            // Query all YARA signature entries
            std::string sql = R"(
        SELECT id, name, signature_data, type, category, status, severity, 
               platform, version, author, description, tags, metadata,
               detection_count, false_positive_count, effectiveness_score,
               created_at, updated_at
        FROM signatures
        WHERE type = ? AND status = ?
        ORDER BY name ASC
    )";

            auto result = dbMgr.QueryWithParams(
                sql,
                err,
                static_cast<int>(Database::SignatureDB::SignatureType::YaraRule),
                static_cast<int>(Database::SignatureDB::SignatureStatus::Active)
            );

            if (err && !err->message.empty()) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"ExportYaraRules: Query failed");
                return false;
            }

            // Validate output directory
            std::filesystem::path outPath(outputPath);
            auto outDir = outPath.parent_path();
            if (!outDir.empty()) {
                Utils::FileUtils::Error fileErr;
                if (!Utils::FileUtils::CreateDirectories(outDir.wstring(), &fileErr)) {
                    if (err) {
                        err->message = L"Failed to create output directory: " +
                            std::wstring(fileErr.message.begin(), fileErr.message.end());
                    }
                    SS_LOG_ERROR(L"ThreatIntelDB", L"ExportYaraRules: Failed to create output directory");
                    return false;
                }
            }

            // Build combined YARA rules file
            std::wostringstream yaraContent;

            // Add file header with metadata
            yaraContent << L"/*\n";
            yaraContent << L" * YARA Rules Export\n";
            yaraContent << L" * Generated by: ShadowStrike ThreatIntelDB\n";
            yaraContent << L" * Export Date: " << Utils::SystemUtils::NowFileTime100nsUTC() << L"\n";
            yaraContent << L" * Total Rules: ";

            size_t exportedCount = 0;
            size_t skippedCount = 0;
            std::vector<std::wstring> ruleNames;

            // First pass: count rules
            while (result.Next()) {
                exportedCount++;
            }

            yaraContent << exportedCount << L"\n";
            yaraContent << L" */\n\n";

            // Re-query for actual export (since we consumed the result)
            result = dbMgr.QueryWithParams(
                sql,
                err,
                static_cast<int>(Database::SignatureDB::SignatureType::YaraRule),
                static_cast<int>(Database::SignatureDB::SignatureStatus::Active)
            );

            // Second pass: export rules
            while (result.Next()) {
                try {
                    int64_t id = result.GetInt64(0);
                    std::wstring name = result.GetWString(1);
                    auto signatureBlob = result.GetBlob(2);
                    auto category = static_cast<SignatureDB::SignatureCategory>(result.GetInt(4));
                    auto severity = static_cast<ThreatSeverity>(result.GetInt(6));
                    std::wstring platform = result.GetWString(7);
                    std::wstring version = result.GetWString(8);
                    std::wstring author = result.GetWString(9);
                    std::wstring description = result.GetWString(10);
                    std::wstring tags = result.GetWString(11);
                    std::wstring metadata = result.GetWString(12);
                    uint64_t detectionCount = result.GetInt64(13);
                    uint64_t falsePositiveCount = result.GetInt64(14);
                    double effectiveness = result.GetDouble(15);

                    // Convert blob to string
                    std::string yaraRule;
                    if (!signatureBlob.empty()) {
                        yaraRule = std::string(
                            reinterpret_cast<const char*>(signatureBlob.data()),
                            signatureBlob.size()
                        );
                    }

                    if (yaraRule.empty()) {
                        SS_LOG_WARN(L"ThreatIntelDB", L"Skipping empty YARA rule: %ls (ID: %lld)", name.c_str(), id);
                        skippedCount++;
                        continue;
                    }

                    // Add rule metadata comment
                    yaraContent << L"/*\n";
                    yaraContent << L" * Rule: " << name << L"\n";
                    yaraContent << L" * ID: " << id << L"\n";
                    yaraContent << L" * Category: " << SignatureDB::SignatureCategoryToString(category) << L"\n";
                    yaraContent << L" * Severity: " << SignatureDB::SignatureSeverityToString(MapThreatToSignatureSeverity(severity)) << L"\n";
                    yaraContent << L" * Platform: " << platform << L"\n";
                    yaraContent << L" * Version: " << version << L"\n";
                    yaraContent << L" * Author: " << author << L"\n";
                    yaraContent << L" * Description: " << description << L"\n";
                    yaraContent << L" * Tags: " << tags << L"\n";
                    yaraContent << L" * Detection Count: " << detectionCount << L"\n";
                    yaraContent << L" * False Positives: " << falsePositiveCount << L"\n";
                    yaraContent << L" * Effectiveness: " << std::fixed << std::setprecision(2) << (effectiveness * 100.0) << L"%\n";
                    yaraContent << L" */\n";

                    // Add the actual YARA rule
                    std::wstring yaraRuleWide(yaraRule.begin(), yaraRule.end());
                    yaraContent << yaraRuleWide << L"\n\n";

                    ruleNames.push_back(name);

                }
                catch (const std::exception& ex) {
                    SS_LOG_ERROR(L"ThreatIntelDB", L"ExportYaraRules: Exception processing rule: %hs", ex.what());
                    skippedCount++;
                    continue;
                }
            }

            // Add footer
            yaraContent << L"/*\n";
            yaraContent << L" * End of YARA Rules Export\n";
            yaraContent << L" * Successfully Exported: " << (exportedCount - skippedCount) << L" rules\n";
            yaraContent << L" * Skipped: " << skippedCount << L" rules\n";
            yaraContent << L" */\n";

            // Write to file
            std::wstring finalContent = yaraContent.str();
            Utils::FileUtils::Error fileErr;

            if (!Utils::FileUtils::WriteAllBytesAtomic(
                outputPath,
                reinterpret_cast<const std::byte*>(finalContent.data()),
                finalContent.size() * sizeof(wchar_t),
                &fileErr
            )) {
                if (err) {
                    err->message = L"Failed to write YARA rules file: " +
                        std::wstring(fileErr.message.begin(), fileErr.message.end());
                }
                SS_LOG_ERROR(L"ThreatIntelDB", L"ExportYaraRules: Failed to write file: %hs", fileErr.message.c_str());
                return false;
            }

            SS_LOG_INFO(L"ThreatIntelDB", L"Successfully exported %zu YARA rules (skipped: %zu) to: %ls",
                (exportedCount - skippedCount), skippedCount, outputPath.data());

            // Log audit event (ExportYaraRules) - use QuarantineDB::Instance().logAuditEvent with correct signature
            QuarantineDB::Instance().logAuditEvent(
                QuarantineDB::QuarantineAction::Submitted, // choose appropriate action enum
                0, // no specific entry id for rule export -> use 0
                L"YARA_EXPORT: Exported " + std::to_wstring(exportedCount - skippedCount) + L" YARA rules to " + std::wstring(outputPath)
            );
            return true;
        }

        bool ThreatIntelDB::ImportYaraRules(std::wstring_view inputPath, DatabaseError* err) {
            if (!m_initialized.load(std::memory_order_acquire)) {
                if (err) err->message = L"ThreatIntelDB not initialized";
                SS_LOG_ERROR(L"ThreatIntelDB", L"ImportYaraRules: DB not initialized");
                return false;
            }

            SS_LOG_INFO(L"ThreatIntelDB", L"Importing YARA rules from: %ls", inputPath.data());

            // Validate input file
            if (!std::filesystem::exists(inputPath)) {
                if (err) err->message = L"YARA rules file not found: " + std::wstring(inputPath);
                SS_LOG_ERROR(L"ThreatIntelDB", L"ImportYaraRules: File not found: %ls", inputPath.data());
                return false;
            }

            // Check file size
            std::error_code ec;
            auto fileSize = std::filesystem::file_size(inputPath, ec);
            if (ec) {
                if (err) err->message = L"Failed to get file size: " + std::wstring(ec.message().begin(), ec.message().end());
                SS_LOG_ERROR(L"ThreatIntelDB", L"ImportYaraRules: Failed to get file size");
                return false;
            }

            constexpr size_t MAX_YARA_FILE_SIZE = 100 * 1024 * 1024; // 100MB
            if (fileSize > MAX_YARA_FILE_SIZE) {
                if (err) err->message = L"YARA file too large (max 100MB)";
                SS_LOG_ERROR(L"ThreatIntelDB", L"ImportYaraRules: File too large: %llu bytes", fileSize);
                return false;
            }

            // Read file content
            std::vector<std::byte> fileData;
            Utils::FileUtils::Error fileErr;
            if (!Utils::FileUtils::ReadAllBytes(inputPath, fileData, &fileErr)) {
                if (err) {
                    err->message = L"Failed to read YARA file: " +
                        std::wstring(fileErr.message.begin(), fileErr.message.end());
                }
                SS_LOG_ERROR(L"ThreatIntelDB", L"ImportYaraRules: Failed to read file: %hs", fileErr.message.c_str());
                return false;
            }

            // Convert to string
            std::string yaraContent(
                reinterpret_cast<const char*>(fileData.data()),
                fileData.size()
            );

            // Validate YARA syntax using compiler
            YR_COMPILER* compiler = nullptr;
            int result = yr_compiler_create(&compiler);
            if (result != ERROR_SUCCESS || !compiler) {
                if (err) err->message = L"Failed to create YARA compiler";
                SS_LOG_ERROR(L"ThreatIntelDB", L"ImportYaraRules: Failed to create YARA compiler");
                return false;
            }

            // Set error callback
            auto errorCallback = [](int errorLevel, const char* fileName, int lineNumber,
                const YR_RULE* rule, const char* message, void* userData) {
                    SS_LOG_ERROR(L"ThreatIntelDB", L"YARA Compilation Error at line %d: %hs",
                        lineNumber, message);
                };

            yr_compiler_set_callback(compiler, errorCallback, nullptr);

            // Try to compile to validate syntax
            result = yr_compiler_add_string(compiler, yaraContent.c_str(), nullptr);

            if (result != 0) {
                yr_compiler_destroy(compiler);
                if (err) err->message = L"YARA syntax validation failed (check logs for details)";
                SS_LOG_ERROR(L"ThreatIntelDB", L"ImportYaraRules: YARA syntax validation failed");
                return false;
            }

            // Get compiled rules to extract metadata
            YR_RULES* rules = nullptr;
            result = yr_compiler_get_rules(compiler, &rules);

            if (result != ERROR_SUCCESS || !rules) {
                yr_compiler_destroy(compiler);
                if (err) err->message = L"Failed to get compiled YARA rules";
                SS_LOG_ERROR(L"ThreatIntelDB", L"ImportYaraRules: Failed to get compiled rules");
                return false;
            }

            // Start database transaction
            auto& dbMgr = DatabaseManager::Instance();
            auto trans = dbMgr.BeginTransaction(Transaction::Type::Immediate, err);
            if (!trans || !trans->IsActive()) {
                yr_rules_destroy(rules);
                yr_compiler_destroy(compiler);
                SS_LOG_ERROR(L"ThreatIntelDB", L"ImportYaraRules: Failed to begin transaction");
                return false;
            }

            size_t importedCount = 0;
            size_t skippedCount = 0;
            size_t updatedCount = 0;

            // Parse and import individual rules
            YR_RULE* rule = nullptr;
            yr_rules_foreach(rules, rule) {
                try {
                    std::string ruleName = rule->identifier;
                    std::wstring ruleNameWide(ruleName.begin(), ruleName.end());

                    // Check if rule already exists
                    bool exists = false;
                    {
                        auto existing = SignatureDB::Instance().GetSignatureByName(ruleNameWide, nullptr);
                        if (existing.has_value() && existing->type == SignatureDB::SignatureType::YaraRule) { exists = true; }
                        std::shared_lock lock(m_signaturesMutex);
                        
                    }

                    // Extract rule text from original content
                    // This is a simplified extraction - in production you'd parse more carefully
                    std::string ruleText = yaraContent; // Full content for now
                    std::vector<uint8_t> ruleBlob(ruleText.begin(), ruleText.end());

                    // Create signature entry
                    SignatureDB::SignatureEntry entry;
                    entry.name = ruleNameWide;
                    entry.type = SignatureDB::SignatureType::YaraRule;
                    entry.category = SignatureDB::SignatureCategory::Malware; // Default, could parse from metadata
                    entry.severity = MapThreatToSignatureSeverity(ThreatSeverity::Medium); // default map
                    entry.status = SignatureDB::SignatureStatus::Active;
                    entry.source = SignatureDB::SignatureSource::Community;
                    entry.targetPlatforms = { L"Windows" };// Default
                    entry.version = 1;
                    entry.author = L"Imported";
                    entry.description = L"Imported YARA rule: " + ruleNameWide;
					entry.signatureData = ToWide(std::string(ruleBlob.begin(), ruleBlob.end()));
                    entry.createdAt = std::chrono::system_clock::now();
                    entry.lastUpdateCheck = entry.createdAt;

                    // Parse metadata if available
                    YR_META* meta = nullptr;
                    yr_rule_metas_foreach(rule, meta) {
                        std::string metaId = meta->identifier;
                        if (metaId == "author" && meta->type == META_TYPE_STRING) {
                            entry.author = std::wstring(meta->string, meta->string + strlen(meta->string));
                        }
                        else if (metaId == "description" && meta->type == META_TYPE_STRING) {
                            entry.description = std::wstring(meta->string, meta->string + strlen(meta->string));
                        }
                        else if (metaId == "severity" && meta->type == META_TYPE_STRING) {
                            std::string sev = meta->string;

                            //map string severity directly to signatureDB::SignatureSeverity
                            SignatureDB::SignatureSeverity mapped = SignatureDB::SignatureSeverity::Medium;
                            if (sev == "critical") mapped = SignatureDB::SignatureSeverity::Critical;
                            else if (sev == "high") mapped = SignatureDB::SignatureSeverity::High;
                            else if (sev == "medium") mapped = SignatureDB::SignatureSeverity::Medium;
                            else if (sev == "low") mapped = SignatureDB::SignatureSeverity::Low;
                            entry.severity = mapped;
                        }
                    }

                    // Parse tags
                    std::vector<std::wstring> tagsVec;
                    
                    const char* tag = nullptr;
                    yr_rule_tags_foreach(rule, tag) {
                      
                        if (!tag) continue;
                        tagsVec.push_back(ToWide(tag));
                    }
                    entry.tags = std::move(tagsVec);

                    if (exists) {
                        // Update existing
                        if (SignatureDB::Instance().UpdateSignature(entry, err)) {
                            updatedCount++;
                        }
                        else {
                            SS_LOG_WARN(L"ThreatIntelDB", L"Failed to update existing rule: %ls", ruleNameWide.c_str());
                            skippedCount++;
                        }
                    }
                    else {
                        // Add new
                        if (SignatureDB::Instance().AddSignature(entry, err) > 0) {
                            importedCount++;
                        }
                        else {
                            SS_LOG_WARN(L"ThreatIntelDB", L"Failed to import new rule: %ls", ruleNameWide.c_str());
                            skippedCount++;
                        }
                    }

                }
                catch (const std::exception& ex) {
                    SS_LOG_ERROR(L"ThreatIntelDB", L"ImportYaraRules: Exception processing rule: %hs", ex.what());
                    skippedCount++;
                    continue;
                }
            }

            // Cleanup YARA resources
            yr_rules_destroy(rules);
            yr_compiler_destroy(compiler);

            // Commit transaction
            if (!trans->Commit(err)) {
                SS_LOG_ERROR(L"ThreatIntelDB", L"ImportYaraRules: Failed to commit transaction");
                return false;
            }

            SS_LOG_INFO(L"ThreatIntelDB",
                L"YARA import complete: %zu imported, %zu updated, %zu skipped",
                importedCount, updatedCount, skippedCount);

            // Log audit event
            QuarantineDB::Instance().logAuditEvent(
                QuarantineDB::QuarantineAction::Submitted,
                0,
                L"YARA_IMPORT: Imported " + std::to_wstring(importedCount) + L" new rules, updated " +
                std::to_wstring(updatedCount) + L" from " + std::wstring(inputPath)
            );
            return true;
        }
       
    } // namespace Database
} // namespace ShadowStrike

  