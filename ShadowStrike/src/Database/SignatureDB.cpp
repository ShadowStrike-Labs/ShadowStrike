
#include "SignatureDB.hpp"
#include "../Utils/SystemUtils.hpp"
#include"../Database/DatabaseManager.hpp"
#include"../Utils/JSONUtils.hpp"
#include"../Utils/Base64Utils.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <regex>

namespace ShadowStrike {
    namespace Database {

        namespace {
            // Database schema version
            constexpr int SIGNATUREDB_SCHEMA_VERSION = 1;

            // SQL statements - kept from previous version

            constexpr const char* SQL_CREATE_SIGNATURES_TABLE = R"(
                CREATE TABLE IF NOT EXISTS signatures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    display_name TEXT NOT NULL,
                    
                    type INTEGER NOT NULL,
                    severity INTEGER NOT NULL,
                    category INTEGER NOT NULL,
                    status INTEGER NOT NULL,
                    source INTEGER NOT NULL,
                    
                    signature_data TEXT,
                    compiled_data BLOB,
                    pattern TEXT,
                    
                    description TEXT,
                    author TEXT,
                    reference TEXT,
                    tags TEXT,
                    
                    version INTEGER NOT NULL DEFAULT 1,
                    version_string TEXT,
                    created_at INTEGER NOT NULL,
                    modified_at INTEGER NOT NULL,
                    last_used_at INTEGER,
                    
                    detection_count INTEGER DEFAULT 0,
                    false_positive_count INTEGER DEFAULT 0,
                    last_detection_timestamp INTEGER DEFAULT 0,
                    effectiveness_score REAL DEFAULT 0.0,
                    
                    avg_match_time_ms INTEGER DEFAULT 0,
                    total_match_time_ms INTEGER DEFAULT 0,
                    match_attempts INTEGER DEFAULT 0,
                    
                    dependencies TEXT,
                    conflicts TEXT,
                    target_file_types TEXT,
                    target_platforms TEXT,
                    min_file_size INTEGER DEFAULT 0,
                    max_file_size INTEGER DEFAULT 0,
                    
                    yara_namespace TEXT,
                    yara_private INTEGER DEFAULT 0,
                    yara_global INTEGER DEFAULT 0,
                    yara_meta TEXT,
                    
                    hash_algorithm TEXT,
                    can_be_whitelisted INTEGER DEFAULT 1,
                    whitelist TEXT,
                    
                    update_source TEXT,
                    update_id TEXT,
                    last_update_check INTEGER,
                    
                    custom_data TEXT
                );
            )";

            constexpr const char* SQL_CREATE_INDICES = R"(
                CREATE INDEX IF NOT EXISTS idx_signatures_name ON signatures(name);
                CREATE INDEX IF NOT EXISTS idx_signatures_type ON signatures(type);
                CREATE INDEX IF NOT EXISTS idx_signatures_status ON signatures(status);
                CREATE INDEX IF NOT EXISTS idx_signatures_category ON signatures(category);
                CREATE INDEX IF NOT EXISTS idx_signatures_severity ON signatures(severity);
                CREATE INDEX IF NOT EXISTS idx_signatures_detection_count ON signatures(detection_count DESC);
                CREATE INDEX IF NOT EXISTS idx_signatures_effectiveness ON signatures(effectiveness_score DESC);
                CREATE INDEX IF NOT EXISTS idx_signatures_created ON signatures(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_signatures_modified ON signatures(modified_at DESC);
                CREATE INDEX IF NOT EXISTS idx_signatures_composite ON signatures(type, status, category);
            )";

            constexpr const char* SQL_CREATE_DETECTIONS_TABLE = R"(
                CREATE TABLE IF NOT EXISTS detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    signature_id INTEGER NOT NULL,
                    signature_name TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    file_hash TEXT,
                    detection_time INTEGER NOT NULL,
                    match_offset INTEGER DEFAULT 0,
                    match_length INTEGER DEFAULT 0,
                    confidence REAL DEFAULT 1.0,
                    is_false_positive INTEGER DEFAULT 0,
                    false_positive_reason TEXT,
                    FOREIGN KEY (signature_id) REFERENCES signatures(id) ON DELETE CASCADE
                );
            )";

            constexpr const char* SQL_CREATE_DETECTION_INDICES = R"(
                CREATE INDEX IF NOT EXISTS idx_detections_signature ON detections(signature_id);
                CREATE INDEX IF NOT EXISTS idx_detections_time ON detections(detection_time DESC);
                CREATE INDEX IF NOT EXISTS idx_detections_hash ON detections(file_hash);
                CREATE INDEX IF NOT EXISTS idx_detections_false_positive ON detections(is_false_positive);
            )";

            constexpr const char* SQL_CREATE_HASH_LOOKUP_TABLE = R"(
                CREATE TABLE IF NOT EXISTS hash_lookup (
                    hash_value TEXT NOT NULL,
                    hash_algorithm TEXT NOT NULL,
                    signature_id INTEGER NOT NULL,
                    PRIMARY KEY (hash_value, hash_algorithm),
                    FOREIGN KEY (signature_id) REFERENCES signatures(id) ON DELETE CASCADE
                ) WITHOUT ROWID;
            )";

            constexpr const char* SQL_CREATE_HASH_LOOKUP_INDEX = R"(
                CREATE INDEX IF NOT EXISTS idx_hash_lookup_value ON hash_lookup(hash_value);
            )";

            constexpr const char* SQL_INSERT_SIGNATURE = R"(
                INSERT INTO signatures (
                    name, display_name, type, severity, category, status, source,
                    signature_data, compiled_data, pattern, description, author, reference, tags,
                    version, version_string, created_at, modified_at,
                    dependencies, conflicts, target_file_types, target_platforms,
                    min_file_size, max_file_size,
                    yara_namespace, yara_private, yara_global, yara_meta,
                    hash_algorithm, can_be_whitelisted, whitelist,
                    update_source, update_id, custom_data
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            )";

            constexpr const char* SQL_SELECT_SIGNATURE_BY_ID = R"(
                SELECT * FROM signatures WHERE id = ?
            )";

            constexpr const char* SQL_SELECT_SIGNATURE_BY_NAME = R"(
                SELECT * FROM signatures WHERE name = ?
            )";

            constexpr const char* SQL_UPDATE_SIGNATURE = R"(
                UPDATE signatures SET
                    display_name = ?, type = ?, severity = ?, category = ?, status = ?, source = ?,
                    signature_data = ?, compiled_data = ?, pattern = ?,
                    description = ?, author = ?, reference = ?, tags = ?,
                    version = ?, version_string = ?, modified_at = ?,
                    dependencies = ?, conflicts = ?, target_file_types = ?, target_platforms = ?,
                    min_file_size = ?, max_file_size = ?,
                    yara_namespace = ?, yara_private = ?, yara_global = ?, yara_meta = ?,
                    hash_algorithm = ?, can_be_whitelisted = ?, whitelist = ?,
                    update_source = ?, update_id = ?, custom_data = ?
                WHERE id = ?
            )";

            constexpr const char* SQL_DELETE_SIGNATURE = R"(
                DELETE FROM signatures WHERE id = ?
            )";

            constexpr const char* SQL_UPDATE_SIGNATURE_STATUS = R"(
                UPDATE signatures SET status = ?, modified_at = ? WHERE id = ?
            )";

            constexpr const char* SQL_COUNT_ALL = R"(
                SELECT COUNT(*) FROM signatures
            )";

            constexpr const char* SQL_INSERT_DETECTION = R"(
                INSERT INTO detections (
                    signature_id, signature_name, file_path, file_hash,
                    detection_time, match_offset, match_length, confidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            )";

            constexpr const char* SQL_RECORD_FALSE_POSITIVE = R"(
                UPDATE detections SET is_false_positive = 1, false_positive_reason = ?
                WHERE signature_id = ? AND file_path = ? AND detection_time = (
                    SELECT MAX(detection_time) FROM detections WHERE signature_id = ? AND file_path = ?
                )
            )";

            constexpr const char* SQL_INSERT_HASH_LOOKUP = R"(
                INSERT OR REPLACE INTO hash_lookup (hash_value, hash_algorithm, signature_id)
                VALUES (?, ?, ?)
            )";

            constexpr const char* SQL_LOOKUP_HASH = R"(
                SELECT signature_id FROM hash_lookup WHERE hash_value = ? AND hash_algorithm = ?
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

            std::string serializeStringVector(const std::vector<std::wstring>& vec) {
                if (vec.empty()) return std::string();
                std::ostringstream oss;
                for (size_t i = 0; i < vec.size(); ++i) {
                    if (i > 0) oss << ";";
                    oss << ToUTF8(vec[i]);
                }
                return oss.str();
            }

            std::vector<std::wstring> deserializeStringVector(std::string_view str) {
                std::vector<std::wstring> result;
                if (str.empty()) return result;
                
                std::string temp(str);
                size_t pos = 0;
                while ((pos = temp.find(';')) != std::string::npos) {
                    result.push_back(ToWide(temp.substr(0, pos)));
                    temp.erase(0, pos + 1);
                }
                if (!temp.empty()) {
                    result.push_back(ToWide(temp));
                }
                return result;
            }
        }

        // ============================================================================
        // SignatureDB Implementation
        // ============================================================================

        SignatureDB& SignatureDB::Instance() {
            static SignatureDB instance;
            return instance;
        }

        SignatureDB::SignatureDB() {
        }

        SignatureDB::~SignatureDB() {
            Shutdown();
        }

        bool SignatureDB::Initialize(const Config& config, DatabaseError* err) {
            if (m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"SignatureDB", L"Already initialized");
                return true;
            }

            SS_LOG_INFO(L"SignatureDB", L"Initializing SignatureDB...");

            std::unique_lock<std::shared_mutex> lock(m_configMutex);
            m_config = config;

            // Initialize DatabaseManager
            DatabaseConfig dbConfig;
            dbConfig.databasePath = m_config.dbPath;
            dbConfig.enableWAL = m_config.enableWAL;
            dbConfig.cacheSizeKB = m_config.dbCacheSizeKB;
            dbConfig.maxConnections = m_config.maxConnections;
            dbConfig.autoBackup = false;

            if (!DatabaseManager::Instance().Initialize(dbConfig, err)) {
                SS_LOG_ERROR(L"SignatureDB", L"Failed to initialize DatabaseManager");
                return false;
            }

            // Create schema
            if (!createSchema(err)) {
                SS_LOG_ERROR(L"SignatureDB", L"Failed to create schema");
                DatabaseManager::Instance().Shutdown();
                return false;
            }

            // Initialize YARA
            if (m_config.enableYaraCompilation) {
                int result = yr_initialize();
                if (result != ERROR_SUCCESS) {
                    SS_LOG_ERROR(L"SignatureDB", L"Failed to initialize YARA: %d", result);
                    if (err) {
                        err->sqliteCode = SQLITE_ERROR;
                        err->message = L"YARA initialization failed";
                    }
                    return false;
                }

                result = yr_compiler_create(&m_yaraCompiler);
                if (result != ERROR_SUCCESS || !m_yaraCompiler) {
                    SS_LOG_ERROR(L"SignatureDB", L"Failed to create YARA compiler");
                    yr_finalize();
                    if (err) {
                        err->sqliteCode = SQLITE_ERROR;
                        err->message = L"YARA compiler creation failed";
                    }
                    return false;
                }

                yr_compiler_set_callback(m_yaraCompiler, yaraCompilerCallback, this);
                SS_LOG_INFO(L"SignatureDB", L"YARA initialized successfully");
            }

            // Ensure cache directory exists
            if (m_config.enableCaching) {
                Utils::FileUtils::Error fileErr;
                if (!Utils::FileUtils::CreateDirectories(m_config.signatureCachePath, &fileErr)) {
                    SS_LOG_WARN(L"SignatureDB", L"Failed to create cache directory: %ls", 
                               m_config.signatureCachePath.c_str());
                }
            }

            // Load active signatures if configured
            if (m_config.loadOnStartup && m_config.enableYaraCompilation) {
                if (!LoadYaraRules(err)) {
                    SS_LOG_WARN(L"SignatureDB", L"Failed to load YARA rules on startup");
                }
            }

            // Initialize hash cache
            {
                std::unique_lock<std::shared_mutex> hashLock(m_hashCacheMutex);
                auto result = DatabaseManager::Instance().Query(
                    "SELECT hash_value, hash_algorithm, signature_id FROM hash_lookup", err);
                
                while (result.Next()) {
                    std::wstring hash = result.GetWString(0);
                    std::wstring algo = result.GetWString(1);
                    int64_t sigId = result.GetInt64(2);
                    
                    std::wstring key = hash + L":" + algo;
                    m_hashSignatureMap[key].push_back(sigId);
                }
                
                SS_LOG_INFO(L"SignatureDB", L"Loaded %zu hash signatures into cache", 
                           m_hashSignatureMap.size());
            }

            // Start update thread if enabled
            if (m_config.enableAutoUpdate) {
                m_lastUpdateCheck = std::chrono::steady_clock::now();
                m_updateThread = std::thread(&SignatureDB::updateThread, this);
            }

            // Initialize statistics
            recalculateStatistics(err);

            m_initialized.store(true, std::memory_order_release);

            SS_LOG_INFO(L"SignatureDB", L"SignatureDB initialized successfully with %lld signatures",
                       m_stats.totalSignatures);

            return true;
        }

        void SignatureDB::Shutdown() {
            if (!m_initialized.load(std::memory_order_acquire)) {
                return;
            }

            SS_LOG_INFO(L"SignatureDB", L"Shutting down SignatureDB...");

            // Stop update thread
            m_shutdownUpdate.store(true, std::memory_order_release);
            m_updateCV.notify_all();

            if (m_updateThread.joinable()) {
                m_updateThread.join();
            }

            // Unload YARA rules
            UnloadYaraRules();

            // Destroy YARA compiler
            if (m_yaraCompiler) {
                yr_compiler_destroy(m_yaraCompiler);
                m_yaraCompiler = nullptr;
            }

            // Finalize YARA
            if (m_config.enableYaraCompilation) {
                yr_finalize();
            }

            // Clear caches
            {
                std::unique_lock<std::shared_mutex> hashLock(m_hashCacheMutex);
                m_hashSignatureMap.clear();
            }

            {
                std::unique_lock<std::mutex> cacheLock(m_cacheMutex);
                m_compiledCache.clear();
            }

            // Shutdown database manager
            DatabaseManager::Instance().Shutdown();

            m_initialized.store(false, std::memory_order_release);

            SS_LOG_INFO(L"SignatureDB", L"SignatureDB shut down");
        }

        // ============================================================================
        // Schema Management
        // ============================================================================

        bool SignatureDB::createSchema(DatabaseError* err) {
            SS_LOG_INFO(L"SignatureDB", L"Creating database schema...");

            // Create tables
            if (!DatabaseManager::Instance().Execute(SQL_CREATE_SIGNATURES_TABLE, err)) {
                return false;
            }

            if (!DatabaseManager::Instance().Execute(SQL_CREATE_DETECTIONS_TABLE, err)) {
                return false;
            }

            if (!DatabaseManager::Instance().Execute(SQL_CREATE_HASH_LOOKUP_TABLE, err)) {
                return false;
            }

            // Create indices
            if (!DatabaseManager::Instance().Execute(SQL_CREATE_INDICES, err)) {
                return false;
            }

            if (!DatabaseManager::Instance().Execute(SQL_CREATE_DETECTION_INDICES, err)) {
                return false;
            }

            if (!DatabaseManager::Instance().Execute(SQL_CREATE_HASH_LOOKUP_INDEX, err)) {
                return false;
            }

            SS_LOG_INFO(L"SignatureDB", L"Schema created successfully");
            return true;
        }

        bool SignatureDB::upgradeSchema(int currentVersion, int targetVersion, DatabaseError* err) {
            // Future schema migrations
            return true;
        }

        // ============================================================================
        // Signature Management Operations
        // ============================================================================

        int64_t SignatureDB::AddSignature(const SignatureEntry& signature, DatabaseError* err) {
            if (!m_initialized.load(std::memory_order_acquire)) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"SignatureDB not initialized";
                }
                return -1;
            }

            // Validate signature
            if (signature.name.empty()) {
                if (err) {
                    err->sqliteCode = SQLITE_CONSTRAINT;
                    err->message = L"Signature name cannot be empty";
                }
                return -1;
            }

            // Insert into database
            int64_t signatureId = dbInsertSignature(signature, err);
            if (signatureId < 0) {
                return -1;
            }

            // If it's a hash signature, add to hash lookup table
            if (signature.type == SignatureType::MD5Hash ||
                signature.type == SignatureType::SHA1Hash ||
                signature.type == SignatureType::SHA256Hash ||
                signature.type == SignatureType::FuzzyHash) {
                
                std::string hashValue = ToUTF8(signature.signatureData);
                std::string hashAlgo = ToUTF8(signature.hashAlgorithm.empty() ? 
                    SignatureTypeToString(signature.type) : signature.hashAlgorithm);

                DatabaseManager::Instance().ExecuteWithParams(
                    SQL_INSERT_HASH_LOOKUP, err,
                    hashValue, hashAlgo, signatureId);

                // Update hash cache
                std::unique_lock<std::shared_mutex> hashLock(m_hashCacheMutex);
                std::wstring key = signature.signatureData + L":" + 
                    (signature.hashAlgorithm.empty() ? SignatureTypeToString(signature.type) : signature.hashAlgorithm);
                m_hashSignatureMap[key].push_back(signatureId);
            }

            // Compile YARA rule if needed
            if (signature.type == SignatureType::YaraRule && m_config.enableYaraCompilation) {
                if (!CompileYaraRule(signatureId, err)) {
                    SS_LOG_WARN(L"SignatureDB", L"Failed to compile YARA rule for signature %lld", signatureId);
                }
            }

            // Update statistics
            {
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.totalSignatures++;
                if (signature.status == SignatureStatus::Active) {
                    m_stats.activeSignatures++;
                }
                if (static_cast<size_t>(signature.type) < 256) {
                    m_stats.signaturesByType[static_cast<size_t>(signature.type)]++;
                }
                if (static_cast<size_t>(signature.category) < 256) {
                    m_stats.signaturesByCategory[static_cast<size_t>(signature.category)]++;
                }
                if (signature.severity <= SignatureSeverity::Critical) {
                    m_stats.signaturesBySeverity[static_cast<size_t>(signature.severity)]++;
                }
            }

            SS_LOG_INFO(L"SignatureDB", L"Added signature: %ls (ID: %lld)", 
                       signature.name.c_str(), signatureId);

            return signatureId;
        }

        int64_t SignatureDB::AddYaraRule(std::wstring_view ruleName,
                                        std::wstring_view ruleSource,
                                        SignatureSeverity severity,
                                        SignatureCategory category,
                                        std::wstring_view author,
                                        DatabaseError* err) {
            SignatureEntry entry;
            entry.name = ruleName;
            entry.displayName = ruleName;
            entry.type = SignatureType::YaraRule;
            entry.severity = severity;
            entry.category = category;
            entry.status = SignatureStatus::Active;
            entry.source = SignatureSource::Custom;
            entry.signatureData = ruleSource;
            entry.author = author;
            entry.createdAt = std::chrono::system_clock::now();
            entry.modifiedAt = entry.createdAt;

            // Validate YARA syntax before adding
            if (m_config.enableSignatureValidation) {
                std::wstring errorMsg;
                if (!ValidateYaraRule(ruleSource, errorMsg, err)) {
                    SS_LOG_ERROR(L"SignatureDB", L"YARA rule validation failed: %ls", errorMsg.c_str());
                    if (err && err->message.empty()) {
                        err->message = L"YARA rule validation failed: " + errorMsg;
                    }
                    return -1;
                }
            }

            return AddSignature(entry, err);
        }

        int64_t SignatureDB::AddHashSignature(std::wstring_view hashValue,
                                             std::wstring_view hashAlgorithm,
                                             std::wstring_view threatName,
                                             SignatureSeverity severity,
                                             DatabaseError* err) {
            // Determine signature type from algorithm
            SignatureType type = SignatureType::SHA256Hash;
            if (hashAlgorithm == L"MD5") {
                type = SignatureType::MD5Hash;
            } else if (hashAlgorithm == L"SHA1") {
                type = SignatureType::SHA1Hash;
            } else if (hashAlgorithm == L"SHA256") {
                type = SignatureType::SHA256Hash;
            } else if (hashAlgorithm == L"SSDeep" || hashAlgorithm == L"TLSH") {
                type = SignatureType::FuzzyHash;
            }

            SignatureEntry entry;
            entry.name = std::wstring(hashAlgorithm) + L"_" + std::wstring(hashValue).substr(0, 16);
            entry.displayName = threatName;
            entry.type = type;
            entry.severity = severity;
            entry.category = SignatureCategory::Malware;
            entry.status = SignatureStatus::Active;
            entry.source = SignatureSource::Custom;
            entry.signatureData = hashValue;
            entry.hashAlgorithm = hashAlgorithm;
            entry.description = L"Hash signature for: " + std::wstring(threatName);
            entry.createdAt = std::chrono::system_clock::now();
            entry.modifiedAt = entry.createdAt;

            return AddSignature(entry, err);
        }

        bool SignatureDB::UpdateSignature(const SignatureEntry& signature, DatabaseError* err) {
            if (!m_initialized.load(std::memory_order_acquire)) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"SignatureDB not initialized";
                }
                return false;
            }

            if (signature.id <= 0) {
                if (err) {
                    err->sqliteCode = SQLITE_CONSTRAINT;
                    err->message = L"Invalid signature ID";
                }
                return false;
            }

            // If this is a hash-related signature update we need the previous DB row
            std::optional<SignatureEntry> oldEntryOpt;
            bool isHashTypeUpdate = (signature.type == SignatureType::MD5Hash ||
                signature.type == SignatureType::SHA1Hash ||
                signature.type == SignatureType::SHA256Hash ||
                signature.type == SignatureType::FuzzyHash);

            if (isHashTypeUpdate) {
                oldEntryOpt = dbSelectSignature(signature.id, nullptr);
                // continue even if old not found; we'll handle gracefully
            }

            bool success = dbUpdateSignature(signature, err);
            if (success) {
                SS_LOG_INFO(L"SignatureDB", L"Updated signature: %ls (ID: %lld)",
                    signature.name.c_str(), signature.id);

                // Recompile YARA rule if changed
                if (signature.type == SignatureType::YaraRule && m_config.enableYaraCompilation) {
                    CompileYaraRule(signature.id, nullptr);
                }

                // Optimize hash-cache update: update only affected entries (don't clear whole cache)
                if (isHashTypeUpdate || (oldEntryOpt.has_value() &&
                    (oldEntryOpt->type == SignatureType::MD5Hash ||
                        oldEntryOpt->type == SignatureType::SHA1Hash ||
                        oldEntryOpt->type == SignatureType::SHA256Hash ||
                        oldEntryOpt->type == SignatureType::FuzzyHash)))
                {
                    // Build keys (old and new)
                    auto buildKey = [&](const SignatureEntry& e) -> std::wstring {
                        std::wstring algo = e.hashAlgorithm.empty() ? SignatureTypeToString(e.type) : e.hashAlgorithm;
                        return e.signatureData + L":" + algo;
                        };

                    std::wstring oldKey;
                    if (oldEntryOpt.has_value() &&
                        (oldEntryOpt->type == SignatureType::MD5Hash ||
                            oldEntryOpt->type == SignatureType::SHA1Hash ||
                            oldEntryOpt->type == SignatureType::SHA256Hash ||
                            oldEntryOpt->type == SignatureType::FuzzyHash)) {
                        oldKey = buildKey(*oldEntryOpt);
                    }

                    std::wstring newKey;
                    if (isHashTypeUpdate) {
                        newKey = buildKey(signature);
                    }

                    {
                        std::unique_lock<std::shared_mutex> hashLock(m_hashCacheMutex);

                        // Remove from old key vector if changed or type became non-hash
                        if (!oldKey.empty() && oldKey != newKey) {
                            auto it = m_hashSignatureMap.find(oldKey);
                            if (it != m_hashSignatureMap.end()) {
                                auto& vec = it->second;
                                vec.erase(std::remove(vec.begin(), vec.end(), signature.id), vec.end());
                                if (vec.empty()) {
                                    m_hashSignatureMap.erase(it);
                                }
                            }
                        }

                        // Insert into new key vector if it's a hash signature
                        if (!newKey.empty()) {
                            auto& vec = m_hashSignatureMap[newKey];
                            // avoid duplicate entries
                            if (std::find(vec.begin(), vec.end(), signature.id) == vec.end()) {
                                vec.push_back(signature.id);
                            }
                        }
                    }

                    // Keep DB hash_lookup table in sync:
                    // remove any old mapping for this signature id, then insert new mapping if needed
                    {
                        // Remove old mappings referencing this signature id
                        DatabaseError localErr;
                        DatabaseManager::Instance().ExecuteWithParams(
                            "DELETE FROM hash_lookup WHERE signature_id = ?", &localErr, signature.id);

                        if (isHashTypeUpdate) {
                            std::string hashValue = ToUTF8(signature.signatureData);
                            std::string hashAlgo = ToUTF8(signature.hashAlgorithm.empty() ? SignatureTypeToString(signature.type) : signature.hashAlgorithm);
                            DatabaseManager::Instance().ExecuteWithParams(
                                SQL_INSERT_HASH_LOOKUP, &localErr,
                                hashValue, hashAlgo, signature.id);
                        }
                    }
                }

                // Update statistics (kept as before)
                {
                    std::lock_guard<std::mutex> lock(m_statsMutex);
                    // No change to counts here; if type changed you may want to adjust counts elsewhere
                }
            }

            return success;
        }
        bool SignatureDB::SetSignatureStatus(int64_t signatureId,
                                             SignatureStatus status,
                                             DatabaseError* err) {
            auto now = std::chrono::system_clock::now();
            auto nowEpoch = std::chrono::duration_cast<std::chrono::seconds>(
                now.time_since_epoch()).count();

            bool success = DatabaseManager::Instance().ExecuteWithParams(
                SQL_UPDATE_SIGNATURE_STATUS, err,
                static_cast<int>(status),
                static_cast<int64_t>(nowEpoch),
                signatureId);

            if (success) {
                SS_LOG_INFO(L"SignatureDB", L"Updated signature %lld status to %ls",
                           signatureId, SignatureStatusToString(status).c_str());

                // Reload YARA rules if active signature changed
                if (m_config.loadActiveOnly && m_config.enableYaraCompilation) {
                    LoadYaraRules(nullptr);
                }
            }

            return success;
        }

        bool SignatureDB::DeleteSignature(int64_t signatureId, DatabaseError* err) {
            if (!m_initialized.load(std::memory_order_acquire)) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"SignatureDB not initialized";
                }
                return false;
            }

            // Get signature info before deletion for logging
            auto signature = GetSignature(signatureId, err);

            bool success = DatabaseManager::Instance().ExecuteWithParams(
                SQL_DELETE_SIGNATURE, err, signatureId);

            if (success && signature.has_value()) {
                SS_LOG_INFO(L"SignatureDB", L"Deleted signature: %ls (ID: %lld)",
                           signature->name.c_str(), signatureId);

                // Remove from caches
                {
                    std::unique_lock<std::mutex> cacheLock(m_cacheMutex);
                    m_compiledCache.erase(signatureId);
                }

                {
                    std::unique_lock<std::shared_mutex> yaraLock(m_yaraMutex);
                    m_yaraRuleMap.erase(signatureId);
                }

                // Update statistics
                {
                    std::lock_guard<std::mutex> lock(m_statsMutex);
                    if (m_stats.totalSignatures > 0) {
                        m_stats.totalSignatures--;
                    }
                }
            }

            return success;
        }

        bool SignatureDB::AddBatch(const std::vector<SignatureEntry>& signatures, DatabaseError* err) {
            if (signatures.empty()) return true;

            auto trans = DatabaseManager::Instance().BeginTransaction(
                Transaction::Type::Immediate, err);
            
            if (!trans || !trans->IsActive()) {
                return false;
            }

            for (const auto& sig : signatures) {
                if (AddSignature(sig, err) < 0) {
                    trans->Rollback(err);
                    return false;
                }
            }

            if (!trans->Commit(err)) {
                return false;
            }

            SS_LOG_INFO(L"SignatureDB", L"Added %zu signatures in batch", signatures.size());
            return true;
        }

        bool SignatureDB::UpdateBatch(const std::vector<SignatureEntry>& signatures, DatabaseError* err) {
            if (signatures.empty()) return true;

            auto trans = DatabaseManager::Instance().BeginTransaction(
                Transaction::Type::Immediate, err);
            
            if (!trans || !trans->IsActive()) {
                return false;
            }

            for (const auto& sig : signatures) {
                if (!UpdateSignature(sig, err)) {
                    trans->Rollback(err);
                    return false;
                }
            }

            if (!trans->Commit(err)) {
                return false;
            }

            SS_LOG_INFO(L"SignatureDB", L"Updated %zu signatures in batch", signatures.size());
            return true;
        }

        bool SignatureDB::DeleteBatch(const std::vector<int64_t>& signatureIds, DatabaseError* err) {
            if (signatureIds.empty()) return true;

            auto trans = DatabaseManager::Instance().BeginTransaction(
                Transaction::Type::Immediate, err);
            
            if (!trans || !trans->IsActive()) {
                return false;
            }

            for (int64_t id : signatureIds) {
                if (!DeleteSignature(id, err)) {
                    trans->Rollback(err);
                    return false;
                }
            }

            if (!trans->Commit(err)) {
                return false;
            }

            SS_LOG_INFO(L"SignatureDB", L"Deleted %zu signatures in batch", signatureIds.size());
            return true;
        }

        // ============================================================================
        // Query Operations
        // ============================================================================

        std::optional<SignatureDB::SignatureEntry> SignatureDB::GetSignature(int64_t id, DatabaseError* err) {
            return dbSelectSignature(id, err);
        }

        std::optional<SignatureDB::SignatureEntry> SignatureDB::GetSignatureByName(std::wstring_view name,
                                                                                   DatabaseError* err) {
            auto result = DatabaseManager::Instance().QueryWithParams(
                SQL_SELECT_SIGNATURE_BY_NAME, err, ToUTF8(name));

            if (result.Next()) {
                return rowToSignatureEntry(result);
            }

            return std::nullopt;
        }

        std::vector<SignatureDB::SignatureEntry> SignatureDB::Query(const QueryFilter& filter,
                                                                     DatabaseError* err) {
            std::vector<std::string> params;
            std::string sql = buildQuerySQL(filter, params);

            return dbSelectSignatures(sql, params, err);
        }

        std::vector<SignatureDB::SignatureEntry> SignatureDB::GetByType(SignatureType type,
                                                                         size_t maxCount,
                                                                         DatabaseError* err) {
            QueryFilter filter;
            filter.type = type;
            filter.maxResults = maxCount;
            return Query(filter, err);
        }

        std::vector<SignatureDB::SignatureEntry> SignatureDB::GetByCategory(SignatureCategory category,
                                                                             size_t maxCount,
                                                                             DatabaseError* err) {
            QueryFilter filter;
            filter.category = category;
            filter.maxResults = maxCount;
            return Query(filter, err);
        }

        std::vector<SignatureDB::SignatureEntry> SignatureDB::GetActiveSignatures(SignatureType type,
                                                                                   DatabaseError* err) {
            QueryFilter filter;
            filter.status = SignatureStatus::Active;
            if (type != SignatureType::Unknown) {
                filter.type = type;
            }
            filter.maxResults = SIZE_MAX;
            return Query(filter, err);
        }

        std::vector<SignatureDB::SignatureEntry> SignatureDB::GetTopDetectors(size_t count,
                                                                               DatabaseError* err) {
            QueryFilter filter;
            filter.minDetectionCount = 1;
            filter.maxResults = count;
            filter.sortByDetectionCount = true;
            filter.sortDescending = true;
            return Query(filter, err);
        }

        std::vector<SignatureDB::SignatureEntry> SignatureDB::SearchByTags(const std::vector<std::wstring>& tags,
                                                                            bool matchAll,
                                                                            DatabaseError* err) {
            if (tags.empty()) return {};

            std::ostringstream sql;
            sql << "SELECT * FROM signatures WHERE 1=1";

            for (const auto& tag : tags) {
                if (matchAll) {
                    sql << " AND tags LIKE ?";
                } else {
                    sql << " OR tags LIKE ?";
                }
            }

            sql << " ORDER BY detection_count DESC LIMIT 1000";

            std::vector<std::string> params;
            for (const auto& tag : tags) {
                params.push_back("%" + ToUTF8(tag) + "%");
            }

            return dbSelectSignatures(sql.str(), params, err);
        }

        int64_t SignatureDB::CountSignatures(const QueryFilter* filter, DatabaseError* err) {
            std::vector<std::string> params;
            std::string sql;
            
            if (filter) {
                sql = buildCountSQL(*filter, params);
            } else {
                sql = SQL_COUNT_ALL;
            }

            auto result = DatabaseManager::Instance().Query(sql, err);
            
            if (result.Next()) {
                return result.GetInt64(0);
            }

            return -1;
        }

        // ============================================================================
        // YARA Operations
        // ============================================================================

        bool SignatureDB::CompileYaraRule(int64_t signatureId, DatabaseError* err) {
            if (!m_config.enableYaraCompilation) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"YARA compilation is disabled";
                }
                return false;
            }

            auto signature = GetSignature(signatureId, err);
            if (!signature.has_value()) {
                return false;
            }

            if (signature->type != SignatureType::YaraRule) {
                if (err) {
                    err->sqliteCode = SQLITE_CONSTRAINT;
                    err->message = L"Not a YARA rule signature";
                }
                return false;
            }

            return compileYaraRuleInternal(*signature, err);
        }

        bool SignatureDB::CompileAllYaraRules(DatabaseError* err) {
            if (!m_config.enableYaraCompilation) {
                return false;
            }

            SS_LOG_INFO(L"SignatureDB", L"Compiling all YARA rules...");

            auto yaraSignatures = GetByType(SignatureType::YaraRule, SIZE_MAX, err);
            
            size_t successCount = 0;
            size_t failCount = 0;

            for (const auto& sig : yaraSignatures) {
                if (compileYaraRuleInternal(sig, nullptr)) {
                    successCount++;
                } else {
                    failCount++;
                }
            }

            SS_LOG_INFO(L"SignatureDB", L"Compiled %zu YARA rules, %zu failed",
                       successCount, failCount);

            {
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.compiledYaraRules = successCount;
                m_stats.failedYaraCompilations = failCount;
            }

            return failCount == 0;
        }

        bool SignatureDB::ValidateYaraRule(std::wstring_view ruleSource,
                                           std::wstring& errorMessage,
                                           DatabaseError* err) {
            if (!m_config.enableYaraCompilation) {
                errorMessage = L"YARA is not enabled";
                return false;
            }

            YR_COMPILER* compiler = nullptr;
            int result = yr_compiler_create(&compiler);
            if (result != ERROR_SUCCESS) {
                errorMessage = L"Failed to create YARA compiler";
                return false;
            }

            struct ErrorContext {
                std::wstring error;
            };
            ErrorContext context;

            yr_compiler_set_callback(compiler, [](int errorLevel, const char* fileName,
                                                   int lineNumber, const YR_RULE* rule,
                                                   const char* message, void* userData) {
                auto* ctx = static_cast<ErrorContext*>(userData);
                std::ostringstream oss;
                oss << "Line " << lineNumber << ": " << message;
                ctx->error = ToWide(oss.str());
            }, &context);

            std::string ruleStr = ToUTF8(ruleSource);
            result = yr_compiler_add_string(compiler, ruleStr.c_str(), nullptr);

            yr_compiler_destroy(compiler);

            if (result != ERROR_SUCCESS) {
                errorMessage = context.error;
                return false;
            }

            return true;
        }

        bool SignatureDB::LoadYaraRules(DatabaseError* err) {
            if (!m_config.enableYaraCompilation) {
                return false;
            }

            SS_LOG_INFO(L"SignatureDB", L"Loading YARA rules into memory...");

            std::shared_lock<std::shared_mutex> yaraLock(m_yaraMutex);
            
            // Unload existing rules first
            if (m_yaraRules) {
                yr_rules_destroy(m_yaraRules);
                m_yaraRules = nullptr;
                m_yaraRuleMap.clear();
            }

            yaraLock.unlock();

            // Create new compiler
            YR_COMPILER* compiler = nullptr;
            int result = yr_compiler_create(&compiler);
            if (result != ERROR_SUCCESS) {
                SS_LOG_ERROR(L"SignatureDB", L"Failed to create YARA compiler");
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"YARA compiler creation failed";
                }
                return false;
            }

            yr_compiler_set_callback(compiler, yaraCompilerCallback, this);

            // Get active YARA rules
            auto yaraSignatures = GetActiveSignatures(SignatureType::YaraRule, err);
            if (yaraSignatures.empty()) {
                yr_compiler_destroy(compiler);
                SS_LOG_WARN(L"SignatureDB", L"No active YARA rules found");
                return true;
            }

            // Add each rule to compiler
            size_t loadedCount = 0;
            for (const auto& sig : yaraSignatures) {
                std::string ruleStr = ToUTF8(sig.signatureData);
                std::string nameStr = ToUTF8(sig.name);
                
                result = yr_compiler_add_string(compiler, ruleStr.c_str(), nameStr.c_str());
                if (result == ERROR_SUCCESS) {
                    loadedCount++;
                } else {
                    SS_LOG_WARN(L"SignatureDB", L"Failed to add YARA rule: %ls", sig.name.c_str());
                }
            }

            // Get compiled rules
            YR_RULES* rules = nullptr;
            result = yr_compiler_get_rules(compiler, &rules);
            yr_compiler_destroy(compiler);

            if (result != ERROR_SUCCESS || !rules) {
                SS_LOG_ERROR(L"SignatureDB", L"Failed to get compiled YARA rules");
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"YARA rule compilation failed";
                }
                return false;
            }

            // Store compiled rules
            std::unique_lock<std::shared_mutex> writeLock(m_yaraMutex);
            m_yaraRules = rules;

            // Build rule map for quick lookup
            YR_RULE* rule = nullptr;
            yr_rules_foreach(m_yaraRules, rule) {
                std::wstring ruleName = ToWide(rule->identifier);
                auto sig = GetSignatureByName(ruleName, nullptr);
                if (sig.has_value()) {
                    m_yaraRuleMap[sig->id] = rule;
                }
            }

            SS_LOG_INFO(L"SignatureDB", L"Loaded %zu YARA rules successfully", loadedCount);

            {
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.totalYaraRules = yaraSignatures.size();
                m_stats.compiledYaraRules = loadedCount;
            }

            return true;
        }

        bool SignatureDB::UnloadYaraRules() {
            std::unique_lock<std::shared_mutex> lock(m_yaraMutex);

            if (m_yaraRules) {
                yr_rules_destroy(m_yaraRules);
                m_yaraRules = nullptr;
            }

            m_yaraRuleMap.clear();

            SS_LOG_INFO(L"SignatureDB", L"YARA rules unloaded");
            return true;
        }

        YR_COMPILER* SignatureDB::GetYaraCompiler(DatabaseError* err) {
            if (!m_config.enableYaraCompilation) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"YARA compilation is disabled";
                }
                return nullptr;
            }

            return m_yaraCompiler;
        }

        // ============================================================================
        // Detection/Matching Operations
        // ============================================================================

        std::vector<SignatureDB::MatchResult> SignatureDB::MatchFile(std::wstring_view filePath,
                                                                     DatabaseError* err) {
            // Read file
            std::vector<std::byte> fileData;
            Utils::FileUtils::Error fileErr;
            if (!Utils::FileUtils::ReadAllBytes(filePath, fileData, &fileErr)) {
                if (err) {
                    err->sqliteCode = SQLITE_IOERR;
                    err->message = L"Failed to read file: " + std::wstring(filePath);
                }
                return {};
            }

            return MatchData(reinterpret_cast<const uint8_t*>(fileData.data()),
                           fileData.size(), filePath, err);
        }

        std::vector<SignatureDB::MatchResult> SignatureDB::MatchData(const uint8_t* data,
                                                                     size_t size,
                                                                     std::wstring_view identifier,
                                                                     DatabaseError* err) {
            if (!m_initialized.load(std::memory_order_acquire)) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"SignatureDB not initialized";
                }
                return {};
            }

            if (!data || size == 0) {
                return {};
            }

            std::vector<MatchResult> results;

            auto startTime = std::chrono::steady_clock::now();

            // Match hash signatures first (fastest)
            auto hashMatches = matchHashSignatures(data, size, err);
            results.insert(results.end(), hashMatches.begin(), hashMatches.end());

            // Match YARA rules
            if (m_config.enableYaraCompilation && m_yaraRules) {
                auto yaraMatches = matchYaraRules(data, size, identifier, err);
                results.insert(results.end(), yaraMatches.begin(), yaraMatches.end());
            }

            // Match pattern signatures
            auto patternMatches = matchPatternSignatures(data, size, err);
            results.insert(results.end(), patternMatches.begin(), patternMatches.end());

            auto endTime = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

            // Update statistics
            {
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.totalMatches++;
                m_stats.totalMatchTime += duration.count();
                m_stats.avgMatchTimeMs = static_cast<double>(m_stats.totalMatchTime) / m_stats.totalMatches;
                if (duration.count() > m_stats.maxMatchTimeMs) {
                    m_stats.maxMatchTimeMs = static_cast<double>(duration.count());
                }
            }

            m_metrics.totalMatches.fetch_add(1, std::memory_order_relaxed);
            m_metrics.totalMatchTime.fetch_add(duration.count(), std::memory_order_relaxed);

            return results;
        }

        std::vector<SignatureDB::MatchResult> SignatureDB::MatchWithType(const uint8_t* data,
                                                                         size_t size,
                                                                         SignatureType type,
                                                                         DatabaseError* err) {
            switch (type) {
                case SignatureType::YaraRule:
                    return matchYaraRules(data, size, L"", err);
                
                case SignatureType::MD5Hash:
                case SignatureType::SHA1Hash:
                case SignatureType::SHA256Hash:
                case SignatureType::FuzzyHash:
                    return matchHashSignatures(data, size, err);
                
                case SignatureType::BytePattern:
                case SignatureType::StringPattern:
                case SignatureType::RegexPattern:
                    return matchPatternSignatures(data, size, err);
                
                default:
                    return {};
            }
        }

        bool SignatureDB::IsKnownMalwareHash(std::wstring_view hash,
                                             std::wstring_view algorithm,
                                             DatabaseError* err) {
            std::wstring key = std::wstring(hash) + L":" + std::wstring(algorithm);

            std::shared_lock<std::shared_mutex> lock(m_hashCacheMutex);
            auto it = m_hashSignatureMap.find(key);
            
            if (it != m_hashSignatureMap.end() && !it->second.empty()) {
                return true;
            }

            // Fallback to database query
            lock.unlock();

            auto result = DatabaseManager::Instance().QueryWithParams(
                SQL_LOOKUP_HASH, err,
                ToUTF8(hash), ToUTF8(algorithm));

            return result.Next();
        }

        std::unordered_map<std::wstring, std::vector<SignatureDB::MatchResult>> 
        SignatureDB::MatchBatch(const std::vector<std::wstring>& filePaths, DatabaseError* err) {
            std::unordered_map<std::wstring, std::vector<MatchResult>> results;

            for (const auto& path : filePaths) {
                auto matches = MatchFile(path, err);
                if (!matches.empty()) {
                    results[path] = std::move(matches);
                }
            }

            return results;
        }

        // ============================================================================
        // Update Operations
        // ============================================================================

        bool SignatureDB::CheckForUpdates(DatabaseError* err) {
            if (!m_config.enableAutoUpdate || m_config.updateServer.empty()) {
                return false;
            }

            SS_LOG_INFO(L"SignatureDB", L"Checking for signature updates...");

            // TODO: Implement cloud update checking
            // This would involve HTTP/HTTPS requests to update server
            // For now, return false

            m_lastUpdateCheck = std::chrono::steady_clock::now();
            return false;
        }

        bool SignatureDB::DownloadUpdates(std::wstring_view updateSource, DatabaseError* err) {
            // TODO: Implement signature download from cloud
            // This would download and verify signature packages
            return false;
        }

        bool SignatureDB::ImportSignatures(std::wstring_view filePath,
            bool overwriteExisting,
            DatabaseError* err) {
            SS_LOG_INFO(L"SignatureDB", L"Importing signatures from: %ls", filePath.data());

            // Read the file
            std::vector<std::byte> fileData;
            Utils::FileUtils::Error fileErr;
            if (!Utils::FileUtils::ReadAllBytes(filePath, fileData, &fileErr)) {
                if (err) {
                    err->sqliteCode = SQLITE_IOERR;
                    err->message = L"Failed to read import file";
                    err->context = L"ImportSignatures.ReadAllBytes";
                }
                return false;
            }
            const std::string jsonText(reinterpret_cast<const char*>(fileData.data()), fileData.size());

            //parse the json
            Utils::JSON::Json root;
            try {
              
                root = Utils::JSON::Json::parse(jsonText, nullptr, /*allow_exceptions*/ true, /*ignore_comments*/ true);
            }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(L"SignatureDB", L"Import parse error: %hs", ex.what());
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Invalid JSON import content";
                    err->context = L"ImportSignatures.Parse";
                }
                return false;
            }

            auto now = std::chrono::system_clock::now();

            //extract the signature array
            Utils::JSON::Json sigArray;
            if (root.is_array()) {
                sigArray = root;
            }
            else if (root.is_object() && root.contains("signatures") && root["signatures"].is_array()) {
                sigArray = root["signatures"];
            }
            else if (root.is_object()) {
				// single signature object
                sigArray = Utils::JSON::Json::array();
                sigArray.push_back(root);
            }
            else {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Unexpected JSON format for import";
                    err->context = L"ImportSignatures.Schema";
                }
                return false;
            }

            if (sigArray.empty()) {
                SS_LOG_WARN(L"SignatureDB", L"Import file contains zero signatures");
                return true;
            }

            //  Transaction
            auto trans = DatabaseManager::Instance().BeginTransaction(Transaction::Type::Immediate, err);
            if (!trans || !trans->IsActive()) {
                if (err && err->message.empty()) {
                    err->sqliteCode = SQLITE_BUSY;
                    err->message = L"Failed to start transaction for import";
                    err->context = L"ImportSignatures.BeginTransaction";
                }
                return false;
            }

            size_t imported = 0;
            size_t updated = 0;
            size_t skipped = 0;

			//  Process each signature
            for (const auto& j : sigArray) {
                try {
                    if (!j.is_object()) { skipped++; continue; }

                    SignatureEntry entry;

					// name (required)
                    if (j.contains("name") && j["name"].is_string()) entry.name = ToWide(j["name"].get<std::string>());
                    if (entry.name.empty()) { skipped++; continue; }

                    // display_name
                    if (j.contains("display_name") && j["display_name"].is_string())
                        entry.displayName = ToWide(j["display_name"].get<std::string>());
                    else
                        entry.displayName = entry.name;

                    // type
                    if (j.contains("type")) {
                        if (j["type"].is_string()) {
                            entry.type = StringToSignatureType(ToWide(j["type"].get<std::string>()));
                        }
                        else if (j["type"].is_number_integer()) {
                            entry.type = static_cast<SignatureType>(j["type"].get<int>());
                        }
                    }

                    // severity
                    if (j.contains("severity")) {
                        if (j["severity"].is_string()) {
                            entry.severity = StringToSignatureSeverity(ToWide(j["severity"].get<std::string>()));
                        }
                        else if (j["severity"].is_number_integer()) {
                            entry.severity = static_cast<SignatureSeverity>(j["severity"].get<int>());
                        }
                    }

                    // category
                    if (j.contains("category")) {
                        if (j["category"].is_string()) {
                            entry.category = StringToSignatureCategory(ToWide(j["category"].get<std::string>()));
                        }
                        else if (j["category"].is_number_integer()) {
                            entry.category = static_cast<SignatureCategory>(j["category"].get<int>());
                        }
                    }

                    // status
                    if (j.contains("status")) {
                        if (j["status"].is_string()) {
                            entry.status = StringToSignatureStatus(ToWide(j["status"].get<std::string>()));
                        }
                        else if (j["status"].is_number_integer()) {
                            entry.status = static_cast<SignatureStatus>(j["status"].get<int>());
                        }
                    }

                    // source
                    if (j.contains("source")) {
                        if (j["source"].is_number_integer()) {
                            entry.source = static_cast<SignatureSource>(j["source"].get<int>());
                        }
                        else if (j["source"].is_string()) {
                            //could be add string map but not need rn
                        }
                    }

                    // signature_data / pattern
                    if (j.contains("signature_data") && j["signature_data"].is_string())
                        entry.signatureData = ToWide(j["signature_data"].get<std::string>());
                    if (j.contains("pattern") && j["pattern"].is_string())
                        entry.pattern = ToWide(j["pattern"].get<std::string>());

                    // compiled_data (base64)
                    if (j.contains("compiled_data_base64") && j["compiled_data_base64"].is_string()) {
                        const std::string b64 = j["compiled_data_base64"].get<std::string>();
                        std::vector<uint8_t> blob;
                        Utils::Base64DecodeError derr = Utils::Base64DecodeError::None;
                        if (Utils::Base64Decode(b64, blob, derr)) {
                            entry.compiledData = std::move(blob);
                        }
                    }

                    // description, author, reference
                    if (j.contains("description") && j["description"].is_string())
                        entry.description = ToWide(j["description"].get<std::string>());
                    if (j.contains("author") && j["author"].is_string())
                        entry.author = ToWide(j["author"].get<std::string>());
                    if (j.contains("reference") && j["reference"].is_string())
                        entry.reference = ToWide(j["reference"].get<std::string>());

                    // tags
                    if (j.contains("tags") && j["tags"].is_array()) {
                        for (const auto& t : j["tags"]) {
                            if (t.is_string()) entry.tags.push_back(ToWide(t.get<std::string>()));
                        }
                    }

                    // version, version_string
                    if (j.contains("version") && j["version"].is_number_integer())
                        entry.version = j["version"].get<int>();
                    if (j.contains("version_string") && j["version_string"].is_string())
                        entry.versionString = ToWide(j["version_string"].get<std::string>());

                    // timestamps (ISO string)
                    entry.createdAt = now;
                    entry.modifiedAt = now;
                    if (j.contains("created_at") && j["created_at"].is_string()) {
                        entry.createdAt = stringToTimePoint(j["created_at"].get<std::string>());
                    }
                    if (j.contains("modified_at") && j["modified_at"].is_string()) {
                        entry.modifiedAt = stringToTimePoint(j["modified_at"].get<std::string>());
                    }
                    if (j.contains("last_used_at") && j["last_used_at"].is_string()) {
                        entry.lastUsedAt = stringToTimePoint(j["last_used_at"].get<std::string>());
                    }

                    // detection stats
                    if (j.contains("detection_count") && j["detection_count"].is_number_unsigned())
                        entry.detectionCount = j["detection_count"].get<uint64_t>();
                    if (j.contains("false_positive_count") && j["false_positive_count"].is_number_unsigned())
                        entry.falsePositiveCount = j["false_positive_count"].get<uint64_t>();
                    if (j.contains("last_detection_timestamp") && j["last_detection_timestamp"].is_number_unsigned())
                        entry.lastDetectionTimestamp = j["last_detection_timestamp"].get<uint64_t>();
                    if (j.contains("effectiveness_score") && j["effectiveness_score"].is_number_float())
                        entry.effectivenessScore = j["effectiveness_score"].get<double>();
                    if (j.contains("avg_match_time_ms") && j["avg_match_time_ms"].is_number_unsigned())
                        entry.avgMatchTimeMs = j["avg_match_time_ms"].get<uint64_t>();
                    if (j.contains("total_match_time_ms") && j["total_match_time_ms"].is_number_unsigned())
                        entry.totalMatchTimeMs = j["total_match_time_ms"].get<uint64_t>();
                    if (j.contains("match_attempts") && j["match_attempts"].is_number_unsigned())
                        entry.matchAttempts = j["match_attempts"].get<uint64_t>();

                    // dependencies, conflicts, targets
                    auto readWStringArray = [](const Utils::JSON::Json& arr, std::vector<std::wstring>& dst) {
                        if (arr.is_array()) {
                            for (const auto& v : arr) if (v.is_string()) dst.push_back(ToWide(v.get<std::string>()));
                        }
                        };
                    if (j.contains("dependencies")) readWStringArray(j["dependencies"], entry.dependencies);
                    if (j.contains("conflicts")) readWStringArray(j["conflicts"], entry.conflicts);
                    if (j.contains("target_file_types")) readWStringArray(j["target_file_types"], entry.targetFileTypes);
                    if (j.contains("target_platforms")) readWStringArray(j["target_platforms"], entry.targetPlatforms);

                    if (j.contains("min_file_size") && j["min_file_size"].is_number_unsigned())
                        entry.minFileSize = j["min_file_size"].get<uint64_t>();
                    if (j.contains("max_file_size") && j["max_file_size"].is_number_unsigned())
                        entry.maxFileSize = j["max_file_size"].get<uint64_t>();

                    // YARA specifics
                    if (j.contains("yara_namespace") && j["yara_namespace"].is_string())
                        entry.yaraNamespace = ToWide(j["yara_namespace"].get<std::string>());
                    if (j.contains("yara_private") && j["yara_private"].is_boolean())
                        entry.yaraPrivate = j["yara_private"].get<bool>();
                    if (j.contains("yara_global") && j["yara_global"].is_boolean())
                        entry.yaraGlobal = j["yara_global"].get<bool>();
                    if (j.contains("yara_meta") && j["yara_meta"].is_object()) {
                        for (auto it = j["yara_meta"].begin(); it != j["yara_meta"].end(); ++it) {
                            if (it.value().is_string()) {
                                entry.yaraMeta[ToWide(it.key())] = ToWide(it.value().get<std::string>());
                            }
                            else if (it.value().is_number() || it.value().is_boolean()) {
                                entry.yaraMeta[ToWide(it.key())] = ToWide(it.value().dump());
                            }
                        }
                    }

                    // Hash specifics
                    if (j.contains("hash_algorithm") && j["hash_algorithm"].is_string())
                        entry.hashAlgorithm = ToWide(j["hash_algorithm"].get<std::string>());

                    // Whitelist
                    if (j.contains("can_be_whitelisted") && j["can_be_whitelisted"].is_boolean())
                        entry.canBeWhitelisted = j["can_be_whitelisted"].get<bool>();
                    if (j.contains("whitelist")) readWStringArray(j["whitelist"], entry.whitelist);

                    // Update tracking
                    if (j.contains("update_source") && j["update_source"].is_string())
                        entry.updateSource = ToWide(j["update_source"].get<std::string>());
                    if (j.contains("update_id") && j["update_id"].is_string())
                        entry.updateId = ToWide(j["update_id"].get<std::string>());
                    if (j.contains("last_update_check") && j["last_update_check"].is_string())
                        entry.lastUpdateCheck = stringToTimePoint(j["last_update_check"].get<std::string>());

                    // Custom data (object of string->string)
                    if (j.contains("custom_data") && j["custom_data"].is_object()) {
                        for (auto it = j["custom_data"].begin(); it != j["custom_data"].end(); ++it) {
                            if (it.value().is_string()) {
                                entry.customData[ToWide(it.key())] = ToWide(it.value().get<std::string>());
                            }
                            else {
                                entry.customData[ToWide(it.key())] = ToWide(it.value().dump());
                            }
                        }
                    }

                    // Insert/Update 
                    auto existing = GetSignatureByName(entry.name, nullptr);
                    if (existing.has_value()) {
                        if (!overwriteExisting) {
                            SS_LOG_WARN(L"SignatureDB", L"Skipping existing signature (overwrite=false): %ls", entry.name.c_str());
                            skipped++;
                            continue;
                        }
						//Update existing
                        entry.id = existing->id;
                        if (j.contains("created_at")) {
							//use if provided
                        }
                        else {
                            entry.createdAt = existing->createdAt;
                        }
                        entry.modifiedAt = now;

                        if (!UpdateSignature(entry, err)) {
                            if (err && !err->message.empty()) SS_LOG_ERROR(L"SignatureDB", L"Update failed: %ls", err->message.c_str());
                            trans->Rollback(err);
                            return false;
                        }
                        updated++;
                    }
                    else {
                        //Add new
                        int64_t id = AddSignature(entry, err);
                        if (id <= 0) {
                            if (err && !err->message.empty()) SS_LOG_ERROR(L"SignatureDB", L"Insert failed: %ls", err->message.c_str());
                            trans->Rollback(err);
                            return false;
                        }
                        imported++;
                    }
                }
                catch (const std::exception& ex) {
                    SS_LOG_ERROR(L"SignatureDB", L"Exception importing a signature: %hs", ex.what());
                    trans->Rollback(err);
                    return false;
                }
            }

            if (!trans->Commit(err)) {
                return false;
            }

            SS_LOG_INFO(L"SignatureDB", L"Signature import completed (imported=%zu, updated=%zu, skipped=%zu)", imported, updated, skipped);
            return true;
        }

        bool SignatureDB::ExportSignatures(std::wstring_view filePath,
            const QueryFilter* filter,
            DatabaseError* err) {
            SS_LOG_INFO(L"SignatureDB", L"Exporting signatures to: %ls", filePath.data());

            //Get signatures
            std::vector<SignatureEntry> signatures = filter ? Query(*filter, err)
                : GetActiveSignatures(SignatureType::Unknown, err);

            //compile the json
            auto toStr = [](const std::wstring& w) -> std::string {
                return ToUTF8(w);
                };
            auto tpToStr = [](const std::chrono::system_clock::time_point& tp) -> std::string {
                return timePointToString(tp);
                };
            auto putWStringArray = [&](Utils::JSON::Json& arr, const std::vector<std::wstring>& v) {
                for (const auto& s : v) arr.push_back(toStr(s));
                };
            auto putWStringMap = [&](Utils::JSON::Json& obj, const std::unordered_map<std::wstring, std::wstring>& m) {
                for (const auto& kv : m) obj[toStr(kv.first)] = toStr(kv.second);
                };

            Utils::JSON::Json root;
            root["exported_at"] = tpToStr(std::chrono::system_clock::now());
            root["count"] = static_cast<uint64_t>(signatures.size());
            root["signatures"] = Utils::JSON::Json::array();

            for (const auto& e : signatures) {
                Utils::JSON::Json j;

                j["id"] = e.id;
                j["name"] = toStr(e.name);
                j["display_name"] = toStr(e.displayName);

                j["type"] = toStr(SignatureTypeToString(e.type));
                j["severity"] = toStr(SignatureSeverityToString(e.severity));
                j["category"] = toStr(SignatureCategoryToString(e.category));
                j["status"] = toStr(SignatureStatusToString(e.status));
                j["source"] = static_cast<int>(e.source);

                j["signature_data"] = toStr(e.signatureData);
                j["pattern"] = toStr(e.pattern);

                // compiled_data -> base64
                if (!e.compiledData.empty()) {
                    std::string b64;
                    Utils::Base64Encode(e.compiledData, b64);
                    j["compiled_data_base64"] = b64;
                }
                else {
                    j["compiled_data_base64"] = "";
                }

                j["description"] = toStr(e.description);
                j["author"] = toStr(e.author);
                j["reference"] = toStr(e.reference);

                // tags
                j["tags"] = Utils::JSON::Json::array();
                putWStringArray(j["tags"], e.tags);

                j["version"] = e.version;
                j["version_string"] = toStr(e.versionString);

                j["created_at"] = tpToStr(e.createdAt);
                j["modified_at"] = tpToStr(e.modifiedAt);
                if (e.lastUsedAt.time_since_epoch().count() != 0)
                    j["last_used_at"] = tpToStr(e.lastUsedAt);

                // stats
                j["detection_count"] = e.detectionCount;
                j["false_positive_count"] = e.falsePositiveCount;
                j["last_detection_timestamp"] = e.lastDetectionTimestamp;
                j["effectiveness_score"] = e.effectivenessScore;
                j["avg_match_time_ms"] = e.avgMatchTimeMs;
                j["total_match_time_ms"] = e.totalMatchTimeMs;
                j["match_attempts"] = e.matchAttempts;

                // deps/targets/etc
                j["dependencies"] = Utils::JSON::Json::array();
                putWStringArray(j["dependencies"], e.dependencies);
                j["conflicts"] = Utils::JSON::Json::array();
                putWStringArray(j["conflicts"], e.conflicts);
                j["target_file_types"] = Utils::JSON::Json::array();
                putWStringArray(j["target_file_types"], e.targetFileTypes);
                j["target_platforms"] = Utils::JSON::Json::array();
                putWStringArray(j["target_platforms"], e.targetPlatforms);

                j["min_file_size"] = e.minFileSize;
                j["max_file_size"] = e.maxFileSize;

                // YARA
                j["yara_namespace"] = toStr(e.yaraNamespace);
                j["yara_private"] = e.yaraPrivate;
                j["yara_global"] = e.yaraGlobal;
                j["yara_meta"] = Utils::JSON::Json::object();
                putWStringMap(j["yara_meta"], e.yaraMeta);

                // Hash
                j["hash_algorithm"] = toStr(e.hashAlgorithm);

                // Whitelist
                j["can_be_whitelisted"] = e.canBeWhitelisted;
                j["whitelist"] = Utils::JSON::Json::array();
                putWStringArray(j["whitelist"], e.whitelist);

                // Update tracking
                j["update_source"] = toStr(e.updateSource);
                j["update_id"] = toStr(e.updateId);
                if (e.lastUpdateCheck.time_since_epoch().count() != 0)
                    j["last_update_check"] = tpToStr(e.lastUpdateCheck);

                // Custom data
                j["custom_data"] = Utils::JSON::Json::object();
                putWStringMap(j["custom_data"], e.customData);

                root["signatures"].push_back(std::move(j));
            }

            //JSON stringify (pretty)
            std::string jsonOut;
            {
                Utils::JSON::StringifyOptions so;
                so.pretty = true;
                so.indentSpaces = 2;
                if (!Utils::JSON::Stringify(root, jsonOut, so)) {
                    if (err) {
                        err->sqliteCode = SQLITE_ERROR;
                        err->message = L"Failed to serialize signatures to JSON";
                        err->context = L"ExportSignatures.Stringify";
                    }
                    return false;
                }
            }

            Utils::FileUtils::Error fileErr;
            const bool ok = Utils::FileUtils::WriteAllTextUtf8Atomic(filePath, jsonOut, &fileErr);
            if (!ok) {
                if (err) {
                    err->sqliteCode = SQLITE_IOERR;
                    err->message = L"Failed to write export file";
                    err->context = L"ExportSignatures.WriteAllTextUtf8Atomic";
                }
                return false;
            }

            SS_LOG_INFO(L"SignatureDB", L"Exported %zu signatures", signatures.size());
            return true;
        }

        // ============================================================================
        // Statistics & Reporting
        // ============================================================================

        SignatureDB::Statistics SignatureDB::GetStatistics(DatabaseError* err) {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            return m_stats;
        }

        void SignatureDB::ResetStatistics() {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            
            m_stats.totalDetections = 0;
            m_stats.detectionsLast24h = 0;
            m_stats.detectionsLast7d = 0;
            m_stats.detectionsLast30d = 0;
            m_stats.totalMatches = 0;
            m_stats.totalMatchTime = 0;
            m_stats.avgMatchTimeMs = 0.0;
            m_stats.maxMatchTimeMs = 0.0;
            m_stats.falsePositiveCount = 0;
            m_stats.falsePositiveRate = 0.0;

            m_metrics.totalMatches.store(0, std::memory_order_relaxed);
            m_metrics.totalMatchTime.store(0, std::memory_order_relaxed);
            m_metrics.yaraMatches.store(0, std::memory_order_relaxed);
            m_metrics.hashMatches.store(0, std::memory_order_relaxed);
            m_metrics.patternMatches.store(0, std::memory_order_relaxed);
        }

        void SignatureDB::RecordDetection(int64_t signatureId,
                                          std::wstring_view filePath,
                                          const MatchResult& result) {
            auto now = std::chrono::system_clock::now();
            auto nowEpoch = std::chrono::duration_cast<std::chrono::seconds>(
                now.time_since_epoch()).count();

            // Calculate file hash
            std::wstring fileHash = calculateFileHash(filePath, L"SHA256");

            // Insert detection record
            DatabaseManager::Instance().ExecuteWithParams(
                SQL_INSERT_DETECTION, nullptr,
                signatureId,
                ToUTF8(result.signatureName),
                ToUTF8(filePath),
                ToUTF8(fileHash),
                static_cast<int64_t>(nowEpoch),
                static_cast<int64_t>(result.matchOffset),
                static_cast<int64_t>(result.matchLength),
                result.confidence);

            // Update signature statistics
            std::string updateStatsSQL = R"(
                UPDATE signatures SET
                    detection_count = detection_count + 1,
                    last_detection_timestamp = ?,
                    last_used_at = ?
                WHERE id = ?
            )";

            DatabaseManager::Instance().ExecuteWithParams(
                updateStatsSQL, nullptr,
                static_cast<int64_t>(nowEpoch),
                static_cast<int64_t>(nowEpoch),
                signatureId);

            // Update global statistics
            {
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.totalDetections++;
                m_stats.detectionsLast24h++;
                m_stats.detectionsLast7d++;
                m_stats.detectionsLast30d++;
            }

            SS_LOG_INFO(L"SignatureDB", L"Recorded detection: %ls in %ls",
                       result.signatureName.c_str(), filePath.data());
        }

        void SignatureDB::RecordFalsePositive(int64_t signatureId,
                                              std::wstring_view filePath,
                                              std::wstring_view reason) {
            DatabaseManager::Instance().ExecuteWithParams(
                SQL_RECORD_FALSE_POSITIVE, nullptr,
                ToUTF8(reason),
                signatureId,
                ToUTF8(filePath),
                signatureId,
                ToUTF8(filePath));

            // Update signature false positive count
            std::string updateSQL = "UPDATE signatures SET false_positive_count = false_positive_count + 1 WHERE id = ?";
            DatabaseManager::Instance().ExecuteWithParams(updateSQL, nullptr, signatureId);

            {
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.falsePositiveCount++;
            }

            SS_LOG_WARN(L"SignatureDB", L"Recorded false positive: signature %lld in %ls",
                       signatureId, filePath.data());
        }

        std::wstring SignatureDB::GetEffectivenessReport(int64_t signatureId) {
            auto signature = GetSignature(signatureId, nullptr);
            if (!signature.has_value()) {
                return L"Signature not found";
            }

            std::wostringstream report;
            report << L"Effectiveness Report for: " << signature->name << L"\n";
            report << L"======================================\n";
            report << L"Total Detections: " << signature->detectionCount << L"\n";
            report << L"False Positives: " << signature->falsePositiveCount << L"\n";
            
            double fpRate = signature->detectionCount > 0 ?
                static_cast<double>(signature->falsePositiveCount) / signature->detectionCount : 0.0;
            report << L"False Positive Rate: " << std::fixed << std::setprecision(2) 
                   << (fpRate * 100.0) << L"%\n";
            
            report << L"Effectiveness Score: " << signature->effectivenessScore << L"\n";
            report << L"Average Match Time: " << signature->avgMatchTimeMs << L" ms\n";
            report << L"Total Match Attempts: " << signature->matchAttempts << L"\n";

            return report.str();
        }

        std::vector<SignatureDB::DetectionRecord> SignatureDB::GetDetectionHistory(
            int64_t signatureId,
            std::optional<std::chrono::system_clock::time_point> since,
            size_t maxCount,
            DatabaseError* err) {
            
            std::ostringstream sql;
            sql << "SELECT * FROM detections WHERE signature_id = ?";
            
            if (since.has_value()) {
                auto sinceEpoch = std::chrono::duration_cast<std::chrono::seconds>(
                    since->time_since_epoch()).count();
                sql << " AND detection_time >= " << sinceEpoch;
            }
            
            sql << " ORDER BY detection_time DESC LIMIT " << maxCount;

            auto result = DatabaseManager::Instance().QueryWithParams(
                sql.str(), err, signatureId);

            std::vector<DetectionRecord> records;
            while (result.Next()) {
                DetectionRecord record;
                record.id = result.GetInt64(0);
                record.signatureId = result.GetInt64(1);
                record.signatureName = result.GetWString(2);
                record.filePath = result.GetWString(3);
                record.fileHash = result.GetWString(4);
                
                int64_t timestamp = result.GetInt64(5);
                record.timestamp = std::chrono::system_clock::from_time_t(
                    static_cast<time_t>(timestamp));
                
                record.wasFalsePositive = result.GetInt(8) != 0;
                
                records.push_back(record);
            }

            return records;
        }

        // ============================================================================
        // Configuration & Maintenance
        // ============================================================================

        SignatureDB::Config SignatureDB::GetConfig() const {
            std::shared_lock<std::shared_mutex> lock(m_configMutex);
            return m_config;
        }

        void SignatureDB::SetConfig(const Config& config) {
            std::unique_lock<std::shared_mutex> lock(m_configMutex);
            m_config = config;
        }

        bool SignatureDB::Vacuum(DatabaseError* err) {
            SS_LOG_INFO(L"SignatureDB", L"Running VACUUM...");
            return DatabaseManager::Instance().Vacuum(err);
        }

        bool SignatureDB::CheckIntegrity(DatabaseError* err) {
            SS_LOG_INFO(L"SignatureDB", L"Checking database integrity...");
            std::vector<std::wstring> issues;
            return DatabaseManager::Instance().CheckIntegrity(issues, err);
        }

        bool SignatureDB::Optimize(DatabaseError* err) {
            SS_LOG_INFO(L"SignatureDB", L"Optimizing database...");
            return DatabaseManager::Instance().Optimize(err);
        }

        bool SignatureDB::RebuildIndices(DatabaseError* err) {
            SS_LOG_INFO(L"SignatureDB", L"Rebuilding indices...");
            
            DatabaseManager::Instance().Execute("DROP INDEX IF EXISTS idx_signatures_name", nullptr);
            DatabaseManager::Instance().Execute("DROP INDEX IF EXISTS idx_signatures_type", nullptr);
            DatabaseManager::Instance().Execute("DROP INDEX IF EXISTS idx_signatures_status", nullptr);
            DatabaseManager::Instance().Execute("DROP INDEX IF EXISTS idx_signatures_detection_count", nullptr);

            return DatabaseManager::Instance().Execute(SQL_CREATE_INDICES, err);
        }

        bool SignatureDB::CleanupDeprecated(DatabaseError* err) {
            auto cutoffTime = std::chrono::system_clock::now() - m_config.deprecatedSignatureRetention;
            auto cutoffEpoch = std::chrono::duration_cast<std::chrono::seconds>(
                cutoffTime.time_since_epoch()).count();

            std::string deleteSQL = "DELETE FROM signatures WHERE status = ? AND modified_at < ?";
            
            bool success = DatabaseManager::Instance().ExecuteWithParams(
                deleteSQL, err,
                static_cast<int>(SignatureStatus::Deprecated),
                static_cast<int64_t>(cutoffEpoch));

            if (success) {
                SS_LOG_INFO(L"SignatureDB", L"Cleaned up deprecated signatures");
            }

            return success;
        }

        bool SignatureDB::CleanupOldVersions(DatabaseError* err) {
            if (!m_initialized.load(std::memory_order_acquire)) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"SignatureDB not initialized";
                    err->context = L"CleanupOldVersions";
                }
                return false;
            }

            const size_t keep = m_config.maxSignatureVersions;
            if (keep == 0) {
				// no cleanup
                SS_LOG_INFO(L"SignatureDB", L"CleanupOldVersions: maxSignatureVersions=0, skipping cleanup");
                return true;
            }

            SS_LOG_INFO(L"SignatureDB", L"CleanupOldVersions: keeping latest %zu versions per signature", keep);

            auto& db = DatabaseManager::Instance();
            auto trans = db.BeginTransaction(Transaction::Type::Immediate, err);
            if (!trans || !trans->IsActive()) {
                SS_LOG_ERROR(L"SignatureDB", L"CleanupOldVersions: failed to start transaction");
                return false;
            }

            std::vector<std::wstring> names;
            {
                auto r = db.QueryWithParams(
                    "SELECT name FROM signatures GROUP BY name HAVING COUNT(*) > ?",
                    err,
                    static_cast<int>(keep)
                );
                while (r.Next()) {
                    names.push_back(r.GetWString(0));
                }
            }

            if (names.empty()) {
                // nothing to delete
                if (!trans->Commit(err)) return false;

                std::lock_guard<std::mutex> lk(m_statsMutex);
                m_stats.lastCleanup = std::chrono::system_clock::now();
                SS_LOG_INFO(L"SignatureDB", L"CleanupOldVersions: nothing to delete");
                return true;
            }

            size_t deletedCount = 0;

          
            for (const auto& nm : names) {
              
                auto rr = db.QueryWithParams(
                    "SELECT id FROM signatures WHERE name = ? "
                    "ORDER BY version DESC, modified_at DESC, created_at DESC, id DESC",
                    err,
                    ToUTF8(nm)
                );

                std::vector<int64_t> ids;
                while (rr.Next()) {
                    ids.push_back(rr.GetInt64(0));
                }

                if (ids.size() <= keep) continue;

              
                for (size_t i = keep; i < ids.size(); ++i) {
                    const int64_t id = ids[i];

                    evictCacheEntry(id);

                    if (!db.ExecuteWithParams(SQL_DELETE_SIGNATURE, err, id)) {
                        SS_LOG_ERROR(L"SignatureDB", L"CleanupOldVersions: delete failed for ID=%lld", id);
                        trans->Rollback(err);
                        return false;
                    }
                    ++deletedCount;
                }
            }

            if (!trans->Commit(err)) {
                SS_LOG_ERROR(L"SignatureDB", L"CleanupOldVersions: commit failed");
                return false;
            }

           
            try {
                std::unique_lock<std::shared_mutex> hashLock(m_hashCacheMutex);
                m_hashSignatureMap.clear();

                auto r = db.Query("SELECT hash_value, hash_algorithm, signature_id FROM hash_lookup", err);
                while (r.Next()) {
                    std::wstring hash = r.GetWString(0);
                    std::wstring algo = r.GetWString(1);
                    int64_t sigId = r.GetInt64(2);
                    std::wstring key = hash + L":" + algo;
                    m_hashSignatureMap[key].push_back(sigId);
                }
            }
            catch (...) {
              
                SS_LOG_WARN(L"SignatureDB", L"CleanupOldVersions: failed to rebuild hash cache");
            }

        
            if (deletedCount > 0 && m_config.enableYaraCompilation) {
                if (!CompileAllYaraRules(nullptr)) {
                    SS_LOG_WARN(L"SignatureDB", L"CleanupOldVersions: CompileAllYaraRules failed after cleanup");
                }
            }

             //update the statistics
            recalculateStatistics(err);
            {
                std::lock_guard<std::mutex> lk(m_statsMutex);
                m_stats.lastCleanup = std::chrono::system_clock::now();
            }

            SS_LOG_INFO(L"SignatureDB", L"CleanupOldVersions: deleted %zu old versions", deletedCount);
            return true;
        }

        // ============================================================================
        // Query Builders
        // ============================================================================

        std::string SignatureDB::buildQuerySQL(const QueryFilter& filter, std::vector<std::string>& outParams) {
            std::ostringstream sql;
            sql << "SELECT * FROM signatures WHERE 1=1";

            if (filter.type) {
                sql << " AND type = " << static_cast<int>(*filter.type);
            }

            if (filter.minSeverity) {
                sql << " AND severity >= " << static_cast<int>(*filter.minSeverity);
            }

            if (filter.maxSeverity) {
                sql << " AND severity <= " << static_cast<int>(*filter.maxSeverity);
            }

            if (filter.category) {
                sql << " AND category = " << static_cast<int>(*filter.category);
            }

            if (filter.status) {
                sql << " AND status = " << static_cast<int>(*filter.status);
            }

            if (filter.source) {
                sql << " AND source = " << static_cast<int>(*filter.source);
            }

            if (filter.namePattern) {
                sql << " AND name LIKE '%" << ToUTF8(*filter.namePattern) << "%'";
            }

            if (filter.minDetectionCount) {
                sql << " AND detection_count >= " << *filter.minDetectionCount;
            }

            if (filter.minEffectiveness) {
                sql << " AND effectiveness_score >= " << *filter.minEffectiveness;
            }

            // Sorting
            if (filter.sortByEffectiveness) {
                sql << " ORDER BY effectiveness_score DESC";
            } else if (filter.sortByDetectionCount) {
                sql << " ORDER BY detection_count DESC";
            } else {
                sql << " ORDER BY created_at DESC";
            }

            sql << " LIMIT " << filter.maxResults;

            return sql.str();
        }

        std::string SignatureDB::buildCountSQL(const QueryFilter& filter, std::vector<std::string>& outParams) {
            std::ostringstream sql;
            sql << "SELECT COUNT(*) FROM signatures WHERE 1=1";

            if (filter.type) {
                sql << " AND type = " << static_cast<int>(*filter.type);
            }

            if (filter.category) {
                sql << " AND category = " << static_cast<int>(*filter.category);
            }

            if (filter.status) {
                sql << " AND status = " << static_cast<int>(*filter.status);
            }

            return sql.str();
        }

        // ============================================================================
        // YARA Internal Operations
        // ============================================================================

        bool SignatureDB::compileYaraRuleInternal(const SignatureEntry& entry, DatabaseError* err) {
            if (!m_yaraCompiler) {
                return false;
            }

            std::string ruleStr = ToUTF8(entry.signatureData);
            std::string nameStr = ToUTF8(entry.name);
            
            int result = yr_compiler_add_string(m_yaraCompiler, ruleStr.c_str(), nameStr.c_str());
            
            if (result != ERROR_SUCCESS) {
                SS_LOG_ERROR(L"SignatureDB", L"Failed to compile YARA rule: %ls", entry.name.c_str());
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"YARA compilation failed";
                }
                return false;
            }

            SS_LOG_DEBUG(L"SignatureDB", L"Compiled YARA rule: %ls", entry.name.c_str());
            return true;
        }

        void SignatureDB::yaraCompilerCallback(int errorLevel, const char* fileName,
                                              int lineNumber, const YR_RULE* rule,
                                              const char* message, void* userData) {
            auto* self = static_cast<SignatureDB*>(userData);
            
            std::wostringstream logMsg;
            logMsg << L"YARA compiler ";
            
            if (errorLevel == YARA_ERROR_LEVEL_ERROR) {
                logMsg << L"ERROR";
            } else {
                logMsg << L"WARNING";
            }
            
            logMsg << L" at line " << lineNumber << L": " << ToWide(message);
            
            if (errorLevel == YARA_ERROR_LEVEL_ERROR) {
                SS_LOG_ERROR(L"SignatureDB", L"%ls", logMsg.str().c_str());
            } else {
                SS_LOG_WARN(L"SignatureDB", L"%ls", logMsg.str().c_str());
            }
        }

        // ============================================================================
        // YARA Callback - Match Processing
        // ============================================================================

        int SignatureDB::yaraMatchCallback(YR_SCAN_CONTEXT* context,
            int message,
            void* messageData,
            void* userData) {
            if (!context || !userData) {
                SS_LOG_ERROR(L"SignatureDB", L"Invalid YARA callback parameters");
                return CALLBACK_ERROR;
            }

            auto* results = static_cast<std::vector<MatchResult>*>(userData);
            if (!results) {
                SS_LOG_ERROR(L"SignatureDB", L"Invalid match results pointer");
                return CALLBACK_ERROR;
            }

            try {
                switch (message) {
                case CALLBACK_MSG_RULE_MATCHING: {
                    auto* rule = static_cast<YR_RULE*>(messageData);
                    if (!rule) break;

                    MatchResult match{};
                    match.signatureName = ToWide(rule->identifier);
                    match.signatureType = SignatureType::YaraRule;
                    match.matchTimestamp = std::chrono::system_clock::now();


                    YR_META* meta = nullptr;
                    yr_rule_metas_foreach(rule, meta) {
                        std::wstring metaId = ToWide(meta->identifier);

                        if (metaId == L"severity" && meta->type == META_TYPE_INTEGER) {
                            int sev = static_cast<int>(meta->integer);
                            if (sev >= 0 && sev <= 4) {
                                match.severity = static_cast<SignatureSeverity>(sev);
                            }
                        }
                        else if ((metaId == L"category" || metaId == L"description") &&
                            meta->type == META_TYPE_STRING) {
                            match.metaTags[metaId] = ToWide(meta->string);
                        }
                    }


                    YR_STRING* string = nullptr;
                    yr_rule_strings_foreach(rule, string) {
                        YR_MATCH* m = nullptr;
                        yr_string_matches_foreach(context, string, m) {

                            match.matchedStrings.push_back(ToWide(string->identifier));


                            if (match.matchedData.empty()) {
                                match.matchOffset = static_cast<size_t>(m->offset);
                                match.matchLength = static_cast<size_t>(m->match_length);

                                constexpr size_t MAX_MATCH_DATA = 1024;
                                size_t copyLen = std::min(match.matchLength, MAX_MATCH_DATA);
                                if (copyLen > 0 && m->data) {
                                    match.matchedData.assign(m->data, m->data + copyLen);
                                }
                            }
                        }
                    }

                    size_t matchCount = match.matchedStrings.size();
                    match.confidence = (matchCount > 5) ? 1.0
                        : (matchCount > 2) ? 0.8
                        : (matchCount > 0) ? 0.6 : 0.4;

                    results->push_back(std::move(match));

                    SS_LOG_DEBUG(L"SignatureDB", L"YARA rule matched: %ls (%zu strings matched)",
                        results->back().signatureName.c_str(), matchCount);
                    break;
                }

                case CALLBACK_MSG_RULE_NOT_MATCHING:
                    break;

                case CALLBACK_MSG_SCAN_FINISHED:
                    SS_LOG_DEBUG(L"SignatureDB", L"YARA scan finished, %zu rules matched",
                        results->size());
                    break;

                case CALLBACK_MSG_IMPORT_MODULE: {
                    auto* moduleName = static_cast<const char*>(messageData);
                    if (moduleName) {
                        SS_LOG_TRACE(L"SignatureDB", L"YARA module imported: %ls",
                            ToWide(moduleName).c_str());
                    }
                    break;
                }

                case CALLBACK_MSG_MODULE_IMPORTED:
                    break;

                default:
                    SS_LOG_WARN(L"SignatureDB", L"Unknown YARA callback message: %d", message);
                    break;
                }

                return CALLBACK_CONTINUE;
            }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(L"SignatureDB", L"Exception in YARA callback: %ls",
                    ToWide(ex.what()).c_str());
                return CALLBACK_ERROR;
            }
            catch (...) {
                SS_LOG_ERROR(L"SignatureDB", L"Unknown exception in YARA callback");
                return CALLBACK_ERROR;
            }
        }

        // ============================================================================
        // Matching Engines
        // ============================================================================

        std::vector<SignatureDB::MatchResult> SignatureDB::matchYaraRules(
            const uint8_t* data,
            size_t size,
            std::wstring_view identifier,
            DatabaseError* err) {
            
            std::vector<MatchResult> results;

            std::shared_lock<std::shared_mutex> lock(m_yaraMutex);
            
            if (!m_yaraRules) {
                return results;
            }

            // YARA scan with timeout
            YR_CALLBACK_FUNC callback = [](YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) -> int {
                if (message == CALLBACK_MSG_RULE_MATCHING) {
                    auto* results = static_cast<std::vector<MatchResult>*>(user_data);
                    auto* rule = static_cast<YR_RULE*>(message_data);
                    
                    MatchResult result;
                    result.signatureName = ToWide(rule->identifier);
                    result.signatureType = SignatureType::YaraRule;
                    result.matchTimestamp = std::chrono::system_clock::now();
                    result.confidence = 1.0;
                    
                    results->push_back(result);
                }
                return CALLBACK_CONTINUE;
            };

            int scanResult = yr_rules_scan_mem(
                m_yaraRules,
                data,
                size,
                0, // flags
                callback,
                &results,
                static_cast<int>(m_config.yaraTimeout)
            );

            if (scanResult != ERROR_SUCCESS) {
                SS_LOG_WARN(L"SignatureDB", L"YARA scan failed with error: %d", scanResult);
            }

            m_metrics.yaraMatches.fetch_add(results.size(), std::memory_order_relaxed);

            return results;
        }

        std::vector<SignatureDB::MatchResult> SignatureDB::matchHashSignatures(
            const uint8_t* data,
            size_t size,
            DatabaseError* err) {
            
            std::vector<MatchResult> results;

            // Calculate hashes
            std::wstring md5 = calculateDataHash(data, size, L"MD5");
            std::wstring sha1 = calculateDataHash(data, size, L"SHA1");
            std::wstring sha256 = calculateDataHash(data, size, L"SHA256");

            std::vector<std::pair<std::wstring, std::wstring>> hashes = {
                {sha256, L"SHA256"},
                {sha1, L"SHA1"},
                {md5, L"MD5"}
            };

            std::shared_lock<std::shared_mutex> lock(m_hashCacheMutex);

            for (const auto& [hash, algo] : hashes) {
                if (hash.empty()) continue;

                std::wstring key = hash + L":" + algo;
                auto it = m_hashSignatureMap.find(key);
                
                if (it != m_hashSignatureMap.end()) {
                    for (int64_t sigId : it->second) {
                        auto sig = GetSignature(sigId, nullptr);
                        if (sig.has_value() && sig->status == SignatureStatus::Active) {
                            MatchResult result;
                            result.signatureId = sigId;
                            result.signatureName = sig->displayName;
                            result.signatureType = sig->type;
                            result.severity = sig->severity;
                            result.category = sig->category;
                            result.matchTimestamp = std::chrono::system_clock::now();
                            result.confidence = 1.0;
                            
                            results.push_back(result);
                        }
                    }
                }
            }

            m_metrics.hashMatches.fetch_add(results.size(), std::memory_order_relaxed);

            return results;
        }

        std::vector<SignatureDB::MatchResult> SignatureDB::matchPatternSignatures(
            const uint8_t* data,
            size_t size,
            DatabaseError* err)
        {
            std::vector<MatchResult> results;
            results.reserve(64);

            if (!data || size == 0) {
                return results;
            }

			//get the active pattern signatures
            QueryFilter filter;
            filter.status = SignatureStatus::Active;
            filter.maxResults = SIZE_MAX;

            auto signatures = Query(filter, nullptr);
            if (signatures.empty()) {
                m_metrics.patternMatches.fetch_add(0, std::memory_order_relaxed);
                return results;
            }

            const char* hayBegin = reinterpret_cast<const char*>(data);
            const char* hayEnd = hayBegin + size;

            
            for (const auto& sig : signatures) {
                if (sig.type != SignatureType::BytePattern &&
                    sig.type != SignatureType::StringPattern &&
                    sig.type != SignatureType::RegexPattern)
                {
                    continue;
                }

				// Pattern text (UTF-8)
                const std::string pat = ToUTF8(sig.pattern);
                if (pat.empty()) {
                    continue;
                }

                //Length filter
                if (sig.type != SignatureType::RegexPattern && pat.size() > size) {
                    continue;
                }

                const auto t0 = std::chrono::steady_clock::now();

                size_t matchPos = std::string::npos;
                size_t matchLen = 0;

                if (sig.type == SignatureType::RegexPattern) {
					// Regex : compile with optimize flag
                    try {
                        const std::regex rx(pat, std::regex::ECMAScript | std::regex::optimize);
                        std::cmatch m;
                        if (std::regex_search(hayBegin, hayEnd, m, rx)) {
                            matchPos = static_cast<size_t>(m.position(0));
                            matchLen = static_cast<size_t>(m.length(0));
                        }
                    }
                    catch (const std::exception& ex) {
						// Regex compile/run error : Log and skip.
                        SS_LOG_WARN(L"SignatureDB", L"Regex compile/search failed for '%ls': %ls",
                            sig.name.c_str(), ToWide(ex.what()).c_str());
                        continue;
                    }
                }
                else {
                    // BytePattern and StringPattern: fast substring searching with Boyer–Moore–Horspool
                    const auto searcher = std::boyer_moore_horspool_searcher(pat.begin(), pat.end());
                    const char* it = std::search(hayBegin, hayEnd, searcher);
                    if (it != hayEnd) {
                        matchPos = static_cast<size_t>(it - hayBegin);
                        matchLen = pat.size();
                    }
                }

                if (matchPos != std::string::npos) {
                    MatchResult result;
                    result.signatureId = sig.id;
                    result.signatureName = sig.displayName;
                    result.signatureType = sig.type;
                    result.severity = sig.severity;
                    result.category = sig.category;

                    result.matchOffset = matchPos;
                    result.matchLength = matchLen;
                    result.matchTimestamp = std::chrono::system_clock::now();

                
                    if (sig.type == SignatureType::RegexPattern) {
                        result.confidence = 0.85;
                    }
                    else {
                        result.confidence = (matchLen >= 8) ? 0.95 : 0.90;
                    }

                 
                    if (matchLen > 0) {
                        const size_t maxCopy = std::min(matchLen, m_config.yaraMaxMatchData);
                        result.matchedData.reserve(maxCopy);
                        const uint8_t* src = reinterpret_cast<const uint8_t*>(hayBegin + matchPos);
                        result.matchedData.insert(result.matchedData.end(), src, src + maxCopy);
                    }

                    const auto t1 = std::chrono::steady_clock::now();
                    result.matchDuration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0);

                    results.push_back(std::move(result));

                 //update the performance metrics(if exists)
                    recordMatch(sig.id, std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0));
                }
            }

            m_metrics.patternMatches.fetch_add(results.size(), std::memory_order_relaxed);
            return results;
        }

        // ============================================================================
        // Hash Calculation
        // ============================================================================

        std::wstring SignatureDB::calculateFileHash(std::wstring_view filePath,
                                                    std::wstring_view algorithm) {
            std::vector<std::byte> fileData;
            Utils::FileUtils::Error err;
            if (!Utils::FileUtils::ReadAllBytes(filePath, fileData, &err)) {
                return L"";
            }

            return calculateDataHash(reinterpret_cast<const uint8_t*>(fileData.data()),
                                    fileData.size(), algorithm);
        }

        std::wstring SignatureDB::calculateDataHash(const uint8_t* data,
                                                    size_t size,
                                                    std::wstring_view algorithm) {
            Utils::HashUtils::Algorithm alg;
            
            if (algorithm == L"MD5") {
                alg = Utils::HashUtils::Algorithm::MD5;
            } else if (algorithm == L"SHA1") {
                alg = Utils::HashUtils::Algorithm::SHA1;
            } else if (algorithm == L"SHA256") {
                alg = Utils::HashUtils::Algorithm::SHA256;
            } else {
                // Default to SHA256
                alg = Utils::HashUtils::Algorithm::SHA256;
            }
            
            std::string hexResult;
            Utils::HashUtils::Error hashErr;
            if (!Utils::HashUtils::ComputeHex(alg, data, size, hexResult, false, &hashErr)) {
                return L"";
            }
            
            return ToWide(hexResult);
        }

        // ============================================================================
        // Cache Management
        // ============================================================================

        bool SignatureDB::cacheCompiledRule(int64_t signatureId, const std::vector<uint8_t>& compiledData) {
            std::unique_lock<std::mutex> lock(m_cacheMutex);

            if (m_compiledCache.size() >= m_config.compiledCacheSize) {
                // Evict oldest
                m_compiledCache.erase(m_compiledCache.begin());
            }

            CacheEntry entry;
            entry.compiledData = compiledData;
            entry.lastAccessed = std::chrono::steady_clock::now();
            entry.accessCount = 0;
            
            m_compiledCache[signatureId] = std::move(entry);
            return true;
        }

        std::optional<std::vector<uint8_t>> SignatureDB::getCachedCompiledRule(int64_t signatureId) {
            std::unique_lock<std::mutex> lock(m_cacheMutex);

            auto it = m_compiledCache.find(signatureId);
            if (it != m_compiledCache.end()) {
                it->second.lastAccessed = std::chrono::steady_clock::now();
                it->second.accessCount++;
                return it->second.compiledData;
            }

            return std::nullopt;
        }

        void SignatureDB::evictCacheEntry(int64_t signatureId) {
            std::unique_lock<std::mutex> lock(m_cacheMutex);
            m_compiledCache.erase(signatureId);
        }

        // ============================================================================
        // Update Thread
        // ============================================================================

        void SignatureDB::updateThread() {
            SS_LOG_INFO(L"SignatureDB", L"Update thread started");

            while (!m_shutdownUpdate.load(std::memory_order_acquire)) {
                std::unique_lock<std::mutex> lock(m_updateMutex);

                m_updateCV.wait_for(lock, m_config.updateCheckInterval, [this]() {
                    return m_shutdownUpdate.load(std::memory_order_acquire);
                });

                if (m_shutdownUpdate.load(std::memory_order_acquire)) {
                    break;
                }

                // Check for updates
                CheckForUpdates(nullptr);
            }

            SS_LOG_INFO(L"SignatureDB", L"Update thread stopped");
        }

        // ============================================================================
        // Statistics Helpers
        // ============================================================================

        void SignatureDB::updateStatistics(const SignatureEntry& entry) {
            std::lock_guard<std::mutex> lock(m_statsMutex);

            // Update type/category/severity counters
            if (static_cast<size_t>(entry.type) < 256) {
                m_stats.signaturesByType[static_cast<size_t>(entry.type)]++;
            }

            if (static_cast<size_t>(entry.category) < 256) {
                m_stats.signaturesByCategory[static_cast<size_t>(entry.category)]++;
            }

            if (entry.severity <= SignatureSeverity::Critical) {
                m_stats.signaturesBySeverity[static_cast<size_t>(entry.severity)]++;
            }
        }

        void SignatureDB::recalculateStatistics(DatabaseError* err) {
            std::lock_guard<std::mutex> lock(m_statsMutex);

            // Reset counters
            m_stats.totalSignatures = 0;
            m_stats.activeSignatures = 0;
            m_stats.disabledSignatures = 0;
            m_stats.deprecatedSignatures = 0;
            std::fill(std::begin(m_stats.signaturesByType), std::end(m_stats.signaturesByType), 0);
            std::fill(std::begin(m_stats.signaturesByCategory), std::end(m_stats.signaturesByCategory), 0);
            std::fill(std::begin(m_stats.signaturesBySeverity), std::end(m_stats.signaturesBySeverity), 0);

            // Recalculate from database
            auto result = DatabaseManager::Instance().Query(SQL_COUNT_ALL, err);
            if (result.Next()) {
                m_stats.totalSignatures = static_cast<uint64_t>(result.GetInt64(0));
            }

            // Count by status
            auto activeResult = DatabaseManager::Instance().Query(
                "SELECT COUNT(*) FROM signatures WHERE status = " +
                std::to_string(static_cast<int>(SignatureStatus::Active)), err);
            
            if (activeResult.Next()) {
                m_stats.activeSignatures = static_cast<uint64_t>(activeResult.GetInt64(0));
            }

            // Get database size
            auto dbStats = DatabaseManager::Instance().GetStats(err);
            m_stats.dbSizeBytes = dbStats.totalSize;
        }

        void SignatureDB::recordMatch(int64_t signatureId, std::chrono::milliseconds duration) {
            // Update signature-specific performance metrics
            std::string updateSQL = R"(
                UPDATE signatures SET
                    match_attempts = match_attempts + 1,
                    total_match_time_ms = total_match_time_ms + ?,
                    avg_match_time_ms = (total_match_time_ms + ?) / (match_attempts + 1),
                    last_used_at = ?
                WHERE id = ?
            )";

            auto now = std::chrono::system_clock::now();
            auto nowEpoch = std::chrono::duration_cast<std::chrono::seconds>(
                now.time_since_epoch()).count();

            DatabaseManager::Instance().ExecuteWithParams(
                updateSQL, nullptr,
                static_cast<int64_t>(duration.count()),
                static_cast<int64_t>(duration.count()),
                static_cast<int64_t>(nowEpoch),
                signatureId);
        }

        // ============================================================================
        // Utility Helpers
        // ============================================================================

        std::vector<std::wstring> SignatureDB::parseTagString(std::string_view tagStr) {
            return deserializeStringVector(tagStr);
        }

        std::string SignatureDB::serializeTagVector(const std::vector<std::wstring>& tags) {
            return serializeStringVector(tags);
        }

        // ============================================================================
        // Missing function implementations that linker expects
        // ============================================================================

        std::wstring SignatureDB::SignatureTypeToString(SignatureType type) {
            switch (type) {
                case SignatureType::Unknown: return L"Unknown";
                case SignatureType::YaraRule: return L"YARA";
                case SignatureType::MD5Hash: return L"MD5";
                case SignatureType::SHA1Hash: return L"SHA1";
                case SignatureType::SHA256Hash: return L"SHA256";
                case SignatureType::FuzzyHash: return L"FuzzyHash";
                case SignatureType::BytePattern: return L"BytePattern";
                case SignatureType::StringPattern: return L"StringPattern";
                case SignatureType::RegexPattern: return L"RegexPattern";
                case SignatureType::Behavioral: return L"Behavioral";
                case SignatureType::Heuristic: return L"Heuristic";
                case SignatureType::PEHeader: return L"PEHeader";
                case SignatureType::Network: return L"Network";
                case SignatureType::Registry: return L"Registry";
                case SignatureType::Mutex: return L"Mutex";
                case SignatureType::Custom: return L"Custom";
                default: return L"Unknown";
            }
        }

        std::wstring SignatureDB::SignatureStatusToString(SignatureStatus status) {
            switch (status) {
                case SignatureStatus::Active: return L"Active";
                case SignatureStatus::Disabled: return L"Disabled";
                case SignatureStatus::Deprecated: return L"Deprecated";
                case SignatureStatus::Testing: return L"Testing";
                case SignatureStatus::Pending: return L"Pending";
                case SignatureStatus::Failed: return L"Failed";
                case SignatureStatus::Archived: return L"Archived";
                default: return L"Unknown";
            }
        }

        int64_t SignatureDB::dbInsertSignature(const SignatureEntry& entry, DatabaseError* err) {
            std::string tagsStr = serializeStringVector(entry.tags);
            auto createdMs = std::chrono::duration_cast<std::chrono::seconds>(
                entry.createdAt.time_since_epoch()).count();
            auto modifiedMs = std::chrono::duration_cast<std::chrono::seconds>(
                entry.modifiedAt.time_since_epoch()).count();

            bool success = DatabaseManager::Instance().ExecuteWithParams(
                SQL_INSERT_SIGNATURE, err,
                ToUTF8(entry.name), ToUTF8(entry.displayName),
                static_cast<int>(entry.type), static_cast<int>(entry.severity),
                static_cast<int>(entry.category), static_cast<int>(entry.status),
                static_cast<int>(entry.source), ToUTF8(entry.signatureData),
                entry.compiledData, ToUTF8(entry.pattern), ToUTF8(entry.description),
                ToUTF8(entry.author), ToUTF8(entry.reference), tagsStr,
                entry.version, ToUTF8(entry.versionString), createdMs, modifiedMs,
                serializeStringVector(entry.dependencies), serializeStringVector(entry.conflicts),
                serializeStringVector(entry.targetFileTypes), serializeStringVector(entry.targetPlatforms),
                static_cast<int64_t>(entry.minFileSize), static_cast<int64_t>(entry.maxFileSize),
                ToUTF8(entry.yaraNamespace), entry.yaraPrivate ? 1 : 0, entry.yaraGlobal ? 1 : 0,
                serializeStringVector(std::vector<std::wstring>{}), ToUTF8(entry.hashAlgorithm),
                entry.canBeWhitelisted ? 1 : 0, serializeStringVector(entry.whitelist),
                ToUTF8(entry.updateSource), ToUTF8(entry.updateId),
                serializeStringVector(std::vector<std::wstring>{})
            );

            return success ? DatabaseManager::Instance().LastInsertRowId() : -1;
        }

        bool SignatureDB::dbUpdateSignature(const SignatureEntry& entry, DatabaseError* err) {
            if (entry.id <= 0) {
                if (err) {
                    err->sqliteCode = SQLITE_CONSTRAINT;
                    err->message = L"Invalid signature ID";
                }
                return false;
            }

            auto modifiedMs = std::chrono::duration_cast<std::chrono::seconds>(
                entry.modifiedAt.time_since_epoch()).count();

            return DatabaseManager::Instance().ExecuteWithParams(
                SQL_UPDATE_SIGNATURE, err,
                ToUTF8(entry.displayName), static_cast<int>(entry.type),
                static_cast<int>(entry.severity), static_cast<int>(entry.category),
                static_cast<int>(entry.status), static_cast<int>(entry.source),
                ToUTF8(entry.signatureData), entry.compiledData, ToUTF8(entry.pattern),
                ToUTF8(entry.description), ToUTF8(entry.author), ToUTF8(entry.reference),
                serializeStringVector(entry.tags), entry.version, ToUTF8(entry.versionString),
                modifiedMs, serializeStringVector(entry.dependencies), serializeStringVector(entry.conflicts),
                serializeStringVector(entry.targetFileTypes), serializeStringVector(entry.targetPlatforms),
                static_cast<int64_t>(entry.minFileSize), static_cast<int64_t>(entry.maxFileSize),
                ToUTF8(entry.yaraNamespace), entry.yaraPrivate ? 1 : 0, entry.yaraGlobal ? 1 : 0,
                serializeStringVector(std::vector<std::wstring>{}), ToUTF8(entry.hashAlgorithm),
                entry.canBeWhitelisted ? 1 : 0, serializeStringVector(entry.whitelist),
                ToUTF8(entry.updateSource), ToUTF8(entry.updateId),
                serializeStringVector(std::vector<std::wstring>{}), entry.id
            );
        }

        std::optional<SignatureDB::SignatureEntry> SignatureDB::dbSelectSignature(int64_t id, DatabaseError* err) {
            auto result = DatabaseManager::Instance().QueryWithParams(SQL_SELECT_SIGNATURE_BY_ID, err, id);
            if (result.Next()) {
                return rowToSignatureEntry(result);
            }
            return std::nullopt;
        }

        std::vector<SignatureDB::SignatureEntry> SignatureDB::dbSelectSignatures(
            std::string_view sql, const std::vector<std::string>& params, DatabaseError* err) {
            
            std::vector<SignatureEntry> entries;
            auto result = DatabaseManager::Instance().Query(sql, err);

            while (result.Next()) {
                SignatureEntry entry;
                entry.id = result.GetInt64("id");
                entry.name = result.GetWString("name");
                entry.displayName = result.GetWString("display_name");
                entry.type = static_cast<SignatureType>(result.GetInt("type"));
                entry.severity = static_cast<SignatureSeverity>(result.GetInt("severity"));
                entry.category = static_cast<SignatureCategory>(result.GetInt("category"));
                entry.status = static_cast<SignatureStatus>(result.GetInt("status"));
                entry.source = static_cast<SignatureSource>(result.GetInt("source"));
                entry.signatureData = result.GetWString("signature_data");
                entry.compiledData = result.GetBlob("compiled_data");
                entry.pattern = result.GetWString("pattern");
                entry.description = result.GetWString("description");
                entry.author = result.GetWString("author");
                entry.reference = result.GetWString("reference");
                entry.tags = deserializeStringVector(result.GetString("tags"));
                entry.version = result.GetInt("version");
                entry.versionString = result.GetWString("version_string");
        
                int64_t createdEpoch = result.GetInt64("created_at");
                int64_t modifiedEpoch = result.GetInt64("modified_at");
                entry.createdAt = std::chrono::system_clock::from_time_t(static_cast<time_t>(createdEpoch));
                entry.modifiedAt = std::chrono::system_clock::from_time_t(static_cast<time_t>(modifiedEpoch));

                entry.detectionCount = static_cast<uint64_t>(result.GetInt64("detection_count"));
                entry.falsePositiveCount = static_cast<uint64_t>(result.GetInt64("false_positive_count"));
                entry.lastDetectionTimestamp = static_cast<uint64_t>(result.GetInt64("last_detection_timestamp"));
                entry.effectivenessScore = result.GetDouble("effectiveness_score");
                entry.avgMatchTimeMs = static_cast<uint64_t>(result.GetInt64("avg_match_time_ms"));
                entry.totalMatchTimeMs = static_cast<uint64_t>(result.GetInt64("total_match_time_ms"));
                entry.matchAttempts = static_cast<uint64_t>(result.GetInt64("match_attempts"));

                entries.push_back(entry);
            }

            return entries;
        }

        SignatureDB::SignatureEntry SignatureDB::rowToSignatureEntry(QueryResult& result) {
            SignatureEntry entry;
            entry.id = result.GetInt64(0);
            entry.name = result.GetWString(1);
            entry.displayName = result.GetWString(2);
            entry.type = static_cast<SignatureType>(result.GetInt(3));
            entry.severity = static_cast<SignatureSeverity>(result.GetInt(4));
            entry.category = static_cast<SignatureCategory>(result.GetInt(5));
            entry.status = static_cast<SignatureStatus>(result.GetInt(6));
            entry.source = static_cast<SignatureSource>(result.GetInt(7));
            entry.signatureData = result.GetWString(8);
            entry.compiledData = result.GetBlob(9);
            entry.pattern = result.GetWString(10);
            entry.description = result.GetWString(11);
            entry.author = result.GetWString(12);
            entry.reference = result.GetWString(13);
            entry.tags = deserializeStringVector(result.GetString(14));
            entry.version = result.GetInt(15);
            entry.versionString = result.GetWString(16);
            
            int64_t createdEpoch = result.GetInt64(17);
            int64_t modifiedEpoch = result.GetInt64(18);
            entry.createdAt = std::chrono::system_clock::from_time_t(static_cast<time_t>(createdEpoch));
            entry.modifiedAt = std::chrono::system_clock::from_time_t(static_cast<time_t>(modifiedEpoch));

            entry.detectionCount = static_cast<uint64_t>(result.GetInt64(19));
            entry.falsePositiveCount = static_cast<uint64_t>(result.GetInt64(20));
            entry.lastDetectionTimestamp = static_cast<uint64_t>(result.GetInt64(21));
            entry.effectivenessScore = result.GetDouble(22);
            entry.avgMatchTimeMs = static_cast<uint64_t>(result.GetInt64(23));
            entry.totalMatchTimeMs = static_cast<uint64_t>(result.GetInt64(24));
            entry.matchAttempts = static_cast<uint64_t>(result.GetInt64(25));

            return entry;
        }

        // ============================================================================
        // Database Operations - Delete Signature
        // ============================================================================

        bool SignatureDB::dbDeleteSignature(int64_t id, DatabaseError* err) {
            if (id <= 0) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"Invalid signature ID";
                }
                return false;
            }

            try {
                // Execute DELETE statement with parameter binding
                bool success = DatabaseManager::Instance().ExecuteWithParams(
                    SQL_DELETE_SIGNATURE,
                    err,
                    id
                );

                if (!success) {
                    SS_LOG_ERROR(L"SignatureDB", L"Failed to delete signature with ID: %lld", id);
                    return false;
                }

                // Verify deletion
                int rowsAffected = DatabaseManager::Instance().GetChangedRowCount();
                if (rowsAffected == 0) {
                    if (err) {
                        err->sqliteCode = SQLITE_NOTFOUND;
                        err->message = L"Signature not found";
                    }
                    SS_LOG_WARN(L"SignatureDB", L"No signature found with ID: %lld", id);
                    return false;
                }

                SS_LOG_DEBUG(L"SignatureDB", L"Successfully deleted signature ID: %lld", id);
                return true;
            }
            catch (const std::exception& ex) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = ToWide(ex.what());
                    err->context = L"dbDeleteSignature";
                }
                SS_LOG_ERROR(L"SignatureDB", L"Exception during signature deletion: %ls",
                    ToWide(ex.what()).c_str());
                return false;
            }
        }

      

        std::wstring SignatureDB::SignatureSeverityToString(SignatureSeverity severity) {
            switch (severity) {
            case SignatureSeverity::Info:     return L"Info";
            case SignatureSeverity::Low:      return L"Low";
            case SignatureSeverity::Medium:   return L"Medium";
            case SignatureSeverity::High:     return L"High";
            case SignatureSeverity::Critical: return L"Critical";
            default: return L"Unknown";
            }
        }

        SignatureDB::SignatureSeverity SignatureDB::StringToSignatureSeverity(std::wstring_view str) {
            if (str == L"Info") return SignatureSeverity::Info;
            if (str == L"Low") return SignatureSeverity::Low;
            if (str == L"Medium") return SignatureSeverity::Medium;
            if (str == L"High") return SignatureSeverity::High;
            if (str == L"Critical") return SignatureSeverity::Critical;
            // case-insensitive fallback
            std::wstring s(str);
            for (auto& c : s) c = static_cast<wchar_t>(towlower(c));
            if (s == L"info") return SignatureSeverity::Info;
            if (s == L"low") return SignatureSeverity::Low;
            if (s == L"medium") return SignatureSeverity::Medium;
            if (s == L"high") return SignatureSeverity::High;
            if (s == L"critical") return SignatureSeverity::Critical;
            return SignatureSeverity::Info;
        }

        std::wstring SignatureDB::SignatureCategoryToString(SignatureCategory category) {
            switch (category) {
            case SignatureCategory::General:     return L"General";
            case SignatureCategory::Malware:     return L"Malware";
            case SignatureCategory::Ransomware:  return L"Ransomware";
            case SignatureCategory::Trojan:      return L"Trojan";
            case SignatureCategory::Virus:       return L"Virus";
            case SignatureCategory::Worm:        return L"Worm";
            case SignatureCategory::Backdoor:    return L"Backdoor";
            case SignatureCategory::Rootkit:     return L"Rootkit";
            case SignatureCategory::Spyware:     return L"Spyware";
            case SignatureCategory::Adware:      return L"Adware";
            case SignatureCategory::Exploit:     return L"Exploit";
            case SignatureCategory::PUA:         return L"PUA";
            case SignatureCategory::Suspicious:  return L"Suspicious";
            case SignatureCategory::Packer:      return L"Packer";
            case SignatureCategory::Obfuscated:  return L"Obfuscated";
            case SignatureCategory::Cryptominer: return L"Cryptominer";
            case SignatureCategory::APT:         return L"APT";
            case SignatureCategory::Custom:      return L"Custom";
            default: return L"Unknown";
            }
        }

        SignatureDB::SignatureCategory SignatureDB::StringToSignatureCategory(std::wstring_view str) {
            if (str == L"General") return SignatureCategory::General;
            if (str == L"Malware") return SignatureCategory::Malware;
            if (str == L"Ransomware") return SignatureCategory::Ransomware;
            if (str == L"Trojan") return SignatureCategory::Trojan;
            if (str == L"Virus") return SignatureCategory::Virus;
            if (str == L"Worm") return SignatureCategory::Worm;
            if (str == L"Backdoor") return SignatureCategory::Backdoor;
            if (str == L"Rootkit") return SignatureCategory::Rootkit;
            if (str == L"Spyware") return SignatureCategory::Spyware;
            if (str == L"Adware") return SignatureCategory::Adware;
            if (str == L"Exploit") return SignatureCategory::Exploit;
            if (str == L"PUA") return SignatureCategory::PUA;
            if (str == L"Suspicious") return SignatureCategory::Suspicious;
            if (str == L"Packer") return SignatureCategory::Packer;
            if (str == L"Obfuscated") return SignatureCategory::Obfuscated;
            if (str == L"Cryptominer") return SignatureCategory::Cryptominer;
            if (str == L"APT") return SignatureCategory::APT;
            if (str == L"Custom") return SignatureCategory::Custom;
            // case-insensitive fallback
            std::wstring s(str);
            for (auto& c : s) c = static_cast<wchar_t>(towlower(c));
            if (s == L"malware") return SignatureCategory::Malware;
            if (s == L"ransomware") return SignatureCategory::Ransomware;
            if (s == L"trojan") return SignatureCategory::Trojan;
            if (s == L"virus") return SignatureCategory::Virus;
            if (s == L"worm") return SignatureCategory::Worm;
            if (s == L"backdoor") return SignatureCategory::Backdoor;
            if (s == L"rootkit") return SignatureCategory::Rootkit;
            if (s == L"spyware") return SignatureCategory::Spyware;
            if (s == L"adware") return SignatureCategory::Adware;
            if (s == L"exploit") return SignatureCategory::Exploit;
            if (s == L"pua") return SignatureCategory::PUA;
            if (s == L"suspicious") return SignatureCategory::Suspicious;
            if (s == L"packer") return SignatureCategory::Packer;
            if (s == L"obfuscated") return SignatureCategory::Obfuscated;
            if (s == L"cryptominer") return SignatureCategory::Cryptominer;
            if (s == L"apt") return SignatureCategory::APT;
            return SignatureCategory::General;
        }

        SignatureDB::SignatureType SignatureDB::StringToSignatureType(std::wstring_view str) {
            if (str == L"YARA" || str == L"Yara" || str == L"YaraRule") return SignatureType::YaraRule;
            if (str == L"MD5" || str == L"MD5Hash") return SignatureType::MD5Hash;
            if (str == L"SHA1" || str == L"SHA1Hash") return SignatureType::SHA1Hash;
            if (str == L"SHA256" || str == L"SHA256Hash") return SignatureType::SHA256Hash;
            if (str == L"FuzzyHash" || str == L"SSDeep" || str == L"TLSH") return SignatureType::FuzzyHash;
            if (str == L"BytePattern") return SignatureType::BytePattern;
            if (str == L"StringPattern") return SignatureType::StringPattern;
            if (str == L"RegexPattern") return SignatureType::RegexPattern;
            if (str == L"Behavioral") return SignatureType::Behavioral;
            if (str == L"Heuristic") return SignatureType::Heuristic;
            if (str == L"PEHeader") return SignatureType::PEHeader;
            if (str == L"Network") return SignatureType::Network;
            if (str == L"Registry") return SignatureType::Registry;
            if (str == L"Mutex") return SignatureType::Mutex;
            if (str == L"Custom") return SignatureType::Custom;
            // fallback: try numeric string
            try {
                int v = std::stoi(std::wstring(str));
                if (v >= 0 && v <= 255) return static_cast<SignatureType>(v);
            }
            catch (...) {}
            return SignatureType::Unknown;
        }

        SignatureDB::SignatureStatus SignatureDB::StringToSignatureStatus(std::wstring_view str) {
            if (str == L"Active") return SignatureStatus::Active;
            if (str == L"Disabled") return SignatureStatus::Disabled;
            if (str == L"Deprecated") return SignatureStatus::Deprecated;
            if (str == L"Testing") return SignatureStatus::Testing;
            if (str == L"Pending") return SignatureStatus::Pending;
            if (str == L"Failed") return SignatureStatus::Failed;
            if (str == L"Archived") return SignatureStatus::Archived;
            std::wstring s(str);
            for (auto& c : s) c = static_cast<wchar_t>(towlower(c));
            if (s == L"active") return SignatureStatus::Active;
            if (s == L"disabled") return SignatureStatus::Disabled;
            if (s == L"deprecated") return SignatureStatus::Deprecated;
            return SignatureStatus::Active;
        }

        std::string SignatureDB::timePointToString(std::chrono::system_clock::time_point tp) {
            using namespace std::chrono;
            std::time_t t = system_clock::to_time_t(tp);
            std::tm tm{};
#if defined(_WIN32)
            gmtime_s(&tm, &t);
#else
            gmtime_r(&t, &tm);
#endif
            std::ostringstream oss;
            oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
            return oss.str();
        }

        std::chrono::system_clock::time_point SignatureDB::stringToTimePoint(std::string_view str) {
            // Expect ISO8601 basic e.g. "2023-08-01T12:34:56Z" (fractional seconds allowed)
            std::string s(str);
            // remove trailing 'Z' for parsing if present
            bool hasZ = false;
            if (!s.empty() && s.back() == 'Z') { hasZ = true; s.pop_back(); }

            // trim fractional seconds
            std::string::size_type dotPos = s.find('.');
            std::string mainPart = (dotPos == std::string::npos) ? s : s.substr(0, dotPos);

            std::tm tm{};
            std::istringstream iss(mainPart);
            iss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
            if (iss.fail()) {
                // parsing failed -> return epoch
                return std::chrono::system_clock::time_point{};
            }

            // Convert tm (UTC) to time_t
#if defined(_WIN32)
            time_t t = _mkgmtime(&tm);
#else
            time_t t = timegm(&tm);
#endif
            if (t == static_cast<time_t>(-1)) return std::chrono::system_clock::time_point{};
            return std::chrono::system_clock::from_time_t(t);
        }


    } // namespace Database
} // namespace ShadowStrike