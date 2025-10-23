#pragma once

#include "../../external/SQLiteCpp/include/SQLiteCpp/SQLiteCpp.h"
#include "DatabaseManager.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/FileUtils.hpp"

#include <yara.h>

#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <unordered_map>
#include <set>

namespace ShadowStrike {
    namespace Database {

        // ============================================================================
        // SignatureDB - Enterprise Malware Signature Management System
        // ============================================================================

        /**
         * @brief Advanced signature database for malware detection and analysis.
         * 
         * Features:
         * - YARA rule compilation and management with incremental compilation
         * - Hash-based signature detection (MD5, SHA1, SHA256, Fuzzy Hashing)
         * - Pattern-based signatures with regex support
         * - Behavioral signatures and heuristics
         * - Signature versioning and update tracking
         * - Performance-optimized signature matching
         * - Real-time signature updates from cloud
         * - Signature effectiveness analytics
         * - Thread-safe concurrent access
         * - Signature whitelisting and exclusions
         * - Custom signature creation and testing
         */
        class SignatureDB {
        public:
            // ============================================================================
            // Types & Enums
            // ============================================================================

            enum class SignatureType : uint8_t {
                Unknown = 0,
                YaraRule = 1,           // YARA compiled rules
                MD5Hash = 2,            // MD5 hash signature
                SHA1Hash = 3,           // SHA1 hash signature
                SHA256Hash = 4,         // SHA256 hash signature
                FuzzyHash = 5,          // SSDeep/TLSH fuzzy hash
                BytePattern = 6,        // Raw byte pattern
                StringPattern = 7,      // String-based pattern
                RegexPattern = 8,       // Regular expression
                Behavioral = 9,         // Behavioral signature
                Heuristic = 10,         // Heuristic rule
                PEHeader = 11,          // PE file header signature
                Network = 12,           // Network traffic pattern
                Registry = 13,          // Registry key pattern
                Mutex = 14,             // Mutex name pattern
                Custom = 255
            };

            enum class SignatureSeverity : uint8_t {
                Info = 0,
                Low = 1,
                Medium = 2,
                High = 3,
                Critical = 4
            };

            enum class SignatureCategory : uint8_t {
                General = 0,
                Malware = 1,
                Ransomware = 2,
                Trojan = 3,
                Virus = 4,
                Worm = 5,
                Backdoor = 6,
                Rootkit = 7,
                Spyware = 8,
                Adware = 9,
                Exploit = 10,
                PUA = 11,               // Potentially Unwanted Application
                Suspicious = 12,
                Packer = 13,
                Obfuscated = 14,
                Cryptominer = 15,
                APT = 16,               // Advanced Persistent Threat
                Custom = 255
            };

            enum class SignatureStatus : uint8_t {
                Active = 0,             // Active and in use
                Disabled = 1,           // Temporarily disabled
                Deprecated = 2,         // Old signature, kept for reference
                Testing = 3,            // Under testing
                Pending = 4,            // Pending approval
                Failed = 5,             // Compilation/validation failed
                Archived = 6            // Archived, not loaded
            };

            enum class SignatureSource : uint8_t {
                Internal = 0,           // Created internally
                Cloud = 1,              // Downloaded from cloud
                Community = 2,          // Community-contributed
                Commercial = 3,         // Commercial vendor
                Custom = 4,             // User-created
                Import = 5              // Imported from external source
            };

            struct SignatureEntry {
                int64_t id = 0;
                std::wstring name;                  // Unique signature name
                std::wstring displayName;           // User-friendly name
                
                SignatureType type = SignatureType::Unknown;
                SignatureSeverity severity = SignatureSeverity::Medium;
                SignatureCategory category = SignatureCategory::General;
                SignatureStatus status = SignatureStatus::Active;
                SignatureSource source = SignatureSource::Internal;
                
                // Signature content
                std::wstring signatureData;         // YARA rule source / hash value / pattern
                std::vector<uint8_t> compiledData;  // Compiled YARA rules (binary)
                std::wstring pattern;               // String/regex pattern
                
                // Metadata
                std::wstring description;
                std::wstring author;
                std::wstring reference;             // CVE, URL, paper reference
                std::vector<std::wstring> tags;     // Classification tags
                
                // Version information
                int version = 1;
                std::wstring versionString;         // "1.0.5"
                std::chrono::system_clock::time_point createdAt;
                std::chrono::system_clock::time_point modifiedAt;
                std::chrono::system_clock::time_point lastUsedAt;
                
                // Detection statistics
                uint64_t detectionCount = 0;        // Total detections
                uint64_t falsePositiveCount = 0;    // Reported false positives
                uint64_t lastDetectionTimestamp = 0;
                double effectivenessScore = 0.0;    // 0.0 - 1.0
                
                // Performance metrics
                uint64_t avgMatchTimeMs = 0;        // Average match time
                uint64_t totalMatchTimeMs = 0;
                uint64_t matchAttempts = 0;
                
                // Dependencies
                std::vector<std::wstring> dependencies; // Other signatures this depends on
                std::vector<std::wstring> conflicts;    // Conflicting signatures
                
                // Target information
                std::vector<std::wstring> targetFileTypes; // .exe, .dll, .pdf, etc.
                std::vector<std::wstring> targetPlatforms; // Windows, Linux, Android, etc.
                uint64_t minFileSize = 0;
                uint64_t maxFileSize = UINT64_MAX;
                
                // YARA specific
                std::wstring yaraNamespace;
                bool yaraPrivate = false;
                bool yaraGlobal = false;
                std::unordered_map<std::wstring, std::wstring> yaraMeta;
                
                // Hash specific
                std::wstring hashAlgorithm;         // "MD5", "SHA256", "SSDeep", etc.
                
                // Whitelisting
                bool canBeWhitelisted = true;
                std::vector<std::wstring> whitelist; // Specific hashes/paths to whitelist
                
                // Update tracking
                std::wstring updateSource;          // Cloud URL or feed
                std::wstring updateId;              // Unique update identifier
                std::chrono::system_clock::time_point lastUpdateCheck;
                
                // Custom metadata
                std::unordered_map<std::wstring, std::wstring> customData;
            };

            // ============================================================================
            // Configuration
            // ============================================================================

            struct Config {
                std::wstring dbPath = L"C:\\ProgramData\\ShadowStrike\\signatures.db";
                std::wstring signatureCachePath = L"C:\\ProgramData\\ShadowStrike\\SignatureCache";
                
                // Database settings
                bool enableWAL = true;
                size_t dbCacheSizeKB = 51200;       // 50MB for large signature sets
                size_t maxConnections = 10;
                
                // YARA settings
                bool enableYaraCompilation = true;
                bool enableYaraFastMatch = true;
                size_t yaraTimeout = 60000;         // 60 seconds
                size_t yaraMaxMatchData = 1024 * 1024; // 1MB
                bool yaraEnableMulticore = true;
                size_t yaraThreads = 0;             // 0 = auto-detect
                
                // Signature loading
                bool loadOnStartup = true;
                bool loadActiveOnly = true;
                bool enableIncrementalLoading = true;
                size_t maxSignaturesInMemory = 100000;
                
                // Update settings
                bool enableAutoUpdate = true;
                std::chrono::hours updateCheckInterval = std::chrono::hours(4);
                std::wstring updateServer = L"https://signatures.shadowstrike.local";
                bool allowCommunitySignatures = false;
                bool requireSignatureVerification = true;
                
                // Performance settings
                bool enableCaching = true;
                size_t compiledCacheSize = 500;     // Number of compiled rules to cache
                bool enableParallelMatching = true;
                size_t matchThreads = 0;            // 0 = auto-detect
                
                // Statistics
                bool enableStatistics = true;
                bool trackEffectiveness = true;
                bool trackPerformance = true;
                
                // Maintenance
                bool enableAutoCleanup = true;
                std::chrono::hours deprecatedSignatureRetention = std::chrono::hours(24 * 365); // 1 year
                size_t maxSignatureVersions = 10;
                
                // Security
                bool requireAdminForCustomSignatures = true;
                bool enableSignatureValidation = true;
                bool enableSandboxTesting = false;
            };

            struct QueryFilter {
                std::optional<SignatureType> type;
                std::optional<SignatureSeverity> minSeverity;
                std::optional<SignatureSeverity> maxSeverity;
                std::optional<SignatureCategory> category;
                std::optional<SignatureStatus> status;
                std::optional<SignatureSource> source;
                
                std::optional<std::wstring> namePattern;
                std::optional<std::wstring> tagFilter;          // Comma-separated tags
                std::optional<std::wstring> authorPattern;
                
                std::optional<std::chrono::system_clock::time_point> createdAfter;
                std::optional<std::chrono::system_clock::time_point> createdBefore;
                std::optional<std::chrono::system_clock::time_point> modifiedAfter;
                
                std::optional<uint64_t> minDetectionCount;
                std::optional<double> minEffectiveness;
                
                std::vector<std::wstring> targetFileTypes;
                std::vector<std::wstring> targetPlatforms;
                
                size_t maxResults = 1000;
                bool sortByEffectiveness = false;
                bool sortByDetectionCount = false;
                bool sortDescending = true;
            };

            struct MatchResult {
                int64_t signatureId = 0;
                std::wstring signatureName;
                SignatureType signatureType;
                SignatureSeverity severity;
                SignatureCategory category;

                std::wstring matchedPattern;
                size_t matchOffset = 0;             // Offset in file where match occurred
                size_t matchLength = 0;
                std::vector<uint8_t> matchedData;   // Actual matched bytes

                // YARA specific
                std::vector<std::wstring> matchedStrings;
                std::unordered_map<std::wstring, std::wstring> metaTags;

                // Timing
                std::chrono::milliseconds matchDuration;
                std::chrono::system_clock::time_point matchTimestamp;

                // Confidence
                double confidence = 1.0;            // 0.0 - 1.0
                bool isPotentialFalsePositive = false;
            };

            struct Statistics {
                // Signature counts
                uint64_t totalSignatures = 0;
                uint64_t activeSignatures = 0;
                uint64_t disabledSignatures = 0;
                uint64_t deprecatedSignatures = 0;
                
                uint64_t signaturesByType[256] = {};
                uint64_t signaturesByCategory[256] = {};
                uint64_t signaturesBySeverity[5] = {};
                
                // YARA specific
                uint64_t totalYaraRules = 0;
                uint64_t compiledYaraRules = 0;
                uint64_t failedYaraCompilations = 0;
                size_t yaraRulesMemoryUsage = 0;
                
                // Detection statistics
                uint64_t totalDetections = 0;
                uint64_t detectionsLast24h = 0;
                uint64_t detectionsLast7d = 0;
                uint64_t detectionsLast30d = 0;
                
                // Performance metrics
                uint64_t totalMatches = 0;
                uint64_t totalMatchTime = 0;
                double avgMatchTimeMs = 0.0;
                double maxMatchTimeMs = 0.0;
                
                // Update statistics
                std::chrono::system_clock::time_point lastUpdate;
                uint64_t updateCount = 0;
                uint64_t failedUpdates = 0;
                
                // Effectiveness
                double overallEffectiveness = 0.0;
                uint64_t falsePositiveCount = 0;
                double falsePositiveRate = 0.0;
                
                // Database statistics
                size_t dbSizeBytes = 0;
                size_t cacheSizeBytes = 0;
                
                // Timing
                std::chrono::system_clock::time_point oldestSignature;
                std::chrono::system_clock::time_point newestSignature;
                std::chrono::system_clock::time_point lastCleanup;
            };

            // ============================================================================
            // Lifecycle
            // ============================================================================

            static SignatureDB& Instance();

            bool Initialize(const Config& config, DatabaseError* err = nullptr);
            void Shutdown();
            bool IsInitialized() const noexcept { return m_initialized.load(); }

            // ============================================================================
            // Signature Management Operations
            // ============================================================================

            // Add new signature
            int64_t AddSignature(const SignatureEntry& signature, DatabaseError* err = nullptr);
            
            // Add YARA rule
            int64_t AddYaraRule(std::wstring_view ruleName,
                               std::wstring_view ruleSource,
                               SignatureSeverity severity,
                               SignatureCategory category,
                               std::wstring_view author = L"",
                               DatabaseError* err = nullptr);

            // Add hash signature
            int64_t AddHashSignature(std::wstring_view hashValue,
                                    std::wstring_view hashAlgorithm,
                                    std::wstring_view threatName,
                                    SignatureSeverity severity,
                                    DatabaseError* err = nullptr);

            // Update signature
            bool UpdateSignature(const SignatureEntry& signature, DatabaseError* err = nullptr);
            
            // Update signature status
            bool SetSignatureStatus(int64_t signatureId,
                                   SignatureStatus status,
                                   DatabaseError* err = nullptr);

            // Delete signature
            bool DeleteSignature(int64_t signatureId, DatabaseError* err = nullptr);
            
            // Batch operations
            bool AddBatch(const std::vector<SignatureEntry>& signatures, DatabaseError* err = nullptr);
            bool UpdateBatch(const std::vector<SignatureEntry>& signatures, DatabaseError* err = nullptr);
            bool DeleteBatch(const std::vector<int64_t>& signatureIds, DatabaseError* err = nullptr);

            // ============================================================================
            // Query Operations
            // ============================================================================

            // Get signature by ID
            std::optional<SignatureEntry> GetSignature(int64_t id, DatabaseError* err = nullptr);
            
            // Get signature by name
            std::optional<SignatureEntry> GetSignatureByName(std::wstring_view name,
                                                            DatabaseError* err = nullptr);

            // Query with filters
            std::vector<SignatureEntry> Query(const QueryFilter& filter,
                                             DatabaseError* err = nullptr);

            // Get by type
            std::vector<SignatureEntry> GetByType(SignatureType type,
                                                 size_t maxCount = 1000,
                                                 DatabaseError* err = nullptr);

            // Get by category
            std::vector<SignatureEntry> GetByCategory(SignatureCategory category,
                                                     size_t maxCount = 1000,
                                                     DatabaseError* err = nullptr);

            // Get active signatures
            std::vector<SignatureEntry> GetActiveSignatures(SignatureType type = SignatureType::Unknown,
                                                           DatabaseError* err = nullptr);

            // Get top detectors
            std::vector<SignatureEntry> GetTopDetectors(size_t count = 100,
                                                       DatabaseError* err = nullptr);

            // Search by tags
            std::vector<SignatureEntry> SearchByTags(const std::vector<std::wstring>& tags,
                                                    bool matchAll = false,
                                                    DatabaseError* err = nullptr);

            // Count signatures
            int64_t CountSignatures(const QueryFilter* filter = nullptr,
                                   DatabaseError* err = nullptr);

            // ============================================================================
            // YARA Operations
            // ============================================================================

            // Compile YARA rule
            bool CompileYaraRule(int64_t signatureId, DatabaseError* err = nullptr);
            bool CompileAllYaraRules(DatabaseError* err = nullptr);
            
            // Validate YARA syntax
            bool ValidateYaraRule(std::wstring_view ruleSource,
                                 std::wstring& errorMessage,
                                 DatabaseError* err = nullptr);

            // Load compiled YARA rules into memory
            bool LoadYaraRules(DatabaseError* err = nullptr);
            bool UnloadYaraRules();
            
            // Get YARA compiler instance
            YR_COMPILER* GetYaraCompiler(DatabaseError* err = nullptr);
            YR_RULES* GetCompiledYaraRules() const noexcept { return m_yaraRules; }

            // ============================================================================
            // Detection/Matching Operations
            // ============================================================================

            // Match file against all signatures
            std::vector<MatchResult> MatchFile(std::wstring_view filePath,
                                              DatabaseError* err = nullptr);

            // Match data buffer
            std::vector<MatchResult> MatchData(const uint8_t* data,
                                              size_t size,
                                              std::wstring_view identifier = L"",
                                              DatabaseError* err = nullptr);

            // Match specific signature type
            std::vector<MatchResult> MatchWithType(const uint8_t* data,
                                                  size_t size,
                                                  SignatureType type,
                                                  DatabaseError* err = nullptr);

            // Quick hash check
            bool IsKnownMalwareHash(std::wstring_view hash,
                                   std::wstring_view algorithm = L"SHA256",
                                   DatabaseError* err = nullptr);

            // Batch matching
            std::unordered_map<std::wstring, std::vector<MatchResult>> MatchBatch(
                const std::vector<std::wstring>& filePaths,
                DatabaseError* err = nullptr);

            // ============================================================================
            // Update Operations
            // ============================================================================

            // Check for updates
            bool CheckForUpdates(DatabaseError* err = nullptr);
            
            // Download and apply updates
            bool DownloadUpdates(std::wstring_view updateSource,
                                DatabaseError* err = nullptr);

            // Import signatures from file
            bool ImportSignatures(std::wstring_view filePath,
                                 bool overwriteExisting = false,
                                 DatabaseError* err = nullptr);

            // Export signatures to file
            bool ExportSignatures(std::wstring_view filePath,
                                 const QueryFilter* filter = nullptr,
                                 DatabaseError* err = nullptr);

            // ============================================================================
            // Statistics & Reporting
            // ============================================================================

            Statistics GetStatistics(DatabaseError* err = nullptr);
            void ResetStatistics();

            // Record detection
            void RecordDetection(int64_t signatureId,
                                std::wstring_view filePath,
                                const MatchResult& result);

            // Record false positive
            void RecordFalsePositive(int64_t signatureId,
                                    std::wstring_view filePath,
                                    std::wstring_view reason = L"");

            // Get signature effectiveness report
            std::wstring GetEffectivenessReport(int64_t signatureId);

            // Get detection history
            struct DetectionRecord {
                int64_t id;
                int64_t signatureId;
                std::wstring signatureName;
                std::wstring filePath;
                std::wstring fileHash;
                std::chrono::system_clock::time_point timestamp;
                bool wasFalsePositive;
            };

            std::vector<DetectionRecord> GetDetectionHistory(
                int64_t signatureId,
                std::optional<std::chrono::system_clock::time_point> since = std::nullopt,
                size_t maxCount = 1000,
                DatabaseError* err = nullptr);

            // ============================================================================
            // Configuration & Maintenance
            // ============================================================================

            Config GetConfig() const;
            void SetConfig(const Config& config);

            // Maintenance operations
            bool Vacuum(DatabaseError* err = nullptr);
            bool CheckIntegrity(DatabaseError* err = nullptr);
            bool Optimize(DatabaseError* err = nullptr);
            bool RebuildIndices(DatabaseError* err = nullptr);
            
            // Cleanup old/deprecated signatures
            bool CleanupDeprecated(DatabaseError* err = nullptr);
            bool CleanupOldVersions(DatabaseError* err = nullptr);

            // ============================================================================
            // Utility Functions
            // ============================================================================

            static std::wstring SignatureTypeToString(SignatureType type);
            static SignatureType StringToSignatureType(std::wstring_view str);

            static std::wstring SignatureSeverityToString(SignatureSeverity severity);
            static SignatureSeverity StringToSignatureSeverity(std::wstring_view str);

            static std::wstring SignatureCategoryToString(SignatureCategory category);
            static SignatureCategory StringToSignatureCategory(std::wstring_view str);

            static std::wstring SignatureStatusToString(SignatureStatus status);
            static SignatureStatus StringToSignatureStatus(std::wstring_view str);

            static std::wstring SignatureSourceToString(SignatureSource source);

        private:
            SignatureDB();
            ~SignatureDB();

            SignatureDB(const SignatureDB&) = delete;
            SignatureDB& operator=(const SignatureDB&) = delete;

            // ============================================================================
            // Internal Operations
            // ============================================================================

            // Schema management
            bool createSchema(DatabaseError* err);
            bool upgradeSchema(int currentVersion, int targetVersion, DatabaseError* err);

            // Database operations
            int64_t dbInsertSignature(const SignatureEntry& entry, DatabaseError* err);
            bool dbUpdateSignature(const SignatureEntry& entry, DatabaseError* err);
            bool dbDeleteSignature(int64_t id, DatabaseError* err);
            std::optional<SignatureEntry> dbSelectSignature(int64_t id, DatabaseError* err);
            std::vector<SignatureEntry> dbSelectSignatures(std::string_view sql,
                                                          const std::vector<std::string>& params,
                                                          DatabaseError* err);

            // Query builders
            std::string buildQuerySQL(const QueryFilter& filter, std::vector<std::string>& outParams);
            std::string buildCountSQL(const QueryFilter& filter, std::vector<std::string>& outParams);

            // YARA internals
            bool compileYaraRuleInternal(const SignatureEntry& entry, DatabaseError* err);
            static void yaraCompilerCallback(int errorLevel,
                                            const char* fileName,
                                            int lineNumber,
                                            const YR_RULE* rule,
                                            const char* message,
                                            void* userData);

            int yaraMatchCallback(YR_SCAN_CONTEXT* context,
                                 int message,
                                 void* messageData,
                                 void* userData);

            // Matching engines
            std::vector<MatchResult> matchYaraRules(const uint8_t* data,
                                                   size_t size,
                                                   std::wstring_view identifier,
                                                   DatabaseError* err);

            std::vector<MatchResult> matchHashSignatures(const uint8_t* data,
                                                        size_t size,
                                                        DatabaseError* err);

            std::vector<MatchResult> matchPatternSignatures(const uint8_t* data,
                                                           size_t size,
                                                           DatabaseError* err);

            // Hash calculation
            std::wstring calculateFileHash(std::wstring_view filePath,
                                          std::wstring_view algorithm);
            std::wstring calculateDataHash(const uint8_t* data,
                                          size_t size,
                                          std::wstring_view algorithm);

            // Cache management
            bool cacheCompiledRule(int64_t signatureId, const std::vector<uint8_t>& compiledData);
            std::optional<std::vector<uint8_t>> getCachedCompiledRule(int64_t signatureId);
            void evictCacheEntry(int64_t signatureId);

            // Update thread
            void updateThread();

            // Statistics helpers
            void updateStatistics(const SignatureEntry& entry);
            void recalculateStatistics(DatabaseError* err);
            void recordMatch(int64_t signatureId, std::chrono::milliseconds duration);

            // Utility helpers
            SignatureEntry rowToSignatureEntry(QueryResult& result);
            static std::string timePointToString(std::chrono::system_clock::time_point tp);
            static std::chrono::system_clock::time_point stringToTimePoint(std::string_view str);

            std::vector<std::wstring> parseTagString(std::string_view tagStr);
            std::string serializeTagVector(const std::vector<std::wstring>& tags);

            // ============================================================================
            // State
            // ============================================================================

            std::atomic<bool> m_initialized{ false };
            Config m_config;
            mutable std::shared_mutex m_configMutex;

            // YARA state
            YR_COMPILER* m_yaraCompiler = nullptr;
            YR_RULES* m_yaraRules = nullptr;
            mutable std::shared_mutex m_yaraMutex;
            std::unordered_map<int64_t, YR_RULE*> m_yaraRuleMap;

            // Hash signature cache (for fast lookup)
            mutable std::shared_mutex m_hashCacheMutex;
            std::unordered_map<std::wstring, std::vector<int64_t>> m_hashSignatureMap;

            // Compiled rule cache
            struct CacheEntry {
                std::vector<uint8_t> compiledData;
                std::chrono::steady_clock::time_point lastAccessed;
                size_t accessCount = 0;
            };
            mutable std::mutex m_cacheMutex;
            std::unordered_map<int64_t, CacheEntry> m_compiledCache;

            // Update thread
            std::thread m_updateThread;
            std::atomic<bool> m_shutdownUpdate{ false };
            std::condition_variable m_updateCV;
            std::mutex m_updateMutex;
            std::chrono::steady_clock::time_point m_lastUpdateCheck;

            // Statistics
            mutable std::mutex m_statsMutex;
            Statistics m_stats;

            // Performance tracking
            struct PerformanceMetrics {
                std::atomic<uint64_t> totalMatches{ 0 };
                std::atomic<uint64_t> totalMatchTime{ 0 };
                std::atomic<uint64_t> yaraMatches{ 0 };
                std::atomic<uint64_t> hashMatches{ 0 };
                std::atomic<uint64_t> patternMatches{ 0 };
            };
            PerformanceMetrics m_metrics;
        };

    } // namespace Database
} // namespace ShadowStrike