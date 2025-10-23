#pragma once

#include "DatabaseManager.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/CryptoUtils.hpp"
// NetworkUtils.hpp removed to avoid winsock header conflicts

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
        // ThreatIntelDB - Global Threat Intelligence Management System
        // ============================================================================

        /**
         * @brief Enterprise-grade threat intelligence database for real-time threat detection.
         * 
         * Features:
         * - Global threat intelligence aggregation (IoC, signatures, behaviors)
         * - Multi-source threat feed integration (CrowdStrike Falcon, VirusTotal, MISP, etc.)
         * - Real-time threat scoring and risk assessment
         * - Advanced IoC (Indicator of Compromise) management
         * - TTPs (Tactics, Techniques, Procedures) tracking via MITRE ATT&CK
         * - Threat actor profiling and attribution
         * - Automated threat correlation and clustering
         * - Reputation scoring (IP, domain, file hash, URL)
         * - Threat feed synchronization with cloud services
         * - False positive management and whitelisting
         * - Comprehensive threat analytics and reporting
         * - Thread-safe concurrent access
         */
        class ThreatIntelDB {
        public:
            // ============================================================================
            // Types & Enumerations
            // ============================================================================

            enum class ThreatType : uint8_t {
                Unknown = 0,
                Malware = 1,
                Ransomware = 2,
                Trojan = 3,
                Virus = 4,
                Worm = 5,
                Rootkit = 6,
                Backdoor = 7,
                Spyware = 8,
                Adware = 9,
                PUA = 10,              // Potentially Unwanted Application
                Exploit = 11,
                Phishing = 12,
                C2Server = 13,         // Command & Control
                Botnet = 14,
                APT = 15,              // Advanced Persistent Threat
                Cryptominer = 16,
                Keylogger = 17,
                Infostealer = 18,
                Webshell = 19,
                Custom = 255
            };

            enum class ThreatSeverity : uint8_t {
                Info = 0,
                Low = 1,
                Medium = 2,
                High = 3,
                Critical = 4,
                Emergency = 5
            };

            enum class IoC_Type : uint8_t {
                FileHash_MD5 = 0,
                FileHash_SHA1 = 1,
                FileHash_SHA256 = 2,
                FileHash_SHA512 = 3,
                IP_Address = 4,
                Domain = 5,
                URL = 6,
                Email = 7,
                Mutex = 8,
                RegistryKey = 9,
                FilePath = 10,
                FileName = 11,
                Certificate = 12,
                UserAgent = 13,
                JA3_Fingerprint = 14,
                YARA_Rule = 15,
                CVE = 16,
                ASN = 17,
                MAC_Address = 18,
                Custom = 255
            };

            enum class ThreatSource : uint8_t {
                Internal = 0,          // Internal detection/analysis
                CrowdStrike = 1,
                VirusTotal = 2,
                MISP = 3,
                AlienVault_OTX = 4,
                ThreatConnect = 5,
                Anomali = 6,
                OpenCTI = 7,
                MalwareBazaar = 8,
                AbuseIPDB = 9,
                URLhaus = 10,
                PhishTank = 11,
                Shodan = 12,
                GreyNoise = 13,
                ThreatFox = 14,
                Community = 15,
                Partner = 16,
                Commercial = 17,
                OSINT = 18,
                Custom = 255
            };

            enum class ThreatConfidence : uint8_t {
                Unverified = 0,
                Low = 1,
                Medium = 2,
                High = 3,
                Confirmed = 4
            };

            enum class TTPPhase : uint8_t {
                Reconnaissance = 0,
                ResourceDevelopment = 1,
                InitialAccess = 2,
                Execution = 3,
                Persistence = 4,
                PrivilegeEscalation = 5,
                DefenseEvasion = 6,
                CredentialAccess = 7,
                Discovery = 8,
                LateralMovement = 9,
                Collection = 10,
                CommandAndControl = 11,
                Exfiltration = 12,
                Impact = 13
            };

            // ============================================================================
            // Core Data Structures
            // ============================================================================

            struct IoC_Entry {
                int64_t id = 0;
                IoC_Type type;
                std::wstring value;
                ThreatType threatType;
                ThreatSeverity severity;
                ThreatConfidence confidence;
                ThreatSource source;
                
                std::wstring threatName;
                std::wstring description;
                std::vector<std::wstring> tags;
                std::vector<std::wstring> aliases;
                
                std::chrono::system_clock::time_point firstSeen;
                std::chrono::system_clock::time_point lastSeen;
                std::chrono::system_clock::time_point expiresAt;
                
                uint64_t hitCount = 0;
                bool isActive = true;
                bool isFalsePositive = false;
                
                std::wstring referenceUrl;
                std::wstring sourceId;
                std::wstring campaign;
                std::wstring threatActor;
                
                // Metadata
                std::unordered_map<std::wstring, std::wstring> metadata;
                int riskScore = 0;              // 0-100
                std::wstring geolocation;       // Country code
                
                std::chrono::system_clock::time_point createdAt;
                std::chrono::system_clock::time_point updatedAt;
            };

            struct ThreatSignature {
                int64_t id = 0;
                std::wstring name;
                ThreatType type;
                ThreatSeverity severity;
                
                std::wstring yaraRule;
                std::wstring clamavSignature;
                std::vector<uint8_t> binaryPattern;
                std::wstring regexPattern;
                
                std::wstring author;
                std::wstring description;
                std::vector<std::wstring> references;
                std::vector<std::wstring> platforms;    // Windows, Linux, macOS
                
                bool isEnabled = true;
                uint64_t detectionCount = 0;
                uint64_t falsePositiveCount = 0;
                double accuracy = 0.0;
                
                std::chrono::system_clock::time_point createdAt;
                std::chrono::system_clock::time_point updatedAt;
                std::chrono::system_clock::time_point lastDetection;
            };

            struct TTP_Entry {
                int64_t id = 0;
                std::wstring mitreId;           // T1055.001 format
                std::wstring name;
                TTPPhase phase;
                
                std::wstring description;
                std::vector<std::wstring> tactics;
                std::vector<std::wstring> techniques;
                std::vector<std::wstring> subTechniques;
                
                std::vector<std::wstring> detectionMethods;
                std::vector<std::wstring> mitigations;
                std::vector<std::wstring> relatedThreats;
                
                ThreatSeverity severity;
                uint64_t observedCount = 0;
                
                std::chrono::system_clock::time_point createdAt;
                std::chrono::system_clock::time_point lastObserved;
            };

            struct ThreatActor {
                int64_t id = 0;
                std::wstring name;
                std::vector<std::wstring> aliases;
                
                std::wstring description;
                std::wstring motivation;        // Financial, Espionage, Hacktivism
                std::wstring origin;            // Country/Region
                std::vector<std::wstring> targetSectors;
                std::vector<std::wstring> targetCountries;
                
                std::vector<std::wstring> ttps;
                std::vector<std::wstring> malwareFamilies;
                std::vector<std::wstring> campaigns;
                
                ThreatSeverity threatLevel;
                bool isAPT = false;
                bool isActive = true;
                
                std::chrono::system_clock::time_point firstSeen;
                std::chrono::system_clock::time_point lastActivity;
                std::chrono::system_clock::time_point createdAt;
            };

            struct ThreatCampaign {
                int64_t id = 0;
                std::wstring name;
                std::wstring description;
                
                std::vector<std::wstring> threatActors;
                std::vector<int64_t> relatedIoCs;
                std::vector<std::wstring> ttps;
                
                ThreatType primaryType;
                ThreatSeverity severity;
                
                std::chrono::system_clock::time_point startDate;
                std::chrono::system_clock::time_point endDate;
                bool isActive = true;
                
                std::vector<std::wstring> affectedRegions;
                std::vector<std::wstring> targetedSectors;
                
                std::wstring objective;
                std::wstring attribution;
                uint64_t victimCount = 0;
                
                std::chrono::system_clock::time_point createdAt;
                std::chrono::system_clock::time_point updatedAt;
            };

            struct ReputationScore {
                std::wstring identifier;       // IP, domain, hash, etc.
                IoC_Type identifierType;
                
                int score = 50;                 // 0 (malicious) - 100 (benign)
                ThreatSeverity threatLevel;
                
                uint64_t positiveReports = 0;
                uint64_t negativeReports = 0;
                uint64_t totalReports = 0;
                
                std::vector<ThreatSource> sources;
                std::chrono::system_clock::time_point lastUpdated;
                std::chrono::system_clock::time_point expiresAt;
                
                bool isWhitelisted = false;
                bool isBlacklisted = false;
                std::wstring notes;
            };

            // ============================================================================
            // Configuration
            // ============================================================================

            struct Config {
                std::wstring dbPath = L"C:\\ProgramData\\ShadowStrike\\threat_intel.db";
                
                // Database settings
                bool enableWAL = true;
                size_t dbCacheSizeKB = 51200;   // 50MB
                size_t maxConnections = 10;
                
                // Cache settings
                bool enableCaching = true;
                size_t maxCacheEntries = 100000;
                std::chrono::milliseconds cacheRefreshInterval = std::chrono::minutes(15);
                
                // IoC management
                std::chrono::hours iocDefaultTTL = std::chrono::hours(24 * 30);  // 30 days
                std::chrono::hours iocExpiredCleanup = std::chrono::hours(24);   // Daily cleanup
                bool autoExpireIoCs = true;
                
                // Threat feed sync
                bool enableFeedSync = true;
                std::chrono::minutes feedSyncInterval = std::chrono::minutes(30);
                std::vector<ThreatSource> enabledSources;
                size_t maxFeedEntriesPerSource = 100000;
                
                // Reputation system
                bool enableReputationScoring = true;
                int defaultReputationScore = 50;
                std::chrono::hours reputationExpiry = std::chrono::hours(24 * 7);  // 7 days
                
                // Performance
                size_t batchOperationSize = 1000;
                bool enableAsyncProcessing = true;
                
                // Security
                bool requireApiAuthentication = true;
                std::wstring apiKey;
                bool enableRateLimiting = true;
                
                // Statistics
                bool enableStatistics = true;
                bool trackHitCounts = true;
            };

            struct QueryFilter {
                std::optional<ThreatType> threatType;
                std::optional<ThreatSeverity> minSeverity;
                std::optional<IoC_Type> iocType;
                std::optional<ThreatSource> source;
                std::optional<ThreatConfidence> minConfidence;
                
                std::optional<std::chrono::system_clock::time_point> firstSeenAfter;
                std::optional<std::chrono::system_clock::time_point> firstSeenBefore;
                std::optional<std::chrono::system_clock::time_point> lastSeenAfter;
                
                std::optional<std::wstring> campaignName;
                std::optional<std::wstring> threatActor;
                std::optional<std::wstring> tagPattern;
                
                bool activeOnly = true;
                bool excludeFalsePositives = true;
                
                size_t maxResults = 1000;
                bool sortByRiskScore = false;
                bool sortDescending = true;
            };

            struct Statistics {
                uint64_t totalIoCs = 0;
                uint64_t activeIoCs = 0;
                uint64_t expiredIoCs = 0;
                uint64_t falsePositives = 0;
                
                uint64_t iocsByType[256] = {};
                uint64_t iocsBySeverity[6] = {};
                uint64_t iocsBySource[256] = {};
                
                uint64_t totalSignatures = 0;
                uint64_t enabledSignatures = 0;
                double avgSignatureAccuracy = 0.0;
                
                uint64_t totalTTPs = 0;
                uint64_t totalThreatActors = 0;
                uint64_t activeCampaigns = 0;
                
                uint64_t totalQueries = 0;
                uint64_t cacheHits = 0;
                uint64_t cacheMisses = 0;
                double cacheHitRate = 0.0;
                
                uint64_t feedSyncCount = 0;
                std::chrono::system_clock::time_point lastFeedSync;
                uint64_t failedSyncCount = 0;
                
				uint64_t lookupCount = 0;
				uint64_t totalItemsretrieved = 0;
				std::chrono::system_clock::time_point lastlookuptime;

                size_t dbSizeBytes = 0;
                std::chrono::system_clock::time_point oldestIoC;
                std::chrono::system_clock::time_point newestIoC;
            };

            // ============================================================================
            // Lifecycle
            // ============================================================================

            static ThreatIntelDB& Instance();

            bool Initialize(const Config& config, DatabaseError* err = nullptr);
            void Shutdown();
            bool IsInitialized() const noexcept { return m_initialized.load(); }

            // ============================================================================
            // IoC Management
            // ============================================================================

            // Add/Update IoC
            int64_t AddIoC(const IoC_Entry& ioc, DatabaseError* err = nullptr);
            bool UpdateIoC(const IoC_Entry& ioc, DatabaseError* err = nullptr);
            bool RemoveIoC(int64_t iocId, DatabaseError* err = nullptr);
            
            // Batch operations
            bool AddIoCBatch(const std::vector<IoC_Entry>& iocs, DatabaseError* err = nullptr);
            bool RemoveIoCBatch(const std::vector<int64_t>& iocIds, DatabaseError* err = nullptr);
            
            // Query IoCs
            std::optional<IoC_Entry> GetIoC(int64_t iocId, DatabaseError* err = nullptr);
            std::vector<IoC_Entry> QueryIoCs(const QueryFilter& filter, DatabaseError* err = nullptr);
            
            // Specific lookups
            std::optional<IoC_Entry> LookupByHash(std::wstring_view hash, DatabaseError* err = nullptr);
            std::optional<IoC_Entry> LookupByIP(std::wstring_view ip, DatabaseError* err = nullptr);
            std::optional<IoC_Entry> LookupByDomain(std::wstring_view domain, DatabaseError* err = nullptr);
            std::optional<IoC_Entry> LookupByValue(std::wstring_view value, 
                                                   IoC_Type type, 
                                                   DatabaseError* err = nullptr);
            
            // Bulk lookups
            std::vector<IoC_Entry> LookupHashesBatch(const std::vector<std::wstring>& hashes,
                                                     DatabaseError* err = nullptr);
            std::vector<IoC_Entry> LookupIPsBatch(const std::vector<std::wstring>& ips,
                                                  DatabaseError* err = nullptr);
            
            // IoC enrichment
            bool EnrichIoC(int64_t iocId, 
                          const std::unordered_map<std::wstring, std::wstring>& metadata,
                          DatabaseError* err = nullptr);
            
            // Expiration management
            bool MarkExpired(int64_t iocId, DatabaseError* err = nullptr);
            bool CleanupExpiredIoCs(DatabaseError* err = nullptr);
            bool ExtendExpiration(int64_t iocId, std::chrono::hours extension, DatabaseError* err = nullptr);
            
            // False positive management
            bool MarkFalsePositive(int64_t iocId, bool isFP, std::wstring_view reason = L"", 
                                  DatabaseError* err = nullptr);
            std::vector<IoC_Entry> GetFalsePositives(size_t maxCount = 100, DatabaseError* err = nullptr);

            // ============================================================================
            // Threat Signatures
            // ============================================================================

            int64_t AddSignature(const ThreatSignature& signature, DatabaseError* err = nullptr);
            bool UpdateSignature(const ThreatSignature& signature, DatabaseError* err = nullptr);
            bool RemoveSignature(int64_t signatureId, DatabaseError* err = nullptr);
            
            std::optional<ThreatSignature> GetSignature(int64_t signatureId, DatabaseError* err = nullptr);
            std::vector<ThreatSignature> GetSignaturesByType(ThreatType type, 
                                                            size_t maxCount = 1000,
                                                            DatabaseError* err = nullptr);
            std::vector<ThreatSignature> GetEnabledSignatures(DatabaseError* err = nullptr);
            
            bool EnableSignature(int64_t signatureId, bool enabled, DatabaseError* err = nullptr);
            bool UpdateSignatureAccuracy(int64_t signatureId, double accuracy, DatabaseError* err = nullptr);

            // ============================================================================
            // TTPs (MITRE ATT&CK)
            // ============================================================================

            int64_t AddTTP(const TTP_Entry& ttp, DatabaseError* err = nullptr);
            bool UpdateTTP(const TTP_Entry& ttp, DatabaseError* err = nullptr);
            bool RemoveTTP(int64_t ttpId, DatabaseError* err = nullptr);
            
            std::optional<TTP_Entry> GetTTP(int64_t ttpId, DatabaseError* err = nullptr);
            std::optional<TTP_Entry> GetTTPByMitreId(std::wstring_view mitreId, DatabaseError* err = nullptr);
            
            std::vector<TTP_Entry> GetTTPsByPhase(TTPPhase phase, DatabaseError* err = nullptr);
            std::vector<TTP_Entry> GetTTPsByThreat(std::wstring_view threatName, DatabaseError* err = nullptr);
            
            bool IncrementTTPObservation(int64_t ttpId, DatabaseError* err = nullptr);

            void loadTTPRelatedData(TTP_Entry& ttp, DatabaseError* err = nullptr);

            // ============================================================================
            // Threat Actors
            // ============================================================================

            int64_t AddThreatActor(const ThreatActor& actor, DatabaseError* err = nullptr);
            bool UpdateThreatActor(const ThreatActor& actor, DatabaseError* err = nullptr);
            bool RemoveThreatActor(int64_t actorId, DatabaseError* err = nullptr);
            
            std::optional<ThreatActor> GetThreatActor(int64_t actorId, DatabaseError* err = nullptr);
            std::optional<ThreatActor> GetThreatActorByName(std::wstring_view name, DatabaseError* err = nullptr);
            
            std::vector<ThreatActor> GetActiveThreatActors(DatabaseError* err = nullptr);
            std::vector<ThreatActor> GetAPTGroups(DatabaseError* err = nullptr);

            // ============================================================================
            // Campaigns
            // ============================================================================

            int64_t AddCampaign(const ThreatCampaign& campaign, DatabaseError* err = nullptr);
            bool UpdateCampaign(const ThreatCampaign& campaign, DatabaseError* err = nullptr);
            bool RemoveCampaign(int64_t campaignId, DatabaseError* err = nullptr);
            
            std::optional<ThreatCampaign> GetCampaign(int64_t campaignId, DatabaseError* err = nullptr);
            std::vector<ThreatCampaign> GetActiveCampaigns(DatabaseError* err = nullptr);
            std::vector<ThreatCampaign> GetCampaignsByActor(std::wstring_view actorName, 
                                                           DatabaseError* err = nullptr);

            // ============================================================================
            // Reputation System
            // ============================================================================

            int GetReputationScore(std::wstring_view identifier, IoC_Type type, 
                                  DatabaseError* err = nullptr);
            bool UpdateReputationScore(const ReputationScore& score, DatabaseError* err = nullptr);
            
            bool AddPositiveReport(std::wstring_view identifier, IoC_Type type, 
                                  ThreatSource source, DatabaseError* err = nullptr);
            bool AddNegativeReport(std::wstring_view identifier, IoC_Type type,
                                  ThreatSource source, DatabaseError* err = nullptr);
            
            bool SetWhitelisted(std::wstring_view identifier, IoC_Type type, bool whitelisted,
                               std::wstring_view reason = L"", DatabaseError* err = nullptr);
            bool SetBlacklisted(std::wstring_view identifier, IoC_Type type, bool blacklisted,
                               std::wstring_view reason = L"", DatabaseError* err = nullptr);
            
            bool IsWhitelisted(std::wstring_view identifier, IoC_Type type);
            bool IsBlacklisted(std::wstring_view identifier, IoC_Type type);

            double getSourceReliability(ThreatSource source) const noexcept;
            void loadActorAliases(ThreatActor& actor);
            void loadActorTargeting(ThreatActor& actor);
            void loadActorTTPAssociations(ThreatActor& actor);
            void loadActorCampaignAssociations(ThreatActor& actor);
            // ============================================================================
            // Threat Feed Integration
            // ============================================================================

            bool SyncThreatFeeds(DatabaseError* err = nullptr);
            bool SyncThreatFeed(ThreatSource source, DatabaseError* err = nullptr);
            
            uint64_t GetLastSyncTimestamp(ThreatSource source);
            bool SetLastSyncTimestamp(ThreatSource source, uint64_t timestamp);
            
            std::vector<IoC_Entry> GetIoCsBySource(ThreatSource source, 
                                                   size_t maxCount = 1000,
                                                   DatabaseError* err = nullptr);

            // ============================================================================
            // Analytics & Correlation
            // ============================================================================

            // Find related IoCs
            std::vector<IoC_Entry> FindRelatedIoCs(int64_t iocId, size_t maxResults = 50,
                                                  DatabaseError* err = nullptr);
            
            // Cluster IoCs by campaign/actor
            std::unordered_map<std::wstring, std::vector<int64_t>> ClusterIoCsByCampaign(
                const std::vector<int64_t>& iocIds, DatabaseError* err = nullptr);
            
            // Threat timeline analysis
            std::vector<IoC_Entry> GetThreatTimeline(std::chrono::system_clock::time_point start,
                                                     std::chrono::system_clock::time_point end,
                                                     DatabaseError* err = nullptr);
            
            // Top threats by various criteria
            std::vector<IoC_Entry> GetTopThreatsByHitCount(size_t topN = 10, DatabaseError* err = nullptr);
            std::vector<IoC_Entry> GetTopThreatsByRiskScore(size_t topN = 10, DatabaseError* err = nullptr);
            std::vector<std::wstring> GetTopThreatActors(size_t topN = 10, DatabaseError* err = nullptr);

            // ============================================================================
            // Import / Export
            // ============================================================================

            bool ExportIoCsToSTIX(std::wstring_view outputPath, const QueryFilter* filter = nullptr,
                                 DatabaseError* err = nullptr);
            bool ImportIoCsFromSTIX(std::wstring_view inputPath, DatabaseError* err = nullptr);
            
            bool ExportIoCsToJSON(std::wstring_view outputPath, const QueryFilter* filter = nullptr,
                                 DatabaseError* err = nullptr);
            bool ImportIoCsFromJSON(std::wstring_view inputPath, DatabaseError* err = nullptr);
            
            bool ExportToCSV(std::wstring_view outputPath, const QueryFilter* filter = nullptr,
                            DatabaseError* err = nullptr);
            
            bool ExportYaraRules(std::wstring_view outputPath, DatabaseError* err = nullptr);
            bool ImportYaraRules(std::wstring_view inputPath, DatabaseError* err = nullptr);

            // ============================================================================
            // Statistics & Maintenance
            // ============================================================================

            Statistics GetStatistics(DatabaseError* err = nullptr);
            void ResetStatistics();
            
            Config GetConfig() const;
            
            bool Vacuum(DatabaseError* err = nullptr);
            bool CheckIntegrity(DatabaseError* err = nullptr);
            bool Optimize(DatabaseError* err = nullptr);
            bool RebuildIndices(DatabaseError* err = nullptr);
            
            bool BackupDatabase(std::wstring_view backupPath, DatabaseError* err = nullptr);
            bool RestoreDatabase(std::wstring_view backupPath, DatabaseError* err = nullptr);

            // ============================================================================
            // Utility Functions
            // ============================================================================

            static std::wstring ThreatTypeToString(ThreatType type);
            static ThreatType StringToThreatType(std::wstring_view str);
            
            static std::wstring ThreatSeverityToString(ThreatSeverity severity);
            static ThreatSeverity StringToThreatSeverity(std::wstring_view str);
            
            static std::wstring IoC_TypeToString(IoC_Type type);
            static IoC_Type StringToIoC_Type(std::wstring_view str);
            
            static std::wstring ThreatSourceToString(ThreatSource source);
            static ThreatSource StringToThreatSource(std::wstring_view str);
            
            static std::wstring ThreatConfidenceToString(ThreatConfidence confidence);
            static ThreatConfidence StringToThreatConfidence(std::wstring_view str);

            static std::wstring TTPPhaseToString(TTPPhase phase);
            static TTPPhase StringToTTPPhase(std::wstring_view str);

            std::wstring generateUUID() const;
            std::string formatISO8601(std::chrono::system_clock::time_point tp) const;
            std::chrono::system_clock::time_point parseISO8601(const std::string& str) const;
            std::string buildSTIXPattern(const IoC_Entry& ioc) const;
            bool parseSTIXPattern(const std::string& pattern, IoC_Entry& outIoc) const;

        private:

          // ============================================================================
          // Threat Feed Integration
          // ============================================================================
           
            class FeedProvider {
            public:
                virtual ~FeedProvider() = default;

                /**
                 * @brief Feed'den veri indir ve IoC listesi oluþtur
                 * @return Yeni IoC_Entry'lerin listesi
                 */
                virtual std::vector<IoC_Entry> FetchAndParse(DatabaseError* err = nullptr) = 0;

                /**
                 * @brief Provider adý (logging için)
                 */
                virtual std::wstring GetProviderName() const = 0;

                /**
                 * @brief API endpoint
                 */
                virtual std::wstring GetEndpoint() const = 0;
            };

            /**
             * @brief VirusTotal feed provider
             */
            class VirusTotalProvider : public FeedProvider {
            public:
                explicit VirusTotalProvider(std::wstring_view apiKey);
                std::vector<IoC_Entry> FetchAndParse(DatabaseError* err = nullptr) override;
                std::wstring GetProviderName() const override { return L"VirusTotal"; }
                std::wstring GetEndpoint() const override;

            private:
                std::wstring m_apiKey;
                std::wstring m_lastCursor;  // Pagination için

				// dont make HTTP requests directly here, use HttpGet
                bool HttpGet(std::wstring_view url, std::string& outResponse, DatabaseError* err);
            };

            /**
             * @brief Abuse.ch feed provider (malware hashleri)
             */
            class AbuseChProvider : public FeedProvider {
            public:
                std::vector<IoC_Entry> FetchAndParse(DatabaseError* err = nullptr) override;
                std::wstring GetProviderName() const override { return L"Abuse.ch"; }
                std::wstring GetEndpoint() const override;

            private:
                bool HttpGet(std::wstring_view url, std::string& outResponse, DatabaseError* err);
                IoC_Entry ParseMalwareHashEntry(const std::string& line);
            };

            /**
             * @brief AlienVault OTX feed provider
             */
            class AlienVaultProvider : public FeedProvider {
            public:
                explicit AlienVaultProvider(std::wstring_view apiKey);
                std::vector<IoC_Entry> FetchAndParse(DatabaseError* err = nullptr) override;
                std::wstring GetProviderName() const override { return L"AlienVault OTX"; }
                std::wstring GetEndpoint() const override;

            private:
                std::wstring m_apiKey;
                bool HttpGet(std::wstring_view url, std::string& outResponse, DatabaseError* err);
            };

            // Helper functions
            std::unique_ptr<FeedProvider> CreateProvider(ThreatSource source, DatabaseError* err);
            bool MergeAndUpdateIoCs(const std::vector<IoC_Entry>& newIoCs,
                ThreatSource source,
                DatabaseError* err);

            // HTTP utilities
            static bool PerformHttpRequest(std::wstring_view url,
                std::string& outResponse,
                const std::map<std::wstring, std::wstring>& headers = {},
                DatabaseError* err = nullptr);


          // ============================================================================
          // LRU Cache Implementation
          // ============================================================================

          /**
           * @brief Linked list node untuk LRU tracking
           * Her node bir cache entry'nin access order'ýný tutar
           */
            struct LRUCacheNode {
                std::wstring key;                           // Cache key
                std::chrono::steady_clock::time_point accessTime;  // Last access time
                size_t accessCount = 0;                     // Total access times

                explicit LRUCacheNode(std::wstring k)
                    : key(std::move(k)), accessTime(std::chrono::steady_clock::now()) {
                }
            };

            // Cache statistics
            struct CacheMetrics {
                uint64_t totalAccesses = 0;
                uint64_t evictedEntries = 0;
                uint64_t hitCount = 0;
                uint64_t missCount = 0;
                std::chrono::milliseconds avgAccessTime{};
                double hitRate = 0.0;
                size_t peakCacheSize = 0;
            };
            // LRU cache helper methods
			void evictLRUEntry();                           // delete least recently used entry
            void updateAccessOrder(const std::wstring& key); // Access order update
            const LRUCacheNode& getLRUNode(const std::wstring& key) const;
            bool isExpiredEntry(const IoC_Entry& entry) const;
            void pruneExpiredEntries();
            CacheMetrics getCacheMetrics() const;

            // LRU state
            mutable std::list<LRUCacheNode> m_lruList;     // LRU order (most recent at front)
            mutable std::unordered_map<std::wstring,
				std::list<LRUCacheNode>::iterator> m_lruIterators;  // iterators for quick access

            std::chrono::steady_clock::time_point m_lastCachePrune;
            size_t m_totalEvictions = 0;



            ThreatIntelDB();
            ~ThreatIntelDB();

            ThreatIntelDB(const ThreatIntelDB&) = delete;
            ThreatIntelDB& operator=(const ThreatIntelDB&) = delete;

            // ============================================================================
            // Internal Operations
            // ============================================================================

            // Schema management
            bool createSchema(DatabaseError* err);
            bool upgradeSchema(int currentVersion, int targetVersion, DatabaseError* err);

            // Database operations
            int64_t dbInsertIoC(const IoC_Entry& ioc, DatabaseError* err);
            bool dbUpdateIoC(const IoC_Entry& ioc, DatabaseError* err);
            bool dbDeleteIoC(int64_t iocId, DatabaseError* err);
            std::optional<IoC_Entry> dbSelectIoC(int64_t iocId, DatabaseError* err);
            std::vector<IoC_Entry> dbSelectIoCs(std::string_view sql,
                                                const std::vector<std::string>& params,
                                                DatabaseError* err);

            // Query builders
            std::string buildIoCQuerySQL(const QueryFilter& filter, std::vector<std::string>& outParams);
            std::string buildIoCCountSQL(const QueryFilter& filter, std::vector<std::string>& outParams);

            // Cache operations
            void cacheIoC(const IoC_Entry& ioc);
            std::optional<IoC_Entry> getCachedIoC(std::wstring_view value, IoC_Type type);
            void invalidateCache(int64_t iocId);
            void invalidateCacheByValue(std::wstring_view value, IoC_Type type);

            // Feed sync
            void feedSyncThread();
            bool syncSingleFeed(ThreatSource source, DatabaseError* err);

            // Reputation calculation
            int calculateReputationScore(const ReputationScore& score);

            // Utility helpers
            IoC_Entry rowToIoC(const QueryResult& result);
            ThreatSignature rowToSignature(const QueryResult& result);
            TTP_Entry rowToTTP(const QueryResult& result);
            ThreatActor rowToActor(const QueryResult& result);
            ThreatCampaign rowToCampaign(const QueryResult& result);

            static std::string timePointToString(std::chrono::system_clock::time_point tp);
            static std::chrono::system_clock::time_point stringToTimePoint(std::string_view str);

            std::string wstringToUtf8(std::wstring_view wstr) const;
            std::wstring utf8ToWstring(std::string_view str) const;

            std::string vectorToString(const std::vector<std::wstring>& vec) const;
            std::vector<std::wstring> stringToVector(std::string_view str) const;

            // Statistics helpers
            void updateStatistics(const IoC_Entry& ioc, bool isNew);
            void recalculateStatistics(DatabaseError* err);

            // ============================================================================
            // State
            // ============================================================================

            std::atomic<bool> m_initialized{ false };
            Config m_config;
            mutable std::shared_mutex m_configMutex;

            // Cache (value -> IoC_Entry)
            mutable std::shared_mutex m_cacheMutex;
            mutable std::shared_mutex m_signaturesMutex;
            std::unordered_map<std::wstring, IoC_Entry> m_iocCache;
            std::unordered_map<int64_t, ThreatSignature> m_signatureCache;
            size_t m_cacheSize = 0;

            // Feed sync thread
            std::thread m_feedSyncThread;
            std::atomic<bool> m_shutdownFeedSync{ false };
            std::condition_variable m_feedSyncCV;
            std::mutex m_feedSyncMutex;
            std::unordered_map<ThreatSource, uint64_t> m_lastSyncTimestamps;

            // Statistics
            mutable std::mutex m_statsMutex;
            Statistics m_stats;
        };

    } // namespace Database
} // namespace ShadowStrike
