/**
 * ============================================================================
 * ShadowStrike Core Engine - SCAN ENGINE (The Brain)
 * ============================================================================
 *
 * @file ScanEngine.hpp
 * @brief Central coordination engine for all scanning operations.
 *
 * This is the "Brain" of the ShadowStrike Antivirus. It serves as the unified
 * facade that orchestrates all underlying detection technologies into a coherent
 * decision-making pipeline. It is responsible for taking a target (file, process,
 * memory buffer) and determining its safety verdict by querying:
 *
 * 1. WhitelistStore (Immune System) - Is it known safe?
 * 2. HashStore (Memory) - Is it known malware?
 * 3. ThreatIntel (Reputation) - Is the source/hash suspicious?
 * 4. SignatureStore (Deep Analysis) - YARA rules, pattern matching.
 * 5. HeuristicAnalyzer (Logic) - Static analysis, entropy, anomaly detection.
 *
 * Architecture Position:
 * ----------------------
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │                 Kernel / User Interface                      │
 *   └───────────┬──────────────────────────────────┬──────────────┘
 *               │ (File Event)                     │ (Scan Request)
 *               ▼                                  ▼
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │                      SCAN ENGINE                             │ ◄── YOU ARE HERE
 *   │           (Orchestrator, Decision Maker, Logger)             │
 *   └──────────────────────────┬──────────────────────────────────┘
 *                              │
 *        ┌────────────┬────────┴────────┬─────────────┐
 *        ▼            ▼                 ▼             ▼
 *   ┌─────────┐  ┌─────────┐      ┌──────────┐  ┌────────────┐
 *   │Whitelist│  │HashStore│      │ThreatRep │  │Signatures  │
 *   └─────────┘  └─────────┘      └──────────┘  └────────────┘
 *
 * Pipeline Flow:
 * --------------
 * Target -> [PreScan: Whitelist] --(Safe)--> [Result: Clean]
 *                 │
 *                 ▼
 *           [FastScan: Hash] --(Match)--> [Result: Infected]
 *                 │
 *                 ▼
 *           [IntelScan: Reputation] --(Bad)--> [Result: Suspicious]
 *                 │
 *                 ▼
 *           [DeepScan: YARA/Patterns] --(Match)--> [Result: Infected]
 *                 │
 *                 ▼
 *           [HeuristicScan: Analysis] --(Score > Threshold)--> [Result: Suspicious]
 *
 * Thread Safety:
 * --------------
 * This class is fully thread-safe. It is designed to be called concurrently
 * from multiple threads (e.g., Minifilter worker threads, UI scan threads).
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../SignatureStore/SignatureStore.hpp"
#include "../../Whitelist/WhiteListStore.hpp"
#include "../../ThreatIntel/ThreatIntelDatabase.hpp"
#include "../../Database/QuarantineDB.hpp"
#include "../../Database/LogDB.hpp"
#include "../../Database/ConfigurationDB.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/SystemUtils.hpp"

// Standard Library
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <atomic>
#include <shared_mutex>
#include <future>
#include <filesystem>
#include <span>
#include <optional>

namespace ShadowStrike {
    namespace Core {
        namespace Engine {

            // ============================================================================
            // SCAN TYPES & ENUMS
            // ============================================================================

            /**
             * @enum ScanType
             * @brief Defines the depth and intent of the scan.
             */
            enum class ScanType : uint8_t {
                RealTime,       ///< Low latency, high priority (Kernel initiated)
                OnDemand,       ///< User initiated, deep scan
                Memory,         ///< Volatile memory scan
                Boot,           ///< Boot-time scan
                Contextual      ///< "Right-click" scan
            };

            /**
             * @enum ScanVerdict
             * @brief The final decision made by the engine.
             */
            enum class ScanVerdict : uint8_t {
                Clean,          ///< No threats found
                Whitelisted,    ///< Explicitly allowed by policy/whitelist
                Infected,       ///< Confirmed malware signature match
                Suspicious,     ///< Heuristics/Reputation threshold exceeded
                Error           ///< Scan failed (locked file, access denied)
            };

            // ============================================================================
            // DATA STRUCTURES
            // ============================================================================

            /**
             * @struct ScanContext
             * @brief Carries metadata about the scan request through the pipeline.
             */
            struct ScanContext {
                ScanType type = ScanType::OnDemand;
                uint32_t processId = 0;             ///< Process initiating the IO (for RealTime)
                std::wstring filePath;              ///< Target file path
                bool isNetworkPath = false;         ///< Is file on network share?
                
                // Real-time constraints
                std::chrono::milliseconds timeout{ 5000 };
                bool stopOnFirstMatch = true;       ///< Performance optimization
                
                // Advanced context
                std::string userSid;                ///< User context
            };

            /**
             * @struct EngineResult
             * @brief The unified result returned to the caller.
             */
            struct EngineResult {
                ScanVerdict verdict = ScanVerdict::Clean;
                
                // Threat Details
                std::string threatName;             ///< e.g., "Worm.Win32.Stuxnet"
                SignatureStore::ThreatLevel severity = SignatureStore::ThreatLevel::Info;
                uint64_t threatId = 0;
                std::string detectionSource;        ///< "HashStore", "YARA", "Heuristic", etc.
                
                // Metadata
                uint64_t scanDurationUs = 0;        ///< Microseconds
                std::string sha256;                 ///< File hash (calculated during scan)
                
                // For Quarantine integration
                bool requiresReboot = false;
            };

            /**
             * @struct EngineConfig
             * @brief Configuration for the Scan Engine.
             */
            struct EngineConfig {
                bool enableRealTime = true;
                bool enableHeuristics = true;
                bool enableCloudLookup = true;
                bool enableMemoryScanning = true;
                bool enableCompressedScanning = false; // Scan inside zips (slow)
                
                size_t maxFileSizeRealTime = 50 * 1024 * 1024; // 50MB limit for RT
                uint32_t sensitivityLevel = 2; // 1=Low, 2=Medium, 3=High (Paranoid)
                
                // Paths to databases
                std::wstring signatureDbPath;
                std::wstring whitelistDbPath;
                std::wstring threatIntelDbPath;
            };

            // ============================================================================
            // SCAN ENGINE CLASS
            // ============================================================================

            /**
             * @class ScanEngine
             * @brief The primary interface for all scanning logic.
             * 
             * Implementation follows the Singleton pattern to manage the lifecycle
             * of heavy database connections (SignatureStore, WhitelistStore).
             */
            class ScanEngine {
            public:
                // ========================================================================
                // LIFECYCLE
                // ========================================================================

                static ScanEngine& Instance();

                /**
                 * @brief Initialize the engine and connect to all subsystems.
                 * @param config Configuration parameters.
                 * @return True if all critical databases loaded successfully.
                 */
                [[nodiscard]] bool Initialize(const EngineConfig& config);

                /**
                 * @brief Gracefully shutdown and release database handles.
                 */
                void Shutdown();

                bool IsInitialized() const { return m_initialized.load(); }

                // ========================================================================
                // PUBLIC SCANNING API
                // ========================================================================

                /**
                 * @brief Scan a file on disk.
                 * Used by Real-Time Protection (Minifilter) and On-Demand Scanner.
                 * 
                 * @param filePath Full path to the file.
                 * @param context Contextual information (PID, ScanType).
                 * @return EngineResult containing the verdict.
                 */
                [[nodiscard]] EngineResult ScanFile(
                    const std::wstring& filePath,
                    const ScanContext& context
                );

                /**
                 * @brief Scan a memory buffer.
                 * Used for network packets, unpacked payloads, or process memory.
                 * 
                 * @param buffer Pointer to data.
                 * @param context Contextual information.
                 * @return EngineResult containing the verdict.
                 */
                [[nodiscard]] EngineResult ScanMemory(
                    std::span<const uint8_t> buffer,
                    const ScanContext& context
                );

                /**
                 * @brief Scan a running process (Memory + Loaded Modules).
                 * 
                 * @param pid Process ID.
                 * @return EngineResult.
                 */
                [[nodiscard]] EngineResult ScanProcess(
                    uint32_t pid,
                    const ScanContext& context
                );

                // ========================================================================
                // MANAGEMENT API
                // ========================================================================

                /**
                 * @brief Reload databases (hot-reload) without stopping the engine.
                 * Called when new signatures are downloaded.
                 */
                bool ReloadDatabases();

                /**
                 * @brief Update configuration at runtime.
                 */
                void UpdateConfig(const EngineConfig& newConfig);

                /**
                 * @brief Get internal statistics.
                 */
                struct Stats {
                    uint64_t totalScans;
                    uint64_t infectionsFound;
                    uint64_t cacheHits;
                    uint64_t whitelistHits;
                    double averageScanTimeMs;
                };
                Stats GetStatistics() const;

            private:
                ScanEngine();
                ~ScanEngine();

                // Delete copy/move
                ScanEngine(const ScanEngine&) = delete;
                ScanEngine& operator=(const ScanEngine&) = delete;

                // ========================================================================
                // INTERNAL PIPELINE STAGES
                // ========================================================================

                /**
                 * @brief Stage 1: Whitelist Check (Fastest)
                 * Checks file path, hash, and authenticode signature against whitelist.
                 */
                [[nodiscard]] std::optional<EngineResult> CheckWhitelist(
                    const std::wstring& filePath,
                    const std::string& fileHash,
                    const ScanContext& context
                );

                /**
                 * @brief Stage 2: Hash Check (Fast)
                 * Checks computed hash against the malware hash database.
                 */
                [[nodiscard]] std::optional<EngineResult> CheckHash(
                    const std::string& fileHash
                );

                /**
                 * @brief Stage 3: Threat Intelligence (Cloud/Local Rep)
                 * Checks URL/IP/Hash reputation if enabled.
                 */
                [[nodiscard]] std::optional<EngineResult> CheckThreatIntel(
                    const std::string& fileHash,
                    const ScanContext& context
                );

                /**
                 * @brief Stage 4: Signature Scan (Deep)
                 * Runs YARA rules and byte-pattern matching.
                 */
                [[nodiscard]] std::optional<EngineResult> RunSignatureScan(
                    const std::wstring& filePath,
                    std::span<const uint8_t> buffer,
                    const ScanContext& context
                );

                /**
                 * @brief Stage 5: Heuristics (Logic)
                 * Static analysis of PE headers, entropy, suspicious sections.
                 */
                [[nodiscard]] std::optional<EngineResult> RunHeuristics(
                    const std::wstring& filePath,
                    std::span<const uint8_t> buffer
                );

                // ========================================================================
                // HELPER FUNCTIONS
                // ========================================================================

                // Calculates SHA256 for internal use.
                std::string ComputeSHA256(const std::wstring& filePath);
                std::string ComputeSHA256(std::span<const uint8_t> buffer);

                // Converts internal store results to public EngineResult
                EngineResult ConvertDetection(
                    const SignatureStore::DetectionResult& det,
                    const std::string& source
                );

                // ========================================================================
                // MEMBERS
                // ========================================================================

                std::atomic<bool> m_initialized{ false };
                EngineConfig m_config;
                mutable std::shared_mutex m_configMutex;

                // Subsystems
                std::unique_ptr<SignatureStore::SignatureStore> m_signatureStore;
                std::unique_ptr<Whitelist::WhitelistStore> m_whitelistStore;
                std::unique_ptr<ThreatIntel::ThreatIntelDatabase> m_threatIntelDB; // Persistence
                // Note: ThreatIntelIndex would be initialized using m_threatIntelDB data

                // Statistics
                struct InternalStats {
                    std::atomic<uint64_t> totalScans{0};
                    std::atomic<uint64_t> infections{0};
                    std::atomic<uint64_t> cacheHits{0};
                    std::atomic<uint64_t> whitelistHits{0};
                    std::atomic<uint64_t> totalTimeUs{0};
                } m_stats;

                // Cache (LRU) for recent scan results to speed up RealTime checks
                struct ScanCacheEntry {
                    std::string hash;
                    ScanVerdict verdict;
                    std::chrono::steady_clock::time_point timestamp;
                };
                // Simple mutex-protected cache for now (Production would use concurrent LRU)
                std::mutex m_cacheMutex;
                std::vector<ScanCacheEntry> m_resultCache; // Placeholder for ring buffer
            };

        } // namespace Engine
    } // namespace Core
} // namespace ShadowStrike