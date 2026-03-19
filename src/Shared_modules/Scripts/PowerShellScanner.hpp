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
/*
 * ════════════════════════════════════════════════════════════════════════════════
 * Copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * 
 * File: PowerShellScanner.hpp
 * Description: 
 *      Enterprise-grade PowerShell script analysis engine for ShadowStrike NGAV.
 *      Provides comprehensive detection of:
 *        • Obfuscation techniques (Base64, XOR, hex encoding, compression)
 *        • AMSI bypass attempts (reflection, ETW patching, memory manipulation)
 *        • Malicious cmdlets and script blocks
 *        • PowerShell Empire, Cobalt Strike, and Metasploit payloads
 *        • Fileless malware and memory-resident threats
 *        • Constrained language mode bypass attempts
 *        • Download cradles and remote code execution
 *        • Process injection and reflective loading
 *        • Persistence mechanisms via profiles and scheduled tasks
 *
 *      Integrates with Windows AMSI, ETW, Script Block Logging, and ML models
 *      for behavioral pattern analysis. Supports both real-time and static
 *      analysis with comprehensive threat intelligence correlation.
 *
 * Version: 3.0.0 Enterprise Edition
 * Build: 2026.01.25
 * Author: ShadowStrike Advanced Threat Research Team
 * Classification: CONFIDENTIAL - Enterprise Security Infrastructure
 * 
 * Threat Coverage:
 *   - PowerShell Empire (Invoke-Mimikatz, Invoke-ReflectivePEInjection)
 *   - Cobalt Strike (PowerShell beacons, stagers)
 *   - Metasploit (PowerSploit framework)
 *   - Living-off-the-Land binaries (LOLBins)
 *   - Custom malware frameworks
 * ════════════════════════════════════════════════════════════════════════════════
 */

#pragma once

#ifndef SHADOWSTRIKE_SCRIPTS_POWERSHELLSCANNER_HPP
#define SHADOWSTRIKE_SCRIPTS_POWERSHELLSCANNER_HPP

// ════════════════════════════════════════════════════════════════════════════════
// STANDARD LIBRARY INCLUDES (C++20)
// ════════════════════════════════════════════════════════════════════════════════

#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <filesystem>
#include <map>
#include <unordered_map>
#include <set>
#include <unordered_set>
#include <optional>
#include <span>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <concepts>
#include <variant>
#include <array>
#include <algorithm>
#include <ranges>
#include <format>
#include <expected>
#include <source_location>
#include <stacktrace>
#include <coroutine>
#include <thread>
#include <condition_variable>
#include <queue>
#include <deque>
#include <bitset>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <numeric>
#include <ratio>
#include <regex>

// ════════════════════════════════════════════════════════════════════════════════
// INFRASTRUCTURE INCLUDES (ShadowStrike Modules)
// ════════════════════════════════════════════════════════════════════════════════

#include "../Utils/StringUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/MemoryUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/RegistryUtils.hpp"
#include "../Utils/JSONUtils.hpp"
#include "../Utils/XMLUtils.hpp"
#include "../Utils/Base64Utils.hpp"
#include "../Utils/CompressionUtils.hpp"
#include "../Utils/CacheManager.hpp"
#include "../Utils/ThreadPool.hpp"
#include "../Utils/Timer.hpp"

#include "../HashStore/HashStore.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../SignatureStore/SignatureStore.hpp"
#include "../ThreatIntel/ThreatIntelLookup.hpp"
#include "../Whitelist/WhiteListStore.hpp"
#include "../Config/ConfigManager.hpp"

// ════════════════════════════════════════════════════════════════════════════════
// NAMESPACE DEFINITION
// ════════════════════════════════════════════════════════════════════════════════

namespace ShadowStrike::Scripts {

// ════════════════════════════════════════════════════════════════════════════════
// FORWARD DECLARATIONS
// ════════════════════════════════════════════════════════════════════════════════

class PowerShellScanner;
class PowerShellDeobfuscator;
class PowerShellEmulator;
class AMSIBypassDetector;
class ScriptBlockAnalyzer;

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS & THRESHOLDS NAMESPACE
// ════════════════════════════════════════════════════════════════════════════════
    namespace Constants {
        constexpr size_t MAX_SCRIPT_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB
        constexpr size_t MAX_RECURSION_DEPTH = 32;
        constexpr double MIN_ENTROPY_OBFUSCATION = 5.8;
        constexpr size_t MAX_TOKEN_ANALYSIS_WINDOW = 500;
        
        constexpr std::string_view POWERSHELL_EXE = "powershell.exe";
        constexpr std::string_view PWSH_EXE = "pwsh.exe";
        
        namespace Heuristics {
            constexpr int SCORE_AMSI_BYPASS = 100;
            constexpr int SCORE_REFLECTION_LOAD = 90;
            constexpr int SCORE_ENCODED_COMMAND = 50;
            constexpr int SCORE_NET_WEBCLIENT = 60;
            constexpr int SCORE_INVOKE_EXPRESSION = 70;
            constexpr int SCORE_SUSPICIOUS_OBFUSCATION = 40;
            
            constexpr int THRESHOLD_BLOCK = 90;
            constexpr int THRESHOLD_SUSPICIOUS = 50;
        }

        namespace Timeouts {
            constexpr std::chrono::milliseconds SCAN_TIMEOUT_MS(2000);
            constexpr std::chrono::milliseconds AMSI_CHECK_TIMEOUT_MS(500);
        }
    }

    // --------------------------------------------------------------------------------
    // ENUMS
    // --------------------------------------------------------------------------------
    enum class ScanStatus {
        CLEAN,
        SUSPICIOUS,
        MALICIOUS,
        ERROR_FILE_ACCESS,
        ERROR_TIMEOUT,
        ERROR_INTERNAL,
        SKIPPED_WHITELISTED,
        SKIPPED_SIZE_LIMIT
    };

    enum class ObfuscationType {
        NONE,
        BASE64,
        XOR,
        STRING_CONCATENATION,
        VARIABLE_REPLACEMENT,
        BACKTICK_INSERTION,
        MIXED_CASE_RANDOMIZATION,
        COMPRESSION_GZIP,
        CUSTOM_ENCODING
    };

    enum class ThreatCategory {
        NONE,
        DOWNLOADER,
        RANSOMWARE_STAGER,
        CREDENTIAL_THEFT,
        PERSISTENCE_MECHANISM,
        PRIVILEGE_ESCALATION,
        REVERSE_SHELL,
        RECONNAISSANCE,
        AMSI_TAMPERING
    };

    enum class ExecutionMode {
        FILE_ON_DISK,
        MEMORY_ONLY,
        INTERACTIVE_SHELL,
        ENCODED_COMMAND_LINE
    };

    // --------------------------------------------------------------------------------
    // CONCEPTS
    // --------------------------------------------------------------------------------
    template<typename T>
    concept PowerShellContext = requires(T t) {
        { t.getProcessId() } -> std::convertible_to<uint32_t>;
        { t.getCommandLine() } -> std::convertible_to<std::string_view>;
        { t.getUserSid() } -> std::convertible_to<std::string_view>;
    };

    // --------------------------------------------------------------------------------
    // DATA STRUCTURES
    // --------------------------------------------------------------------------------
    
    struct PowerShellScanConfig {
        bool enableAmsiIntegration = true;
        bool enableDeepScriptAnalysis = true;
        bool enableDeobfuscation = true;
        bool blockObfuscatedScripts = false; // Aggressive mode
        bool scanInteractiveCommands = true;
        bool reportToCloud = true;
        
        uint32_t maxScriptSize = Constants::MAX_SCRIPT_SIZE_BYTES;
        uint32_t maxScanTimeMs = Constants::Timeouts::SCAN_TIMEOUT_MS.count();
        double minEntropyThreshold = Constants::MIN_ENTROPY_OBFUSCATION;
        
        std::vector<std::string> blacklistedCmdlets;
        std::vector<std::string> whitelistedSigners;

        // Custom equality for configuration comparison
        bool operator==(const PowerShellScanConfig& other) const = default;
    };

    struct ObfuscationDetails {
        ObfuscationType primaryType = ObfuscationType::NONE;
        double entropyScore = 0.0;
        size_t suspiciousTokenCount = 0;
        std::string decodedSnippet; // Preview of deobfuscated content
        std::vector<std::string> techniquesDetected;
    };

    struct ScanResult {
        ScanStatus status = ScanStatus::CLEAN;
        ThreatCategory category = ThreatCategory::NONE;
        int riskScore = 0;
        std::string threatName;
        std::string description;
        
        // Metadata
        std::string filePath; // Empty if memory-only
        std::string sha256;
        std::chrono::system_clock::time_point scanTime;
        std::chrono::microseconds scanDuration;
        
        // Analysis Details
        ObfuscationDetails obfuscation;
        std::vector<std::string> matchedRules;
        std::vector<std::pair<size_t, std::string>> flaggedLines; // Line number, Content
        
        // Context
        uint32_t processId = 0;
        std::string userSid;
        ExecutionMode mode = ExecutionMode::FILE_ON_DISK;

        [[nodiscard]] bool isBlocking() const {
            return status == ScanStatus::MALICIOUS || 
                  (status == ScanStatus::SUSPICIOUS && riskScore >= Constants::Heuristics::THRESHOLD_BLOCK);
        }
    };

    struct PowerShellStats {
        std::atomic<uint64_t> totalScans{0};
        std::atomic<uint64_t> maliciousDetected{0};
        std::atomic<uint64_t> suspiciousDetected{0};
        std::atomic<uint64_t> obfuscatedDetected{0};
        std::atomic<uint64_t> amsiBypassesBlocked{0};
        std::atomic<uint64_t> timeouts{0};
        std::atomic<uint64_t> totalBytesScanned{0};
        std::atomic<uint64_t> averageScanTimeUs{0};
    };

    // --------------------------------------------------------------------------------
    // MAIN CLASS
    // --------------------------------------------------------------------------------
    class PowerShellScanner {
    public:
        // ----------------------------------------------------------------------------
        // LIFECYCLE
        // ----------------------------------------------------------------------------
        
        // Singleton Accessor
        static PowerShellScanner& getInstance();

        // Delete copy/move to enforce singleton
        PowerShellScanner(const PowerShellScanner&) = delete;
        PowerShellScanner& operator=(const PowerShellScanner&) = delete;
        PowerShellScanner(PowerShellScanner&&) = delete;
        PowerShellScanner& operator=(PowerShellScanner&&) = delete;

        // ----------------------------------------------------------------------------
        // PUBLIC API - SCANNING
        // ----------------------------------------------------------------------------
        
        /**
         * @brief Scans a PowerShell script file on disk.
         * 
         * @param path The filesystem path to the script (.ps1, .psm1, .psd1).
         * @param pid Optional process ID if triggered by process creation.
         * @return ScanResult Detailed analysis result.
         */
        [[nodiscard]] ScanResult scanFile(
            const std::filesystem::path& path, 
            uint32_t pid = 0
        );

        /**
         * @brief Scans an in-memory script or command block.
         * 
         * @param content The script content to analyze.
         * @param sourceDescription Description of origin (e.g., "AMSI Buffer", "EncodedCommand").
         * @param pid Process ID executing the script.
         * @return ScanResult Detailed analysis result.
         */
        [[nodiscard]] ScanResult scanMemory(
            std::span<const char> content,
            std::string_view sourceDescription,
            uint32_t pid
        );

        /**
         * @brief Scans a parsed command line for PowerShell execution flags and encoded commands.
         * 
         * @param commandLine The full command line string.
         * @param pid The process ID.
         * @return ScanResult Detailed analysis result.
         */
        [[nodiscard]] ScanResult scanCommandLine(
            std::string_view commandLine,
            uint32_t pid
        );

        // ----------------------------------------------------------------------------
        // PUBLIC API - MANAGEMENT
        // ----------------------------------------------------------------------------

        /**
         * @brief Updates the scanner configuration.
         * Thread-safe.
         */
        void updateConfig(const PowerShellScanConfig& newConfig);

        /**
         * @brief Retrieves the current configuration.
         */
        PowerShellScanConfig getConfig() const;

        /**
         * @brief Registers a callback for scan events.
         */
        void registerCallback(std::function<void(const ScanResult&)> callback);

        /**
         * @brief Retrieves current runtime statistics.
         */
        PowerShellStats getStats() const;

        /**
         * @brief Resets runtime statistics.
         */
        void resetStats();

        /**
         * @brief Performs a self-test of the scanner engine.
         * @return true if operational, false if critical failure.
         */
        bool healthCheck();

    private:
        // ----------------------------------------------------------------------------
        // PRIVATE IMPLEMENTATION (PIMPL)
        // ----------------------------------------------------------------------------
        class Impl;
        std::unique_ptr<Impl> pImpl;

        // Private constructor for Singleton
        PowerShellScanner();
        ~PowerShellScanner();

        // ----------------------------------------------------------------------------
        // INTERNAL HELPERS
        // ----------------------------------------------------------------------------
        
        // Helper to check whitelist caches before deep scanning
        bool isWhitelisted(const std::filesystem::path& path, const std::string& hash);
        
        // Helper to perform static analysis on script content
        ScanResult performStaticAnalysis(
            std::string_view content, 
            const std::string& contextName
        );

        // Helper to detect and handle AMSI bypass attempts specifically
        bool detectAmsiBypass(std::string_view content, std::vector<std::string>& techniques);

        // Deobfuscation engine entry point
        std::string attemptDeobfuscation(std::string_view content, ObfuscationType& detectedType);
        
        // Base64 decoding helper for PowerShell's specific unicode/widechar encoding
        std::string decodePowerShellBase64(std::string_view encoded);

        // Thread synchronization
        mutable std::mutex configMutex;
        mutable std::mutex callbackMutex;
    };

} // namespace ShadowStrike::Scripts