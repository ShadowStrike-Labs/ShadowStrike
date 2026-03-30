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
 *        • PowerShell v2 downgrade attacks (AMSI bypass)
 *
 *      Integrates with Windows AMSI, ETW, Script Block Logging, and
 *      kernel driver (PhantomSensor) for process-level enforcement.
 *
 * Version: 4.1.0 Enterprise Edition
 * Build: 2026.01.28
 * Author: ShadowStrike Advanced Threat Research Team
 * Classification: CONFIDENTIAL - Enterprise Security Infrastructure
 * ════════════════════════════════════════════════════════════════════════════════
 */

#pragma once

#ifndef SHADOWSTRIKE_SCRIPTS_POWERSHELLSCANNER_HPP
#define SHADOWSTRIKE_SCRIPTS_POWERSHELLSCANNER_HPP

#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <filesystem>
#include <optional>
#include <span>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <array>
#include <unordered_map>
#include <list>
#include <cstdint>

#include "../Utils/Logger.hpp"

// Forward declarations for cross-module integration
namespace ShadowStrike::Whitelist { class WhitelistStore; }

namespace ShadowStrike::Scripts {

// ════════════════════════════════════════════════════════════════════════════════
// FORWARD DECLARATIONS
// ════════════════════════════════════════════════════════════════════════════════

class PowerShellScanner;

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS & THRESHOLDS
// ════════════════════════════════════════════════════════════════════════════════

namespace Constants {
    constexpr size_t MAX_SCRIPT_SIZE_BYTES       = 10 * 1024 * 1024;
    constexpr size_t MAX_DEOBFUSCATION_DEPTH     = 5;
    constexpr size_t MAX_FLAGGED_LINES           = 100;
    constexpr double MIN_ENTROPY_OBFUSCATION     = 5.8;

    constexpr std::string_view POWERSHELL_EXE    = "powershell.exe";
    constexpr std::string_view PWSH_EXE          = "pwsh.exe";

    namespace Heuristics {
        constexpr int SCORE_AMSI_BYPASS          = 100;
        constexpr int SCORE_REFLECTION_LOAD      = 90;
        constexpr int SCORE_ENCODED_COMMAND       = 50;
        constexpr int SCORE_NET_WEBCLIENT         = 60;
        constexpr int SCORE_INVOKE_EXPRESSION     = 70;
        constexpr int SCORE_SUSPICIOUS_OBFUSCATION = 40;
        constexpr int SCORE_V2_DOWNGRADE          = 100;
        constexpr int SCORE_MIMIKATZ              = 100;
        constexpr int SCORE_SHELLCODE_INJECTION   = 95;
        constexpr int SCORE_WMI_PERSISTENCE       = 80;
        constexpr int SCORE_LANGUAGE_MODE_BYPASS  = 90;
        constexpr int SCORE_REVERSE_SHELL         = 90;

        constexpr int THRESHOLD_BLOCK             = 90;
        constexpr int THRESHOLD_SUSPICIOUS        = 50;
    }

    namespace Timeouts {
        constexpr std::chrono::milliseconds SCAN_TIMEOUT_MS{2000};
        constexpr std::chrono::milliseconds AMSI_CHECK_TIMEOUT_MS{500};
    }
}

namespace PSConstants {
    inline constexpr size_t SCAN_CACHE_CAPACITY       = 4096;
    inline constexpr std::chrono::seconds SCAN_CACHE_TTL{300};
    inline constexpr size_t MAX_CALLBACKS              = 16;
    inline constexpr uint32_t KERNEL_MSG_BLOCK_PROCESS = 0x30;
}

// ════════════════════════════════════════════════════════════════════════════════
// ENUMS
// ════════════════════════════════════════════════════════════════════════════════

#ifdef ERROR_TIMEOUT
#pragma push_macro("ERROR_TIMEOUT")
#undef ERROR_TIMEOUT
#define SHADOWSTRIKE_RESTORE_ERROR_TIMEOUT_
#endif

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

#ifdef SHADOWSTRIKE_RESTORE_ERROR_TIMEOUT_
#pragma pop_macro("ERROR_TIMEOUT")
#undef SHADOWSTRIKE_RESTORE_ERROR_TIMEOUT_
#endif

enum class ObfuscationType {
    NONE,
    BASE64,
    XOR,
    STRING_CONCATENATION,
    VARIABLE_REPLACEMENT,
    BACKTICK_INSERTION,
    MIXED_CASE_RANDOMIZATION,
    COMPRESSION_GZIP,
    CHAR_ARRAY,
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
    AMSI_TAMPERING,
    PROCESS_INJECTION,
    V2_DOWNGRADE
};

enum class ExecutionMode {
    FILE_ON_DISK,
    MEMORY_ONLY,
    INTERACTIVE_SHELL,
    ENCODED_COMMAND_LINE
};

// ════════════════════════════════════════════════════════════════════════════════
// DATA STRUCTURES
// ════════════════════════════════════════════════════════════════════════════════

struct PowerShellScanConfig {
    bool enableAmsiIntegration         = true;
    bool enableDeepScriptAnalysis      = true;
    bool enableDeobfuscation           = true;
    bool blockObfuscatedScripts        = false;
    bool scanInteractiveCommands       = true;
    bool blockV2Downgrade              = true;

    uint32_t maxScriptSize             = Constants::MAX_SCRIPT_SIZE_BYTES;
    uint32_t maxScanTimeMs             = static_cast<uint32_t>(Constants::Timeouts::SCAN_TIMEOUT_MS.count());
    uint32_t maxDeobfuscationDepth     = Constants::MAX_DEOBFUSCATION_DEPTH;
    double   minEntropyThreshold       = Constants::MIN_ENTROPY_OBFUSCATION;

    std::vector<std::string> blacklistedCmdlets;
    std::vector<std::string> whitelistedSigners;

    bool operator==(const PowerShellScanConfig& other) const = default;
};

struct ObfuscationDetails {
    ObfuscationType primaryType         = ObfuscationType::NONE;
    double          entropyScore        = 0.0;
    size_t          suspiciousTokenCount = 0;
    std::string     decodedSnippet;
    std::vector<std::string> techniquesDetected;
};

struct ScanResult {
    ScanStatus      status              = ScanStatus::CLEAN;
    ThreatCategory  category            = ThreatCategory::NONE;
    int             riskScore           = 0;
    std::string     threatName;
    std::string     description;

    std::string     filePath;
    std::string     sha256;
    std::chrono::system_clock::time_point scanTime;
    std::chrono::microseconds             scanDuration{0};

    ObfuscationDetails obfuscation;
    std::vector<std::string> matchedRules;
    std::vector<std::pair<size_t, std::string>> flaggedLines;

    uint32_t      processId             = 0;
    std::string   userSid;
    ExecutionMode mode                  = ExecutionMode::FILE_ON_DISK;

    [[nodiscard]] bool isBlocking() const noexcept {
        return status == ScanStatus::MALICIOUS ||
              (status == ScanStatus::SUSPICIOUS &&
               riskScore >= Constants::Heuristics::THRESHOLD_BLOCK);
    }
};

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

struct PSStatisticsSnapshot {
    uint64_t totalScans = 0;
    uint64_t maliciousDetected = 0;
    uint64_t suspiciousDetected = 0;
    uint64_t obfuscatedDetected = 0;
    uint64_t amsiBypassesBlocked = 0;
    uint64_t v2DowngradesBlocked = 0;
    uint64_t timeouts = 0;
    uint64_t totalBytesScanned = 0;
    uint64_t averageScanTimeUs = 0;
    uint64_t cacheHits = 0;
    uint64_t cacheMisses = 0;
    TimePoint startTime{};

    [[nodiscard]] std::string ToJson() const;
};

// ════════════════════════════════════════════════════════════════════════════════
// MAIN CLASS — PIMPL + Meyers' Singleton
// ════════════════════════════════════════════════════════════════════════════════

class PowerShellScanner {
public:
    static PowerShellScanner& getInstance();

    PowerShellScanner(const PowerShellScanner&)            = delete;
    PowerShellScanner& operator=(const PowerShellScanner&) = delete;
    PowerShellScanner(PowerShellScanner&&)                 = delete;
    PowerShellScanner& operator=(PowerShellScanner&&)      = delete;

    // ── Scanning ─────────────────────────────────────────────────────────────

    [[nodiscard]] ScanResult scanFile(
        const std::filesystem::path& path,
        uint32_t pid = 0);

    [[nodiscard]] ScanResult scanMemory(
        std::span<const char> content,
        std::string_view sourceDescription,
        uint32_t pid);

    [[nodiscard]] ScanResult scanCommandLine(
        std::string_view commandLine,
        uint32_t pid);

    // ── Management ───────────────────────────────────────────────────────────

    void updateConfig(const PowerShellScanConfig& newConfig);

    [[nodiscard]] PowerShellScanConfig getConfig() const;

    void registerCallback(std::function<void(const ScanResult&)> callback);

    void setWhitelistStore(Whitelist::WhitelistStore* store) noexcept;

    [[nodiscard]] PSStatisticsSnapshot getStats() const;

    void resetStats();

    [[nodiscard]] bool healthCheck();

    // ── Kernel Bridge ────────────────────────────────────────────────────

    void OnKernelProcessNotify(
        uint32_t processId,
        std::wstring_view imagePath,
        std::wstring_view commandLine,
        bool isCreate);

    void OnKernelImageLoad(
        uint32_t processId,
        std::wstring_view imagePath,
        uint64_t imageBase,
        size_t imageSize);

    [[nodiscard]] bool RequestKernelProcessBlock(
        uint32_t processId,
        const std::wstring& reason);

    // ── Cross-Module Wiring ──────────────────────────────────────────────

    void ReportThreatToAlertSystem(const ScanResult& result);
    void ReportScanTelemetry(const ScanResult& result);
    void ReportThreatToBehaviorAnalyzer(const ScanResult& result);

    // ── Version ──────────────────────────────────────────────────────────

    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;

    PowerShellScanner();
    ~PowerShellScanner();
};

} // namespace ShadowStrike::Scripts

#endif // SHADOWSTRIKE_SCRIPTS_POWERSHELLSCANNER_HPP
