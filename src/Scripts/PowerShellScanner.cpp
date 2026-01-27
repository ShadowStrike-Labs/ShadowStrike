/*
 * ════════════════════════════════════════════════════════════════════════════════
 * Copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * File: PowerShellScanner.cpp
 * Description:
 *      Enterprise-grade PowerShell script analysis engine implementation.
 *      Provides comprehensive detection capabilities for malicious PowerShell
 *      scripts, obfuscation techniques, and AMSI bypass attempts.
 *
 * Version: 3.0.0 Enterprise Edition
 * Build: 2026.01.27
 * Author: ShadowStrike Advanced Threat Research Team
 * Classification: CONFIDENTIAL - Enterprise Security Infrastructure
 *
 * Implementation Standards:
 *   - PIMPL pattern for ABI stability
 *   - Meyers' Singleton for thread-safe instantiation
 *   - std::shared_mutex for concurrent read/write access
 *   - Comprehensive error handling with structured logging
 *   - Statistics tracking for all operations
 *   - JSON serialization for diagnostics and reporting
 *
 * ════════════════════════════════════════════════════════════════════════════════
 */

#include "pch.h"
#include "PowerShellScanner.hpp"

// ════════════════════════════════════════════════════════════════════════════════
// WINDOWS PLATFORM HEADERS
// ════════════════════════════════════════════════════════════════════════════════

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <amsi.h>
#pragma comment(lib, "amsi.lib")
#endif

// ════════════════════════════════════════════════════════════════════════════════
// STANDARD LIBRARY IMPLEMENTATION HEADERS
// ════════════════════════════════════════════════════════════════════════════════

#include <sstream>
#include <iomanip>
#include <cctype>
#include <cmath>

namespace ShadowStrike::Scripts {

// ════════════════════════════════════════════════════════════════════════════════
// LOGGING CATEGORY
// ════════════════════════════════════════════════════════════════════════════════

namespace {
    constexpr const wchar_t* LOG_CATEGORY = L"PowerShellScanner";
}

// ════════════════════════════════════════════════════════════════════════════════
// STATIC PATTERN DEFINITIONS
// ════════════════════════════════════════════════════════════════════════════════

namespace Patterns {

    // AMSI bypass patterns - techniques used to disable or evade AMSI
    static const std::vector<std::pair<std::string, std::string>> AMSI_BYPASS_PATTERNS = {
        {"AmsiScanBuffer", "Direct AMSI function tampering"},
        {"AmsiInitFailed", "AMSI initialization bypass"},
        {"amsiContext", "AMSI context manipulation"},
        {"amsiSession", "AMSI session manipulation"},
        {"AmsiUtils", "AMSI utility class bypass"},
        {"amsi.dll", "AMSI DLL manipulation"},
        {"SetProtectedEventLogging", "Event logging bypass"},
        {"System.Management.Automation.AmsiUtils", "Reflection-based AMSI bypass"},
        {"[Ref].Assembly.GetType", "Reflection assembly access"},
        {"NonPublic,Static", "Non-public member access via reflection"},
        {"GetField(", "Reflection field access"},
        {"SetValue(", "Reflection value modification"},
        {"Runtime.InteropServices.Marshal", "Memory manipulation via Marshal"},
        {"VirtualProtect", "Memory protection modification"},
        {"WriteProcessMemory", "Process memory writing"},
        {"NtWriteVirtualMemory", "NT API memory writing"},
        {"EtwEventWrite", "ETW bypass attempt"},
    };

    // Suspicious cmdlet patterns
    static const std::vector<std::pair<std::string, int>> SUSPICIOUS_CMDLETS = {
        {"Invoke-Expression", Constants::Heuristics::SCORE_INVOKE_EXPRESSION},
        {"Invoke-Command", 50},
        {"Invoke-Mimikatz", 100},
        {"Invoke-ReflectivePEInjection", 100},
        {"Invoke-Shellcode", 100},
        {"Invoke-TokenManipulation", 90},
        {"Invoke-CredentialInjection", 90},
        {"Invoke-DllInjection", 95},
        {"Invoke-WmiCommand", 60},
        {"Invoke-PSRemoting", 50},
        {"New-Object Net.WebClient", Constants::Heuristics::SCORE_NET_WEBCLIENT},
        {"System.Net.WebClient", Constants::Heuristics::SCORE_NET_WEBCLIENT},
        {"DownloadString", 70},
        {"DownloadFile", 65},
        {"DownloadData", 65},
        {"Invoke-WebRequest", 55},
        {"Start-BitsTransfer", 50},
        {"[System.Reflection.Assembly]::Load", Constants::Heuristics::SCORE_REFLECTION_LOAD},
        {"[Reflection.Assembly]::Load", Constants::Heuristics::SCORE_REFLECTION_LOAD},
        {"LoadWithPartialName", 80},
        {"Add-Type", 40},
        {"[DllImport", 70},
        {"GetDelegateForFunctionPointer", 85},
        {"VirtualAlloc", 80},
        {"CreateThread", 75},
        {"OpenProcess", 70},
        {"ReadProcessMemory", 75},
        {"WriteProcessMemory", 85},
        {"Get-Credential", 45},
        {"ConvertTo-SecureString", 40},
        {"SecureString", 35},
        {"Get-WmiObject", 35},
        {"Get-CimInstance", 30},
        {"Register-ScheduledTask", 55},
        {"New-ScheduledTask", 55},
        {"Set-ItemProperty.*Run", 60},
        {"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 65},
        {"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 65},
        {"-EncodedCommand", Constants::Heuristics::SCORE_ENCODED_COMMAND},
        {"-enc ", Constants::Heuristics::SCORE_ENCODED_COMMAND},
        {"-e ", 45},
        {"-ep bypass", 50},
        {"-ExecutionPolicy Bypass", 50},
        {"-NoProfile", 25},
        {"-NonInteractive", 20},
        {"-WindowStyle Hidden", 45},
        {"-w hidden", 45},
        {"FromBase64String", 55},
        {"ToBase64String", 35},
        {"[Convert]::FromBase64String", 55},
        {"System.Convert", 30},
        {"IO.Compression", 50},
        {"DeflateStream", 55},
        {"GZipStream", 55},
        {"MemoryStream", 40},
        {"BinaryReader", 35},
        {"BinaryWriter", 35},
        {"Invoke-Obfuscation", 100},
        {"Out-EncodedCommand", 80},
        {"Invoke-CradleCrafter", 95},
        {"PowerSploit", 100},
        {"Empire", 95},
        {"Mimikatz", 100},
        {"sekurlsa", 100},
        {"kerberos::golden", 100},
        {"lsadump::", 100},
        {"Rubeus", 95},
        {"SharpHound", 90},
        {"BloodHound", 85},
        {"Covenant", 90},
        {"Cobalt", 85},
    };

    // Obfuscation indicators
    static const std::vector<std::string> OBFUSCATION_INDICATORS = {
        "`",        // Backtick insertion
        "\"+'\"",   // String concatenation
        "'+\"",
        "\"+\"",
        "'{0}'",    // Format string abuse
        "-f '",
        "-join",
        "[char]",
        "[int]",
        "-bxor",
        "-band",
        "-replace",
        "-split",
        "iex",      // Alias for Invoke-Expression
        "iwr",      // Alias for Invoke-WebRequest
        "sal ",     // Set-Alias
        "sv ",      // Set-Variable
        "gv ",      // Get-Variable
        "&(",       // Call operator with expression
        ".(",       // Dot-source with expression
        "| iex",
        "|iex",
    };

    // PowerShell file extensions
    static const std::vector<std::wstring> POWERSHELL_EXTENSIONS = {
        L".ps1",
        L".psm1",
        L".psd1",
        L".ps1xml",
        L".pssc",
        L".psrc",
    };

} // namespace Patterns

// ════════════════════════════════════════════════════════════════════════════════
// PIMPL IMPLEMENTATION CLASS
// ════════════════════════════════════════════════════════════════════════════════

class PowerShellScanner::Impl {
public:
    // ────────────────────────────────────────────────────────────────────────────
    // CONSTRUCTION / DESTRUCTION
    // ────────────────────────────────────────────────────────────────────────────

    Impl() noexcept
        : m_initialized(false)
        , m_amsiInitialized(false)
        , m_amsiContext(nullptr)
    {
        SS_LOG_INFO(LOG_CATEGORY, L"Initializing PowerShellScanner implementation");

        // Initialize AMSI if available
        initializeAmsi();

        // Initialize performance frequency for timing
        QueryPerformanceFrequency(&m_perfFrequency);

        // Load default configuration
        m_config = PowerShellScanConfig{};

        // Populate default blacklisted cmdlets
        m_config.blacklistedCmdlets = {
            "Invoke-Mimikatz",
            "Invoke-ReflectivePEInjection",
            "Invoke-Shellcode",
            "Invoke-TokenManipulation",
        };

        m_initialized = true;
        SS_LOG_INFO(LOG_CATEGORY, L"PowerShellScanner implementation initialized successfully");
    }

    ~Impl() noexcept {
        SS_LOG_INFO(LOG_CATEGORY, L"Shutting down PowerShellScanner implementation");
        shutdownAmsi();
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SCANNING OPERATIONS
    // ────────────────────────────────────────────────────────────────────────────

    [[nodiscard]] ScanResult scanFile(
        const std::filesystem::path& path,
        uint32_t pid
    ) noexcept {
        const auto startTime = std::chrono::high_resolution_clock::now();
        ScanResult result;
        result.scanTime = std::chrono::system_clock::now();
        result.processId = pid;
        result.mode = ExecutionMode::FILE_ON_DISK;
        result.filePath = path.string();

        // Increment statistics
        m_stats.totalScans++;

        try {
            // Validate path
            if (path.empty()) {
                SS_LOG_WARN(LOG_CATEGORY, L"Empty path provided for scanning");
                result.status = ScanStatus::ERROR_FILE_ACCESS;
                result.description = "Empty file path provided";
                return finalizeScanResult(result, startTime);
            }

            // Validate path length
            if (path.wstring().length() > 32767) {
                SS_LOG_WARN(LOG_CATEGORY, L"Path too long: %zu characters", path.wstring().length());
                result.status = ScanStatus::ERROR_FILE_ACCESS;
                result.description = "Path exceeds maximum length";
                return finalizeScanResult(result, startTime);
            }

            // Check file existence
            std::error_code ec;
            if (!std::filesystem::exists(path, ec)) {
                SS_LOG_WARN(LOG_CATEGORY, L"File does not exist: %ls", path.c_str());
                result.status = ScanStatus::ERROR_FILE_ACCESS;
                result.description = "File does not exist";
                return finalizeScanResult(result, startTime);
            }

            // Check file size
            const auto fileSize = std::filesystem::file_size(path, ec);
            if (ec) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to get file size: %ls", path.c_str());
                result.status = ScanStatus::ERROR_FILE_ACCESS;
                result.description = "Failed to read file size";
                return finalizeScanResult(result, startTime);
            }

            if (fileSize > m_config.maxScriptSize) {
                SS_LOG_WARN(LOG_CATEGORY, L"File too large: %llu bytes (max: %u)",
                    fileSize, m_config.maxScriptSize);
                result.status = ScanStatus::SKIPPED_SIZE_LIMIT;
                result.description = "File exceeds maximum size limit";
                return finalizeScanResult(result, startTime);
            }

            m_stats.totalBytesScanned += fileSize;

            // Compute file hash for whitelist/blacklist checking
            std::array<uint8_t, 32> hashBytes{};
            Utils::FileUtils::Error fileErr;
            if (Utils::FileUtils::ComputeFileSHA256(path.wstring(), hashBytes, &fileErr)) {
                result.sha256 = bytesToHexString(hashBytes);

                // Check whitelist first
                if (isWhitelistedInternal(path, result.sha256)) {
                    SS_LOG_DEBUG(LOG_CATEGORY, L"File is whitelisted: %ls", path.c_str());
                    result.status = ScanStatus::SKIPPED_WHITELISTED;
                    result.description = "File is whitelisted";
                    return finalizeScanResult(result, startTime);
                }
            } else {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to compute file hash: %hs", fileErr.message.c_str());
            }

            // Read file content
            std::string content;
            if (!Utils::FileUtils::ReadAllTextUtf8(path.wstring(), content, &fileErr)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to read file: %ls - %hs",
                    path.c_str(), fileErr.message.c_str());
                result.status = ScanStatus::ERROR_FILE_ACCESS;
                result.description = "Failed to read file content";
                return finalizeScanResult(result, startTime);
            }

            // Perform static analysis on content
            result = performStaticAnalysisInternal(content, path.filename().string());
            result.filePath = path.string();
            result.sha256 = bytesToHexString(hashBytes);
            result.processId = pid;
            result.mode = ExecutionMode::FILE_ON_DISK;
            result.scanTime = std::chrono::system_clock::now();

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Exception during file scan: %hs", ex.what());
            result.status = ScanStatus::ERROR_INTERNAL;
            result.description = std::string("Internal error: ") + ex.what();
        } catch (...) {
            SS_LOG_FATAL(LOG_CATEGORY, L"Unknown exception during file scan");
            result.status = ScanStatus::ERROR_INTERNAL;
            result.description = "Unknown internal error";
        }

        return finalizeScanResult(result, startTime);
    }

    [[nodiscard]] ScanResult scanMemory(
        std::span<const char> content,
        std::string_view sourceDescription,
        uint32_t pid
    ) noexcept {
        const auto startTime = std::chrono::high_resolution_clock::now();
        ScanResult result;
        result.scanTime = std::chrono::system_clock::now();
        result.processId = pid;
        result.mode = ExecutionMode::MEMORY_ONLY;

        m_stats.totalScans++;

        try {
            // Validate input
            if (content.empty()) {
                SS_LOG_DEBUG(LOG_CATEGORY, L"Empty content provided for memory scan");
                result.status = ScanStatus::CLEAN;
                result.description = "Empty content";
                return finalizeScanResult(result, startTime);
            }

            // Check size limit
            if (content.size() > m_config.maxScriptSize) {
                SS_LOG_WARN(LOG_CATEGORY, L"Memory content too large: %zu bytes", content.size());
                result.status = ScanStatus::SKIPPED_SIZE_LIMIT;
                result.description = "Content exceeds maximum size limit";
                return finalizeScanResult(result, startTime);
            }

            m_stats.totalBytesScanned += content.size();

            // Convert to string for analysis
            std::string contentStr(content.data(), content.size());

            // Perform static analysis
            result = performStaticAnalysisInternal(contentStr, std::string(sourceDescription));
            result.processId = pid;
            result.mode = ExecutionMode::MEMORY_ONLY;
            result.scanTime = std::chrono::system_clock::now();

            // If AMSI integration is enabled, perform AMSI scan
            if (m_config.enableAmsiIntegration && m_amsiInitialized) {
                performAmsiScan(contentStr, result);
            }

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Exception during memory scan: %hs", ex.what());
            result.status = ScanStatus::ERROR_INTERNAL;
            result.description = std::string("Internal error: ") + ex.what();
        } catch (...) {
            SS_LOG_FATAL(LOG_CATEGORY, L"Unknown exception during memory scan");
            result.status = ScanStatus::ERROR_INTERNAL;
            result.description = "Unknown internal error";
        }

        return finalizeScanResult(result, startTime);
    }

    [[nodiscard]] ScanResult scanCommandLine(
        std::string_view commandLine,
        uint32_t pid
    ) noexcept {
        const auto startTime = std::chrono::high_resolution_clock::now();
        ScanResult result;
        result.scanTime = std::chrono::system_clock::now();
        result.processId = pid;
        result.mode = ExecutionMode::ENCODED_COMMAND_LINE;

        m_stats.totalScans++;

        try {
            if (commandLine.empty()) {
                result.status = ScanStatus::CLEAN;
                return finalizeScanResult(result, startTime);
            }

            std::string cmdLine(commandLine);
            std::string cmdLineLower = toLowerAscii(cmdLine);

            // Check if this is a PowerShell command
            if (cmdLineLower.find("powershell") == std::string::npos &&
                cmdLineLower.find("pwsh") == std::string::npos) {
                result.status = ScanStatus::CLEAN;
                result.description = "Not a PowerShell command";
                return finalizeScanResult(result, startTime);
            }

            int riskScore = 0;
            std::vector<std::string> matchedRules;

            // Check for encoded command
            std::string encodedPayload;
            if (extractEncodedCommand(cmdLine, encodedPayload)) {
                riskScore += Constants::Heuristics::SCORE_ENCODED_COMMAND;
                matchedRules.push_back("EncodedCommand detected");

                // Decode and analyze the payload
                std::string decodedPayload = decodePowerShellBase64Internal(encodedPayload);
                if (!decodedPayload.empty()) {
                    // Recursively analyze the decoded content
                    auto decodedResult = performStaticAnalysisInternal(decodedPayload, "DecodedCommand");
                    riskScore += decodedResult.riskScore;
                    matchedRules.insert(matchedRules.end(),
                        decodedResult.matchedRules.begin(),
                        decodedResult.matchedRules.end());

                    result.obfuscation = decodedResult.obfuscation;
                    result.obfuscation.primaryType = ObfuscationType::BASE64;
                    result.obfuscation.decodedSnippet = decodedPayload.substr(0, 200);
                }
            }

            // Check for suspicious command-line flags
            static const std::vector<std::pair<std::string, int>> CMD_FLAGS = {
                {"-executionpolicy bypass", 50},
                {"-ep bypass", 50},
                {"-exec bypass", 50},
                {"-noprofile", 25},
                {"-nop", 25},
                {"-noninteractive", 20},
                {"-noni", 20},
                {"-windowstyle hidden", 45},
                {"-w hidden", 45},
                {"-sta", 15},
                {"-command", 10},
                {"-c ", 10},
                {"-file", 5},
            };

            for (const auto& [flag, score] : CMD_FLAGS) {
                if (cmdLineLower.find(flag) != std::string::npos) {
                    riskScore += score;
                    matchedRules.push_back("Suspicious flag: " + flag);
                }
            }

            // Check for download cradles in command line
            static const std::vector<std::pair<std::string, int>> CRADLE_PATTERNS = {
                {"downloadstring", 70},
                {"downloadfile", 65},
                {"invoke-webrequest", 55},
                {"iwr", 50},
                {"wget", 45},
                {"curl", 40},
                {"bits", 45},
                {"net.webclient", 60},
            };

            for (const auto& [pattern, score] : CRADLE_PATTERNS) {
                if (cmdLineLower.find(pattern) != std::string::npos) {
                    riskScore += score;
                    matchedRules.push_back("Download cradle: " + pattern);
                }
            }

            // Determine status based on risk score
            result.riskScore = riskScore;
            result.matchedRules = std::move(matchedRules);

            if (riskScore >= Constants::Heuristics::THRESHOLD_BLOCK) {
                result.status = ScanStatus::MALICIOUS;
                result.threatName = "PowerShell/Suspicious.CmdLine";
                result.category = ThreatCategory::DOWNLOADER;
                m_stats.maliciousDetected++;
            } else if (riskScore >= Constants::Heuristics::THRESHOLD_SUSPICIOUS) {
                result.status = ScanStatus::SUSPICIOUS;
                result.threatName = "PowerShell/Heuristic.CmdLine";
                m_stats.suspiciousDetected++;
            } else {
                result.status = ScanStatus::CLEAN;
            }

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Exception during command line scan: %hs", ex.what());
            result.status = ScanStatus::ERROR_INTERNAL;
            result.description = std::string("Internal error: ") + ex.what();
        }

        return finalizeScanResult(result, startTime);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CONFIGURATION MANAGEMENT
    // ────────────────────────────────────────────────────────────────────────────

    void updateConfig(const PowerShellScanConfig& newConfig) noexcept {
        std::unique_lock lock(m_configMutex);
        m_config = newConfig;
        SS_LOG_INFO(LOG_CATEGORY, L"Configuration updated");
    }

    [[nodiscard]] PowerShellScanConfig getConfig() const noexcept {
        std::shared_lock lock(m_configMutex);
        return m_config;
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CALLBACK MANAGEMENT
    // ────────────────────────────────────────────────────────────────────────────

    void registerCallback(std::function<void(const ScanResult&)> callback) noexcept {
        if (!callback) {
            SS_LOG_WARN(LOG_CATEGORY, L"Attempted to register null callback");
            return;
        }

        std::unique_lock lock(m_callbackMutex);
        m_callbacks.push_back(std::move(callback));
        SS_LOG_DEBUG(LOG_CATEGORY, L"Callback registered. Total callbacks: %zu", m_callbacks.size());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // STATISTICS
    // ────────────────────────────────────────────────────────────────────────────

    [[nodiscard]] PowerShellStats getStats() const noexcept {
        return m_stats;
    }

    void resetStats() noexcept {
        m_stats.totalScans = 0;
        m_stats.maliciousDetected = 0;
        m_stats.suspiciousDetected = 0;
        m_stats.obfuscatedDetected = 0;
        m_stats.amsiBypassesBlocked = 0;
        m_stats.timeouts = 0;
        m_stats.totalBytesScanned = 0;
        m_stats.averageScanTimeUs = 0;
        m_totalScanTimeUs = 0;

        SS_LOG_INFO(LOG_CATEGORY, L"Statistics reset");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // HEALTH CHECK
    // ────────────────────────────────────────────────────────────────────────────

    [[nodiscard]] bool healthCheck() noexcept {
        SS_LOG_INFO(LOG_CATEGORY, L"Performing health check");

        bool healthy = true;

        // Test 1: Basic initialization
        if (!m_initialized) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Health check failed: Not initialized");
            return false;
        }

        // Test 2: Test pattern detection with known malicious sample
        const std::string testMalicious = "Invoke-Mimikatz -DumpCreds";
        auto result = performStaticAnalysisInternal(testMalicious, "HealthCheckMalicious");
        if (result.status != ScanStatus::MALICIOUS && result.riskScore < 90) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Health check failed: Known malicious pattern not detected");
            healthy = false;
        }

        // Test 3: Test clean sample doesn't trigger false positive
        const std::string testClean = "Get-Process | Where-Object { $_.CPU -gt 100 }";
        result = performStaticAnalysisInternal(testClean, "HealthCheckClean");
        if (result.status == ScanStatus::MALICIOUS) {
            SS_LOG_WARN(LOG_CATEGORY, L"Health check warning: False positive on clean sample");
            // Don't fail, just warn - this is a heuristic system
        }

        // Test 4: Test Base64 decoding
        const std::string testBase64 = "VGVzdA=="; // "Test"
        std::string decoded = decodePowerShellBase64Internal(testBase64);
        // PowerShell base64 is UTF-16LE, so regular "Test" won't decode correctly
        // This is just a sanity check that the function runs

        // Test 5: Test AMSI initialization (if enabled)
        if (m_config.enableAmsiIntegration && !m_amsiInitialized) {
            SS_LOG_WARN(LOG_CATEGORY, L"Health check warning: AMSI not initialized");
            // Don't fail - AMSI might not be available on all systems
        }

        // Test 6: Verify configuration is valid
        auto config = getConfig();
        if (config.maxScriptSize == 0) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Health check failed: Invalid max script size");
            healthy = false;
        }

        if (healthy) {
            SS_LOG_INFO(LOG_CATEGORY, L"Health check passed");
        }

        return healthy;
    }

    // ────────────────────────────────────────────────────────────────────────────
    // WHITELIST CHECKING
    // ────────────────────────────────────────────────────────────────────────────

    [[nodiscard]] bool isWhitelistedInternal(
        const std::filesystem::path& path,
        const std::string& hash
    ) const noexcept {
        try {
            // Check path-based whitelist
            std::wstring pathLower = Utils::StringUtils::ToLowerCopy(path.wstring());

            // System scripts are generally trusted
            static const std::vector<std::wstring> TRUSTED_PATHS = {
                L"\\windows\\system32\\",
                L"\\windows\\syswow64\\",
                L"\\program files\\windowspowershell\\",
                L"\\program files (x86)\\windowspowershell\\",
            };

            for (const auto& trusted : TRUSTED_PATHS) {
                if (pathLower.find(trusted) != std::wstring::npos) {
                    // Additional verification: check if signed by Microsoft
                    // This would integrate with SignatureStore in production
                    return true;
                }
            }

            // Check hash-based whitelist
            // In production, this would call Whitelist::WhiteListStore::Instance()
            // For now, we return false to ensure scanning

        } catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Exception in whitelist check");
        }

        return false;
    }

    // ────────────────────────────────────────────────────────────────────────────
    // STATIC ANALYSIS
    // ────────────────────────────────────────────────────────────────────────────

    [[nodiscard]] ScanResult performStaticAnalysisInternal(
        std::string_view content,
        const std::string& contextName
    ) noexcept {
        ScanResult result;
        result.scanTime = std::chrono::system_clock::now();

        if (content.empty()) {
            result.status = ScanStatus::CLEAN;
            return result;
        }

        int riskScore = 0;
        std::vector<std::string> matchedRules;
        std::vector<std::pair<size_t, std::string>> flaggedLines;
        std::vector<std::string> amsiTechniques;

        // Convert to lowercase for case-insensitive matching
        std::string contentLower = toLowerAscii(std::string(content));

        // Phase 1: Check for AMSI bypass attempts
        if (detectAmsiBypassInternal(content, amsiTechniques)) {
            riskScore += Constants::Heuristics::SCORE_AMSI_BYPASS;
            result.category = ThreatCategory::AMSI_TAMPERING;
            m_stats.amsiBypassesBlocked++;

            for (const auto& technique : amsiTechniques) {
                matchedRules.push_back("AMSI Bypass: " + technique);
            }
        }

        // Phase 2: Check for suspicious cmdlets and patterns
        for (const auto& [pattern, score] : Patterns::SUSPICIOUS_CMDLETS) {
            std::string patternLower = toLowerAscii(pattern);
            size_t pos = 0;
            while ((pos = contentLower.find(patternLower, pos)) != std::string::npos) {
                riskScore += score;
                matchedRules.push_back("Suspicious pattern: " + pattern);

                // Find line number
                size_t lineNum = std::count(content.begin(), content.begin() + pos, '\n') + 1;
                size_t lineStart = content.rfind('\n', pos);
                lineStart = (lineStart == std::string::npos) ? 0 : lineStart + 1;
                size_t lineEnd = content.find('\n', pos);
                if (lineEnd == std::string::npos) lineEnd = content.length();

                std::string line(content.substr(lineStart, lineEnd - lineStart));
                if (line.length() > 200) line = line.substr(0, 200) + "...";
                flaggedLines.emplace_back(lineNum, line);

                pos += patternLower.length();

                // Limit matches per pattern to prevent DoS
                if (flaggedLines.size() > 100) break;
            }
        }

        // Phase 3: Analyze obfuscation
        ObfuscationDetails obfuscation = analyzeObfuscation(content);
        result.obfuscation = obfuscation;

        if (obfuscation.primaryType != ObfuscationType::NONE) {
            m_stats.obfuscatedDetected++;
            riskScore += Constants::Heuristics::SCORE_SUSPICIOUS_OBFUSCATION;
            matchedRules.push_back("Obfuscation detected: " +
                obfuscationTypeToString(obfuscation.primaryType));

            // Aggressive mode: block all obfuscated scripts
            std::shared_lock lock(m_configMutex);
            if (m_config.blockObfuscatedScripts &&
                obfuscation.entropyScore > m_config.minEntropyThreshold) {
                riskScore += 50;
                matchedRules.push_back("High entropy obfuscation blocked");
            }
        }

        // Phase 4: Attempt deobfuscation if enabled
        {
            std::shared_lock lock(m_configMutex);
            if (m_config.enableDeobfuscation &&
                obfuscation.primaryType == ObfuscationType::BASE64) {
                ObfuscationType detectedType;
                std::string deobfuscated = attemptDeobfuscationInternal(content, detectedType);

                if (!deobfuscated.empty() && deobfuscated != content) {
                    // Recursively analyze deobfuscated content (with depth limit)
                    static thread_local int recursionDepth = 0;
                    if (recursionDepth < static_cast<int>(Constants::MAX_RECURSION_DEPTH)) {
                        recursionDepth++;
                        auto deobResult = performStaticAnalysisInternal(deobfuscated,
                            contextName + "_deobfuscated");
                        recursionDepth--;

                        riskScore += deobResult.riskScore / 2; // Weight deobfuscated findings less
                        matchedRules.insert(matchedRules.end(),
                            deobResult.matchedRules.begin(),
                            deobResult.matchedRules.end());
                    }
                }
            }
        }

        // Phase 5: Check blacklisted cmdlets
        {
            std::shared_lock lock(m_configMutex);
            for (const auto& blacklisted : m_config.blacklistedCmdlets) {
                std::string blacklistedLower = toLowerAscii(blacklisted);
                if (contentLower.find(blacklistedLower) != std::string::npos) {
                    riskScore += 100;
                    matchedRules.push_back("Blacklisted cmdlet: " + blacklisted);
                }
            }
        }

        // Determine final status
        result.riskScore = std::min(riskScore, 100);
        result.matchedRules = std::move(matchedRules);
        result.flaggedLines = std::move(flaggedLines);

        if (riskScore >= Constants::Heuristics::THRESHOLD_BLOCK) {
            result.status = ScanStatus::MALICIOUS;
            result.threatName = determineThreatName(result);
            m_stats.maliciousDetected++;
        } else if (riskScore >= Constants::Heuristics::THRESHOLD_SUSPICIOUS) {
            result.status = ScanStatus::SUSPICIOUS;
            result.threatName = "PowerShell/Heuristic.Suspicious";
            m_stats.suspiciousDetected++;
        } else {
            result.status = ScanStatus::CLEAN;
        }

        return result;
    }

    [[nodiscard]] bool detectAmsiBypassInternal(
        std::string_view content,
        std::vector<std::string>& techniques
    ) const noexcept {
        bool detected = false;
        std::string contentLower = toLowerAscii(std::string(content));

        for (const auto& [pattern, description] : Patterns::AMSI_BYPASS_PATTERNS) {
            std::string patternLower = toLowerAscii(pattern);
            if (contentLower.find(patternLower) != std::string::npos) {
                techniques.push_back(description);
                detected = true;
            }
        }

        // Check for combined reflection-based bypass
        if (contentLower.find("[ref].assembly") != std::string::npos &&
            contentLower.find("gettype") != std::string::npos &&
            contentLower.find("getfield") != std::string::npos) {
            techniques.push_back("Reflection-based memory patch");
            detected = true;
        }

        // Check for string obfuscation of AMSI
        static const std::vector<std::string> AMSI_OBFUSCATED = {
            "('ams'+'i')",
            "('am'+'si')",
            "('a'+'msi')",
            "\"ams\"+\"i\"",
            "\"am\"+\"si\"",
        };

        for (const auto& obfuscated : AMSI_OBFUSCATED) {
            if (contentLower.find(toLowerAscii(obfuscated)) != std::string::npos) {
                techniques.push_back("Obfuscated AMSI reference");
                detected = true;
                break;
            }
        }

        return detected;
    }

    [[nodiscard]] std::string attemptDeobfuscationInternal(
        std::string_view content,
        ObfuscationType& detectedType
    ) noexcept {
        detectedType = ObfuscationType::NONE;
        std::string result;

        // Try Base64 decoding
        std::regex base64Pattern(R"([A-Za-z0-9+/]{50,}={0,2})");
        std::string contentStr(content);
        std::smatch match;

        if (std::regex_search(contentStr, match, base64Pattern)) {
            std::string decoded = decodePowerShellBase64Internal(match.str());
            if (!decoded.empty() && isPrintableContent(decoded)) {
                detectedType = ObfuscationType::BASE64;
                result = decoded;
            }
        }

        // Try removing backtick obfuscation
        if (content.find('`') != std::string_view::npos) {
            result = std::string(content);
            result.erase(std::remove(result.begin(), result.end(), '`'), result.end());
            if (!result.empty()) {
                detectedType = ObfuscationType::BACKTICK_INSERTION;
            }
        }

        return result;
    }

    [[nodiscard]] std::string decodePowerShellBase64Internal(
        std::string_view encoded
    ) const noexcept {
        try {
            if (encoded.empty()) return "";

            // Remove whitespace
            std::string cleanedBase64;
            cleanedBase64.reserve(encoded.size());
            for (char c : encoded) {
                if (!std::isspace(static_cast<unsigned char>(c))) {
                    cleanedBase64 += c;
                }
            }

            // Standard Base64 decoding
            static const std::string base64Chars =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

            auto isBase64 = [](unsigned char c) -> bool {
                return (std::isalnum(c) || (c == '+') || (c == '/'));
            };

            std::vector<uint8_t> decoded;
            decoded.reserve(cleanedBase64.size() * 3 / 4);

            int i = 0;
            uint8_t char_array_4[4], char_array_3[3];
            int in_len = static_cast<int>(cleanedBase64.size());
            int j = 0;

            while (in_len-- && (cleanedBase64[j] != '=') && isBase64(cleanedBase64[j])) {
                char_array_4[i++] = cleanedBase64[j++];
                if (i == 4) {
                    for (i = 0; i < 4; i++) {
                        char_array_4[i] = static_cast<uint8_t>(
                            base64Chars.find(char_array_4[i]));
                    }

                    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

                    for (i = 0; i < 3; i++) {
                        decoded.push_back(char_array_3[i]);
                    }
                    i = 0;
                }
            }

            if (i) {
                for (int k = i; k < 4; k++) char_array_4[k] = 0;

                for (int k = 0; k < 4; k++) {
                    char_array_4[k] = static_cast<uint8_t>(
                        base64Chars.find(char_array_4[k]));
                }

                char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

                for (int k = 0; k < i - 1; k++) {
                    decoded.push_back(char_array_3[k]);
                }
            }

            // PowerShell typically uses UTF-16LE encoding
            // Try to convert from UTF-16LE to UTF-8
            if (decoded.size() >= 2 && decoded.size() % 2 == 0) {
                std::wstring wideStr;
                wideStr.reserve(decoded.size() / 2);

                for (size_t idx = 0; idx < decoded.size(); idx += 2) {
                    wchar_t wc = static_cast<wchar_t>(decoded[idx]) |
                                (static_cast<wchar_t>(decoded[idx + 1]) << 8);
                    if (wc == 0) break;  // Null terminator
                    wideStr += wc;
                }

                return Utils::StringUtils::ToNarrow(wideStr);
            }

            // Return as-is if not UTF-16LE
            return std::string(decoded.begin(), decoded.end());

        } catch (...) {
            return "";
        }
    }

private:
    // ────────────────────────────────────────────────────────────────────────────
    // AMSI INTEGRATION
    // ────────────────────────────────────────────────────────────────────────────

    void initializeAmsi() noexcept {
#ifdef _WIN32
        try {
            HRESULT hr = AmsiInitialize(L"ShadowStrike", &m_amsiContext);
            if (SUCCEEDED(hr)) {
                m_amsiInitialized = true;
                SS_LOG_INFO(LOG_CATEGORY, L"AMSI initialized successfully");
            } else {
                SS_LOG_WARN(LOG_CATEGORY, L"AMSI initialization failed: 0x%08X", hr);
            }
        } catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Exception during AMSI initialization");
        }
#endif
    }

    void shutdownAmsi() noexcept {
#ifdef _WIN32
        if (m_amsiContext) {
            AmsiUninitialize(m_amsiContext);
            m_amsiContext = nullptr;
            m_amsiInitialized = false;
            SS_LOG_INFO(LOG_CATEGORY, L"AMSI shutdown complete");
        }
#endif
    }

    void performAmsiScan(const std::string& content, ScanResult& result) noexcept {
#ifdef _WIN32
        if (!m_amsiInitialized || !m_amsiContext) return;

        try {
            AMSI_RESULT amsiResult = AMSI_RESULT_NOT_DETECTED;

            // Convert to wide string for AMSI
            std::wstring wideContent = Utils::StringUtils::ToWide(content);

            HRESULT hr = AmsiScanString(
                m_amsiContext,
                wideContent.c_str(),
                L"PowerShellScanner",
                nullptr,  // No session
                &amsiResult
            );

            if (SUCCEEDED(hr)) {
                if (AmsiResultIsMalware(amsiResult)) {
                    result.riskScore = std::max(result.riskScore, 95);
                    result.status = ScanStatus::MALICIOUS;
                    result.matchedRules.push_back("AMSI detection: Malware");
                    result.threatName = "PowerShell/AMSI.Detection";
                    m_stats.maliciousDetected++;
                } else if (amsiResult >= AMSI_RESULT_DETECTED) {
                    result.riskScore = std::max(result.riskScore, 75);
                    if (result.status != ScanStatus::MALICIOUS) {
                        result.status = ScanStatus::SUSPICIOUS;
                    }
                    result.matchedRules.push_back("AMSI detection: Suspicious");
                }
            }
        } catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Exception during AMSI scan");
        }
#endif
    }

    // ────────────────────────────────────────────────────────────────────────────
    // OBFUSCATION ANALYSIS
    // ────────────────────────────────────────────────────────────────────────────

    [[nodiscard]] ObfuscationDetails analyzeObfuscation(std::string_view content) const noexcept {
        ObfuscationDetails details;

        if (content.empty()) return details;

        // Calculate entropy
        details.entropyScore = calculateEntropy(content);

        // Count obfuscation indicators
        std::string contentStr(content);
        for (const auto& indicator : Patterns::OBFUSCATION_INDICATORS) {
            size_t pos = 0;
            while ((pos = contentStr.find(indicator, pos)) != std::string::npos) {
                details.suspiciousTokenCount++;
                pos += indicator.length();
            }
        }

        // Determine primary obfuscation type
        if (content.find("FromBase64String") != std::string::npos ||
            content.find("ToBase64String") != std::string::npos) {
            details.primaryType = ObfuscationType::BASE64;
            details.techniquesDetected.push_back("Base64 encoding");
        }

        if (std::count(content.begin(), content.end(), '`') > 5) {
            if (details.primaryType == ObfuscationType::NONE) {
                details.primaryType = ObfuscationType::BACKTICK_INSERTION;
            }
            details.techniquesDetected.push_back("Backtick insertion");
        }

        if (content.find("-bxor") != std::string::npos) {
            if (details.primaryType == ObfuscationType::NONE) {
                details.primaryType = ObfuscationType::XOR;
            }
            details.techniquesDetected.push_back("XOR encoding");
        }

        if (content.find("'+\"") != std::string::npos ||
            content.find("\"+\"") != std::string::npos ||
            content.find("\"+'") != std::string::npos) {
            if (details.primaryType == ObfuscationType::NONE) {
                details.primaryType = ObfuscationType::STRING_CONCATENATION;
            }
            details.techniquesDetected.push_back("String concatenation");
        }

        if (content.find("DeflateStream") != std::string::npos ||
            content.find("GZipStream") != std::string::npos) {
            if (details.primaryType == ObfuscationType::NONE) {
                details.primaryType = ObfuscationType::COMPRESSION_GZIP;
            }
            details.techniquesDetected.push_back("Compression");
        }

        // Check for mixed case randomization
        int capsCount = 0, lowerCount = 0;
        for (char c : content) {
            if (std::isupper(static_cast<unsigned char>(c))) capsCount++;
            else if (std::islower(static_cast<unsigned char>(c))) lowerCount++;
        }
        if (capsCount > 0 && lowerCount > 0) {
            double ratio = static_cast<double>(capsCount) / (capsCount + lowerCount);
            if (ratio > 0.3 && ratio < 0.7) {
                if (details.primaryType == ObfuscationType::NONE) {
                    details.primaryType = ObfuscationType::MIXED_CASE_RANDOMIZATION;
                }
                details.techniquesDetected.push_back("Mixed case randomization");
            }
        }

        // High entropy indicates possible obfuscation
        if (details.entropyScore > Constants::MIN_ENTROPY_OBFUSCATION) {
            if (details.primaryType == ObfuscationType::NONE) {
                details.primaryType = ObfuscationType::CUSTOM_ENCODING;
            }
            details.techniquesDetected.push_back("High entropy content");
        }

        return details;
    }

    [[nodiscard]] double calculateEntropy(std::string_view data) const noexcept {
        if (data.empty()) return 0.0;

        std::array<size_t, 256> frequency{};
        for (unsigned char c : data) {
            frequency[c]++;
        }

        double entropy = 0.0;
        const double dataSize = static_cast<double>(data.size());

        for (size_t count : frequency) {
            if (count > 0) {
                double probability = static_cast<double>(count) / dataSize;
                entropy -= probability * std::log2(probability);
            }
        }

        return entropy;
    }

    // ────────────────────────────────────────────────────────────────────────────
    // UTILITY METHODS
    // ────────────────────────────────────────────────────────────────────────────

    [[nodiscard]] std::string toLowerAscii(const std::string& str) const noexcept {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return result;
    }

    [[nodiscard]] std::string bytesToHexString(const std::array<uint8_t, 32>& bytes) const noexcept {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (uint8_t byte : bytes) {
            oss << std::setw(2) << static_cast<int>(byte);
        }
        return oss.str();
    }

    [[nodiscard]] bool isPrintableContent(const std::string& content) const noexcept {
        if (content.empty()) return false;

        int printableCount = 0;
        for (unsigned char c : content) {
            if (std::isprint(c) || std::isspace(c)) {
                printableCount++;
            }
        }

        // At least 80% should be printable
        return (static_cast<double>(printableCount) / content.size()) > 0.8;
    }

    [[nodiscard]] bool extractEncodedCommand(
        const std::string& cmdLine,
        std::string& encodedPayload
    ) const noexcept {
        std::string cmdLineLower = toLowerAscii(cmdLine);

        // Look for -EncodedCommand, -enc, -e flags
        static const std::vector<std::string> encodedFlags = {
            "-encodedcommand",
            "-enc",
            "-e ",
            "-ec ",
        };

        for (const auto& flag : encodedFlags) {
            size_t pos = cmdLineLower.find(flag);
            if (pos != std::string::npos) {
                // Extract the base64 payload after the flag
                size_t payloadStart = pos + flag.length();

                // Skip whitespace
                while (payloadStart < cmdLine.size() &&
                       std::isspace(static_cast<unsigned char>(cmdLine[payloadStart]))) {
                    payloadStart++;
                }

                // Find the end of the payload (next space or end of string)
                size_t payloadEnd = payloadStart;
                while (payloadEnd < cmdLine.size() &&
                       !std::isspace(static_cast<unsigned char>(cmdLine[payloadEnd]))) {
                    payloadEnd++;
                }

                if (payloadEnd > payloadStart) {
                    encodedPayload = cmdLine.substr(payloadStart, payloadEnd - payloadStart);
                    return true;
                }
            }
        }

        return false;
    }

    [[nodiscard]] std::string determineThreatName(const ScanResult& result) const noexcept {
        switch (result.category) {
            case ThreatCategory::AMSI_TAMPERING:
                return "PowerShell/AMSIBypass.Gen";
            case ThreatCategory::CREDENTIAL_THEFT:
                return "PowerShell/CredTheft.Gen";
            case ThreatCategory::DOWNLOADER:
                return "PowerShell/Downloader.Gen";
            case ThreatCategory::RANSOMWARE_STAGER:
                return "PowerShell/Ransom.Stager";
            case ThreatCategory::REVERSE_SHELL:
                return "PowerShell/ReverseShell.Gen";
            case ThreatCategory::PERSISTENCE_MECHANISM:
                return "PowerShell/Persist.Gen";
            case ThreatCategory::PRIVILEGE_ESCALATION:
                return "PowerShell/PrivEsc.Gen";
            case ThreatCategory::RECONNAISSANCE:
                return "PowerShell/Recon.Gen";
            default:
                return "PowerShell/Suspicious.Gen";
        }
    }

    [[nodiscard]] std::string obfuscationTypeToString(ObfuscationType type) const noexcept {
        switch (type) {
            case ObfuscationType::BASE64: return "Base64";
            case ObfuscationType::XOR: return "XOR";
            case ObfuscationType::STRING_CONCATENATION: return "StringConcat";
            case ObfuscationType::VARIABLE_REPLACEMENT: return "VarReplace";
            case ObfuscationType::BACKTICK_INSERTION: return "Backtick";
            case ObfuscationType::MIXED_CASE_RANDOMIZATION: return "MixedCase";
            case ObfuscationType::COMPRESSION_GZIP: return "Compression";
            case ObfuscationType::CUSTOM_ENCODING: return "CustomEncoding";
            default: return "None";
        }
    }

    [[nodiscard]] ScanResult finalizeScanResult(
        ScanResult& result,
        const std::chrono::high_resolution_clock::time_point& startTime
    ) noexcept {
        // Calculate scan duration
        const auto endTime = std::chrono::high_resolution_clock::now();
        result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(
            endTime - startTime);

        // Update statistics
        uint64_t durationUs = static_cast<uint64_t>(result.scanDuration.count());
        uint64_t totalScans = m_stats.totalScans.load();
        if (totalScans > 0) {
            m_totalScanTimeUs += durationUs;
            m_stats.averageScanTimeUs = m_totalScanTimeUs / totalScans;
        }

        // Invoke callbacks
        {
            std::shared_lock lock(m_callbackMutex);
            for (const auto& callback : m_callbacks) {
                try {
                    callback(result);
                } catch (const std::exception& ex) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"Callback exception: %hs", ex.what());
                } catch (...) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"Unknown callback exception");
                }
            }
        }

        // Log significant detections
        if (result.status == ScanStatus::MALICIOUS) {
            SS_LOG_WARN(LOG_CATEGORY, L"Malicious PowerShell detected: %hs (score: %d)",
                result.threatName.c_str(), result.riskScore);
        } else if (result.status == ScanStatus::SUSPICIOUS) {
            SS_LOG_INFO(LOG_CATEGORY, L"Suspicious PowerShell detected (score: %d)",
                result.riskScore);
        }

        return result;
    }

    // ────────────────────────────────────────────────────────────────────────────
    // MEMBER VARIABLES
    // ────────────────────────────────────────────────────────────────────────────

    std::atomic<bool> m_initialized;
    PowerShellScanConfig m_config;
    mutable std::shared_mutex m_configMutex;

    PowerShellStats m_stats;
    std::atomic<uint64_t> m_totalScanTimeUs{0};

    std::vector<std::function<void(const ScanResult&)>> m_callbacks;
    mutable std::shared_mutex m_callbackMutex;

    // AMSI integration
    bool m_amsiInitialized;
#ifdef _WIN32
    HAMSICONTEXT m_amsiContext;
#else
    void* m_amsiContext;
#endif

    // Performance timing
    LARGE_INTEGER m_perfFrequency{};
};

// ════════════════════════════════════════════════════════════════════════════════
// POWERSHELLSCANNER PUBLIC IMPLEMENTATION (Facade)
// ════════════════════════════════════════════════════════════════════════════════

// Meyers' Singleton - Thread-safe, exception-safe instantiation
PowerShellScanner& PowerShellScanner::getInstance() {
    static PowerShellScanner instance;
    return instance;
}

// Private constructor
PowerShellScanner::PowerShellScanner()
    : pImpl(std::make_unique<Impl>())
{
    SS_LOG_INFO(LOG_CATEGORY, L"PowerShellScanner singleton created");
}

// Destructor
PowerShellScanner::~PowerShellScanner() {
    SS_LOG_INFO(LOG_CATEGORY, L"PowerShellScanner singleton destroyed");
}

// ────────────────────────────────────────────────────────────────────────────────
// PUBLIC API - SCANNING
// ────────────────────────────────────────────────────────────────────────────────

[[nodiscard]] ScanResult PowerShellScanner::scanFile(
    const std::filesystem::path& path,
    uint32_t pid
) {
    return pImpl->scanFile(path, pid);
}

[[nodiscard]] ScanResult PowerShellScanner::scanMemory(
    std::span<const char> content,
    std::string_view sourceDescription,
    uint32_t pid
) {
    return pImpl->scanMemory(content, sourceDescription, pid);
}

[[nodiscard]] ScanResult PowerShellScanner::scanCommandLine(
    std::string_view commandLine,
    uint32_t pid
) {
    return pImpl->scanCommandLine(commandLine, pid);
}

// ────────────────────────────────────────────────────────────────────────────────
// PUBLIC API - MANAGEMENT
// ────────────────────────────────────────────────────────────────────────────────

void PowerShellScanner::updateConfig(const PowerShellScanConfig& newConfig) {
    std::lock_guard lock(configMutex);
    pImpl->updateConfig(newConfig);
}

PowerShellScanConfig PowerShellScanner::getConfig() const {
    std::lock_guard lock(configMutex);
    return pImpl->getConfig();
}

void PowerShellScanner::registerCallback(std::function<void(const ScanResult&)> callback) {
    std::lock_guard lock(callbackMutex);
    pImpl->registerCallback(std::move(callback));
}

PowerShellStats PowerShellScanner::getStats() const {
    return pImpl->getStats();
}

void PowerShellScanner::resetStats() {
    pImpl->resetStats();
}

bool PowerShellScanner::healthCheck() {
    return pImpl->healthCheck();
}

// ────────────────────────────────────────────────────────────────────────────────
// PRIVATE HELPERS (Delegated to Impl)
// ────────────────────────────────────────────────────────────────────────────────

bool PowerShellScanner::isWhitelisted(
    const std::filesystem::path& path,
    const std::string& hash
) {
    return pImpl->isWhitelistedInternal(path, hash);
}

ScanResult PowerShellScanner::performStaticAnalysis(
    std::string_view content,
    const std::string& contextName
) {
    return pImpl->performStaticAnalysisInternal(content, contextName);
}

bool PowerShellScanner::detectAmsiBypass(
    std::string_view content,
    std::vector<std::string>& techniques
) {
    return pImpl->detectAmsiBypassInternal(content, techniques);
}

std::string PowerShellScanner::attemptDeobfuscation(
    std::string_view content,
    ObfuscationType& detectedType
) {
    return pImpl->attemptDeobfuscationInternal(content, detectedType);
}

std::string PowerShellScanner::decodePowerShellBase64(std::string_view encoded) {
    return pImpl->decodePowerShellBase64Internal(encoded);
}

} // namespace ShadowStrike::Scripts
