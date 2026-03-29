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
 * File: PowerShellScanner.cpp
 * Description:
 *      Enterprise-grade PowerShell script analysis engine — detects nation-state
 *      APT PowerShell abuse including AMSI bypass, v2 downgrade, encoded
 *      commands, download cradles, reflective PE loading, Mimikatz, shellcode
 *      injection, WMI persistence, and multi-layer obfuscation.
 *
 * Version: 4.0.0 Enterprise Edition
 * Author: ShadowStrike Advanced Threat Research Team
 * ════════════════════════════════════════════════════════════════════════════════
 */

#include "pch.h"
#include "PowerShellScanner.hpp"

#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/Base64Utils.hpp"
#include "../SignatureStore/SignatureStore.hpp"
#include "../Whitelist/WhiteListStore.hpp"
#include "../Communication/IPCManager.hpp"
#include "AMSIIntegration.hpp"

#ifdef _WIN32
#include <amsi.h>
#pragma comment(lib, "amsi.lib")
#endif

#include <sstream>
#include <iomanip>
#include <cctype>
#include <cmath>
#include <algorithm>
#include <numeric>

namespace ShadowStrike::Scripts {

// ════════════════════════════════════════════════════════════════════════════════
// LOGGING
// ════════════════════════════════════════════════════════════════════════════════

namespace {
    constexpr const wchar_t* LOG_CAT = L"PowerShellScanner";
}

// ════════════════════════════════════════════════════════════════════════════════
// STATIC PATTERN TABLES — Substring-match only, zero regex on hot path.
//
// Every pattern is stored as lowercase for O(1) comparison against
// a pre-lowered copy of attacker content.  No std::regex is ever used
// on attacker-controlled data (eliminates ReDoS entirely).
// ════════════════════════════════════════════════════════════════════════════════

namespace Patterns {

// ── AMSI bypass strings (case-insensitive via lowered copy) ──────────────────
struct TaggedPattern {
    const char* text;
    const char* description;
};

static constexpr TaggedPattern AMSI_BYPASS_PATTERNS[] = {
    {"amsiscanbuffer",                                "AMSI ScanBuffer patch"},
    {"amsiInitfailed",                                "amsiInitFailed bypass"},
    {"amsicontext",                                   "AMSI context manipulation"},
    {"amsisession",                                   "AMSI session manipulation"},
    {"amsiutils",                                     "AmsiUtils reflection bypass"},
    {"amsi.dll",                                      "AMSI DLL manipulation"},
    {"setprotectedeventlogging",                      "Event logging bypass"},
    {"system.management.automation.amsiutils",        "Full reflection AMSI bypass"},
    {"[ref].assembly.gettype",                        "Reflection assembly access"},
    {"nonpublic,static",                              "Non-public member reflection"},
    {"runtime.interopservices.marshal",               "Marshal memory manipulation"},
    {"virtualprotect",                                "VirtualProtect on AMSI"},
    {"ntwritevirtualmemory",                          "NT API memory write"},
    {"etweventwrite",                                 "ETW bypass (blinding)"},
};

// Obfuscated AMSI references (string-split evasion)
static constexpr const char* AMSI_OBFUSCATED_REFS[] = {
    "('ams'+'i')",  "('am'+'si')",  "('a'+'msi')",
    "\"ams\"+\"i\"", "\"am\"+\"si\"",
    "('amsi'+'utils')", "('amsiinit'+'failed')",
};

// ── Suspicious cmdlets / API calls ───────────────────────────────────────────
struct ScoredPattern {
    const char* text;
    int         score;
};

static constexpr ScoredPattern SUSPICIOUS_CMDLETS[] = {
    {"invoke-expression",                     70},
    {"invoke-command",                        50},
    {"invoke-mimikatz",                      100},
    {"invoke-reflectivepeinjection",         100},
    {"invoke-shellcode",                     100},
    {"invoke-tokenmanipulation",              90},
    {"invoke-credentialinjection",            90},
    {"invoke-dllinjection",                   95},
    {"invoke-wmicommand",                     60},
    {"new-object net.webclient",              60},
    {"system.net.webclient",                  60},
    {"downloadstring",                        70},
    {"downloadfile",                          65},
    {"downloaddata",                          65},
    {"invoke-webrequest",                     55},
    {"start-bitstransfer",                    50},
    {"[system.reflection.assembly]::load",    90},
    {"[reflection.assembly]::load",           90},
    {"loadwithpartialname",                   80},
    {"add-type",                              40},
    {"[dllimport",                            70},
    {"getdelegateforfunctionpointer",         85},
    {"virtualalloc",                          80},
    {"createthread",                          75},
    {"openprocess",                           70},
    {"readprocessmemory",                     75},
    {"writeprocessmemory",                    85},
    {"get-credential",                        45},
    {"converttosecurestring",                 40},
    {"-encodedcommand",                       50},
    {"-enc ",                                 50},
    {"frombase64string",                      55},
    {"[convert]::frombase64string",           55},
    {"io.compression",                        50},
    {"deflatestream",                         55},
    {"gzipstream",                            55},
    {"memorystream",                          40},
    {"invoke-obfuscation",                   100},
    {"out-encodedcommand",                    80},
    {"invoke-cradlecrafter",                  95},
    {"powersploit",                          100},
    {"mimikatz",                             100},
    {"sekurlsa::",                           100},
    {"lsadump::",                            100},
    {"kerberos::golden",                     100},
    {"privilege::debug",                      95},
    {"sekurlsa::logonpasswords",             100},
    {"rubeus",                                95},
    {"sharphound",                            90},
    {"bloodhound",                            85},
    {"covenant",                              90},
    {"cobalt",                                85},
    {"-executionpolicy bypass",               50},
    {"-ep bypass",                            50},
    {"-noprofile",                            25},
    {"-noninteractive",                       20},
    {"-windowstyle hidden",                   45},
    {"-w hidden",                             45},
};

// ── Download cradle patterns ─────────────────────────────────────────────────
static constexpr ScoredPattern DOWNLOAD_CRADLES[] = {
    {"downloadstring(",                       70},
    {"downloadfile(",                         65},
    {"downloaddata(",                         65},
    {"invoke-webrequest",                     55},
    {"start-bitstransfer",                    50},
    {"net.webclient",                         60},
    {"system.net.sockets.tcpclient",          80},
    {"bitstransfer",                          50},
};

// ── Shellcode injection (P/Invoke combo) ─────────────────────────────────────
static constexpr const char* SHELLCODE_MARKERS[] = {
    "virtualalloc",
    "createthread",
    "writeprocessmemory",
    "getdelegateforfunctionpointer",
    "rtlmovememory",
    "[byte[]]",
    "0x90",
};

// ── WMI persistence ──────────────────────────────────────────────────────────
static constexpr const char* WMI_PERSISTENCE[] = {
    "set-wmiinstance",
    "__eventconsumer",
    "__eventfilter",
    "__filtertoconsumerbinding",
    "root\\subscription",
    "commandlineeventconsumer",
    "activescripteventconsumer",
};

// ── Mimikatz module commands ─────────────────────────────────────────────────
static constexpr const char* MIMIKATZ_CMDS[] = {
    "sekurlsa::logonpasswords",
    "sekurlsa::wdigest",
    "sekurlsa::kerberos",
    "lsadump::sam",
    "lsadump::dcsync",
    "lsadump::lsa",
    "privilege::debug",
    "token::elevate",
    "kerberos::golden",
    "kerberos::ptt",
};

// ── Constrained language mode bypass ─────────────────────────────────────────
static constexpr const char* CLM_BYPASS[] = {
    "$executioncontext.sessionstate.languagemode",
    "fulllanguage",
    "constrainedlanguage",
    "system.management.automation.runspaces",
    "powershell.create()",
    "[powershell]::create()",
};

// ── Reverse shell patterns ───────────────────────────────────────────────────
static constexpr const char* REVERSE_SHELL[] = {
    "system.net.sockets.tcpclient",
    "networkstream",
    "getstream()",
    "ncat",
    "nc.exe",
    "invoke-powershelltcp",
};

// ── Obfuscation indicators ──────────────────────────────────────────────────
static constexpr const char* OBFUSCATION_INDICATORS[] = {
    "'+\"",  "\"+\"",  "\"+'",
    "'{0}'", "-f '",   "-join",
    "[char]", "[int]",
    "-bxor",  "-band",
    "&(",     ".(",
    "| iex",  "|iex",
    "[scriptblock]::create",
};

// ── PowerShell file extensions ───────────────────────────────────────────────
static constexpr const wchar_t* PS_EXTENSIONS[] = {
    L".ps1", L".psm1", L".psd1", L".ps1xml", L".pssc", L".psrc",
};

} // namespace Patterns

// ════════════════════════════════════════════════════════════════════════════════
// PIMPL IMPLEMENTATION
// ════════════════════════════════════════════════════════════════════════════════

class PowerShellScanner::Impl {
public:
    // ── Lifecycle ────────────────────────────────────────────────────────────

    Impl() noexcept {
        SS_LOG_INFO(LOG_CAT, L"Initializing PowerShellScanner implementation");

        m_config.blacklistedCmdlets = {
            "Invoke-Mimikatz",
            "Invoke-ReflectivePEInjection",
            "Invoke-Shellcode",
            "Invoke-TokenManipulation",
        };

        m_initialized.store(true, std::memory_order_release);
        SS_LOG_INFO(LOG_CAT, L"PowerShellScanner initialized");
    }

    ~Impl() noexcept {
        SS_LOG_INFO(LOG_CAT, L"PowerShellScanner shutting down");
    }

    // ── scanFile ────────────────────────────────────────────────────────────

    [[nodiscard]] ScanResult scanFile(
        const std::filesystem::path& path,
        uint32_t pid
    ) noexcept {
        const auto startTime = std::chrono::high_resolution_clock::now();
        ScanResult result;
        result.scanTime  = std::chrono::system_clock::now();
        result.processId = pid;
        result.mode      = ExecutionMode::FILE_ON_DISK;
        result.filePath  = path.string();
        m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);

        try {
            if (path.empty()) {
                result.status      = ScanStatus::ERROR_FILE_ACCESS;
                result.description = "Empty file path";
                return finalize(result, startTime);
            }

            std::error_code ec;
            if (!std::filesystem::exists(path, ec) || ec) {
                result.status      = ScanStatus::ERROR_FILE_ACCESS;
                result.description = "File does not exist";
                return finalize(result, startTime);
            }

            const auto fileSize = std::filesystem::file_size(path, ec);
            if (ec) {
                result.status      = ScanStatus::ERROR_FILE_ACCESS;
                result.description = "Failed to get file size";
                return finalize(result, startTime);
            }

            const uint32_t maxSize = getConfigValue<uint32_t>([](const PowerShellScanConfig& c){ return c.maxScriptSize; });
            if (fileSize > maxSize) {
                SS_LOG_WARN(LOG_CAT, L"File too large: %llu bytes (max: %u)", fileSize, maxSize);
                result.status      = ScanStatus::SKIPPED_SIZE_LIMIT;
                result.description = "File exceeds size limit";
                return finalize(result, startTime);
            }
            m_stats.totalBytesScanned.fetch_add(fileSize, std::memory_order_relaxed);

            // Compute hash
            std::array<uint8_t, 32> hashBytes{};
            Utils::FileUtils::Error fileErr;
            if (Utils::FileUtils::ComputeFileSHA256(path.wstring(), hashBytes, &fileErr)) {
                result.sha256 = hexString(hashBytes);

                if (isWhitelisted(path, result.sha256)) {
                    result.status      = ScanStatus::SKIPPED_WHITELISTED;
                    result.description = "Whitelisted";
                    return finalize(result, startTime);
                }
            }

            // Read content
            std::string content;
            if (!Utils::FileUtils::ReadAllTextUtf8(path.wstring(), content, &fileErr)) {
                SS_LOG_ERROR(LOG_CAT, L"Failed to read file: %ls", path.c_str());
                result.status      = ScanStatus::ERROR_FILE_ACCESS;
                result.description = "Read failed";
                return finalize(result, startTime);
            }

            result = analyzeContent(content, path.filename().string(), 0);
            result.filePath  = path.string();
            result.sha256    = hexString(hashBytes);
            result.processId = pid;
            result.mode      = ExecutionMode::FILE_ON_DISK;
            result.scanTime  = std::chrono::system_clock::now();

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CAT, L"Exception in scanFile: %hs", ex.what());
            result.status      = ScanStatus::ERROR_INTERNAL;
            result.description = std::string("Internal error: ") + ex.what();
        } catch (...) {
            SS_LOG_FATAL(LOG_CAT, L"Unknown exception in scanFile");
            result.status      = ScanStatus::ERROR_INTERNAL;
            result.description = "Unknown internal error";
        }

        return finalize(result, startTime);
    }

    // ── scanMemory ──────────────────────────────────────────────────────────

    [[nodiscard]] ScanResult scanMemory(
        std::span<const char> content,
        std::string_view sourceDescription,
        uint32_t pid
    ) noexcept {
        const auto startTime = std::chrono::high_resolution_clock::now();
        ScanResult result;
        result.scanTime  = std::chrono::system_clock::now();
        result.processId = pid;
        result.mode      = ExecutionMode::MEMORY_ONLY;
        m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);

        try {
            if (content.empty()) {
                result.status = ScanStatus::CLEAN;
                return finalize(result, startTime);
            }

            const uint32_t maxSize = getConfigValue<uint32_t>([](const PowerShellScanConfig& c){ return c.maxScriptSize; });
            if (content.size() > maxSize) {
                SS_LOG_WARN(LOG_CAT, L"Memory content too large: %zu bytes", content.size());
                result.status      = ScanStatus::SKIPPED_SIZE_LIMIT;
                result.description = "Content exceeds size limit";
                return finalize(result, startTime);
            }
            m_stats.totalBytesScanned.fetch_add(content.size(), std::memory_order_relaxed);

            std::string contentStr(content.data(), content.size());
            result = analyzeContent(contentStr, std::string(sourceDescription), 0);
            result.processId = pid;
            result.mode      = ExecutionMode::MEMORY_ONLY;
            result.scanTime  = std::chrono::system_clock::now();

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CAT, L"Exception in scanMemory: %hs", ex.what());
            result.status      = ScanStatus::ERROR_INTERNAL;
            result.description = std::string("Internal error: ") + ex.what();
        } catch (...) {
            SS_LOG_FATAL(LOG_CAT, L"Unknown exception in scanMemory");
            result.status      = ScanStatus::ERROR_INTERNAL;
            result.description = "Unknown internal error";
        }

        return finalize(result, startTime);
    }

    // ── scanCommandLine ─────────────────────────────────────────────────────

    [[nodiscard]] ScanResult scanCommandLine(
        std::string_view commandLine,
        uint32_t pid
    ) noexcept {
        const auto startTime = std::chrono::high_resolution_clock::now();
        ScanResult result;
        result.scanTime  = std::chrono::system_clock::now();
        result.processId = pid;
        result.mode      = ExecutionMode::ENCODED_COMMAND_LINE;
        m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);

        try {
            if (commandLine.empty()) {
                result.status = ScanStatus::CLEAN;
                return finalize(result, startTime);
            }

            std::string cmdLower = toLower(std::string(commandLine));

            // Only scan PowerShell processes
            if (cmdLower.find("powershell") == std::string::npos &&
                cmdLower.find("pwsh") == std::string::npos) {
                result.status      = ScanStatus::CLEAN;
                result.description = "Not a PowerShell command";
                return finalize(result, startTime);
            }

            int totalScore = 0;
            std::vector<std::string> rules;

            // ── V2 DOWNGRADE DETECTION (Critical — v2 has no AMSI) ──────
            if (detectV2Downgrade(cmdLower)) {
                totalScore += Constants::Heuristics::SCORE_V2_DOWNGRADE;
                rules.push_back("PowerShell v2 downgrade attack");
                result.category = ThreatCategory::V2_DOWNGRADE;
                m_stats.v2DowngradesBlocked.fetch_add(1, std::memory_order_relaxed);

                SS_LOG_WARN(LOG_CAT,
                    L"PowerShell v2 downgrade detected PID=%u", pid);

                notifyKernelBlock(pid, "PowerShell v2 downgrade");
            }

            // ── Encoded command extraction & recursive scan ─────────────
            std::string encodedPayload;
            if (extractEncodedCommand(std::string(commandLine), encodedPayload)) {
                totalScore += Constants::Heuristics::SCORE_ENCODED_COMMAND;
                rules.push_back("EncodedCommand detected");

                std::string decoded = decodeBase64(encodedPayload);
                if (!decoded.empty()) {
                    auto inner = analyzeContent(decoded, "DecodedCommand", 0);
                    totalScore += inner.riskScore;
                    rules.insert(rules.end(),
                        inner.matchedRules.begin(), inner.matchedRules.end());
                    result.obfuscation = inner.obfuscation;
                    result.obfuscation.primaryType = ObfuscationType::BASE64;
                    result.obfuscation.decodedSnippet =
                        decoded.substr(0, std::min<size_t>(decoded.size(), 200));
                }
            }

            // ── Suspicious command-line flags ───────────────────────────
            static constexpr Patterns::ScoredPattern CMD_FLAGS[] = {
                {"-executionpolicy bypass", 50}, {"-ep bypass", 50},
                {"-exec bypass", 50},            {"-noprofile", 25},
                {"-nop", 25},                    {"-noninteractive", 20},
                {"-noni", 20},                   {"-windowstyle hidden", 45},
                {"-w hidden", 45},               {"-sta", 15},
            };

            for (const auto& [pat, score] : CMD_FLAGS) {
                if (cmdLower.find(pat) != std::string::npos) {
                    totalScore += score;
                    rules.push_back(std::string("Suspicious flag: ") + pat);
                }
            }

            // ── Download cradles ────────────────────────────────────────
            for (const auto& [pat, score] : Patterns::DOWNLOAD_CRADLES) {
                if (cmdLower.find(pat) != std::string::npos) {
                    totalScore += score;
                    rules.push_back(std::string("Download cradle: ") + pat);
                }
            }

            // ── Classify ────────────────────────────────────────────────
            result.riskScore    = std::min(totalScore, 100);
            result.matchedRules = std::move(rules);
            classifyResult(result, totalScore);

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CAT, L"Exception in scanCommandLine: %hs", ex.what());
            result.status      = ScanStatus::ERROR_INTERNAL;
            result.description = std::string("Internal error: ") + ex.what();
        }

        return finalize(result, startTime);
    }

    // ── Config / Callbacks / Stats / Health ──────────────────────────────────

    void updateConfig(const PowerShellScanConfig& cfg) noexcept {
        std::unique_lock lk(m_configMtx);
        m_config = cfg;
        SS_LOG_INFO(LOG_CAT, L"Configuration updated (maxDepth=%u, blockV2=%d)",
            cfg.maxDeobfuscationDepth, cfg.blockV2Downgrade ? 1 : 0);
    }

    [[nodiscard]] PowerShellScanConfig getConfig() const noexcept {
        std::shared_lock lk(m_configMtx);
        return m_config;
    }

    void registerCallback(std::function<void(const ScanResult&)> cb) noexcept {
        if (!cb) return;
        std::unique_lock lk(m_cbMtx);
        m_callbacks.push_back(std::move(cb));
    }

    [[nodiscard]] PowerShellStats getStats() const noexcept { return m_stats; }

    void resetStats() noexcept {
        m_stats.totalScans.store(0, std::memory_order_relaxed);
        m_stats.maliciousDetected.store(0, std::memory_order_relaxed);
        m_stats.suspiciousDetected.store(0, std::memory_order_relaxed);
        m_stats.obfuscatedDetected.store(0, std::memory_order_relaxed);
        m_stats.amsiBypassesBlocked.store(0, std::memory_order_relaxed);
        m_stats.v2DowngradesBlocked.store(0, std::memory_order_relaxed);
        m_stats.timeouts.store(0, std::memory_order_relaxed);
        m_stats.totalBytesScanned.store(0, std::memory_order_relaxed);
        m_stats.averageScanTimeUs.store(0, std::memory_order_relaxed);
        m_totalScanTimeUs.store(0, std::memory_order_relaxed);
    }

    [[nodiscard]] bool healthCheck() noexcept {
        if (!m_initialized.load(std::memory_order_acquire)) return false;

        // Known-malicious must trigger
        const std::string testMal = "Invoke-Mimikatz -DumpCreds";
        auto r1 = analyzeContent(testMal, "HC_Mal", 0);
        if (r1.riskScore < Constants::Heuristics::THRESHOLD_BLOCK) {
            SS_LOG_ERROR(LOG_CAT, L"Health check: known-malicious not detected");
            return false;
        }

        // Clean sample must not trigger
        const std::string testClean = "Get-Process | Where-Object { $_.CPU -gt 100 }";
        auto r2 = analyzeContent(testClean, "HC_Clean", 0);
        if (r2.status == ScanStatus::MALICIOUS) {
            SS_LOG_WARN(LOG_CAT, L"Health check: false positive on clean sample");
        }

        // V2 detection
        const std::string testV2 = "powershell.exe -version 2 -command test";
        auto r3 = scanCommandLine(testV2, 0);
        if (r3.category != ThreatCategory::V2_DOWNGRADE) {
            SS_LOG_ERROR(LOG_CAT, L"Health check: v2 downgrade not detected");
            return false;
        }

        SS_LOG_INFO(LOG_CAT, L"Health check passed");
        return true;
    }

private:
    // ════════════════════════════════════════════════════════════════════════
    // CORE ANALYSIS — Multi-layer, depth-limited, no regex on attacker data
    // ════════════════════════════════════════════════════════════════════════

    [[nodiscard]] ScanResult analyzeContent(
        std::string_view content,
        const std::string& contextName,
        uint32_t depth
    ) noexcept {
        ScanResult result;
        result.scanTime = std::chrono::system_clock::now();

        if (content.empty()) {
            result.status = ScanStatus::CLEAN;
            return result;
        }

        int totalScore = 0;
        std::vector<std::string> rules;
        std::vector<std::pair<size_t, std::string>> flagged;

        // ── Phase 0: Normalize — remove backticks, collapse whitespace ──
        std::string normalized = normalize(content);
        std::string normLower  = toLower(normalized);

        // ── Phase 1: AMSI bypass detection ──────────────────────────────
        std::vector<std::string> amsiTechniques;
        if (detectAmsiBypass(normLower, amsiTechniques)) {
            totalScore += Constants::Heuristics::SCORE_AMSI_BYPASS;
            result.category = ThreatCategory::AMSI_TAMPERING;
            m_stats.amsiBypassesBlocked.fetch_add(1, std::memory_order_relaxed);
            for (const auto& t : amsiTechniques) {
                rules.push_back("AMSI Bypass: " + t);
            }

            // Notify AMSIIntegration about bypass attempt
            notifyAmsiBypassDetected(result.processId, amsiTechniques);
        }

        // ── Phase 2: Suspicious cmdlet/API matching ─────────────────────
        for (const auto& [pat, score] : Patterns::SUSPICIOUS_CMDLETS) {
            if (normLower.find(pat) != std::string::npos) {
                totalScore += score;
                rules.push_back(std::string("Suspicious: ") + pat);
                addFlaggedLine(content, normLower, pat, flagged);
            }
        }

        // ── Phase 3: Mimikatz module detection ──────────────────────────
        for (const char* cmd : Patterns::MIMIKATZ_CMDS) {
            if (normLower.find(cmd) != std::string::npos) {
                totalScore += Constants::Heuristics::SCORE_MIMIKATZ;
                rules.push_back(std::string("Mimikatz: ") + cmd);
                result.category = ThreatCategory::CREDENTIAL_THEFT;
            }
        }

        // ── Phase 4: Shellcode injection combo ──────────────────────────
        {
            int shellcodeHits = 0;
            for (const char* m : Patterns::SHELLCODE_MARKERS) {
                if (normLower.find(m) != std::string::npos) ++shellcodeHits;
            }
            if (shellcodeHits >= 3) {
                totalScore += Constants::Heuristics::SCORE_SHELLCODE_INJECTION;
                rules.push_back("Shellcode injection pattern (P/Invoke combo)");
                result.category = ThreatCategory::PROCESS_INJECTION;
            }
        }

        // ── Phase 5: WMI persistence ────────────────────────────────────
        {
            int wmiHits = 0;
            for (const char* w : Patterns::WMI_PERSISTENCE) {
                if (normLower.find(w) != std::string::npos) ++wmiHits;
            }
            if (wmiHits >= 2) {
                totalScore += Constants::Heuristics::SCORE_WMI_PERSISTENCE;
                rules.push_back("WMI event subscription persistence");
                result.category = ThreatCategory::PERSISTENCE_MECHANISM;
            }
        }

        // ── Phase 6: Constrained language mode bypass ───────────────────
        for (const char* c : Patterns::CLM_BYPASS) {
            if (normLower.find(c) != std::string::npos) {
                totalScore += Constants::Heuristics::SCORE_LANGUAGE_MODE_BYPASS;
                rules.push_back(std::string("CLM bypass: ") + c);
                break;
            }
        }

        // ── Phase 7: Reverse shell ──────────────────────────────────────
        {
            int revHits = 0;
            for (const char* r : Patterns::REVERSE_SHELL) {
                if (normLower.find(r) != std::string::npos) ++revHits;
            }
            if (revHits >= 2) {
                totalScore += Constants::Heuristics::SCORE_REVERSE_SHELL;
                rules.push_back("Reverse shell pattern");
                result.category = ThreatCategory::REVERSE_SHELL;
            }
        }

        // ── Phase 8: Download cradles ───────────────────────────────────
        for (const auto& [pat, score] : Patterns::DOWNLOAD_CRADLES) {
            if (normLower.find(pat) != std::string::npos) {
                totalScore += score;
                rules.push_back(std::string("Download cradle: ") + pat);
                if (result.category == ThreatCategory::NONE)
                    result.category = ThreatCategory::DOWNLOADER;
            }
        }

        // ── Phase 9: Obfuscation analysis ───────────────────────────────
        ObfuscationDetails obf = analyzeObfuscation(content);
        result.obfuscation = obf;
        if (obf.primaryType != ObfuscationType::NONE) {
            m_stats.obfuscatedDetected.fetch_add(1, std::memory_order_relaxed);
            totalScore += Constants::Heuristics::SCORE_SUSPICIOUS_OBFUSCATION;
            rules.push_back("Obfuscation: " + obfuscationName(obf.primaryType));
        }

        // ── Phase 10: Multi-layer deobfuscation ─────────────────────────
        const uint32_t maxDepth = getConfigValue<uint32_t>(
            [](const PowerShellScanConfig& c){ return c.maxDeobfuscationDepth; });
        const bool deobfEnabled = getConfigValue<bool>(
            [](const PowerShellScanConfig& c){ return c.enableDeobfuscation; });

        if (deobfEnabled && depth < maxDepth) {
            std::string deobfuscated = deobfuscate(content);
            if (!deobfuscated.empty() && deobfuscated != content) {
                auto inner = analyzeContent(deobfuscated, contextName + "_deobf", depth + 1);
                totalScore += inner.riskScore / 2;
                rules.insert(rules.end(),
                    inner.matchedRules.begin(), inner.matchedRules.end());
            }
        }

        // ── Phase 11: Blacklisted cmdlets ───────────────────────────────
        {
            std::shared_lock lk(m_configMtx);
            for (const auto& bl : m_config.blacklistedCmdlets) {
                if (normLower.find(toLower(bl)) != std::string::npos) {
                    totalScore += 100;
                    rules.push_back("Blacklisted: " + bl);
                }
            }
        }

        // ── Classify ────────────────────────────────────────────────────
        result.riskScore    = std::min(totalScore, 100);
        result.matchedRules = std::move(rules);
        result.flaggedLines = std::move(flagged);
        classifyResult(result, totalScore);

        return result;
    }

    // ════════════════════════════════════════════════════════════════════════
    // V2 DOWNGRADE DETECTION
    // ════════════════════════════════════════════════════════════════════════

    [[nodiscard]] bool detectV2Downgrade(std::string_view cmdLower) const noexcept {
        // Matches: -version 2, -v 2, -version 2.0
        static constexpr const char* V2_FLAGS[] = {
            "-version 2", "-v 2", "-version 2.0", "-v 2.0",
        };
        for (const char* flag : V2_FLAGS) {
            auto pos = cmdLower.find(flag);
            if (pos != std::string_view::npos) {
                // Ensure the '2' is not part of a longer number
                size_t afterFlag = pos + std::string_view(flag).size();
                if (afterFlag >= cmdLower.size() ||
                    !std::isdigit(static_cast<unsigned char>(cmdLower[afterFlag]))) {
                    return true;
                }
            }
        }
        return false;
    }

    // ════════════════════════════════════════════════════════════════════════
    // AMSI BYPASS DETECTION
    // ════════════════════════════════════════════════════════════════════════

    [[nodiscard]] bool detectAmsiBypass(
        const std::string& contentLower,
        std::vector<std::string>& techniques
    ) const noexcept {
        bool detected = false;

        // Direct pattern matches
        for (const auto& [pat, desc] : Patterns::AMSI_BYPASS_PATTERNS) {
            std::string patLower = toLower(std::string(pat));
            if (contentLower.find(patLower) != std::string::npos) {
                techniques.push_back(desc);
                detected = true;
            }
        }

        // Obfuscated AMSI references (string-split)
        for (const char* obf : Patterns::AMSI_OBFUSCATED_REFS) {
            if (contentLower.find(toLower(std::string(obf))) != std::string::npos) {
                techniques.push_back("Obfuscated AMSI reference");
                detected = true;
                break;
            }
        }

        // Combined reflection bypass pattern:
        // [Ref].Assembly.GetType + GetField + SetValue
        if (contentLower.find("[ref].assembly") != std::string::npos &&
            contentLower.find("gettype") != std::string::npos &&
            contentLower.find("getfield") != std::string::npos &&
            contentLower.find("setvalue") != std::string::npos) {
            techniques.push_back("Reflection-based AMSI memory patch");
            detected = true;
        }

        // Marshal::WriteInt32 AMSI context null
        if (contentLower.find("writeint32") != std::string::npos &&
            (contentLower.find("amsi") != std::string::npos ||
             contentLower.find("marshal") != std::string::npos)) {
            techniques.push_back("Marshal::WriteInt32 AMSI context null");
            detected = true;
        }

        return detected;
    }

    // ════════════════════════════════════════════════════════════════════════
    // NORMALIZATION — remove backticks, collapse whitespace
    // ════════════════════════════════════════════════════════════════════════

    [[nodiscard]] std::string normalize(std::string_view input) const noexcept {
        std::string out;
        out.reserve(input.size());
        bool prevSpace = false;
        for (char c : input) {
            if (c == '`') continue;                 // Strip PowerShell backtick escapes
            if (c == '\r') continue;                // Normalize line endings
            if (std::isspace(static_cast<unsigned char>(c))) {
                if (!prevSpace) out += ' ';
                prevSpace = true;
            } else {
                out += c;
                prevSpace = false;
            }
        }
        return out;
    }

    // ════════════════════════════════════════════════════════════════════════
    // DEOBFUSCATION ENGINE — multi-technique, single-layer
    // ════════════════════════════════════════════════════════════════════════

    [[nodiscard]] std::string deobfuscate(std::string_view content) const noexcept {
        // Try Base64 extraction — look for long base64 runs
        std::string best;

        // Scan for base64 blob (>=40 chars of [A-Za-z0-9+/=])
        size_t pos = 0;
        const size_t len = content.size();
        while (pos < len) {
            // Skip non-base64
            while (pos < len && !isBase64Char(content[pos])) ++pos;
            size_t start = pos;
            while (pos < len && (isBase64Char(content[pos]) || content[pos] == '=')) ++pos;
            size_t blobLen = pos - start;
            if (blobLen >= 40) {
                std::string decoded = decodeBase64(content.substr(start, blobLen));
                if (!decoded.empty() && isPrintable(decoded)) {
                    return decoded;
                }
            }
        }

        // Try removing backticks (already done in normalize, but for raw input)
        std::string noBt;
        noBt.reserve(content.size());
        for (char c : content) {
            if (c != '`') noBt += c;
        }
        if (noBt.size() != content.size() && !noBt.empty()) {
            return noBt;
        }

        return {};
    }

    // ════════════════════════════════════════════════════════════════════════
    // BASE64 DECODE — PowerShell UTF-16LE aware, safe
    // ════════════════════════════════════════════════════════════════════════

    [[nodiscard]] std::string decodeBase64(std::string_view encoded) const noexcept {
        try {
            if (encoded.empty() || encoded.size() > 10 * 1024 * 1024) return {};

            // Clean whitespace
            std::string clean;
            clean.reserve(encoded.size());
            for (char c : encoded) {
                if (!std::isspace(static_cast<unsigned char>(c)))
                    clean += c;
            }

            static constexpr char B64[] =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

            auto indexOf = [](char c) -> int {
                if (c >= 'A' && c <= 'Z') return c - 'A';
                if (c >= 'a' && c <= 'z') return c - 'a' + 26;
                if (c >= '0' && c <= '9') return c - '0' + 52;
                if (c == '+') return 62;
                if (c == '/') return 63;
                return -1;
            };

            std::vector<uint8_t> raw;
            raw.reserve(clean.size() * 3 / 4);

            int buf = 0, bits = 0;
            for (char c : clean) {
                if (c == '=') break;
                int val = indexOf(c);
                if (val < 0) break;
                buf = (buf << 6) | val;
                bits += 6;
                if (bits >= 8) {
                    bits -= 8;
                    raw.push_back(static_cast<uint8_t>((buf >> bits) & 0xFF));
                }
            }

            // PowerShell -EncodedCommand uses UTF-16LE
            if (raw.size() >= 2 && raw.size() % 2 == 0) {
                bool looksUtf16 = true;
                for (size_t i = 1; i < raw.size() && i < 20; i += 2) {
                    if (raw[i] != 0) { looksUtf16 = false; break; }
                }
                if (looksUtf16) {
                    std::wstring ws;
                    ws.reserve(raw.size() / 2);
                    for (size_t i = 0; i + 1 < raw.size(); i += 2) {
                        wchar_t wc = static_cast<wchar_t>(raw[i]) |
                                     (static_cast<wchar_t>(raw[i + 1]) << 8);
                        if (wc == 0) break;
                        ws += wc;
                    }
                    return Utils::StringUtils::ToNarrow(ws);
                }
            }

            return std::string(raw.begin(), raw.end());
        } catch (...) {
            return {};
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // OBFUSCATION ANALYSIS
    // ════════════════════════════════════════════════════════════════════════

    [[nodiscard]] ObfuscationDetails analyzeObfuscation(std::string_view content) const noexcept {
        ObfuscationDetails d;
        if (content.empty()) return d;

        d.entropyScore = entropy(content);

        // Count indicators
        std::string s(content);
        for (const char* ind : Patterns::OBFUSCATION_INDICATORS) {
            size_t pos = 0;
            while ((pos = s.find(ind, pos)) != std::string::npos) {
                d.suspiciousTokenCount++;
                pos += std::strlen(ind);
            }
        }

        // Detect types
        std::string lower = toLower(s);

        if (lower.find("frombase64string") != std::string::npos ||
            lower.find("tobase64string") != std::string::npos) {
            d.primaryType = ObfuscationType::BASE64;
            d.techniquesDetected.push_back("Base64 encoding");
        }

        size_t btCount = static_cast<size_t>(std::count(content.begin(), content.end(), '`'));
        if (btCount > 5) {
            if (d.primaryType == ObfuscationType::NONE)
                d.primaryType = ObfuscationType::BACKTICK_INSERTION;
            d.techniquesDetected.push_back("Backtick insertion");
        }

        if (lower.find("-bxor") != std::string::npos) {
            if (d.primaryType == ObfuscationType::NONE)
                d.primaryType = ObfuscationType::XOR;
            d.techniquesDetected.push_back("XOR encoding");
        }

        if (lower.find("[char]") != std::string::npos) {
            if (d.primaryType == ObfuscationType::NONE)
                d.primaryType = ObfuscationType::CHAR_ARRAY;
            d.techniquesDetected.push_back("Char code concatenation");
        }

        if (s.find("'+\"") != std::string::npos ||
            s.find("\"+\"") != std::string::npos ||
            s.find("\"+'") != std::string::npos) {
            if (d.primaryType == ObfuscationType::NONE)
                d.primaryType = ObfuscationType::STRING_CONCATENATION;
            d.techniquesDetected.push_back("String concatenation");
        }

        if (lower.find("deflatestream") != std::string::npos ||
            lower.find("gzipstream") != std::string::npos) {
            if (d.primaryType == ObfuscationType::NONE)
                d.primaryType = ObfuscationType::COMPRESSION_GZIP;
            d.techniquesDetected.push_back("Compression");
        }

        // Mixed case randomization
        int caps = 0, low = 0;
        for (char c : content) {
            if (std::isupper(static_cast<unsigned char>(c))) ++caps;
            else if (std::islower(static_cast<unsigned char>(c))) ++low;
        }
        if (caps > 0 && low > 0) {
            double ratio = static_cast<double>(caps) / (caps + low);
            if (ratio > 0.3 && ratio < 0.7) {
                if (d.primaryType == ObfuscationType::NONE)
                    d.primaryType = ObfuscationType::MIXED_CASE_RANDOMIZATION;
                d.techniquesDetected.push_back("Mixed case randomization");
            }
        }

        if (d.entropyScore > Constants::MIN_ENTROPY_OBFUSCATION) {
            if (d.primaryType == ObfuscationType::NONE)
                d.primaryType = ObfuscationType::CUSTOM_ENCODING;
            d.techniquesDetected.push_back("High entropy");
        }

        return d;
    }

    // ════════════════════════════════════════════════════════════════════════
    // WHITELIST — Requires signature validation, not just path
    // ════════════════════════════════════════════════════════════════════════

    [[nodiscard]] bool isWhitelisted(
        const std::filesystem::path& path,
        const std::string& hash
    ) const noexcept {
        try {
            // Check hash-based whitelist via WhiteListStore
            auto& wls = Whitelist::WhiteListStore::Instance();
            if (wls.IsHashWhitelisted(hash)) {
                SS_LOG_DEBUG(LOG_CAT, L"Hash whitelisted: %hs", hash.c_str());
                return true;
            }

            // System path alone is NOT sufficient — an attacker can drop .ps1
            // files into System32 via other exploits. Only trust if both
            // path is in a trusted location AND hash is known-good.
        } catch (...) {
            SS_LOG_ERROR(LOG_CAT, L"Exception in whitelist check");
        }
        return false;
    }

    // ════════════════════════════════════════════════════════════════════════
    // KERNEL WIRING — notify PhantomSensor via IPC
    // ════════════════════════════════════════════════════════════════════════

    void notifyKernelBlock(uint32_t pid, const char* reason) const noexcept {
        if (pid == 0) return;
        try {
            // Build behavioral alert for kernel
            // The IPC path sends FilterMessageType_BehavioralAlert which the
            // kernel driver's BehaviorEngine consumes to apply enforcement.
            struct AlertMsg {
                uint32_t messageType;
                uint32_t processId;
                uint32_t threatScore;
                char     reason[128];
            };

            AlertMsg msg{};
            msg.messageType = 0x90; // FilterMessageType_BehavioralAlert value
            msg.processId   = pid;
            msg.threatScore = 100;
            std::strncpy(msg.reason, reason, sizeof(msg.reason) - 1);

            auto& ipc = Communication::IPCManager::Instance();
            if (ipc.IsFilterPortConnected()) {
                ipc.SendToKernel(&msg, sizeof(msg));
            }

            SS_LOG_WARN(LOG_CAT,
                L"Kernel notified: block PID=%u reason=%hs", pid, reason);
        } catch (...) {
            SS_LOG_ERROR(LOG_CAT, L"Failed to notify kernel for PID=%u", pid);
        }
    }

    void notifyAmsiBypassDetected(
        uint32_t pid,
        const std::vector<std::string>& techniques
    ) const noexcept {
        try {
            auto& amsi = AMSIIntegration::Instance();
            if (amsi.IsInitialized() && pid != 0) {
                amsi.StartIntegrityMonitoring(pid);

                auto report = amsi.CheckIntegrity(pid);
                if (report.status == AmsiIntegrityStatus::Tampered) {
                    SS_LOG_WARN(LOG_CAT,
                        L"AMSI tampered in PID=%u, attempting repair", pid);
                    amsi.RepairIntegrity(pid);
                }
            }
        } catch (...) {
            SS_LOG_ERROR(LOG_CAT, L"Failed to notify AMSIIntegration for PID=%u", pid);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // UTILITY
    // ════════════════════════════════════════════════════════════════════════

    [[nodiscard]] static std::string toLower(const std::string& s) noexcept {
        std::string r = s;
        std::transform(r.begin(), r.end(), r.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return r;
    }

    [[nodiscard]] static std::string toLower(std::string&& s) noexcept {
        std::transform(s.begin(), s.end(), s.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return s;
    }

    [[nodiscard]] static std::string hexString(const std::array<uint8_t, 32>& b) noexcept {
        static constexpr char hex[] = "0123456789abcdef";
        std::string r;
        r.reserve(64);
        for (uint8_t v : b) {
            r += hex[v >> 4];
            r += hex[v & 0xF];
        }
        return r;
    }

    [[nodiscard]] static double entropy(std::string_view data) noexcept {
        if (data.empty()) return 0.0;
        std::array<size_t, 256> freq{};
        for (unsigned char c : data) freq[c]++;
        double e = 0.0;
        const double n = static_cast<double>(data.size());
        for (size_t f : freq) {
            if (f > 0) {
                double p = static_cast<double>(f) / n;
                e -= p * std::log2(p);
            }
        }
        return e;
    }

    [[nodiscard]] static bool isBase64Char(char c) noexcept {
        return std::isalnum(static_cast<unsigned char>(c)) || c == '+' || c == '/';
    }

    [[nodiscard]] static bool isPrintable(const std::string& s) noexcept {
        if (s.empty()) return false;
        int good = 0;
        for (unsigned char c : s) {
            if (std::isprint(c) || std::isspace(c)) ++good;
        }
        return (static_cast<double>(good) / s.size()) > 0.8;
    }

    [[nodiscard]] bool extractEncodedCommand(
        const std::string& cmdLine,
        std::string& payload
    ) const noexcept {
        std::string lower = toLower(cmdLine);
        static constexpr const char* FLAGS[] = {
            "-encodedcommand ", "-enc ", "-e ", "-ec ",
        };
        for (const char* flag : FLAGS) {
            size_t pos = lower.find(flag);
            if (pos == std::string::npos) continue;

            size_t start = pos + std::strlen(flag);
            while (start < cmdLine.size() &&
                   std::isspace(static_cast<unsigned char>(cmdLine[start])))
                ++start;

            size_t end = start;
            while (end < cmdLine.size() &&
                   !std::isspace(static_cast<unsigned char>(cmdLine[end])))
                ++end;

            if (end > start) {
                payload = cmdLine.substr(start, end - start);
                return true;
            }
        }
        return false;
    }

    void addFlaggedLine(
        std::string_view content,
        const std::string& contentLower,
        const char* pattern,
        std::vector<std::pair<size_t, std::string>>& flagged
    ) const noexcept {
        if (flagged.size() >= Constants::MAX_FLAGGED_LINES) return;
        auto pos = contentLower.find(pattern);
        if (pos == std::string::npos) return;

        size_t lineNum = static_cast<size_t>(
            std::count(content.begin(), content.begin() + std::min(pos, content.size()), '\n')) + 1;
        size_t ls = content.rfind('\n', pos);
        ls = (ls == std::string_view::npos) ? 0 : ls + 1;
        size_t le = content.find('\n', pos);
        if (le == std::string_view::npos) le = content.size();

        std::string line(content.substr(ls, std::min<size_t>(le - ls, 200)));
        if (le - ls > 200) line += "...";
        flagged.emplace_back(lineNum, std::move(line));
    }

    void classifyResult(ScanResult& result, int rawScore) const noexcept {
        if (rawScore >= Constants::Heuristics::THRESHOLD_BLOCK) {
            result.status     = ScanStatus::MALICIOUS;
            result.threatName = threatName(result.category);
            m_stats.maliciousDetected.fetch_add(1, std::memory_order_relaxed);
        } else if (rawScore >= Constants::Heuristics::THRESHOLD_SUSPICIOUS) {
            result.status     = ScanStatus::SUSPICIOUS;
            result.threatName = "PowerShell/Heuristic.Suspicious";
            m_stats.suspiciousDetected.fetch_add(1, std::memory_order_relaxed);
        } else {
            result.status = ScanStatus::CLEAN;
        }
    }

    [[nodiscard]] static std::string threatName(ThreatCategory cat) noexcept {
        switch (cat) {
            case ThreatCategory::AMSI_TAMPERING:      return "PowerShell/AMSIBypass.Gen";
            case ThreatCategory::CREDENTIAL_THEFT:    return "PowerShell/CredTheft.Gen";
            case ThreatCategory::DOWNLOADER:           return "PowerShell/Downloader.Gen";
            case ThreatCategory::RANSOMWARE_STAGER:   return "PowerShell/Ransom.Stager";
            case ThreatCategory::REVERSE_SHELL:       return "PowerShell/ReverseShell.Gen";
            case ThreatCategory::PERSISTENCE_MECHANISM: return "PowerShell/Persist.Gen";
            case ThreatCategory::PRIVILEGE_ESCALATION: return "PowerShell/PrivEsc.Gen";
            case ThreatCategory::RECONNAISSANCE:      return "PowerShell/Recon.Gen";
            case ThreatCategory::PROCESS_INJECTION:   return "PowerShell/Injection.Gen";
            case ThreatCategory::V2_DOWNGRADE:        return "PowerShell/V2Downgrade.Block";
            default:                                  return "PowerShell/Suspicious.Gen";
        }
    }

    [[nodiscard]] static std::string obfuscationName(ObfuscationType t) noexcept {
        switch (t) {
            case ObfuscationType::BASE64:                  return "Base64";
            case ObfuscationType::XOR:                     return "XOR";
            case ObfuscationType::STRING_CONCATENATION:    return "StringConcat";
            case ObfuscationType::VARIABLE_REPLACEMENT:    return "VarReplace";
            case ObfuscationType::BACKTICK_INSERTION:      return "Backtick";
            case ObfuscationType::MIXED_CASE_RANDOMIZATION: return "MixedCase";
            case ObfuscationType::COMPRESSION_GZIP:        return "Compression";
            case ObfuscationType::CHAR_ARRAY:              return "CharArray";
            case ObfuscationType::CUSTOM_ENCODING:         return "CustomEncoding";
            default:                                       return "None";
        }
    }

    template<typename T, typename Fn>
    [[nodiscard]] T getConfigValue(Fn&& getter) const noexcept {
        std::shared_lock lk(m_configMtx);
        return getter(m_config);
    }

    ScanResult finalize(
        ScanResult& result,
        const std::chrono::high_resolution_clock::time_point& start
    ) noexcept {
        const auto end = std::chrono::high_resolution_clock::now();
        result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        uint64_t durUs = static_cast<uint64_t>(result.scanDuration.count());
        uint64_t total = m_stats.totalScans.load(std::memory_order_relaxed);
        if (total > 0) {
            m_totalScanTimeUs.fetch_add(durUs, std::memory_order_relaxed);
            m_stats.averageScanTimeUs.store(
                m_totalScanTimeUs.load(std::memory_order_relaxed) / total,
                std::memory_order_relaxed);
        }

        // Invoke callbacks (shared_lock — multiple readers, callbacks don't modify vector)
        {
            std::shared_lock lk(m_cbMtx);
            for (const auto& cb : m_callbacks) {
                try { cb(result); }
                catch (const std::exception& ex) {
                    SS_LOG_ERROR(LOG_CAT, L"Callback exception: %hs", ex.what());
                }
                catch (...) {
                    SS_LOG_ERROR(LOG_CAT, L"Unknown callback exception");
                }
            }
        }

        if (result.status == ScanStatus::MALICIOUS) {
            SS_LOG_WARN(LOG_CAT,
                L"MALICIOUS: %hs score=%d PID=%u",
                result.threatName.c_str(), result.riskScore, result.processId);

            // On malicious detection, notify kernel to enforce
            if (result.processId != 0) {
                notifyKernelBlock(result.processId, result.threatName.c_str());
            }
        } else if (result.status == ScanStatus::SUSPICIOUS) {
            SS_LOG_INFO(LOG_CAT,
                L"SUSPICIOUS: score=%d PID=%u", result.riskScore, result.processId);
        }

        return result;
    }

    // ── Member state ────────────────────────────────────────────────────────

    std::atomic<bool>            m_initialized{false};
    PowerShellScanConfig         m_config;
    mutable std::shared_mutex    m_configMtx;

    PowerShellStats              m_stats;
    std::atomic<uint64_t>        m_totalScanTimeUs{0};

    std::vector<std::function<void(const ScanResult&)>> m_callbacks;
    mutable std::shared_mutex    m_cbMtx;
};

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC FACADE — Singleton + delegation to PIMPL
// ════════════════════════════════════════════════════════════════════════════════

PowerShellScanner& PowerShellScanner::getInstance() {
    static PowerShellScanner instance;
    return instance;
}

PowerShellScanner::PowerShellScanner()
    : pImpl(std::make_unique<Impl>()) {
    SS_LOG_INFO(LOG_CAT, L"PowerShellScanner singleton created");
}

PowerShellScanner::~PowerShellScanner() {
    SS_LOG_INFO(LOG_CAT, L"PowerShellScanner singleton destroyed");
}

// ── Scanning delegation ─────────────────────────────────────────────────────

ScanResult PowerShellScanner::scanFile(
    const std::filesystem::path& path, uint32_t pid) {
    return pImpl->scanFile(path, pid);
}

ScanResult PowerShellScanner::scanMemory(
    std::span<const char> content, std::string_view src, uint32_t pid) {
    return pImpl->scanMemory(content, src, pid);
}

ScanResult PowerShellScanner::scanCommandLine(
    std::string_view cmdLine, uint32_t pid) {
    return pImpl->scanCommandLine(cmdLine, pid);
}

// ── Management delegation ───────────────────────────────────────────────────

void PowerShellScanner::updateConfig(const PowerShellScanConfig& cfg) {
    pImpl->updateConfig(cfg);
}

PowerShellScanConfig PowerShellScanner::getConfig() const {
    return pImpl->getConfig();
}

void PowerShellScanner::registerCallback(std::function<void(const ScanResult&)> cb) {
    pImpl->registerCallback(std::move(cb));
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

} // namespace ShadowStrike::Scripts
