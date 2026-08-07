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
 * ShadowStrike Core Registry - REGISTRY MONITOR IMPLEMENTATION
 * ============================================================================
 *
 * @file RegistryMonitor.cpp
 * @brief Enterprise-grade real-time Windows Registry monitoring and protection.
 *
 * This module provides comprehensive real-time registry interception, analysis,
 * and policy enforcement through kernel-level callbacks and user-mode analysis.
 *
 * Architecture:
 * - PIMPL pattern for ABI stability
 * - Meyers' Singleton for thread-safe instance management
 * - Kernel communication via filter port (FilterConnectCommunicationPort)
 * - Multi-threaded event processing with work queues
 * - Policy engine with rule-based verdicts
 * - Protected key enforcement for self-defense
 * - Deception mode with honeypots and silent drops
 *
 * Detection Capabilities:
 * - Persistence mechanisms (Run keys, services, Winlogon, IFEO, etc.)
 * - Fileless malware (binary blobs, encoded scripts, PowerShell commands)
 * - COM hijacking and DLL search order hijacking
 * - Security bypass attempts (UAC, Defender, AMSI, ETW)
 * - Self-defense tampering detection
 * - Network configuration changes (proxy, DNS, hosts)
 *
 * MITRE ATT&CK Coverage:
 * - T1547.001: Boot or Logon Autostart Execution: Registry Run Keys
 * - T1547.004: Winlogon Helper DLL
 * - T1546.015: Component Object Model Hijacking
 * - T1546.012: Image File Execution Options Injection
 * - T1112: Modify Registry
 * - T1562.001: Disable or Modify Tools
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "RegistryMonitor.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/CryptoUtils.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Whitelist/WhiteListStore.hpp"
#include "../../ThreatIntel/ThreatIntelLookup.hpp"
#include "../../HashStore/HashStore.hpp"

// ============================================================================
// SYSTEM INCLUDES
// ============================================================================
#include <Windows.h>
#include <winternl.h>
#include "../../Communication/FilterConnection.hpp"
#include "../../Communication/MessageDispatcher.hpp"
#include "../../Communication/Communication.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <thread>
#include <future>
#include <queue>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <cwctype>

#pragma comment(lib, "fltLib.lib")
#pragma comment(lib, "ntdll.lib")

namespace ShadowStrike {
namespace Core {
namespace Registry {

using namespace Utils;
using namespace std::chrono;

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================
namespace {

    // Critical persistence keys
    const std::vector<std::wstring> PERSISTENCE_KEYS = {
        // Run keys
        L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"\\Registry\\User\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"\\Registry\\User\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",

        // Services
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services",

        // Winlogon
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",

        // IFEO
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",

        // AppInit
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        L"\\Registry\\Machine\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows",

        // Boot Execute
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager",

        // Shell extensions
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks",
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers",

        // Scheduled tasks
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule",
    };

    // Security-critical keys
    const std::vector<std::wstring> SECURITY_KEYS = {
        // UAC
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",

        // Defender
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows Defender",
        L"\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",

        // Firewall
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy",

        // AMSI
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\AMSI",

        // ETW
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger",
    };

    // Network keys
    const std::vector<std::wstring> NETWORK_KEYS = {
        // Proxy
        L"\\Registry\\User\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",

        // DNS
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters",

        // Hosts file (registry doesn't directly control it, but related settings)
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters",
    };

    // COM/CLSID keys
    const std::vector<std::wstring> COM_KEYS = {
        L"\\Registry\\User\\*\\Software\\Classes\\CLSID",
        L"\\Registry\\Machine\\SOFTWARE\\Classes\\CLSID",
        L"\\Registry\\Machine\\SOFTWARE\\Wow6432Node\\Classes\\CLSID",
    };

    // Entropy threshold for encoded data
    constexpr double ENCODED_DATA_ENTROPY = 7.0;

    // Simple URL prefix check (avoids std::regex ReDoS risk on callback hot-path)
    [[nodiscard]] bool ContainsUrlPrefix(const std::string& s) noexcept {
        auto lower = s;
        for (auto& c : lower) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
        return lower.find("http://") != std::string::npos ||
               lower.find("https://") != std::string::npos ||
               lower.find("ftp://") != std::string::npos;
    }

    // Null-byte detection for registry key cloaking attacks
    [[nodiscard]] bool ContainsNullBytes(std::wstring_view path) noexcept {
        for (auto ch : path) {
            if (ch == L'\0') return true;
        }
        return false;
    }

    // Case-insensitive substring check without allocation
    [[nodiscard]] bool IContainsRaw(std::wstring_view haystack, std::wstring_view needle) noexcept {
        if (needle.empty()) return true;
        if (haystack.size() < needle.size()) return false;
        for (size_t i = 0; i <= haystack.size() - needle.size(); ++i) {
            bool match = true;
            for (size_t j = 0; j < needle.size(); ++j) {
                if (::towlower(haystack[i + j]) != ::towlower(needle[j])) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------------
    // Log-injection hardening: registry paths, value names and process paths
    // originate from attacker-controlled processes and may contain CR/LF or
    // other control characters that could be used to forge log lines or
    // poison downstream SIEM ingestion. Sanitize every wide field we feed
    // into Logger format strings. Output is also length-capped to defend
    // against log-flooding via gigantic keys.
    // ------------------------------------------------------------------------
    constexpr size_t kMaxLogFieldChars = 1024;

    [[nodiscard]] std::string SanitizeForLog(std::wstring_view wide) {
        std::string narrow = StringUtils::ToNarrow(wide);
        if (narrow.size() > kMaxLogFieldChars) {
            narrow.resize(kMaxLogFieldChars);
            narrow.append("...<truncated>");
        }
        for (char& c : narrow) {
            const auto uc = static_cast<unsigned char>(c);
            if (uc < 0x20 || uc == 0x7F) {
                c = '?';
            }
        }
        return narrow;
    }

    [[nodiscard]] std::string SanitizeForLog(std::string_view narrowIn) {
        std::string narrow(narrowIn);
        if (narrow.size() > kMaxLogFieldChars) {
            narrow.resize(kMaxLogFieldChars);
            narrow.append("...<truncated>");
        }
        for (char& c : narrow) {
            const auto uc = static_cast<unsigned char>(c);
            if (uc < 0x20 || uc == 0x7F) {
                c = '?';
            }
        }
        return narrow;
    }

    // Wide variant of the script-signature heuristic. The original narrow
    // implementation produced false negatives on REG_SZ / REG_EXPAND_SZ
    // values stored as UTF-16, because every other byte of the marker
    // ("p\0o\0w\0e\0...") would not appear in the narrow scan.
    [[nodiscard]] bool ContainsScriptSignatureWide(std::wstring_view wide) noexcept {
        if (wide.size() < 5) return false;
        static constexpr std::wstring_view kMarkers[] = {
            L"powershell", L"Invoke-", L"IEX",
            L"@echo", L"cmd.exe",
            L"WScript", L"CreateObject",
            L"ActiveXObject",
        };
        for (auto m : kMarkers) {
            if (IContainsRaw(wide, m)) return true;
        }
        return false;
    }

    // Lightweight FNV-1a 64-bit hash used by the alert-dedup ring. Combining
    // PID, op, key path and value name lets us suppress alert/event-callback
    // floods that target the same key (typical post-exploitation behaviour
    // when a script repeatedly writes the same Run value), without affecting
    // the kernel verdict reply which must still be emitted every time.
    [[nodiscard]] uint64_t HashEventForDedup(uint32_t pid, uint8_t op,
                                             std::wstring_view keyPath,
                                             std::wstring_view valueName) noexcept {
        uint64_t h = 0xcbf29ce484222325ULL;
        const auto mix = [&h](uint8_t b) noexcept {
            h ^= b;
            h *= 0x100000001b3ULL;
        };
        const uint8_t pidBytes[5] = {
            static_cast<uint8_t>(pid),
            static_cast<uint8_t>(pid >> 8),
            static_cast<uint8_t>(pid >> 16),
            static_cast<uint8_t>(pid >> 24),
            op,
        };
        for (auto b : pidBytes) mix(b);
        for (wchar_t c : keyPath) {
            const wchar_t lc = ::towlower(c);
            mix(static_cast<uint8_t>(lc));
            mix(static_cast<uint8_t>(static_cast<uint16_t>(lc) >> 8));
        }
        mix(0xFF);
        for (wchar_t c : valueName) {
            const wchar_t lc = ::towlower(c);
            mix(static_cast<uint8_t>(lc));
            mix(static_cast<uint8_t>(static_cast<uint16_t>(lc) >> 8));
        }
        return h;
    }

    // Extract a process basename ("filename.exe") from a full image path.
    // Previously processName was set to the full wide path converted to
    // narrow form, which polluted UI displays and broke whitelist lookups
    // by exact name. Empty input → empty output.
    [[nodiscard]] std::string ProcessBaseName(std::wstring_view fullPath) {
        if (fullPath.empty()) return {};
        size_t pos = fullPath.find_last_of(L"\\/");
        std::wstring_view tail = (pos == std::wstring_view::npos)
            ? fullPath
            : fullPath.substr(pos + 1);
        return StringUtils::ToNarrow(tail);
    }

    // Hard caps applied to attacker-influenceable lists. These do not change
    // the public constants; they merely enforce them in the Add* paths so a
    // misconfigured policy push (or a hostile IPC client able to call into
    // these APIs through a higher-level wrapper) cannot exhaust memory.
    constexpr size_t kMaxHoneypotKeys = 1024;

    // How many distinct events to remember for dedup, and the suppression
    // window. Both are intentionally conservative — the kernel still gets a
    // verdict per request; only user-facing alerts/callbacks are deduped.
    constexpr size_t kDedupRingSize = 256;
    constexpr std::chrono::milliseconds kDedupWindow{ 2000 };

    // Strip large value blobs from a stored event before keeping it in the
    // recent-events ring. Without this cap, 1000 × 1 MB events ≈ 1 GB of
    // resident memory in the user-mode service.
    constexpr size_t kRecentEventDataPreview = 256;

    void TruncateEventForRetention(RegistryEvent& ev) noexcept {
        try {
            if (ev.data.size() > kRecentEventDataPreview) {
                ev.data.resize(kRecentEventDataPreview);
            }
            if (ev.previousData.size() > kRecentEventDataPreview) {
                ev.previousData.resize(kRecentEventDataPreview);
            }
        } catch (...) {
            ev.data.clear();
            ev.previousData.clear();
        }
    }

} // anonymous namespace

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

[[nodiscard]] static double CalculateEntropyInternal(std::span<const uint8_t> data) noexcept {
    if (data.empty()) return 0.0;

    std::array<uint64_t, 256> frequency{};
    for (uint8_t byte : data) {
        frequency[byte]++;
    }

    double entropy = 0.0;
    double dataSize = static_cast<double>(data.size());

    for (uint64_t count : frequency) {
        if (count > 0) {
            double probability = static_cast<double>(count) / dataSize;
            entropy -= probability * std::log2(probability);
        }
    }

    return entropy;
}

[[nodiscard]] static bool ContainsExecutableSignature(std::span<const uint8_t> data) noexcept {
    if (data.size() < 2) return false;

    // Check for MZ header
    if (data[0] == 'M' && data[1] == 'Z') return true;

    // Check for PE header
    if (data.size() >= 4) {
        if (data[0] == 'P' && data[1] == 'E' && data[2] == 0 && data[3] == 0) {
            return true;
        }
    }

    return false;
}

[[nodiscard]] static bool ContainsScriptSignature(std::span<const uint8_t> data) noexcept {
    if (data.size() < 10) return false;

    std::string str(reinterpret_cast<const char*>(data.data()),
                    std::min(data.size(), size_t(100)));

    // PowerShell
    if (str.find("powershell") != std::string::npos) return true;
    if (str.find("Invoke-") != std::string::npos) return true;
    if (str.find("IEX") != std::string::npos) return true;

    // CMD/BAT
    if (str.find("@echo") != std::string::npos) return true;
    if (str.find("cmd.exe") != std::string::npos) return true;

    // VBS
    if (str.find("WScript") != std::string::npos) return true;
    if (str.find("CreateObject") != std::string::npos) return true;

    // JS
    if (str.find("ActiveXObject") != std::string::npos) return true;

    return false;
}

[[nodiscard]] static bool IsPathLike(const std::wstring& str) noexcept {
    if (str.length() < 3) return false;

    // C:\...
    if (str[1] == L':' && str[2] == L'\\') return true;

    // \\...
    if (str[0] == L'\\' && str[1] == L'\\') return true;

    return false;
}

[[nodiscard]] static bool MatchesRegistryKeyPattern(const std::wstring& lowerPath,
                                                    const std::wstring& pattern) {
    const std::wstring lowerPattern = StringUtils::ToLowerCopy(pattern);
    const size_t wildcardPos = lowerPattern.find(L'*');
    if (wildcardPos == std::wstring::npos) {
        return lowerPath.find(lowerPattern) != std::wstring::npos;
    }

    const std::wstring prefix = lowerPattern.substr(0, wildcardPos);
    const std::wstring suffix = lowerPattern.substr(wildcardPos + 1);
    const size_t prefixPos = lowerPath.find(prefix);
    if (prefixPos == std::wstring::npos) {
        return false;
    }

    return suffix.empty() ||
           lowerPath.find(suffix, prefixPos + prefix.size()) != std::wstring::npos;
}

// ============================================================================
// REGISTRY EVENT METHODS
// ============================================================================

bool RegistryEvent::IsPersistenceKey() const {
    const std::wstring lowerPath = StringUtils::ToLowerCopy(keyPath);

    for (const auto& key : PERSISTENCE_KEYS) {
        if (MatchesRegistryKeyPattern(lowerPath, key)) {
            return true;
        }
    }

    return false;
}

bool RegistryEvent::IsServiceKey() const {
    const std::wstring lowerPath = StringUtils::ToLowerCopy(keyPath);
    return lowerPath.find(L"\\services\\") != std::wstring::npos ||
           lowerPath.find(L"currentcontrolset\\services") != std::wstring::npos;
}

bool RegistryEvent::IsSecurityKey() const {
    const std::wstring lowerPath = StringUtils::ToLowerCopy(keyPath);

    for (const auto& key : SECURITY_KEYS) {
        if (MatchesRegistryKeyPattern(lowerPath, key)) {
            return true;
        }
    }

    return false;
}

bool RegistryEvent::IsCOMKey() const {
    const std::wstring lowerPath = StringUtils::ToLowerCopy(keyPath);

    for (const auto& key : COM_KEYS) {
        if (MatchesRegistryKeyPattern(lowerPath, key)) {
            return true;
        }
    }

    return false;
}

bool RegistryEvent::IsNetworkKey() const {
    const std::wstring lowerPath = StringUtils::ToLowerCopy(keyPath);

    for (const auto& key : NETWORK_KEYS) {
        if (MatchesRegistryKeyPattern(lowerPath, key)) {
            return true;
        }
    }

    return false;
}

KeyCategory RegistryEvent::GetCategory() const {
    if (IsPersistenceKey()) return KeyCategory::Persistence;
    if (IsSecurityKey()) return KeyCategory::Security;
    if (IsNetworkKey()) return KeyCategory::Network;
    if (IsCOMKey()) return KeyCategory::COM;
    if (IsServiceKey()) return KeyCategory::System;

    const std::wstring lowerPath = StringUtils::ToLowerCopy(keyPath);

    if (lowerPath.find(L"\\explorer\\") != std::wstring::npos) {
        return KeyCategory::Shell;
    }

    if (lowerPath.find(L"\\drivers\\") != std::wstring::npos) {
        return KeyCategory::Driver;
    }

    return KeyCategory::Unknown;
}

std::wstring RegistryEvent::GetHive() const {
    const std::wstring lowerPath = StringUtils::ToLowerCopy(keyPath);

    if (lowerPath.starts_with(L"\\registry\\machine") ||
        lowerPath.starts_with(L"hklm\\") ||
        lowerPath.starts_with(L"hkey_local_machine\\")) {
        return L"HKLM";
    }

    if (lowerPath.starts_with(L"\\registry\\user") ||
        lowerPath.starts_with(L"hkcu\\") ||
        lowerPath.starts_with(L"hkey_current_user\\")) {
        return L"HKCU";
    }

    if (lowerPath.starts_with(L"hku\\") ||
        lowerPath.starts_with(L"hkey_users\\")) {
        return L"HKU";
    }

    if (lowerPath.starts_with(L"hkcr\\") ||
        lowerPath.starts_with(L"hkey_classes_root\\")) {
        return L"HKCR";
    }

    return L"UNKNOWN";
}

// ============================================================================
// CONFIGURATION FACTORY METHODS
// ============================================================================

RegistryMonitorConfig RegistryMonitorConfig::CreateDefault() noexcept {
    RegistryMonitorConfig config;
    config.enabled = true;
    config.useKernelCallback = true;
    config.useUserModeHooks = false;

    config.monitorCreateKey = true;
    config.monitorSetValue = true;
    config.monitorDeleteKey = true;
    config.monitorDeleteValue = true;
    config.monitorRename = true;
    config.monitorLoadHive = true;
    config.monitorSecurity = false;
    config.monitorTransactions = false;

    config.analyzeValues = true;
    config.detectFileless = true;
    config.detectPersistence = true;
    config.detectSecurityChanges = true;

    config.selfDefenseEnabled = true;
    config.protectShadowStrikeKeys = true;

    config.deception.enabled = false;

    config.logAllOperations = false;
    config.logBlockedOnly = true;
    config.logPersistenceKeys = true;

    return config;
}

RegistryMonitorConfig RegistryMonitorConfig::CreateHighSecurity() noexcept {
    RegistryMonitorConfig config;
    config.enabled = true;
    config.useKernelCallback = true;
    config.useUserModeHooks = false;

    config.monitorCreateKey = true;
    config.monitorSetValue = true;
    config.monitorDeleteKey = true;
    config.monitorDeleteValue = true;
    config.monitorRename = true;
    config.monitorLoadHive = true;
    config.monitorSecurity = true;
    config.monitorTransactions = true;

    config.analyzeValues = true;
    config.detectFileless = true;
    config.detectPersistence = true;
    config.detectSecurityChanges = true;
    config.largeValueThreshold = 32 * 1024;  // More aggressive

    config.selfDefenseEnabled = true;
    config.protectShadowStrikeKeys = true;

    config.deception.enabled = true;
    config.deception.silentDropEnabled = true;
    config.deception.honeypotEnabled = true;
    config.deception.fakeSuccessEnabled = true;

    config.logAllOperations = true;
    config.logBlockedOnly = false;
    config.logPersistenceKeys = true;

    return config;
}

RegistryMonitorConfig RegistryMonitorConfig::CreatePerformance() noexcept {
    RegistryMonitorConfig config;
    config.enabled = true;
    config.useKernelCallback = true;
    config.useUserModeHooks = false;

    config.monitorCreateKey = true;
    config.monitorSetValue = true;
    config.monitorDeleteKey = true;
    config.monitorDeleteValue = false;  // Reduce load
    config.monitorRename = false;
    config.monitorLoadHive = false;
    config.monitorSecurity = false;
    config.monitorTransactions = false;

    config.analyzeValues = false;  // Skip expensive analysis
    config.detectFileless = false;
    config.detectPersistence = true;  // Keep critical detection
    config.detectSecurityChanges = true;

    config.selfDefenseEnabled = true;
    config.protectShadowStrikeKeys = true;

    config.deception.enabled = false;

    config.eventQueueSize = 20000;  // Larger queue
    config.workerThreads = 4;       // More workers

    config.logAllOperations = false;
    config.logBlockedOnly = true;
    config.logPersistenceKeys = false;

    return config;
}

RegistryMonitorConfig RegistryMonitorConfig::CreateForensic() noexcept {
    RegistryMonitorConfig config;
    config.enabled = true;
    config.useKernelCallback = true;
    config.useUserModeHooks = true;  // Capture everything

    config.monitorCreateKey = true;
    config.monitorSetValue = true;
    config.monitorDeleteKey = true;
    config.monitorDeleteValue = true;
    config.monitorRename = true;
    config.monitorLoadHive = true;
    config.monitorSecurity = true;
    config.monitorTransactions = true;

    config.analyzeValues = true;
    config.detectFileless = true;
    config.detectPersistence = true;
    config.detectSecurityChanges = true;

    config.selfDefenseEnabled = false;  // Don't block, just observe

    config.deception.enabled = false;

    config.logAllOperations = true;    // Log everything
    config.logBlockedOnly = false;
    config.logPersistenceKeys = true;

    return config;
}

void RegistryMonitorStatistics::Reset() noexcept {
    totalEvents = 0;
    createKeyEvents = 0;
    setValueEvents = 0;
    deleteKeyEvents = 0;
    deleteValueEvents = 0;
    renameEvents = 0;

    allowedOperations = 0;
    blockedOperations = 0;
    silentDropped = 0;

    persistenceAttempts = 0;
    filelessPayloads = 0;
    securityChanges = 0;
    selfDefenseBlocks = 0;

    alertsGenerated = 0;
    criticalAlerts = 0;

    avgCallbackTimeUs = 0;
    maxCallbackTimeUs = 0;
    droppedEvents = 0;
}

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class RegistryMonitorImpl final {
public:
    RegistryMonitorImpl() = default;
    ~RegistryMonitorImpl() = default;

    // Delete copy/move
    RegistryMonitorImpl(const RegistryMonitorImpl&) = delete;
    RegistryMonitorImpl& operator=(const RegistryMonitorImpl&) = delete;
    RegistryMonitorImpl(RegistryMonitorImpl&&) = delete;
    RegistryMonitorImpl& operator=(RegistryMonitorImpl&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const RegistryMonitorConfig& config) {
        std::unique_lock lock(m_mutex);

        try {
            // Reject re-initialization while running to avoid leaking worker
            // threads and producing inconsistent kernel-connection state.
            // Callers must Stop() before reconfiguring.
            if (m_running) {
                SS_LOG_ERROR(L"Registry", L"Initialize rejected: monitor is running");
                return false;
            }

            // Validate configuration. workerThreads == 0 would dead-lock the
            // event pipeline (no consumers), so coerce it to a safe default
            // and clamp to a hard ceiling to bound thread/handle usage.
            RegistryMonitorConfig sanitised = config;
            if (sanitised.workerThreads == 0) {
                sanitised.workerThreads = 1;
            } else if (sanitised.workerThreads > 32) {
                sanitised.workerThreads = 32;
            }
            if (sanitised.largeValueThreshold == 0 ||
                sanitised.largeValueThreshold > RegistryMonitorConstants::MAX_VALUE_DATA_SIZE) {
                sanitised.largeValueThreshold =
                    RegistryMonitorConstants::LARGE_VALUE_THRESHOLD;
            }

            m_config = sanitised;
            m_initialized = true;

            if (sanitised.protectShadowStrikeKeys) {
                SetupSelfDefenseKeys();
            }

            SS_LOG_INFO(L"Registry", L"RegistryMonitor initialized (kernel=%d, selfDefense=%d)",
                sanitised.useKernelCallback ? 1 : 0,
                sanitised.selfDefenseEnabled ? 1 : 0);

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"RegistryMonitor initialization failed: %hs",
                SanitizeForLog(e.what()).c_str());
            return false;
        }
    }

    [[nodiscard]] bool Start() {
        std::unique_lock lock(m_mutex);

        try {
            if (!m_initialized) {
                SS_LOG_ERROR(L"Registry", L"Cannot start: not initialized");
                return false;
            }

            if (m_running) {
                SS_LOG_WARN(L"Registry", L"Already running");
                return true;
            }

            if (m_config.useKernelCallback) {
                m_kernelConnected = ConnectToKernelDriver();
                if (!m_kernelConnected) {
                    SS_LOG_WARN(L"Registry", L"Kernel connection failed, running in user-mode only");
                }
            }

            StartWorkerThreads();

            m_running = true;

            SS_LOG_INFO(L"Registry", L"RegistryMonitor started (kernel=%d, workers=%u)",
                m_kernelConnected ? 1 : 0, m_config.workerThreads);

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"Start failed: %hs", e.what());
            return false;
        }
    }

    void Stop() {
        std::unique_lock lock(m_mutex);

        try {
            if (!m_running) return;

            // Order matters: signal the worker loop to exit BEFORE tearing down
            // the FilterConnection. Disconnect() unblocks GetMessage but the
            // worker may then race back into the loop and re-observe the
            // connection pointer; setting m_stopRequested first ensures the
            // post-Disconnect iteration is the last one.
            m_stopRequested = true;

            // Disconnect kernel filter port via RAII connection wrapper. Keep
            // the pointer alive until the workers join so any final reply on
            // a delayed verdict path does not chase a dangling handle.
            if (m_kernelConnected && m_connection) {
                m_connection->Disconnect();
                m_kernelConnected = false;
            }

            // Must release lock before joining worker threads — workers
            // re-acquire it via IsRunning()/IsKernelConnected() observers
            // and via ProcessEvent's snapshot path.
            lock.unlock();
            StopWorkerThreads();
            lock.lock();

            // Now it is safe to drop the connection object; no worker can
            // resurface to call into it.
            m_connection.reset();

            m_running = false;

            SS_LOG_INFO(L"Registry", L"RegistryMonitor stopped");

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"Stop failed: %hs",
                SanitizeForLog(e.what()).c_str());
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_mutex);

        try {
            if (m_running) {
                m_stopRequested = true;
                if (m_connection) {
                    m_connection->Disconnect();
                    m_kernelConnected = false;
                }
                lock.unlock();
                StopWorkerThreads();
                lock.lock();
            }

            m_connection.reset();

            m_rules.clear();
            m_protectedKeys.clear();
            m_protectedKeysLower.clear();
            m_alertCallbacks.clear();
            m_eventCallbacks.clear();
            m_valueCallbacks.clear();
            m_recentEvents.clear();
            m_dedupRing.clear();
            m_dedupOrder.clear();
            m_dedupNextSlot = 0;

            m_initialized = false;
            m_running = false;

            SS_LOG_INFO(L"Registry", L"RegistryMonitor shutdown complete");

        } catch (...) {
            // Suppress all exceptions during shutdown
        }
    }

    [[nodiscard]] bool IsRunning() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_running;
    }

    [[nodiscard]] bool IsKernelConnected() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_kernelConnected;
    }

    // ========================================================================
    // POLICY MANAGEMENT
    // ========================================================================

    void SetPolicyCallback(RegistryPolicyCallback callback) {
        std::unique_lock lock(m_mutex);
        m_policyCallback = std::move(callback);
    }

    [[nodiscard]] uint64_t AddRule(const RegistryRule& rule) {
        std::unique_lock lock(m_mutex);

        try {
            if (m_rules.size() >= RegistryMonitorConstants::MAX_RULES) {
                SS_LOG_ERROR(L"Registry", L"AddRule rejected: MAX_RULES (%zu) reached",
                    RegistryMonitorConstants::MAX_RULES);
                return 0;
            }

            // Bound attacker-influenceable string fields to avoid log/memory
            // amplification through pattern-driven matching loops.
            RegistryRule newRule = rule;
            if (newRule.name.size() > 256) newRule.name.resize(256);
            if (newRule.description.size() > 1024) newRule.description.resize(1024);
            if (newRule.keyPathPattern.size() > RegistryMonitorConstants::MAX_KEY_PATH_LENGTH) {
                SS_LOG_ERROR(L"Registry", L"AddRule rejected: keyPathPattern too long (%zu)",
                    newRule.keyPathPattern.size());
                return 0;
            }
            if (newRule.processPathPattern.size() > RegistryMonitorConstants::MAX_KEY_PATH_LENGTH) {
                SS_LOG_ERROR(L"Registry", L"AddRule rejected: processPathPattern too long");
                return 0;
            }
            if (newRule.processIds.size() > 4096) {
                SS_LOG_ERROR(L"Registry", L"AddRule rejected: too many processIds (%zu)",
                    newRule.processIds.size());
                return 0;
            }

            newRule.ruleId = ++m_nextRuleId;
            newRule.createdAt = std::chrono::system_clock::now();

            const uint64_t id = newRule.ruleId;
            const std::string safeName = SanitizeForLog(newRule.name);
            m_rules[id] = std::move(newRule);

            SS_LOG_INFO(L"Registry", L"Added registry rule: %hs (id=%llu)",
                safeName.c_str(), static_cast<unsigned long long>(id));

            return id;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"AddRule failed: %hs",
                SanitizeForLog(e.what()).c_str());
            return 0;
        }
    }

    bool RemoveRule(uint64_t ruleId) {
        std::unique_lock lock(m_mutex);

        try {
            bool removed = m_rules.erase(ruleId) > 0;
            if (removed) {
                SS_LOG_INFO(L"Registry", L"Removed registry rule: %llu",
                    static_cast<unsigned long long>(ruleId));
            }
            return removed;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"RemoveRule failed: %hs", e.what());
            return false;
        }
    }

    [[nodiscard]] std::vector<RegistryRule> GetRules() const {
        std::shared_lock lock(m_mutex);

        std::vector<RegistryRule> rules;
        rules.reserve(m_rules.size());

        for (const auto& [id, rule] : m_rules) {
            rules.push_back(rule);
        }

        return rules;
    }

    bool SetRuleEnabled(uint64_t ruleId, bool enabled) {
        std::unique_lock lock(m_mutex);

        try {
            auto it = m_rules.find(ruleId);
            if (it != m_rules.end()) {
                it->second.enabled = enabled;
                SS_LOG_INFO(L"Registry", L"Rule %llu %ls",
                    static_cast<unsigned long long>(ruleId), enabled ? L"enabled" : L"disabled");
                return true;
            }
            return false;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"SetRuleEnabled failed: %hs", e.what());
            return false;
        }
    }

    // ========================================================================
    // KEY PROTECTION
    // ========================================================================

    void AddProtectedKey(const std::wstring& keyPath) {
        std::unique_lock lock(m_mutex);

        try {
            if (keyPath.empty() ||
                keyPath.size() > RegistryMonitorConstants::MAX_KEY_PATH_LENGTH) {
                SS_LOG_WARN(L"Registry", L"AddProtectedKey rejected: invalid path length %zu",
                    keyPath.size());
                return;
            }
            if (ContainsNullBytes(keyPath)) {
                SS_LOG_WARN(L"Registry", L"AddProtectedKey rejected: embedded null byte");
                return;
            }
            if (m_protectedKeys.size() >= RegistryMonitorConstants::MAX_PROTECTED_KEYS) {
                SS_LOG_ERROR(L"Registry", L"AddProtectedKey rejected: MAX_PROTECTED_KEYS reached");
                return;
            }

            ProtectedKey pk;
            pk.keyPath = keyPath;
            pk.includeSubkeys = true;
            pk.protectValues = true;
            pk.protectDelete = true;
            pk.protectRename = true;
            pk.protectSecurity = true;

            m_protectedKeys.push_back(std::move(pk));
            m_protectedKeysLower.push_back(StringUtils::ToLowerCopy(
                m_protectedKeys.back().keyPath));

            SS_LOG_INFO(L"Registry", L"Added protected key: %hs",
                SanitizeForLog(keyPath).c_str());

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"AddProtectedKey failed: %hs",
                SanitizeForLog(e.what()).c_str());
        }
    }

    void AddProtectedKey(const ProtectedKey& config) {
        std::unique_lock lock(m_mutex);

        try {
            if (config.keyPath.empty() ||
                config.keyPath.size() > RegistryMonitorConstants::MAX_KEY_PATH_LENGTH ||
                ContainsNullBytes(config.keyPath)) {
                SS_LOG_WARN(L"Registry", L"AddProtectedKey(config) rejected: invalid path");
                return;
            }
            if (m_protectedKeys.size() >= RegistryMonitorConstants::MAX_PROTECTED_KEYS) {
                SS_LOG_ERROR(L"Registry", L"AddProtectedKey rejected: MAX_PROTECTED_KEYS reached");
                return;
            }

            m_protectedKeys.push_back(config);
            m_protectedKeysLower.push_back(StringUtils::ToLowerCopy(config.keyPath));

            SS_LOG_INFO(L"Registry", L"Added protected key: %hs",
                SanitizeForLog(config.keyPath).c_str());

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"AddProtectedKey failed: %hs",
                SanitizeForLog(e.what()).c_str());
        }
    }

    void RemoveProtectedKey(const std::wstring& keyPath) {
        std::unique_lock lock(m_mutex);

        try {
            const std::wstring lowerTarget = StringUtils::ToLowerCopy(keyPath);

            // Walk both vectors in lock-step so the parallel lowercase cache
            // remains consistent with m_protectedKeys.
            size_t i = 0;
            while (i < m_protectedKeys.size()) {
                const std::wstring& thisLower =
                    (i < m_protectedKeysLower.size())
                        ? m_protectedKeysLower[i]
                        : (m_protectedKeysLower.emplace_back(
                              StringUtils::ToLowerCopy(m_protectedKeys[i].keyPath)),
                           m_protectedKeysLower[i]);

                if (thisLower == lowerTarget) {
                    m_protectedKeys.erase(m_protectedKeys.begin() + i);
                    if (i < m_protectedKeysLower.size()) {
                        m_protectedKeysLower.erase(m_protectedKeysLower.begin() + i);
                    }
                    SS_LOG_INFO(L"Registry", L"Removed protected key: %hs",
                        SanitizeForLog(keyPath).c_str());
                    // Do not break: remove all duplicates if any.
                } else {
                    ++i;
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"RemoveProtectedKey failed: %hs",
                SanitizeForLog(e.what()).c_str());
        }
    }

    [[nodiscard]] bool IsProtectedKey(const std::wstring& keyPath) const {
        std::shared_lock lock(m_mutex);

        const std::wstring lowerPath = StringUtils::ToLowerCopy(keyPath);

        // m_protectedKeysLower is a parallel cache populated under unique_lock
        // by the Add/Remove paths. Avoiding per-call ToLowerCopy on the entire
        // protected-key set is the difference between O(N) and O(N·M) work on
        // a hot path that fires on every registry operation matched by a
        // sysadmin-deployed policy.
        const size_t count = std::min(m_protectedKeys.size(),
                                      m_protectedKeysLower.size());
        for (size_t i = 0; i < count; ++i) {
            const auto& pk = m_protectedKeys[i];
            const std::wstring& lowerProtected = m_protectedKeysLower[i];

            if (lowerPath == lowerProtected) {
                return true;
            }

            if (pk.includeSubkeys &&
                !lowerProtected.empty() &&
                lowerPath.size() > lowerProtected.size() &&
                lowerPath.starts_with(lowerProtected) &&
                (lowerProtected.back() == L'\\' ||
                 lowerPath[lowerProtected.size()] == L'\\')) {
                return true;
            }
        }

        return false;
    }

    [[nodiscard]] std::vector<ProtectedKey> GetProtectedKeys() const {
        std::shared_lock lock(m_mutex);
        return m_protectedKeys;
    }

    // ========================================================================
    // KEY ANALYSIS
    // ========================================================================

    [[nodiscard]] static bool IsCriticalKey(const std::wstring& keyPath) {
        const std::wstring lowerPath = StringUtils::ToLowerCopy(keyPath);

        // System critical keys
        if (lowerPath.find(L"\\currentcontrolset\\control\\session manager") != std::wstring::npos) {
            return true;
        }

        if (lowerPath.find(L"\\currentcontrolset\\services\\") != std::wstring::npos) {
            return true;
        }

        return false;
    }

    [[nodiscard]] static KeyCategory GetKeyCategory(const std::wstring& keyPath) {
        RegistryEvent event;
        event.keyPath = keyPath;
        return event.GetCategory();
    }

    [[nodiscard]] ValueAnalysis AnalyzeValue(
        std::span<const uint8_t> data,
        RegistryValueType type) const {

        ValueAnalysis analysis;
        analysis.dataSize = data.size();
        analysis.type = type;
        const auto addExtractedPath = [&analysis](const std::wstring& candidate) {
            analysis.containsPath = true;
            if (std::find(analysis.extractedPaths.begin(),
                          analysis.extractedPaths.end(),
                          candidate) == analysis.extractedPaths.end()) {
                analysis.extractedPaths.push_back(candidate);
            }
        };

        try {
            // Hostile-input bound: refuse to analyze more than the documented
            // wire ceiling. Anything above this would mean the deserialiser
            // (or a future call site) violated its contract; treat as suspect
            // but do not pull the whole blob through entropy/path scans.
            const size_t analysedSize = std::min<size_t>(
                data.size(), RegistryMonitorConstants::MAX_VALUE_DATA_SIZE);
            std::span<const uint8_t> view = data.subspan(0, analysedSize);

            // Snapshot the configured threshold under shared lock; the field
            // can be mutated by Initialize() and racing reads of a non-atomic
            // size_t are undefined behaviour.
            size_t largeThreshold = 0;
            {
                std::shared_lock lock(m_mutex);
                largeThreshold = m_config.largeValueThreshold;
            }
            if (largeThreshold == 0) {
                largeThreshold = RegistryMonitorConstants::LARGE_VALUE_THRESHOLD;
            }

            if (data.size() > largeThreshold) {
                analysis.isLargeValue = true;
                analysis.riskFactors.push_back("Large value size");
            }

            if (view.size() >= RegistryMonitorConstants::MIN_BLOB_SIZE_FOR_ANALYSIS) {
                analysis.entropy = CalculateEntropyInternal(view);
                analysis.isHighEntropy = (analysis.entropy >= RegistryMonitorConstants::ENTROPY_THRESHOLD);

                if (analysis.isHighEntropy) {
                    analysis.riskFactors.push_back("High entropy (possibly encrypted/encoded)");
                }
            }

            if (type == RegistryValueType::BINARY && view.size() > 1024) {
                analysis.isBinaryBlob = true;
                analysis.riskFactors.push_back("Large binary blob");
            }

            if (ContainsExecutableSignature(view)) {
                analysis.containsExecutable = true;
                analysis.riskFactors.push_back("Contains executable signature");
            }

            // Narrow scan for ASCII script markers (e.g. legacy REG_BINARY
            // shellcode dumps, batch fragments stored as raw bytes).
            if (ContainsScriptSignature(view)) {
                analysis.containsScript = true;
                analysis.riskFactors.push_back("Contains script content");
            }

            // String analysis for REG_SZ / REG_EXPAND_SZ / REG_MULTI_SZ
            if (type == RegistryValueType::SZ ||
                type == RegistryValueType::EXPAND_SZ ||
                type == RegistryValueType::MULTI_SZ) {

                const size_t charCount = view.size() / sizeof(wchar_t);
                if (charCount > 0) {
                    const wchar_t* base = reinterpret_cast<const wchar_t*>(view.data());

                    // Defensive copy: callers may hand us non-null-terminated
                    // data. Building std::wstring from (ptr, count) guarantees
                    // an internal null terminator without reading past the end.
                    std::wstring value(base, charCount);
                    while (!value.empty() && value.back() == L'\0') {
                        value.pop_back();
                    }

                    if (charCount > value.size() + 1) {
                        // Embedded null bytes BEFORE the trailing null and
                        // before the end of the declared buffer — classic
                        // cloaking pattern (path appears short to RegEdit
                        // but the kernel writes the full hidden string).
                        analysis.riskFactors.push_back("Embedded null bytes (cloaking attempt)");
                    }

                    // Wide-character script signature scan. Catches malware
                    // that stores its PowerShell payload as a real REG_SZ
                    // (UTF-16) value, which the narrow scan above misses
                    // because of the interleaved zero bytes.
                    if (!analysis.containsScript && ContainsScriptSignatureWide(value)) {
                        analysis.containsScript = true;
                        analysis.riskFactors.push_back("Contains script content");
                    }

                    if (type == RegistryValueType::EXPAND_SZ && !value.empty()) {
                        // Two-step expansion: query required size, then
                        // expand with an exact-fit buffer. Prevents %ENV%
                        // cloaking that defeats fixed-buffer truncation.
                        const DWORD required = ExpandEnvironmentStringsW(
                            value.c_str(), nullptr, 0);
                        if (required > 0 &&
                            required <= RegistryMonitorConstants::MAX_KEY_PATH_LENGTH) {
                            std::wstring expanded(required, L'\0');
                            const DWORD wrote = ExpandEnvironmentStringsW(
                                value.c_str(), expanded.data(), required);
                            if (wrote > 0 && wrote <= required) {
                                expanded.resize(wrote > 0 ? wrote - 1 : 0);
                                if (expanded != value) {
                                    analysis.riskFactors.push_back(
                                        "Contains expandable environment variables");
                                }
                                if (IsPathLike(expanded)) {
                                    addExtractedPath(expanded);
                                }
                            }
                        }
                    }

                    if (type == RegistryValueType::MULTI_SZ) {
                        // Split on embedded nulls. Cap iterations defensively
                        // to prevent quadratic explosion on a pathologically
                        // crafted blob full of empty strings.
                        size_t entries = 0;
                        size_t i = 0;
                        while (i < charCount && entries < 1024) {
                            size_t j = i;
                            while (j < charCount && base[j] != L'\0') ++j;
                            if (j > i) {
                                std::wstring entry(base + i, j - i);
                                if (IsPathLike(entry)) addExtractedPath(entry);
                                std::string narrow = StringUtils::ToNarrow(entry);
                                if (ContainsUrlPrefix(narrow)) {
                                    analysis.containsUrl = true;
                                    if (analysis.extractedUrls.size() < 64) {
                                        analysis.extractedUrls.push_back(std::move(narrow));
                                    }
                                }
                                if (!analysis.containsScript &&
                                    ContainsScriptSignatureWide(entry)) {
                                    analysis.containsScript = true;
                                    analysis.riskFactors.push_back("Contains script content");
                                }
                                ++entries;
                            }
                            i = j + 1;
                        }
                    } else {
                        if (IsPathLike(value)) {
                            addExtractedPath(value);
                        }
                        std::string narrowValue = StringUtils::ToNarrow(value);
                        if (ContainsUrlPrefix(narrowValue)) {
                            analysis.containsUrl = true;
                            analysis.extractedUrls.push_back(std::move(narrowValue));
                        }
                    }
                }
            }

            if (analysis.riskFactors.size() >= 3) {
                analysis.risk = RiskLevel::High;
            } else if (analysis.riskFactors.size() >= 2) {
                analysis.risk = RiskLevel::Medium;
            } else if (analysis.riskFactors.size() >= 1) {
                analysis.risk = RiskLevel::Low;
            } else {
                analysis.risk = RiskLevel::Safe;
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"AnalyzeValue - Exception: %hs",
                SanitizeForLog(e.what()).c_str());
        }

        return analysis;
    }

    // ========================================================================
    // EVENT PROCESSING
    // ========================================================================

    [[nodiscard]] RegistryVerdict ProcessEvent(const RegistryEvent& event) {
        const auto startTime = std::chrono::steady_clock::now();
        RegistryVerdict resultVerdict = RegistryVerdict::Allow;

        // RAII helper: regardless of which return path we take, the event is
        // recorded into the bounded recent-events ring (forensics) and the
        // event callbacks fire. This eliminates the silent-loss bug where
        // Block/Alert/SilentDrop events vanished from the UI ring.
        struct FinalizeGuard {
            RegistryMonitorImpl* self;
            const RegistryEvent& src;
            RegistryVerdict& verdict;
            bool armed{ true };
            ~FinalizeGuard() {
                if (!armed || !self) return;
                try {
                    RegistryEvent retained = src;
                    TruncateEventForRetention(retained);
                    {
                        std::unique_lock lock(self->m_mutex);
                        self->m_recentEvents.push_back(std::move(retained));
                        while (self->m_recentEvents.size() > MAX_RECENT_EVENTS) {
                            self->m_recentEvents.pop_front();
                        }
                    }
                    self->NotifyEventCallbacks(src, verdict);
                } catch (...) {
                    // Forensic recording must never propagate exceptions.
                }
            }
        } finalize{ this, event, resultVerdict };

        try {
            m_stats.totalEvents++;

            if (ContainsNullBytes(event.keyPath)) {
                m_stats.blockedOperations++;
                SS_LOG_FATAL(L"Registry",
                    L"Null-byte key cloaking detected (PID=%u): %hs",
                    event.processId,
                    SanitizeForLog(event.keyPath).c_str());
                GenerateAlert(event, RegistryThreatType::SELF_DEFENSE_TAMPER,
                    RiskLevel::Critical, "Null-byte registry key cloaking attack");
                // Post-operation notifications cannot be blocked (kernel has
                // already applied the change); collapse Block to Allow there
                // but keep the alert + audit trail.
                resultVerdict = event.isPreOperation ? RegistryVerdict::Block
                                                     : RegistryVerdict::Allow;
                UpdatePerformanceStats(startTime);
                return resultVerdict;
            }

            if (event.keyPath.size() > RegistryMonitorConstants::MAX_KEY_PATH_LENGTH) {
                m_stats.blockedOperations++;
                SS_LOG_WARN(L"Registry", L"Key path exceeds max length (%zu > %zu)",
                    event.keyPath.size(), RegistryMonitorConstants::MAX_KEY_PATH_LENGTH);
                resultVerdict = event.isPreOperation ? RegistryVerdict::Block
                                                     : RegistryVerdict::Allow;
                UpdatePerformanceStats(startTime);
                return resultVerdict;
            }

            switch (event.operation) {
                case RegistryOp::CreateKey:   m_stats.createKeyEvents++; break;
                case RegistryOp::SetValue:    m_stats.setValueEvents++; break;
                case RegistryOp::DeleteKey:   m_stats.deleteKeyEvents++; break;
                case RegistryOp::DeleteValue: m_stats.deleteValueEvents++; break;
                case RegistryOp::RenameKey:   m_stats.renameEvents++; break;
                default: break;
            }

            RegistryMonitorConfig configSnap;
            std::vector<std::pair<uint64_t, RegistryRule>> rulesSnap;
            RegistryPolicyCallback policySnap;
            {
                std::shared_lock lock(m_mutex);
                configSnap = m_config;
                rulesSnap.reserve(m_rules.size());
                for (const auto& [id, rule] : m_rules) {
                    if (rule.enabled) {
                        rulesSnap.emplace_back(id, rule);
                    }
                }
                policySnap = m_policyCallback;
            }

            if (configSnap.selfDefenseEnabled && IsProtectedKey(event.keyPath)) {
                m_stats.selfDefenseBlocks++;
                m_stats.blockedOperations++;

                SS_LOG_FATAL(L"Registry",
                    L"Blocked access to protected key: %hs (process: %hs, PID: %u)",
                    SanitizeForLog(event.keyPath).c_str(),
                    SanitizeForLog(event.processName).c_str(),
                    event.processId);

                GenerateAlert(event, RegistryThreatType::SELF_DEFENSE_TAMPER,
                             RiskLevel::Critical, "Attempted to modify protected registry key");

                resultVerdict = event.isPreOperation ? RegistryVerdict::Block
                                                     : RegistryVerdict::Allow;
                UpdatePerformanceStats(startTime);
                return resultVerdict;
            }

            RegistryVerdict verdict = ApplyRulesSnapshot(rulesSnap, event);
            if (verdict != RegistryVerdict::Allow) {
                m_stats.blockedOperations++;
                if (verdict == RegistryVerdict::SilentDrop) {
                    m_stats.silentDropped++;
                }
                // Post-op events cannot retroactively block, but rule hits
                // still count for stats and are retained in the ring.
                resultVerdict = event.isPreOperation ? verdict : RegistryVerdict::Allow;
                UpdatePerformanceStats(startTime);
                return resultVerdict;
            }

            if (policySnap) {
                verdict = policySnap(event);
                if (verdict != RegistryVerdict::Allow) {
                    m_stats.blockedOperations++;
                    resultVerdict = event.isPreOperation ? verdict : RegistryVerdict::Allow;
                    UpdatePerformanceStats(startTime);
                    return resultVerdict;
                }
            }

            RegistryThreatType threat = DetectThreat(event, configSnap);
            if (threat != RegistryThreatType::NONE) {
                RiskLevel risk = AssessRisk(threat);

                if (risk >= RiskLevel::High) {
                    m_stats.blockedOperations++;
                    GenerateAlert(event, threat, risk, "Registry threat detected");
                    resultVerdict = event.isPreOperation ? RegistryVerdict::Block
                                                         : RegistryVerdict::Allow;
                    UpdatePerformanceStats(startTime);
                    return resultVerdict;
                } else {
                    m_stats.allowedOperations++;
                    GenerateAlert(event, threat, risk, "Suspicious registry activity");
                    resultVerdict = RegistryVerdict::Alert;
                    UpdatePerformanceStats(startTime);
                    return resultVerdict;
                }
            }

            m_stats.allowedOperations++;
            resultVerdict = RegistryVerdict::Allow;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"ProcessEvent exception: %hs",
                SanitizeForLog(e.what()).c_str());
            resultVerdict = RegistryVerdict::Allow;  // Fail-open: never freeze the kernel
        }

        UpdatePerformanceStats(startTime);
        return resultVerdict;
    }

    [[nodiscard]] std::vector<RegistryEvent> GetRecentEvents(size_t maxCount) const {
        std::shared_lock lock(m_mutex);

        std::vector<RegistryEvent> events;
        size_t count = std::min(maxCount, m_recentEvents.size());
        events.reserve(count);

        auto it = m_recentEvents.rbegin();
        for (size_t i = 0; i < count && it != m_recentEvents.rend(); ++i, ++it) {
            events.push_back(*it);
        }

        return events;
    }

    // ========================================================================
    // DECEPTION
    // ========================================================================

    void ConfigureDeception(const DeceptionConfig& config) {
        std::unique_lock lock(m_mutex);
        m_config.deception = config;
        if (m_config.deception.honeypotKeys.size() > kMaxHoneypotKeys) {
            m_config.deception.honeypotKeys.resize(kMaxHoneypotKeys);
            SS_LOG_WARN(L"Registry", L"Honeypot key list truncated to %zu entries",
                kMaxHoneypotKeys);
        }
        SS_LOG_INFO(L"Registry", L"Deception mode configured (enabled=%d)", config.enabled ? 1 : 0);
    }

    void AddHoneypotKey(const std::wstring& keyPath) {
        std::unique_lock lock(m_mutex);
        if (keyPath.empty() ||
            keyPath.size() > RegistryMonitorConstants::MAX_KEY_PATH_LENGTH ||
            ContainsNullBytes(keyPath)) {
            SS_LOG_WARN(L"Registry", L"AddHoneypotKey rejected: invalid path");
            return;
        }
        if (m_config.deception.honeypotKeys.size() >= kMaxHoneypotKeys) {
            SS_LOG_ERROR(L"Registry", L"AddHoneypotKey rejected: limit %zu reached",
                kMaxHoneypotKeys);
            return;
        }
        m_config.deception.honeypotKeys.push_back(keyPath);
        SS_LOG_INFO(L"Registry", L"Added honeypot key: %hs",
            SanitizeForLog(keyPath).c_str());
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    [[nodiscard]] uint64_t RegisterAlertCallback(RegistryAlertCallback callback) {
        std::unique_lock lock(m_mutex);
        uint64_t id = ++m_nextCallbackId;
        m_alertCallbacks[id] = std::move(callback);
        return id;
    }

    [[nodiscard]] uint64_t RegisterEventCallback(RegistryEventCallback callback) {
        std::unique_lock lock(m_mutex);
        uint64_t id = ++m_nextCallbackId;
        m_eventCallbacks[id] = std::move(callback);
        return id;
    }

    [[nodiscard]] uint64_t RegisterValueCallback(ValueAnalysisCallback callback) {
        std::unique_lock lock(m_mutex);
        uint64_t id = ++m_nextCallbackId;
        m_valueCallbacks[id] = std::move(callback);
        return id;
    }

    bool UnregisterCallback(uint64_t callbackId) {
        std::unique_lock lock(m_mutex);

        bool removed = false;
        removed |= (m_alertCallbacks.erase(callbackId) > 0);
        removed |= (m_eventCallbacks.erase(callbackId) > 0);
        removed |= (m_valueCallbacks.erase(callbackId) > 0);

        return removed;
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const RegistryMonitorStatistics& GetStatistics() const noexcept {
        return m_stats;
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
    }

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    [[nodiscard]] bool PerformDiagnostics() const {
        std::shared_lock lock(m_mutex);

        try {
            SS_LOG_INFO(L"Registry", L"=== RegistryMonitor Diagnostics ===");
            SS_LOG_INFO(L"Registry", L"Initialized: %d", m_initialized ? 1 : 0);
            SS_LOG_INFO(L"Registry", L"Running: %d", m_running ? 1 : 0);
            SS_LOG_INFO(L"Registry", L"Kernel connected: %d", m_kernelConnected ? 1 : 0);
            SS_LOG_INFO(L"Registry", L"Rules: %zu", m_rules.size());
            SS_LOG_INFO(L"Registry", L"Protected keys: %zu", m_protectedKeys.size());
            SS_LOG_INFO(L"Registry", L"Total events: %llu",
                static_cast<unsigned long long>(m_stats.totalEvents.load()));
            SS_LOG_INFO(L"Registry", L"Blocked operations: %llu",
                static_cast<unsigned long long>(m_stats.blockedOperations.load()));
            SS_LOG_INFO(L"Registry", L"Persistence attempts: %llu",
                static_cast<unsigned long long>(m_stats.persistenceAttempts.load()));
            SS_LOG_INFO(L"Registry", L"Self-defense blocks: %llu",
                static_cast<unsigned long long>(m_stats.selfDefenseBlocks.load()));
            SS_LOG_INFO(L"Registry", L"Avg callback latency: %llu us",
                static_cast<unsigned long long>(m_stats.avgCallbackTimeUs.load()));

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"PerformDiagnostics exception: %hs", e.what());
            return false;
        }
    }

    bool ExportDiagnostics(const std::wstring& outputPath) const {
        std::shared_lock lock(m_mutex);

        try {
            // Validate path length
            if (outputPath.empty() || outputPath.size() > MAX_PATH) {
                SS_LOG_ERROR(L"Registry", L"ExportDiagnostics: invalid path");
                return false;
            }

            std::ofstream out(outputPath, std::ios::trunc);
            if (!out.is_open()) {
                SS_LOG_ERROR(L"Registry", L"ExportDiagnostics: failed to open %ls", outputPath.c_str());
                return false;
            }

            out << "=== ShadowStrike RegistryMonitor Diagnostics ===\n";
            out << "Initialized: " << m_initialized << "\n";
            out << "Running: " << m_running << "\n";
            out << "Kernel connected: " << m_kernelConnected << "\n";
            out << "Rules: " << m_rules.size() << "\n";
            out << "Protected keys: " << m_protectedKeys.size() << "\n";
            out << "Total events: " << m_stats.totalEvents.load() << "\n";
            out << "Blocked operations: " << m_stats.blockedOperations.load() << "\n";
            out << "Allowed operations: " << m_stats.allowedOperations.load() << "\n";
            out << "Silent drops: " << m_stats.silentDropped.load() << "\n";
            out << "Persistence attempts: " << m_stats.persistenceAttempts.load() << "\n";
            out << "Fileless payloads: " << m_stats.filelessPayloads.load() << "\n";
            out << "Security changes: " << m_stats.securityChanges.load() << "\n";
            out << "Self-defense blocks: " << m_stats.selfDefenseBlocks.load() << "\n";
            out << "Alerts generated: " << m_stats.alertsGenerated.load() << "\n";
            out << "Critical alerts: " << m_stats.criticalAlerts.load() << "\n";
            out << "Avg callback us: " << m_stats.avgCallbackTimeUs.load() << "\n";
            out << "Max callback us: " << m_stats.maxCallbackTimeUs.load() << "\n";
            out << "Dropped events: " << m_stats.droppedEvents.load() << "\n";

            out.flush();
            if (out.fail()) {
                SS_LOG_ERROR(L"Registry", L"ExportDiagnostics: write error to %ls", outputPath.c_str());
                return false;
            }

            SS_LOG_INFO(L"Registry", L"Exported diagnostics to: %ls", outputPath.c_str());
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"ExportDiagnostics exception: %hs", e.what());
            return false;
        }
    }

private:
    // ========================================================================
    // INTERNAL METHODS
    // ========================================================================

    void SetupSelfDefenseKeys() {
        // Helper: push both the ProtectedKey and its precomputed lowercase
        // path so the IsProtectedKey hot path stays cache-aligned with no
        // per-call ToLowerCopy on the protected-key set.
        const auto addSelfDefenseKey = [this](std::wstring path,
                                              bool includeSecurity = false) {
            ProtectedKey pk;
            pk.keyPath = path;
            pk.includeSubkeys = true;
            pk.protectValues = true;
            pk.protectDelete = true;
            pk.protectRename = true;
            pk.protectSecurity = includeSecurity;
            pk.isSelfDefense = true;
            m_protectedKeysLower.push_back(StringUtils::ToLowerCopy(path));
            m_protectedKeys.push_back(std::move(pk));
        };

        // Protect ShadowStrike registry keys in BOTH kernel path format and
        // user-mode format. The kernel sends \Registry\Machine\... paths;
        // user-mode policy code may use HKLM\... — both must match.
        addSelfDefenseKey(L"\\Registry\\Machine\\SOFTWARE\\ShadowStrike", true);
        addSelfDefenseKey(L"HKLM\\SOFTWARE\\ShadowStrike", true);

        // Service keys.
        addSelfDefenseKey(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\ShadowStrike");
        addSelfDefenseKey(L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\ShadowStrike");

        // Sensor driver parameters.
        addSelfDefenseKey(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\PhantomSensor");

        // Wow6432Node variant — prevents 32-bit-redirection bypass.
        addSelfDefenseKey(L"\\Registry\\Machine\\SOFTWARE\\Wow6432Node\\ShadowStrike");

        SS_LOG_INFO(L"Registry", L"Self-defense keys configured (%zu entries)",
            m_protectedKeys.size());
    }

    [[nodiscard]] bool ConnectToKernelDriver() {
        try {
            SS_LOG_INFO(L"Registry", L"Connecting to ShadowStrike Registry Filter port: %ls",
                RegistryMonitorConstants::COMMUNICATION_PORT);

            m_connection = std::make_unique<Communication::FilterConnection>(
                RegistryMonitorConstants::COMMUNICATION_PORT);

            if (m_connection->Connect()) {
                SS_LOG_INFO(L"Registry", L"Successfully connected to kernel registry filter");
                return true;
            }

            SS_LOG_ERROR(L"Registry", L"Failed to connect to kernel registry filter: %hs",
                m_connection->GetLastErrorMessage().c_str());
            return false;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"ConnectToKernelDriver exception: %hs",
                SanitizeForLog(e.what()).c_str());
            return false;
        }
    }

    void StartWorkerThreads() {
        m_stopRequested = false;

        for (uint32_t i = 0; i < m_config.workerThreads; ++i) {
            m_workerThreads.emplace_back([this]() {
                WorkerThreadProc();
            });
        }
    }

    void StopWorkerThreads() {
        for (auto& thread : m_workerThreads) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        m_workerThreads.clear();
    }

    void WorkerThreadProc() {
        SS_LOG_DEBUG(L"Registry", L"Registry worker thread started (tid=%u)",
            ::GetCurrentThreadId());

        std::vector<uint8_t> messageBuffer(Communication::MAX_MESSAGE_SIZE);

        // Reconnect backoff state. We start at 500 ms and cap at 30 s so a
        // permanent kernel-side fault does not pin a CPU. Only one worker
        // performs the reconnect attempt at a time, gated by m_mutex.
        std::chrono::milliseconds reconnectDelay{ 500 };
        constexpr std::chrono::milliseconds kReconnectMin{ 500 };
        constexpr std::chrono::milliseconds kReconnectMax{ 30000 };

        while (!m_stopRequested) {
            // Connection liveness gate. If the kernel filter port has dropped
            // (driver unload, FltSendMessage failure, etc.), attempt to
            // reconnect under unique_lock so multiple workers do not race on
            // m_connection. Reads of m_connection are otherwise safe because
            // the pointer itself is only replaced under unique_lock and the
            // FilterConnection object is internally thread-safe.
            bool connected = false;
            {
                std::shared_lock lock(m_mutex);
                connected = (m_connection && m_connection->IsConnected());
            }

            if (!connected) {
                if (m_stopRequested) break;

                // Attempt reconnect — bounded, single-flight.
                bool didReconnect = false;
                {
                    std::unique_lock lock(m_mutex);
                    if (!m_stopRequested && m_connection &&
                        !m_connection->IsConnected()) {
                        if (m_connection->Connect()) {
                            m_kernelConnected = true;
                            didReconnect = true;
                        }
                    } else if (m_connection && m_connection->IsConnected()) {
                        didReconnect = true;
                    }
                }

                if (didReconnect) {
                    SS_LOG_INFO(L"Registry",
                        L"Reconnected to kernel registry filter (worker tid=%u)",
                        ::GetCurrentThreadId());
                    reconnectDelay = kReconnectMin;
                    continue;
                }

                std::this_thread::sleep_for(reconnectDelay);
                reconnectDelay = std::min(reconnectDelay * 2, kReconnectMax);
                continue;
            }
            reconnectDelay = kReconnectMin;

            size_t bytesReceived = 0;
            try {
                std::shared_lock lock(m_mutex);
                if (!m_connection) {
                    lock.unlock();
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }
                const auto recv = m_connection->GetMessage(messageBuffer, 1000);
                bytesReceived = recv.payloadBytes;

                // A frame we could not decrypt still has a kernel thread waiting
                // on it, and its Filter Manager MessageId survives in cleartext.
                // Release the waiter with a Clean verdict rather than letting it
                // time out: the driver treats an unanswered scan as "not scanned,
                // allowed" anyway, but each timeout also feeds the scan-bridge
                // circuit breaker, which stops scanning altogether once it trips.
                if (recv.ReplyOwed()) {
                    Communication::ScanVerdictReply failOpen{};
                    failOpen.messageId      = recv.replyOwedId;
                    failOpen.verdict        = Communication::ScanVerdict::Clean;
                    failOpen.threatDetected = false;
                    auto foBuf = Communication::MessageDispatcher::SerializeVerdictReply(failOpen);
                    if (!foBuf.empty() && m_connection) {
                        (void)m_connection->ReplyMessage(foBuf, recv.replyOwedId);
                    }
                    SS_LOG_WARN(L"Registry", L"Undecryptable frame answered fail-open "
                        L"to release kernel waiter msgId=%llu",
                        static_cast<unsigned long long>(recv.replyOwedId));
                }
            } catch (const std::exception& e) {
                SS_LOG_WARN(L"Registry", L"GetMessage threw: %hs",
                    SanitizeForLog(e.what()).c_str());
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            } catch (...) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            if (bytesReceived < sizeof(Communication::MessageHeader)) {
                continue;
            }
            if (bytesReceived > messageBuffer.size()) {
                // Filter-driver protocol violation; drop and resync.
                m_stats.droppedEvents++;
                continue;
            }

            auto* header = reinterpret_cast<const Communication::MessageHeader*>(messageBuffer.data());
            if (!header->IsValid()) {
                m_stats.droppedEvents++;
                continue;
            }

            if (header->messageType != static_cast<uint16_t>(Communication::MessageType::RegistryNotify)) {
                continue;
            }

            // Authoritative payload size comes from the header's declared
            // dataSize, NOT from bytesReceived. An attacker who somehow
            // injected trailing bytes (or a buggy driver) must not be able
            // to feed us data beyond the header's contract. We clamp to the
            // minimum of received-bytes-minus-header and declared dataSize.
            if (header->dataSize < sizeof(Communication::RegistryNotificationData)) {
                m_stats.droppedEvents++;
                SS_LOG_WARN(L"Registry", L"Undersized registry notification (dataSize=%u)",
                    static_cast<unsigned>(header->dataSize));
                continue;
            }
            const size_t headerSize = sizeof(Communication::MessageHeader);
            if (bytesReceived < headerSize + sizeof(Communication::RegistryNotificationData)) {
                m_stats.droppedEvents++;
                SS_LOG_WARN(L"Registry", L"Truncated registry notification (bytes=%zu)",
                    bytesReceived);
                continue;
            }

            const size_t declaredPayload = header->dataSize;
            const size_t receivedPayload = bytesReceived - headerSize;
            const size_t payloadSize = std::min(declaredPayload, receivedPayload);

            const auto* regData = reinterpret_cast<const Communication::RegistryNotificationData*>(
                messageBuffer.data() + headerSize);

            // Strict enum validation: refuse to dispatch unknown operation
            // codes. RegistryOp values are sparse (gaps between 5-10, 13-20,
            // etc.). We accept anything in the declared upper bound and let
            // downstream code use Unknown for unmapped gaps.
            const uint32_t rawOp = regData->operationType;
            if (rawOp > static_cast<uint32_t>(RegistryOp::RollbackTransaction)) {
                m_stats.droppedEvents++;
                SS_LOG_WARN(L"Registry", L"Rejected unknown operationType=%u msgId=%llu",
                    rawOp,
                    static_cast<unsigned long long>(header->messageId));
                continue;
            }

            RegistryEvent event;
            event.eventId = header->messageId;
            event.timestamp = std::chrono::system_clock::now();
            event.processId = regData->processId;
            event.threadId = regData->threadId;
            event.operation = static_cast<RegistryOp>(rawOp);
            event.isPreOperation = (regData->flags & 0x01) != 0;
            event.isTransacted = (regData->flags & 0x02) != 0;
            event.valueType = static_cast<RegistryValueType>(regData->valueType);

            const uint8_t* varData = messageBuffer.data() +
                headerSize + sizeof(Communication::RegistryNotificationData);
            const size_t varAvailable = payloadSize -
                sizeof(Communication::RegistryNotificationData);

            size_t offset = 0;

            // keyPathLength and valueNameLength are uint16 (chars), so the
            // multiplication by sizeof(wchar_t)=2 cannot overflow size_t.
            // We still cap to MAX_KEY_PATH_LENGTH to prevent allocation
            // amplification from a 65535-char attacker-supplied path.
            const size_t keyPathBytes =
                static_cast<size_t>(regData->keyPathLength) * sizeof(wchar_t);
            if (keyPathBytes > 0 && offset + keyPathBytes <= varAvailable &&
                regData->keyPathLength <= RegistryMonitorConstants::MAX_KEY_PATH_LENGTH) {
                event.keyPath.assign(
                    reinterpret_cast<const wchar_t*>(varData + offset),
                    regData->keyPathLength);
                offset += keyPathBytes;
            } else if (keyPathBytes > 0) {
                m_stats.droppedEvents++;
                SS_LOG_WARN(L"Registry", L"Rejected oversized keyPath chars=%u msgId=%llu",
                    static_cast<unsigned>(regData->keyPathLength),
                    static_cast<unsigned long long>(header->messageId));
                continue;
            }

            const size_t valueNameBytes =
                static_cast<size_t>(regData->valueNameLength) * sizeof(wchar_t);
            if (valueNameBytes > 0 && offset + valueNameBytes <= varAvailable &&
                regData->valueNameLength <= RegistryMonitorConstants::MAX_VALUE_NAME_LENGTH) {
                event.valueName.assign(
                    reinterpret_cast<const wchar_t*>(varData + offset),
                    regData->valueNameLength);
                offset += valueNameBytes;
            } else if (valueNameBytes > 0) {
                m_stats.droppedEvents++;
                SS_LOG_WARN(L"Registry", L"Rejected oversized valueName chars=%u msgId=%llu",
                    static_cast<unsigned>(regData->valueNameLength),
                    static_cast<unsigned long long>(header->messageId));
                continue;
            }

            if (regData->valueDataLength > 0 &&
                offset + regData->valueDataLength <= varAvailable &&
                regData->valueDataLength <= RegistryMonitorConstants::MAX_VALUE_DATA_SIZE) {
                event.data.assign(
                    varData + offset,
                    varData + offset + regData->valueDataLength);
                offset += regData->valueDataLength;
            } else if (regData->valueDataLength > 0) {
                m_stats.droppedEvents++;
                SS_LOG_WARN(L"Registry",
                    L"Rejected oversized valueData bytes=%u msgId=%llu",
                    static_cast<unsigned>(regData->valueDataLength),
                    static_cast<unsigned long long>(header->messageId));
                continue;
            }

            // Enrich with process context (best-effort, non-blocking).
            // GetProcessName returns just the basename — what UIs expect —
            // so we use it instead of narrowing the full process path.
            try {
                auto procPath = ProcessUtils::GetProcessPath(event.processId);
                if (procPath.has_value()) {
                    event.processPath = procPath.value();
                }
                auto procName = ProcessUtils::GetProcessName(event.processId);
                if (procName.has_value()) {
                    event.processName = StringUtils::ToNarrow(procName.value());
                } else if (procPath.has_value()) {
                    event.processName = ProcessBaseName(procPath.value());
                }
                ProcessUtils::ProcessBasicInfo basicInfo;
                if (ProcessUtils::GetProcessBasicInfo(event.processId, basicInfo)) {
                    event.sessionId = basicInfo.sessionId;
                }
                ProcessUtils::ProcessSecurityInfo secInfo;
                if (ProcessUtils::GetProcessSecurityInfo(event.processId, secInfo)) {
                    event.isElevated = secInfo.isElevated;
                }
            } catch (...) {
                // Process may have exited; proceed with PID only.
            }

            RegistryVerdict verdict = ProcessEvent(event);

            // Reply gate: only pre-operations can be blocked. The kernel must
            // not be told to apply a post-op verdict (the change is already
            // committed) and must not be left waiting if it did not request
            // a reply. requiresReply is the authoritative flag.
            if (regData->requiresReply && event.isPreOperation) {
                Communication::ScanVerdictReply reply{};
                reply.messageId = header->messageId;
                reply.shouldCache = false;
                reply.cacheTTL = 0;
                reply.threatScore = 0;

                switch (verdict) {
                    case RegistryVerdict::Block:
                        reply.verdict = Communication::ScanVerdict::Malicious;
                        reply.threatDetected = true;
                        reply.threatScore = 100;
                        break;
                    case RegistryVerdict::SilentDrop:
                        reply.verdict = Communication::ScanVerdict::Clean;
                        reply.threatDetected = false;
                        break;
                    case RegistryVerdict::Alert:
                        reply.verdict = Communication::ScanVerdict::Suspicious;
                        reply.threatDetected = true;
                        reply.threatScore = 50;
                        break;
                    default:
                        reply.verdict = Communication::ScanVerdict::Clean;
                        reply.threatDetected = false;
                        break;
                }

                auto replyBuf = Communication::MessageDispatcher::SerializeVerdictReply(reply);
                if (!replyBuf.empty()) {
                    std::shared_lock lock(m_mutex);
                    if (m_connection &&
                        !m_connection->ReplyMessage(replyBuf, header->messageId)) {
                        SS_LOG_WARN(L"Registry", L"Failed to reply verdict for msgId=%llu",
                            static_cast<unsigned long long>(header->messageId));
                    }
                }
            } else if (regData->requiresReply) {
                // Post-op required a reply: send Clean to release the kernel
                // without blocking. Verdict was used only for telemetry.
                Communication::ScanVerdictReply reply{};
                reply.messageId = header->messageId;
                reply.verdict = Communication::ScanVerdict::Clean;
                reply.threatDetected = false;
                auto replyBuf = Communication::MessageDispatcher::SerializeVerdictReply(reply);
                if (!replyBuf.empty()) {
                    std::shared_lock lock(m_mutex);
                    if (m_connection) {
                        (void)m_connection->ReplyMessage(replyBuf, header->messageId);
                    }
                }
            }
        }

        SS_LOG_DEBUG(L"Registry", L"Registry worker thread stopped (tid=%u)",
            ::GetCurrentThreadId());
    }

    // Lock-free variant operating on a pre-snapshotted rule set (used by ProcessEvent)
    [[nodiscard]] RegistryVerdict ApplyRulesSnapshot(
        std::vector<std::pair<uint64_t, RegistryRule>>& rules,
        const RegistryEvent& event) {

        std::sort(rules.begin(), rules.end(),
            [](const auto& a, const auto& b) {
                return a.second.priority > b.second.priority;
            });

        for (auto& [id, rule] : rules) {
            if (RuleMatches(rule, event)) {
                rule.matchCount++;
                return rule.verdict;
            }
        }

        return RegistryVerdict::Allow;
    }

    [[nodiscard]] bool RuleMatches(const RegistryRule& rule, const RegistryEvent& event) const {
        // Check rule expiration
        if (!rule.isPermanent && rule.expiresAt != std::chrono::system_clock::time_point{}) {
            if (std::chrono::system_clock::now() > rule.expiresAt) {
                return false;
            }
        }

        if (rule.operation.has_value() && rule.operation.value() != event.operation) {
            return false;
        }

        if (rule.valueType.has_value() && rule.valueType.value() != event.valueType) {
            return false;
        }

        // Key path matching (case-insensitive)
        if (!rule.keyPathPattern.empty()) {
            if (!StringUtils::IContains(event.keyPath, rule.keyPathPattern)) {
                // Try wildcard: prefix*
                size_t starPos = rule.keyPathPattern.find(L'*');
                if (starPos != std::wstring::npos) {
                    const std::wstring prefix = StringUtils::ToLowerCopy(
                        rule.keyPathPattern.substr(0, starPos));
                    const std::wstring lowerPath = StringUtils::ToLowerCopy(event.keyPath);
                    if (!lowerPath.starts_with(prefix)) {
                        return false;
                    }
                } else {
                    if (!StringUtils::IEquals(event.keyPath, rule.keyPathPattern)) {
                        return false;
                    }
                }
            }
        }

        // Process path match (case-insensitive contains)
        if (!rule.processPathPattern.empty()) {
            if (!StringUtils::IContains(event.processPath, rule.processPathPattern)) {
                return false;
            }
        }

        // Process ID match
        if (!rule.processIds.empty()) {
            if (std::find(rule.processIds.begin(), rule.processIds.end(),
                          event.processId) == rule.processIds.end()) {
                return false;
            }
        }

        // User SID match
        if (!rule.userSidPattern.empty()) {
            if (!StringUtils::IContains(event.userSid, rule.userSidPattern)) {
                return false;
            }
        }

        return true;
    }

    [[nodiscard]] RegistryThreatType DetectThreat(
        const RegistryEvent& event,
        const RegistryMonitorConfig& cfg) {
        // Persistence detection
        if (cfg.detectPersistence && event.IsPersistenceKey()) {
            m_stats.persistenceAttempts++;

            if (event.keyPath.find(L"\\Run") != std::wstring::npos) {
                return RegistryThreatType::PERSISTENCE_RUN_KEY;
            }
            if (event.IsServiceKey()) {
                return RegistryThreatType::PERSISTENCE_SERVICE;
            }
            if (event.keyPath.find(L"Winlogon") != std::wstring::npos) {
                return RegistryThreatType::PERSISTENCE_WINLOGON;
            }
            if (event.keyPath.find(L"Image File Execution Options") != std::wstring::npos) {
                return RegistryThreatType::PERSISTENCE_IFEO;
            }
        }

        // COM hijacking
        if (event.IsCOMKey()) {
            return RegistryThreatType::COM_HIJACK;
        }

        // Security changes
        if (cfg.detectSecurityChanges && event.IsSecurityKey()) {
            m_stats.securityChanges++;

            if (event.keyPath.find(L"Windows Defender") != std::wstring::npos) {
                return RegistryThreatType::DEFENDER_DISABLE;
            }
            if (event.keyPath.find(L"AMSI") != std::wstring::npos) {
                return RegistryThreatType::AMSI_BYPASS;
            }
            if (event.keyPath.find(L"ETW") != std::wstring::npos ||
                event.keyPath.find(L"Autologger") != std::wstring::npos) {
                return RegistryThreatType::ETW_BYPASS;
            }
        }

        // Fileless detection
        if (cfg.detectFileless && cfg.analyzeValues &&
            event.operation == RegistryOp::SetValue && !event.data.empty()) {

            auto analysis = AnalyzeValue(event.data, event.valueType);
            InvokeValueCallbacks(event, analysis);

            if (analysis.isBinaryBlob && analysis.isLargeValue) {
                m_stats.filelessPayloads++;
                return RegistryThreatType::FILELESS_PAYLOAD;
            }

            if (analysis.containsScript) {
                m_stats.filelessPayloads++;
                return RegistryThreatType::ENCODED_SCRIPT;
            }

            if (analysis.isHighEntropy && analysis.isLargeValue) {
                m_stats.filelessPayloads++;
                return RegistryThreatType::ENCODED_SCRIPT;
            }
        }

        // Network changes
        if (event.IsNetworkKey()) {
            if (event.keyPath.find(L"Internet Settings") != std::wstring::npos) {
                return RegistryThreatType::PROXY_MODIFICATION;
            }
            if (event.keyPath.find(L"Tcpip\\Parameters") != std::wstring::npos) {
                return RegistryThreatType::DNS_MODIFICATION;
            }
        }

        return RegistryThreatType::NONE;
    }

    // Backwards-compatible overload: snapshot the config under shared_lock for
    // any caller that still passes only the event. New call sites should pass
    // the snapshotted config explicitly to avoid the extra lock.
    [[nodiscard]] RegistryThreatType DetectThreat(const RegistryEvent& event) {
        RegistryMonitorConfig snap;
        {
            std::shared_lock lock(m_mutex);
            snap = m_config;
        }
        return DetectThreat(event, snap);
    }

    [[nodiscard]] RiskLevel AssessRisk(RegistryThreatType threat) const {
        switch (threat) {
            case RegistryThreatType::SELF_DEFENSE_TAMPER:
            case RegistryThreatType::DEFENDER_DISABLE:
            case RegistryThreatType::AMSI_BYPASS:
            case RegistryThreatType::ETW_BYPASS:
                return RiskLevel::Critical;

            case RegistryThreatType::PERSISTENCE_SERVICE:
            case RegistryThreatType::PERSISTENCE_WINLOGON:
            case RegistryThreatType::PERSISTENCE_IFEO:
            case RegistryThreatType::FILELESS_PAYLOAD:
                return RiskLevel::High;

            case RegistryThreatType::PERSISTENCE_RUN_KEY:
            case RegistryThreatType::COM_HIJACK:
            case RegistryThreatType::ENCODED_SCRIPT:
                return RiskLevel::Medium;

            default:
                return RiskLevel::Low;
        }
    }

    void GenerateAlert(const RegistryEvent& event, RegistryThreatType threat,
                      RiskLevel risk, const std::string& description) {

        // Dedup gate: collapse identical alert events that fire repeatedly
        // inside the dedup window (e.g. a tight write loop on a Run key).
        // Statistics are still incremented per attempt, but we suppress the
        // callback storm + log spam. Self-defense / critical events bypass
        // dedup so analysts never miss a single tamper attempt.
        const uint64_t evtHash = HashEventForDedup(
            event.processId,
            static_cast<uint8_t>(event.operation),
            event.keyPath,
            event.valueName) ^ static_cast<uint64_t>(threat);
        bool suppressed = false;
        if (risk < RiskLevel::Critical) {
            std::unique_lock lock(m_mutex);
            const auto now = std::chrono::steady_clock::now();
            auto it = m_dedupRing.find(evtHash);
            if (it != m_dedupRing.end()) {
                if (now - it->second < kDedupWindow) {
                    suppressed = true;
                } else {
                    it->second = now;
                }
            } else {
                if (m_dedupOrder.size() < kDedupRingSize) {
                    m_dedupOrder.push_back(evtHash);
                } else {
                    // FIFO eviction
                    const uint64_t evicted = m_dedupOrder[m_dedupNextSlot];
                    m_dedupRing.erase(evicted);
                    m_dedupOrder[m_dedupNextSlot] = evtHash;
                    m_dedupNextSlot = (m_dedupNextSlot + 1) % kDedupRingSize;
                }
                m_dedupRing.emplace(evtHash, now);
            }
        }

        if (suppressed) {
            m_stats.alertsGenerated++;
            return;
        }

        RegistryAlert alert;
        alert.alertId = ++m_nextAlertId;
        alert.eventId = event.eventId;
        alert.timestamp = std::chrono::system_clock::now();

        alert.threatType = threat;
        alert.risk = risk;
        alert.description = description;

        alert.operation = event.operation;
        alert.keyPath = event.keyPath;
        alert.valueName = event.valueName;

        alert.processId = event.processId;
        alert.processPath = event.processPath;
        alert.userName = event.userName;

        switch (threat) {
            case RegistryThreatType::PERSISTENCE_RUN_KEY:
                alert.mitreTechnique = "T1547";
                alert.mitreSubTechnique = "T1547.001";
                break;
            case RegistryThreatType::PERSISTENCE_WINLOGON:
                alert.mitreTechnique = "T1547";
                alert.mitreSubTechnique = "T1547.004";
                break;
            case RegistryThreatType::COM_HIJACK:
                alert.mitreTechnique = "T1546";
                alert.mitreSubTechnique = "T1546.015";
                break;
            case RegistryThreatType::PERSISTENCE_IFEO:
                alert.mitreTechnique = "T1546";
                alert.mitreSubTechnique = "T1546.012";
                break;
            default:
                alert.mitreTechnique = "T1112";
                break;
        }

        m_stats.alertsGenerated++;
        if (risk == RiskLevel::Critical) {
            m_stats.criticalAlerts++;
        }

        InvokeAlertCallbacks(alert);

        SS_LOG_WARN(L"Registry", L"Registry alert: %hs (PID=%u, key=%hs)",
            SanitizeForLog(description).c_str(),
            event.processId,
            SanitizeForLog(event.keyPath).c_str());
    }

    void InvokeAlertCallbacks(const RegistryAlert& alert) {
        // Snapshot callbacks under lock, invoke outside lock to prevent deadlock
        std::vector<RegistryAlertCallback> callbacks;
        {
            std::shared_lock lock(m_mutex);
            callbacks.reserve(m_alertCallbacks.size());
            for (const auto& [id, cb] : m_alertCallbacks) {
                if (cb) callbacks.push_back(cb);
            }
        }

        for (const auto& callback : callbacks) {
            try {
                callback(alert);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Registry", L"Alert callback threw: %hs",
                    SanitizeForLog(e.what()).c_str());
            }
        }
    }

    void InvokeValueCallbacks(const RegistryEvent& event,
                              const ValueAnalysis& analysis) {
        std::vector<ValueAnalysisCallback> callbacks;
        {
            std::shared_lock lock(m_mutex);
            callbacks.reserve(m_valueCallbacks.size());
            for (const auto& [id, cb] : m_valueCallbacks) {
                if (cb) callbacks.push_back(cb);
            }
        }
        for (const auto& callback : callbacks) {
            try {
                callback(event, analysis);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Registry", L"Value callback threw: %hs",
                    SanitizeForLog(e.what()).c_str());
            }
        }
    }

    void NotifyEventCallbacks(const RegistryEvent& event, RegistryVerdict verdict) {
        std::vector<RegistryEventCallback> callbacks;
        {
            std::shared_lock lock(m_mutex);
            callbacks.reserve(m_eventCallbacks.size());
            for (const auto& [id, cb] : m_eventCallbacks) {
                if (cb) callbacks.push_back(cb);
            }
        }

        for (const auto& callback : callbacks) {
            try {
                callback(event, verdict);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Registry", L"Event callback threw: %hs",
                    SanitizeForLog(e.what()).c_str());
            }
        }
    }

    void UpdatePerformanceStats(std::chrono::steady_clock::time_point startTime) noexcept {
        try {
            const auto endTime = std::chrono::steady_clock::now();
            const uint64_t latencyUs = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count());

            // Update running average (approximate, avoid division by zero)
            const uint64_t events = m_stats.totalEvents.load(std::memory_order_relaxed);
            if (events > 0) {
                const uint64_t currentAvg = m_stats.avgCallbackTimeUs.load(std::memory_order_relaxed);
                // Exponential moving average: new_avg ≈ old_avg * 0.99 + sample * 0.01
                // Approximation using integer math to avoid float on hot path
                const uint64_t newAvg = currentAvg - (currentAvg / 128) + (latencyUs / 128);
                m_stats.avgCallbackTimeUs.store(newAvg, std::memory_order_relaxed);
            } else {
                m_stats.avgCallbackTimeUs.store(latencyUs, std::memory_order_relaxed);
            }

            // Update max (CAS loop for correctness)
            uint64_t currentMax = m_stats.maxCallbackTimeUs.load(std::memory_order_relaxed);
            while (latencyUs > currentMax) {
                if (m_stats.maxCallbackTimeUs.compare_exchange_weak(
                        currentMax, latencyUs,
                        std::memory_order_relaxed, std::memory_order_relaxed)) {
                    break;
                }
            }

        } catch (...) {
            // Performance stats are advisory; never let them crash the monitor
        }
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };
    bool m_running{ false };
    bool m_kernelConnected{ false };
    std::atomic<bool> m_stopRequested{ false };

    RegistryMonitorConfig m_config;
    RegistryMonitorStatistics m_stats;

    // Kernel communication
    std::unique_ptr<Communication::FilterConnection> m_connection;

    // Worker threads
    std::vector<std::thread> m_workerThreads;

    // Policy
    RegistryPolicyCallback m_policyCallback;
    std::unordered_map<uint64_t, RegistryRule> m_rules;
    uint64_t m_nextRuleId{ 0 };

    // Protection
    std::vector<ProtectedKey> m_protectedKeys;
    // Parallel cache of pre-lowercased keyPaths for IsProtectedKey hot path.
    // Kept strictly in sync with m_protectedKeys (1:1 index correspondence)
    // under the unique_lock taken in AddProtectedKey / RemoveProtectedKey /
    // Shutdown. Reading is allowed under shared_lock.
    std::vector<std::wstring> m_protectedKeysLower;

    // Recent events
    std::deque<RegistryEvent> m_recentEvents;
    static constexpr size_t MAX_RECENT_EVENTS = 1000;

    // Callbacks
    std::unordered_map<uint64_t, RegistryAlertCallback> m_alertCallbacks;
    std::unordered_map<uint64_t, RegistryEventCallback> m_eventCallbacks;
    std::unordered_map<uint64_t, ValueAnalysisCallback> m_valueCallbacks;
    uint64_t m_nextCallbackId{ 0 };

    // Alert tracking
    std::atomic<uint64_t> m_nextAlertId{ 1 };

    // Alert dedup ring. Maps event-hash -> last-seen timestamp; a FIFO ring
    // (m_dedupOrder + m_dedupNextSlot) bounds the total membership to
    // kDedupRingSize entries, preventing memory growth under flood. Protected
    // by m_mutex.
    std::unordered_map<uint64_t, std::chrono::steady_clock::time_point> m_dedupRing;
    std::vector<uint64_t> m_dedupOrder;
    size_t m_dedupNextSlot{ 0 };
};

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

RegistryMonitor& RegistryMonitor::Instance() {
    static RegistryMonitor instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

RegistryMonitor::RegistryMonitor()
    : m_impl(std::make_unique<RegistryMonitorImpl>()) {
    SS_LOG_INFO(L"Registry", L"RegistryMonitor instance created");
}

RegistryMonitor::~RegistryMonitor() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    SS_LOG_INFO(L"Registry", L"RegistryMonitor instance destroyed");
}

// ============================================================================
// PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

bool RegistryMonitor::Initialize(const RegistryMonitorConfig& config) {
    return m_impl->Initialize(config);
}

bool RegistryMonitor::Start() {
    return m_impl->Start();
}

void RegistryMonitor::Stop() {
    m_impl->Stop();
}

void RegistryMonitor::Shutdown() noexcept {
    m_impl->Shutdown();
}

bool RegistryMonitor::IsRunning() const noexcept {
    return m_impl->IsRunning();
}

bool RegistryMonitor::IsKernelConnected() const noexcept {
    return m_impl->IsKernelConnected();
}

// ========================================================================
// POLICY MANAGEMENT
// ========================================================================

void RegistryMonitor::SetPolicyCallback(RegistryPolicyCallback callback) {
    m_impl->SetPolicyCallback(std::move(callback));
}

uint64_t RegistryMonitor::AddRule(const RegistryRule& rule) {
    return m_impl->AddRule(rule);
}

bool RegistryMonitor::RemoveRule(uint64_t ruleId) {
    return m_impl->RemoveRule(ruleId);
}

std::vector<RegistryRule> RegistryMonitor::GetRules() const {
    return m_impl->GetRules();
}

bool RegistryMonitor::SetRuleEnabled(uint64_t ruleId, bool enabled) {
    return m_impl->SetRuleEnabled(ruleId, enabled);
}

// ========================================================================
// KEY PROTECTION
// ========================================================================

void RegistryMonitor::AddProtectedKey(const std::wstring& keyPath) {
    m_impl->AddProtectedKey(keyPath);
}

void RegistryMonitor::AddProtectedKey(const ProtectedKey& config) {
    m_impl->AddProtectedKey(config);
}

void RegistryMonitor::RemoveProtectedKey(const std::wstring& keyPath) {
    m_impl->RemoveProtectedKey(keyPath);
}

bool RegistryMonitor::IsProtectedKey(const std::wstring& keyPath) const {
    return m_impl->IsProtectedKey(keyPath);
}

std::vector<ProtectedKey> RegistryMonitor::GetProtectedKeys() const {
    return m_impl->GetProtectedKeys();
}

// ========================================================================
// KEY ANALYSIS
// ========================================================================

bool RegistryMonitor::IsCriticalKey(const std::wstring& keyPath) {
    return RegistryMonitorImpl::IsCriticalKey(keyPath);
}

KeyCategory RegistryMonitor::GetKeyCategory(const std::wstring& keyPath) {
    return RegistryMonitorImpl::GetKeyCategory(keyPath);
}

ValueAnalysis RegistryMonitor::AnalyzeValue(
    std::span<const uint8_t> data,
    RegistryValueType type) const {
    return m_impl->AnalyzeValue(data, type);
}

// ========================================================================
// EVENT HANDLING
// ========================================================================

RegistryVerdict RegistryMonitor::ProcessEvent(const RegistryEvent& event) {
    return m_impl->ProcessEvent(event);
}

std::vector<RegistryEvent> RegistryMonitor::GetRecentEvents(size_t maxCount) const {
    return m_impl->GetRecentEvents(maxCount);
}

// ========================================================================
// DECEPTION
// ========================================================================

void RegistryMonitor::ConfigureDeception(const DeceptionConfig& config) {
    m_impl->ConfigureDeception(config);
}

void RegistryMonitor::AddHoneypotKey(const std::wstring& keyPath) {
    m_impl->AddHoneypotKey(keyPath);
}

// ========================================================================
// CALLBACKS
// ========================================================================

uint64_t RegistryMonitor::RegisterAlertCallback(RegistryAlertCallback callback) {
    return m_impl->RegisterAlertCallback(std::move(callback));
}

uint64_t RegistryMonitor::RegisterEventCallback(RegistryEventCallback callback) {
    return m_impl->RegisterEventCallback(std::move(callback));
}

uint64_t RegistryMonitor::RegisterValueCallback(ValueAnalysisCallback callback) {
    return m_impl->RegisterValueCallback(std::move(callback));
}

bool RegistryMonitor::UnregisterCallback(uint64_t callbackId) {
    return m_impl->UnregisterCallback(callbackId);
}

// ========================================================================
// STATISTICS
// ========================================================================

const RegistryMonitorStatistics& RegistryMonitor::GetStatistics() const noexcept {
    return m_impl->GetStatistics();
}

void RegistryMonitor::ResetStatistics() noexcept {
    m_impl->ResetStatistics();
}

// ========================================================================
// DIAGNOSTICS
// ========================================================================

bool RegistryMonitor::PerformDiagnostics() const {
    return m_impl->PerformDiagnostics();
}

bool RegistryMonitor::ExportDiagnostics(const std::wstring& outputPath) const {
    return m_impl->ExportDiagnostics(outputPath);
}

}  // namespace Registry
}  // namespace Core
}  // namespace ShadowStrike
