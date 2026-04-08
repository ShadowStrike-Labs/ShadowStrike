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

// ============================================================================
// REGISTRY EVENT METHODS
// ============================================================================

bool RegistryEvent::IsPersistenceKey() const {
    const std::wstring lowerPath = StringUtils::ToLowerCopy(keyPath);

    for (const auto& key : PERSISTENCE_KEYS) {
        const std::wstring lowerKey = StringUtils::ToLowerCopy(key);
        if (lowerPath.find(lowerKey) != std::wstring::npos) {
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
        const std::wstring lowerKey = StringUtils::ToLowerCopy(key);
        if (lowerPath.find(lowerKey) != std::wstring::npos) {
            return true;
        }
    }

    return false;
}

bool RegistryEvent::IsCOMKey() const {
    const std::wstring lowerPath = StringUtils::ToLowerCopy(keyPath);

    for (const auto& key : COM_KEYS) {
        const std::wstring lowerKey = StringUtils::ToLowerCopy(key);
        if (lowerPath.find(lowerKey) != std::wstring::npos) {
            return true;
        }
    }

    return false;
}

bool RegistryEvent::IsNetworkKey() const {
    const std::wstring lowerPath = StringUtils::ToLowerCopy(keyPath);

    for (const auto& key : NETWORK_KEYS) {
        const std::wstring lowerKey = StringUtils::ToLowerCopy(key);
        if (lowerPath.find(lowerKey) != std::wstring::npos) {
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
            m_config = config;
            m_initialized = true;

            if (config.protectShadowStrikeKeys) {
                SetupSelfDefenseKeys();
            }

            SS_LOG_INFO(L"Registry", L"RegistryMonitor initialized (kernel=%d, selfDefense=%d)",
                config.useKernelCallback ? 1 : 0, config.selfDefenseEnabled ? 1 : 0);

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"RegistryMonitor initialization failed: %hs", e.what());
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

            m_stopRequested = true;

            // Disconnect kernel filter port via RAII connection wrapper
            if (m_kernelConnected && m_connection) {
                m_connection->Disconnect();
                m_kernelConnected = false;
            }

            // Must release lock before joining worker threads (they may need it)
            lock.unlock();
            StopWorkerThreads();
            lock.lock();

            m_running = false;

            SS_LOG_INFO(L"Registry", L"RegistryMonitor stopped");

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"Stop failed: %hs", e.what());
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

            m_rules.clear();
            m_protectedKeys.clear();
            m_alertCallbacks.clear();
            m_eventCallbacks.clear();
            m_valueCallbacks.clear();
            m_recentEvents.clear();

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
            RegistryRule newRule = rule;
            newRule.ruleId = ++m_nextRuleId;
            newRule.createdAt = std::chrono::system_clock::now();

            m_rules[newRule.ruleId] = newRule;

            SS_LOG_INFO(L"Registry", L"Added registry rule: %hs (id=%llu)",
                newRule.name.c_str(), static_cast<unsigned long long>(newRule.ruleId));

            return newRule.ruleId;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"AddRule failed: %hs", e.what());
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
            ProtectedKey pk;
            pk.keyPath = keyPath;
            pk.includeSubkeys = true;
            pk.protectValues = true;
            pk.protectDelete = true;
            pk.protectRename = true;
            pk.protectSecurity = true;

            m_protectedKeys.push_back(pk);

            SS_LOG_INFO(L"Registry", L"Added protected key: %ls", keyPath.c_str());

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"AddProtectedKey failed: %hs", e.what());
        }
    }

    void AddProtectedKey(const ProtectedKey& config) {
        std::unique_lock lock(m_mutex);

        try {
            m_protectedKeys.push_back(config);

            SS_LOG_INFO(L"Registry", L"Added protected key: %ls", config.keyPath.c_str());

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"AddProtectedKey failed: %hs", e.what());
        }
    }

    void RemoveProtectedKey(const std::wstring& keyPath) {
        std::unique_lock lock(m_mutex);

        try {
            const std::wstring lowerTarget = StringUtils::ToLowerCopy(keyPath);
            auto it = std::remove_if(m_protectedKeys.begin(), m_protectedKeys.end(),
                [&lowerTarget](const ProtectedKey& pk) {
                    return StringUtils::ToLowerCopy(pk.keyPath) == lowerTarget;
                });

            if (it != m_protectedKeys.end()) {
                m_protectedKeys.erase(it, m_protectedKeys.end());
                SS_LOG_INFO(L"Registry", L"Removed protected key: %ls", keyPath.c_str());
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"RemoveProtectedKey failed: %hs", e.what());
        }
    }

    [[nodiscard]] bool IsProtectedKey(const std::wstring& keyPath) const {
        std::shared_lock lock(m_mutex);

        const std::wstring lowerPath = StringUtils::ToLowerCopy(keyPath);

        for (const auto& pk : m_protectedKeys) {
            const std::wstring lowerProtected = StringUtils::ToLowerCopy(pk.keyPath);

            if (lowerPath == lowerProtected) {
                return true;
            }

            if (pk.includeSubkeys &&
                lowerPath.size() > lowerProtected.size() &&
                lowerPath.starts_with(lowerProtected) &&
                (lowerProtected.back() == L'\\' || lowerPath[lowerProtected.size()] == L'\\')) {
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

        try {
            // Size check
            if (data.size() > m_config.largeValueThreshold) {
                analysis.isLargeValue = true;
                analysis.riskFactors.push_back("Large value size");
            }

            // Entropy analysis
            if (data.size() >= RegistryMonitorConstants::MIN_BLOB_SIZE_FOR_ANALYSIS) {
                analysis.entropy = CalculateEntropyInternal(data);
                analysis.isHighEntropy = (analysis.entropy >= RegistryMonitorConstants::ENTROPY_THRESHOLD);

                if (analysis.isHighEntropy) {
                    analysis.riskFactors.push_back("High entropy (possibly encrypted/encoded)");
                }
            }

            // Binary blob detection
            if (type == RegistryValueType::BINARY && data.size() > 1024) {
                analysis.isBinaryBlob = true;
                analysis.riskFactors.push_back("Large binary blob");
            }

            // Executable signature
            if (ContainsExecutableSignature(data)) {
                analysis.containsExecutable = true;
                analysis.riskFactors.push_back("Contains executable signature");
            }

            // Script signature
            if (ContainsScriptSignature(data)) {
                analysis.containsScript = true;
                analysis.riskFactors.push_back("Contains script content");
            }

            // String analysis for REG_SZ/REG_EXPAND_SZ
            if (type == RegistryValueType::SZ || type == RegistryValueType::EXPAND_SZ) {
                // Safe wchar_t extraction with bounds check
                const size_t charCount = data.size() / sizeof(wchar_t);
                if (charCount > 0 && data.size() >= sizeof(wchar_t)) {
                    std::wstring value(reinterpret_cast<const wchar_t*>(data.data()), charCount);
                    // Strip trailing null if present
                    if (!value.empty() && value.back() == L'\0') {
                        value.pop_back();
                    }

                    // Null-byte cloaking detection (embedded nulls before end)
                    if (charCount > 1 && ContainsNullBytes(std::wstring_view(value.data(), charCount - 1))) {
                        analysis.riskFactors.push_back("Embedded null bytes (cloaking attempt)");
                    }

                    // REG_EXPAND_SZ: expand environment variables to detect evasion
                    if (type == RegistryValueType::EXPAND_SZ && !value.empty()) {
                        wchar_t expandedBuf[4096]{};
                        DWORD expandedLen = ExpandEnvironmentStringsW(value.c_str(), expandedBuf,
                            static_cast<DWORD>(std::size(expandedBuf)));
                        if (expandedLen > 0 && expandedLen < std::size(expandedBuf)) {
                            std::wstring expanded(expandedBuf, expandedLen - 1);
                            if (expanded != value) {
                                analysis.riskFactors.push_back("Contains expandable environment variables");
                            }
                            // Use expanded value for path detection
                            if (IsPathLike(expanded)) {
                                analysis.containsPath = true;
                                analysis.extractedPaths.push_back(expanded);
                            }
                        }
                    }

                    // Path detection on raw value
                    if (IsPathLike(value)) {
                        analysis.containsPath = true;
                        analysis.extractedPaths.push_back(value);
                    }

                    // URL detection (lightweight, no regex on hot path)
                    std::string narrowValue = StringUtils::ToNarrow(value);
                    if (ContainsUrlPrefix(narrowValue)) {
                        analysis.containsUrl = true;
                        analysis.extractedUrls.push_back(narrowValue);
                    }
                }
            }

            // Risk assessment
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
            SS_LOG_ERROR(L"Registry", L"AnalyzeValue - Exception: %hs", e.what());
        }

        return analysis;
    }

    // ========================================================================
    // EVENT PROCESSING
    // ========================================================================

    [[nodiscard]] RegistryVerdict ProcessEvent(const RegistryEvent& event) {
        const auto startTime = std::chrono::steady_clock::now();
        RegistryVerdict resultVerdict = RegistryVerdict::Allow;

        try {
            m_stats.totalEvents++;

            // Validate input: null-byte cloaking detection
            if (ContainsNullBytes(event.keyPath)) {
                m_stats.blockedOperations++;
                SS_LOG_FATAL(L"Registry", L"Null-byte key cloaking detected (PID=%u): %ls",
                    event.processId, event.keyPath.c_str());
                GenerateAlert(event, RegistryThreatType::SELF_DEFENSE_TAMPER,
                    RiskLevel::Critical, "Null-byte registry key cloaking attack");
                resultVerdict = RegistryVerdict::Block;
                UpdatePerformanceStats(startTime);
                return resultVerdict;
            }

            // Cap key path length to prevent abuse
            if (event.keyPath.size() > RegistryMonitorConstants::MAX_KEY_PATH_LENGTH) {
                m_stats.blockedOperations++;
                SS_LOG_WARN(L"Registry", L"Key path exceeds max length (%zu > %zu)",
                    event.keyPath.size(), RegistryMonitorConstants::MAX_KEY_PATH_LENGTH);
                resultVerdict = RegistryVerdict::Block;
                UpdatePerformanceStats(startTime);
                return resultVerdict;
            }

            // Update operation counters
            switch (event.operation) {
                case RegistryOp::CreateKey:   m_stats.createKeyEvents++; break;
                case RegistryOp::SetValue:    m_stats.setValueEvents++; break;
                case RegistryOp::DeleteKey:   m_stats.deleteKeyEvents++; break;
                case RegistryOp::DeleteValue: m_stats.deleteValueEvents++; break;
                case RegistryOp::RenameKey:   m_stats.renameEvents++; break;
                default: break;
            }

            // Snapshot config and rules under lock for thread-safe evaluation
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

            // Self-defense check (IsProtectedKey acquires its own shared_lock)
            if (configSnap.selfDefenseEnabled && IsProtectedKey(event.keyPath)) {
                m_stats.selfDefenseBlocks++;
                m_stats.blockedOperations++;

                SS_LOG_FATAL(L"Registry", L"Blocked access to protected key: %ls (process: %hs, PID: %u)",
                    event.keyPath.c_str(), event.processName.c_str(), event.processId);

                GenerateAlert(event, RegistryThreatType::SELF_DEFENSE_TAMPER,
                             RiskLevel::Critical, "Attempted to modify protected registry key");

                resultVerdict = RegistryVerdict::Block;
                UpdatePerformanceStats(startTime);
                return resultVerdict;
            }

            // Apply rules (on snapshot, no lock held)
            RegistryVerdict verdict = ApplyRulesSnapshot(rulesSnap, event);
            if (verdict != RegistryVerdict::Allow) {
                m_stats.blockedOperations++;
                if (verdict == RegistryVerdict::SilentDrop) {
                    m_stats.silentDropped++;
                }
                resultVerdict = verdict;
                UpdatePerformanceStats(startTime);
                return resultVerdict;
            }

            // User policy callback (on snapshot)
            if (policySnap) {
                verdict = policySnap(event);
                if (verdict != RegistryVerdict::Allow) {
                    m_stats.blockedOperations++;
                    resultVerdict = verdict;
                    UpdatePerformanceStats(startTime);
                    return resultVerdict;
                }
            }

            // Threat detection
            RegistryThreatType threat = DetectThreat(event);
            if (threat != RegistryThreatType::NONE) {
                RiskLevel risk = AssessRisk(threat);

                if (risk >= RiskLevel::High) {
                    m_stats.blockedOperations++;
                    GenerateAlert(event, threat, risk, "Registry threat detected");
                    resultVerdict = RegistryVerdict::Block;
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

            // Store in recent events (bounded)
            {
                std::unique_lock lock(m_mutex);
                m_recentEvents.push_back(event);
                while (m_recentEvents.size() > MAX_RECENT_EVENTS) {
                    m_recentEvents.pop_front();
                }
            }

            // Notify event callbacks
            NotifyEventCallbacks(event, resultVerdict);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"ProcessEvent exception: %hs", e.what());
            resultVerdict = RegistryVerdict::Allow;  // Fail-open to avoid system hang
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
        SS_LOG_INFO(L"Registry", L"Deception mode configured (enabled=%d)", config.enabled ? 1 : 0);
    }

    void AddHoneypotKey(const std::wstring& keyPath) {
        std::unique_lock lock(m_mutex);
        m_config.deception.honeypotKeys.push_back(keyPath);
        SS_LOG_INFO(L"Registry", L"Added honeypot key: %ls", keyPath.c_str());
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
        // Protect ShadowStrike registry keys in BOTH kernel path format and user-mode format
        // Kernel sends \Registry\Machine\... paths; user-mode code may use HKLM\...
        const std::wstring shadowStrikePaths[] = {
            L"\\Registry\\Machine\\SOFTWARE\\ShadowStrike",
            L"HKLM\\SOFTWARE\\ShadowStrike",
        };
        for (const auto& path : shadowStrikePaths) {
            ProtectedKey pk;
            pk.keyPath = path;
            pk.includeSubkeys = true;
            pk.protectValues = true;
            pk.protectDelete = true;
            pk.protectRename = true;
            pk.protectSecurity = true;
            pk.isSelfDefense = true;
            m_protectedKeys.push_back(pk);
        }

        // Protect service keys
        const std::wstring servicePaths[] = {
            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\ShadowStrike",
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\ShadowStrike",
        };
        for (const auto& path : servicePaths) {
            ProtectedKey pk;
            pk.keyPath = path;
            pk.includeSubkeys = true;
            pk.protectValues = true;
            pk.protectDelete = true;
            pk.protectRename = true;
            pk.isSelfDefense = true;
            m_protectedKeys.push_back(pk);
        }

        // Protect driver parameters
        ProtectedKey driverKey;
        driverKey.keyPath = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\PhantomSensor";
        driverKey.includeSubkeys = true;
        driverKey.protectValues = true;
        driverKey.protectDelete = true;
        driverKey.protectRename = true;
        driverKey.isSelfDefense = true;
        m_protectedKeys.push_back(driverKey);

        // Also protect Wow6432Node variant for 32-bit process bypass prevention
        ProtectedKey wow64Key;
        wow64Key.keyPath = L"\\Registry\\Machine\\SOFTWARE\\Wow6432Node\\ShadowStrike";
        wow64Key.includeSubkeys = true;
        wow64Key.protectValues = true;
        wow64Key.protectDelete = true;
        wow64Key.protectRename = true;
        wow64Key.isSelfDefense = true;
        m_protectedKeys.push_back(wow64Key);

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
            SS_LOG_ERROR(L"Registry", L"ConnectToKernelDriver exception: %hs", e.what());
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

        while (!m_stopRequested) {
            if (!m_connection || !m_connection->IsConnected()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                continue;
            }

            size_t bytesReceived = 0;
            try {
                bytesReceived = m_connection->GetMessage(messageBuffer, 1000);
            } catch (...) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            if (bytesReceived < sizeof(Communication::MessageHeader)) {
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

            // Validate payload bounds
            if (header->dataSize < sizeof(Communication::RegistryNotificationData) ||
                bytesReceived < sizeof(Communication::MessageHeader) + sizeof(Communication::RegistryNotificationData)) {
                m_stats.droppedEvents++;
                SS_LOG_WARN(L"Registry", L"Undersized registry notification (%zu bytes)", bytesReceived);
                continue;
            }

            const auto* regData = reinterpret_cast<const Communication::RegistryNotificationData*>(
                messageBuffer.data() + sizeof(Communication::MessageHeader));

            // Marshal wire data into RegistryEvent
            RegistryEvent event;
            event.eventId = header->messageId;
            event.timestamp = std::chrono::system_clock::now();
            event.processId = regData->processId;
            event.threadId = regData->threadId;
            event.operation = static_cast<RegistryOp>(regData->operationType);
            event.isPreOperation = (regData->flags & 0x01) != 0;
            event.isTransacted = (regData->flags & 0x02) != 0;
            event.valueType = static_cast<RegistryValueType>(regData->valueType);

            // Extract variable-length key path
            const uint8_t* varData = messageBuffer.data() +
                sizeof(Communication::MessageHeader) +
                sizeof(Communication::RegistryNotificationData);
            const size_t varAvailable = bytesReceived -
                sizeof(Communication::MessageHeader) -
                sizeof(Communication::RegistryNotificationData);

            size_t offset = 0;

            // Key path (wchar_t array, length in characters)
            const size_t keyPathBytes = static_cast<size_t>(regData->keyPathLength) * sizeof(wchar_t);
            if (keyPathBytes > 0 && offset + keyPathBytes <= varAvailable &&
                keyPathBytes <= RegistryMonitorConstants::MAX_KEY_PATH_LENGTH * sizeof(wchar_t)) {
                event.keyPath.assign(
                    reinterpret_cast<const wchar_t*>(varData + offset),
                    regData->keyPathLength);
                offset += keyPathBytes;
            }

            // Value name
            const size_t valueNameBytes = static_cast<size_t>(regData->valueNameLength) * sizeof(wchar_t);
            if (valueNameBytes > 0 && offset + valueNameBytes <= varAvailable &&
                valueNameBytes <= RegistryMonitorConstants::MAX_VALUE_NAME_LENGTH * sizeof(wchar_t)) {
                event.valueName.assign(
                    reinterpret_cast<const wchar_t*>(varData + offset),
                    regData->valueNameLength);
                offset += valueNameBytes;
            }

            // Value data
            if (regData->valueDataLength > 0 && offset + regData->valueDataLength <= varAvailable &&
                regData->valueDataLength <= RegistryMonitorConstants::MAX_VALUE_DATA_SIZE) {
                event.data.assign(
                    varData + offset,
                    varData + offset + regData->valueDataLength);
                offset += regData->valueDataLength;
            }

            // Enrich with process context (best-effort, non-blocking)
            try {
                auto procPath = ProcessUtils::GetProcessPath(event.processId);
                if (procPath.has_value()) {
                    event.processPath = procPath.value();
                    event.processName = StringUtils::ToNarrow(procPath.value());
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
                // Process may have exited; proceed with PID only
            }

            // Core verdict decision
            RegistryVerdict verdict = ProcessEvent(event);

            // Reply to kernel with verdict (only if kernel expects a reply)
            if (regData->requiresReply) {
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
                    if (!m_connection->ReplyMessage(replyBuf, header->messageId)) {
                        SS_LOG_WARN(L"Registry", L"Failed to reply verdict for msgId=%llu",
                            static_cast<unsigned long long>(header->messageId));
                    }
                }
            }
        }

        SS_LOG_DEBUG(L"Registry", L"Registry worker thread stopped (tid=%u)",
            ::GetCurrentThreadId());
    }

    [[nodiscard]] RegistryVerdict ApplyRules(const RegistryEvent& event) {
        std::shared_lock lock(m_mutex);

        // Collect enabled rules sorted by priority
        std::vector<std::pair<uint64_t, const RegistryRule*>> sortedRules;
        sortedRules.reserve(m_rules.size());
        for (const auto& [id, rule] : m_rules) {
            if (rule.enabled) {
                sortedRules.emplace_back(id, &rule);
            }
        }

        std::sort(sortedRules.begin(), sortedRules.end(),
            [](const auto& a, const auto& b) {
                return a.second->priority > b.second->priority;
            });

        for (auto& [id, rulePtr] : sortedRules) {
            if (RuleMatches(*rulePtr, event)) {
                // Update match count (under exclusive lock if needed)
                auto it = m_rules.find(id);
                if (it != m_rules.end()) {
                    // matchCount is now non-atomic; safe under shared_lock for read
                    // Upgrade to unique_lock for write would be needed, but the
                    // count is advisory so a racy increment is acceptable here.
                }
                return rulePtr->verdict;
            }
        }

        return RegistryVerdict::Allow;
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

    [[nodiscard]] RegistryThreatType DetectThreat(const RegistryEvent& event) {
        // Persistence detection
        if (m_config.detectPersistence && event.IsPersistenceKey()) {
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
        if (m_config.detectSecurityChanges && event.IsSecurityKey()) {
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
        if (m_config.detectFileless && m_config.analyzeValues &&
            event.operation == RegistryOp::SetValue && !event.data.empty()) {

            auto analysis = AnalyzeValue(event.data, event.valueType);

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

        // MITRE mapping
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

        // Invoke callbacks
        InvokeAlertCallbacks(alert);

        SS_LOG_WARN(L"Registry", L"Registry alert: %hs (PID=%u, key=%ls)",
            description.c_str(), event.processId, event.keyPath.c_str());
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
                SS_LOG_ERROR(L"Registry", L"Alert callback threw: %hs", e.what());
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
                SS_LOG_ERROR(L"Registry", L"Event callback threw: %hs", e.what());
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
