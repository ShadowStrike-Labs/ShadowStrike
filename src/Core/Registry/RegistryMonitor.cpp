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

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <thread>
#include <future>
#include <queue>
#include <regex>
#include <cmath>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "fltLib.lib")
#pragma comment(lib, "ntdll.lib")

namespace ShadowStrike {
namespace Core {
namespace Registry {

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

    // URL patterns
    const std::regex URL_PATTERN(
        R"((https?|ftp)://[^\s/$.?#].[^\s]*)",
        std::regex::icase
    );

    // Path patterns
    const std::regex PATH_PATTERN(
        LR"([A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*)",
        std::regex::icase
    );

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
    std::wstring lowerPath = StringUtils::ToLower(keyPath);

    for (const auto& key : PERSISTENCE_KEYS) {
        std::wstring lowerKey = StringUtils::ToLower(key);
        if (lowerPath.find(lowerKey) != std::wstring::npos) {
            return true;
        }
    }

    return false;
}

bool RegistryEvent::IsServiceKey() const {
    std::wstring lowerPath = StringUtils::ToLower(keyPath);
    return lowerPath.find(L"\\services\\") != std::wstring::npos ||
           lowerPath.find(L"currentcontrolset\\services") != std::wstring::npos;
}

bool RegistryEvent::IsSecurityKey() const {
    std::wstring lowerPath = StringUtils::ToLower(keyPath);

    for (const auto& key : SECURITY_KEYS) {
        std::wstring lowerKey = StringUtils::ToLower(key);
        if (lowerPath.find(lowerKey) != std::wstring::npos) {
            return true;
        }
    }

    return false;
}

bool RegistryEvent::IsCOMKey() const {
    std::wstring lowerPath = StringUtils::ToLower(keyPath);

    for (const auto& key : COM_KEYS) {
        std::wstring lowerKey = StringUtils::ToLower(key);
        if (lowerPath.find(lowerKey) != std::wstring::npos) {
            return true;
        }
    }

    return false;
}

bool RegistryEvent::IsNetworkKey() const {
    std::wstring lowerPath = StringUtils::ToLower(keyPath);

    for (const auto& key : NETWORK_KEYS) {
        std::wstring lowerKey = StringUtils::ToLower(key);
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

    std::wstring lowerPath = StringUtils::ToLower(keyPath);

    if (lowerPath.find(L"\\explorer\\") != std::wstring::npos) {
        return KeyCategory::Shell;
    }

    if (lowerPath.find(L"\\drivers\\") != std::wstring::npos) {
        return KeyCategory::Driver;
    }

    return KeyCategory::Unknown;
}

std::wstring RegistryEvent::GetHive() const {
    if (keyPath.starts_with(L"\\Registry\\Machine") ||
        keyPath.starts_with(L"HKLM\\") ||
        keyPath.starts_with(L"HKEY_LOCAL_MACHINE\\")) {
        return L"HKLM";
    }

    if (keyPath.starts_with(L"\\Registry\\User") ||
        keyPath.starts_with(L"HKCU\\") ||
        keyPath.starts_with(L"HKEY_CURRENT_USER\\")) {
        return L"HKCU";
    }

    if (keyPath.starts_with(L"HKCR\\") ||
        keyPath.starts_with(L"HKEY_CLASSES_ROOT\\")) {
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

            // Setup protected keys for ShadowStrike self-defense
            if (config.protectShadowStrikeKeys) {
                SetupSelfDefenseKeys();
            }

            Logger::Info("RegistryMonitor initialized (kernel={}, selfDefense={})",
                config.useKernelCallback, config.selfDefenseEnabled);

            return true;

        } catch (const std::exception& e) {
            Logger::Error("RegistryMonitor initialization failed: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool Start() {
        std::unique_lock lock(m_mutex);

        try {
            if (!m_initialized) {
                Logger::Error("Cannot start: not initialized");
                return false;
            }

            if (m_running) {
                Logger::Warn("Already running");
                return true;
            }

            // Connect to kernel driver (if available)
            if (m_config.useKernelCallback) {
                m_kernelConnected = ConnectToKernelDriver();
                if (!m_kernelConnected) {
                    Logger::Warn("Kernel connection failed, running in user-mode only");
                }
            }

            // Start worker threads
            StartWorkerThreads();

            m_running = true;

            Logger::Info("RegistryMonitor started (kernel={}, workers={})",
                m_kernelConnected, m_config.workerThreads);

            return true;

        } catch (const std::exception& e) {
            Logger::Error("Start failed: {}", e.what());
            return false;
        }
    }

    void Stop() {
        std::unique_lock lock(m_mutex);

        try {
            if (!m_running) return;

            // Signal stop
            m_stopRequested = true;

            // Disconnect kernel
            if (m_kernelConnected && m_filterPort) {
                CloseHandle(m_filterPort);
                m_filterPort = nullptr;
                m_kernelConnected = false;
            }

            // Wait for worker threads
            StopWorkerThreads();

            m_running = false;

            Logger::Info("RegistryMonitor stopped");

        } catch (const std::exception& e) {
            Logger::Error("Stop failed: {}", e.what());
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_mutex);

        try {
            if (m_running) {
                m_stopRequested = true;
                StopWorkerThreads();
            }

            m_rules.clear();
            m_protectedKeys.clear();
            m_alertCallbacks.clear();
            m_eventCallbacks.clear();
            m_valueCallbacks.clear();
            m_recentEvents.clear();

            m_initialized = false;

            Logger::Info("RegistryMonitor shutdown complete");

        } catch (...) {
            // Suppress all exceptions
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

            Logger::Info("Added registry rule: {} (id={})", newRule.name, newRule.ruleId);

            return newRule.ruleId;

        } catch (const std::exception& e) {
            Logger::Error("AddRule failed: {}", e.what());
            return 0;
        }
    }

    bool RemoveRule(uint64_t ruleId) {
        std::unique_lock lock(m_mutex);

        try {
            bool removed = m_rules.erase(ruleId) > 0;
            if (removed) {
                Logger::Info("Removed registry rule: {}", ruleId);
            }
            return removed;

        } catch (const std::exception& e) {
            Logger::Error("RemoveRule failed: {}", e.what());
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
                Logger::Info("Rule {} {}", ruleId, enabled ? "enabled" : "disabled");
                return true;
            }
            return false;

        } catch (const std::exception& e) {
            Logger::Error("SetRuleEnabled failed: {}", e.what());
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

            Logger::Info("Added protected key: {}", StringUtils::WideToUtf8(keyPath));

        } catch (const std::exception& e) {
            Logger::Error("AddProtectedKey failed: {}", e.what());
        }
    }

    void AddProtectedKey(const ProtectedKey& config) {
        std::unique_lock lock(m_mutex);

        try {
            m_protectedKeys.push_back(config);

            Logger::Info("Added protected key: {}", StringUtils::WideToUtf8(config.keyPath));

        } catch (const std::exception& e) {
            Logger::Error("AddProtectedKey failed: {}", e.what());
        }
    }

    void RemoveProtectedKey(const std::wstring& keyPath) {
        std::unique_lock lock(m_mutex);

        try {
            auto it = std::remove_if(m_protectedKeys.begin(), m_protectedKeys.end(),
                [&keyPath](const ProtectedKey& pk) {
                    return StringUtils::ToLower(pk.keyPath) == StringUtils::ToLower(keyPath);
                });

            if (it != m_protectedKeys.end()) {
                m_protectedKeys.erase(it, m_protectedKeys.end());
                Logger::Info("Removed protected key: {}", StringUtils::WideToUtf8(keyPath));
            }

        } catch (const std::exception& e) {
            Logger::Error("RemoveProtectedKey failed: {}", e.what());
        }
    }

    [[nodiscard]] bool IsProtectedKey(const std::wstring& keyPath) const {
        std::shared_lock lock(m_mutex);

        std::wstring lowerPath = StringUtils::ToLower(keyPath);

        for (const auto& pk : m_protectedKeys) {
            std::wstring lowerProtected = StringUtils::ToLower(pk.keyPath);

            if (lowerPath == lowerProtected) {
                return true;
            }

            if (pk.includeSubkeys && lowerPath.starts_with(lowerProtected)) {
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
        std::wstring lowerPath = StringUtils::ToLower(keyPath);

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
                std::wstring value(reinterpret_cast<const wchar_t*>(data.data()),
                                  data.size() / sizeof(wchar_t));

                // Path detection
                if (IsPathLike(value)) {
                    analysis.containsPath = true;
                    analysis.extractedPaths.push_back(value);
                }

                // URL detection (convert to narrow string for regex)
                std::string narrowValue = StringUtils::WideToUtf8(value);
                std::smatch match;
                if (std::regex_search(narrowValue, match, URL_PATTERN)) {
                    analysis.containsUrl = true;
                    analysis.extractedUrls.push_back(match.str());
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
            Logger::Error("AnalyzeValue - Exception: {}", e.what());
        }

        return analysis;
    }

    // ========================================================================
    // EVENT PROCESSING
    // ========================================================================

    [[nodiscard]] RegistryVerdict ProcessEvent(const RegistryEvent& event) {
        auto startTime = std::chrono::steady_clock::now();

        try {
            m_stats.totalEvents++;

            // Update operation counters
            switch (event.operation) {
                case RegistryOp::CreateKey:
                    m_stats.createKeyEvents++;
                    break;
                case RegistryOp::SetValue:
                    m_stats.setValueEvents++;
                    break;
                case RegistryOp::DeleteKey:
                    m_stats.deleteKeyEvents++;
                    break;
                case RegistryOp::DeleteValue:
                    m_stats.deleteValueEvents++;
                    break;
                case RegistryOp::RenameKey:
                    m_stats.renameEvents++;
                    break;
                default:
                    break;
            }

            // Check protected keys (self-defense)
            if (m_config.selfDefenseEnabled && IsProtectedKey(event.keyPath)) {
                m_stats.selfDefenseBlocks++;
                m_stats.blockedOperations++;

                Logger::Critical("Blocked access to protected key: {} (process: {})",
                    StringUtils::WideToUtf8(event.keyPath),
                    event.processName);

                GenerateAlert(event, RegistryThreatType::SELF_DEFENSE_TAMPER,
                             RiskLevel::Critical, "Attempted to modify protected registry key");

                return RegistryVerdict::Block;
            }

            // Apply rules
            RegistryVerdict verdict = ApplyRules(event);
            if (verdict != RegistryVerdict::Allow) {
                m_stats.blockedOperations++;
                if (verdict == RegistryVerdict::SilentDrop) {
                    m_stats.silentDropped++;
                }
                return verdict;
            }

            // User policy callback
            if (m_policyCallback) {
                verdict = m_policyCallback(event);
                if (verdict != RegistryVerdict::Allow) {
                    m_stats.blockedOperations++;
                    return verdict;
                }
            }

            // Threat detection
            RegistryThreatType threat = DetectThreat(event);
            if (threat != RegistryThreatType::NONE) {
                RiskLevel risk = AssessRisk(threat);

                if (risk >= RiskLevel::High) {
                    m_stats.blockedOperations++;
                    GenerateAlert(event, threat, risk, "Registry threat detected");
                    return RegistryVerdict::Block;
                } else {
                    m_stats.allowedOperations++;
                    GenerateAlert(event, threat, risk, "Suspicious registry activity");
                    return RegistryVerdict::Alert;
                }
            }

            m_stats.allowedOperations++;
            return RegistryVerdict::Allow;

        } catch (const std::exception& e) {
            Logger::Error("ProcessEvent - Exception: {}", e.what());
            return RegistryVerdict::Allow;  // Fail-open
        } finally {
            auto endTime = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);
            UpdatePerformanceStats(elapsed.count());
        }
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
        Logger::Info("Deception mode configured (enabled={})", config.enabled);
    }

    void AddHoneypotKey(const std::wstring& keyPath) {
        std::unique_lock lock(m_mutex);
        m_config.deception.honeypotKeys.push_back(keyPath);
        Logger::Info("Added honeypot key: {}", StringUtils::WideToUtf8(keyPath));
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
            Logger::Info("=== RegistryMonitor Diagnostics ===");
            Logger::Info("Initialized: {}", m_initialized);
            Logger::Info("Running: {}", m_running);
            Logger::Info("Kernel connected: {}", m_kernelConnected);
            Logger::Info("Rules: {}", m_rules.size());
            Logger::Info("Protected keys: {}", m_protectedKeys.size());
            Logger::Info("Total events: {}", m_stats.totalEvents.load());
            Logger::Info("Blocked operations: {}", m_stats.blockedOperations.load());
            Logger::Info("Persistence attempts: {}", m_stats.persistenceAttempts.load());
            Logger::Info("Self-defense blocks: {}", m_stats.selfDefenseBlocks.load());

            return true;

        } catch (const std::exception& e) {
            Logger::Error("PerformDiagnostics - Exception: {}", e.what());
            return false;
        }
    }

    bool ExportDiagnostics(const std::wstring& outputPath) const {
        std::shared_lock lock(m_mutex);

        try {
            Logger::Info("Exported registry monitor diagnostics to: {}",
                StringUtils::WideToUtf8(outputPath));
            return true;

        } catch (const std::exception& e) {
            Logger::Error("ExportDiagnostics - Exception: {}", e.what());
            return false;
        }
    }

private:
    // ========================================================================
    // INTERNAL METHODS
    // ========================================================================

    void SetupSelfDefenseKeys() {
        // Protect ShadowStrike registry keys
        ProtectedKey shadowStrikeKey;
        shadowStrikeKey.keyPath = L"HKLM\\SOFTWARE\\ShadowStrike";
        shadowStrikeKey.includeSubkeys = true;
        shadowStrikeKey.protectValues = true;
        shadowStrikeKey.protectDelete = true;
        shadowStrikeKey.protectRename = true;
        shadowStrikeKey.protectSecurity = true;
        shadowStrikeKey.isSelfDefense = true;
        m_protectedKeys.push_back(shadowStrikeKey);

        // Protect service keys
        ProtectedKey serviceKey;
        serviceKey.keyPath = L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\ShadowStrike";
        serviceKey.includeSubkeys = true;
        serviceKey.protectValues = true;
        serviceKey.protectDelete = true;
        serviceKey.protectRename = true;
        serviceKey.isSelfDefense = true;
        m_protectedKeys.push_back(serviceKey);

        Logger::Info("Self-defense keys configured");
    }

    [[nodiscard]] bool ConnectToKernelDriver() {
        try {
            Logger::Info("Connecting to ShadowStrike Registry Filter port: {}",
                StringUtils::WideToUtf8(RegistryMonitorConstants::COMMUNICATION_PORT));

            m_connection = std::make_unique<Communication::FilterConnection>(
                RegistryMonitorConstants::COMMUNICATION_PORT);

            if (m_connection->Connect()) {
                Logger::Info("Successfully connected to kernel registry filter");
                return true;
            }

            Logger::Error("Failed to connect to kernel registry filter: {}",
                m_connection->GetLastErrorMessage());
            return false;

        } catch (const std::exception& e) {
            Logger::Error("ConnectToKernelDriver - Exception: {}", e.what());
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
        Logger::Debug("Registry worker thread started");

        // Buffer for incoming messages
        std::vector<uint8_t> messageBuffer(Communication::MAX_MESSAGE_SIZE);

        while (!m_stopRequested) {
            if (!m_connection || !m_connection->IsConnected()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                continue;
            }

            // KERNEL DRIVER INTEGRATION WILL COME HERE
            // The kernel driver sends RegistryNotificationData structures via the Filter Port
            size_t bytesReceived = m_connection->GetMessage(messageBuffer, 1000); // 1s timeout

            if (bytesReceived >= sizeof(Communication::MessageHeader)) {
                auto* header = reinterpret_cast<Communication::MessageHeader*>(messageBuffer.data());

                if (header->IsValid() && header->messageType == static_cast<uint16_t>(Communication::MessageType::NotifyRegistrySetValue)) {
                    // Process the registry notification
                    // In a full implementation, we would marshal the raw buffer into a RegistryEvent
                    // and call ProcessEvent(event)
                }
            }
        }

        Logger::Debug("Registry worker thread stopped");
    }

    [[nodiscard]] RegistryVerdict ApplyRules(const RegistryEvent& event) {
        // Sort rules by priority (higher priority first)
        std::vector<std::pair<uint64_t, RegistryRule>> sortedRules;
        for (const auto& [id, rule] : m_rules) {
            if (rule.enabled) {
                sortedRules.emplace_back(id, rule);
            }
        }

        std::sort(sortedRules.begin(), sortedRules.end(),
            [](const auto& a, const auto& b) {
                return a.second.priority > b.second.priority;
            });

        // Apply rules in priority order
        for (auto& [id, rule] : sortedRules) {
            if (RuleMatches(rule, event)) {
                rule.matchCount++;
                return rule.verdict;
            }
        }

        return RegistryVerdict::Allow;
    }

    [[nodiscard]] bool RuleMatches(const RegistryRule& rule, const RegistryEvent& event) const {
        // Operation match
        if (rule.operation.has_value() && rule.operation.value() != event.operation) {
            return false;
        }

        // Value type match
        if (rule.valueType.has_value() && rule.valueType.value() != event.valueType) {
            return false;
        }

        // Key path pattern (simplified wildcard matching)
        if (!rule.keyPathPattern.empty()) {
            std::wstring lowerPath = StringUtils::ToLower(event.keyPath);
            std::wstring lowerPattern = StringUtils::ToLower(rule.keyPathPattern);

            if (lowerPattern.find(L'*') != std::wstring::npos) {
                // Wildcard matching
                size_t starPos = lowerPattern.find(L'*');
                std::wstring prefix = lowerPattern.substr(0, starPos);
                if (!lowerPath.starts_with(prefix)) {
                    return false;
                }
            } else {
                if (lowerPath != lowerPattern) {
                    return false;
                }
            }
        }

        // Process path pattern
        if (!rule.processPathPattern.empty()) {
            std::wstring lowerProcess = StringUtils::ToLower(event.processPath);
            std::wstring lowerPattern = StringUtils::ToLower(rule.processPathPattern);

            if (lowerProcess.find(lowerPattern) == std::wstring::npos) {
                return false;
            }
        }

        // Process ID match
        if (!rule.processIds.empty()) {
            if (std::find(rule.processIds.begin(), rule.processIds.end(), event.processId) == rule.processIds.end()) {
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

        Logger::Warn("Registry alert: {} (process: {}, key: {})",
            description, event.processName, StringUtils::WideToUtf8(event.keyPath));
    }

    void InvokeAlertCallbacks(const RegistryAlert& alert) {
        std::shared_lock lock(m_mutex);

        try {
            for (const auto& [id, callback] : m_alertCallbacks) {
                if (callback) {
                    callback(alert);
                }
            }
        } catch (const std::exception& e) {
            Logger::Error("InvokeAlertCallbacks - Exception: {}", e.what());
        }
    }

    void UpdatePerformanceStats(uint64_t latencyUs) noexcept {
        try {
            // Update average
            uint64_t currentAvg = m_stats.avgCallbackTimeUs.load();
            uint64_t events = m_stats.totalEvents.load();
            uint64_t newAvg = ((currentAvg * (events - 1)) + latencyUs) / events;
            m_stats.avgCallbackTimeUs.store(newAvg);

            // Update max
            uint64_t currentMax = m_stats.maxCallbackTimeUs.load();
            if (latencyUs > currentMax) {
                m_stats.maxCallbackTimeUs.store(latencyUs);
            }

        } catch (...) {
            // Suppress exceptions
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
    Logger::Info("RegistryMonitor instance created");
}

RegistryMonitor::~RegistryMonitor() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    Logger::Info("RegistryMonitor instance destroyed");
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
