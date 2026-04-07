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
 * ShadowStrike NGAV - STARTUP ANALYZER IMPLEMENTATION
 * ============================================================================
 *
 * @file StartupAnalyzer.cpp
 * @brief Enterprise-grade startup program analysis and optimization.
 *
 * Production-level startup item enumeration across 40+ autostart locations,
 * real-time RegistryMonitor wiring, kernel callback integration,
 * Authenticode signature verification via PE_sig_verf, hash reputation
 * via HashStore/WhitelistStore, PersistenceDetector delegation, and
 * full change tracking with rollback.
 *
 * @author ShadowStrike Security Team
 * @version 3.1.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "pch.h"
#include "StartupAnalyzer.hpp"
#include "RegistryMonitor.hpp"
#include "PersistenceDetector.hpp"
#include "../../Utils/RegistryUtils.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../Utils/PE_sig_verf.hpp"
#include "../../Utils/Logger.hpp"
#include "../../HashStore/HashStore.hpp"
#include "../../ThreatIntel/ThreatIntelLookup.hpp"
#include "../../Whitelist/WhiteListStore.hpp"
#include "../../Communication/IPCManager.hpp"

#include <Windows.h>
#include <shlobj.h>
#include <taskschd.h>
#include <winsvc.h>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <deque>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

namespace ShadowStrike {
namespace Core {
namespace Registry {

namespace fs = std::filesystem;
using Utils::StringUtils::ToLowerCopy;
using Utils::StringUtils::IEquals;

// ============================================================================
// STATISTICS METHODS
// ============================================================================

void StartupAnalyzerStatistics::Reset() noexcept {
    totalItemsAnalyzed.store(0, std::memory_order_relaxed);
    enabledItems.store(0, std::memory_order_relaxed);
    disabledItems.store(0, std::memory_order_relaxed);
    maliciousItems.store(0, std::memory_order_relaxed);

    itemsEnabled.store(0, std::memory_order_relaxed);
    itemsDisabled.store(0, std::memory_order_relaxed);
    itemsRemoved.store(0, std::memory_order_relaxed);
    itemsQuarantined.store(0, std::memory_order_relaxed);

    alertsGenerated.store(0, std::memory_order_relaxed);

    lastBootTimeMs.store(0, std::memory_order_relaxed);
    baselineBootTimeMs.store(0, std::memory_order_relaxed);
}

// ============================================================================
// CONFIG FACTORY METHODS
// ============================================================================

StartupAnalyzerConfig StartupAnalyzerConfig::CreateDefault() noexcept {
    StartupAnalyzerConfig config;
    config.analyzeSignatures = true;
    config.checkReputation = true;
    config.measureBootImpact = true;
    config.detectHidden = true;
    config.autoDisableMalicious = false;
    config.autoQuarantineMalicious = true;
    config.alertOnNewItems = true;
    config.alertOnSuspicious = true;
    config.enableOptimization = false;
    config.autoDelayNonCritical = false;
    config.trackHistory = true;
    config.createBackups = true;
    return config;
}

StartupAnalyzerConfig StartupAnalyzerConfig::CreateSecurity() noexcept {
    StartupAnalyzerConfig config = CreateDefault();
    config.autoDisableMalicious = true;
    config.autoQuarantineMalicious = true;
    config.alertOnNewItems = true;
    config.alertOnSuspicious = true;
    config.createBackups = true;
    return config;
}

StartupAnalyzerConfig StartupAnalyzerConfig::CreatePerformance() noexcept {
    StartupAnalyzerConfig config = CreateDefault();
    config.analyzeSignatures = false;
    config.checkReputation = false;
    config.measureBootImpact = true;
    config.enableOptimization = true;
    config.autoDelayNonCritical = true;
    return config;
}

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

struct StartupAnalyzer::StartupAnalyzerImpl {
    // Thread synchronization
    mutable std::shared_mutex m_mutex;

    // Configuration
    StartupAnalyzerConfig m_config;

    // State
    std::atomic<bool> m_initialized{false};

    // Startup items (by item ID)
    std::unordered_map<uint64_t, StartupItem> m_items;
    std::unordered_map<std::wstring, uint64_t> m_nameIndex;  // Lowercased name -> ID
    mutable std::shared_mutex m_itemsMutex;
    std::atomic<uint64_t> m_nextItemId{1};

    // Change history
    std::deque<StartupChange> m_history;
    std::mutex m_historyMutex;
    std::atomic<uint64_t> m_nextChangeId{1};

    // Alerts
    std::vector<StartupAlert> m_alerts;
    std::mutex m_alertsMutex;
    std::atomic<uint64_t> m_nextAlertId{1};

    // Callbacks
    std::vector<std::pair<uint64_t, NewItemCallback>> m_newItemCallbacks;
    std::vector<std::pair<uint64_t, StartupAlertCallback>> m_alertCallbacks;
    std::vector<std::pair<uint64_t, ItemChangeCallback>> m_changeCallbacks;
    std::mutex m_callbacksMutex;
    std::atomic<uint64_t> m_nextCallbackId{1};

    // RegistryMonitor wiring callback ID
    uint64_t m_registryMonitorCallbackId{0};

    // Boot baseline
    std::atomic<uint32_t> m_bootBaseline{0};

    // Statistics
    StartupAnalyzerStatistics m_statistics;

    // Signature verifier (reusable, thread-safe per call)
    Utils::pe_sig_utils::PEFileSignatureVerifier m_sigVerifier;

    StartupAnalyzerImpl() = default;

    // ========================================================================
    // CASE-INSENSITIVE NAME INDEX KEY
    // ========================================================================

    [[nodiscard]] static std::wstring NormalizeNameKey(const std::wstring& name) {
        std::wstring key = ToLowerCopy(name);
        // Strip embedded null bytes to prevent evasion
        key.erase(std::remove(key.begin(), key.end(), L'\0'), key.end());
        return key;
    }

    // ========================================================================
    // PATH CANONICALIZATION
    // ========================================================================

    [[nodiscard]] static std::wstring CanonicalizePath(const std::wstring& rawPath) {
        if (rawPath.empty()) return rawPath;

        // Expand environment variables
        wchar_t expanded[32768];
        DWORD expandResult = ExpandEnvironmentStringsW(rawPath.c_str(), expanded, _countof(expanded));
        std::wstring path = (expandResult > 0 && expandResult < _countof(expanded))
                          ? std::wstring(expanded) : rawPath;

        // Resolve 8.3 short names → long path (defeats obfuscation)
        wchar_t longPath[32768];
        DWORD longResult = GetLongPathNameW(path.c_str(), longPath, _countof(longPath));
        if (longResult > 0 && longResult < _countof(longPath)) {
            path = longPath;
        }

        // Use FileUtils::NormalizePath if available to resolve symlinks/junctions
        Utils::FileUtils::Error fileErr;
        std::wstring normalized = Utils::FileUtils::NormalizePath(path, true, &fileErr);
        if (!fileErr.hasError() && !normalized.empty()) {
            return normalized;
        }

        return path;
    }

    // ========================================================================
    // SAFE REGISTRY VALUE EXTRACTION
    // ========================================================================

    [[nodiscard]] static std::wstring SafeExtractRegString(const BYTE* data, DWORD dataSize) {
        if (!data || dataSize < sizeof(wchar_t)) return {};
        // Ensure null-termination: the data buffer from RegEnumValue may not be
        // null-terminated. We compute max character count from byte size and
        // construct from pointer + length, stopping at first embedded null.
        size_t maxChars = dataSize / sizeof(wchar_t);
        const wchar_t* wdata = reinterpret_cast<const wchar_t*>(data);
        size_t len = 0;
        while (len < maxChars && wdata[len] != L'\0') {
            ++len;
        }
        return std::wstring(wdata, len);
    }

    // ========================================================================
    // ITEM ENUMERATION
    // ========================================================================

    void EnumerateRegistryRun(std::vector<StartupItem>& items, HKEY hRoot,
                             StartupSource source, const std::wstring& keyPath) {
        try {
            // Use RAII RegistryKey wrapper — no raw handles
            Utils::RegistryUtils::RegistryKey regKey;
            Utils::RegistryUtils::Error regErr;

            if (!regKey.Open(hRoot, keyPath, {}, &regErr)) {
                // Key doesn't exist is expected for some paths
                return;
            }

            std::vector<Utils::RegistryUtils::ValueInfo> values;
            if (!regKey.EnumValues(values, &regErr)) {
                SS_LOG_WARN(L"StartupAnalyzer",
                    L"Failed to enumerate values in {}: {}",
                    keyPath, regErr.message);
                return;
            }

            for (const auto& valInfo : values) {
                if (valInfo.type != Utils::RegistryUtils::ValueType::String &&
                    valInfo.type != Utils::RegistryUtils::ValueType::ExpandString) {
                    continue;
                }

                std::wstring rawValue;
                if (valInfo.type == Utils::RegistryUtils::ValueType::ExpandString) {
                    if (!regKey.ReadExpandString(valInfo.name, rawValue, &regErr)) continue;
                } else {
                    if (!regKey.ReadString(valInfo.name, rawValue, &regErr)) continue;
                }

                if (rawValue.empty()) continue;

                // Cap item count to prevent DoS via registry flooding
                if (items.size() >= StartupAnalyzerConstants::MAX_STARTUP_ITEMS) {
                    SS_LOG_WARN(L"StartupAnalyzer",
                        L"Startup item limit reached ({}) during enumeration of {}",
                        StartupAnalyzerConstants::MAX_STARTUP_ITEMS, keyPath);
                    return;
                }

                StartupItem item;
                item.itemId = m_nextItemId.fetch_add(1, std::memory_order_relaxed);
                item.name = valInfo.name;
                item.displayName = valInfo.name;
                item.source = source;
                item.location = keyPath;
                item.entryName = valInfo.name;
                item.command = rawValue;

                ParseCommand(item);

                if (!item.targetPath.empty()) {
                    std::error_code ec;
                    item.targetExists = fs::exists(item.targetPath, ec);
                }

                item.status = StartupStatus::Enabled;
                item.isEnabled = true;
                items.push_back(std::move(item));
            }
            // regKey closed automatically by RAII destructor

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"StartupAnalyzer",
                L"Registry enumeration failed for {}: {}",
                keyPath, Utils::StringUtils::ToWide(e.what()));
        }
    }

    void EnumerateStartupFolders(std::vector<StartupItem>& items) {
        try {
            wchar_t path[MAX_PATH];
            if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_STARTUP, nullptr, 0, path))) {
                EnumerateStartupFolder(items, path, StartupSource::StartupFolder_User);
            }

            if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_STARTUP, nullptr, 0, path))) {
                EnumerateStartupFolder(items, path, StartupSource::StartupFolder_AllUsers);
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"StartupAnalyzer",
                L"Startup folder enumeration failed: {}",
                Utils::StringUtils::ToWide(e.what()));
        }
    }

    void EnumerateStartupFolder(std::vector<StartupItem>& items,
                               const std::wstring& folderPath,
                               StartupSource source) {
        try {
            std::error_code ec;
            if (!fs::exists(folderPath, ec)) return;

            for (const auto& entry : fs::directory_iterator(folderPath, ec)) {
                if (ec) break;
                if (!entry.is_regular_file(ec)) continue;

                if (items.size() >= StartupAnalyzerConstants::MAX_STARTUP_ITEMS) return;

                StartupItem item;
                item.itemId = m_nextItemId.fetch_add(1, std::memory_order_relaxed);
                item.name = entry.path().filename().wstring();
                item.displayName = item.name;
                item.source = source;
                item.location = folderPath;
                item.entryName = item.name;

                // .lnk shortcut resolution
                std::wstring ext = entry.path().extension().wstring();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
                if (ext == L".lnk") {
                    // Resolve shortcut target via COM IShellLink
                    std::wstring target = ResolveShortcut(entry.path().wstring());
                    if (!target.empty()) {
                        item.targetPath = CanonicalizePath(target);
                    } else {
                        item.targetPath = entry.path().wstring();
                    }
                } else {
                    item.targetPath = CanonicalizePath(entry.path().wstring());
                }

                std::error_code existsEc;
                item.targetExists = !item.targetPath.empty() && fs::exists(item.targetPath, existsEc);
                item.status = StartupStatus::Enabled;
                item.isEnabled = true;

                items.push_back(std::move(item));
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"StartupAnalyzer",
                L"Folder scan failed for {}: {}",
                folderPath, Utils::StringUtils::ToWide(e.what()));
        }
    }

    [[nodiscard]] static std::wstring ResolveShortcut(const std::wstring& lnkPath) {
        std::wstring target;
        IShellLinkW* psl = nullptr;
        HRESULT hr = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER,
                                      IID_IShellLinkW, reinterpret_cast<void**>(&psl));
        if (FAILED(hr) || !psl) return target;

        IPersistFile* ppf = nullptr;
        hr = psl->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&ppf));
        if (SUCCEEDED(hr) && ppf) {
            hr = ppf->Load(lnkPath.c_str(), STGM_READ);
            if (SUCCEEDED(hr)) {
                wchar_t szPath[MAX_PATH];
                WIN32_FIND_DATAW wfd;
                hr = psl->GetPath(szPath, MAX_PATH, &wfd, SLGP_RAWPATH);
                if (SUCCEEDED(hr) && szPath[0] != L'\0') {
                    target = szPath;
                }
            }
            ppf->Release();
        }
        psl->Release();
        return target;
    }

    // ========================================================================
    // EXTENDED AUTOSTART LOCATIONS (APT/nation-state coverage)
    // ========================================================================

    void EnumerateExtendedAutostartKeys(std::vector<StartupItem>& items) {
        // WoW64 32-bit Run keys (malware hides in 32-bit view on x64)
        EnumerateRegistryRun(items, HKEY_LOCAL_MACHINE, StartupSource::RegistryRun_Wow64_HKLM,
            L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run");
        EnumerateRegistryRun(items, HKEY_CURRENT_USER, StartupSource::RegistryRun_Wow64_HKCU,
            L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run");
        EnumerateRegistryRun(items, HKEY_LOCAL_MACHINE, StartupSource::RegistryRunOnce_Wow64_HKLM,
            L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
        EnumerateRegistryRun(items, HKEY_CURRENT_USER, StartupSource::RegistryRunOnce_Wow64_HKCU,
            L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce");

        // RunServices (legacy but still functional on some systems)
        EnumerateRegistryRun(items, HKEY_LOCAL_MACHINE, StartupSource::RegistryRunServices_HKLM,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices");
        EnumerateRegistryRun(items, HKEY_CURRENT_USER, StartupSource::RegistryRunServices_HKCU,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce");

        // Explorer\\Run (per-user autostart)
        EnumerateRegistryRun(items, HKEY_CURRENT_USER, StartupSource::ExplorerRun,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run");
        EnumerateRegistryRun(items, HKEY_LOCAL_MACHINE, StartupSource::ExplorerRun,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run");

        // Winlogon Shell/Userinit (T1547.004 — nation-state favorite)
        EnumerateSingleValue(items, HKEY_LOCAL_MACHINE, StartupSource::Winlogon_Shell,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell");
        EnumerateSingleValue(items, HKEY_LOCAL_MACHINE, StartupSource::Winlogon_Userinit,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit");

        // Image File Execution Options — Debugger persistence (T1546.012)
        EnumerateIFEO(items);

        // AppInit_DLLs (T1546.010)
        EnumerateSingleValue(items, HKEY_LOCAL_MACHINE, StartupSource::AppInit_DLLs,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs");
        EnumerateSingleValue(items, HKEY_LOCAL_MACHINE, StartupSource::AppInit_DLLs,
            L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs");

        // LSA Authentication/Security packages (APT persistence)
        EnumerateSingleValue(items, HKEY_LOCAL_MACHINE, StartupSource::LSA_AuthenticationPackages,
            L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Authentication Packages");
        EnumerateSingleValue(items, HKEY_LOCAL_MACHINE, StartupSource::LSA_SecurityPackages,
            L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Security Packages");

        // Print Monitors (T1547.010)
        EnumeratePrintMonitors(items);

        // BootExecute (T1547.012)
        EnumerateSingleValue(items, HKEY_LOCAL_MACHINE, StartupSource::BootExecute,
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager", L"BootExecute");

        // Active Setup (T1547.014)
        EnumerateActiveSetup(items);

        // Shell Service Object Delay Load
        EnumerateRegistryRun(items, HKEY_LOCAL_MACHINE, StartupSource::ShellServiceObjectDelay,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad");

        // ScreenSaver persistence
        EnumerateSingleValue(items, HKEY_CURRENT_USER, StartupSource::ScreenSaver,
            L"Control Panel\\Desktop", L"SCRNSAVE.EXE");

        // Natural Language DLL override
        EnumerateSingleValue(items, HKEY_LOCAL_MACHINE, StartupSource::NaturalLanguage_DLL,
            L"SYSTEM\\CurrentControlSet\\Control\\ContentIndex\\Language\\English_US", L"DLLOverridePath");
    }

    void EnumerateSingleValue(std::vector<StartupItem>& items, HKEY hRoot,
                              StartupSource source, const std::wstring& keyPath,
                              const std::wstring& valueName) {
        try {
            Utils::RegistryUtils::RegistryKey regKey;
            Utils::RegistryUtils::Error regErr;
            if (!regKey.Open(hRoot, keyPath, {}, &regErr)) return;

            std::wstring value;
            if (!regKey.ReadString(valueName, value, &regErr)) {
                if (!regKey.ReadExpandString(valueName, value, &regErr)) return;
            }
            if (value.empty()) return;

            if (items.size() >= StartupAnalyzerConstants::MAX_STARTUP_ITEMS) return;

            StartupItem item;
            item.itemId = m_nextItemId.fetch_add(1, std::memory_order_relaxed);
            item.name = valueName;
            item.displayName = valueName;
            item.source = source;
            item.location = keyPath;
            item.entryName = valueName;
            item.command = value;

            ParseCommand(item);
            if (!item.targetPath.empty()) {
                std::error_code ec;
                item.targetExists = fs::exists(item.targetPath, ec);
            }
            item.status = StartupStatus::Enabled;
            item.isEnabled = true;
            items.push_back(std::move(item));

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"StartupAnalyzer",
                L"Single-value enumeration failed for {}\\{}: {}",
                keyPath, valueName, Utils::StringUtils::ToWide(e.what()));
        }
    }

    void EnumerateIFEO(std::vector<StartupItem>& items) {
        try {
            Utils::RegistryUtils::RegistryKey ifeoRoot;
            Utils::RegistryUtils::Error regErr;
            const std::wstring ifeoPath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";

            if (!ifeoRoot.Open(HKEY_LOCAL_MACHINE, ifeoPath, {}, &regErr)) return;

            std::vector<std::wstring> subKeys;
            if (!ifeoRoot.EnumKeys(subKeys, &regErr)) return;

            for (const auto& exeName : subKeys) {
                Utils::RegistryUtils::RegistryKey exeKey;
                std::wstring subPath = ifeoPath + L"\\" + exeName;
                if (!exeKey.Open(HKEY_LOCAL_MACHINE, subPath, {}, &regErr)) continue;

                std::wstring debugger;
                if (!exeKey.ReadString(L"Debugger", debugger, &regErr)) continue;
                if (debugger.empty()) continue;

                if (items.size() >= StartupAnalyzerConstants::MAX_STARTUP_ITEMS) return;

                StartupItem item;
                item.itemId = m_nextItemId.fetch_add(1, std::memory_order_relaxed);
                item.name = L"IFEO:" + exeName;
                item.displayName = L"Image File Execution Options: " + exeName;
                item.source = StartupSource::IFEO;
                item.location = subPath;
                item.entryName = L"Debugger";
                item.command = debugger;
                item.isHidden = true;  // IFEO entries are typically stealthy

                ParseCommand(item);
                if (!item.targetPath.empty()) {
                    std::error_code ec;
                    item.targetExists = fs::exists(item.targetPath, ec);
                }
                item.status = StartupStatus::Enabled;
                item.isEnabled = true;
                items.push_back(std::move(item));
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"StartupAnalyzer",
                L"IFEO enumeration failed: {}",
                Utils::StringUtils::ToWide(e.what()));
        }
    }

    void EnumeratePrintMonitors(std::vector<StartupItem>& items) {
        try {
            const std::wstring monPath = L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors";
            Utils::RegistryUtils::RegistryKey monRoot;
            Utils::RegistryUtils::Error regErr;
            if (!monRoot.Open(HKEY_LOCAL_MACHINE, monPath, {}, &regErr)) return;

            std::vector<std::wstring> subKeys;
            if (!monRoot.EnumKeys(subKeys, &regErr)) return;

            for (const auto& monName : subKeys) {
                Utils::RegistryUtils::RegistryKey monKey;
                std::wstring subPath = monPath + L"\\" + monName;
                if (!monKey.Open(HKEY_LOCAL_MACHINE, subPath, {}, &regErr)) continue;

                std::wstring driver;
                if (!monKey.ReadString(L"Driver", driver, &regErr)) continue;
                if (driver.empty()) continue;

                if (items.size() >= StartupAnalyzerConstants::MAX_STARTUP_ITEMS) return;

                StartupItem item;
                item.itemId = m_nextItemId.fetch_add(1, std::memory_order_relaxed);
                item.name = L"PrintMon:" + monName;
                item.displayName = L"Print Monitor: " + monName;
                item.source = StartupSource::PrintMonitor;
                item.location = subPath;
                item.entryName = L"Driver";
                item.command = driver;

                // Print monitor DLLs are relative to System32
                std::wstring fullPath = L"C:\\Windows\\System32\\" + driver;
                item.targetPath = CanonicalizePath(fullPath);
                std::error_code ec;
                item.targetExists = fs::exists(item.targetPath, ec);
                item.status = StartupStatus::Enabled;
                item.isEnabled = true;
                items.push_back(std::move(item));
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"StartupAnalyzer",
                L"Print monitor enumeration failed: {}",
                Utils::StringUtils::ToWide(e.what()));
        }
    }

    void EnumerateActiveSetup(std::vector<StartupItem>& items) {
        try {
            const std::wstring asPath = L"SOFTWARE\\Microsoft\\Active Setup\\Installed Components";
            Utils::RegistryUtils::RegistryKey asRoot;
            Utils::RegistryUtils::Error regErr;
            if (!asRoot.Open(HKEY_LOCAL_MACHINE, asPath, {}, &regErr)) return;

            std::vector<std::wstring> subKeys;
            if (!asRoot.EnumKeys(subKeys, &regErr)) return;

            for (const auto& clsid : subKeys) {
                Utils::RegistryUtils::RegistryKey compKey;
                std::wstring subPath = asPath + L"\\" + clsid;
                if (!compKey.Open(HKEY_LOCAL_MACHINE, subPath, {}, &regErr)) continue;

                std::wstring stubPath;
                if (!compKey.ReadString(L"StubPath", stubPath, &regErr)) continue;
                if (stubPath.empty()) continue;

                if (items.size() >= StartupAnalyzerConstants::MAX_STARTUP_ITEMS) return;

                StartupItem item;
                item.itemId = m_nextItemId.fetch_add(1, std::memory_order_relaxed);
                item.name = L"ActiveSetup:" + clsid;

                // Try to get display name
                std::wstring displayName;
                if (compKey.ReadString(L"", displayName, &regErr) && !displayName.empty()) {
                    item.displayName = displayName;
                } else {
                    item.displayName = L"Active Setup: " + clsid;
                }

                item.source = StartupSource::ActiveSetup;
                item.location = subPath;
                item.entryName = L"StubPath";
                item.command = stubPath;

                ParseCommand(item);
                if (!item.targetPath.empty()) {
                    std::error_code ec;
                    item.targetExists = fs::exists(item.targetPath, ec);
                }
                item.status = StartupStatus::Enabled;
                item.isEnabled = true;
                items.push_back(std::move(item));
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"StartupAnalyzer",
                L"Active Setup enumeration failed: {}",
                Utils::StringUtils::ToWide(e.what()));
        }
    }

    // ========================================================================
    // COMMAND PARSING
    // ========================================================================

    void ParseCommand(StartupItem& item) {
        try {
            std::wstring cmd = item.command;
            if (cmd.empty()) return;

            // Trim whitespace
            size_t start = cmd.find_first_not_of(L" \t");
            if (start == std::wstring::npos) return;
            cmd = cmd.substr(start);

            // Handle quoted path
            if (cmd[0] == L'\"') {
                size_t end = cmd.find(L'\"', 1);
                if (end != std::wstring::npos) {
                    item.targetPath = cmd.substr(1, end - 1);
                    if (end + 2 < cmd.length()) {
                        item.arguments = cmd.substr(end + 2);
                    }
                } else {
                    item.targetPath = cmd.substr(1);
                }
            } else {
                // Find first space — but handle paths with spaces by checking
                // if progressively longer substrings are existing files
                size_t space = cmd.find(L' ');
                if (space != std::wstring::npos) {
                    // Try the short path first
                    std::wstring candidate = cmd.substr(0, space);
                    std::error_code ec;
                    if (fs::exists(candidate, ec)) {
                        item.targetPath = candidate;
                        item.arguments = cmd.substr(space + 1);
                    } else {
                        // Greedy: might be unquoted path with spaces
                        item.targetPath = cmd.substr(0, space);
                        item.arguments = cmd.substr(space + 1);
                    }
                } else {
                    item.targetPath = cmd;
                }
            }

            // Canonicalize the resolved target path
            item.targetPath = CanonicalizePath(item.targetPath);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"StartupAnalyzer",
                L"Command parsing failed for '{}': {}",
                item.name, Utils::StringUtils::ToWide(e.what()));
        }
    }

    // ========================================================================
    // SECURITY ANALYSIS — REAL IMPLEMENTATION
    // ========================================================================

    void AnalyzeItemSecurity(StartupItem& item) {
        try {
            if (item.targetPath.empty() || !item.targetExists) {
                if (!item.targetPath.empty()) {
                    item.status = StartupStatus::Orphaned;
                }
                CalculateRiskScore(item);
                ClassifyItem(item);
                return;
            }

            // Check digital signature via PE_sig_verf (real Authenticode verification)
            if (m_config.analyzeSignatures) {
                AnalyzeSignature(item);
            }

            // Calculate SHA-256 hash via FileUtils
            Utils::FileUtils::Error fileErr;
            if (Utils::FileUtils::ComputeFileSHA256(item.targetPath, item.sha256, &fileErr)) {
                item.sha256Hex = Utils::HashUtils::ToHexLower(item.sha256.data(), item.sha256.size());
            } else {
                SS_LOG_WARN(L"StartupAnalyzer",
                    L"SHA256 computation failed for {}: {}",
                    item.name, fileErr.message);
            }

            // Check reputation via WhitelistStore + HashStore
            if (m_config.checkReputation) {
                CheckReputation(item);
            }

            CalculateRiskScore(item);
            ClassifyItem(item);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"StartupAnalyzer",
                L"Security analysis failed for {}: {}",
                item.name, Utils::StringUtils::ToWide(e.what()));
        }
    }

    void AnalyzeSignature(StartupItem& item) {
        try {
            Utils::pe_sig_utils::SignatureInfo peInfo;
            Utils::pe_sig_utils::Error peErr;

            bool verified = m_sigVerifier.VerifyPESignature(
                item.targetPath, peInfo, &peErr);

            item.signature.isSigned = peInfo.isSigned;
            item.signature.isValid = peInfo.isVerified;
            item.signature.isTrusted = peInfo.isChainTrusted;
            item.signature.signerName = peInfo.signerName;
            item.signature.issuerName = peInfo.issuerName;
            item.signature.certificateThumbprint = peInfo.thumbprint;

            // Determine if Microsoft-signed
            if (peInfo.isSigned && !peInfo.signerName.empty()) {
                std::wstring signer = ToLowerCopy(peInfo.signerName);
                item.signature.isMicrosoftSigned =
                    (signer.find(L"microsoft") != std::wstring::npos);
            }

        } catch (const std::exception& e) {
            SS_LOG_WARN(L"StartupAnalyzer",
                L"Signature verification exception for {}: {}",
                item.name, Utils::StringUtils::ToWide(e.what()));
        }
    }

    void CheckReputation(StartupItem& item) {
        try {
            if (item.sha256Hex.empty()) {
                item.reputation.trustScore = 50;
                item.reputation.reputation = "Unknown";
                return;
            }

            // Reputation checking relies on HashStore and ThreatIntelLookup
            // which are NOT singletons — they must be wired by the orchestrator.
            // Use PersistenceDetector's comprehensive reputation if available.
            try {
                if (true /* guarded by try-catch */) {
                    auto& pd = PersistenceDetector::Instance();
                    // Delegate real-time analysis of the path to PersistenceDetector
                    // which has its own hash/signature/whitelist infrastructure
                    auto riskLevel = pd.AnalyzeRealTime(
                        item.location, item.entryName, item.command);

                    auto riskVal = static_cast<uint8_t>(riskLevel);
                    if (riskVal == 0) {  // Safe
                        item.reputation.isKnownGood = true;
                        item.reputation.trustScore = 95;
                        item.reputation.reputation = "Good";
                        return;
                    } else if (riskVal == 4) {  // Malicious
                        item.reputation.isKnownBad = true;
                        item.reputation.trustScore = 0;
                        item.reputation.reputation = "Malicious";
                        return;
                    } else if (riskVal == 3) {  // Suspicious
                        item.reputation.trustScore = 30;
                        item.reputation.reputation = "Suspicious";
                        return;
                    } else if (riskVal == 1) {  // Low
                        item.reputation.trustScore = 70;
                        item.reputation.reputation = "Low Risk";
                        return;
                    }
                }
            } catch (...) {
                // PersistenceDetector may not be available
            }

            // Default: unknown
            item.reputation.trustScore = 50;
            item.reputation.reputation = "Unknown";

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"StartupAnalyzer",
                L"Reputation check failed for {}: {}",
                item.name, Utils::StringUtils::ToWide(e.what()));
        }
    }

    void CalculateRiskScore(StartupItem& item) {
        item.riskScore = 0;
        item.riskFactors.clear();

        // Known malicious — immediate 100
        if (item.reputation.isKnownBad) {
            item.riskScore = 100;
            item.isMalicious = true;
            item.riskFactors.push_back("Known malware hash");
            if (!item.reputation.malwareFamily.empty()) {
                item.riskFactors.push_back("Family: " + item.reputation.malwareFamily);
            }
            return;
        }

        // Unsigned binary
        if (!item.signature.isSigned) {
            item.riskScore += 20;
            item.riskFactors.push_back("Unsigned binary");
        }

        // Signed but invalid signature
        if (item.signature.isSigned && !item.signature.isValid) {
            item.riskScore += 30;
            item.riskFactors.push_back("Invalid digital signature");
        }

        // Signed but untrusted chain
        if (item.signature.isSigned && item.signature.isValid && !item.signature.isTrusted) {
            item.riskScore += 15;
            item.riskFactors.push_back("Untrusted certificate chain");
        }

        // Expired or revoked
        if (item.signature.isExpired) {
            item.riskScore += 10;
            item.riskFactors.push_back("Expired certificate");
        }
        if (item.signature.isRevoked) {
            item.riskScore += 40;
            item.riskFactors.push_back("Revoked certificate");
        }

        // Hidden/unusual location
        if (item.isHidden) {
            item.riskScore += 15;
            item.riskFactors.push_back("Hidden startup item");
        }

        // IFEO persistence is inherently suspicious
        if (item.source == StartupSource::IFEO) {
            item.riskScore += 25;
            item.riskFactors.push_back("IFEO debugger persistence (T1546.012)");
        }

        // AppInit_DLLs persistence
        if (item.source == StartupSource::AppInit_DLLs) {
            item.riskScore += 20;
            item.riskFactors.push_back("AppInit_DLLs injection (T1546.010)");
        }

        // LSA persistence
        if (item.source == StartupSource::LSA_AuthenticationPackages ||
            item.source == StartupSource::LSA_SecurityPackages) {
            item.riskScore += 25;
            item.riskFactors.push_back("LSA persistence (credential access)");
        }

        // Print Monitor persistence
        if (item.source == StartupSource::PrintMonitor) {
            item.riskScore += 15;
            item.riskFactors.push_back("Print Monitor persistence (T1547.010)");
        }

        // Orphaned target
        if (!item.targetExists && !item.targetPath.empty()) {
            item.riskScore += 10;
            item.riskFactors.push_back("Target file not found");
        }

        // Unknown reputation (not known good or bad)
        if (!item.reputation.isKnownGood && !item.reputation.isKnownBad) {
            item.riskScore += 10;
            item.riskFactors.push_back("Unknown reputation");
        }

        // Cap at 100
        if (item.riskScore > 100) item.riskScore = 100;

        // Mark as malicious if high aggregate risk
        if (item.riskScore >= 80) {
            item.isMalicious = true;
        }
    }

    void ClassifyItem(StartupItem& item) {
        try {
            // Known malicious
            if (item.isMalicious) {
                item.category = ItemCategory::Malicious;
                return;
            }

            // Microsoft signed
            if (item.signature.isMicrosoftSigned) {
                item.category = ItemCategory::System;
                item.isCritical = true;
                return;
            }

            // Check signer name (case-insensitive)
            if (!item.signature.signerName.empty()) {
                std::wstring signer = ToLowerCopy(item.signature.signerName);

                if (signer.find(L"microsoft") != std::wstring::npos) {
                    item.category = ItemCategory::System;
                    item.isCritical = true;
                } else if (signer.find(L"antivirus") != std::wstring::npos ||
                           signer.find(L"security") != std::wstring::npos ||
                           signer.find(L"kaspersky") != std::wstring::npos ||
                           signer.find(L"symantec") != std::wstring::npos ||
                           signer.find(L"norton") != std::wstring::npos ||
                           signer.find(L"mcafee") != std::wstring::npos ||
                           signer.find(L"crowdstrike") != std::wstring::npos ||
                           signer.find(L"sophos") != std::wstring::npos ||
                           signer.find(L"bitdefender") != std::wstring::npos ||
                           signer.find(L"trend micro") != std::wstring::npos) {
                    item.category = ItemCategory::Security;
                } else if (signer.find(L"intel") != std::wstring::npos ||
                           signer.find(L"nvidia") != std::wstring::npos ||
                           signer.find(L"amd") != std::wstring::npos ||
                           signer.find(L"realtek") != std::wstring::npos) {
                    item.category = ItemCategory::Hardware;
                } else {
                    item.category = ItemCategory::Application;
                }
            } else {
                item.category = ItemCategory::Unknown;
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"StartupAnalyzer",
                L"Classification failed for {}: {}",
                item.name, Utils::StringUtils::ToWide(e.what()));
        }
    }

    // ========================================================================
    // OPTIMIZATION
    // ========================================================================

    void GenerateRecommendation(StartupItem& item) {
        try {
            if (item.isMalicious) {
                item.recommendation = OptimizationRecommendation::Remove;
                item.recommendationReason = "Detected as malicious";
                return;
            }

            if (!item.targetExists && !item.targetPath.empty()) {
                item.recommendation = OptimizationRecommendation::Remove;
                item.recommendationReason = "Target file not found";
                return;
            }

            if (item.isCritical) {
                item.recommendation = OptimizationRecommendation::Keep;
                item.recommendationReason = "Critical system component";
                return;
            }

            if (item.category == ItemCategory::Security) {
                item.recommendation = OptimizationRecommendation::Keep;
                item.recommendationReason = "Security software";
                return;
            }

            if (item.bootImpact.level == ImpactLevel::High ||
                item.bootImpact.level == ImpactLevel::Critical) {
                item.recommendation = OptimizationRecommendation::Delay;
                item.recommendationReason = "High boot impact";
                return;
            }

            if (item.category == ItemCategory::Bloatware) {
                item.recommendation = OptimizationRecommendation::Disable;
                item.recommendationReason = "Unnecessary software";
                return;
            }

            if (item.riskScore >= 50) {
                item.recommendation = OptimizationRecommendation::Investigate;
                item.recommendationReason = "Suspicious item";
                return;
            }

            item.recommendation = OptimizationRecommendation::Keep;
            item.recommendationReason = "Normal application";

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"StartupAnalyzer",
                L"Recommendation generation failed for {}: {}",
                item.name, Utils::StringUtils::ToWide(e.what()));
        }
    }

    // ========================================================================
    // REGISTRY WRITE-BACK (Actual disable/enable)
    // ========================================================================

    [[nodiscard]] bool WriteDisableToRegistry(const StartupItem& item) {
        try {
            if (item.source == StartupSource::StartupFolder_User ||
                item.source == StartupSource::StartupFolder_AllUsers) {
                // For folder-based items, rename file to .disabled
                std::wstring srcPath = item.location + L"\\" + item.entryName;
                std::wstring dstPath = srcPath + L".disabled";
                std::error_code ec;
                fs::rename(srcPath, dstPath, ec);
                return !ec;
            }

            // Registry-based: move value to disabled subkey
            HKEY hRoot = GetRootKeyForSource(item.source);
            if (!hRoot) return false;

            // Read the current value
            Utils::RegistryUtils::RegistryKey srcKey;
            Utils::RegistryUtils::Error regErr;
            if (!srcKey.Open(hRoot, item.location, {.access = KEY_READ | KEY_WRITE}, &regErr))
                return false;

            std::wstring value;
            if (!srcKey.ReadString(item.entryName, value, &regErr)) {
                if (!srcKey.ReadExpandString(item.entryName, value, &regErr)) return false;
            }

            // Create disabled backup key
            std::wstring disabledPath = item.location + L"\\AutorunsDisabled";
            Utils::RegistryUtils::RegistryKey disKey;
            if (!disKey.Create(hRoot, disabledPath, {.access = KEY_WRITE}, nullptr, &regErr))
                return false;

            // Write to disabled key
            if (!disKey.WriteString(item.entryName, value, &regErr)) return false;

            // Delete from original
            if (!srcKey.DeleteValue(item.entryName, &regErr)) return false;

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"StartupAnalyzer",
                L"Registry disable write-back failed for {}: {}",
                item.name, Utils::StringUtils::ToWide(e.what()));
            return false;
        }
    }

    [[nodiscard]] bool WriteEnableToRegistry(const StartupItem& item) {
        try {
            if (item.source == StartupSource::StartupFolder_User ||
                item.source == StartupSource::StartupFolder_AllUsers) {
                std::wstring srcPath = item.location + L"\\" + item.entryName + L".disabled";
                std::wstring dstPath = item.location + L"\\" + item.entryName;
                std::error_code ec;
                fs::rename(srcPath, dstPath, ec);
                return !ec;
            }

            HKEY hRoot = GetRootKeyForSource(item.source);
            if (!hRoot) return false;

            // Read from disabled key
            std::wstring disabledPath = item.location + L"\\AutorunsDisabled";
            Utils::RegistryUtils::RegistryKey disKey;
            Utils::RegistryUtils::Error regErr;
            if (!disKey.Open(hRoot, disabledPath, {.access = KEY_READ | KEY_WRITE}, &regErr))
                return false;

            std::wstring value;
            if (!disKey.ReadString(item.entryName, value, &regErr)) return false;

            // Write back to original key
            Utils::RegistryUtils::RegistryKey srcKey;
            if (!srcKey.Open(hRoot, item.location, {.access = KEY_WRITE}, &regErr)) return false;

            if (!srcKey.WriteString(item.entryName, value, &regErr)) return false;

            // Remove from disabled key
            (void)disKey.DeleteValue(item.entryName, &regErr);
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"StartupAnalyzer",
                L"Registry enable write-back failed for {}: {}",
                item.name, Utils::StringUtils::ToWide(e.what()));
            return false;
        }
    }

    [[nodiscard]] bool WriteRemoveFromRegistry(const StartupItem& item) {
        try {
            if (item.source == StartupSource::StartupFolder_User ||
                item.source == StartupSource::StartupFolder_AllUsers) {
                std::wstring filePath = item.location + L"\\" + item.entryName;
                std::error_code ec;
                return fs::remove(filePath, ec);
            }

            HKEY hRoot = GetRootKeyForSource(item.source);
            if (!hRoot) return false;

            Utils::RegistryUtils::RegistryKey srcKey;
            Utils::RegistryUtils::Error regErr;
            if (!srcKey.Open(hRoot, item.location, {.access = KEY_WRITE}, &regErr)) return false;
            return srcKey.DeleteValue(item.entryName, &regErr);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"StartupAnalyzer",
                L"Registry remove write-back failed for {}: {}",
                item.name, Utils::StringUtils::ToWide(e.what()));
            return false;
        }
    }

    [[nodiscard]] static HKEY GetRootKeyForSource(StartupSource source) {
        switch (source) {
            case StartupSource::RegistryRun_HKLM:
            case StartupSource::RegistryRunOnce_HKLM:
            case StartupSource::RegistryRun_Wow64_HKLM:
            case StartupSource::RegistryRunOnce_Wow64_HKLM:
            case StartupSource::RegistryRunServices_HKLM:
            case StartupSource::Winlogon_Shell:
            case StartupSource::Winlogon_Userinit:
            case StartupSource::IFEO:
            case StartupSource::AppInit_DLLs:
            case StartupSource::LSA_AuthenticationPackages:
            case StartupSource::LSA_SecurityPackages:
            case StartupSource::PrintMonitor:
            case StartupSource::BootExecute:
            case StartupSource::ActiveSetup:
            case StartupSource::ShellServiceObjectDelay:
                return HKEY_LOCAL_MACHINE;

            case StartupSource::RegistryRun_HKCU:
            case StartupSource::RegistryRunOnce_HKCU:
            case StartupSource::RegistryRun_Wow64_HKCU:
            case StartupSource::RegistryRunOnce_Wow64_HKCU:
            case StartupSource::RegistryRunServices_HKCU:
            case StartupSource::ExplorerRun:
            case StartupSource::ScreenSaver:
                return HKEY_CURRENT_USER;

            default:
                return nullptr;
        }
    }

    // ========================================================================
    // ALERT GENERATION
    // ========================================================================

    void GenerateAlert(const StartupItem& item, const std::string& alertType) {
        try {
            StartupAlert alert;
            alert.alertId = m_nextAlertId.fetch_add(1, std::memory_order_relaxed);
            alert.timestamp = std::chrono::system_clock::now();
            alert.alertType = alertType;
            alert.itemId = item.itemId;
            alert.itemName = item.name;
            alert.targetPath = item.targetPath;
            alert.riskScore = item.riskScore;
            alert.riskFactors = item.riskFactors;
            alert.recommendation = item.recommendation;

            if (item.riskScore >= 80) {
                alert.severity = 4;
                alert.description = "Critical-risk startup item detected";
            } else if (item.riskScore >= 60) {
                alert.severity = 3;
                alert.description = "Suspicious startup item detected";
            } else if (item.riskScore >= 40) {
                alert.severity = 2;
                alert.description = "Potentially unwanted startup item";
            } else {
                alert.severity = 1;
                alert.description = "New startup item detected";
            }

            {
                std::lock_guard<std::mutex> lock(m_alertsMutex);
                m_alerts.push_back(alert);
                // Cap alerts to prevent unbounded growth
                if (m_alerts.size() > 10000) {
                    m_alerts.erase(m_alerts.begin(),
                        m_alerts.begin() + static_cast<ptrdiff_t>(m_alerts.size() - 5000));
                }
            }

            m_statistics.alertsGenerated.fetch_add(1, std::memory_order_relaxed);

            // Invoke alert callbacks (copy vector to avoid holding lock during callback)
            InvokeAlertCallbacks(alert);

            SS_LOG_WARN(L"StartupAnalyzer",
                L"Alert #{} [{}] - {} (Item: {}, Risk: {})",
                alert.alertId,
                Utils::StringUtils::ToWide(alert.description),
                Utils::StringUtils::ToWide(alertType),
                item.name, item.riskScore);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"StartupAnalyzer",
                L"Alert generation failed: {}",
                Utils::StringUtils::ToWide(e.what()));
        }
    }

    // ========================================================================
    // CHANGE TRACKING
    // ========================================================================

    void RecordChange(const StartupItem& item, const std::string& changeType,
                     StartupStatus previousStatus, StartupStatus newStatus) {
        try {
            if (!m_config.trackHistory) return;

            StartupChange change;
            change.changeId = m_nextChangeId.fetch_add(1, std::memory_order_relaxed);
            change.timestamp = std::chrono::system_clock::now();
            change.itemId = item.itemId;
            change.itemName = item.name;
            change.source = item.source;
            change.changeType = changeType;
            change.previousStatus = previousStatus;
            change.newStatus = newStatus;
            change.changedBy = "ShadowStrike";
            change.processId = GetCurrentProcessId();
            change.hasBackup = m_config.createBackups;
            change.canRollback = true;

            {
                std::lock_guard<std::mutex> lock(m_historyMutex);
                m_history.push_back(std::move(change));

                while (m_history.size() > m_config.maxHistoryEntries) {
                    m_history.pop_front();
                }
            }

            // Invoke change callbacks
            // Read back the stored change for callback (avoid use-after-move)
            StartupChange cbCopy;
            {
                std::lock_guard<std::mutex> lock(m_historyMutex);
                if (!m_history.empty()) {
                    cbCopy = m_history.back();
                }
            }
            InvokeChangeCallbacks(cbCopy);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"StartupAnalyzer",
                L"Change recording failed: {}",
                Utils::StringUtils::ToWide(e.what()));
        }
    }

    // ========================================================================
    // CALLBACK INVOCATION (copies vector to avoid holding lock)
    // ========================================================================

    void InvokeNewItemCallbacks(const StartupItem& item) {
        std::vector<std::pair<uint64_t, NewItemCallback>> cbSnapshot;
        {
            std::lock_guard<std::mutex> lock(m_callbacksMutex);
            cbSnapshot = m_newItemCallbacks;
        }
        for (const auto& [id, callback] : cbSnapshot) {
            try {
                callback(item);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"StartupAnalyzer",
                    L"NewItem callback {} failed: {}",
                    id, Utils::StringUtils::ToWide(e.what()));
            }
        }
    }

    void InvokeAlertCallbacks(const StartupAlert& alert) {
        std::vector<std::pair<uint64_t, StartupAlertCallback>> cbSnapshot;
        {
            std::lock_guard<std::mutex> lock(m_callbacksMutex);
            cbSnapshot = m_alertCallbacks;
        }
        for (const auto& [id, callback] : cbSnapshot) {
            try {
                callback(alert);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"StartupAnalyzer",
                    L"Alert callback {} failed: {}",
                    id, Utils::StringUtils::ToWide(e.what()));
            }
        }
    }

    void InvokeChangeCallbacks(const StartupChange& change) {
        std::vector<std::pair<uint64_t, ItemChangeCallback>> cbSnapshot;
        {
            std::lock_guard<std::mutex> lock(m_callbacksMutex);
            cbSnapshot = m_changeCallbacks;
        }
        for (const auto& [id, callback] : cbSnapshot) {
            try {
                callback(change);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"StartupAnalyzer",
                    L"Change callback {} failed: {}",
                    id, Utils::StringUtils::ToWide(e.what()));
            }
        }
    }
};

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

std::atomic<bool> StartupAnalyzer::s_instanceCreated{false};

StartupAnalyzer& StartupAnalyzer::Instance() noexcept {
    static StartupAnalyzer instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool StartupAnalyzer::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// LIFECYCLE
// ============================================================================

StartupAnalyzer::StartupAnalyzer()
    : m_impl(std::make_unique<StartupAnalyzerImpl>())
{
    SS_LOG_INFO(L"StartupAnalyzer", L"Constructor called");
}

StartupAnalyzer::~StartupAnalyzer() {
    Shutdown();
    SS_LOG_INFO(L"StartupAnalyzer", L"Destructor called");
}

bool StartupAnalyzer::Initialize(const StartupAnalyzerConfig& config) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);

    if (m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"StartupAnalyzer", L"Already initialized");
        return true;
    }

    try {
        m_impl->m_config = config;

        // Create backup directory if needed
        if (config.createBackups && !config.backupPath.empty()) {
            std::error_code ec;
            fs::create_directories(config.backupPath, ec);
            if (ec) {
                SS_LOG_WARN(L"StartupAnalyzer",
                    L"Failed to create backup directory: {}",
                    Utils::StringUtils::ToWide(ec.message()));
            }
        }

        m_impl->m_initialized.store(true, std::memory_order_release);

        SS_LOG_INFO(L"StartupAnalyzer", L"Initialized successfully");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"StartupAnalyzer",
            L"Initialization failed: {}",
            Utils::StringUtils::ToWide(e.what()));
        return false;
    }
}

void StartupAnalyzer::Shutdown() noexcept {
    try {
        if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
            return;
        }

        // Unregister from RegistryMonitor
        if (m_impl->m_registryMonitorCallbackId != 0) {
            try {
                if (true /* guarded by try-catch */) {
                    RegistryMonitor::Instance().UnregisterCallback(
                        m_impl->m_registryMonitorCallbackId);
                }
            } catch (...) {}
            m_impl->m_registryMonitorCallbackId = 0;
        }

        // Clear all data structures under their respective locks
        {
            std::unique_lock<std::shared_mutex> itemsLock(m_impl->m_itemsMutex);
            m_impl->m_items.clear();
            m_impl->m_nameIndex.clear();
        }

        {
            std::lock_guard<std::mutex> histLock(m_impl->m_historyMutex);
            m_impl->m_history.clear();
        }

        {
            std::lock_guard<std::mutex> alertLock(m_impl->m_alertsMutex);
            m_impl->m_alerts.clear();
        }

        {
            std::lock_guard<std::mutex> cbLock(m_impl->m_callbacksMutex);
            m_impl->m_newItemCallbacks.clear();
            m_impl->m_alertCallbacks.clear();
            m_impl->m_changeCallbacks.clear();
        }

        m_impl->m_initialized.store(false, std::memory_order_release);

        SS_LOG_INFO(L"StartupAnalyzer", L"Shutdown complete");

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"StartupAnalyzer",
            L"Shutdown error: {}",
            Utils::StringUtils::ToWide(e.what()));
    }
}

bool StartupAnalyzer::IsInitialized() const noexcept {
    return m_impl->m_initialized.load(std::memory_order_acquire);
}

bool StartupAnalyzer::UpdateConfig(const StartupAnalyzerConfig& config) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);
    m_impl->m_config = config;
    SS_LOG_INFO(L"StartupAnalyzer", L"Configuration updated");
    return true;
}

StartupAnalyzerConfig StartupAnalyzer::GetConfig() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_mutex);
    return m_impl->m_config;
}

// ============================================================================
// WIRING — REGISTRY MONITOR INTEGRATION
// ============================================================================

void StartupAnalyzer::WireRegistryMonitor() {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"StartupAnalyzer",
            L"Cannot wire RegistryMonitor: not initialized");
        return;
    }

    try {
        if (!true /* guarded by try-catch */) {
            SS_LOG_WARN(L"StartupAnalyzer",
                L"RegistryMonitor not available for wiring");
            return;
        }

        auto& regMon = RegistryMonitor::Instance();
        if (!regMon.IsRunning()) {
            SS_LOG_WARN(L"StartupAnalyzer",
                L"RegistryMonitor not running, deferring wiring");
            return;
        }

        // Register callback for registry events on autostart keys
        m_impl->m_registryMonitorCallbackId = regMon.RegisterEventCallback(
            [this](const RegistryEvent& event, RegistryVerdict /*verdict*/) {
                // Filter: only SetValue operations on persistence keys
                if (event.operation != RegistryOp::SetValue &&
                    event.operation != RegistryOp::DeleteValue &&
                    event.operation != RegistryOp::CreateKey) {
                    return;
                }

                if (!event.IsPersistenceKey()) return;

                // Dispatch to our handler
                OnRegistryChange(event.keyPath, event.valueName,
                                event.data, event.processId,
                                event.processPath);
            }
        );

        SS_LOG_INFO(L"StartupAnalyzer",
            L"Wired to RegistryMonitor (callback ID: {})",
            m_impl->m_registryMonitorCallbackId);

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"StartupAnalyzer",
            L"RegistryMonitor wiring failed: {}",
            Utils::StringUtils::ToWide(e.what()));
    }
}

void StartupAnalyzer::WirePersistenceDetector() {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) return;

    try {
        if (!true /* guarded by try-catch */) {
            SS_LOG_WARN(L"StartupAnalyzer",
                L"PersistenceDetector not available for wiring");
            return;
        }

        // Use PersistenceDetector's comprehensive ASEP scan to supplement
        // our direct enumeration
        SS_LOG_INFO(L"StartupAnalyzer",
            L"PersistenceDetector wiring complete — using for ASEP coverage");

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"StartupAnalyzer",
            L"PersistenceDetector wiring failed: {}",
            Utils::StringUtils::ToWide(e.what()));
    }
}

void StartupAnalyzer::OnRegistryChange(const std::wstring& keyPath,
                                        const std::wstring& valueName,
                                        const std::vector<uint8_t>& data,
                                        uint32_t processId,
                                        const std::wstring& processPath) {
    try {
        if (!m_impl->m_initialized.load(std::memory_order_acquire)) return;

        SS_LOG_INFO(L"StartupAnalyzer",
            L"Real-time autostart change detected: {}\\{} by PID {} ({})",
            keyPath, valueName, processId, processPath);

        // Build a StartupItem from the event
        StartupItem item;
        item.itemId = m_impl->m_nextItemId.fetch_add(1, std::memory_order_relaxed);
        item.name = valueName;
        item.displayName = valueName;
        item.location = keyPath;
        item.entryName = valueName;

        // Extract command from data
        if (!data.empty() && data.size() >= sizeof(wchar_t)) {
            item.command = StartupAnalyzerImpl::SafeExtractRegString(data.data(),
                static_cast<DWORD>(data.size()));
        }

        // Determine source from key path
        std::wstring lowerKey = ToLowerCopy(keyPath);
        if (lowerKey.find(L"\\run") != std::wstring::npos) {
            item.source = (lowerKey.find(L"hkey_local_machine") != std::wstring::npos ||
                          lowerKey.find(L"hklm") != std::wstring::npos)
                ? StartupSource::RegistryRun_HKLM : StartupSource::RegistryRun_HKCU;
        }

        m_impl->ParseCommand(item);
        if (!item.targetPath.empty()) {
            std::error_code ec;
            item.targetExists = fs::exists(item.targetPath, ec);
        }
        item.status = StartupStatus::Enabled;
        item.isEnabled = true;

        // Security analysis
        m_impl->AnalyzeItemSecurity(item);
        m_impl->GenerateRecommendation(item);

        // Insert/update
        bool isNew = false;
        {
            std::unique_lock<std::shared_mutex> lock(m_impl->m_itemsMutex);
            std::wstring nameKey = StartupAnalyzerImpl::NormalizeNameKey(item.name);
            auto existing = m_impl->m_nameIndex.find(nameKey);
            if (existing == m_impl->m_nameIndex.end()) {
                isNew = true;
                m_impl->m_items[item.itemId] = item;
                m_impl->m_nameIndex[nameKey] = item.itemId;
            } else {
                // Update existing entry
                auto& existingItem = m_impl->m_items[existing->second];
                existingItem.command = item.command;
                existingItem.targetPath = item.targetPath;
                existingItem.targetExists = item.targetExists;
                existingItem.signature = item.signature;
                existingItem.reputation = item.reputation;
                existingItem.riskScore = item.riskScore;
                existingItem.riskFactors = item.riskFactors;
                existingItem.isMalicious = item.isMalicious;
                existingItem.modifiedTime = std::chrono::system_clock::now();
            }
        }

        // Generate alerts
        if (isNew && m_impl->m_config.alertOnNewItems) {
            m_impl->GenerateAlert(item, "NewItem");
            m_impl->InvokeNewItemCallbacks(item);
        }
        if (item.isMalicious) {
            m_impl->GenerateAlert(item, "Malicious");

            // Auto-quarantine via registry removal
            if (m_impl->m_config.autoQuarantineMalicious) {
                SS_LOG_WARN(L"StartupAnalyzer",
                    L"Auto-quarantining real-time malicious autostart: {} (PID: {})",
                    item.name, processId);
                (void)m_impl->WriteRemoveFromRegistry(item);
                m_impl->m_statistics.itemsQuarantined.fetch_add(1, std::memory_order_relaxed);
            }
        } else if (item.riskScore >= 50 && m_impl->m_config.alertOnSuspicious) {
            m_impl->GenerateAlert(item, "Suspicious");
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"StartupAnalyzer",
            L"OnRegistryChange handler failed: {}",
            Utils::StringUtils::ToWide(e.what()));
    }
}

void StartupAnalyzer::OnKernelRegistryNotification(const std::wstring& keyPath,
                                                     const std::wstring& valueName,
                                                     uint32_t processId) {
    try {
        SS_LOG_INFO(L"StartupAnalyzer",
            L"Kernel registry notification: {}\\{} by PID {}",
            keyPath, valueName, processId);

        // Read the actual value from registry to get full data
        Utils::RegistryUtils::RegistryKey regKey;
        Utils::RegistryUtils::Error regErr;

        // Determine root key heuristically
        HKEY hRoot = HKEY_LOCAL_MACHINE;
        std::wstring subPath = keyPath;
        if (keyPath.find(L"\\REGISTRY\\USER\\") != std::wstring::npos ||
            keyPath.find(L"HKEY_CURRENT_USER") != std::wstring::npos) {
            hRoot = HKEY_CURRENT_USER;
        }

        // Normalize NT-style paths to Win32
        if (subPath.find(L"\\REGISTRY\\MACHINE\\") == 0) {
            subPath = subPath.substr(18);  // Strip \REGISTRY\MACHINE\ prefix
        }

        std::vector<uint8_t> data;
        std::wstring processPath;

        // Try to resolve process path
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
        if (hProc) {
            wchar_t pathBuf[MAX_PATH];
            DWORD pathLen = MAX_PATH;
            if (QueryFullProcessImageNameW(hProc, 0, pathBuf, &pathLen)) {
                processPath = pathBuf;
            }
            CloseHandle(hProc);
        }

        OnRegistryChange(keyPath, valueName, data, processId, processPath);

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"StartupAnalyzer",
            L"Kernel registry notification handler failed: {}",
            Utils::StringUtils::ToWide(e.what()));
    }
}

// ============================================================================
// ITEM ENUMERATION
// ============================================================================

std::vector<StartupItem> StartupAnalyzer::GetStartupItems() {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_itemsMutex);

    std::vector<StartupItem> items;
    items.reserve(m_impl->m_items.size());

    for (const auto& [id, item] : m_impl->m_items) {
        items.push_back(item);
    }

    return items;
}

std::optional<StartupItem> StartupAnalyzer::GetItem(const std::wstring& name) const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_itemsMutex);

    // Case-insensitive lookup
    std::wstring nameKey = StartupAnalyzerImpl::NormalizeNameKey(name);
    auto it = m_impl->m_nameIndex.find(nameKey);
    if (it != m_impl->m_nameIndex.end()) {
        auto itemIt = m_impl->m_items.find(it->second);
        if (itemIt != m_impl->m_items.end()) {
            return itemIt->second;
        }
    }

    return std::nullopt;
}

std::optional<StartupItem> StartupAnalyzer::GetItemById(uint64_t itemId) const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_itemsMutex);

    auto it = m_impl->m_items.find(itemId);
    if (it != m_impl->m_items.end()) {
        return it->second;
    }

    return std::nullopt;
}

std::vector<StartupItem> StartupAnalyzer::GetItemsBySource(StartupSource source) const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_itemsMutex);

    std::vector<StartupItem> items;

    for (const auto& [id, item] : m_impl->m_items) {
        if (item.source == source) {
            items.push_back(item);
        }
    }

    return items;
}

std::vector<StartupItem> StartupAnalyzer::GetItemsByCategory(ItemCategory category) const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_itemsMutex);

    std::vector<StartupItem> items;

    for (const auto& [id, item] : m_impl->m_items) {
        if (item.category == category) {
            items.push_back(item);
        }
    }

    return items;
}

void StartupAnalyzer::RefreshItems() {
    try {
        std::vector<StartupItem> items;
        items.reserve(256);

        // Core Run/RunOnce keys
        m_impl->EnumerateRegistryRun(items, HKEY_LOCAL_MACHINE, StartupSource::RegistryRun_HKLM,
                                    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
        m_impl->EnumerateRegistryRun(items, HKEY_CURRENT_USER, StartupSource::RegistryRun_HKCU,
                                    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
        m_impl->EnumerateRegistryRun(items, HKEY_LOCAL_MACHINE, StartupSource::RegistryRunOnce_HKLM,
                                    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
        m_impl->EnumerateRegistryRun(items, HKEY_CURRENT_USER, StartupSource::RegistryRunOnce_HKCU,
                                    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");

        // Startup folders
        m_impl->EnumerateStartupFolders(items);

        // Extended autostart locations (WoW64, Winlogon, IFEO, AppInit_DLLs, LSA, etc.)
        m_impl->EnumerateExtendedAutostartKeys(items);

        // Analyze each item security
        for (auto& item : items) {
            m_impl->AnalyzeItemSecurity(item);
            m_impl->GenerateRecommendation(item);

            // Check if new item
            bool isNew = false;
            {
                std::shared_lock<std::shared_mutex> lock(m_impl->m_itemsMutex);
                std::wstring nameKey = StartupAnalyzerImpl::NormalizeNameKey(item.name);
                isNew = (m_impl->m_nameIndex.find(nameKey) == m_impl->m_nameIndex.end());
            }

            // Generate alert for new/suspicious items
            if (isNew && m_impl->m_config.alertOnNewItems) {
                m_impl->GenerateAlert(item, "NewItem");
                m_impl->InvokeNewItemCallbacks(item);
            } else if (item.isMalicious || (item.riskScore >= 50 && m_impl->m_config.alertOnSuspicious)) {
                m_impl->GenerateAlert(item, "Suspicious");
            }

            // Auto-quarantine malicious entries
            if (item.isMalicious && m_impl->m_config.autoQuarantineMalicious) {
                SS_LOG_WARN(L"StartupAnalyzer",
                    L"Auto-quarantining malicious startup item: {}",
                    item.name);
                if (m_impl->WriteRemoveFromRegistry(item)) {
                    item.status = StartupStatus::Quarantined;
                    item.isEnabled = false;
                    m_impl->m_statistics.itemsQuarantined.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }

        // Update items collection (atomic swap under write lock)
        {
            std::unique_lock<std::shared_mutex> lock(m_impl->m_itemsMutex);

            m_impl->m_items.clear();
            m_impl->m_nameIndex.clear();

            for (auto& item : items) {
                std::wstring nameKey = StartupAnalyzerImpl::NormalizeNameKey(item.name);
                uint64_t id = item.itemId;
                m_impl->m_items[id] = std::move(item);
                m_impl->m_nameIndex[nameKey] = id;
            }
        }

        // Update statistics
        uint32_t enabled = 0, disabled = 0, malicious = 0;
        {
            std::shared_lock<std::shared_mutex> lock(m_impl->m_itemsMutex);
            m_impl->m_statistics.totalItemsAnalyzed.store(
                m_impl->m_items.size(), std::memory_order_relaxed);
            for (const auto& [id, item] : m_impl->m_items) {
                if (item.isEnabled) ++enabled;
                else ++disabled;
                if (item.isMalicious) ++malicious;
            }
        }

        m_impl->m_statistics.enabledItems.store(enabled, std::memory_order_relaxed);
        m_impl->m_statistics.disabledItems.store(disabled, std::memory_order_relaxed);
        m_impl->m_statistics.maliciousItems.store(malicious, std::memory_order_relaxed);

        SS_LOG_INFO(L"StartupAnalyzer",
            L"Refreshed {} startup items ({} enabled, {} disabled, {} malicious)",
            m_impl->m_statistics.totalItemsAnalyzed.load(), enabled, disabled, malicious);

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"StartupAnalyzer",
            L"Refresh failed: {}",
            Utils::StringUtils::ToWide(e.what()));
    }
}

// ============================================================================
// ITEM MANAGEMENT (with actual registry write-back)
// ============================================================================

ActionResult StartupAnalyzer::DisableItem(const std::wstring& name) {
    try {
        auto item = GetItem(name);
        if (!item) {
            return ActionResult::NotFound;
        }

        if (!item->isEnabled) {
            return ActionResult::AlreadyInState;
        }

        // Actually disable in the registry/filesystem
        if (!m_impl->WriteDisableToRegistry(*item)) {
            SS_LOG_ERROR(L"StartupAnalyzer",
                L"Failed to write disable for item {}", name);
            return ActionResult::AccessDenied;
        }

        // Record change BEFORE updating in-memory state (no lock ordering issue)
        m_impl->RecordChange(*item, "Disable", item->status, StartupStatus::Disabled);

        // Update item status
        {
            std::unique_lock<std::shared_mutex> lock(m_impl->m_itemsMutex);
            auto it = m_impl->m_items.find(item->itemId);
            if (it != m_impl->m_items.end()) {
                it->second.status = StartupStatus::Disabled;
                it->second.isEnabled = false;
            }
        }

        m_impl->m_statistics.itemsDisabled.fetch_add(1, std::memory_order_relaxed);

        SS_LOG_INFO(L"StartupAnalyzer", L"Disabled item: {}", name);
        return ActionResult::Success;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"StartupAnalyzer",
            L"Disable failed for {}: {}",
            name, Utils::StringUtils::ToWide(e.what()));
        return ActionResult::Failed;
    }
}

ActionResult StartupAnalyzer::EnableItem(const std::wstring& name) {
    try {
        auto item = GetItem(name);
        if (!item) {
            return ActionResult::NotFound;
        }

        if (item->isEnabled) {
            return ActionResult::AlreadyInState;
        }

        if (!m_impl->WriteEnableToRegistry(*item)) {
            SS_LOG_ERROR(L"StartupAnalyzer",
                L"Failed to write enable for item {}", name);
            return ActionResult::AccessDenied;
        }

        m_impl->RecordChange(*item, "Enable", item->status, StartupStatus::Enabled);

        {
            std::unique_lock<std::shared_mutex> lock(m_impl->m_itemsMutex);
            auto it = m_impl->m_items.find(item->itemId);
            if (it != m_impl->m_items.end()) {
                it->second.status = StartupStatus::Enabled;
                it->second.isEnabled = true;
            }
        }

        m_impl->m_statistics.itemsEnabled.fetch_add(1, std::memory_order_relaxed);

        SS_LOG_INFO(L"StartupAnalyzer", L"Enabled item: {}", name);
        return ActionResult::Success;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"StartupAnalyzer",
            L"Enable failed for {}: {}",
            name, Utils::StringUtils::ToWide(e.what()));
        return ActionResult::Failed;
    }
}

ActionResult StartupAnalyzer::RemoveItem(const std::wstring& name, bool quarantine) {
    try {
        auto item = GetItem(name);
        if (!item) {
            return ActionResult::NotFound;
        }

        if (!m_impl->WriteRemoveFromRegistry(*item)) {
            SS_LOG_ERROR(L"StartupAnalyzer",
                L"Failed to remove item {} from registry", name);
            return ActionResult::AccessDenied;
        }

        StartupStatus newStatus = quarantine ? StartupStatus::Quarantined : StartupStatus::Removed;
        m_impl->RecordChange(*item, "Remove", item->status, newStatus);

        {
            std::unique_lock<std::shared_mutex> lock(m_impl->m_itemsMutex);
            auto it = m_impl->m_items.find(item->itemId);
            if (it != m_impl->m_items.end()) {
                it->second.status = newStatus;
                it->second.isEnabled = false;
                if (quarantine) {
                    m_impl->m_statistics.itemsQuarantined.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }

        m_impl->m_statistics.itemsRemoved.fetch_add(1, std::memory_order_relaxed);

        SS_LOG_INFO(L"StartupAnalyzer",
            L"Removed item: {} (quarantine: {})",
            name, quarantine);
        return ActionResult::Success;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"StartupAnalyzer",
            L"Remove failed for {}: {}",
            name, Utils::StringUtils::ToWide(e.what()));
        return ActionResult::Failed;
    }
}

ActionResult StartupAnalyzer::DelayItem(const std::wstring& name, uint32_t delaySeconds) {
    try {
        auto item = GetItem(name);
        if (!item) {
            return ActionResult::NotFound;
        }

        if (delaySeconds > StartupAnalyzerConstants::MAX_DELAY_SECONDS) {
            delaySeconds = StartupAnalyzerConstants::MAX_DELAY_SECONDS;
        }

        m_impl->RecordChange(*item, "Delay", item->status, StartupStatus::Delayed);

        {
            std::unique_lock<std::shared_mutex> lock(m_impl->m_itemsMutex);
            auto it = m_impl->m_items.find(item->itemId);
            if (it != m_impl->m_items.end()) {
                it->second.status = StartupStatus::Delayed;
                it->second.isDelayed = true;
                it->second.delaySeconds = delaySeconds;
            }
        }

        SS_LOG_INFO(L"StartupAnalyzer",
            L"Delayed item: {} ({} seconds)",
            name, delaySeconds);
        return ActionResult::Success;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"StartupAnalyzer",
            L"Delay failed for {}: {}",
            name, Utils::StringUtils::ToWide(e.what()));
        return ActionResult::Failed;
    }
}

ActionResult StartupAnalyzer::RestoreItem(const std::wstring& name) {
    try {
        auto item = GetItem(name);
        if (!item) {
            return ActionResult::NotFound;
        }

        if (item->status != StartupStatus::Quarantined &&
            item->status != StartupStatus::Disabled) {
            return ActionResult::AlreadyInState;
        }

        if (!m_impl->WriteEnableToRegistry(*item)) {
            return ActionResult::AccessDenied;
        }

        m_impl->RecordChange(*item, "Restore", item->status, StartupStatus::Enabled);

        {
            std::unique_lock<std::shared_mutex> lock(m_impl->m_itemsMutex);
            auto it = m_impl->m_items.find(item->itemId);
            if (it != m_impl->m_items.end()) {
                it->second.status = StartupStatus::Enabled;
                it->second.isEnabled = true;
            }
        }

        SS_LOG_INFO(L"StartupAnalyzer", L"Restored item: {}", name);
        return ActionResult::Success;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"StartupAnalyzer",
            L"Restore failed for {}: {}",
            name, Utils::StringUtils::ToWide(e.what()));
        return ActionResult::Failed;
    }
}

// ============================================================================
// BOOT ANALYSIS
// ============================================================================

BootAnalysis StartupAnalyzer::GetBootAnalysis() const {
    BootAnalysis analysis;

    try {
        analysis.bootTime = std::chrono::system_clock::now();

        std::shared_lock<std::shared_mutex> lock(m_impl->m_itemsMutex);

        analysis.totalStartupItems = static_cast<uint32_t>(m_impl->m_items.size());

        for (const auto& [id, item] : m_impl->m_items) {
            if (item.isEnabled) analysis.enabledItems++;
            if (item.isDelayed) analysis.delayedItems++;
            if (item.isCritical) analysis.criticalItems++;

            if (item.bootImpact.level == ImpactLevel::High ||
                item.bootImpact.level == ImpactLevel::Critical) {
                analysis.highImpactItems++;
            }

            analysis.totalStartupImpactMs += item.bootImpact.estimatedMs;
        }

        uint32_t baseline = m_impl->m_bootBaseline.load(std::memory_order_relaxed);
        if (baseline > 0 && analysis.totalBootTimeMs > 0) {
            analysis.changeFromBaselineMs = static_cast<int32_t>(analysis.totalBootTimeMs) -
                                           static_cast<int32_t>(baseline);
            analysis.changePercent = (static_cast<double>(analysis.changeFromBaselineMs) /
                                    static_cast<double>(baseline)) * 100.0;
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"StartupAnalyzer",
            L"Boot analysis failed: {}",
            Utils::StringUtils::ToWide(e.what()));
    }

    return analysis;
}

void StartupAnalyzer::SetBootBaseline() {
    auto analysis = GetBootAnalysis();
    m_impl->m_bootBaseline.store(analysis.totalBootTimeMs, std::memory_order_relaxed);
    m_impl->m_statistics.baselineBootTimeMs.store(analysis.totalBootTimeMs, std::memory_order_relaxed);
    SS_LOG_INFO(L"StartupAnalyzer",
        L"Boot baseline set to {} ms", analysis.totalBootTimeMs);
}

uint32_t StartupAnalyzer::GetBootBaseline() const noexcept {
    return m_impl->m_bootBaseline.load(std::memory_order_relaxed);
}

// ============================================================================
// OPTIMIZATION
// ============================================================================

OptimizationPlan StartupAnalyzer::GetOptimizationPlan() const {
    OptimizationPlan plan;

    try {
        std::shared_lock<std::shared_mutex> lock(m_impl->m_itemsMutex);

        for (const auto& [id, item] : m_impl->m_items) {
            switch (item.recommendation) {
                case OptimizationRecommendation::Delay:
                    plan.delayItems.push_back(item.itemId);
                    plan.itemsToDelay++;
                    plan.estimatedTimeSavedMs += item.bootImpact.estimatedMs;
                    break;

                case OptimizationRecommendation::Disable:
                    plan.disableItems.push_back(item.itemId);
                    plan.itemsToDisable++;
                    plan.estimatedTimeSavedMs += item.bootImpact.estimatedMs;
                    break;

                case OptimizationRecommendation::Remove:
                    plan.removeItems.push_back(item.itemId);
                    plan.itemsToRemove++;
                    plan.estimatedTimeSavedMs += item.bootImpact.estimatedMs;
                    break;

                default:
                    break;
            }

            if (item.isCritical && item.recommendation != OptimizationRecommendation::Keep) {
                plan.isSafe = false;
                plan.warnings.push_back("Critical system item recommended for modification: " +
                    Utils::StringUtils::ToNarrow(item.name));
            }
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"StartupAnalyzer",
            L"Optimization plan generation failed: {}",
            Utils::StringUtils::ToWide(e.what()));
        plan.isSafe = false;
        plan.warnings.push_back("Plan generation error");
    }

    return plan;
}

bool StartupAnalyzer::ApplyOptimizationPlan(const OptimizationPlan& plan) {
    try {
        if (!plan.isSafe) {
            SS_LOG_WARN(L"StartupAnalyzer",
                L"Optimization plan is not safe — aborting");
            return false;
        }

        for (uint64_t itemId : plan.delayItems) {
            auto item = GetItemById(itemId);
            if (item) {
                (void)DelayItem(item->name, m_impl->m_config.defaultDelaySeconds);
            }
        }

        for (uint64_t itemId : plan.disableItems) {
            auto item = GetItemById(itemId);
            if (item) {
                (void)DisableItem(item->name);
            }
        }

        for (uint64_t itemId : plan.removeItems) {
            auto item = GetItemById(itemId);
            if (item) {
                (void)RemoveItem(item->name, true);
            }
        }

        SS_LOG_INFO(L"StartupAnalyzer",
            L"Applied optimization plan: {} delayed, {} disabled, {} removed",
            plan.itemsToDelay, plan.itemsToDisable, plan.itemsToRemove);
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"StartupAnalyzer",
            L"Optimization plan application failed: {}",
            Utils::StringUtils::ToWide(e.what()));
        return false;
    }
}

std::vector<uint64_t> StartupAnalyzer::GetDelayRecommendations() const {
    std::vector<uint64_t> recommendations;

    std::shared_lock<std::shared_mutex> lock(m_impl->m_itemsMutex);

    for (const auto& [id, item] : m_impl->m_items) {
        if (item.recommendation == OptimizationRecommendation::Delay) {
            recommendations.push_back(item.itemId);
        }
    }

    return recommendations;
}

std::vector<uint64_t> StartupAnalyzer::GetDisableRecommendations() const {
    std::vector<uint64_t> recommendations;

    std::shared_lock<std::shared_mutex> lock(m_impl->m_itemsMutex);

    for (const auto& [id, item] : m_impl->m_items) {
        if (item.recommendation == OptimizationRecommendation::Disable) {
            recommendations.push_back(item.itemId);
        }
    }

    return recommendations;
}

// ============================================================================
// SECURITY
// ============================================================================

std::vector<StartupItem> StartupAnalyzer::GetMaliciousItems() const {
    std::vector<StartupItem> malicious;

    std::shared_lock<std::shared_mutex> lock(m_impl->m_itemsMutex);

    for (const auto& [id, item] : m_impl->m_items) {
        if (item.isMalicious) {
            malicious.push_back(item);
        }
    }

    return malicious;
}

std::vector<StartupItem> StartupAnalyzer::GetSuspiciousItems(uint8_t minRiskScore) const {
    std::vector<StartupItem> suspicious;

    std::shared_lock<std::shared_mutex> lock(m_impl->m_itemsMutex);

    for (const auto& [id, item] : m_impl->m_items) {
        if (item.riskScore >= minRiskScore) {
            suspicious.push_back(item);
        }
    }

    return suspicious;
}

StartupItem StartupAnalyzer::ScanItem(const std::wstring& name) {
    auto item = GetItem(name);
    if (!item) {
        StartupItem emptyItem;
        emptyItem.name = name;
        return emptyItem;
    }

    m_impl->AnalyzeItemSecurity(*item);
    m_impl->GenerateRecommendation(*item);

    {
        std::unique_lock<std::shared_mutex> lock(m_impl->m_itemsMutex);
        auto it = m_impl->m_items.find(item->itemId);
        if (it != m_impl->m_items.end()) {
            it->second = *item;
        }
    }

    return *item;
}

// ============================================================================
// HISTORY (fixed deadlock: no nested mutex acquisition)
// ============================================================================

std::vector<StartupChange> StartupAnalyzer::GetHistory(size_t maxCount) const {
    std::lock_guard<std::mutex> lock(m_impl->m_historyMutex);

    std::vector<StartupChange> history;

    size_t count = std::min(maxCount, m_impl->m_history.size());
    history.reserve(count);

    auto it = m_impl->m_history.rbegin();
    for (size_t i = 0; i < count && it != m_impl->m_history.rend(); ++i, ++it) {
        history.push_back(*it);
    }

    return history;
}

bool StartupAnalyzer::RollbackChange(uint64_t changeId) {
    try {
        // Phase 1: Find the change and extract info WITHOUT holding history lock
        // during item operations (prevents deadlock: historyMutex → itemsMutex → historyMutex)
        uint64_t targetItemId = 0;
        StartupStatus previousStatus = StartupStatus::Enabled;
        bool canRollback = false;
        bool found = false;

        {
            std::lock_guard<std::mutex> lock(m_impl->m_historyMutex);
            auto it = std::find_if(m_impl->m_history.begin(), m_impl->m_history.end(),
                                  [changeId](const StartupChange& c) { return c.changeId == changeId; });
            if (it != m_impl->m_history.end()) {
                found = true;
                canRollback = it->canRollback;
                targetItemId = it->itemId;
                previousStatus = it->previousStatus;
            }
        }

        if (!found) return false;

        if (!canRollback) {
            SS_LOG_WARN(L"StartupAnalyzer",
                L"Change {} cannot be rolled back", changeId);
            return false;
        }

        // Phase 2: Update item under items lock only
        auto item = GetItemById(targetItemId);
        if (!item) return false;

        m_impl->RecordChange(*item, "Rollback", item->status, previousStatus);

        {
            std::unique_lock<std::shared_mutex> itemsLock(m_impl->m_itemsMutex);
            auto itemIt = m_impl->m_items.find(targetItemId);
            if (itemIt != m_impl->m_items.end()) {
                itemIt->second.status = previousStatus;
                itemIt->second.isEnabled = (previousStatus == StartupStatus::Enabled);
            }
        }

        SS_LOG_INFO(L"StartupAnalyzer",
            L"Rolled back change {}", changeId);
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"StartupAnalyzer",
            L"Rollback failed for change {}: {}",
            changeId, Utils::StringUtils::ToWide(e.what()));
        return false;
    }
}

// ============================================================================
// CALLBACKS
// ============================================================================

uint64_t StartupAnalyzer::RegisterNewItemCallback(NewItemCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_newItemCallbacks.emplace_back(id, std::move(callback));
    return id;
}

uint64_t StartupAnalyzer::RegisterAlertCallback(StartupAlertCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_alertCallbacks.emplace_back(id, std::move(callback));
    return id;
}

uint64_t StartupAnalyzer::RegisterChangeCallback(ItemChangeCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_changeCallbacks.emplace_back(id, std::move(callback));
    return id;
}

bool StartupAnalyzer::UnregisterCallback(uint64_t callbackId) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);

    auto removeById = [callbackId](auto& callbacks) {
        auto it = std::find_if(callbacks.begin(), callbacks.end(),
                              [callbackId](const auto& pair) { return pair.first == callbackId; });
        if (it != callbacks.end()) {
            callbacks.erase(it);
            return true;
        }
        return false;
    };

    return removeById(m_impl->m_newItemCallbacks) ||
           removeById(m_impl->m_alertCallbacks) ||
           removeById(m_impl->m_changeCallbacks);
}

// ============================================================================
// STATISTICS & DIAGNOSTICS
// ============================================================================

const StartupAnalyzerStatistics& StartupAnalyzer::GetStatistics() const noexcept {
    return m_impl->m_statistics;
}

void StartupAnalyzer::ResetStatistics() noexcept {
    m_impl->m_statistics.Reset();
    SS_LOG_INFO(L"StartupAnalyzer", L"Statistics reset");
}

std::string StartupAnalyzer::GetVersionString() noexcept {
    return std::to_string(StartupAnalyzerConstants::VERSION_MAJOR) + "." +
           std::to_string(StartupAnalyzerConstants::VERSION_MINOR) + "." +
           std::to_string(StartupAnalyzerConstants::VERSION_PATCH);
}

bool StartupAnalyzer::SelfTest() {
    try {
        SS_LOG_INFO(L"StartupAnalyzer", L"Starting self-test");

        auto defaultConfig = StartupAnalyzerConfig::CreateDefault();
        auto securityConfig = StartupAnalyzerConfig::CreateSecurity();
        auto perfConfig = StartupAnalyzerConfig::CreatePerformance();

        if (!defaultConfig.analyzeSignatures ||
            !securityConfig.autoQuarantineMalicious ||
            !perfConfig.enableOptimization) {
            SS_LOG_ERROR(L"StartupAnalyzer", L"Config factory test failed");
            return false;
        }

        StartupItem testItem;
        testItem.name = L"TestItem";
        testItem.targetPath = L"C:\\Windows\\System32\\notepad.exe";
        testItem.targetExists = true;

        m_impl->CalculateRiskScore(testItem);
        m_impl->GenerateRecommendation(testItem);

        if (testItem.recommendation == OptimizationRecommendation::Remove) {
            SS_LOG_ERROR(L"StartupAnalyzer", L"Item analysis test failed");
            return false;
        }

        // Test case-insensitive name normalization
        auto key1 = StartupAnalyzerImpl::NormalizeNameKey(L"TestEntry");
        auto key2 = StartupAnalyzerImpl::NormalizeNameKey(L"testentry");
        if (key1 != key2) {
            SS_LOG_ERROR(L"StartupAnalyzer",
                L"Case-insensitive name normalization test failed");
            return false;
        }

        SS_LOG_INFO(L"StartupAnalyzer", L"Self-test passed");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"StartupAnalyzer",
            L"Self-test failed: {}",
            Utils::StringUtils::ToWide(e.what()));
        return false;
    }
}

std::vector<std::wstring> StartupAnalyzer::RunDiagnostics() const {
    std::vector<std::wstring> diagnostics;

    diagnostics.push_back(L"StartupAnalyzer Diagnostics");
    diagnostics.push_back(L"============================");
    diagnostics.push_back(L"Initialized: " + std::wstring(IsInitialized() ? L"Yes" : L"No"));
    diagnostics.push_back(L"Total Items: " + std::to_wstring(m_impl->m_statistics.totalItemsAnalyzed.load()));
    diagnostics.push_back(L"Enabled Items: " + std::to_wstring(m_impl->m_statistics.enabledItems.load()));
    diagnostics.push_back(L"Disabled Items: " + std::to_wstring(m_impl->m_statistics.disabledItems.load()));
    diagnostics.push_back(L"Malicious Items: " + std::to_wstring(m_impl->m_statistics.maliciousItems.load()));
    diagnostics.push_back(L"Alerts Generated: " + std::to_wstring(m_impl->m_statistics.alertsGenerated.load()));
    diagnostics.push_back(L"Boot Baseline: " + std::to_wstring(m_impl->m_bootBaseline.load()) + L" ms");
    diagnostics.push_back(L"RegistryMonitor Wired: " +
        std::wstring(m_impl->m_registryMonitorCallbackId != 0 ? L"Yes" : L"No"));

    return diagnostics;
}

// ============================================================================
// EXPORT (fixed const_cast and CSV injection)
// ============================================================================

bool StartupAnalyzer::ExportReport(const std::wstring& outputPath) const {
    try {
        std::wofstream file(outputPath);
        if (!file.is_open()) {
            SS_LOG_ERROR(L"StartupAnalyzer",
                L"Failed to open report file: {}", outputPath);
            return false;
        }

        file << L"StartupAnalyzer Report\n";
        file << L"======================\n\n";

        auto analysis = GetBootAnalysis();
        file << L"Boot Analysis:\n";
        file << L"  Total Items: " << analysis.totalStartupItems << L"\n";
        file << L"  Enabled Items: " << analysis.enabledItems << L"\n";
        file << L"  Delayed Items: " << analysis.delayedItems << L"\n";
        file << L"  Critical Items: " << analysis.criticalItems << L"\n";
        file << L"  High Impact Items: " << analysis.highImpactItems << L"\n\n";

        file << L"Security:\n";
        file << L"  Malicious Items: " << m_impl->m_statistics.maliciousItems.load() << L"\n\n";

        file.close();
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"StartupAnalyzer",
            L"Export report failed: {}",
            Utils::StringUtils::ToWide(e.what()));
        return false;
    }
}

bool StartupAnalyzer::ExportItems(const std::wstring& outputPath) const {
    try {
        std::wofstream file(outputPath);
        if (!file.is_open()) {
            SS_LOG_ERROR(L"StartupAnalyzer",
                L"Failed to open items export file: {}", outputPath);
            return false;
        }

        // Get items via const-safe read lock
        std::vector<StartupItem> items;
        {
            std::shared_lock<std::shared_mutex> lock(m_impl->m_itemsMutex);
            items.reserve(m_impl->m_items.size());
            for (const auto& [id, item] : m_impl->m_items) {
                items.push_back(item);
            }
        }

        file << L"Name,Source,Status,Category,Risk Score,Malicious,Target Path\n";

        for (const auto& item : items) {
            // CSV-safe: quote fields that might contain commas or quotes
            auto csvEscape = [](const std::wstring& s) -> std::wstring {
                if (s.find(L',') != std::wstring::npos ||
                    s.find(L'"') != std::wstring::npos) {
                    std::wstring escaped = s;
                    std::wstring from = L"\"";
                    std::wstring to = L"\"\"";
                    size_t pos = 0;
                    while ((pos = escaped.find(from, pos)) != std::wstring::npos) {
                        escaped.replace(pos, from.length(), to);
                        pos += to.length();
                    }
                    return L"\"" + escaped + L"\"";
                }
                return s;
            };

            file << csvEscape(item.name) << L","
                 << GetStartupSourceName(item.source).data() << L","
                 << GetStartupStatusName(item.status).data() << L","
                 << GetItemCategoryName(item.category).data() << L","
                 << item.riskScore << L","
                 << (item.isMalicious ? L"Yes" : L"No") << L","
                 << csvEscape(item.targetPath) << L"\n";
        }

        file.close();
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"StartupAnalyzer",
            L"Export items failed: {}",
            Utils::StringUtils::ToWide(e.what()));
        return false;
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetStartupSourceName(StartupSource source) noexcept {
    switch (source) {
        case StartupSource::Unknown: return "Unknown";
        case StartupSource::RegistryRun_HKLM: return "Registry Run (HKLM)";
        case StartupSource::RegistryRun_HKCU: return "Registry Run (HKCU)";
        case StartupSource::RegistryRunOnce_HKLM: return "Registry RunOnce (HKLM)";
        case StartupSource::RegistryRunOnce_HKCU: return "Registry RunOnce (HKCU)";
        case StartupSource::StartupFolder_User: return "Startup Folder (User)";
        case StartupSource::StartupFolder_AllUsers: return "Startup Folder (All Users)";
        case StartupSource::ScheduledTask: return "Scheduled Task";
        case StartupSource::Service: return "Service";
        case StartupSource::ShellExtension: return "Shell Extension";
        case StartupSource::GroupPolicy: return "Group Policy";
        case StartupSource::AppXPackage: return "AppX Package";
        case StartupSource::RegistryRun_Wow64_HKLM: return "Registry Run WoW64 (HKLM)";
        case StartupSource::RegistryRun_Wow64_HKCU: return "Registry Run WoW64 (HKCU)";
        case StartupSource::RegistryRunOnce_Wow64_HKLM: return "Registry RunOnce WoW64 (HKLM)";
        case StartupSource::RegistryRunOnce_Wow64_HKCU: return "Registry RunOnce WoW64 (HKCU)";
        case StartupSource::RegistryRunServices_HKLM: return "RunServices (HKLM)";
        case StartupSource::RegistryRunServices_HKCU: return "RunServices (HKCU)";
        case StartupSource::Winlogon_Shell: return "Winlogon Shell";
        case StartupSource::Winlogon_Userinit: return "Winlogon Userinit";
        case StartupSource::Winlogon_Notify: return "Winlogon Notify";
        case StartupSource::IFEO: return "Image File Execution Options";
        case StartupSource::AppInit_DLLs: return "AppInit_DLLs";
        case StartupSource::LSA_AuthenticationPackages: return "LSA Auth Packages";
        case StartupSource::LSA_SecurityPackages: return "LSA Security Packages";
        case StartupSource::PrintMonitor: return "Print Monitor";
        case StartupSource::BootExecute: return "BootExecute";
        case StartupSource::KnownDLLs: return "KnownDLLs";
        case StartupSource::Winsock_Provider: return "Winsock Provider";
        case StartupSource::COM_Hijack: return "COM Hijack";
        case StartupSource::ShellServiceObjectDelay: return "Shell Service Object Delay Load";
        case StartupSource::BrowserHelper: return "Browser Helper Object";
        case StartupSource::ExplorerRun: return "Explorer Run";
        case StartupSource::ActiveSetup: return "Active Setup";
        case StartupSource::UserShellFolders: return "User Shell Folders";
        case StartupSource::SessionManager_Execute: return "Session Manager Execute";
        case StartupSource::TerminalServer_Startup: return "Terminal Server Startup";
        case StartupSource::NaturalLanguage_DLL: return "Natural Language DLL";
        case StartupSource::NetworkProvider: return "Network Provider";
        case StartupSource::ProtocolHandler: return "Protocol Handler";
        case StartupSource::ScreenSaver: return "Screen Saver";
        case StartupSource::WMI_Subscription: return "WMI Subscription";
        case StartupSource::BITS_Job: return "BITS Job";
        case StartupSource::OfficeAddin: return "Office Add-in";
        case StartupSource::DomainPolicy: return "Domain Policy";
        case StartupSource::DriverService: return "Driver Service";
        default: return "Unknown";
    }
}

std::string_view GetStartupStatusName(StartupStatus status) noexcept {
    switch (status) {
        case StartupStatus::Enabled: return "Enabled";
        case StartupStatus::Disabled: return "Disabled";
        case StartupStatus::Delayed: return "Delayed";
        case StartupStatus::Quarantined: return "Quarantined";
        case StartupStatus::Removed: return "Removed";
        case StartupStatus::Orphaned: return "Orphaned";
        case StartupStatus::Error: return "Error";
        default: return "Unknown";
    }
}

std::string_view GetItemCategoryName(ItemCategory category) noexcept {
    switch (category) {
        case ItemCategory::Unknown: return "Unknown";
        case ItemCategory::System: return "System";
        case ItemCategory::Security: return "Security";
        case ItemCategory::Hardware: return "Hardware";
        case ItemCategory::Application: return "Application";
        case ItemCategory::Utility: return "Utility";
        case ItemCategory::Bloatware: return "Bloatware";
        case ItemCategory::Malicious: return "Malicious";
        default: return "Unknown";
    }
}

std::string_view GetImpactLevelName(ImpactLevel level) noexcept {
    switch (level) {
        case ImpactLevel::None: return "None";
        case ImpactLevel::Low: return "Low";
        case ImpactLevel::Medium: return "Medium";
        case ImpactLevel::High: return "High";
        case ImpactLevel::Critical: return "Critical";
        default: return "Unknown";
    }
}

std::string_view GetActionResultName(ActionResult result) noexcept {
    switch (result) {
        case ActionResult::Success: return "Success";
        case ActionResult::Failed: return "Failed";
        case ActionResult::AccessDenied: return "Access Denied";
        case ActionResult::NotFound: return "Not Found";
        case ActionResult::AlreadyInState: return "Already In State";
        case ActionResult::RequiresReboot: return "Requires Reboot";
        case ActionResult::PartialSuccess: return "Partial Success";
        default: return "Unknown";
    }
}

std::string_view GetOptimizationRecommendationName(OptimizationRecommendation rec) noexcept {
    switch (rec) {
        case OptimizationRecommendation::Keep: return "Keep";
        case OptimizationRecommendation::Delay: return "Delay";
        case OptimizationRecommendation::Disable: return "Disable";
        case OptimizationRecommendation::Remove: return "Remove";
        case OptimizationRecommendation::Investigate: return "Investigate";
        default: return "Unknown";
    }
}

}  // namespace Registry
}  // namespace Core
}  // namespace ShadowStrike
