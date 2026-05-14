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
 * ShadowStrike Ransomware Protection - HONEYPOT MANAGER IMPLEMENTATION
 * ============================================================================
 *
 * @file HoneyPotManager.cpp
 * @brief Implementation of enterprise-grade decoy file management system
 *
 * Implements the PIMPL class for HoneypotManager, handling:
 * - Strategic deployment of decoy files with APT-resistant naming
 * - Cryptographically secure random content generation
 * - Kernel minifilter integration for instant detection
 * - Process whitelisting and false-positive prevention
 * - Atomic file creation and integrity monitoring
 *
 * @author ShadowStrike Security Team
 * @version 3.1.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "HoneypotManager.hpp"

#include <algorithm>
#include <random>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <thread>

// Third-party libraries
#include <nlohmann/json.hpp>

// ShadowStrike infrastructure
#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/SystemUtils.hpp"

// Cross-module wiring
#include "../Communication/AlertSystem.hpp"
#include "../Communication/TelemetryCollector.hpp"
#include "../Communication/IPCManager.hpp"

// Windows headers
#ifdef _WIN32
#include <shlobj.h>
#include <knownfolders.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

namespace ShadowStrike {
namespace Ransomware {

// Pull Utils into scope for readability
using namespace ShadowStrike::Utils;
namespace fs = std::filesystem;

static constexpr const wchar_t* kLogCategory = L"Honeypot";

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

namespace {

    /**
     * @brief Generate cryptographically secure random bytes via BCryptGenRandom.
     */
    [[nodiscard]] bool CryptoRandomBytes(uint8_t* buffer, size_t size) noexcept {
        if (!buffer || size == 0) return false;
#ifdef _WIN32
        NTSTATUS status = BCryptGenRandom(
            nullptr, buffer, static_cast<ULONG>(size),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        return BCRYPT_SUCCESS(status);
#else
        return false;
#endif
    }

    [[nodiscard]] std::vector<uint8_t> GenerateRandomBytes(size_t size) {
        if (size == 0 || size > HoneypotConstants::MAX_HONEYPOT_SIZE) return {};
        std::vector<uint8_t> buffer(size);
        if (!CryptoRandomBytes(buffer.data(), size)) {
            SS_LOG_ERROR(kLogCategory, L"BCryptGenRandom failed for %zu bytes", size);
            buffer.clear();
        }
        return buffer;
    }

    /**
     * @brief Get standard location path via SHGetKnownFolderPath.
     */
    [[nodiscard]] std::wstring GetLocationPath(LocationType type) {
#ifdef _WIN32
        PWSTR path = nullptr;
        HRESULT hr = E_FAIL;

        switch (type) {
            case LocationType::UserDocuments:
                hr = SHGetKnownFolderPath(FOLDERID_Documents, 0, nullptr, &path);
                break;
            case LocationType::UserDesktop:
                hr = SHGetKnownFolderPath(FOLDERID_Desktop, 0, nullptr, &path);
                break;
            case LocationType::UserPictures:
                hr = SHGetKnownFolderPath(FOLDERID_Pictures, 0, nullptr, &path);
                break;
            case LocationType::UserDownloads:
                hr = SHGetKnownFolderPath(FOLDERID_Downloads, 0, nullptr, &path);
                break;
            case LocationType::RootDrive: {
                wchar_t sysPath[MAX_PATH]{};
                if (GetSystemDirectoryW(sysPath, MAX_PATH)) {
                    return std::wstring(sysPath).substr(0, 3);
                }
                return L"C:\\";
            }
            default:
                break;
        }

        if (SUCCEEDED(hr) && path) {
            std::wstring result(path);
            CoTaskMemFree(path);
            return result;
        }
        if (path) CoTaskMemFree(path);
#endif
        return L"";
    }

    /**
     * @brief Generate a unique hex ID from CSPRNG.
     */
    [[nodiscard]] std::string GenerateId() {
        uint8_t raw[16]{};
        if (!CryptoRandomBytes(raw, sizeof(raw))) {
            std::random_device rd;
            std::mt19937_64 gen(rd());
            std::uniform_int_distribution<uint64_t> dis;
            auto v1 = dis(gen), v2 = dis(gen);
            std::memcpy(raw, &v1, 8);
            std::memcpy(raw + 8, &v2, 8);
        }
        return HashUtils::ToHexLower(raw, sizeof(raw));
    }

    /**
     * @brief Pick a random index in [0, upperBound) using CSPRNG.
     */
    [[nodiscard]] size_t SecureRandomIndex(size_t upperBound) {
        if (upperBound <= 1) return 0;
        uint64_t raw = 0;
        CryptoRandomBytes(reinterpret_cast<uint8_t*>(&raw), sizeof(raw));
        return static_cast<size_t>(raw % upperBound);
    }

} // anonymous namespace

// ============================================================================
// HONEYPOT MANAGER IMPLEMENTATION (PIMPL)
// ============================================================================

class HoneypotManagerImpl {
public:
    HoneypotManagerImpl();
    ~HoneypotManagerImpl();

    // Lifecycle
    bool Initialize(const HoneypotManagerConfiguration& config);
    void Shutdown();
    bool IsInitialized() const noexcept { return m_initialized.load(std::memory_order_acquire); }
    ModuleStatus GetStatus() const noexcept { return m_status.load(std::memory_order_acquire); }

    // Deployment
    bool DeployTraps();
    bool DeployToLocation(const DeploymentLocation& location);
    std::optional<std::string> DeployHoneypot(std::wstring_view directory, const HoneypotTemplate& tmpl);
    void RemoveTraps();
    void RemoveHoneypot(const std::string& honeypotId);
    void RemoveHoneypotByPath(std::wstring_view path);

    // Detection
    bool IsTrap(const std::wstring& filePath) const;
    std::optional<HoneyFile> GetHoneypot(std::wstring_view path) const;
    std::optional<HoneyFile> GetHoneypotById(const std::string& honeypotId) const;
    std::vector<HoneyFile> GetActiveHoneypots() const;
    std::vector<HoneyFile> GetHoneypotsInDirectory(std::wstring_view directory) const;

    // Regeneration & Health
    void RegenerateTrap(const std::wstring& filePath);
    void RegenerateAllMissing();
    bool VerifyHoneypot(const std::string& honeypotId);
    std::vector<std::string> VerifyAllHoneypots();
    void RunHealthCheck();

    // Access Handling
    void OnHoneypotAccessed(std::wstring_view path, uint32_t pid, HoneypotAccessType accessType);
    bool ProcessKernelNotification(std::wstring_view path, uint32_t pid,
                                   uint32_t threadId, HoneypotAccessType accessType);
    bool IsProcessWhitelisted(uint32_t pid) const;
    void ReportFalsePositive(uint64_t eventId, const std::string& reason);
    std::vector<HoneypotAccessEvent> GetRecentAccessEvents(size_t maxCount) const;

    // Callbacks
    void SetAccessCallback(HoneypotAccessCallback callback);
    void SetStatusCallback(HoneypotStatusCallback callback);

    // Statistics & Templates
    HoneypotStatisticsSnapshot GetStatisticsSnapshot() const;
    void ResetStatistics();
    size_t GetHoneypotCount() const noexcept;
    size_t GetActiveHoneypotCount() const noexcept;

    void AddTemplate(const HoneypotTemplate& tmpl);
    void RemoveTemplate(const std::string& templateName);
    std::vector<HoneypotTemplate> GetTemplates() const;

    // Utility
    void CreateDecoyFile(std::wstring_view path, HoneypotFileType type);
    bool SelfTest();

private:
    void CreateHoneypotFile(const HoneypotTemplate& tmpl, const std::wstring& path);
    void NotifyAccess(const HoneypotAccessEvent& event);
    void NotifyStatus(const HoneyFile& file, HoneypotStatus status);
    void HandleDetectedAccess(std::wstring_view path, uint32_t pid,
                              HoneypotAccessType accessType);
    void ApplyFileAttributes(const std::wstring& path) const;
    void RandomizeTimestamps(const std::wstring& path) const;

    mutable std::shared_mutex m_mutex;
    std::atomic<bool> m_initialized{false};
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    HoneypotManagerConfiguration m_config;

    std::unordered_map<std::string, HoneyFile> m_honeypots;
    std::unordered_map<std::wstring, std::string> m_pathIndex;
    std::vector<HoneypotTemplate> m_templates;

    mutable std::mutex m_eventMutex;
    std::deque<HoneypotAccessEvent> m_recentEvents;
    std::atomic<uint64_t> m_eventCounter{1};

    mutable std::mutex m_callbackMutex;
    HoneypotAccessCallback m_accessCallback;
    HoneypotStatusCallback m_statusCallback;

    mutable HoneypotStatistics m_stats;
};

// ============================================================================
// IMPLEMENTATION DETAILS
// ============================================================================

HoneypotManagerImpl::HoneypotManagerImpl() {
    SS_LOG_INFO(kLogCategory, L"Instance created");
}

HoneypotManagerImpl::~HoneypotManagerImpl() {
    Shutdown();
    SS_LOG_INFO(kLogCategory, L"Instance destroyed");
}

bool HoneypotManagerImpl::Initialize(const HoneypotManagerConfiguration& config) {
    std::unique_lock lock(m_mutex);

    if (m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(kLogCategory, L"Already initialized");
        return true;
    }

    try {
        m_status.store(ModuleStatus::Initializing, std::memory_order_release);

        if (!config.IsValid()) {
            SS_LOG_ERROR(kLogCategory, L"Invalid configuration supplied");
            m_status.store(ModuleStatus::Error, std::memory_order_release);
            return false;
        }

        m_config = config;

        if (m_config.templates.empty()) {
            m_config.LoadDefaultTemplates();
            m_templates = m_config.templates;
        } else {
            m_templates = m_config.templates;
        }

        if (m_config.locations.empty()) {
            m_config.LoadDefaultLocations();
        }

        m_stats.Reset();

        m_initialized.store(true, std::memory_order_release);
        m_status.store(ModuleStatus::Running, std::memory_order_release);

        SS_LOG_INFO(kLogCategory, L"Initialized with %zu templates, %zu locations",
                    m_templates.size(), m_config.locations.size());

        if (m_config.autoDeployOnStartup) {
            lock.unlock();
            DeployTraps();
        }

        return true;
    } catch (const std::exception& e) {
        SS_LOG_FATAL(kLogCategory, L"Initialization failed: %hs", e.what());
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    }
}

void HoneypotManagerImpl::Shutdown() {
    std::unique_lock lock(m_mutex);

    if (!m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    m_status.store(ModuleStatus::Stopping, std::memory_order_release);

    m_honeypots.clear();
    m_pathIndex.clear();
    m_templates.clear();

    m_initialized.store(false, std::memory_order_release);
    m_status.store(ModuleStatus::Stopped, std::memory_order_release);

    SS_LOG_INFO(kLogCategory, L"Shutdown complete");
}

bool HoneypotManagerImpl::DeployTraps() {
    if (!m_initialized.load(std::memory_order_acquire)) return false;

    std::vector<DeploymentLocation> locations;
    {
        std::shared_lock lock(m_mutex);
        locations = m_config.locations;
    }

    std::sort(locations.begin(), locations.end(),
        [](const DeploymentLocation& a, const DeploymentLocation& b) {
            return a.priority > b.priority;
        });

    size_t deployedCount = 0;
    for (const auto& loc : locations) {
        if (loc.isEnabled) {
            if (DeployToLocation(loc)) {
                deployedCount++;
            }
        }
    }

    SS_LOG_INFO(kLogCategory, L"Deployment cycle complete: %zu locations seeded", deployedCount);
    return true;
}

bool HoneypotManagerImpl::DeployToLocation(const DeploymentLocation& location) {
    std::wstring basePath;
    if (location.path.empty()) {
        basePath = GetLocationPath(location.type);
    } else {
        basePath = location.path;
    }

    if (basePath.empty()) {
        SS_LOG_WARN(kLogCategory, L"Empty location path for type %d",
                    static_cast<int>(location.type));
        return false;
    }

    std::error_code fsec;
    if (!fs::exists(basePath, fsec)) {
        SS_LOG_WARN(kLogCategory, L"Location path does not exist: %ls", basePath.c_str());
        return false;
    }

    const size_t trapsToDeploy = location.maxHoneypots;
    std::vector<HoneypotTemplate> availableTemplates = GetTemplates();
    if (availableTemplates.empty()) return false;

    size_t successCount = 0;
    for (size_t i = 0; i < trapsToDeploy; ++i) {
        if (GetHoneypotCount() >= m_config.maxTotalHoneypots) {
            SS_LOG_INFO(kLogCategory, L"Global honeypot limit (%zu) reached",
                        m_config.maxTotalHoneypots);
            break;
        }

        const auto& tmpl = availableTemplates[SecureRandomIndex(availableTemplates.size())];
        if (DeployHoneypot(basePath, tmpl)) {
            successCount++;
        }
    }

    return successCount > 0;
}

std::optional<std::string> HoneypotManagerImpl::DeployHoneypot(
    std::wstring_view directory,
    const HoneypotTemplate& tmpl) {

    try {
        std::wstring filename = GenerateHoneypotFilename(tmpl.fileType);

        if (!tmpl.filenamePatterns.empty()) {
            filename = tmpl.filenamePatterns[SecureRandomIndex(tmpl.filenamePatterns.size())];
            if (!tmpl.extension.empty() &&
                filename.find(tmpl.extension) == std::wstring::npos) {
                filename += tmpl.extension;
            }
        }

        fs::path fullPath = fs::path(directory) / filename;

        // Collision avoidance with CSPRNG suffix
        if (fs::exists(fullPath)) {
            uint32_t suffix = 0;
            CryptoRandomBytes(reinterpret_cast<uint8_t*>(&suffix), sizeof(suffix));
            suffix %= 10000u;
            std::wstring stem = fullPath.stem().wstring();
            std::wstring ext  = fullPath.extension().wstring();
            fullPath = fs::path(directory) / (stem + L"_" + std::to_wstring(suffix) + ext);
        }

        // Validate path doesn't escape target directory (use security-hardened API)
        FileUtils::Error pathErr;
        if (!FileUtils::IsPathUnderRoot(fullPath.wstring(), directory, true, &pathErr)) {
            SS_LOG_ERROR(kLogCategory, L"Path traversal blocked: %ls", fullPath.c_str());
            return std::nullopt;
        }

        // Create the honeypot file
        CreateHoneypotFile(tmpl, fullPath.wstring());

        // Build honeypot record
        HoneyFile honeyFile;
        honeyFile.honeypotId    = GenerateId();
        honeyFile.path          = fullPath.wstring();
        honeyFile.originalName  = filename;
        honeyFile.type          = HoneypotType::File;
        honeyFile.fileType      = tmpl.fileType;
        honeyFile.status        = HoneypotStatus::Active;
        honeyFile.creationTime  = std::chrono::system_clock::now();
        honeyFile.lastVerified  = Clock::now();
        honeyFile.isHidden      = m_config.hideFiles;
        honeyFile.isSystem      = m_config.makeSystemFiles;
        honeyFile.autoRegenerate = m_config.autoRegenerate;

        std::error_code ec;
        honeyFile.fileSize = fs::file_size(fullPath, ec);
        if (ec) honeyFile.fileSize = 0;

        // Integrity hash
        FileUtils::Error hashErr;
        if (!FileUtils::ComputeFileSHA256(fullPath.wstring(), honeyFile.contentHash, &hashErr)) {
            SS_LOG_WARN(kLogCategory, L"Hash failed for %ls", fullPath.c_str());
        }

        // Stealth: randomize timestamps and set attributes
        ApplyFileAttributes(fullPath.wstring());
        RandomizeTimestamps(fullPath.wstring());

        // Register under lock
        {
            std::unique_lock lock(m_mutex);
            std::wstring lowerPath = StringUtils::ToLowerCopy(honeyFile.path);
            m_pathIndex[lowerPath] = honeyFile.honeypotId;
            m_honeypots[honeyFile.honeypotId] = honeyFile;
        }

        m_stats.totalDeployed.fetch_add(1, std::memory_order_relaxed);
        m_stats.currentlyActive.fetch_add(1, std::memory_order_relaxed);

        SS_LOG_DEBUG(kLogCategory, L"Deployed trap: %ls", fullPath.c_str());
        return honeyFile.honeypotId;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(kLogCategory, L"Deployment failed: %hs", e.what());
        return std::nullopt;
    }
}

void HoneypotManagerImpl::ApplyFileAttributes(const std::wstring& path) const {
#ifdef _WIN32
    if (!m_config.hideFiles && !m_config.makeSystemFiles) return;
    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return;
    if (m_config.hideFiles)       attrs |= FILE_ATTRIBUTE_HIDDEN;
    if (m_config.makeSystemFiles) attrs |= FILE_ATTRIBUTE_SYSTEM;
    SetFileAttributesW(path.c_str(), attrs);
#endif
}

void HoneypotManagerImpl::RandomizeTimestamps(const std::wstring& path) const {
#ifdef _WIN32
    HANDLE hFile = CreateFileW(path.c_str(), FILE_WRITE_ATTRIBUTES,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING,
                               FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        SS_LOG_DEBUG(kLogCategory, L"Cannot open %ls for timestamp randomization", path.c_str());
        return;
    }

    // Offset creation time 30-180 days into the past
    uint32_t daysBack = 0;
    CryptoRandomBytes(reinterpret_cast<uint8_t*>(&daysBack), sizeof(daysBack));
    daysBack = 30 + (daysBack % 151);

    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart  = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    uli.QuadPart -= static_cast<uint64_t>(daysBack) * 864000000000ULL;
    ft.dwLowDateTime  = uli.LowPart;
    ft.dwHighDateTime = uli.HighPart;

    // Last-write 2 hours to 30 days in the past
    FILETIME ftWrite{};
    GetSystemTimeAsFileTime(&ftWrite);
    ULARGE_INTEGER uliW;
    uliW.LowPart  = ftWrite.dwLowDateTime;
    uliW.HighPart = ftWrite.dwHighDateTime;
    uint32_t hoursBack = 0;
    CryptoRandomBytes(reinterpret_cast<uint8_t*>(&hoursBack), sizeof(hoursBack));
    hoursBack = 2 + (hoursBack % 720);
    uliW.QuadPart -= static_cast<uint64_t>(hoursBack) * 36000000000ULL;
    ftWrite.dwLowDateTime  = uliW.LowPart;
    ftWrite.dwHighDateTime = uliW.HighPart;

    if (!SetFileTime(hFile, &ft, nullptr, &ftWrite)) {
        SS_LOG_DEBUG(kLogCategory, L"SetFileTime failed on %ls", path.c_str());
    }
    CloseHandle(hFile);
#endif
}

void HoneypotManagerImpl::RemoveTraps() {
    std::unique_lock lock(m_mutex);

    for (const auto& [id, file] : m_honeypots) {
        try {
#ifdef _WIN32
            DWORD attrs = GetFileAttributesW(file.path.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES) {
                attrs &= ~(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
                SetFileAttributesW(file.path.c_str(), attrs);
            }
#endif
            std::error_code ec;
            fs::remove(file.path, ec);
            if (ec) {
                SS_LOG_WARN(kLogCategory, L"Failed to remove trap %ls: %hs",
                            file.path.c_str(), ec.message().c_str());
            }
        } catch (const std::exception& e) {
            SS_LOG_WARN(kLogCategory, L"Exception removing trap %ls: %hs",
                        file.path.c_str(), e.what());
        }
    }

    m_honeypots.clear();
    m_pathIndex.clear();
    m_stats.currentlyActive.store(0, std::memory_order_relaxed);
    SS_LOG_INFO(kLogCategory, L"All traps removed");
}

void HoneypotManagerImpl::RemoveHoneypot(const std::string& honeypotId) {
    std::unique_lock lock(m_mutex);

    auto it = m_honeypots.find(honeypotId);
    if (it == m_honeypots.end()) return;

    const auto& filePath = it->second.path;
    try {
#ifdef _WIN32
        DWORD attrs = GetFileAttributesW(filePath.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES) {
            attrs &= ~(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
            SetFileAttributesW(filePath.c_str(), attrs);
        }
#endif
        std::error_code ec;
        fs::remove(filePath, ec);
    } catch (...) {}

    m_pathIndex.erase(StringUtils::ToLowerCopy(filePath));
    m_honeypots.erase(it);
    if (m_stats.currentlyActive.load(std::memory_order_relaxed) > 0)
        m_stats.currentlyActive.fetch_sub(1, std::memory_order_relaxed);
}

void HoneypotManagerImpl::RemoveHoneypotByPath(std::wstring_view path) {
    std::wstring lowerPath = StringUtils::ToLowerCopy(std::wstring(path));
    std::string id;
    {
        std::shared_lock lock(m_mutex);
        auto it = m_pathIndex.find(lowerPath);
        if (it != m_pathIndex.end()) {
            id = it->second;
        }
    }
    if (!id.empty()) {
        RemoveHoneypot(id);
    }
}

bool HoneypotManagerImpl::IsTrap(const std::wstring& filePath) const {
    if (filePath.empty()) return false;
    std::shared_lock lock(m_mutex);
    return m_pathIndex.contains(StringUtils::ToLowerCopy(filePath));
}

std::optional<HoneyFile> HoneypotManagerImpl::GetHoneypot(std::wstring_view path) const {
    std::shared_lock lock(m_mutex);
    auto it = m_pathIndex.find(StringUtils::ToLowerCopy(std::wstring(path)));
    if (it != m_pathIndex.end()) {
        auto fileIt = m_honeypots.find(it->second);
        if (fileIt != m_honeypots.end()) {
            return fileIt->second;
        }
    }
    return std::nullopt;
}

std::optional<HoneyFile> HoneypotManagerImpl::GetHoneypotById(const std::string& honeypotId) const {
    std::shared_lock lock(m_mutex);
    auto it = m_honeypots.find(honeypotId);
    if (it != m_honeypots.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<HoneyFile> HoneypotManagerImpl::GetActiveHoneypots() const {
    std::shared_lock lock(m_mutex);
    std::vector<HoneyFile> result;
    result.reserve(m_honeypots.size());
    for (const auto& [id, file] : m_honeypots) {
        if (file.status == HoneypotStatus::Active) {
            result.push_back(file);
        }
    }
    return result;
}

std::vector<HoneyFile> HoneypotManagerImpl::GetHoneypotsInDirectory(std::wstring_view directory) const {
    std::shared_lock lock(m_mutex);
    std::vector<HoneyFile> result;
    std::wstring dirLower = StringUtils::ToLowerCopy(std::wstring(directory));

    if (!dirLower.empty() && dirLower.back() != L'\\' && dirLower.back() != L'/') {
        dirLower += L'\\';
    }

    for (const auto& [lpath, id] : m_pathIndex) {
        if (lpath.starts_with(dirLower)) {
            auto it = m_honeypots.find(id);
            if (it != m_honeypots.end()) {
                result.push_back(it->second);
            }
        }
    }
    return result;
}

void HoneypotManagerImpl::RegenerateTrap(const std::wstring& filePath) {
    if (!m_config.autoRegenerate) return;

    auto honeypot = GetHoneypot(filePath);
    if (!honeypot || !honeypot->autoRegenerate) return;

    HoneypotTemplate tmpl = GetDefaultTemplate(honeypot->fileType);

    try {
        CreateHoneypotFile(tmpl, honeypot->path);
        ApplyFileAttributes(honeypot->path);
        RandomizeTimestamps(honeypot->path);

        {
            std::unique_lock lock(m_mutex);
            auto it = m_honeypots.find(honeypot->honeypotId);
            if (it != m_honeypots.end()) {
                it->second.status = HoneypotStatus::Active;
                it->second.lastVerified = Clock::now();
                FileUtils::Error err;
                FileUtils::ComputeFileSHA256(it->second.path, it->second.contentHash, &err);
            }
        }

        m_stats.regenerations.fetch_add(1, std::memory_order_relaxed);
        SS_LOG_INFO(kLogCategory, L"Regenerated trap: %ls", honeypot->path.c_str());

    } catch (const std::exception& e) {
        SS_LOG_ERROR(kLogCategory, L"Regeneration failed for %ls: %hs",
                     honeypot->path.c_str(), e.what());
    }
}

void HoneypotManagerImpl::RegenerateAllMissing() {
    std::vector<std::wstring> missingPaths;
    {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, file] : m_honeypots) {
            std::error_code ec;
            if (!fs::exists(file.path, ec) && file.autoRegenerate) {
                missingPaths.push_back(file.path);
            }
        }
    }
    for (const auto& p : missingPaths) {
        RegenerateTrap(p);
    }
}

bool HoneypotManagerImpl::VerifyHoneypot(const std::string& honeypotId) {
    std::unique_lock lock(m_mutex);
    auto it = m_honeypots.find(honeypotId);
    if (it == m_honeypots.end()) return false;

    HoneyFile& file = it->second;
    file.lastVerified = Clock::now();

    std::error_code ec;
    if (!fs::exists(file.path, ec)) {
        file.status = HoneypotStatus::Missing;
        SS_LOG_WARN(kLogCategory, L"Trap missing: %ls", file.path.c_str());
        return false;
    }

    try {
        Hash256 currentHash{};
        FileUtils::Error hashErr;
        if (!FileUtils::ComputeFileSHA256(file.path, currentHash, &hashErr)) {
            file.status = HoneypotStatus::Error;
            return false;
        }

        if (currentHash != file.contentHash) {
            file.status = HoneypotStatus::Modified;
            SS_LOG_WARN(kLogCategory, L"Integrity failure on trap: %ls", file.path.c_str());
            return false;
        }

        file.status = HoneypotStatus::Active;
        return true;
    } catch (...) {
        file.status = HoneypotStatus::Error;
        return false;
    }
}

std::vector<std::string> HoneypotManagerImpl::VerifyAllHoneypots() {
    std::vector<std::string> failedIds;
    std::vector<std::string> allIds;
    {
        std::shared_lock lock(m_mutex);
        allIds.reserve(m_honeypots.size());
        for (const auto& [id, _] : m_honeypots) {
            allIds.push_back(id);
        }
    }
    for (const auto& id : allIds) {
        if (!VerifyHoneypot(id)) {
            failedIds.push_back(id);
        }
    }
    return failedIds;
}

void HoneypotManagerImpl::RunHealthCheck() {
    auto failed = VerifyAllHoneypots();
    if (!failed.empty()) {
        SS_LOG_WARN(kLogCategory, L"Health check: %zu compromised traps", failed.size());
        if (m_config.autoRegenerate) {
            for (const auto& id : failed) {
                auto h = GetHoneypotById(id);
                if (h) RegenerateTrap(h->path);
            }
        }
    } else {
        SS_LOG_DEBUG(kLogCategory, L"Health check passed (%llu active)",
                     m_stats.currentlyActive.load(std::memory_order_relaxed));
    }
}

// ============================================================================
// ACCESS HANDLING — CRITICAL DETECTION HOT-PATH
// ============================================================================

bool HoneypotManagerImpl::IsProcessWhitelisted(uint32_t pid) const {
    if (pid == 0 || pid == 4) return true;  // System/Idle
    if (pid == GetCurrentProcessId()) return true;  // Self

    // Check configured whitelists
    std::optional<std::wstring> procName;
    std::optional<std::wstring> procPath;
    {
        ProcessUtils::Error err;
        procName = ProcessUtils::GetProcessName(static_cast<ProcessUtils::ProcessId>(pid), &err);
        procPath = ProcessUtils::GetProcessPath(static_cast<ProcessUtils::ProcessId>(pid), &err);
    }

    std::shared_lock lock(m_mutex);

    if (procName) {
        for (const auto& wl : m_config.whitelistedProcessNames) {
            if (StringUtils::IEquals(*procName, wl)) return true;
        }
    }

    if (procPath) {
        for (const auto& wl : m_config.whitelistedProcessPaths) {
            if (StringUtils::IEquals(*procPath, wl)) return true;
        }
    }

    return false;
}

void HoneypotManagerImpl::HandleDetectedAccess(
    std::wstring_view path, uint32_t pid, HoneypotAccessType accessType) {

    m_stats.accessEvents.fetch_add(1, std::memory_order_relaxed);
    if (static_cast<size_t>(accessType) < m_stats.eventsByType.size()) {
        m_stats.eventsByType[static_cast<size_t>(accessType)].fetch_add(1, std::memory_order_relaxed);
    }

    // Build access event
    HoneypotAccessEvent event;
    event.eventId   = m_eventCounter.fetch_add(1, std::memory_order_relaxed);
    event.timestamp = std::chrono::system_clock::now();
    event.honeypotPath = std::wstring(path);
    event.processId    = pid;
    event.accessType   = accessType;
    event.isSuspicious = true;

    // Gather process forensics
    {
        ProcessUtils::Error err;
        auto name = ProcessUtils::GetProcessName(static_cast<ProcessUtils::ProcessId>(pid), &err);
        if (name) event.processName = *name;

        auto ppath = ProcessUtils::GetProcessPath(static_cast<ProcessUtils::ProcessId>(pid), &err);
        if (ppath) event.processPath = *ppath;

        auto cmdline = ProcessUtils::GetProcessCommandLine(static_cast<ProcessUtils::ProcessId>(pid), &err);
        if (cmdline) event.commandLine = *cmdline;

        auto ppid = ProcessUtils::GetParentProcessId(static_cast<ProcessUtils::ProcessId>(pid), &err);
        if (ppid) event.parentPid = static_cast<uint32_t>(*ppid);
    }

    // Resolve honeypot ID and mark compromised (single lock acquisition)
    {
        std::unique_lock lock(m_mutex);
        auto pathIt = m_pathIndex.find(StringUtils::ToLowerCopy(std::wstring(path)));
        if (pathIt != m_pathIndex.end()) {
            event.honeypotId = pathIt->second;
            auto fileIt = m_honeypots.find(pathIt->second);
            if (fileIt != m_honeypots.end()) {
                fileIt->second.status = HoneypotStatus::Compromised;
            }
        }
    }

    // Determine response action
    bool shouldKill = m_config.killOnAccess &&
                      (accessType == HoneypotAccessType::Write ||
                       accessType == HoneypotAccessType::Delete ||
                       accessType == HoneypotAccessType::Rename);

    if (shouldKill && pid > 4) {
        SS_LOG_FATAL(kLogCategory,
            L"RANSOMWARE DETECTED! PID %u (%ls) touched trap %ls [%ls]",
            pid, event.processName.c_str(), event.honeypotPath.c_str(),
            StringUtils::ToWide(std::string(GetAccessTypeName(accessType))).c_str());

        ProcessUtils::Error killErr;
        if (ProcessUtils::TerminateProcess(static_cast<ProcessUtils::ProcessId>(pid), 1, &killErr)) {
            event.actionTaken = "Process Terminated";
            m_stats.processesKilled.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_INFO(kLogCategory, L"Terminated malicious process %u", pid);
        } else {
            event.actionTaken = "Termination Failed";
            SS_LOG_ERROR(kLogCategory, L"Failed to terminate PID %u", pid);
        }
    } else if (accessType == HoneypotAccessType::Read) {
        SS_LOG_WARN(kLogCategory, L"READ alert: PID %u (%ls) read trap %ls",
                    pid, event.processName.c_str(), event.honeypotPath.c_str());
        event.actionTaken = "Alert Only";
    } else {
        SS_LOG_WARN(kLogCategory, L"Access alert: PID %u (%ls) accessed trap %ls",
                    pid, event.processName.c_str(), event.honeypotPath.c_str());
        event.actionTaken = "Alert Only";
    }

    // === Cross-module wiring: AlertSystem + TelemetryCollector ===
    {
        using namespace Communication;
        if (AlertSystem::HasInstance()) {
            auto severity = shouldKill
                ? AlertSeverity::Critical
                : AlertSeverity::High;
            std::string subject = "Honeypot access by PID " + std::to_string(pid);
            std::string details = "Trap: " + StringUtils::ToNarrow(event.honeypotPath) +
                " | Process: " + StringUtils::ToNarrow(event.processName) +
                " | Action: " + event.actionTaken;
            // RaiseAlert(severity, type, subject, details, source).  The
            // previous call was shifted by one — the literal
            // "HoneypotManager" was being recorded as the alert subject,
            // the real subject as details, and the real details as the
            // source field — corrupting every honeypot alert sent to
            // SIEM.
            (void)AlertSystem::Instance().RaiseAlert(
                severity, AlertType::ThreatDetection,
                subject, details, "HoneypotManager");
        }
        if (TelemetryCollector::HasInstance()) {
            TelemetryCollector::Instance().RecordCustom("honeypot_access", {
                {"pid", std::to_string(pid)},
                {"honeypotPath", StringUtils::ToNarrow(event.honeypotPath)},
                {"processName", StringUtils::ToNarrow(event.processName)},
                {"accessType", std::string(GetAccessTypeName(accessType))},
                {"actionTaken", event.actionTaken},
                {"honeypotId", event.honeypotId}
            });
        }
        // Kernel-level block for destructive access when local kill fails
        if (shouldKill && event.actionTaken == "Termination Failed") {
            if (IPCManager::HasInstance() && IPCManager::Instance().IsFilterPortConnected()) {
#pragma pack(push, 1)
                struct { uint32_t msgType = 0x30; uint32_t targetPid; wchar_t reason[256]{}; } req;
#pragma pack(pop)
                req.targetPid = pid;
                wcsncpy_s(req.reason, 256, L"HoneypotManager: trap file accessed", _TRUNCATE);
                (void)IPCManager::Instance().SendToKernel(&req, sizeof(req));
            }
        }
    }

    // Store event
    {
        std::lock_guard lock(m_eventMutex);
        m_recentEvents.push_back(std::move(event));
        while (m_recentEvents.size() > 1000) m_recentEvents.pop_front();
    }

    // Notify callback (copy event since we moved it)
    {
        std::lock_guard lock(m_eventMutex);
        if (!m_recentEvents.empty()) {
            NotifyAccess(m_recentEvents.back());
        }
    }
}

void HoneypotManagerImpl::OnHoneypotAccessed(
    std::wstring_view path, uint32_t pid, HoneypotAccessType accessType) {

    if (!IsTrap(std::wstring(path))) return;
    if (IsProcessWhitelisted(pid)) return;

    HandleDetectedAccess(path, pid, accessType);
}

bool HoneypotManagerImpl::ProcessKernelNotification(
    std::wstring_view path, uint32_t pid, uint32_t threadId,
    HoneypotAccessType accessType) {

    // Kernel minifilter sends pre-operation notifications here.
    // Return true = BLOCK the operation at kernel level.
    if (!IsTrap(std::wstring(path))) return false;
    if (IsProcessWhitelisted(pid)) return false;

    SS_LOG_INFO(kLogCategory,
        L"Kernel notification: PID %u TID %u type %d on %ls",
        pid, threadId, static_cast<int>(accessType), std::wstring(path).c_str());

    HandleDetectedAccess(path, pid, accessType);

    // Write/Delete/Rename/SetInfo on a honeypot = BLOCK immediately
    if (accessType != HoneypotAccessType::Read &&
        accessType != HoneypotAccessType::Enumerate) {
        return true;  // Instruct minifilter to deny the IRP
    }

    // Reads generate an alert but are allowed (to let the ransomware
    // reveal itself before it attempts the write)
    return false;
}

void HoneypotManagerImpl::ReportFalsePositive(uint64_t eventId, const std::string& reason) {
    std::lock_guard lock(m_eventMutex);
    for (auto& event : m_recentEvents) {
        if (event.eventId == eventId) {
            if (!event.isSuspicious) {
                if (!reason.empty()) {
                    event.details = StringUtils::ToWide("False Positive: " + reason);
                }
                break;
            }
            event.isSuspicious = false;
            event.details = StringUtils::ToWide("False Positive: " + reason);
            m_stats.falsePositives.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_INFO(kLogCategory, L"Event %llu marked as false positive", eventId);
            break;
        }
    }
}

std::vector<HoneypotAccessEvent> HoneypotManagerImpl::GetRecentAccessEvents(size_t maxCount) const {
    std::lock_guard lock(m_eventMutex);
    std::vector<HoneypotAccessEvent> result;
    size_t count = std::min(maxCount, m_recentEvents.size());
    result.reserve(count);
    for (auto it = m_recentEvents.rbegin();
         it != m_recentEvents.rend() && result.size() < count; ++it) {
        result.push_back(*it);
    }
    return result;
}

void HoneypotManagerImpl::SetAccessCallback(HoneypotAccessCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    m_accessCallback = std::move(callback);
}

void HoneypotManagerImpl::SetStatusCallback(HoneypotStatusCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    m_statusCallback = std::move(callback);
}

HoneypotStatisticsSnapshot HoneypotManagerImpl::GetStatisticsSnapshot() const {
    HoneypotStatisticsSnapshot snap;
    snap.totalDeployed   = m_stats.totalDeployed.load(std::memory_order_relaxed);
    snap.currentlyActive = m_stats.currentlyActive.load(std::memory_order_relaxed);
    snap.accessEvents    = m_stats.accessEvents.load(std::memory_order_relaxed);
    snap.processesKilled = m_stats.processesKilled.load(std::memory_order_relaxed);
    snap.regenerations   = m_stats.regenerations.load(std::memory_order_relaxed);
    snap.falsePositives  = m_stats.falsePositives.load(std::memory_order_relaxed);
    for (size_t i = 0; i < snap.eventsByType.size(); ++i) {
        snap.eventsByType[i] = m_stats.eventsByType[i].load(std::memory_order_relaxed);
    }
    TimePoint st;
    {
        std::shared_lock lock(m_mutex);
        st = m_stats.startTime;
    }
    auto uptimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - st).count();
    snap.uptimeSeconds = static_cast<uint64_t>(uptimeMs > 0 ? uptimeMs / 1000 : 0);
    return snap;
}

void HoneypotManagerImpl::ResetStatistics() {
    m_stats.Reset();
}

size_t HoneypotManagerImpl::GetHoneypotCount() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_honeypots.size();
}

size_t HoneypotManagerImpl::GetActiveHoneypotCount() const noexcept {
    return m_stats.currentlyActive.load(std::memory_order_relaxed);
}

void HoneypotManagerImpl::AddTemplate(const HoneypotTemplate& tmpl) {
    std::unique_lock lock(m_mutex);
    m_templates.push_back(tmpl);
}

void HoneypotManagerImpl::RemoveTemplate(const std::string& templateName) {
    std::unique_lock lock(m_mutex);
    std::erase_if(m_templates,
        [&](const HoneypotTemplate& t) { return t.templateName == templateName; });
}

std::vector<HoneypotTemplate> HoneypotManagerImpl::GetTemplates() const {
    std::shared_lock lock(m_mutex);
    return m_templates;
}

void HoneypotManagerImpl::CreateDecoyFile(std::wstring_view path, HoneypotFileType type) {
    HoneypotTemplate tmpl = GetDefaultTemplate(type);
    CreateHoneypotFile(tmpl, std::wstring(path));
}

// ============================================================================
// FILE CREATION — APT-RESISTANT CONTENT GENERATION
// ============================================================================

void HoneypotManagerImpl::CreateHoneypotFile(
    const HoneypotTemplate& tmpl, const std::wstring& filePath) {

    // Determine target size
    size_t targetSize = tmpl.minSize;
    if (tmpl.maxSize > tmpl.minSize) {
        uint32_t r = 0;
        CryptoRandomBytes(reinterpret_cast<uint8_t*>(&r), sizeof(r));
        targetSize = tmpl.minSize + (r % (tmpl.maxSize - tmpl.minSize + 1));
    }
    targetSize = std::clamp(targetSize,
                            HoneypotConstants::MIN_HONEYPOT_SIZE,
                            HoneypotConstants::MAX_HONEYPOT_SIZE);

    // Build content buffer
    std::vector<uint8_t> content;
    content.reserve(targetSize);

    // 1. Write magic bytes (file header)
    if (!tmpl.magicBytes.empty()) {
        content.insert(content.end(), tmpl.magicBytes.begin(), tmpl.magicBytes.end());
    }

    // 2. Write explicit template content
    if (!tmpl.contentTemplate.empty()) {
        size_t space = targetSize - content.size();
        size_t toWrite = std::min(tmpl.contentTemplate.size(), space);
        content.insert(content.end(),
                       tmpl.contentTemplate.begin(),
                       tmpl.contentTemplate.begin() + toWrite);
    }

    // 3. Fill remaining with varied random chunks (each chunk uniquely generated)
    while (content.size() < targetSize) {
        size_t remaining = targetSize - content.size();
        size_t chunkSize = std::min<size_t>(4096, remaining);
        auto chunk = GenerateRandomBytes(chunkSize);
        if (chunk.empty()) {
            SS_LOG_ERROR(kLogCategory, L"Random generation failed during file creation");
            break;
        }
        content.insert(content.end(), chunk.begin(), chunk.end());
    }

    if (content.size() > targetSize) {
        content.resize(targetSize);
    }

    // Atomic write via FileUtils
    FileUtils::Error writeErr;
    if (!FileUtils::WriteAllBytesAtomic(
            filePath,
            reinterpret_cast<const std::byte*>(content.data()),
            content.size(), &writeErr)) {
        throw std::runtime_error(
            "Atomic write failed for: " + StringUtils::ToNarrow(filePath));
    }
}

void HoneypotManagerImpl::NotifyAccess(const HoneypotAccessEvent& event) {
    std::lock_guard lock(m_callbackMutex);
    if (m_accessCallback) {
        try {
            m_accessCallback(event);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(kLogCategory, L"Access callback threw: %hs", e.what());
        }
    }
}

void HoneypotManagerImpl::NotifyStatus(const HoneyFile& file, HoneypotStatus status) {
    std::lock_guard lock(m_callbackMutex);
    if (m_statusCallback) {
        try {
            m_statusCallback(file, status);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(kLogCategory, L"Status callback threw: %hs", e.what());
        }
    }
}

bool HoneypotManagerImpl::SelfTest() {
    SS_LOG_INFO(kLogCategory, L"Running self-test...");

    try {
        // Use agent's own data directory for test artifacts
        fs::path testDir = fs::temp_directory_path() / L"ShadowStrike_SelfTest";
        std::error_code ec;
        fs::create_directories(testDir, ec);
        if (ec) {
            SS_LOG_ERROR(kLogCategory, L"Cannot create self-test directory");
            return false;
        }

        fs::path testFile = testDir / L"selftest_honeypot.dat";

        HoneypotTemplate tmpl;
        tmpl.templateName = "SelfTest";
        tmpl.fileType = HoneypotFileType::Text;
        tmpl.minSize = 512;
        tmpl.maxSize = 1024;
        tmpl.randomizeContent = true;

        CreateHoneypotFile(tmpl, testFile.wstring());

        if (!fs::exists(testFile, ec)) {
            SS_LOG_ERROR(kLogCategory, L"Self-test failed: file not created");
            return false;
        }

        // Verify integrity round-trip
        Hash256 hash{};
        FileUtils::Error hashErr;
        if (!FileUtils::ComputeFileSHA256(testFile.wstring(), hash, &hashErr)) {
            SS_LOG_ERROR(kLogCategory, L"Self-test failed: hash computation");
            fs::remove(testFile, ec);
            fs::remove(testDir, ec);
            return false;
        }

        // Cleanup
        fs::remove(testFile, ec);
        fs::remove(testDir, ec);

        SS_LOG_INFO(kLogCategory, L"Self-test PASSED");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(kLogCategory, L"Self-test exception: %hs", e.what());
        return false;
    }
}

// ============================================================================
// SINGLETON & PUBLIC FORWARDING
// ============================================================================

std::atomic<bool> HoneypotManager::s_instanceCreated{false};

HoneypotManager& HoneypotManager::Instance() noexcept {
    static HoneypotManager instance;
    return instance;
}

bool HoneypotManager::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

HoneypotManager::HoneypotManager()
    : m_impl(std::make_unique<HoneypotManagerImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

HoneypotManager::~HoneypotManager() = default;

bool HoneypotManager::Initialize(const HoneypotManagerConfiguration& config) {
    return m_impl->Initialize(config);
}

void HoneypotManager::Shutdown() {
    m_impl->Shutdown();
}

bool HoneypotManager::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus HoneypotManager::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool HoneypotManager::DeployTraps() {
    return m_impl->DeployTraps();
}

bool HoneypotManager::DeployToLocation(const DeploymentLocation& location) {
    return m_impl->DeployToLocation(location);
}

std::optional<std::string> HoneypotManager::DeployHoneypot(
    std::wstring_view directory, const HoneypotTemplate& tmpl) {
    return m_impl->DeployHoneypot(directory, tmpl);
}

void HoneypotManager::RemoveTraps() {
    m_impl->RemoveTraps();
}

void HoneypotManager::RemoveHoneypot(const std::string& honeypotId) {
    m_impl->RemoveHoneypot(honeypotId);
}

void HoneypotManager::RemoveHoneypotByPath(std::wstring_view path) {
    m_impl->RemoveHoneypotByPath(path);
}

bool HoneypotManager::IsTrap(const std::wstring& filePath) const {
    return m_impl->IsTrap(filePath);
}

bool HoneypotManager::IsTrap(std::wstring_view filePath) const {
    return m_impl->IsTrap(std::wstring(filePath));
}

std::optional<HoneyFile> HoneypotManager::GetHoneypot(std::wstring_view path) const {
    return m_impl->GetHoneypot(path);
}

std::optional<HoneyFile> HoneypotManager::GetHoneypotById(const std::string& honeypotId) const {
    return m_impl->GetHoneypotById(honeypotId);
}

std::vector<HoneyFile> HoneypotManager::GetActiveHoneypots() const {
    return m_impl->GetActiveHoneypots();
}

std::vector<HoneyFile> HoneypotManager::GetHoneypotsInDirectory(std::wstring_view directory) const {
    return m_impl->GetHoneypotsInDirectory(directory);
}

void HoneypotManager::RegenerateTrap(const std::wstring& filePath) {
    m_impl->RegenerateTrap(filePath);
}

void HoneypotManager::RegenerateTrap(const std::string& honeypotId) {
    auto hp = m_impl->GetHoneypotById(honeypotId);
    if (hp) m_impl->RegenerateTrap(hp->path);
}

void HoneypotManager::RegenerateAllMissing() {
    m_impl->RegenerateAllMissing();
}

bool HoneypotManager::VerifyHoneypot(const std::string& honeypotId) {
    return m_impl->VerifyHoneypot(honeypotId);
}

std::vector<std::string> HoneypotManager::VerifyAllHoneypots() {
    return m_impl->VerifyAllHoneypots();
}

void HoneypotManager::RunHealthCheck() {
    m_impl->RunHealthCheck();
}

void HoneypotManager::OnHoneypotAccessed(
    std::wstring_view path, uint32_t pid, HoneypotAccessType accessType) {
    m_impl->OnHoneypotAccessed(path, pid, accessType);
}

bool HoneypotManager::ProcessKernelNotification(
    std::wstring_view path, uint32_t pid, uint32_t threadId,
    HoneypotAccessType accessType) {
    return m_impl->ProcessKernelNotification(path, pid, threadId, accessType);
}

bool HoneypotManager::IsProcessWhitelisted(uint32_t pid) const {
    return m_impl->IsProcessWhitelisted(pid);
}

void HoneypotManager::ReportFalsePositive(uint64_t eventId, const std::string& reason) {
    m_impl->ReportFalsePositive(eventId, reason);
}

std::vector<HoneypotAccessEvent> HoneypotManager::GetRecentAccessEvents(size_t maxCount) const {
    return m_impl->GetRecentAccessEvents(maxCount);
}

void HoneypotManager::SetAccessCallback(HoneypotAccessCallback callback) {
    m_impl->SetAccessCallback(std::move(callback));
}

void HoneypotManager::SetStatusCallback(HoneypotStatusCallback callback) {
    m_impl->SetStatusCallback(std::move(callback));
}

HoneypotStatisticsSnapshot HoneypotManager::GetStatistics() const {
    return m_impl->GetStatisticsSnapshot();
}

void HoneypotManager::ResetStatistics() {
    m_impl->ResetStatistics();
}

size_t HoneypotManager::GetHoneypotCount() const noexcept {
    return m_impl->GetHoneypotCount();
}

size_t HoneypotManager::GetActiveHoneypotCount() const noexcept {
    return m_impl->GetActiveHoneypotCount();
}

void HoneypotManager::AddTemplate(const HoneypotTemplate& tmpl) {
    m_impl->AddTemplate(tmpl);
}

void HoneypotManager::RemoveTemplate(const std::string& templateName) {
    m_impl->RemoveTemplate(templateName);
}

std::vector<HoneypotTemplate> HoneypotManager::GetTemplates() const {
    return m_impl->GetTemplates();
}

void HoneypotManager::CreateDecoyFile(std::wstring_view path, HoneypotFileType type) {
    m_impl->CreateDecoyFile(path, type);
}

bool HoneypotManager::SelfTest() {
    return m_impl->SelfTest();
}

std::string HoneypotManager::GetVersionString() noexcept {
    return std::to_string(HoneypotConstants::VERSION_MAJOR) + "." +
           std::to_string(HoneypotConstants::VERSION_MINOR) + "." +
           std::to_string(HoneypotConstants::VERSION_PATCH);
}

// ============================================================================
// UTILITY FUNCTIONS & SERIALIZATION
// ============================================================================

std::string_view GetHoneypotTypeName(HoneypotType type) noexcept {
    switch (type) {
        case HoneypotType::File: return "File";
        case HoneypotType::Directory: return "Directory";
        case HoneypotType::Shortcut: return "Shortcut";
        case HoneypotType::Stream: return "Stream";
        default: return "Unknown";
    }
}

std::string_view GetHoneypotFileTypeName(HoneypotFileType type) noexcept {
    switch (type) {
        case HoneypotFileType::Document: return "Document";
        case HoneypotFileType::Spreadsheet: return "Spreadsheet";
        case HoneypotFileType::PDF: return "PDF";
        case HoneypotFileType::Image: return "Image";
        case HoneypotFileType::Database: return "Database";
        case HoneypotFileType::Crypto: return "Crypto";
        case HoneypotFileType::Password: return "Password";
        default: return "Other";
    }
}

std::string_view GetLocationTypeName(LocationType type) noexcept {
    switch (type) {
        case LocationType::UserDocuments: return "UserDocuments";
        case LocationType::UserDesktop: return "UserDesktop";
        case LocationType::UserPictures: return "UserPictures";
        case LocationType::UserDownloads: return "UserDownloads";
        case LocationType::RootDrive: return "RootDrive";
        default: return "Custom";
    }
}

std::string_view GetAccessTypeName(HoneypotAccessType type) noexcept {
    switch (type) {
        case HoneypotAccessType::Read: return "Read";
        case HoneypotAccessType::Write: return "Write";
        case HoneypotAccessType::Delete: return "Delete";
        case HoneypotAccessType::Rename: return "Rename";
        case HoneypotAccessType::Enumerate: return "Enumerate";
        case HoneypotAccessType::SetInfo: return "SetInfo";
        default: return "Unknown";
    }
}

std::string_view GetHoneypotStatusName(HoneypotStatus status) noexcept {
    switch (status) {
        case HoneypotStatus::Active: return "Active";
        case HoneypotStatus::Inactive: return "Inactive";
        case HoneypotStatus::Missing: return "Missing";
        case HoneypotStatus::Modified: return "Modified";
        case HoneypotStatus::Compromised: return "Compromised";
        case HoneypotStatus::Disabled: return "Disabled";
        default: return "Unknown";
    }
}

HoneypotTemplate GetDefaultTemplate(HoneypotFileType type) {
    HoneypotTemplate tmpl;
    tmpl.fileType = type;
    tmpl.randomizeContent = true;
    tmpl.minSize = 2048;
    tmpl.maxSize = 65536;

    switch (type) {
        case HoneypotFileType::Document:
            tmpl.templateName = "Word Doc";
            tmpl.extension = L".docx";
            // PK ZIP header (Office Open XML)
            tmpl.magicBytes = {0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00};
            break;
        case HoneypotFileType::Spreadsheet:
            tmpl.templateName = "Excel Sheet";
            tmpl.extension = L".xlsx";
            tmpl.magicBytes = {0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00};
            break;
        case HoneypotFileType::Presentation:
            tmpl.templateName = "PowerPoint";
            tmpl.extension = L".pptx";
            tmpl.magicBytes = {0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00};
            break;
        case HoneypotFileType::PDF:
            tmpl.templateName = "PDF Document";
            tmpl.extension = L".pdf";
            // Full PDF header with version
            tmpl.magicBytes = {0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x37};
            break;
        case HoneypotFileType::Image:
            tmpl.templateName = "JPEG Image";
            tmpl.extension = L".jpg";
            // JFIF header
            tmpl.magicBytes = {0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46,
                               0x49, 0x46, 0x00, 0x01};
            break;
        case HoneypotFileType::Crypto:
            tmpl.templateName = "Wallet";
            tmpl.extension = L".dat";
            tmpl.minSize = 4096;
            tmpl.maxSize = 131072;
            break;
        case HoneypotFileType::Database:
            tmpl.templateName = "SQLite DB";
            tmpl.extension = L".db";
            // SQLite header
            tmpl.magicBytes = {0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66,
                               0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00};
            break;
        default:
            tmpl.templateName = "Text File";
            tmpl.extension = L".txt";
            break;
    }
    return tmpl;
}

std::wstring GenerateHoneypotFilename(HoneypotFileType type) {
    // Pick from realistic business document name stems
    const size_t idx = SecureRandomIndex(HoneypotConstants::DECOY_NAME_STEM_COUNT);
    std::wstring name = HoneypotConstants::DECOY_NAME_STEMS[idx];

    // Append type-appropriate extension
    switch (type) {
        case HoneypotFileType::Document:     name += L".docx"; break;
        case HoneypotFileType::Spreadsheet:  name += L".xlsx"; break;
        case HoneypotFileType::Presentation: name += L".pptx"; break;
        case HoneypotFileType::PDF:          name += L".pdf";  break;
        case HoneypotFileType::Image:        name += L".jpg";  break;
        case HoneypotFileType::Database:     name += L".db";   break;
        case HoneypotFileType::Archive:      name += L".zip";  break;
        default:                             name += L".txt";  break;
    }

    return name;
}

// ============================================================================
// SERIALIZATION
// ============================================================================

std::string HoneyFile::ToJson() const {
    nlohmann::json j;
    j["id"] = honeypotId;
    j["path"] = StringUtils::ToNarrow(path);
    j["status"] = static_cast<int>(status);
    j["fileType"] = static_cast<int>(fileType);
    j["fileSize"] = fileSize;
    j["isHidden"] = isHidden;
    j["autoRegenerate"] = autoRegenerate;
    return j.dump();
}

std::string HoneypotAccessEvent::ToJson() const {
    nlohmann::json j;
    j["eventId"] = eventId;
    j["honeypotPath"] = StringUtils::ToNarrow(honeypotPath);
    j["processId"] = processId;
    j["processName"] = StringUtils::ToNarrow(processName);
    j["processPath"] = StringUtils::ToNarrow(processPath);
    j["accessType"] = static_cast<int>(accessType);
    j["action"] = actionTaken;
    j["isSuspicious"] = isSuspicious;
    j["parentPid"] = parentPid;
    return j.dump();
}

bool HoneypotManagerConfiguration::IsValid() const noexcept {
    return maxTotalHoneypots > 0 && maxTotalHoneypots <= 10000;
}

void HoneypotManagerConfiguration::LoadDefaultLocations() {
    DeploymentLocation doc;
    doc.type = LocationType::UserDocuments;
    doc.isEnabled = true;
    doc.priority = 10;
    locations.push_back(doc);

    DeploymentLocation desktop;
    desktop.type = LocationType::UserDesktop;
    desktop.isEnabled = true;
    desktop.priority = 8;
    locations.push_back(desktop);

    DeploymentLocation downloads;
    downloads.type = LocationType::UserDownloads;
    downloads.isEnabled = true;
    downloads.priority = 7;
    locations.push_back(downloads);

    DeploymentLocation pictures;
    pictures.type = LocationType::UserPictures;
    pictures.isEnabled = true;
    pictures.priority = 5;
    locations.push_back(pictures);
}

void HoneypotManagerConfiguration::LoadDefaultTemplates() {
    templates.push_back(GetDefaultTemplate(HoneypotFileType::Document));
    templates.push_back(GetDefaultTemplate(HoneypotFileType::PDF));
    templates.push_back(GetDefaultTemplate(HoneypotFileType::Spreadsheet));
    templates.push_back(GetDefaultTemplate(HoneypotFileType::Image));
}

void HoneypotStatistics::Reset() noexcept {
    totalDeployed.store(0, std::memory_order_relaxed);
    currentlyActive.store(0, std::memory_order_relaxed);
    accessEvents.store(0, std::memory_order_relaxed);
    processesKilled.store(0, std::memory_order_relaxed);
    regenerations.store(0, std::memory_order_relaxed);
    falsePositives.store(0, std::memory_order_relaxed);
    for (auto& e : eventsByType) e.store(0, std::memory_order_relaxed);
    startTime = Clock::now();
}

std::string HoneypotStatistics::ToJson() const {
    nlohmann::json j;
    j["totalDeployed"] = totalDeployed.load(std::memory_order_relaxed);
    j["active"] = currentlyActive.load(std::memory_order_relaxed);
    j["events"] = accessEvents.load(std::memory_order_relaxed);
    j["killed"] = processesKilled.load(std::memory_order_relaxed);
    j["regenerations"] = regenerations.load(std::memory_order_relaxed);
    j["falsePositives"] = falsePositives.load(std::memory_order_relaxed);
    return j.dump();
}

std::string HoneypotStatisticsSnapshot::ToJson() const {
    nlohmann::json j;
    j["totalDeployed"]   = totalDeployed;
    j["active"]          = currentlyActive;
    j["events"]          = accessEvents;
    j["killed"]          = processesKilled;
    j["regenerations"]   = regenerations;
    j["falsePositives"]  = falsePositives;
    j["uptimeSeconds"]   = uptimeSeconds;
    nlohmann::json byType = nlohmann::json::array();
    for (size_t i = 0; i < eventsByType.size(); ++i) {
        byType.push_back(eventsByType[i]);
    }
    j["eventsByType"] = std::move(byType);
    return j.dump(2);
}

// ============================================================================
// KERNEL BRIDGE IMPLEMENTATIONS
// ============================================================================

void HoneypotManager::OnKernelProcessNotify(
    uint32_t pid, uint32_t parentPid,
    std::wstring_view imagePath, bool isCreate)
{
    (void)pid;
    (void)parentPid;
    (void)imagePath;
    if (!IsInitialized()) return;

    if (!isCreate) {
        // Process exit: no honeypot action needed
        return;
    }
    // Process creation: honeypot checks are demand-driven via IsTrap() / OnHoneypotAccessed()
}

void HoneypotManager::OnKernelImageLoad(
    uint32_t pid, std::wstring_view imagePath, uintptr_t imageBase)
{
    (void)pid;
    (void)imagePath;
    (void)imageBase;
    // Honeypot detection is file-access based, not image-load based
}

[[nodiscard]] bool HoneypotManager::RequestKernelProcessBlock(
    uint32_t pid, std::wstring_view reason)
{
    using Communication::IPCManager;
    if (!IPCManager::HasInstance() || !IPCManager::Instance().IsFilterPortConnected()) {
        SS_LOG_WARN(kLogCategory,
            L"[KernelBridge] Cannot block PID %u — kernel IPC not connected", pid);
        return false;
    }

#pragma pack(push, 1)
    struct KernelBlockRequest {
        uint32_t msgType = 0x30;
        uint32_t targetPid = 0;
        wchar_t  reason[256]{};
    };
#pragma pack(pop)

    KernelBlockRequest req;
    req.targetPid = pid;
    if (!reason.empty()) {
        wcsncpy_s(req.reason, 256, reason.data(),
                  std::min<size_t>(reason.size(), 255));
    }

    bool sent = IPCManager::Instance().SendToKernel(&req, sizeof(req));
    if (!sent) {
        SS_LOG_ERROR(kLogCategory,
            L"[KernelBridge] Failed to send block request for PID %u", pid);
    }
    return sent;
}

// ============================================================================
// CROSS-MODULE WIRING IMPLEMENTATIONS
// ============================================================================

void HoneypotManager::ReportAccessToAlertSystem(
    uint32_t pid, const HoneypotAccessEvent& event)
{
    using Communication::AlertSystem;
    if (!AlertSystem::HasInstance()) return;

    auto severity = (event.actionTaken == "Process Terminated")
        ? Communication::AlertSeverity::Critical
        : Communication::AlertSeverity::High;

    std::string subject = "Honeypot access by PID " + std::to_string(pid);
    std::string details = "Trap: " + Utils::StringUtils::ToNarrow(event.honeypotPath) +
        " | Process: " + Utils::StringUtils::ToNarrow(event.processName) +
        " | Action: " + event.actionTaken;

    // RaiseAlert(severity, type, subject, details, source).
    (void)AlertSystem::Instance().RaiseAlert(
        severity,
        Communication::AlertType::ThreatDetection,
        subject,
        details,
        "HoneypotManager");
}

void HoneypotManager::ReportHoneypotTelemetry(
    const std::string& eventName,
    const std::map<std::string, std::string>& fields)
{
    using Communication::TelemetryCollector;
    if (!TelemetryCollector::HasInstance()) return;

    TelemetryCollector::Instance().RecordCustom(eventName, fields);
}

} // namespace Ransomware
} // namespace ShadowStrike
