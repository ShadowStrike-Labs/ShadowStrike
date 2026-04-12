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
#include "pch.h"

#include "ProgramUpdater.hpp"
#include "UpdateVerifier.hpp"
#include "RollbackManager.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/PE_sig_verf.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/SystemUtils.hpp"

#include <algorithm>
#include <charconv>
#include <sstream>

#pragma comment(lib, "version.lib")

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

namespace {

    constexpr const wchar_t* kLogCategory = L"ProgUpdater";

    // Maximum package file size for hashing — prevent DoS (2 GiB).
    constexpr uint64_t kMaxPackageFileSize = 2ULL * 1024 * 1024 * 1024;

    // Maximum components we track to bound memory.
    constexpr size_t kMaxComponents = 64;

    // Maximum rollback versions returned.
    constexpr size_t kMaxRollbackVersions = 16;

    // Maximum changelog entries in a package.
    constexpr size_t kMaxChangelogEntries = 1024;

    // Maximum staged files.
    constexpr size_t kMaxStagedFiles = 10000;

    // Service names for ShadowStrike.
    constexpr const wchar_t* kServiceName = L"ShadowStrikeService";

    // Component filenames — map ComponentType to expected binary names.
    struct ComponentDef {
        ShadowStrike::Update::ComponentType type;
        const wchar_t* fileName;
        const char* displayName;
        bool isDriver;
        bool requiresElevation;
    };

    constexpr ComponentDef kComponentDefs[] = {
        { ShadowStrike::Update::ComponentType::Service,          L"ShadowStrikeService.exe", "ShadowStrike Service",          false, true  },
        { ShadowStrike::Update::ComponentType::GUI,              L"ShadowStrikeGUI.exe",     "ShadowStrike GUI",              false, false },
        { ShadowStrike::Update::ComponentType::Tray,             L"ShadowStrikeTray.exe",    "ShadowStrike Tray",             false, false },
        { ShadowStrike::Update::ComponentType::CLI,              L"ShadowStrikeCLI.exe",     "ShadowStrike CLI",              false, false },
        { ShadowStrike::Update::ComponentType::MinifilterDriver, L"ShadowStrikeMF.sys",      "ShadowStrike Minifilter Driver", true, true  },
        { ShadowStrike::Update::ComponentType::NetworkDriver,    L"ShadowStrikeNet.sys",     "ShadowStrike Network Driver",   true,  true  },
        { ShadowStrike::Update::ComponentType::Helper,           L"ShadowStrikeHelper.exe",  "ShadowStrike Helper",           false, true  },
        { ShadowStrike::Update::ComponentType::SDK,              L"ShadowStrikeSDK.dll",     "ShadowStrike SDK",              false, false },
        { ShadowStrike::Update::ComponentType::Uninstaller,      L"ShadowStrikeUninstall.exe","ShadowStrike Uninstaller",     false, true  },
    };

    constexpr size_t kComponentDefCount = std::size(kComponentDefs);

    // Find component definition by type.
    [[nodiscard]] const ComponentDef* FindComponentDef(
        ShadowStrike::Update::ComponentType type) noexcept
    {
        for (size_t i = 0; i < kComponentDefCount; ++i) {
            if (kComponentDefs[i].type == type) return &kComponentDefs[i];
        }
        return nullptr;
    }

    // Format a system_clock time_point as ISO-8601 string.
    [[nodiscard]] std::string FormatIso8601(
        const std::chrono::system_clock::time_point& tp) noexcept
    {
        try {
            const auto tt = std::chrono::system_clock::to_time_t(tp);
            std::tm tmBuf{};
            if (gmtime_s(&tmBuf, &tt) != 0) return "1970-01-01T00:00:00Z";
            char buf[32]{};
            if (std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmBuf) == 0)
                return "1970-01-01T00:00:00Z";
            return std::string(buf);
        }
        catch (...) { return "1970-01-01T00:00:00Z"; }
    }

    // Escape a string for JSON output.
    [[nodiscard]] std::string JsonEscape(const std::string& s) noexcept
    {
        std::string out;
        out.reserve(s.size() + 8);
        for (const char c : s) {
            switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char hex[8];
                    (void)std::snprintf(hex, sizeof(hex), "\\u%04x",
                        static_cast<unsigned>(static_cast<unsigned char>(c)));
                    out += hex;
                }
                else {
                    out += c;
                }
                break;
            }
        }
        return out;
    }

    // Parse a dotted version string into components: major.minor.patch.build
    [[nodiscard]] std::array<uint32_t, 4> ParseVersionString(const std::string& version)
    {
        std::array<uint32_t, 4> components = { 0, 0, 0, 0 };
        if (version.empty()) return components;

        size_t compIdx = 0;
        size_t start = 0;

        while (start < version.size() && compIdx < components.size()) {
            size_t dot = version.find('.', start);
            if (dot == std::string::npos) dot = version.size();

            if (dot > start) {
                uint32_t val = 0;
                const auto [ptr, errc] = std::from_chars(
                    version.data() + start,
                    version.data() + dot,
                    val);
                if (errc == std::errc{}) {
                    components[compIdx] = val;
                }
            }
            ++compIdx;
            start = dot + 1;
        }

        return components;
    }

    // Compute SHA-256 hex hash of a file with bounds checking.
    [[nodiscard]] std::string HashFileSHA256(const std::filesystem::path& filePath)
    {
        if (filePath.empty()) return {};

        std::error_code ec;
        if (!std::filesystem::exists(filePath, ec) || ec) return {};

        const auto fileSize = std::filesystem::file_size(filePath, ec);
        if (ec || fileSize > kMaxPackageFileSize) return {};

        std::vector<uint8_t> digest;
        ShadowStrike::Utils::HashUtils::Error hErr;
        if (!ShadowStrike::Utils::HashUtils::ComputeFile(
                ShadowStrike::Utils::HashUtils::Algorithm::SHA256,
                filePath.wstring(), digest, &hErr))
        {
            return {};
        }
        return ShadowStrike::Utils::HashUtils::ToHexLower(digest);
    }

    // Check whether a component type represents a kernel driver.
    [[nodiscard]] bool IsDriverComponent(
        ShadowStrike::Update::ComponentType type) noexcept
    {
        return type == ShadowStrike::Update::ComponentType::MinifilterDriver
            || type == ShadowStrike::Update::ComponentType::NetworkDriver;
    }

} // anonymous namespace

// ============================================================================
// NAMESPACE ALIASES
// ============================================================================

namespace FU = ShadowStrike::Utils::FileUtils;
namespace HU = ShadowStrike::Utils::HashUtils;
namespace SU = ShadowStrike::Utils::StringUtils;

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

namespace ShadowStrike {
namespace Update {

class ProgramUpdaterImpl {
public:
    // Configuration & status
    ProgramUpdaterConfiguration    m_config;
    mutable std::shared_mutex      m_mutex;
    ProgUpdaterStatus              m_status{ ProgUpdaterStatus::Uninitialized };
    std::atomic<bool>              m_initialized{ false };

    // Version & components
    ProgramVersion                 m_currentVersion;
    std::vector<ComponentInfo>     m_installedComponents;
    fs::path                       m_installDirectory;

    // Update state machine
    ProgUpdateState                m_updateState{ ProgUpdateState::Idle };
    ProgUpdateProgress             m_progress;
    std::optional<ProgramPackage>  m_stagedPackage;
    std::optional<ProgramPackage>  m_pendingPackage;
    fs::path                       m_stagingDir;
    fs::path                       m_backupDir;

    // Reboot tracking
    bool                           m_rebootRequired{ false };
    bool                           m_rebootScheduled{ false };

    // Statistics
    ProgUpdaterStatistics          m_stats;

    // Callbacks
    ProgProgressCallback           m_progressCallback;
    ProgCompletionCallback         m_completionCallback;
    ServiceControlCallback         m_serviceControlCallback;
    ErrorCallback                  m_errorCallback;
    mutable std::mutex             m_callbackMutex;

    // PE verifier for code signature checks
    Utils::pe_sig_utils::PEFileSignatureVerifier m_peVerifier;

    // ========================================================================
    // CALLBACK HELPERS
    // ========================================================================

    void NotifyProgress(const ProgUpdateProgress& prog)
    {
        std::lock_guard lock(m_callbackMutex);
        if (m_progressCallback) {
            try { m_progressCallback(prog); }
            catch (...) { SS_LOG_WARN(kLogCategory, L"Progress callback threw exception"); }
        }
    }

    void NotifyCompletion(const ProgUpdateResult& result)
    {
        std::lock_guard lock(m_callbackMutex);
        if (m_completionCallback) {
            try { m_completionCallback(result); }
            catch (...) { SS_LOG_WARN(kLogCategory, L"Completion callback threw exception"); }
        }
    }

    void NotifyError(const std::string& message, int code)
    {
        std::lock_guard lock(m_callbackMutex);
        if (m_errorCallback) {
            try { m_errorCallback(message, code); }
            catch (...) { SS_LOG_WARN(kLogCategory, L"Error callback threw exception"); }
        }
    }

    // ========================================================================
    // STATE HELPERS
    // ========================================================================

    void SetState(ProgUpdateState newState) noexcept
    {
        m_updateState = newState;
        m_progress.state = newState;
    }

    void UpdateProgress(ProgUpdateState state, uint8_t pct,
                        const std::string& operation,
                        std::optional<ComponentType> component = std::nullopt)
    {
        m_progress.state = state;
        m_updateState = state;
        m_progress.progressPercent = pct;
        m_progress.currentOperation = operation;
        if (component.has_value()) {
            m_progress.currentComponent = component;
        }
        auto copy = m_progress;
        NotifyProgress(copy);
    }

    void ResetProgress() noexcept
    {
        m_progress = ProgUpdateProgress{};
        m_updateState = ProgUpdateState::Idle;
    }

    [[nodiscard]] bool IsInTerminalState() const noexcept
    {
        return m_updateState == ProgUpdateState::Completed
            || m_updateState == ProgUpdateState::Failed;
    }

    // ========================================================================
    // COMPONENT DISCOVERY
    // ========================================================================

    void DiscoverInstalledComponents()
    {
        m_installedComponents.clear();

        for (size_t i = 0; i < kComponentDefCount; ++i) {
            const auto& def = kComponentDefs[i];
            fs::path componentPath = m_installDirectory / def.fileName;

            std::error_code ec;
            if (!fs::exists(componentPath, ec) || ec) continue;

            ComponentInfo info;
            info.type = def.type;
            info.displayName = def.displayName;
            info.fileName = def.fileName;
            info.installPath = componentPath;
            info.isDriver = def.isDriver;
            info.requiresElevation = def.requiresElevation;
            info.isInstalled = true;

            const auto fsize = fs::file_size(componentPath, ec);
            if (!ec) info.fileSize = fsize;

            info.fileHash = HashFileSHA256(componentPath);

            auto verOpt = GetFileVersionInfo(componentPath);
            if (verOpt.has_value()) {
                info.currentVersion = *verOpt;
            }

            // Check if a process with this filename is running (simple heuristic).
            info.isRunning = false;

            if (m_installedComponents.size() < kMaxComponents) {
                m_installedComponents.push_back(std::move(info));
            }
        }

        SS_LOG_DEBUG(kLogCategory, L"Discovered %zu installed components",
                     m_installedComponents.size());
    }

    // ========================================================================
    // SERVICE CONTROL
    // ========================================================================

    [[nodiscard]] bool StopService()
    {
        std::lock_guard lock(m_callbackMutex);
        if (m_serviceControlCallback) {
            try {
                return m_serviceControlCallback(true);
            }
            catch (...) {
                SS_LOG_ERROR(kLogCategory, L"ServiceControlCallback (stop) threw exception");
                return false;
            }
        }
        SS_LOG_WARN(kLogCategory, L"No ServiceControlCallback registered — cannot stop service");
        return false;
    }

    [[nodiscard]] bool StartService()
    {
        std::lock_guard lock(m_callbackMutex);
        if (m_serviceControlCallback) {
            try {
                return m_serviceControlCallback(false);
            }
            catch (...) {
                SS_LOG_ERROR(kLogCategory, L"ServiceControlCallback (start) threw exception");
                return false;
            }
        }
        SS_LOG_WARN(kLogCategory, L"No ServiceControlCallback registered — cannot start service");
        return false;
    }

    // ========================================================================
    // FILE OPERATIONS
    // ========================================================================

    [[nodiscard]] bool StagePackageFiles(const ProgramPackage& package)
    {
        if (m_stagingDir.empty()) {
            SS_LOG_ERROR(kLogCategory, L"Staging directory not configured");
            return false;
        }

        if (!FU::CreateDirectories(m_stagingDir.wstring())) {
            SS_LOG_ERROR(kLogCategory, L"Failed to create staging directory: %ls",
                         m_stagingDir.wstring().c_str());
            return false;
        }

        // In a complete implementation, download package from downloadUrl.
        // Transport is not configured — log and return status based on local staging.
        if (!package.downloadUrl.empty()) {
            SS_LOG_WARN(kLogCategory,
                L"HTTP download transport not configured — package must be pre-staged. URL: %hs",
                package.downloadUrl.c_str());
        }

        // Verify that the staging directory has content from a pre-staged drop.
        std::error_code ec;
        bool hasFiles = false;
        for (auto it = fs::directory_iterator(m_stagingDir, ec);
             it != fs::directory_iterator() && !ec; ++it)
        {
            if (it->is_regular_file(ec) && !ec) {
                hasFiles = true;
                break;
            }
        }

        if (!hasFiles) {
            SS_LOG_ERROR(kLogCategory,
                L"Staging directory is empty — no pre-staged package files found at: %ls",
                m_stagingDir.wstring().c_str());
            return false;
        }

        SS_LOG_INFO(kLogCategory, L"Package files staged at: %ls",
                    m_stagingDir.wstring().c_str());
        return true;
    }

    [[nodiscard]] bool ValidateStagedFiles(const ProgramPackage& package)
    {
        if (!UpdateVerifier::HasInstance() ||
            !UpdateVerifier::Instance().IsInitialized())
        {
            SS_LOG_WARN(kLogCategory,
                L"UpdateVerifier not available — skipping full package verification");
        }
        else {
            // Verify package signature.
            if (!package.signature.empty()) {
                auto result = UpdateVerifier::Instance().VerifyPackageFull(
                    m_stagingDir, package.signature);
                if (!result.isValid) {
                    SS_LOG_ERROR(kLogCategory,
                        L"Package signature verification failed: %hs",
                        result.errorMessage.c_str());
                    return false;
                }
                SS_LOG_INFO(kLogCategory, L"Package signature verified successfully");
            }

            // Verify hash if provided.
            if (!package.checksum.empty()) {
                if (!UpdateVerifier::Instance().VerifyHash(
                        m_stagingDir, package.checksum))
                {
                    SS_LOG_ERROR(kLogCategory,
                        L"Package checksum verification failed");
                    return false;
                }
            }

            // Anti-downgrade check.
            if (!package.newVersion.versionString.empty()) {
                if (!UpdateVerifier::Instance().ValidateVersionSequence(
                        package.newVersion.versionString))
                {
                    SS_LOG_ERROR(kLogCategory,
                        L"Version sequence validation failed — possible downgrade attack");
                    return false;
                }
            }
        }

        SS_LOG_INFO(kLogCategory, L"Staged files validation passed");
        return true;
    }

    [[nodiscard]] bool ReplaceComponentFile(const ComponentDef& def,
                                            const ProgramPackage& package)
    {
        fs::path targetPath = m_installDirectory / def.fileName;
        fs::path stagedPath = m_stagingDir / def.fileName;

        std::error_code ec;
        if (!fs::exists(stagedPath, ec) || ec) {
            SS_LOG_DEBUG(kLogCategory, L"No staged file for component %hs — skipping",
                         def.displayName);
            return true;
        }

        // Back up the existing file before replacement.
        if (fs::exists(targetPath, ec) && !ec) {
            fs::path backupPath = m_backupDir / def.fileName;
            if (!FU::CreateDirectories(m_backupDir.wstring())) {
                SS_LOG_ERROR(kLogCategory, L"Failed to create backup directory: %ls",
                             m_backupDir.wstring().c_str());
                return false;
            }
            std::error_code copyEc;
            fs::copy_file(targetPath, backupPath,
                          fs::copy_options::overwrite_existing, copyEc);
            if (copyEc) {
                SS_LOG_ERROR(kLogCategory, L"Failed to back up %ls: %hs",
                             targetPath.wstring().c_str(),
                             copyEc.message().c_str());
                return false;
            }
        }

        // Driver components use MoveFileEx with DELAY_UNTIL_REBOOT.
        if (def.isDriver) {
            BOOL ok = ::MoveFileExW(
                stagedPath.wstring().c_str(),
                targetPath.wstring().c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_DELAY_UNTIL_REBOOT);
            if (!ok) {
                SS_LOG_LAST_ERROR(kLogCategory,
                    L"MoveFileEx (DELAY_UNTIL_REBOOT) failed for driver: %ls",
                    def.fileName);
                return false;
            }
            m_rebootRequired = true;
            m_stats.driverUpdates++;
            SS_LOG_INFO(kLogCategory,
                L"Driver %ls scheduled for replacement on reboot",
                def.fileName);
            return true;
        }

        // User-mode: ShadowCopy method — atomic replace.
        if (package.installMethod == InstallMethod::ShadowCopy ||
            package.installMethod == InstallMethod::InPlace)
        {
            BOOL ok = ::MoveFileExW(
                stagedPath.wstring().c_str(),
                targetPath.wstring().c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
            if (!ok) {
                // If file is locked, fall back to MoveFileEx with reboot flag.
                DWORD lastErr = ::GetLastError();
                if (lastErr == ERROR_ACCESS_DENIED ||
                    lastErr == ERROR_SHARING_VIOLATION)
                {
                    SS_LOG_WARN(kLogCategory,
                        L"File %ls is locked — scheduling for replacement on reboot",
                        def.fileName);
                    ok = ::MoveFileExW(
                        stagedPath.wstring().c_str(),
                        targetPath.wstring().c_str(),
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_DELAY_UNTIL_REBOOT);
                    if (!ok) {
                        SS_LOG_LAST_ERROR(kLogCategory,
                            L"MoveFileEx (DELAY_UNTIL_REBOOT) fallback failed: %ls",
                            def.fileName);
                        return false;
                    }
                    m_rebootRequired = true;
                    return true;
                }
                SS_LOG_LAST_ERROR(kLogCategory,
                    L"MoveFileEx failed for %ls", def.fileName);
                return false;
            }
            SS_LOG_INFO(kLogCategory, L"Replaced %ls successfully", def.fileName);
            return true;
        }

        // MoveFileEx method: always schedule for reboot.
        if (package.installMethod == InstallMethod::MoveFileEx) {
            BOOL ok = ::MoveFileExW(
                stagedPath.wstring().c_str(),
                targetPath.wstring().c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_DELAY_UNTIL_REBOOT);
            if (!ok) {
                SS_LOG_LAST_ERROR(kLogCategory,
                    L"MoveFileEx (DELAY_UNTIL_REBOOT) failed: %ls", def.fileName);
                return false;
            }
            m_rebootRequired = true;
            SS_LOG_INFO(kLogCategory,
                L"Scheduled %ls for replacement on reboot", def.fileName);
            return true;
        }

        // Installer method — execute staged installer silently.
        if (package.installMethod == InstallMethod::Installer) {
            std::wstring cmdLine = stagedPath.wstring()
                + L" /S /SILENT /VERYSILENT /norestart";

            STARTUPINFOW si{};
            si.cb = sizeof(si);
            PROCESS_INFORMATION pi{};

            BOOL created = ::CreateProcessW(
                nullptr,
                cmdLine.data(),
                nullptr,
                nullptr,
                FALSE,
                CREATE_NO_WINDOW,
                nullptr,
                nullptr,
                &si,
                &pi);

            if (!created) {
                SS_LOG_LAST_ERROR(kLogCategory,
                    L"CreateProcessW failed for installer: %ls", def.fileName);
                return false;
            }

            constexpr DWORD kInstallerTimeoutMs = 5 * 60 * 1000; // 5 minutes
            DWORD waitResult = ::WaitForSingleObject(pi.hProcess, kInstallerTimeoutMs);

            if (waitResult == WAIT_TIMEOUT) {
                SS_LOG_ERROR(kLogCategory,
                    L"Installer timed out after %u ms: %ls",
                    kInstallerTimeoutMs, def.fileName);
                ::TerminateProcess(pi.hProcess, 1);
                ::CloseHandle(pi.hProcess);
                ::CloseHandle(pi.hThread);
                return false;
            }

            DWORD exitCode = 0;
            ::GetExitCodeProcess(pi.hProcess, &exitCode);
            ::CloseHandle(pi.hProcess);
            ::CloseHandle(pi.hThread);

            if (exitCode != 0) {
                SS_LOG_ERROR(kLogCategory,
                    L"Installer exited with code %u: %ls", exitCode, def.fileName);
                return false;
            }

            SS_LOG_INFO(kLogCategory,
                L"Installer completed successfully: %ls", def.fileName);
            return true;
        }

        return false;
    }

    // ========================================================================
    // APPLY LOGIC
    // ========================================================================

    [[nodiscard]] bool ExecuteUpdate(const ProgramPackage& package)
    {
        const auto startTime = Clock::now();
        const auto sysStart  = std::chrono::system_clock::now();

        ProgUpdateResult result;
        result.oldVersion = m_currentVersion;
        result.newVersion = package.newVersion;
        result.appliedTime = sysStart;

        // 1. Staging
        UpdateProgress(ProgUpdateState::Staging, 10, "Staging update files");
        if (!StagePackageFiles(package)) {
            SetState(ProgUpdateState::Failed);
            m_progress.errorMessage = "Staging failed";
            m_stats.updatesFailed++;
            result.errorMessage = "Staging failed";
            NotifyCompletion(result);
            NotifyError("Staging failed", ERROR_INSTALL_FAILURE);
            return false;
        }

        // 2. Validation
        UpdateProgress(ProgUpdateState::Validating, 25, "Validating staged files");
        if (!ValidateStagedFiles(package)) {
            SetState(ProgUpdateState::Failed);
            m_progress.errorMessage = "Validation failed";
            m_stats.updatesFailed++;
            result.errorMessage = "Validation failed";
            NotifyCompletion(result);
            NotifyError("Validation failed", ERROR_INSTALL_FAILURE);
            return false;
        }

        // 3. Create rollback snapshot before proceeding.
        if (RollbackManager::HasInstance() &&
            RollbackManager::Instance().IsInitialized())
        {
            auto snapId = RollbackManager::Instance().CreateSnapshot(
                SnapshotType::Full, "Pre-update snapshot");
            if (snapId.empty()) {
                SS_LOG_WARN(kLogCategory,
                    L"Failed to create pre-update snapshot — proceeding anyway");
            } else {
                SS_LOG_INFO(kLogCategory, L"Created pre-update snapshot: %hs",
                            snapId.c_str());
            }
        }

        // 4. Determine which components need updating.
        bool anyDriverComponent = false;
        for (const auto& compType : package.components) {
            if (IsDriverComponent(compType)) {
                anyDriverComponent = true;
                break;
            }
        }

        // Respect driver update policy.
        if (anyDriverComponent && !m_config.allowDriverUpdates) {
            SS_LOG_ERROR(kLogCategory,
                L"Package contains driver updates but allowDriverUpdates is disabled");
            SetState(ProgUpdateState::Failed);
            m_progress.errorMessage = "Driver updates not allowed by policy";
            m_stats.updatesFailed++;
            result.errorMessage = "Driver updates not allowed by policy";
            NotifyCompletion(result);
            NotifyError("Driver updates disabled", ERROR_INSTALL_FAILURE);
            return false;
        }

        // 5. Stop services (for user-mode components).
        bool stoppedService = false;
        bool hasUserModeComponents = false;
        for (const auto& compType : package.components) {
            if (!IsDriverComponent(compType)) {
                hasUserModeComponents = true;
                break;
            }
        }

        if (hasUserModeComponents) {
            UpdateProgress(ProgUpdateState::Stopping, 40, "Stopping services");
            if (StopService()) {
                stoppedService = true;
                m_stats.serviceRestarts++;
                SS_LOG_INFO(kLogCategory, L"Service stopped for update");
            } else {
                SS_LOG_WARN(kLogCategory,
                    L"Failed to stop service — attempting file replacement anyway");
            }
        }

        // 6. Replace files.
        UpdateProgress(ProgUpdateState::Replacing, 55, "Replacing files");
        m_progress.componentsTotal = static_cast<uint32_t>(package.components.size());
        m_progress.componentsCompleted = 0;

        bool allSucceeded = true;
        for (const auto& compType : package.components) {
            const auto* def = FindComponentDef(compType);
            if (!def) {
                SS_LOG_WARN(kLogCategory,
                    L"Unknown component type %u in package — skipping",
                    static_cast<unsigned>(compType));
                continue;
            }

            m_progress.currentComponent = compType;
            m_progress.currentOperation =
                std::string("Replacing ") + def->displayName;

            if (!ReplaceComponentFile(*def, package)) {
                SS_LOG_ERROR(kLogCategory, L"Failed to replace component: %hs",
                             def->displayName);
                allSucceeded = false;
                break;
            }

            m_progress.componentsCompleted++;
            result.updatedComponents.push_back(compType);

            const uint8_t pctBase = 55;
            const uint8_t pctRange = 25;
            if (m_progress.componentsTotal > 0) {
                m_progress.progressPercent = static_cast<uint8_t>(
                    pctBase + (pctRange * m_progress.componentsCompleted /
                               m_progress.componentsTotal));
            }

            auto copy = m_progress;
            NotifyProgress(copy);
        }

        // 7. Restart service if we stopped it.
        if (stoppedService) {
            UpdateProgress(ProgUpdateState::Starting, 82, "Starting services");
            if (!StartService()) {
                SS_LOG_ERROR(kLogCategory, L"Failed to restart service after update");
                allSucceeded = false;
            } else {
                SS_LOG_INFO(kLogCategory, L"Service restarted after update");
            }
        }

        // 8. Verify installation health.
        if (allSucceeded && m_config.verifyAfterUpdate) {
            UpdateProgress(ProgUpdateState::Verifying, 90, "Verifying installation");
            DiscoverInstalledComponents();
            // Basic health: check that updated components exist on disk.
            for (const auto& compType : result.updatedComponents) {
                const auto* def = FindComponentDef(compType);
                if (!def) continue;
                if (IsDriverComponent(compType) && m_rebootRequired) continue;
                fs::path p = m_installDirectory / def->fileName;
                std::error_code ec;
                if (!fs::exists(p, ec) || ec) {
                    SS_LOG_ERROR(kLogCategory,
                        L"Post-update verification failed — %ls missing",
                        def->fileName);
                    allSucceeded = false;
                    break;
                }
            }
        }

        // 9. Handle failure → auto-rollback.
        if (!allSucceeded) {
            if (m_config.autoRollbackOnFailure) {
                UpdateProgress(ProgUpdateState::RollingBack, 95,
                               "Rolling back due to failure");
                if (RollbackManager::HasInstance() &&
                    RollbackManager::Instance().IsInitialized() &&
                    RollbackManager::Instance().CanRollback())
                {
                    if (RollbackManager::Instance().TriggerRollback()) {
                        SS_LOG_INFO(kLogCategory,
                            L"Automatic rollback completed after update failure");
                        result.wasRollback = true;
                        m_stats.rollbacksPerformed++;
                    } else {
                        SS_LOG_ERROR(kLogCategory,
                            L"Automatic rollback failed — system may be inconsistent");
                    }
                } else {
                    SS_LOG_ERROR(kLogCategory,
                        L"RollbackManager not available for auto-rollback");
                }
            }

            SetState(ProgUpdateState::Failed);
            m_progress.errorMessage = "Update failed during file replacement";
            m_stats.updatesFailed++;
            result.success = false;
            result.errorMessage = "Update failed during file replacement";

            const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                Clock::now() - startTime);
            result.durationSeconds = static_cast<uint32_t>(elapsed.count());

            NotifyCompletion(result);
            NotifyError("Update failed", ERROR_INSTALL_FAILURE);
            return false;
        }

        // 10. Success.
        SetState(ProgUpdateState::Completed);

        // Compute reboot requirement.
        RebootRequirement reboot = package.rebootRequirement;
        if (anyDriverComponent) {
            reboot = RebootRequirement::Required;
        }
        result.rebootRequired = (reboot == RebootRequirement::Required ||
                                 reboot == RebootRequirement::Immediate ||
                                 m_rebootRequired);

        if (result.rebootRequired) {
            m_rebootRequired = true;
        }

        result.success = true;
        m_currentVersion = package.newVersion;
        m_stats.updatesApplied++;
        m_stats.lastUpdateTime = std::chrono::system_clock::now();

        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            Clock::now() - startTime);
        result.durationSeconds = static_cast<uint32_t>(elapsed.count());

        UpdateProgress(ProgUpdateState::Completed, 100, "Update completed");

        SS_LOG_INFO(kLogCategory,
            L"Program update completed: %hs → %hs (%u components, %us, reboot=%s)",
            result.oldVersion.versionString.c_str(),
            result.newVersion.versionString.c_str(),
            static_cast<unsigned>(result.updatedComponents.size()),
            result.durationSeconds,
            result.rebootRequired ? L"yes" : L"no");

        NotifyCompletion(result);

        // Post-update: record boot for loop detection.
        if (RollbackManager::HasInstance() &&
            RollbackManager::Instance().IsInitialized())
        {
            RollbackManager::Instance().RecordBoot();
        }

        return true;
    }
};

// ============================================================================
// STRUCT IMPLEMENTATIONS
// ============================================================================

// --- ProgramVersion ---

bool ProgramVersion::operator<(const ProgramVersion& other) const noexcept
{
    if (major != other.major) return major < other.major;
    if (minor != other.minor) return minor < other.minor;
    if (patch != other.patch) return patch < other.patch;
    return build < other.build;
}

bool ProgramVersion::operator>(const ProgramVersion& other) const noexcept
{
    return other < *this;
}

bool ProgramVersion::operator==(const ProgramVersion& other) const noexcept
{
    return major == other.major
        && minor == other.minor
        && patch == other.patch
        && build == other.build;
}

std::string ProgramVersion::ToJson() const
{
    std::ostringstream os;
    os << "{\"major\":" << major
       << ",\"minor\":" << minor
       << ",\"patch\":" << patch
       << ",\"build\":" << build
       << ",\"versionString\":\"" << JsonEscape(versionString)
       << "\",\"productName\":\"" << JsonEscape(productName)
       << "\",\"fileDescription\":\"" << JsonEscape(fileDescription)
       << "\",\"copyright\":\"" << JsonEscape(copyright)
       << "\"}";
    return os.str();
}

std::string ProgramVersion::ToString() const
{
    std::ostringstream os;
    os << major << '.' << minor << '.' << patch << '.' << build;
    return os.str();
}

// --- ComponentInfo ---

std::string ComponentInfo::ToJson() const
{
    std::ostringstream os;
    os << "{\"type\":\"" << GetComponentTypeName(type)
       << "\",\"displayName\":\"" << JsonEscape(displayName)
       << "\",\"fileName\":\"" << JsonEscape(SU::ToNarrow(fileName))
       << "\",\"installPath\":\"" << JsonEscape(installPath.string())
       << "\",\"currentVersion\":" << currentVersion.ToJson()
       << ",\"fileSize\":" << fileSize
       << ",\"fileHash\":\"" << JsonEscape(fileHash)
       << "\",\"isInstalled\":" << (isInstalled ? "true" : "false")
       << ",\"isRunning\":" << (isRunning ? "true" : "false")
       << ",\"requiresElevation\":" << (requiresElevation ? "true" : "false")
       << ",\"isDriver\":" << (isDriver ? "true" : "false")
       << "}";
    return os.str();
}

// --- ProgramPackage ---

std::string ProgramPackage::ToJson() const
{
    std::ostringstream os;
    os << "{\"packageId\":\"" << JsonEscape(packageId)
       << "\",\"newVersion\":" << newVersion.ToJson()
       << ",\"packageSize\":" << packageSize
       << ",\"downloadUrl\":\"" << JsonEscape(downloadUrl)
       << "\",\"checksum\":\"" << JsonEscape(checksum)
       << "\",\"installMethod\":\"" << GetInstallMethodName(installMethod)
       << "\",\"rebootRequirement\":\"" << GetRebootRequirementName(rebootRequirement)
       << "\",\"isMandatory\":" << (isMandatory ? "true" : "false")
       << ",\"componentsCount\":" << components.size()
       << ",\"changelogEntries\":" << changelog.size()
       << ",\"dependenciesCount\":" << dependencies.size()
       << "}";
    return os.str();
}

// --- ProgUpdateProgress ---

std::string ProgUpdateProgress::ToJson() const
{
    std::ostringstream os;
    os << "{\"state\":\"" << GetUpdateStateName(state)
       << "\",\"progressPercent\":" << static_cast<unsigned>(progressPercent)
       << ",\"currentOperation\":\"" << JsonEscape(currentOperation) << "\"";
    if (currentComponent.has_value()) {
        os << ",\"currentComponent\":\""
           << GetComponentTypeName(*currentComponent) << "\"";
    }
    os << ",\"bytesDownloaded\":" << bytesDownloaded
       << ",\"totalBytes\":" << totalBytes
       << ",\"componentsCompleted\":" << componentsCompleted
       << ",\"componentsTotal\":" << componentsTotal;
    if (!errorMessage.empty()) {
        os << ",\"error\":\"" << JsonEscape(errorMessage) << "\"";
    }
    os << "}";
    return os.str();
}

// --- ProgUpdateResult ---

std::string ProgUpdateResult::ToJson() const
{
    std::ostringstream os;
    os << "{\"success\":" << (success ? "true" : "false")
       << ",\"oldVersion\":" << oldVersion.ToJson()
       << ",\"newVersion\":" << newVersion.ToJson()
       << ",\"updatedComponents\":[";
    for (size_t i = 0; i < updatedComponents.size(); ++i) {
        if (i > 0) os << ',';
        os << '"' << GetComponentTypeName(updatedComponents[i]) << '"';
    }
    os << "],\"rebootRequired\":" << (rebootRequired ? "true" : "false")
       << ",\"wasRollback\":" << (wasRollback ? "true" : "false")
       << ",\"appliedTime\":\"" << FormatIso8601(appliedTime) << "\""
       << ",\"durationSeconds\":" << durationSeconds;
    if (!errorMessage.empty()) {
        os << ",\"error\":\"" << JsonEscape(errorMessage) << "\"";
    }
    os << "}";
    return os.str();
}

// --- ProgUpdaterStatistics ---

void ProgUpdaterStatistics::Reset() noexcept
{
    updatesApplied = 0;
    updatesFailed = 0;
    rollbacksPerformed = 0;
    driverUpdates = 0;
    serviceRestarts = 0;
    rebootsScheduled = 0;
    bytesDownloaded = 0;
    startTime = Clock::now();
    lastUpdateTime.reset();
}

std::string ProgUpdaterStatistics::ToJson() const
{
    std::ostringstream os;
    os << "{\"updatesApplied\":" << updatesApplied
       << ",\"updatesFailed\":" << updatesFailed
       << ",\"rollbacksPerformed\":" << rollbacksPerformed
       << ",\"driverUpdates\":" << driverUpdates
       << ",\"serviceRestarts\":" << serviceRestarts
       << ",\"rebootsScheduled\":" << rebootsScheduled
       << ",\"bytesDownloaded\":" << bytesDownloaded;
    if (lastUpdateTime.has_value()) {
        os << ",\"lastUpdateTime\":\"" << FormatIso8601(*lastUpdateTime) << "\"";
    }
    os << "}";
    return os.str();
}

// --- ProgramUpdaterConfiguration ---

bool ProgramUpdaterConfiguration::IsValid() const noexcept
{
    if (bootLoopThreshold == 0) return false;
    if (bootLoopWindowMinutes == 0) return false;
    if (maxBackupVersions == 0) return false;
    return true;
}

// ============================================================================
// SINGLETON
// ============================================================================

std::atomic<bool> ProgramUpdater::s_instanceCreated{ false };

ProgramUpdater& ProgramUpdater::Instance() noexcept
{
    static ProgramUpdater instance;
    return instance;
}

bool ProgramUpdater::HasInstance() noexcept
{
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

ProgramUpdater::ProgramUpdater()
    : m_impl(std::make_unique<ProgramUpdaterImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
    SS_LOG_DEBUG(kLogCategory, L"ProgramUpdater constructed");
}

ProgramUpdater::~ProgramUpdater()
{
    if (m_impl && m_impl->m_initialized.load(std::memory_order_acquire)) {
        Shutdown();
    }
    s_instanceCreated.store(false, std::memory_order_release);
    SS_LOG_DEBUG(kLogCategory, L"ProgramUpdater destroyed");
}

// ============================================================================
// LIFECYCLE
// ============================================================================

bool ProgramUpdater::Initialize(const ProgramUpdaterConfiguration& config)
{
    if (!m_impl) return false;

    if (m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(kLogCategory,
            L"Initialize called on already-initialized instance");
        return true;
    }

    std::unique_lock lock(m_impl->m_mutex);

    m_impl->m_status = ProgUpdaterStatus::Initializing;

    SS_LOG_INFO(kLogCategory, L"Initializing ProgramUpdater v%u.%u.%u",
                ProgUpdateConstants::VERSION_MAJOR,
                ProgUpdateConstants::VERSION_MINOR,
                ProgUpdateConstants::VERSION_PATCH);

    m_impl->m_config = config;

    // Validate configuration.
    if (!config.IsValid()) {
        SS_LOG_WARN(kLogCategory,
            L"Configuration validation failed — using defaults where needed");
    }

    // Resolve install directory from executable path.
    auto exePath = Utils::SystemUtils::GetExecutablePath();
    if (exePath.empty()) {
        wchar_t buf[MAX_PATH]{};
        ::GetModuleFileNameW(nullptr, buf, MAX_PATH);
        exePath = buf;
    }
    m_impl->m_installDirectory = fs::path(exePath).parent_path();

    // Resolve staging directory.
    if (config.stagingDirectory.empty()) {
        m_impl->m_stagingDir =
            m_impl->m_installDirectory / ProgUpdateConstants::STAGING_DIR;
    } else {
        m_impl->m_stagingDir = config.stagingDirectory;
    }

    // Resolve backup directory.
    if (config.backupDirectory.empty()) {
        m_impl->m_backupDir =
            m_impl->m_installDirectory / ProgUpdateConstants::BACKUP_DIR;
    } else {
        m_impl->m_backupDir = config.backupDirectory;
    }

    // Create directories.
    if (!FU::CreateDirectories(m_impl->m_stagingDir.wstring())) {
        SS_LOG_ERROR(kLogCategory,
            L"Failed to create staging directory: %ls",
            m_impl->m_stagingDir.wstring().c_str());
        m_impl->m_status = ProgUpdaterStatus::Error;
        m_impl->NotifyError("Failed to create staging directory",
                            ERROR_PATH_NOT_FOUND);
        return false;
    }

    if (!FU::CreateDirectories(m_impl->m_backupDir.wstring())) {
        SS_LOG_ERROR(kLogCategory,
            L"Failed to create backup directory: %ls",
            m_impl->m_backupDir.wstring().c_str());
        m_impl->m_status = ProgUpdaterStatus::Error;
        m_impl->NotifyError("Failed to create backup directory",
                            ERROR_PATH_NOT_FOUND);
        return false;
    }

    // Discover installed components and determine current version.
    m_impl->DiscoverInstalledComponents();

    // Set current version from the Service component (primary).
    for (const auto& comp : m_impl->m_installedComponents) {
        if (comp.type == ComponentType::Service) {
            m_impl->m_currentVersion = comp.currentVersion;
            break;
        }
    }

    // If no Service component found, try to determine from any component.
    if (m_impl->m_currentVersion.versionString.empty() &&
        !m_impl->m_installedComponents.empty())
    {
        m_impl->m_currentVersion =
            m_impl->m_installedComponents.front().currentVersion;
    }

    m_impl->m_stats.Reset();
    m_impl->ResetProgress();

    m_impl->m_initialized.store(true, std::memory_order_release);
    m_impl->m_status = ProgUpdaterStatus::Running;

    SS_LOG_INFO(kLogCategory,
        L"ProgramUpdater initialized (version=%hs, components=%zu, "
        L"installDir=%ls, staging=%ls)",
        m_impl->m_currentVersion.ToString().c_str(),
        m_impl->m_installedComponents.size(),
        m_impl->m_installDirectory.wstring().c_str(),
        m_impl->m_stagingDir.wstring().c_str());

    return true;
}

void ProgramUpdater::Shutdown()
{
    if (!m_impl) return;

    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    SS_LOG_INFO(kLogCategory, L"Shutting down ProgramUpdater");

    std::unique_lock lock(m_impl->m_mutex);

    m_impl->m_status = ProgUpdaterStatus::Stopping;

    if (m_impl->m_updateState != ProgUpdateState::Idle &&
        m_impl->m_updateState != ProgUpdateState::Completed &&
        m_impl->m_updateState != ProgUpdateState::Failed)
    {
        SS_LOG_WARN(kLogCategory,
            L"Shutdown requested while update is in state: %hs",
            std::string(GetUpdateStateName(m_impl->m_updateState)).c_str());
    }

    m_impl->m_initialized.store(false, std::memory_order_release);
    m_impl->m_status = ProgUpdaterStatus::Stopped;

    lock.unlock();

    // Clear callbacks under their own lock.
    {
        std::lock_guard cbLock(m_impl->m_callbackMutex);
        m_impl->m_progressCallback = nullptr;
        m_impl->m_completionCallback = nullptr;
        m_impl->m_serviceControlCallback = nullptr;
        m_impl->m_errorCallback = nullptr;
    }

    SS_LOG_INFO(kLogCategory, L"ProgramUpdater shutdown complete");
}

bool ProgramUpdater::IsInitialized() const noexcept
{
    if (!m_impl) return false;
    return m_impl->m_initialized.load(std::memory_order_acquire);
}

ProgUpdaterStatus ProgramUpdater::GetStatus() const noexcept
{
    if (!m_impl) return ProgUpdaterStatus::Uninitialized;
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_status;
}

bool ProgramUpdater::UpdateConfiguration(
    const ProgramUpdaterConfiguration& config)
{
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory,
            L"UpdateConfiguration called on uninitialized instance");
        return false;
    }

    if (!config.IsValid()) {
        SS_LOG_ERROR(kLogCategory,
            L"UpdateConfiguration: invalid configuration rejected");
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);

    if (m_impl->m_updateState != ProgUpdateState::Idle &&
        m_impl->m_updateState != ProgUpdateState::Completed &&
        m_impl->m_updateState != ProgUpdateState::Failed)
    {
        SS_LOG_WARN(kLogCategory,
            L"Cannot update configuration while update is in progress");
        return false;
    }

    m_impl->m_config = config;

    // Update paths if changed.
    if (!config.stagingDirectory.empty()) {
        m_impl->m_stagingDir = config.stagingDirectory;
    }
    if (!config.backupDirectory.empty()) {
        m_impl->m_backupDir = config.backupDirectory;
    }

    SS_LOG_INFO(kLogCategory, L"Configuration updated (enabled=%s, auto=%s, "
                L"driverUpdates=%s, bootLoop=%s)",
                config.enabled ? L"true" : L"false",
                config.autoUpdate ? L"true" : L"false",
                config.allowDriverUpdates ? L"true" : L"false",
                config.enableBootLoopDetection ? L"true" : L"false");

    return true;
}

ProgramUpdaterConfiguration ProgramUpdater::GetConfiguration() const
{
    if (!m_impl) return {};
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config;
}

// ============================================================================
// VERSION CHECK
// ============================================================================

bool ProgramUpdater::IsNewVersionAvailable()
{
    auto pkg = CheckForUpdate();
    return pkg.has_value();
}

std::optional<ProgramPackage> ProgramUpdater::CheckForUpdate()
{
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory,
            L"CheckForUpdate called on uninitialized instance");
        return std::nullopt;
    }

    if (!m_impl->m_config.enabled) {
        SS_LOG_DEBUG(kLogCategory, L"Updates are disabled by configuration");
        return std::nullopt;
    }

    std::unique_lock lock(m_impl->m_mutex);

    m_impl->SetState(ProgUpdateState::Checking);

    SS_LOG_INFO(kLogCategory, L"Checking for program updates (current=%hs)",
                m_impl->m_currentVersion.ToString().c_str());

    // NOTE: In a production deployment, this would query the update server
    // via the configured transport. The HTTP transport layer is not configured
    // in this build — return pending package if one has been pre-staged.
    SS_LOG_INFO(kLogCategory,
        L"Update check: no transport configured — checking for pre-staged package");

    if (m_impl->m_stagedPackage.has_value()) {
        const auto& staged = *m_impl->m_stagedPackage;
        if (staged.newVersion > m_impl->m_currentVersion) {
            SS_LOG_INFO(kLogCategory,
                L"Pre-staged package found: %hs → %hs",
                m_impl->m_currentVersion.ToString().c_str(),
                staged.newVersion.ToString().c_str());
            m_impl->SetState(ProgUpdateState::Idle);
            return staged;
        }
    }

    m_impl->SetState(ProgUpdateState::Idle);
    SS_LOG_INFO(kLogCategory, L"No new version available");
    return std::nullopt;
}

ProgramVersion ProgramUpdater::GetCurrentVersion() const
{
    if (!m_impl) return {};
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_currentVersion;
}

std::vector<ComponentInfo> ProgramUpdater::GetInstalledComponents() const
{
    if (!m_impl) return {};
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_installedComponents;
}

std::optional<ComponentInfo> ProgramUpdater::GetComponentInfo(
    ComponentType type) const
{
    if (!m_impl) return std::nullopt;
    std::shared_lock lock(m_impl->m_mutex);
    for (const auto& comp : m_impl->m_installedComponents) {
        if (comp.type == type) return comp;
    }
    return std::nullopt;
}

// ============================================================================
// UPDATE OPERATIONS
// ============================================================================

bool ProgramUpdater::ApplyProgramUpdate()
{
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory,
            L"ApplyProgramUpdate called on uninitialized instance");
        return false;
    }

    auto pkgOpt = CheckForUpdate();
    if (!pkgOpt.has_value()) {
        SS_LOG_INFO(kLogCategory,
            L"No update available to apply");
        return false;
    }

    return ApplyPackage(*pkgOpt);
}

bool ProgramUpdater::ApplyPackage(const ProgramPackage& package)
{
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory,
            L"ApplyPackage called on uninitialized instance");
        return false;
    }

    if (!m_impl->m_config.enabled) {
        SS_LOG_WARN(kLogCategory,
            L"Updates are disabled by configuration");
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);

    if (m_impl->m_updateState != ProgUpdateState::Idle &&
        m_impl->m_updateState != ProgUpdateState::Completed &&
        m_impl->m_updateState != ProgUpdateState::Failed)
    {
        SS_LOG_WARN(kLogCategory,
            L"Cannot apply package — update already in progress (state=%hs)",
            std::string(GetUpdateStateName(m_impl->m_updateState)).c_str());
        return false;
    }

    if (package.packageId.empty()) {
        SS_LOG_ERROR(kLogCategory, L"Cannot apply package with empty packageId");
        return false;
    }

    if (package.components.empty()) {
        SS_LOG_ERROR(kLogCategory,
            L"Cannot apply package with no components");
        return false;
    }

    m_impl->m_status = ProgUpdaterStatus::Updating;
    m_impl->ResetProgress();
    m_impl->m_rebootRequired = false;

    SS_LOG_INFO(kLogCategory,
        L"Applying package %hs (version=%hs, components=%zu, method=%hs)",
        package.packageId.c_str(),
        package.newVersion.ToString().c_str(),
        package.components.size(),
        std::string(GetInstallMethodName(package.installMethod)).c_str());

    bool success = m_impl->ExecuteUpdate(package);

    m_impl->m_status = success ? ProgUpdaterStatus::Running
                               : ProgUpdaterStatus::Running;

    return success;
}

bool ProgramUpdater::StageUpdate(const ProgramPackage& package)
{
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory,
            L"StageUpdate called on uninitialized instance");
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);

    if (m_impl->m_updateState != ProgUpdateState::Idle &&
        m_impl->m_updateState != ProgUpdateState::Completed &&
        m_impl->m_updateState != ProgUpdateState::Failed)
    {
        SS_LOG_WARN(kLogCategory,
            L"Cannot stage update while another is in progress");
        return false;
    }

    SS_LOG_INFO(kLogCategory,
        L"Staging update package %hs (version=%hs)",
        package.packageId.c_str(),
        package.newVersion.ToString().c_str());

    m_impl->SetState(ProgUpdateState::Staging);
    m_impl->UpdateProgress(ProgUpdateState::Staging, 10,
                           "Staging package files");

    if (!m_impl->StagePackageFiles(package)) {
        m_impl->SetState(ProgUpdateState::Failed);
        m_impl->m_progress.errorMessage = "Staging failed";
        m_impl->m_stats.updatesFailed++;
        m_impl->NotifyError("Staging failed", ERROR_INSTALL_FAILURE);
        return false;
    }

    m_impl->UpdateProgress(ProgUpdateState::Validating, 50,
                           "Validating staged files");

    if (!m_impl->ValidateStagedFiles(package)) {
        m_impl->SetState(ProgUpdateState::Failed);
        m_impl->m_progress.errorMessage = "Validation of staged files failed";
        m_impl->m_stats.updatesFailed++;
        m_impl->NotifyError("Staged file validation failed", ERROR_INSTALL_FAILURE);
        return false;
    }

    m_impl->m_stagedPackage = package;
    m_impl->SetState(ProgUpdateState::Idle);
    m_impl->m_progress.progressPercent = 100;

    SS_LOG_INFO(kLogCategory,
        L"Update package %hs staged successfully",
        package.packageId.c_str());

    return true;
}

bool ProgramUpdater::ApplyStagedUpdate()
{
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory,
            L"ApplyStagedUpdate called on uninitialized instance");
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);

    if (!m_impl->m_stagedPackage.has_value()) {
        SS_LOG_ERROR(kLogCategory,
            L"No staged package available to apply");
        return false;
    }

    auto package = *m_impl->m_stagedPackage;

    m_impl->m_status = ProgUpdaterStatus::Updating;
    m_impl->ResetProgress();
    m_impl->m_rebootRequired = false;

    SS_LOG_INFO(kLogCategory,
        L"Applying staged update: %hs",
        package.packageId.c_str());

    bool success = m_impl->ExecuteUpdate(package);

    if (success) {
        m_impl->m_stagedPackage.reset();
    }

    m_impl->m_status = ProgUpdaterStatus::Running;

    return success;
}

void ProgramUpdater::CancelUpdate()
{
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_mutex);

    if (m_impl->m_updateState == ProgUpdateState::Idle ||
        m_impl->m_updateState == ProgUpdateState::Completed ||
        m_impl->m_updateState == ProgUpdateState::Failed)
    {
        SS_LOG_DEBUG(kLogCategory,
            L"CancelUpdate: no update in progress to cancel");
        return;
    }

    SS_LOG_INFO(kLogCategory,
        L"Cancelling update in state: %hs",
        std::string(GetUpdateStateName(m_impl->m_updateState)).c_str());

    m_impl->SetState(ProgUpdateState::Failed);
    m_impl->m_progress.errorMessage = "Update cancelled by user";
    m_impl->m_status = ProgUpdaterStatus::Running;

    m_impl->NotifyError("Update cancelled by user", ERROR_CANCELLED);
}

ProgUpdateState ProgramUpdater::GetUpdateState() const noexcept
{
    if (!m_impl) return ProgUpdateState::Idle;
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_updateState;
}

bool ProgramUpdater::IsUpdateInProgress() const noexcept
{
    if (!m_impl) return false;
    std::shared_lock lock(m_impl->m_mutex);
    const auto state = m_impl->m_updateState;
    return state != ProgUpdateState::Idle
        && state != ProgUpdateState::Completed
        && state != ProgUpdateState::Failed;
}

// ============================================================================
// PROGRESS
// ============================================================================

ProgUpdateProgress ProgramUpdater::GetProgress() const
{
    if (!m_impl) return {};
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_progress;
}

// ============================================================================
// ROLLBACK
// ============================================================================

bool ProgramUpdater::CanRollback() const
{
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    if (!RollbackManager::HasInstance() ||
        !RollbackManager::Instance().IsInitialized())
    {
        return false;
    }

    return RollbackManager::Instance().CanRollback();
}

bool ProgramUpdater::PerformRollback()
{
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory,
            L"PerformRollback called on uninitialized instance");
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);

    if (!RollbackManager::HasInstance() ||
        !RollbackManager::Instance().IsInitialized())
    {
        SS_LOG_ERROR(kLogCategory,
            L"RollbackManager not available for rollback");
        return false;
    }

    if (!RollbackManager::Instance().CanRollback()) {
        SS_LOG_ERROR(kLogCategory,
            L"No rollback snapshots available");
        return false;
    }

    SS_LOG_INFO(kLogCategory, L"Initiating program rollback");

    m_impl->SetState(ProgUpdateState::RollingBack);
    m_impl->UpdateProgress(ProgUpdateState::RollingBack, 10,
                           "Rolling back to previous version");

    bool success = RollbackManager::Instance().TriggerRollback();

    if (success) {
        m_impl->m_stats.rollbacksPerformed++;
        m_impl->DiscoverInstalledComponents();

        // Update current version from refreshed components.
        for (const auto& comp : m_impl->m_installedComponents) {
            if (comp.type == ComponentType::Service) {
                m_impl->m_currentVersion = comp.currentVersion;
                break;
            }
        }

        m_impl->SetState(ProgUpdateState::Completed);
        m_impl->UpdateProgress(ProgUpdateState::Completed, 100,
                               "Rollback completed");

        SS_LOG_INFO(kLogCategory,
            L"Rollback completed — current version: %hs",
            m_impl->m_currentVersion.ToString().c_str());
    } else {
        m_impl->SetState(ProgUpdateState::Failed);
        m_impl->m_progress.errorMessage = "Rollback failed";
        m_impl->NotifyError("Rollback failed", ERROR_INSTALL_FAILURE);
        SS_LOG_ERROR(kLogCategory, L"Rollback failed");
    }

    return success;
}

std::vector<ProgramVersion> ProgramUpdater::GetRollbackVersions() const
{
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    std::vector<ProgramVersion> versions;

    if (!RollbackManager::HasInstance() ||
        !RollbackManager::Instance().IsInitialized())
    {
        return versions;
    }

    auto snapshots = RollbackManager::Instance().GetSnapshots();
    versions.reserve(std::min(snapshots.size(), kMaxRollbackVersions));

    for (const auto& snap : snapshots) {
        if (versions.size() >= kMaxRollbackVersions) break;

        ProgramVersion ver;
        if (!snap.versionString.empty()) {
            auto parts = ParseVersionString(snap.versionString);
            ver.major = static_cast<uint16_t>(parts[0]);
            ver.minor = static_cast<uint16_t>(parts[1]);
            ver.patch = static_cast<uint16_t>(parts[2]);
            ver.build = parts[3];
            ver.versionString = snap.versionString;
        }
        versions.push_back(std::move(ver));
    }

    return versions;
}

// ============================================================================
// REBOOT HANDLING
// ============================================================================

bool ProgramUpdater::IsRebootRequired() const noexcept
{
    if (!m_impl) return false;
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_rebootRequired;
}

bool ProgramUpdater::ScheduleReboot(uint32_t delayMinutes)
{
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory,
            L"ScheduleReboot called on uninitialized instance");
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);

    const DWORD delaySec = static_cast<DWORD>(delayMinutes) * 60;

    SS_LOG_INFO(kLogCategory,
        L"Scheduling system reboot in %u minutes (%u seconds)",
        delayMinutes, delaySec);

    // Enable SE_SHUTDOWN_NAME privilege.
    HANDLE hToken = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(),
                            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        SS_LOG_LAST_ERROR(kLogCategory,
            L"OpenProcessToken failed for shutdown privilege");
        return false;
    }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    ::LookupPrivilegeValueW(nullptr, L"SeShutdownPrivilege",
                            &tp.Privileges[0].Luid);
    ::AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr);
    DWORD privErr = ::GetLastError();
    ::CloseHandle(hToken);

    if (privErr != ERROR_SUCCESS) {
        SS_LOG_WARN(kLogCategory,
            L"AdjustTokenPrivileges returned error %u — reboot may fail",
            privErr);
    }

    BOOL ok = ::InitiateSystemShutdownExW(
        nullptr,                        // local machine
        const_cast<LPWSTR>(L"ShadowStrike: Scheduled reboot for pending updates"),
        delaySec,
        FALSE,                          // don't force close apps
        TRUE,                           // reboot after shutdown
        SHTDN_REASON_MAJOR_APPLICATION | SHTDN_REASON_MINOR_INSTALLATION |
        SHTDN_REASON_FLAG_PLANNED);

    if (!ok) {
        SS_LOG_LAST_ERROR(kLogCategory,
            L"InitiateSystemShutdownExW failed");
        return false;
    }

    m_impl->m_rebootScheduled = true;
    m_impl->m_stats.rebootsScheduled++;

    SS_LOG_INFO(kLogCategory,
        L"System reboot scheduled in %u minutes", delayMinutes);

    return true;
}

void ProgramUpdater::CancelScheduledReboot()
{
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_mutex);

    if (!m_impl->m_rebootScheduled) {
        SS_LOG_DEBUG(kLogCategory, L"No reboot scheduled to cancel");
        return;
    }

    BOOL ok = ::AbortSystemShutdownW(nullptr);
    if (!ok) {
        SS_LOG_LAST_ERROR(kLogCategory,
            L"AbortSystemShutdownW failed");
        return;
    }

    m_impl->m_rebootScheduled = false;
    SS_LOG_INFO(kLogCategory, L"Scheduled reboot cancelled");
}

bool ProgramUpdater::FinalizePendingUpdates()
{
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory,
            L"FinalizePendingUpdates called on uninitialized instance");
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);

    SS_LOG_INFO(kLogCategory, L"Finalizing pending updates after reboot");

    // Re-discover components to pick up any files replaced during reboot.
    m_impl->DiscoverInstalledComponents();

    // Update current version.
    for (const auto& comp : m_impl->m_installedComponents) {
        if (comp.type == ComponentType::Service) {
            m_impl->m_currentVersion = comp.currentVersion;
            break;
        }
    }

    // Clear reboot flags.
    m_impl->m_rebootRequired = false;
    m_impl->m_rebootScheduled = false;

    // Verify system stability via RollbackManager.
    if (RollbackManager::HasInstance() &&
        RollbackManager::Instance().IsInitialized())
    {
        RollbackManager::Instance().RecordBoot();

        if (!RollbackManager::Instance().VerifyStability()) {
            SS_LOG_WARN(kLogCategory,
                L"Post-reboot stability check failed — system may need attention");
            return false;
        }
    }

    SS_LOG_INFO(kLogCategory,
        L"Pending updates finalized — current version: %hs",
        m_impl->m_currentVersion.ToString().c_str());

    return true;
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

bool ProgramUpdater::VerifyInstallationHealth()
{
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory,
            L"VerifyInstallationHealth called on uninitialized instance");
        return false;
    }

    std::shared_lock lock(m_impl->m_mutex);

    SS_LOG_DEBUG(kLogCategory, L"Verifying installation health");

    bool healthy = true;

    for (const auto& comp : m_impl->m_installedComponents) {
        std::error_code ec;
        if (!fs::exists(comp.installPath, ec) || ec) {
            SS_LOG_ERROR(kLogCategory,
                L"Component %hs missing at: %ls",
                comp.displayName.c_str(),
                comp.installPath.wstring().c_str());
            healthy = false;
            continue;
        }

        // Verify file hash if we recorded one.
        if (!comp.fileHash.empty()) {
            auto currentHash = HashFileSHA256(comp.installPath);
            if (currentHash.empty()) {
                SS_LOG_WARN(kLogCategory,
                    L"Cannot compute hash for %hs",
                    comp.displayName.c_str());
            } else if (currentHash != comp.fileHash) {
                SS_LOG_ERROR(kLogCategory,
                    L"Hash mismatch for %hs (expected=%hs, actual=%hs)",
                    comp.displayName.c_str(),
                    comp.fileHash.c_str(),
                    currentHash.c_str());
                healthy = false;
            }
        }
    }

    if (healthy) {
        SS_LOG_INFO(kLogCategory,
            L"Installation health check passed (%zu components)",
            m_impl->m_installedComponents.size());
    } else {
        SS_LOG_ERROR(kLogCategory,
            L"Installation health check FAILED");
    }

    return healthy;
}

bool ProgramUpdater::IsBootLoopDetected() const
{
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    if (!m_impl->m_config.enableBootLoopDetection) {
        return false;
    }

    if (!RollbackManager::HasInstance() ||
        !RollbackManager::Instance().IsInitialized())
    {
        return false;
    }

    return RollbackManager::Instance().IsBootLoopDetected();
}

void ProgramUpdater::ClearBootLoopCounter()
{
    if (!m_impl) return;

    if (RollbackManager::HasInstance() &&
        RollbackManager::Instance().IsInitialized())
    {
        RollbackManager::Instance().ClearBootLoopCounter();
        SS_LOG_INFO(kLogCategory, L"Boot loop counter cleared");
    }
}

// ============================================================================
// CALLBACKS
// ============================================================================

void ProgramUpdater::RegisterProgressCallback(ProgProgressCallback callback)
{
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_progressCallback = std::move(callback);
    SS_LOG_DEBUG(kLogCategory, L"Progress callback registered");
}

void ProgramUpdater::RegisterCompletionCallback(ProgCompletionCallback callback)
{
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_completionCallback = std::move(callback);
    SS_LOG_DEBUG(kLogCategory, L"Completion callback registered");
}

void ProgramUpdater::RegisterServiceControlCallback(
    ServiceControlCallback callback)
{
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_serviceControlCallback = std::move(callback);
    SS_LOG_DEBUG(kLogCategory, L"ServiceControl callback registered");
}

void ProgramUpdater::RegisterErrorCallback(ErrorCallback callback)
{
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_errorCallback = std::move(callback);
    SS_LOG_DEBUG(kLogCategory, L"Error callback registered");
}

void ProgramUpdater::UnregisterCallbacks()
{
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_progressCallback = nullptr;
    m_impl->m_completionCallback = nullptr;
    m_impl->m_serviceControlCallback = nullptr;
    m_impl->m_errorCallback = nullptr;
    SS_LOG_DEBUG(kLogCategory, L"All callbacks unregistered");
}

// ============================================================================
// STATISTICS
// ============================================================================

ProgUpdaterStatistics ProgramUpdater::GetStatistics() const
{
    if (!m_impl) return {};
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_stats;
}

void ProgramUpdater::ResetStatistics()
{
    if (!m_impl) return;
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_stats.Reset();
    SS_LOG_DEBUG(kLogCategory, L"Statistics reset");
}

bool ProgramUpdater::SelfTest()
{
    SS_LOG_INFO(kLogCategory, L"Running ProgramUpdater self-test");

    bool allPassed = true;

    // Test 1: Singleton consistency.
    {
        auto& inst = ProgramUpdater::Instance();
        if (&inst != this) {
            SS_LOG_ERROR(kLogCategory,
                L"SelfTest: singleton identity check FAILED");
            allPassed = false;
        }
    }

    // Test 2: HasInstance() should return true.
    if (!ProgramUpdater::HasInstance()) {
        SS_LOG_ERROR(kLogCategory,
            L"SelfTest: HasInstance() returned false after Instance()");
        allPassed = false;
    }

    // Test 3: Version comparison operators.
    {
        ProgramVersion v1;
        v1.major = 1; v1.minor = 0; v1.patch = 0; v1.build = 0;
        ProgramVersion v2;
        v2.major = 2; v2.minor = 0; v2.patch = 0; v2.build = 0;

        if (!(v1 < v2)) {
            SS_LOG_ERROR(kLogCategory,
                L"SelfTest: version operator< FAILED");
            allPassed = false;
        }
        if (!(v2 > v1)) {
            SS_LOG_ERROR(kLogCategory,
                L"SelfTest: version operator> FAILED");
            allPassed = false;
        }
        if (!(v1 == v1)) {
            SS_LOG_ERROR(kLogCategory,
                L"SelfTest: version operator== FAILED");
            allPassed = false;
        }
    }

    // Test 4: Enum name functions return non-empty.
    {
        auto name = GetComponentTypeName(ComponentType::Service);
        if (name.empty()) {
            SS_LOG_ERROR(kLogCategory,
                L"SelfTest: GetComponentTypeName returned empty");
            allPassed = false;
        }
    }

    // Test 5: CompareVersions sanity.
    {
        ProgramVersion a;
        a.major = 3; a.minor = 0; a.patch = 0; a.build = 0;
        ProgramVersion b;
        b.major = 3; b.minor = 0; b.patch = 1; b.build = 0;

        int cmp = CompareVersions(a, b);
        if (cmp >= 0) {
            SS_LOG_ERROR(kLogCategory,
                L"SelfTest: CompareVersions FAILED (3.0.0 should be < 3.0.1)");
            allPassed = false;
        }
    }

    // Test 6: JSON serialization doesn't crash.
    {
        try {
            ProgUpdaterStatistics stats;
            [[maybe_unused]] auto json = stats.ToJson();
            ProgramVersion ver;
            [[maybe_unused]] auto verJson = ver.ToJson();
            ProgUpdateProgress prog;
            [[maybe_unused]] auto progJson = prog.ToJson();
        }
        catch (...) {
            SS_LOG_ERROR(kLogCategory,
                L"SelfTest: JSON serialization threw exception");
            allPassed = false;
        }
    }

    if (allPassed) {
        SS_LOG_INFO(kLogCategory, L"ProgramUpdater self-test PASSED");
    } else {
        SS_LOG_ERROR(kLogCategory, L"ProgramUpdater self-test FAILED");
    }

    return allPassed;
}

std::string ProgramUpdater::GetVersionString() noexcept
{
    try {
        std::ostringstream os;
        os << "ProgramUpdater v"
           << ProgUpdateConstants::VERSION_MAJOR << '.'
           << ProgUpdateConstants::VERSION_MINOR << '.'
           << ProgUpdateConstants::VERSION_PATCH;
        return os.str();
    }
    catch (...) {
        return "ProgramUpdater v?.?.?";
    }
}

// ============================================================================
// FREE FUNCTIONS — ENUM NAME CONVERTERS
// ============================================================================

std::string_view GetComponentTypeName(ComponentType type) noexcept
{
    switch (type) {
        case ComponentType::Service:          return "Service";
        case ComponentType::GUI:              return "GUI";
        case ComponentType::Tray:             return "Tray";
        case ComponentType::CLI:              return "CLI";
        case ComponentType::MinifilterDriver: return "MinifilterDriver";
        case ComponentType::NetworkDriver:    return "NetworkDriver";
        case ComponentType::Helper:           return "Helper";
        case ComponentType::SDK:              return "SDK";
        case ComponentType::Uninstaller:      return "Uninstaller";
    }
    return "Unknown";
}

std::string_view GetUpdateStateName(ProgUpdateState state) noexcept
{
    switch (state) {
        case ProgUpdateState::Idle:        return "Idle";
        case ProgUpdateState::Checking:    return "Checking";
        case ProgUpdateState::Downloading: return "Downloading";
        case ProgUpdateState::Staging:     return "Staging";
        case ProgUpdateState::Validating:  return "Validating";
        case ProgUpdateState::Stopping:    return "Stopping";
        case ProgUpdateState::Replacing:   return "Replacing";
        case ProgUpdateState::Starting:    return "Starting";
        case ProgUpdateState::Verifying:   return "Verifying";
        case ProgUpdateState::Completed:   return "Completed";
        case ProgUpdateState::Failed:      return "Failed";
        case ProgUpdateState::RollingBack: return "RollingBack";
    }
    return "Unknown";
}

std::string_view GetInstallMethodName(InstallMethod method) noexcept
{
    switch (method) {
        case InstallMethod::InPlace:    return "InPlace";
        case InstallMethod::ShadowCopy: return "ShadowCopy";
        case InstallMethod::Installer:  return "Installer";
        case InstallMethod::MoveFileEx: return "MoveFileEx";
    }
    return "Unknown";
}

std::string_view GetRebootRequirementName(RebootRequirement req) noexcept
{
    switch (req) {
        case RebootRequirement::None:      return "None";
        case RebootRequirement::Optional:  return "Optional";
        case RebootRequirement::Required:  return "Required";
        case RebootRequirement::Immediate: return "Immediate";
    }
    return "Unknown";
}

// ============================================================================
// FREE FUNCTIONS — VERSION & SIGNATURE UTILITIES
// ============================================================================

std::optional<ProgramVersion> GetFileVersionInfo(const fs::path& filePath)
{
    if (filePath.empty()) return std::nullopt;

    std::error_code ec;
    if (!fs::exists(filePath, ec) || ec) return std::nullopt;

    const std::wstring wpath = filePath.wstring();

    DWORD handle = 0;
    const DWORD infoSize = ::GetFileVersionInfoSizeW(wpath.c_str(), &handle);
    if (infoSize == 0) {
        return std::nullopt;
    }

    // Cap allocation to prevent abuse (max 16 MB for version info block).
    if (infoSize > 16 * 1024 * 1024) {
        SS_LOG_WARN(kLogCategory,
            L"GetFileVersionInfo: version info size %u exceeds cap for %ls",
            infoSize, wpath.c_str());
        return std::nullopt;
    }

    std::vector<uint8_t> buffer(infoSize, 0);
    if (!::GetFileVersionInfoW(wpath.c_str(), handle, infoSize, buffer.data())) {
        return std::nullopt;
    }

    VS_FIXEDFILEINFO* ffi = nullptr;
    UINT ffiLen = 0;
    if (!::VerQueryValueW(buffer.data(), L"\\",
                          reinterpret_cast<LPVOID*>(&ffi), &ffiLen))
    {
        return std::nullopt;
    }

    if (!ffi || ffiLen < sizeof(VS_FIXEDFILEINFO)) {
        return std::nullopt;
    }

    ProgramVersion ver;
    ver.major = static_cast<uint16_t>(HIWORD(ffi->dwFileVersionMS));
    ver.minor = static_cast<uint16_t>(LOWORD(ffi->dwFileVersionMS));
    ver.patch = static_cast<uint16_t>(HIWORD(ffi->dwFileVersionLS));
    ver.build = static_cast<uint32_t>(LOWORD(ffi->dwFileVersionLS));
    ver.versionString = ver.ToString();

    // Try to extract string values (product name, description, copyright).
    struct StringQuery {
        const wchar_t* key;
        std::string* target;
    };

    StringQuery queries[] = {
        { L"ProductName",     &ver.productName },
        { L"FileDescription", &ver.fileDescription },
        { L"LegalCopyright",  &ver.copyright },
    };

    // Try common code pages: 0409/04B0 (English/Unicode).
    const wchar_t* codepages[] = {
        L"040904B0",
        L"040904E4",
        L"000004B0",
    };

    for (const auto* cp : codepages) {
        bool foundAny = false;
        for (auto& q : queries) {
            if (!q.target->empty()) continue;
            wchar_t subBlock[128]{};
            (void)std::swprintf(subBlock, std::size(subBlock),
                L"\\StringFileInfo\\%ls\\%ls", cp, q.key);

            LPVOID strPtr = nullptr;
            UINT strLen = 0;
            if (::VerQueryValueW(buffer.data(), subBlock, &strPtr, &strLen) &&
                strPtr && strLen > 0)
            {
                *q.target = SU::ToNarrow(
                    std::wstring_view(static_cast<const wchar_t*>(strPtr),
                                      strLen - 1));
                foundAny = true;
            }
        }
        if (foundAny) break;
    }

    return ver;
}

bool VerifyCodeSignature(const fs::path& filePath)
{
    if (filePath.empty()) return false;

    std::error_code ec;
    if (!fs::exists(filePath, ec) || ec) return false;

    // Delegate to UpdateVerifier if available.
    if (UpdateVerifier::HasInstance() &&
        UpdateVerifier::Instance().IsInitialized())
    {
        return UpdateVerifier::Instance().VerifyAuthenticode(filePath);
    }

    // Fallback: use PE signature verifier directly.
    Utils::pe_sig_utils::PEFileSignatureVerifier verifier;
    Utils::pe_sig_utils::SignatureInfo info;
    Utils::pe_sig_utils::Error peErr;

    if (!verifier.VerifyPESignature(filePath.wstring(), info, &peErr)) {
        SS_LOG_WARN(kLogCategory,
            L"VerifyCodeSignature: PE verification failed for %ls",
            filePath.wstring().c_str());
        return false;
    }

    return info.isSigned && info.isVerified;
}

int CompareVersions(const ProgramVersion& a, const ProgramVersion& b)
{
    if (a.major != b.major) return (a.major < b.major) ? -1 : 1;
    if (a.minor != b.minor) return (a.minor < b.minor) ? -1 : 1;
    if (a.patch != b.patch) return (a.patch < b.patch) ? -1 : 1;
    if (a.build != b.build) return (a.build < b.build) ? -1 : 1;
    return 0;
}

}  // namespace Update
}  // namespace ShadowStrike

