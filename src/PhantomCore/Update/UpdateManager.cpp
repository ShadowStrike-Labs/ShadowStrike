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

#include "UpdateManager.hpp"
#include "SignatureUpdater.hpp"
#include "ProgramUpdater.hpp"
#include "UpdateScheduler.hpp"
#include "UpdateVerifier.hpp"
#include "DeltaUpdater.hpp"
#include "RollbackManager.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"

#include <algorithm>
#include <charconv>
#include <format>
#include <sstream>

// ============================================================================
// ANONYMOUS NAMESPACE — helpers, constants
// ============================================================================

namespace {

constexpr const wchar_t* kLogCategory = L"UpdateMgr";

constexpr size_t kMaxCallbackCount  = 64;
constexpr size_t kMaxHistoryEntries = 10'000;
constexpr size_t kMaxAvailablePkgs  = 4096;

namespace HU = ::ShadowStrike::Utils::HashUtils;
namespace SU = ::ShadowStrike::Utils::StringUtils;
namespace FU = ::ShadowStrike::Utils::FileUtils;

// Reparse-point check used to refuse following symlinks/junctions in
// the configured staging directory.
[[nodiscard]] bool IsReparsePoint(const std::filesystem::path& p) noexcept {
    FU::FileStat st{};
    if (!FU::Stat(p.wstring(), st)) return false;
    return st.isReparsePoint;
}

// Map a coarse UpdateType to the matching SignatureDatabaseType for the
// signature-family. Returns nullopt if the type does not correspond to a
// signature database (e.g. Program, Driver, ...).
[[nodiscard]] std::optional<::ShadowStrike::Update::SignatureDatabaseType>
SignatureDbTypeFor(::ShadowStrike::Update::UpdateType type) noexcept
{
    using UT = ::ShadowStrike::Update::UpdateType;
    using DT = ::ShadowStrike::Update::SignatureDatabaseType;
    switch (type) {
    case UT::Signature:  return DT::Main;
    case UT::Heuristics: return DT::Heuristic;
    case UT::Whitelist:  return DT::URLs;     // closest semantic mapping
    case UT::Patterns:   return DT::Patterns;
    default:             return std::nullopt;
    }
}

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

[[nodiscard]] std::string JsonEscape(const std::string& s) noexcept {
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

[[nodiscard]] std::string BytesToHex(const std::vector<uint8_t>& v) noexcept {
    return HU::ToHexLower(v);
}

[[nodiscard]] std::string GenerateEntryId() noexcept {
    try {
        auto now = std::chrono::system_clock::now();
        auto epoch = now.time_since_epoch();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
        static std::atomic<uint64_t> s_counter{0};
        uint64_t seq = s_counter.fetch_add(1, std::memory_order_relaxed);
        return "upd-" + std::to_string(ms) + "-" + std::to_string(seq);
    }
    catch (...) { return "upd-unknown"; }
}

[[nodiscard]] std::string GeneratePackageId(
    ::ShadowStrike::Update::UpdateType type) noexcept
{
    try {
        auto now = std::chrono::system_clock::now();
        auto epoch = now.time_since_epoch();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
        return "pkg-" + std::string(::ShadowStrike::Update::GetUpdateTypeName(type))
            + "-" + std::to_string(ms);
    }
    catch (...) { return "pkg-unknown"; }
}

// Map UpdateType to whether it is a signature-family type.
[[nodiscard]] bool IsSignatureType(
    ::ShadowStrike::Update::UpdateType type) noexcept
{
    using UT = ::ShadowStrike::Update::UpdateType;
    switch (type) {
    case UT::Signature:
    case UT::Heuristics:
    case UT::Whitelist:
    case UT::Patterns:
        return true;
    default:
        return false;
    }
}

// Map UpdateType to whether it is a program-family type.
[[nodiscard]] bool IsProgramType(
    ::ShadowStrike::Update::UpdateType type) noexcept
{
    using UT = ::ShadowStrike::Update::UpdateType;
    switch (type) {
    case UT::Program:
    case UT::Driver:
    case UT::Engine:
        return true;
    default:
        return false;
    }
}

}  // anonymous namespace

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

namespace ShadowStrike {
namespace Update {

class UpdateManagerImpl {
public:
    ::ShadowStrike::Update::UpdateConfiguration    m_config;
    mutable std::shared_mutex      m_mutex;
    UpdateModuleStatus             m_moduleStatus{UpdateModuleStatus::Uninitialized};
    std::atomic<bool>              m_initialized{false};

    // Single-writer gate for ApplyPackageInternal — claimed via CAS so
    // two concurrent StartUpdate/StartAllUpdates calls cannot both enter
    // the apply path. m_status alone is not enough: the racy
    // IsUpdateInProgress()-then-apply pattern allows both callers to pass
    // the gate.
    std::atomic<bool>              m_applyInFlight{false};

    // Available packages discovered by last CheckForUpdates
    std::vector<UpdatePackage>     m_availablePackages;

    // Active download progress (packageId -> progress)
    std::map<std::string, DownloadProgress> m_downloadProgress;

    // Update history
    std::vector<UpdateHistoryEntry> m_history;

    // Pending reboot update types
    std::set<UpdateType>           m_pendingRebootTypes;

    // Statistics (plain uint64_t fields, guarded by m_mutex)
    UpdateStatistics               m_stats;

    // Callbacks
    StatusCallback                 m_statusCallback;
    ProgressCallback               m_progressCallback;
    CompletionCallback             m_completionCallback;
    AvailableCallback              m_availableCallback;
    ErrorCallback                  m_errorCallback;
    mutable std::mutex             m_callbackMutex;

    // ========================================================================
    // CALLBACK HELPERS
    // ========================================================================

    void NotifyStatus(UpdateStatus status) {
        std::lock_guard lock(m_callbackMutex);
        if (m_statusCallback) {
            try { m_statusCallback(status); }
            catch (...) { SS_LOG_WARN(kLogCategory, L"Status callback threw exception"); }
        }
    }

    void NotifyProgress(const DownloadProgress& progress) {
        std::lock_guard lock(m_callbackMutex);
        if (m_progressCallback) {
            try { m_progressCallback(progress); }
            catch (...) { SS_LOG_WARN(kLogCategory, L"Progress callback threw exception"); }
        }
    }

    void NotifyCompletion(const UpdateResult& result) {
        std::lock_guard lock(m_callbackMutex);
        if (m_completionCallback) {
            try { m_completionCallback(result); }
            catch (...) { SS_LOG_WARN(kLogCategory, L"Completion callback threw exception"); }
        }
    }

    void NotifyAvailable(const std::vector<UpdatePackage>& packages) {
        std::lock_guard lock(m_callbackMutex);
        if (m_availableCallback) {
            try { m_availableCallback(packages); }
            catch (...) { SS_LOG_WARN(kLogCategory, L"Available callback threw exception"); }
        }
    }

    void NotifyError(const std::string& message, int code) {
        std::lock_guard lock(m_callbackMutex);
        if (m_errorCallback) {
            try { m_errorCallback(message, code); }
            catch (...) { SS_LOG_WARN(kLogCategory, L"Error callback threw exception"); }
        }
    }

    // ========================================================================
    // HISTORY RECORDING
    // ========================================================================

    void RecordHistory(UpdateType type, const VersionInfo& version,
                       bool success, bool wasRollback, uint64_t sizeBytes,
                       uint32_t durationSec)
    {
        // Caller must hold exclusive lock on m_mutex.
        UpdateHistoryEntry entry;
        entry.entryId = GenerateEntryId();
        entry.type = type;
        entry.version = version;
        entry.appliedTime = std::chrono::system_clock::now();
        entry.success = success;
        entry.wasRollback = wasRollback;
        entry.size = sizeBytes;
        entry.durationSeconds = durationSec;

        if (m_history.size() >= kMaxHistoryEntries) {
            m_history.erase(m_history.begin());
        }
        m_history.push_back(std::move(entry));
    }

    // ========================================================================
    // SUB-MODULE INITIALIZATION HELPERS
    // ========================================================================

    [[nodiscard]] bool InitializeSubModules() {
        // Init order: Verifier -> Delta -> Rollback -> Scheduler -> Sig -> Prog
        SS_LOG_INFO(kLogCategory, L"Initializing UpdateVerifier sub-module");
        if (UpdateVerifier::HasInstance()) {
            auto& verifier = UpdateVerifier::Instance();
            if (!verifier.IsInitialized()) {
                if (!verifier.Initialize()) {
                    SS_LOG_ERROR(kLogCategory,
                        L"UpdateVerifier initialization failed");
                    return false;
                }
            }
        }

        SS_LOG_INFO(kLogCategory, L"Initializing DeltaUpdater sub-module");
        {
            auto& delta = DeltaUpdater::Instance();
            if (!delta.IsInitialized()) {
                if (!delta.Initialize()) {
                    SS_LOG_ERROR(kLogCategory,
                        L"DeltaUpdater initialization failed");
                    return false;
                }
            }
        }

        SS_LOG_INFO(kLogCategory, L"Initializing RollbackManager sub-module");
        {
            auto& rollback = RollbackManager::Instance();
            if (!rollback.IsInitialized()) {
                if (!rollback.Initialize()) {
                    SS_LOG_ERROR(kLogCategory,
                        L"RollbackManager initialization failed");
                    return false;
                }
            }
        }

        SS_LOG_INFO(kLogCategory, L"Initializing UpdateScheduler sub-module");
        {
            auto& scheduler = UpdateScheduler::Instance();
            if (!scheduler.IsInitialized()) {
                UpdateSchedulerConfiguration schedConfig;
                schedConfig.defaultIntervalHours = m_config.checkIntervalHours;
                schedConfig.enableGameModeRespect = m_config.deferDuringGaming;
                schedConfig.cpuDeferThreshold = m_config.cpuDeferThreshold;
                schedConfig.enableMeteredDetection = m_config.respectMeteredConnection;
                if (!scheduler.Initialize(schedConfig)) {
                    SS_LOG_ERROR(kLogCategory,
                        L"UpdateScheduler initialization failed");
                    return false;
                }
            }
        }

        SS_LOG_INFO(kLogCategory, L"Initializing SignatureUpdater sub-module");
        {
            auto& sigUpdater = SignatureUpdater::Instance();
            if (!sigUpdater.IsInitialized()) {
                SignatureUpdaterConfiguration sigConfig;

                // LEFT EMPTY WHEN WE HAVE NOTHING TO GIVE, so the sub-module's
                // own fallback can fire. Joining an empty path with a
                // subdirectory yields the RELATIVE path "signatures", which is
                // NOT empty - so it silently defeated the .empty() guard
                // SignatureUpdater already has and handed it a path that
                // resolves against the process working directory instead.
                if (!m_config.stagingDirectory.empty()) {
                    sigConfig.stagingDirectory =
                        m_config.stagingDirectory / "signatures";
                }
                if (!sigUpdater.Initialize(sigConfig)) {
                    SS_LOG_ERROR(kLogCategory,
                        L"SignatureUpdater initialization failed");
                    return false;
                }
            }
        }

        SS_LOG_INFO(kLogCategory, L"Initializing ProgramUpdater sub-module");
        {
            auto& progUpdater = ProgramUpdater::Instance();
            if (!progUpdater.IsInitialized()) {
                ProgramUpdaterConfiguration progConfig;

                // Same rule as SignatureUpdater above: an empty parent path must
                // stay empty rather than becoming the relative path "program".
                if (!m_config.stagingDirectory.empty()) {
                    progConfig.stagingDirectory =
                        m_config.stagingDirectory / "program";
                }
                if (!progUpdater.Initialize(progConfig)) {
                    SS_LOG_ERROR(kLogCategory,
                        L"ProgramUpdater initialization failed");
                    return false;
                }
            }
        }

        return true;
    }

    void ShutdownSubModules() {
        // Reverse order: Scheduler -> ProgramUpdater -> SignatureUpdater
        //                -> Rollback -> Delta -> Verifier
        SS_LOG_INFO(kLogCategory, L"Shutting down UpdateScheduler");
        if (UpdateScheduler::HasInstance()) {
            auto& scheduler = UpdateScheduler::Instance();
            if (scheduler.IsInitialized()) scheduler.Shutdown();
        }

        SS_LOG_INFO(kLogCategory, L"Shutting down ProgramUpdater");
        if (ProgramUpdater::HasInstance()) {
            auto& prog = ProgramUpdater::Instance();
            if (prog.IsInitialized()) prog.Shutdown();
        }

        SS_LOG_INFO(kLogCategory, L"Shutting down SignatureUpdater");
        if (SignatureUpdater::HasInstance()) {
            auto& sig = SignatureUpdater::Instance();
            if (sig.IsInitialized()) sig.Shutdown();
        }

        SS_LOG_INFO(kLogCategory, L"Shutting down RollbackManager");
        if (RollbackManager::HasInstance()) {
            auto& rollback = RollbackManager::Instance();
            if (rollback.IsInitialized()) rollback.Shutdown();
        }

        SS_LOG_INFO(kLogCategory, L"Shutting down DeltaUpdater");
        if (DeltaUpdater::HasInstance()) {
            auto& delta = DeltaUpdater::Instance();
            if (delta.IsInitialized()) delta.Shutdown();
        }

        SS_LOG_INFO(kLogCategory, L"Shutting down UpdateVerifier");
        if (UpdateVerifier::HasInstance()) {
            auto& verifier = UpdateVerifier::Instance();
            if (verifier.IsInitialized()) verifier.Shutdown();
        }
    }

    // ========================================================================
    // BUILD UpdatePackage FROM SIGNATURE CHECK
    // ========================================================================

    [[nodiscard]] std::vector<UpdatePackage> BuildSignaturePackages() {
        std::vector<UpdatePackage> result;
        if (!SignatureUpdater::HasInstance()) return result;

        auto& sigUpdater = SignatureUpdater::Instance();
        if (!sigUpdater.IsInitialized()) return result;

        auto sigPackages = sigUpdater.CheckForUpdates();
        result.reserve(sigPackages.size());

        for (const auto& sp : sigPackages) {
            if (result.size() >= kMaxAvailablePkgs) break;

            UpdatePackage pkg;
            pkg.packageId = sp.packageId;
            pkg.type = UpdateType::Signature;
            pkg.priority = sp.isMandatory ? UpdatePriority::Critical : UpdatePriority::Normal;

            // Map current version from sig updater
            auto dbVer = sigUpdater.GetDatabaseVersion(sp.type);
            pkg.currentVersion.major = static_cast<uint16_t>(dbVer.versionNumber >> 32);
            pkg.currentVersion.minor = static_cast<uint16_t>((dbVer.versionNumber >> 16) & 0xFFFF);
            pkg.currentVersion.patch = static_cast<uint16_t>(dbVer.versionNumber & 0xFFFF);
            pkg.currentVersion.versionString = dbVer.versionString;

            pkg.newVersion.versionString = sp.targetVersion.versionString;
            pkg.newVersion.major = static_cast<uint16_t>(sp.targetVersion.versionNumber >> 32);
            pkg.newVersion.minor = static_cast<uint16_t>((sp.targetVersion.versionNumber >> 16) & 0xFFFF);
            pkg.newVersion.patch = static_cast<uint16_t>(sp.targetVersion.versionNumber & 0xFFFF);

            pkg.packageSize = sp.downloadSize;
            pkg.downloadSize = sp.downloadSize;
            pkg.downloadUrl = sp.downloadUrl;
            pkg.isDelta = (sp.method == UpdateMethod::Delta);
            pkg.requiresReboot = false;
            pkg.isMandatory = sp.isMandatory;
            pkg.releaseNotes = sp.releaseNotes;

            result.push_back(std::move(pkg));
        }
        return result;
    }

    // ========================================================================
    // BUILD UpdatePackage FROM PROGRAM CHECK
    // ========================================================================

    [[nodiscard]] std::vector<UpdatePackage> BuildProgramPackages() {
        std::vector<UpdatePackage> result;
        if (!ProgramUpdater::HasInstance()) return result;

        auto& progUpdater = ProgramUpdater::Instance();
        if (!progUpdater.IsInitialized()) return result;

        auto progPkg = progUpdater.CheckForUpdate();
        if (!progPkg.has_value()) return result;

        UpdatePackage pkg;
        pkg.packageId = progPkg->packageId;
        pkg.type = UpdateType::Program;
        pkg.priority = progPkg->isMandatory ? UpdatePriority::Critical : UpdatePriority::High;

        auto curVer = progUpdater.GetCurrentVersion();
        pkg.currentVersion.major = curVer.major;
        pkg.currentVersion.minor = curVer.minor;
        pkg.currentVersion.patch = curVer.patch;
        pkg.currentVersion.build = curVer.build;
        pkg.currentVersion.versionString = curVer.versionString;

        pkg.newVersion.major = progPkg->newVersion.major;
        pkg.newVersion.minor = progPkg->newVersion.minor;
        pkg.newVersion.patch = progPkg->newVersion.patch;
        pkg.newVersion.build = progPkg->newVersion.build;
        pkg.newVersion.versionString = progPkg->newVersion.versionString;

        pkg.packageSize = progPkg->packageSize;
        pkg.downloadSize = progPkg->packageSize;
        pkg.downloadUrl = progPkg->downloadUrl;
        pkg.checksum = progPkg->checksum;
        pkg.signature = progPkg->signature;
        pkg.isDelta = false;
        pkg.requiresReboot = (progPkg->rebootRequirement != RebootRequirement::None);
        pkg.isMandatory = progPkg->isMandatory;
        pkg.releaseNotes = progPkg->releaseNotes;
        pkg.dependencies = progPkg->dependencies;

        result.push_back(std::move(pkg));
        return result;
    }

    // ========================================================================
    // APPLY A SINGLE UPDATE PACKAGE
    // ========================================================================

    [[nodiscard]] UpdateResult ApplyPackageInternal(const UpdatePackage& package,
                                                    std::atomic<UpdateStatus>& statusAtom)
    {
        UpdateResult result;
        result.type = package.type;
        result.oldVersion = package.currentVersion;
        result.newVersion = package.newVersion;
        const auto startTime = Clock::now();

        SS_LOG_INFO(kLogCategory, L"Applying update package '%S' type=%S",
            package.packageId.c_str(),
            std::string(GetUpdateTypeName(package.type)).c_str());

        // Create rollback snapshot before update
        if (RollbackManager::HasInstance()) {
            auto& rollback = RollbackManager::Instance();
            if (rollback.IsInitialized()) {
                SS_LOG_INFO(kLogCategory, L"Creating pre-update rollback snapshot");
                auto snapshotId = rollback.CreateSnapshot(
                    SnapshotType::Full,
                    "Pre-update snapshot for " + package.packageId);
                if (snapshotId.empty()) {
                    SS_LOG_WARN(kLogCategory,
                        L"Failed to create rollback snapshot; proceeding with update");
                }
            }
        }

        // Update download progress
        {
            DownloadProgress dp;
            dp.packageId = package.packageId;
            dp.state = DownloadState::Downloading;
            dp.totalBytes = package.downloadSize;
            dp.startTime = std::chrono::system_clock::now();
            std::unique_lock lk(m_mutex);
            m_downloadProgress[package.packageId] = dp;
        }

        statusAtom.store(UpdateStatus::Applying, std::memory_order_release);
        NotifyStatus(UpdateStatus::Applying);

        bool applySuccess = false;

        if (IsSignatureType(package.type)) {
            if (SignatureUpdater::HasInstance() &&
                SignatureUpdater::Instance().IsInitialized())
            {
                // Dispatch to the specific signature database matching
                // the package.type instead of running the entire enabled
                // set; otherwise a single-package Apply triggers updates
                // across unrelated databases.
                const auto dbType = SignatureDbTypeFor(package.type);
                if (!dbType.has_value()) {
                    result.errorMessage =
                        "No SignatureDatabaseType mapping for UpdateType " +
                        std::string(GetUpdateTypeName(package.type));
                    SS_LOG_ERROR(kLogCategory,
                        L"No db-type mapping for UpdateType %S",
                        std::string(GetUpdateTypeName(package.type)).c_str());
                    applySuccess = false;
                }
                else {
                    applySuccess = SignatureUpdater::Instance()
                                       .UpdateDatabase(*dbType);
                    if (!applySuccess) {
                        result.errorMessage =
                            "SignatureUpdater::UpdateDatabase failed for " +
                            std::string(GetUpdateTypeName(package.type));
                    }
                }
            }
            else {
                result.errorMessage = "SignatureUpdater not available";
                SS_LOG_ERROR(kLogCategory, L"SignatureUpdater not available for package '%S'",
                    package.packageId.c_str());
            }
        }
        else if (IsProgramType(package.type)) {
            if (ProgramUpdater::HasInstance() &&
                ProgramUpdater::Instance().IsInitialized())
            {
                applySuccess = ProgramUpdater::Instance().ApplyProgramUpdate();
            }
            else {
                result.errorMessage = "ProgramUpdater not available";
                SS_LOG_ERROR(kLogCategory, L"ProgramUpdater not available for package '%S'",
                    package.packageId.c_str());
            }
        }
        else {
            // Configuration / Emergency types — check staging directory
            SS_LOG_WARN(kLogCategory,
                L"No specific handler for update type %S; checking staging directory",
                std::string(GetUpdateTypeName(package.type)).c_str());

            std::error_code ec;

            // SECURITY: Reject packageId containing path separators or
            // traversal sequences to prevent zip-slip / path traversal.
            if (package.packageId.find('/') != std::string::npos ||
                package.packageId.find('\\') != std::string::npos ||
                package.packageId.find("..") != std::string::npos ||
                package.packageId.empty())
            {
                result.errorMessage = "Invalid packageId (path traversal rejected): "
                                      + package.packageId;
                SS_LOG_ERROR(kLogCategory,
                    L"SECURITY: Rejected packageId with path traversal: '%S'",
                    package.packageId.c_str());
            }
            else {
            auto stagingPath = m_config.stagingDirectory / package.packageId;

            // Defence-in-depth: enforce that the composed stagingPath
            // remains under m_config.stagingDirectory (lexical + symlink
            // resolution) and that it is not itself a reparse point.
            if (!FU::IsPathUnderRoot(stagingPath.wstring(),
                                     m_config.stagingDirectory.wstring(),
                                     true))
            {
                applySuccess = false;
                result.errorMessage =
                    "Staged path escapes staging directory: " + package.packageId;
                SS_LOG_ERROR(kLogCategory,
                    L"SECURITY: stagingPath '%s' escapes staging root for package '%S'",
                    stagingPath.wstring().c_str(),
                    package.packageId.c_str());
            }
            else if (fs::exists(stagingPath, ec) && !ec &&
                     IsReparsePoint(stagingPath))
            {
                applySuccess = false;
                result.errorMessage =
                    "Staged package is a reparse point: " + package.packageId;
                SS_LOG_ERROR(kLogCategory,
                    L"SECURITY: Refusing reparse-point staged package '%S'",
                    package.packageId.c_str());
            }
            else if (fs::exists(stagingPath, ec) && !ec) {
                // Verify if verifier is available
                if (UpdateVerifier::HasInstance() &&
                    UpdateVerifier::Instance().IsInitialized() &&
                    !package.signature.empty())
                {
                    applySuccess = UpdateVerifier::Instance().VerifyPackage(
                        stagingPath.wstring(), package.signature);
                    if (!applySuccess) {
                        result.errorMessage = "Package verification failed for " + package.packageId;
                        SS_LOG_ERROR(kLogCategory,
                            L"Verification failed for staged package '%S'",
                            package.packageId.c_str());
                    }
                }
                else {
                    // SECURITY: Refuse to install unverified packages.
                    // A missing verifier or absent signature is a supply-chain risk.
                    applySuccess = false;
                    result.errorMessage =
                        "Package rejected: cryptographic verification unavailable for "
                        + package.packageId;
                    SS_LOG_ERROR(kLogCategory,
                        L"SECURITY: Rejecting staged package '%S' — "
                        L"no verifier or no signature available",
                        package.packageId.c_str());
                }
            }
            else {
                result.errorMessage = "Staged package not found: " + package.packageId;
                SS_LOG_ERROR(kLogCategory,
                    L"Staged package '%S' not found in staging directory",
                    package.packageId.c_str());
            }
            } // end path-traversal-safe else
        }

        auto endTime = Clock::now();
        auto durationSec = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime).count());

        result.success = applySuccess;
        result.appliedTime = std::chrono::system_clock::now();
        result.requiresReboot = package.requiresReboot;

        // Update download progress to completed/failed
        {
            std::unique_lock lk(m_mutex);
            auto it = m_downloadProgress.find(package.packageId);
            if (it != m_downloadProgress.end()) {
                it->second.state = applySuccess ? DownloadState::Completed : DownloadState::Failed;
                it->second.bytesDownloaded = applySuccess ? package.downloadSize : 0;
                it->second.progressPercent = applySuccess ? 100 : 0;
                if (!applySuccess) {
                    it->second.errorMessage = result.errorMessage;
                }
            }

            // Record stats
            if (applySuccess) {
                m_stats.updatesApplied++;
                m_stats.bytesDownloaded += package.downloadSize;
                if (package.isDelta) m_stats.deltaUpdates++;
                auto idx = static_cast<size_t>(package.type);
                if (idx < m_stats.byUpdateType.size()) {
                    m_stats.byUpdateType[idx]++;
                }
                m_stats.lastUpdateTime = std::chrono::system_clock::now();

                if (package.requiresReboot) {
                    m_pendingRebootTypes.insert(package.type);
                }
            }
            else {
                m_stats.updatesFailed++;

                // Attempt rollback if applicable
                if (RollbackManager::HasInstance()) {
                    auto& rollback = RollbackManager::Instance();
                    if (rollback.IsInitialized() && rollback.CanRollback()) {
                        SS_LOG_WARN(kLogCategory,
                            L"Update failed for '%S'; triggering rollback",
                            package.packageId.c_str());
                        bool rollbackOk = rollback.TriggerRollback();
                        result.wasRollback = rollbackOk;
                        if (rollbackOk) {
                            m_stats.rollbacksPerformed++;
                            SS_LOG_INFO(kLogCategory,
                                L"Rollback succeeded for failed update '%S'",
                                package.packageId.c_str());
                        }
                        else {
                            SS_LOG_ERROR(kLogCategory,
                                L"Rollback also failed for '%S'",
                                package.packageId.c_str());
                        }
                    }
                }
            }

            // Record history
            RecordHistory(package.type, package.newVersion, applySuccess,
                          result.wasRollback, package.downloadSize, durationSec);
        }

        NotifyCompletion(result);
        return result;
    }
};

// ============================================================================
// STRUCT METHOD IMPLEMENTATIONS
// ============================================================================

// ----- VersionInfo -----

bool VersionInfo::operator<(const VersionInfo& other) const noexcept {
    if (major != other.major) return major < other.major;
    if (minor != other.minor) return minor < other.minor;
    if (patch != other.patch) return patch < other.patch;
    return build < other.build;
}

bool VersionInfo::operator>(const VersionInfo& other) const noexcept {
    return other < *this;
}

bool VersionInfo::operator==(const VersionInfo& other) const noexcept {
    return major == other.major && minor == other.minor &&
           patch == other.patch && build == other.build;
}

std::string VersionInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{\"major\":" << major
        << ",\"minor\":" << minor
        << ",\"patch\":" << patch
        << ",\"build\":" << build
        << ",\"versionString\":\"" << JsonEscape(versionString) << "\""
        << ",\"releaseDate\":\"" << FormatIso8601(releaseDate) << "\""
        << "}";
    return oss.str();
}

std::string VersionInfo::ToString() const {
    if (!versionString.empty()) return versionString;
    return std::to_string(major) + "." + std::to_string(minor) + "." +
           std::to_string(patch) + "." + std::to_string(build);
}

// ----- UpdatePackage -----

std::string UpdatePackage::ToJson() const {
    std::ostringstream oss;
    oss << "{\"packageId\":\"" << JsonEscape(packageId) << "\""
        << ",\"type\":\"" << GetUpdateTypeName(type) << "\""
        << ",\"priority\":\"" << GetPriorityName(priority) << "\""
        << ",\"currentVersion\":" << currentVersion.ToJson()
        << ",\"newVersion\":" << newVersion.ToJson()
        << ",\"packageSize\":" << packageSize
        << ",\"downloadSize\":" << downloadSize
        << ",\"downloadUrl\":\"" << JsonEscape(downloadUrl) << "\""
        << ",\"checksum\":\"" << JsonEscape(checksum) << "\""
        << ",\"isDelta\":" << (isDelta ? "true" : "false")
        << ",\"requiresReboot\":" << (requiresReboot ? "true" : "false")
        << ",\"isMandatory\":" << (isMandatory ? "true" : "false")
        << ",\"releaseNotes\":\"" << JsonEscape(releaseNotes) << "\""
        << "}";
    return oss.str();
}

// ----- DownloadProgress -----

std::string DownloadProgress::ToJson() const {
    std::ostringstream oss;
    oss << "{\"packageId\":\"" << JsonEscape(packageId) << "\""
        << ",\"state\":\"" << GetDownloadStateName(state) << "\""
        << ",\"bytesDownloaded\":" << bytesDownloaded
        << ",\"totalBytes\":" << totalBytes
        << ",\"progressPercent\":" << static_cast<int>(progressPercent)
        << ",\"speedBps\":" << speedBps
        << ",\"etaSeconds\":" << etaSeconds
        << ",\"startTime\":\"" << FormatIso8601(startTime) << "\""
        << ",\"retryCount\":" << retryCount
        << ",\"errorMessage\":\"" << JsonEscape(errorMessage) << "\""
        << "}";
    return oss.str();
}

// ----- UpdateResult -----

std::string UpdateResult::ToJson() const {
    std::ostringstream oss;
    oss << "{\"success\":" << (success ? "true" : "false")
        << ",\"type\":\"" << GetUpdateTypeName(type) << "\""
        << ",\"oldVersion\":" << oldVersion.ToJson()
        << ",\"newVersion\":" << newVersion.ToJson()
        << ",\"appliedTime\":\"" << FormatIso8601(appliedTime) << "\""
        << ",\"requiresReboot\":" << (requiresReboot ? "true" : "false")
        << ",\"wasRollback\":" << (wasRollback ? "true" : "false")
        << ",\"errorMessage\":\"" << JsonEscape(errorMessage) << "\""
        << "}";
    return oss.str();
}

// ----- UpdateHistoryEntry -----

std::string UpdateHistoryEntry::ToJson() const {
    std::ostringstream oss;
    oss << "{\"entryId\":\"" << JsonEscape(entryId) << "\""
        << ",\"type\":\"" << GetUpdateTypeName(type) << "\""
        << ",\"version\":" << version.ToJson()
        << ",\"appliedTime\":\"" << FormatIso8601(appliedTime) << "\""
        << ",\"success\":" << (success ? "true" : "false")
        << ",\"wasRollback\":" << (wasRollback ? "true" : "false")
        << ",\"size\":" << size
        << ",\"durationSeconds\":" << durationSeconds
        << "}";
    return oss.str();
}

// ----- UpdateStatistics -----

void UpdateStatistics::Reset() noexcept {
    checksPerformed = 0;
    updatesApplied = 0;
    updatesFailed = 0;
    rollbacksPerformed = 0;
    bytesDownloaded = 0;
    deltaUpdates = 0;
    byUpdateType.fill(0);
    startTime = Clock::now();
    lastCheckTime.reset();
    lastUpdateTime.reset();
}

std::string UpdateStatistics::ToJson() const {
    std::ostringstream oss;
    oss << "{\"checksPerformed\":" << checksPerformed
        << ",\"updatesApplied\":" << updatesApplied
        << ",\"updatesFailed\":" << updatesFailed
        << ",\"rollbacksPerformed\":" << rollbacksPerformed
        << ",\"bytesDownloaded\":" << bytesDownloaded
        << ",\"deltaUpdates\":" << deltaUpdates;

    oss << ",\"byUpdateType\":[";
    for (size_t i = 0; i < byUpdateType.size(); ++i) {
        if (i > 0) oss << ",";
        oss << byUpdateType[i];
    }
    oss << "]";

    if (lastCheckTime.has_value())
        oss << ",\"lastCheckTime\":\"" << FormatIso8601(*lastCheckTime) << "\"";
    else
        oss << ",\"lastCheckTime\":null";

    if (lastUpdateTime.has_value())
        oss << ",\"lastUpdateTime\":\"" << FormatIso8601(*lastUpdateTime) << "\"";
    else
        oss << ",\"lastUpdateTime\":null";

    oss << "}";
    return oss.str();
}

// ----- UpdateConfiguration -----

bool UpdateConfiguration::IsValid() const noexcept {
    if (checkIntervalHours == 0) return false;
    if (downloadTimeoutSeconds == 0) return false;
    if (maxRetryAttempts == 0) return false;
    return true;
}

// ============================================================================
// STATIC MEMBERS
// ============================================================================

std::atomic<bool> UpdateManager::s_instanceCreated{false};

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

UpdateManager::UpdateManager()
    : m_impl(std::make_unique<UpdateManagerImpl>())
{
    SS_LOG_TRACE(kLogCategory, L"UpdateManager instance constructed");
}

UpdateManager::~UpdateManager() {
    if (m_impl && m_impl->m_initialized.load(std::memory_order_acquire)) {
        Shutdown();
    }
    SS_LOG_TRACE(kLogCategory, L"UpdateManager instance destroyed");
}

// ============================================================================
// SINGLETON
// ============================================================================

UpdateManager& UpdateManager::Instance() noexcept {
    static UpdateManager s_instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return s_instance;
}

bool UpdateManager::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// LIFECYCLE
// ============================================================================

bool UpdateManager::Initialize(const ::ShadowStrike::Update::UpdateConfiguration& config) {
    if (m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(kLogCategory, L"UpdateManager already initialized");
        return true;
    }

    SS_LOG_INFO(kLogCategory, L"Initializing UpdateManager v%u.%u.%u",
        UpdateConstants::VERSION_MAJOR,
        UpdateConstants::VERSION_MINOR,
        UpdateConstants::VERSION_PATCH);

    {
        std::unique_lock lk(m_impl->m_mutex);
        m_impl->m_moduleStatus = UpdateModuleStatus::Initializing;
    }

    if (!config.IsValid()) {
        SS_LOG_ERROR(kLogCategory, L"Invalid UpdateConfiguration supplied");
        std::unique_lock lk(m_impl->m_mutex);
        m_impl->m_moduleStatus = UpdateModuleStatus::Error;
        return false;
    }

    {
        std::unique_lock lk(m_impl->m_mutex);
        m_impl->m_config = config;
    }

    // Ensure staging directory exists and refuse to follow reparse points.
    // A symlink/junction under stagingDirectory would let an attacker
    // redirect downloaded packages outside the controlled tree.
    if (!m_impl->m_config.stagingDirectory.empty()) {
        std::error_code ec;
        fs::create_directories(m_impl->m_config.stagingDirectory, ec);
        if (ec) {
            SS_LOG_WARN(kLogCategory,
                L"Could not create staging directory: %S", ec.message().c_str());
        }
        if (IsReparsePoint(m_impl->m_config.stagingDirectory)) {
            SS_LOG_ERROR(kLogCategory,
                L"Refusing to use staging directory '%s' (reparse point)",
                m_impl->m_config.stagingDirectory.wstring().c_str());
            std::unique_lock lk(m_impl->m_mutex);
            m_impl->m_moduleStatus = UpdateModuleStatus::Error;
            return false;
        }
    }

    // Initialize all sub-modules
    if (!m_impl->InitializeSubModules()) {
        SS_LOG_ERROR(kLogCategory, L"One or more sub-modules failed to initialize");
        // Tear down whatever sub-modules did come up so that we do not
        // leak partially-initialised singletons.
        m_impl->ShutdownSubModules();
        std::unique_lock lk(m_impl->m_mutex);
        m_impl->m_moduleStatus = UpdateModuleStatus::Error;
        return false;
    }

    {
        std::unique_lock lk(m_impl->m_mutex);
        m_impl->m_moduleStatus = UpdateModuleStatus::Running;
        m_impl->m_stats.startTime = Clock::now();
    }

    m_impl->m_initialized.store(true, std::memory_order_release);
    m_status.store(UpdateStatus::Idle, std::memory_order_release);

    SS_LOG_INFO(kLogCategory, L"UpdateManager initialized successfully");
    return true;
}

void UpdateManager::Shutdown() {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(kLogCategory, L"UpdateManager::Shutdown called but not initialized");
        return;
    }

    SS_LOG_INFO(kLogCategory, L"UpdateManager shutting down");

    {
        std::unique_lock lk(m_impl->m_mutex);
        m_impl->m_moduleStatus = UpdateModuleStatus::Stopping;
    }

    m_status.store(UpdateStatus::Idle, std::memory_order_release);
    m_impl->ShutdownSubModules();
    m_impl->m_initialized.store(false, std::memory_order_release);

    {
        std::unique_lock lk(m_impl->m_mutex);
        m_impl->m_moduleStatus = UpdateModuleStatus::Stopped;
        m_impl->m_availablePackages.clear();
        m_impl->m_downloadProgress.clear();
    }

    SS_LOG_INFO(kLogCategory, L"UpdateManager shutdown complete");
}

bool UpdateManager::IsInitialized() const noexcept {
    return m_impl->m_initialized.load(std::memory_order_acquire);
}

UpdateModuleStatus UpdateManager::GetModuleStatus() const noexcept {
    std::shared_lock lk(m_impl->m_mutex);
    return m_impl->m_moduleStatus;
}

bool UpdateManager::UpdateConfiguration(const ::ShadowStrike::Update::UpdateConfiguration& config) {
    if (!config.IsValid()) {
        SS_LOG_ERROR(kLogCategory, L"Invalid UpdateConfiguration in reconfigure");
        return false;
    }

    std::unique_lock lk(m_impl->m_mutex);
    m_impl->m_config = config;

    SS_LOG_INFO(kLogCategory, L"UpdateManager configuration updated");

    // Propagate interval to scheduler if active
    if (UpdateScheduler::HasInstance() &&
        UpdateScheduler::Instance().IsInitialized())
    {
        UpdateScheduler::Instance().SetInterval(
            std::chrono::hours(config.checkIntervalHours));
    }

    return true;
}

struct UpdateConfiguration UpdateManager::GetConfiguration() const {
    std::shared_lock lk(m_impl->m_mutex);
    return m_impl->m_config;
}

// ============================================================================
// UPDATE OPERATIONS
// ============================================================================

void UpdateManager::CheckForUpdates() {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory, L"CheckForUpdates called but UpdateManager not initialized");
        return;
    }

    SS_LOG_INFO(kLogCategory, L"Checking for updates (all types)");
    m_status.store(UpdateStatus::Checking, std::memory_order_release);
    m_impl->NotifyStatus(UpdateStatus::Checking);

    std::vector<UpdatePackage> merged;

    // Signature-family packages
    try {
        auto sigPkgs = m_impl->BuildSignaturePackages();
        merged.insert(merged.end(),
            std::make_move_iterator(sigPkgs.begin()),
            std::make_move_iterator(sigPkgs.end()));
    }
    catch (const std::exception& ex) {
        SS_LOG_ERROR(kLogCategory,
            L"Exception building signature packages: %S", ex.what());
        m_impl->NotifyError("Signature check failed: " + std::string(ex.what()), -10);
    }

    // Program-family packages
    try {
        auto progPkgs = m_impl->BuildProgramPackages();
        merged.insert(merged.end(),
            std::make_move_iterator(progPkgs.begin()),
            std::make_move_iterator(progPkgs.end()));
    }
    catch (const std::exception& ex) {
        SS_LOG_ERROR(kLogCategory,
            L"Exception building program packages: %S", ex.what());
        m_impl->NotifyError("Program check failed: " + std::string(ex.what()), -11);
    }

    // Sort by priority (highest first)
    std::sort(merged.begin(), merged.end(),
        [](const UpdatePackage& a, const UpdatePackage& b) {
            return static_cast<uint8_t>(a.priority) > static_cast<uint8_t>(b.priority);
        });

    {
        std::unique_lock lk(m_impl->m_mutex);
        m_impl->m_availablePackages = merged;
        m_impl->m_stats.checksPerformed++;
        m_impl->m_stats.lastCheckTime = std::chrono::system_clock::now();
    }

    if (merged.empty()) {
        SS_LOG_INFO(kLogCategory, L"No updates available");
        m_status.store(UpdateStatus::Idle, std::memory_order_release);
    }
    else {
        SS_LOG_INFO(kLogCategory, L"Found %zu available update(s)", merged.size());
        m_status.store(UpdateStatus::Available, std::memory_order_release);
    }

    m_impl->NotifyAvailable(merged);
    m_impl->NotifyStatus(m_status.load(std::memory_order_acquire));
}

std::future<std::vector<UpdatePackage>> UpdateManager::CheckForUpdatesAsync() {
    return std::async(std::launch::async, [this]() -> std::vector<UpdatePackage> {
        CheckForUpdates();
        std::shared_lock lk(m_impl->m_mutex);
        return m_impl->m_availablePackages;
    });
}

std::optional<UpdatePackage> UpdateManager::CheckForUpdate(UpdateType type) {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory,
            L"CheckForUpdate called but UpdateManager not initialized");
        return std::nullopt;
    }

    SS_LOG_INFO(kLogCategory, L"Checking for updates of type %S",
        std::string(GetUpdateTypeName(type)).c_str());

    if (IsSignatureType(type)) {
        auto sigPkgs = m_impl->BuildSignaturePackages();
        for (auto& pkg : sigPkgs) {
            // Match by type mapping
            if (pkg.type == type) return std::move(pkg);
        }
        // Signature types may map to UpdateType::Signature generically
        if (!sigPkgs.empty() && type == UpdateType::Signature)
            return std::move(sigPkgs.front());
    }
    else if (IsProgramType(type)) {
        auto progPkgs = m_impl->BuildProgramPackages();
        if (!progPkgs.empty()) return std::move(progPkgs.front());
    }
    else {
        // For Configuration / Emergency, check staging directory
        SS_LOG_INFO(kLogCategory,
            L"No transport configured for remote check of type %S; "
            L"checking local staging directory",
            std::string(GetUpdateTypeName(type)).c_str());

        std::error_code ec;
        auto stagingDir = m_impl->m_config.stagingDirectory;
        if (!stagingDir.empty() && fs::exists(stagingDir, ec) && !ec) {
            // Refuse to follow a symlink/junction at stagingDir to avoid
            // enumerating a directory outside the controlled tree.
            if (IsReparsePoint(stagingDir)) {
                SS_LOG_ERROR(kLogCategory,
                    L"CheckForUpdate: staging directory '%s' is a reparse point",
                    stagingDir.wstring().c_str());
                return std::nullopt;
            }
            for (const auto& entry : fs::directory_iterator(stagingDir, ec)) {
                if (ec) break;
                if (!entry.is_regular_file(ec)) continue;
                // Convention: staged files named with type prefix
                auto filename = entry.path().stem().string();
                auto typeName = std::string(GetUpdateTypeName(type));
                if (filename.find(typeName) == 0) {
                    UpdatePackage pkg;
                    pkg.packageId = GeneratePackageId(type);
                    pkg.type = type;
                    pkg.priority = (type == UpdateType::Emergency)
                        ? UpdatePriority::Emergency : UpdatePriority::Normal;
                    pkg.packageSize = entry.file_size(ec);
                    pkg.downloadSize = pkg.packageSize;
                    return pkg;
                }
            }
        }
    }

    {
        std::unique_lock lk(m_impl->m_mutex);
        m_impl->m_stats.checksPerformed++;
        m_impl->m_stats.lastCheckTime = std::chrono::system_clock::now();
    }

    return std::nullopt;
}

bool UpdateManager::StartUpdate() {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory, L"StartUpdate called but not initialized");
        return false;
    }

    std::shared_lock lk(m_impl->m_mutex);
    if (m_impl->m_availablePackages.empty()) {
        SS_LOG_WARN(kLogCategory, L"StartUpdate called with no available packages");
        return false;
    }

    // Start the first (highest priority) package
    auto pkg = m_impl->m_availablePackages.front();
    lk.unlock();

    return StartUpdate(pkg.packageId);
}

bool UpdateManager::StartUpdate(const std::string& packageId) {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory, L"StartUpdate(packageId) called but not initialized");
        return false;
    }

    // Claim the apply-slot atomically. If another caller is already in
    // ApplyPackageInternal we refuse rather than racing them through it.
    bool expected = false;
    if (!m_impl->m_applyInFlight.compare_exchange_strong(
            expected, true,
            std::memory_order_acq_rel, std::memory_order_acquire))
    {
        SS_LOG_WARN(kLogCategory,
            L"StartUpdate('%S') rejected: another update is already applying",
            packageId.c_str());
        return false;
    }
    // RAII release of the slot on any exit path.
    struct ApplyGuard {
        std::atomic<bool>& flag;
        ~ApplyGuard() { flag.store(false, std::memory_order_release); }
    } guard{m_impl->m_applyInFlight};

    if (IsUpdateInProgress()) {
        SS_LOG_WARN(kLogCategory,
            L"StartUpdate('%S') rejected: update already in progress",
            packageId.c_str());
        return false;
    }

    UpdatePackage target;
    bool found = false;
    {
        std::shared_lock lk(m_impl->m_mutex);
        for (const auto& pkg : m_impl->m_availablePackages) {
            if (pkg.packageId == packageId) {
                target = pkg;
                found = true;
                break;
            }
        }
    }

    if (!found) {
        SS_LOG_ERROR(kLogCategory, L"Package '%S' not found in available updates",
            packageId.c_str());
        return false;
    }

    auto result = m_impl->ApplyPackageInternal(target, m_status);

    if (result.success) {
        if (result.requiresReboot) {
            m_status.store(UpdateStatus::RebootRequired, std::memory_order_release);
        }
        else {
            m_status.store(UpdateStatus::Completed, std::memory_order_release);
        }
    }
    else {
        m_status.store(result.wasRollback ? UpdateStatus::RollingBack : UpdateStatus::Failed,
            std::memory_order_release);
    }

    m_impl->NotifyStatus(m_status.load(std::memory_order_acquire));

    // Remove from available packages
    {
        std::unique_lock lk(m_impl->m_mutex);
        auto& avail = m_impl->m_availablePackages;
        avail.erase(
            std::remove_if(avail.begin(), avail.end(),
                [&packageId](const UpdatePackage& p) { return p.packageId == packageId; }),
            avail.end());
    }

    return result.success;
}

bool UpdateManager::StartAllUpdates() {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory, L"StartAllUpdates called but not initialized");
        return false;
    }

    // Claim the apply-slot atomically for the entire batch. This avoids
    // a race where two concurrent StartAllUpdates / StartUpdate callers
    // each iterate the package list and both pass IsUpdateInProgress().
    bool expected = false;
    if (!m_impl->m_applyInFlight.compare_exchange_strong(
            expected, true,
            std::memory_order_acq_rel, std::memory_order_acquire))
    {
        SS_LOG_WARN(kLogCategory,
            L"StartAllUpdates rejected: another update is already applying");
        return false;
    }
    struct ApplyGuard {
        std::atomic<bool>& flag;
        ~ApplyGuard() { flag.store(false, std::memory_order_release); }
    } guard{m_impl->m_applyInFlight};

    std::vector<UpdatePackage> packages;
    {
        std::shared_lock lk(m_impl->m_mutex);
        packages = m_impl->m_availablePackages;
    }

    if (packages.empty()) {
        SS_LOG_INFO(kLogCategory, L"StartAllUpdates: no packages to apply");
        return true;
    }

    SS_LOG_INFO(kLogCategory, L"Applying all %zu available updates", packages.size());

    bool allSuccess = true;
    bool anyReboot = false;

    for (const auto& pkg : packages) {
        if (IsUpdateInProgress()) {
            SS_LOG_WARN(kLogCategory,
                L"Skipping package '%S': concurrent update in progress",
                pkg.packageId.c_str());
            continue;
        }

        auto result = m_impl->ApplyPackageInternal(pkg, m_status);
        if (!result.success) {
            allSuccess = false;
            SS_LOG_ERROR(kLogCategory,
                L"Update '%S' failed: %S",
                pkg.packageId.c_str(), result.errorMessage.c_str());
        }
        if (result.requiresReboot) anyReboot = true;
    }

    // Clear applied packages from available
    {
        std::unique_lock lk(m_impl->m_mutex);
        m_impl->m_availablePackages.clear();
    }

    if (anyReboot) {
        m_status.store(UpdateStatus::RebootRequired, std::memory_order_release);
    }
    else if (allSuccess) {
        m_status.store(UpdateStatus::Completed, std::memory_order_release);
    }
    else {
        m_status.store(UpdateStatus::Failed, std::memory_order_release);
    }

    m_impl->NotifyStatus(m_status.load(std::memory_order_acquire));
    return allSuccess;
}

void UpdateManager::PauseUpdate() {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) return;

    SS_LOG_INFO(kLogCategory, L"PauseUpdate requested");

    // Delegate to sub-modules that support pausing
    if (UpdateScheduler::HasInstance() &&
        UpdateScheduler::Instance().IsInitialized())
    {
        UpdateScheduler::Instance().Pause();
    }

    {
        std::unique_lock lk(m_impl->m_mutex);
        for (auto& [id, dp] : m_impl->m_downloadProgress) {
            if (dp.state == DownloadState::Downloading) {
                dp.state = DownloadState::Paused;
            }
        }
        m_impl->m_moduleStatus = UpdateModuleStatus::Paused;
    }
}

void UpdateManager::ResumeUpdate() {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) return;

    SS_LOG_INFO(kLogCategory, L"ResumeUpdate requested");

    if (UpdateScheduler::HasInstance() &&
        UpdateScheduler::Instance().IsInitialized())
    {
        UpdateScheduler::Instance().Resume();
    }

    {
        std::unique_lock lk(m_impl->m_mutex);
        for (auto& [id, dp] : m_impl->m_downloadProgress) {
            if (dp.state == DownloadState::Paused) {
                dp.state = DownloadState::Downloading;
            }
        }
        m_impl->m_moduleStatus = UpdateModuleStatus::Running;
    }
}

void UpdateManager::CancelUpdate() {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) return;

    SS_LOG_INFO(kLogCategory, L"CancelUpdate requested");

    // Delegate cancellation
    if (SignatureUpdater::HasInstance() &&
        SignatureUpdater::Instance().IsInitialized() &&
        SignatureUpdater::Instance().IsUpdating())
    {
        SS_LOG_INFO(kLogCategory, L"Cancelling SignatureUpdater in-progress update");
        // SignatureUpdater has no explicit cancel; log the limitation
        SS_LOG_WARN(kLogCategory,
            L"SignatureUpdater does not expose CancelUpdate; update will complete");
    }

    if (ProgramUpdater::HasInstance() &&
        ProgramUpdater::Instance().IsInitialized() &&
        ProgramUpdater::Instance().IsUpdateInProgress())
    {
        ProgramUpdater::Instance().CancelUpdate();
    }

    {
        std::unique_lock lk(m_impl->m_mutex);
        for (auto& [id, dp] : m_impl->m_downloadProgress) {
            if (dp.state == DownloadState::Downloading ||
                dp.state == DownloadState::Paused)
            {
                dp.state = DownloadState::Cancelled;
            }
        }
    }

    m_status.store(UpdateStatus::Idle, std::memory_order_release);
    m_impl->NotifyStatus(UpdateStatus::Idle);
}

UpdateStatus UpdateManager::GetStatus() const noexcept {
    return m_status.load(std::memory_order_acquire);
}

bool UpdateManager::IsUpdateInProgress() const noexcept {
    auto status = m_status.load(std::memory_order_acquire);
    switch (status) {
    case UpdateStatus::Downloading:
    case UpdateStatus::Verifying:
    case UpdateStatus::Staging:
    case UpdateStatus::Applying:
    case UpdateStatus::RollingBack:
        return true;
    default:
        return false;
    }
}

// ============================================================================
// VERSION INFORMATION
// ============================================================================

VersionInfo UpdateManager::GetCurrentVersion(UpdateType type) const {
    VersionInfo ver;

    if (IsSignatureType(type)) {
        if (SignatureUpdater::HasInstance() &&
            SignatureUpdater::Instance().IsInitialized())
        {
            auto verStr = SignatureUpdater::Instance().GetCurrentVersion();
            ver.versionString = verStr;
            // Parse version string for components
            auto parsed = ParseVersionString(verStr);
            if (parsed.has_value()) {
                ver = *parsed;
            }
        }
    }
    else if (IsProgramType(type)) {
        if (ProgramUpdater::HasInstance() &&
            ProgramUpdater::Instance().IsInitialized())
        {
            auto pv = ProgramUpdater::Instance().GetCurrentVersion();
            ver.major = pv.major;
            ver.minor = pv.minor;
            ver.patch = pv.patch;
            ver.build = pv.build;
            ver.versionString = pv.versionString;
        }
    }
    else {
        // Module-level version
        ver.major = UpdateConstants::VERSION_MAJOR;
        ver.minor = UpdateConstants::VERSION_MINOR;
        ver.patch = UpdateConstants::VERSION_PATCH;
        ver.versionString = GetVersionString();
    }

    return ver;
}

std::map<UpdateType, VersionInfo> UpdateManager::GetAllCurrentVersions() const {
    std::map<UpdateType, VersionInfo> versions;

    // Query signature version
    versions[UpdateType::Signature] = GetCurrentVersion(UpdateType::Signature);
    versions[UpdateType::Program] = GetCurrentVersion(UpdateType::Program);
    versions[UpdateType::Driver] = GetCurrentVersion(UpdateType::Driver);
    versions[UpdateType::Engine] = GetCurrentVersion(UpdateType::Engine);
    versions[UpdateType::Configuration] = GetCurrentVersion(UpdateType::Configuration);
    versions[UpdateType::Heuristics] = GetCurrentVersion(UpdateType::Heuristics);
    versions[UpdateType::Whitelist] = GetCurrentVersion(UpdateType::Whitelist);
    versions[UpdateType::Patterns] = GetCurrentVersion(UpdateType::Patterns);
    versions[UpdateType::Emergency] = GetCurrentVersion(UpdateType::Emergency);

    return versions;
}

std::vector<UpdatePackage> UpdateManager::GetAvailableUpdates() const {
    std::shared_lock lk(m_impl->m_mutex);
    return m_impl->m_availablePackages;
}

bool UpdateManager::HasPendingUpdates() const noexcept {
    std::shared_lock lk(m_impl->m_mutex);
    return !m_impl->m_availablePackages.empty();
}

// ============================================================================
// DOWNLOAD MANAGEMENT
// ============================================================================

std::optional<DownloadProgress> UpdateManager::GetDownloadProgress() const {
    std::shared_lock lk(m_impl->m_mutex);
    if (m_impl->m_downloadProgress.empty()) return std::nullopt;
    // Return the first active download
    for (const auto& [id, dp] : m_impl->m_downloadProgress) {
        if (dp.state == DownloadState::Downloading ||
            dp.state == DownloadState::Connecting ||
            dp.state == DownloadState::Paused)
        {
            return dp;
        }
    }
    // Return most recent entry
    return m_impl->m_downloadProgress.rbegin()->second;
}

std::vector<DownloadProgress> UpdateManager::GetAllDownloadProgress() const {
    std::shared_lock lk(m_impl->m_mutex);
    std::vector<DownloadProgress> result;
    result.reserve(m_impl->m_downloadProgress.size());
    for (const auto& [id, dp] : m_impl->m_downloadProgress) {
        result.push_back(dp);
    }
    return result;
}

// ============================================================================
// HISTORY
// ============================================================================

std::vector<UpdateHistoryEntry> UpdateManager::GetUpdateHistory(
    size_t limit,
    std::optional<UpdateType> filterType) const
{
    std::shared_lock lk(m_impl->m_mutex);

    std::vector<UpdateHistoryEntry> result;
    result.reserve(std::min(limit, m_impl->m_history.size()));

    // Iterate from newest to oldest
    for (auto it = m_impl->m_history.rbegin();
         it != m_impl->m_history.rend() && result.size() < limit;
         ++it)
    {
        if (filterType.has_value() && it->type != *filterType) continue;
        result.push_back(*it);
    }

    return result;
}

std::optional<SystemTimePoint> UpdateManager::GetLastUpdateTime(UpdateType type) const {
    std::shared_lock lk(m_impl->m_mutex);

    // Search from newest to oldest
    for (auto it = m_impl->m_history.rbegin();
         it != m_impl->m_history.rend(); ++it)
    {
        if (it->type == type && it->success) {
            return it->appliedTime;
        }
    }
    return std::nullopt;
}

std::optional<SystemTimePoint> UpdateManager::GetLastCheckTime() const {
    std::shared_lock lk(m_impl->m_mutex);
    return m_impl->m_stats.lastCheckTime;
}

// ============================================================================
// REBOOT HANDLING
// ============================================================================

bool UpdateManager::IsRebootRequired() const noexcept {
    // Check own state
    if (m_status.load(std::memory_order_acquire) == UpdateStatus::RebootRequired)
        return true;

    // Check ProgramUpdater
    if (ProgramUpdater::HasInstance() &&
        ProgramUpdater::Instance().IsInitialized())
    {
        if (ProgramUpdater::Instance().IsRebootRequired()) return true;
    }

    std::shared_lock lk(m_impl->m_mutex);
    return !m_impl->m_pendingRebootTypes.empty();
}

std::vector<UpdateType> UpdateManager::GetPendingRebootUpdates() const {
    std::shared_lock lk(m_impl->m_mutex);
    std::vector<UpdateType> result(m_impl->m_pendingRebootTypes.begin(),
                                    m_impl->m_pendingRebootTypes.end());
    return result;
}

bool UpdateManager::FinalizePendingUpdates() {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory,
            L"FinalizePendingUpdates called but not initialized");
        return false;
    }

    SS_LOG_INFO(kLogCategory, L"Finalizing pending updates after reboot");

    bool success = true;

    // Delegate to ProgramUpdater
    if (ProgramUpdater::HasInstance() &&
        ProgramUpdater::Instance().IsInitialized())
    {
        if (!ProgramUpdater::Instance().FinalizePendingUpdates()) {
            SS_LOG_ERROR(kLogCategory,
                L"ProgramUpdater::FinalizePendingUpdates failed");
            success = false;
        }
    }

    // Validate system health after finalization
    if (RollbackManager::HasInstance() &&
        RollbackManager::Instance().IsInitialized())
    {
        auto& rollback = RollbackManager::Instance();
        rollback.RecordBoot();

        if (rollback.IsBootLoopDetected()) {
            SS_LOG_ERROR(kLogCategory,
                L"Boot loop detected after update finalization; triggering rollback");
            (void)rollback.TriggerRollback();
            success = false;
        }
        else {
            // Mark as stable
            rollback.BackupCurrentVersion();
        }
    }

    {
        std::unique_lock lk(m_impl->m_mutex);
        m_impl->m_pendingRebootTypes.clear();
    }

    m_status.store(success ? UpdateStatus::Completed : UpdateStatus::Failed,
        std::memory_order_release);

    SS_LOG_INFO(kLogCategory, L"FinalizePendingUpdates completed; success=%s",
        success ? L"true" : L"false");
    return success;
}

// ============================================================================
// CALLBACKS
// ============================================================================

void UpdateManager::RegisterStatusCallback(StatusCallback callback) {
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_statusCallback = std::move(callback);
    SS_LOG_DEBUG(kLogCategory, L"Status callback registered");
}

void UpdateManager::RegisterProgressCallback(ProgressCallback callback) {
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_progressCallback = std::move(callback);
    SS_LOG_DEBUG(kLogCategory, L"Progress callback registered");
}

void UpdateManager::RegisterCompletionCallback(CompletionCallback callback) {
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_completionCallback = std::move(callback);
    SS_LOG_DEBUG(kLogCategory, L"Completion callback registered");
}

void UpdateManager::RegisterAvailableCallback(AvailableCallback callback) {
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_availableCallback = std::move(callback);
    SS_LOG_DEBUG(kLogCategory, L"Available callback registered");
}

void UpdateManager::RegisterErrorCallback(Update::ErrorCallback callback) {
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_errorCallback = std::move(callback);
    SS_LOG_DEBUG(kLogCategory, L"Error callback registered");
}

void UpdateManager::UnregisterCallbacks() {
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_statusCallback = nullptr;
    m_impl->m_progressCallback = nullptr;
    m_impl->m_completionCallback = nullptr;
    m_impl->m_availableCallback = nullptr;
    m_impl->m_errorCallback = nullptr;
    SS_LOG_DEBUG(kLogCategory, L"All callbacks unregistered");
}

// ============================================================================
// STATISTICS
// ============================================================================

UpdateStatistics UpdateManager::GetStatistics() const {
    std::shared_lock lk(m_impl->m_mutex);
    return m_impl->m_stats;
}

void UpdateManager::ResetStatistics() {
    std::unique_lock lk(m_impl->m_mutex);
    m_impl->m_stats.Reset();
    SS_LOG_INFO(kLogCategory, L"Statistics reset");
}

bool UpdateManager::SelfTest() {
    SS_LOG_INFO(kLogCategory, L"Running UpdateManager self-test");

    bool allOk = true;

    // Verify all sub-modules are reachable
    if (!UpdateVerifier::HasInstance() ||
        !UpdateVerifier::Instance().IsInitialized())
    {
        SS_LOG_WARN(kLogCategory, L"Self-test: UpdateVerifier not initialized");
        allOk = false;
    }
    else {
        if (!UpdateVerifier::Instance().SelfTest()) {
            SS_LOG_WARN(kLogCategory, L"Self-test: UpdateVerifier self-test failed");
            allOk = false;
        }
    }

    if (!DeltaUpdater::HasInstance() ||
        !DeltaUpdater::Instance().IsInitialized())
    {
        SS_LOG_WARN(kLogCategory, L"Self-test: DeltaUpdater not initialized");
        allOk = false;
    }
    else {
        if (!DeltaUpdater::Instance().SelfTest()) {
            SS_LOG_WARN(kLogCategory, L"Self-test: DeltaUpdater self-test failed");
            allOk = false;
        }
    }

    if (!RollbackManager::HasInstance() ||
        !RollbackManager::Instance().IsInitialized())
    {
        SS_LOG_WARN(kLogCategory, L"Self-test: RollbackManager not initialized");
        allOk = false;
    }
    else {
        if (!RollbackManager::Instance().SelfTest()) {
            SS_LOG_WARN(kLogCategory, L"Self-test: RollbackManager self-test failed");
            allOk = false;
        }
    }

    if (!UpdateScheduler::HasInstance() ||
        !UpdateScheduler::Instance().IsInitialized())
    {
        SS_LOG_WARN(kLogCategory, L"Self-test: UpdateScheduler not initialized");
        allOk = false;
    }
    else {
        if (!UpdateScheduler::Instance().SelfTest()) {
            SS_LOG_WARN(kLogCategory, L"Self-test: UpdateScheduler self-test failed");
            allOk = false;
        }
    }

    if (!SignatureUpdater::HasInstance() ||
        !SignatureUpdater::Instance().IsInitialized())
    {
        SS_LOG_WARN(kLogCategory, L"Self-test: SignatureUpdater not initialized");
        allOk = false;
    }
    else {
        if (!SignatureUpdater::Instance().SelfTest()) {
            SS_LOG_WARN(kLogCategory, L"Self-test: SignatureUpdater self-test failed");
            allOk = false;
        }
    }

    if (!ProgramUpdater::HasInstance() ||
        !ProgramUpdater::Instance().IsInitialized())
    {
        SS_LOG_WARN(kLogCategory, L"Self-test: ProgramUpdater not initialized");
        allOk = false;
    }
    else {
        if (!ProgramUpdater::Instance().SelfTest()) {
            SS_LOG_WARN(kLogCategory, L"Self-test: ProgramUpdater self-test failed");
            allOk = false;
        }
    }

    // Verify staging directory is accessible
    {
        std::shared_lock lk(m_impl->m_mutex);
        if (!m_impl->m_config.stagingDirectory.empty()) {
            std::error_code ec;
            if (!fs::exists(m_impl->m_config.stagingDirectory, ec) || ec) {
                SS_LOG_WARN(kLogCategory,
                    L"Self-test: staging directory inaccessible");
                allOk = false;
            }
        }
    }

    SS_LOG_INFO(kLogCategory, L"Self-test %s", allOk ? L"passed" : L"failed");
    return allOk;
}

std::string UpdateManager::GetVersionString() noexcept {
    return std::to_string(UpdateConstants::VERSION_MAJOR) + "." +
           std::to_string(UpdateConstants::VERSION_MINOR) + "." +
           std::to_string(UpdateConstants::VERSION_PATCH);
}

// ============================================================================
// FREE (UTILITY) FUNCTIONS
// ============================================================================

std::string_view GetStatusName(UpdateStatus status) noexcept {
    switch (status) {
    case UpdateStatus::Idle:            return "Idle";
    case UpdateStatus::Checking:        return "Checking";
    case UpdateStatus::Available:       return "Available";
    case UpdateStatus::Downloading:     return "Downloading";
    case UpdateStatus::Verifying:       return "Verifying";
    case UpdateStatus::Staging:         return "Staging";
    case UpdateStatus::Applying:        return "Applying";
    case UpdateStatus::RebootRequired:  return "RebootRequired";
    case UpdateStatus::Completed:       return "Completed";
    case UpdateStatus::RollingBack:     return "RollingBack";
    case UpdateStatus::Failed:          return "Failed";
    case UpdateStatus::Error:           return "Error";
    default:                            return "Unknown";
    }
}

std::string_view GetUpdateTypeName(UpdateType type) noexcept {
    switch (type) {
    case UpdateType::Signature:         return "Signature";
    case UpdateType::Program:           return "Program";
    case UpdateType::Driver:            return "Driver";
    case UpdateType::Configuration:     return "Configuration";
    case UpdateType::Engine:            return "Engine";
    case UpdateType::Heuristics:        return "Heuristics";
    case UpdateType::Whitelist:         return "Whitelist";
    case UpdateType::Patterns:          return "Patterns";
    case UpdateType::Emergency:         return "Emergency";
    default:                            return "Unknown";
    }
}

std::string_view GetPriorityName(UpdatePriority priority) noexcept {
    switch (priority) {
    case UpdatePriority::Low:           return "Low";
    case UpdatePriority::Normal:        return "Normal";
    case UpdatePriority::High:          return "High";
    case UpdatePriority::Critical:      return "Critical";
    case UpdatePriority::Emergency:     return "Emergency";
    default:                            return "Unknown";
    }
}

std::string_view GetChannelName(UpdateChannel channel) noexcept {
    switch (channel) {
    case UpdateChannel::Stable:         return "Stable";
    case UpdateChannel::Beta:           return "Beta";
    case UpdateChannel::Canary:         return "Canary";
    case UpdateChannel::Developer:      return "Developer";
    case UpdateChannel::Enterprise:     return "Enterprise";
    default:                            return "Unknown";
    }
}

std::string_view GetDownloadStateName(DownloadState state) noexcept {
    switch (state) {
    case DownloadState::NotStarted:     return "NotStarted";
    case DownloadState::Connecting:     return "Connecting";
    case DownloadState::Downloading:    return "Downloading";
    case DownloadState::Paused:         return "Paused";
    case DownloadState::Completed:      return "Completed";
    case DownloadState::Failed:         return "Failed";
    case DownloadState::Cancelled:      return "Cancelled";
    default:                            return "Unknown";
    }
}

std::optional<VersionInfo> ParseVersionString(const std::string& version) {
    if (version.empty()) return std::nullopt;

    VersionInfo vi;
    vi.versionString = version;

    // Parse "major.minor.patch.build" or "major.minor.patch"
    uint32_t components[4] = {0, 0, 0, 0};
    size_t idx = 0;
    const char* ptr = version.c_str();

    for (size_t i = 0; i < 4 && ptr && *ptr; ++i) {
        auto [p, ec] = std::from_chars(ptr, version.c_str() + version.size(),
                                        components[i]);
        if (ec != std::errc{}) break;
        idx = i + 1;
        if (p && *p == '.') {
            ptr = p + 1;
        }
        else {
            break;
        }
    }

    if (idx == 0) return std::nullopt;

    vi.major = static_cast<uint16_t>(components[0]);
    vi.minor = static_cast<uint16_t>(components[1]);
    vi.patch = static_cast<uint16_t>(components[2]);
    vi.build = components[3];

    return vi;
}

int CompareVersions(const VersionInfo& a, const VersionInfo& b) {
    if (a.major != b.major) return (a.major < b.major) ? -1 : 1;
    if (a.minor != b.minor) return (a.minor < b.minor) ? -1 : 1;
    if (a.patch != b.patch) return (a.patch < b.patch) ? -1 : 1;
    if (a.build != b.build) return (a.build < b.build) ? -1 : 1;
    return 0;
}

std::string FormatDownloadSize(uint64_t bytes) {
    if (bytes == 0) return "0 B";

    constexpr uint64_t KB = 1024;
    constexpr uint64_t MB = 1024 * KB;
    constexpr uint64_t GB = 1024 * MB;

    char buf[64]{};
    if (bytes >= GB) {
        std::snprintf(buf, sizeof(buf), "%.2f GB",
            static_cast<double>(bytes) / static_cast<double>(GB));
    }
    else if (bytes >= MB) {
        std::snprintf(buf, sizeof(buf), "%.2f MB",
            static_cast<double>(bytes) / static_cast<double>(MB));
    }
    else if (bytes >= KB) {
        std::snprintf(buf, sizeof(buf), "%.1f KB",
            static_cast<double>(bytes) / static_cast<double>(KB));
    }
    else {
        std::snprintf(buf, sizeof(buf), "%llu B",
            static_cast<unsigned long long>(bytes));
    }
    return std::string(buf);
}

}  // namespace Update
}  // namespace ShadowStrike

