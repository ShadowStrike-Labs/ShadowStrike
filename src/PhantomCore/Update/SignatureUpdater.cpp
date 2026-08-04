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

#include "SignatureUpdater.hpp"
#include "UpdateVerifier.hpp"
#include "DeltaUpdater.hpp"
#include "RollbackManager.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/DataStorePaths.hpp"

#include <algorithm>
#include <charconv>
#include <deque>
#include <format>
#include <queue>
#include <sstream>

// ============================================================================
// ANONYMOUS NAMESPACE — helpers, constants
// ============================================================================

namespace {

constexpr const wchar_t* kLogCategory = L"SigUpdater";

constexpr uint64_t kMaxDatabaseFileSize = 2ULL * 1024 * 1024 * 1024;  // 2 GiB
constexpr uint64_t kMaxPackageSize      = 1ULL * 1024 * 1024 * 1024;  // 1 GiB
constexpr size_t   kMaxBackupCount      = 32;
constexpr size_t   kMaxCallbackCount    = 64;

namespace HU = ::ShadowStrike::Utils::HashUtils;
namespace FU = ::ShadowStrike::Utils::FileUtils;

// Reparse-point check used to refuse following symlinks/junctions in
// trusted database / staging / backup roots.
[[nodiscard]] bool IsReparsePoint(const std::filesystem::path& p) noexcept {
    FU::FileStat st{};
    if (!FU::Stat(p.wstring(), st)) return false;
    return st.isReparsePoint;
}

// Validate a single path-component identifier that came from an
// untrusted package manifest (e.g. DeltaPatchInfo::patchId). Rejects
// any value that could escape the staging directory or break filesystem
// invariants on Windows.
[[nodiscard]] bool IsSafePatchId(const std::string& id) noexcept {
    if (id.empty() || id.size() > 256) return false;
    for (const unsigned char c : id) {
        if (c < 0x20) return false;
        switch (c) {
        case '/': case '\\': case ':': case '*': case '?':
        case '"': case '<':  case '>': case '|':
            return false;
        default: break;
        }
    }
    if (id == "." || id == "..") return false;
    return true;
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

// Convert bytes vector to hex lowercase.
[[nodiscard]] std::string BytesToHex(const std::vector<uint8_t>& v) noexcept {
    return HU::ToHexLower(v);
}

// Compute SHA-256 hex of a file.
[[nodiscard]] std::optional<std::string> HashFileSha256(
    const std::filesystem::path& filePath) noexcept
{
    std::vector<uint8_t> digest;
    if (!HU::ComputeFile(HU::Algorithm::SHA256,
                         filePath.wstring(), digest)) {
        return std::nullopt;
    }
    return HU::ToHexLower(digest);
}

}  // anonymous namespace

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

namespace ShadowStrike {
namespace Update {

class SignatureUpdaterImpl {
public:
    SignatureUpdaterConfiguration   m_config;
    mutable std::shared_mutex      m_mutex;
    SigUpdaterStatus               m_status{SigUpdaterStatus::Uninitialized};
    std::atomic<bool>              m_initialized{false};

    // Current state machine
    SigUpdateState                 m_updateState{SigUpdateState::Idle};

    // Per-database version tracking
    std::map<SignatureDatabaseType, DatabaseVersion> m_versions;

    // Per-database progress
    std::map<SignatureDatabaseType, SigUpdateProgress> m_progress;

    // Loaded database flags
    std::set<SignatureDatabaseType> m_loadedDatabases;

    // Backup storage: type -> list of backup versions (newest first)
    std::map<SignatureDatabaseType, std::vector<DatabaseVersion>> m_backups;

    // Statistics (plain uint64_t fields, guarded by m_mutex)
    SigUpdaterStatistics m_stats;

    // Callbacks
    SigProgressCallback    m_progressCallback;
    SigCompletionCallback  m_completionCallback;
    SigReloadCallback      m_reloadCallback;
    ErrorCallback          m_errorCallback;
    mutable std::mutex     m_callbackMutex;

    // ========================================================================
    // CALLBACK HELPERS
    // ========================================================================

    void NotifyProgress(const SigUpdateProgress& progress) {
        std::lock_guard lock(m_callbackMutex);
        if (m_progressCallback) {
            try { m_progressCallback(progress); }
            catch (...) { SS_LOG_WARN(kLogCategory, L"Progress callback threw exception"); }
        }
    }

    void NotifyCompletion(const SigUpdateResult& result) {
        std::lock_guard lock(m_callbackMutex);
        if (m_completionCallback) {
            try { m_completionCallback(result); }
            catch (...) { SS_LOG_WARN(kLogCategory, L"Completion callback threw exception"); }
        }
    }

    void NotifyReload(SignatureDatabaseType type) {
        std::lock_guard lock(m_callbackMutex);
        if (m_reloadCallback) {
            try { m_reloadCallback(type); }
            catch (...) { SS_LOG_WARN(kLogCategory, L"Reload callback threw exception"); }
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
    // STATE MACHINE
    // ========================================================================

    void TransitionState(SigUpdateState newState) {
        // Caller must hold exclusive lock on m_mutex.
        SS_LOG_DEBUG(kLogCategory, L"State transition: %S -> %S",
            std::string(GetUpdateStateName(m_updateState)).c_str(),
            std::string(GetUpdateStateName(newState)).c_str());
        m_updateState = newState;
    }

    // ========================================================================
    // PROGRESS UPDATE
    // ========================================================================

    void UpdateProgress(SignatureDatabaseType type, SigUpdateState state,
                        uint8_t pct, const std::string& operation,
                        uint64_t bytesDown = 0, uint64_t totalBytes = 0)
    {
        SigUpdateProgress prog;
        prog.type = type;
        prog.state = state;
        prog.progressPercent = pct;
        prog.currentOperation = operation;
        prog.bytesDownloaded = bytesDown;
        prog.totalBytes = totalBytes;

        {
            // m_mutex should already be held by caller or we take it
            // For progress map updates we hold exclusive.
            m_progress[type] = prog;
        }
        NotifyProgress(prog);
    }

    // ========================================================================
    // PATH HELPERS
    // ========================================================================

    [[nodiscard]] fs::path GetDatabasePath(SignatureDatabaseType type) const {
        auto ext = GetDatabaseExtension(type);
        auto name = GetDatabaseTypeName(type);
        return m_config.databaseDirectory /
               (std::string(name) + std::string(ext));
    }

    [[nodiscard]] fs::path GetBackupDir(SignatureDatabaseType type,
                                         uint32_t index) const {
        auto name = GetDatabaseTypeName(type);
        return m_config.databaseDirectory / "backups" /
               (std::string(name) + "_" + std::to_string(index));
    }

    [[nodiscard]] fs::path GetStagingPath(SignatureDatabaseType type) const {
        auto name = GetDatabaseTypeName(type);
        auto ext = GetDatabaseExtension(type);
        return m_config.stagingDirectory /
               (std::string(name) + "_staging" + std::string(ext));
    }

    // ========================================================================
    // DATABASE OPERATIONS
    // ========================================================================

    [[nodiscard]] bool LoadDatabaseVersion(SignatureDatabaseType type) {
        // Read version metadata from the database file's sidecar .ver file
        auto dbPath = GetDatabasePath(type);
        auto verPath = dbPath;
        verPath += ".ver";

        std::error_code ec;
        if (!fs::exists(dbPath, ec) || ec) {
            SS_LOG_DEBUG(kLogCategory, L"Database file does not exist for type %S",
                std::string(GetDatabaseTypeName(type)).c_str());
            return false;
        }

        DatabaseVersion ver;
        ver.type = type;
        ver.sizeBytes = fs::file_size(dbPath, ec);
        if (ec) ver.sizeBytes = 0;

        // Compute checksum
        auto hashOpt = HashFileSha256(dbPath);
        if (hashOpt) {
            ver.checksum = *hashOpt;
        }

        // Try to read version metadata from .ver sidecar
        if (fs::exists(verPath, ec) && !ec) {
            std::string content;
            if (FU::ReadAllTextUtf8(verPath.wstring(), content)) {
                // Minimal parse: first line = version number, second = version string
                std::istringstream iss(content);
                std::string line;
                if (std::getline(iss, line)) {
                    auto result = std::from_chars(line.data(),
                        line.data() + line.size(), ver.versionNumber);
                    (void)result;
                }
                if (std::getline(iss, line)) {
                    ver.versionString = line;
                }
                if (std::getline(iss, line)) {
                    uint64_t sigCount = 0;
                    auto result = std::from_chars(line.data(),
                        line.data() + line.size(), sigCount);
                    (void)result;
                    ver.signatureCount = sigCount;
                }
            }
        }

        m_versions[type] = ver;
        m_loadedDatabases.insert(type);
        return true;
    }

    [[nodiscard]] bool WriteVersionSidecar(SignatureDatabaseType type,
                                            const DatabaseVersion& ver) {
        auto dbPath = GetDatabasePath(type);
        auto verPath = dbPath;
        verPath += ".ver";

        std::ostringstream oss;
        oss << ver.versionNumber << "\n"
            << ver.versionString << "\n"
            << ver.signatureCount << "\n";

        return FU::WriteAllTextUtf8Atomic(verPath.wstring(), oss.str());
    }

    // ========================================================================
    // APPLY SINGLE PACKAGE
    // ========================================================================

    [[nodiscard]] SigUpdateResult ApplyPackageInternal(
        const SignaturePackage& package)
    {
        SigUpdateResult result;
        result.type = package.type;
        result.methodUsed = package.method;
        const auto startTime = Clock::now();

        // Snapshot old version
        {
            auto it = m_versions.find(package.type);
            if (it != m_versions.end()) {
                result.oldVersion = it->second;
            }
        }

        result.newVersion = package.targetVersion;

        // -- Monotonicity / downgrade defence ---------------------------------
        // We refuse any package whose targetVersion.versionNumber is not
        // strictly greater than the currently-installed version, unless
        // no version is currently installed (oldVersion.versionNumber == 0
        // AND the package type was not in m_versions). This blocks the
        // classic "ship a stale, but still validly-signed, signature pack
        // to disarm detection" attack.
        if (result.oldVersion.versionNumber != 0 &&
            package.targetVersion.versionNumber <= result.oldVersion.versionNumber)
        {
            result.errorMessage =
                "Refusing downgrade: targetVersion (" +
                std::to_string(package.targetVersion.versionNumber) +
                ") <= currentVersion (" +
                std::to_string(result.oldVersion.versionNumber) + ")";
            result.success = false;
            m_stats.updatesFailed++;
            SS_LOG_ERROR(kLogCategory,
                L"Downgrade rejected for type %S: %llu -> %llu",
                std::string(GetDatabaseTypeName(package.type)).c_str(),
                static_cast<unsigned long long>(result.oldVersion.versionNumber),
                static_cast<unsigned long long>(package.targetVersion.versionNumber));
            NotifyError(result.errorMessage, -14);
            return result;
        }

        auto dbPath = GetDatabasePath(package.type);
        auto stagingPath = GetStagingPath(package.type);

        // -- Reparse-point defence on trusted roots ---------------------------
        // The database and staging roots are configured at Initialize-time
        // but could be mutated on disk between calls; refuse to operate if
        // either has been replaced by a junction/symlink.
        if (IsReparsePoint(m_config.databaseDirectory) ||
            IsReparsePoint(m_config.stagingDirectory))
        {
            result.errorMessage =
                "Database or staging directory is a reparse point";
            result.success = false;
            m_stats.updatesFailed++;
            SS_LOG_ERROR(kLogCategory,
                L"Refusing update: reparse point detected on trusted root");
            NotifyError(result.errorMessage, -15);
            return result;
        }

        // --- State: Checking ---
        TransitionState(SigUpdateState::Checking);
        UpdateProgress(package.type, SigUpdateState::Checking, 5,
            "Validating package metadata");

        if (package.packageId.empty()) {
            result.errorMessage = "Empty package ID";
            result.success = false;
            m_stats.updatesFailed++;
            NotifyError(result.errorMessage, -1);
            return result;
        }

        // --- State: Downloading (local staging) ---
        TransitionState(SigUpdateState::Downloading);
        UpdateProgress(package.type, SigUpdateState::Downloading, 10,
            "Preparing local staging");

        // No network transport is wired in, and that is deliberate rather than an
        // oversight: package authentication is not provisioned yet (see
        // UpdateVerifier::VerifySignature - no update-signing trust anchor is
        // loaded, so every signature check fails closed). Downloading definition
        // packages we cannot authenticate would be worse than not downloading
        // them, because a poisoned definition set can disable detection or cause
        // mass false positives across every endpoint at once. The transport must
        // stay absent until signing is in place.
        if (!package.downloadUrl.empty()) {
            SS_LOG_WARN(kLogCategory,
                L"Update for %S declares a download URL but no network transport "
                L"is enabled; expecting the package in the local staging "
                L"directory. Remote updates require a provisioned signing trust "
                L"anchor first - definitions that cannot be authenticated are not "
                L"safe to install.",
                std::string(GetDatabaseTypeName(package.type)).c_str());
        }

        // Check if staging file exists
        std::error_code ec;
        bool stagingExists = fs::exists(stagingPath, ec) && !ec;

        // --- State: Patching ---
        TransitionState(SigUpdateState::Patching);
        UpdateProgress(package.type, SigUpdateState::Patching, 30,
            "Applying update");

        if (package.method == UpdateMethod::Delta && !package.deltaPatches.empty()) {
            // Apply delta chain
            fs::path currentSource = dbPath;

            for (size_t i = 0; i < package.deltaPatches.size(); ++i) {
                const auto& patch = package.deltaPatches[i];

                // Untrusted: patchId comes from the package manifest and
                // is used as a path component. Reject anything that could
                // escape stagingDirectory or break Windows path rules.
                if (!IsSafePatchId(patch.patchId)) {
                    result.errorMessage =
                        "Unsafe delta patch identifier: " + patch.patchId;
                    result.success = false;
                    m_stats.updatesFailed++;
                    SS_LOG_ERROR(kLogCategory,
                        L"Rejected delta patch id (path traversal / invalid chars)");
                    NotifyError(result.errorMessage, -2);
                    return result;
                }

                auto patchFile = m_config.stagingDirectory / patch.patchId;

                // Final containment check after lexical composition.
                if (!FU::IsPathUnderRoot(patchFile.wstring(),
                        m_config.stagingDirectory.wstring(), true))
                {
                    result.errorMessage =
                        "Delta patch path escapes staging directory: " + patch.patchId;
                    result.success = false;
                    m_stats.updatesFailed++;
                    SS_LOG_ERROR(kLogCategory,
                        L"Delta patch path escapes staging root");
                    NotifyError(result.errorMessage, -2);
                    return result;
                }

                if (!fs::exists(patchFile, ec) || ec) {
                    result.errorMessage = "Delta patch file missing: " + patch.patchId;
                    result.success = false;
                    m_stats.updatesFailed++;
                    NotifyError(result.errorMessage, -2);
                    return result;
                }

                if (IsReparsePoint(patchFile)) {
                    result.errorMessage =
                        "Delta patch file is a reparse point: " + patch.patchId;
                    result.success = false;
                    m_stats.updatesFailed++;
                    SS_LOG_ERROR(kLogCategory,
                        L"Delta patch file is a reparse point — rejected");
                    NotifyError(result.errorMessage, -2);
                    return result;
                }

                // Per-patch size cap (defence-in-depth — fail fast before
                // engaging the delta engine on attacker-sized inputs).
                const auto patchSz = fs::file_size(patchFile, ec);
                if (ec || patchSz == 0 || patchSz > kMaxPackageSize) {
                    result.errorMessage =
                        "Delta patch file size invalid or exceeds cap: " + patch.patchId;
                    result.success = false;
                    m_stats.updatesFailed++;
                    SS_LOG_ERROR(kLogCategory,
                        L"Delta patch size invalid (size=%llu, cap=%llu)",
                        static_cast<unsigned long long>(patchSz),
                        static_cast<unsigned long long>(kMaxPackageSize));
                    NotifyError(result.errorMessage, -2);
                    return result;
                }

                // Validate patch
                if (DeltaUpdater::HasInstance() &&
                    DeltaUpdater::Instance().IsInitialized())
                {
                    if (!DeltaUpdater::Instance().ValidatePatch(patchFile)) {
                        result.errorMessage = "Delta patch validation failed: " + patch.patchId;
                        result.success = false;
                        m_stats.updatesFailed++;
                        NotifyError(result.errorMessage, -3);
                        return result;
                    }
                }

                fs::path outputFile = m_config.stagingDirectory /
                    ("delta_out_" + std::to_string(i) + std::string(GetDatabaseExtension(package.type)));

                if (DeltaUpdater::HasInstance() &&
                    DeltaUpdater::Instance().IsInitialized())
                {
                    auto patchResult = DeltaUpdater::Instance().ApplyPatchFile(
                        currentSource, patchFile, outputFile);
                    if (!patchResult.success) {
                        result.errorMessage = "Delta patch application failed at step " +
                            std::to_string(i) + ": " + patchResult.errorMessage;
                        result.success = false;
                        m_stats.updatesFailed++;
                        NotifyError(result.errorMessage, -4);
                        return result;
                    }
                    result.bytesDownloaded += patch.patchSize;
                }
                else {
                    result.errorMessage = "DeltaUpdater not available";
                    result.success = false;
                    m_stats.updatesFailed++;
                    NotifyError(result.errorMessage, -5);
                    return result;
                }

                // Chain: output of this patch is source for next
                currentSource = outputFile;

                uint8_t pct = static_cast<uint8_t>(
                    30 + (40 * (i + 1)) / package.deltaPatches.size());
                UpdateProgress(package.type, SigUpdateState::Patching, pct,
                    "Applied delta " + std::to_string(i + 1) + "/" +
                    std::to_string(package.deltaPatches.size()));
            }

            // Move final delta output to staging path
            fs::rename(currentSource, stagingPath, ec);
            if (ec) {
                // Fallback: copy and remove
                fs::copy_file(currentSource, stagingPath,
                    fs::copy_options::overwrite_existing, ec);
                if (ec) {
                    result.errorMessage = "Failed to stage delta result: " + ec.message();
                    result.success = false;
                    m_stats.updatesFailed++;
                    NotifyError(result.errorMessage, -6);
                    return result;
                }
                fs::remove(currentSource, ec);
            }

            m_stats.deltaPatchesApplied += package.deltaPatches.size();
            stagingExists = true;
        }
        else if (package.method == UpdateMethod::Full ||
                 package.method == UpdateMethod::Rollup)
        {
            // Full/Rollup: the package file must exist in staging already
            if (!stagingExists) {
                result.errorMessage = "Full package not found in staging directory";
                result.success = false;
                m_stats.updatesFailed++;
                NotifyError(result.errorMessage, -7);
                return result;
            }
            if (IsReparsePoint(stagingPath)) {
                result.errorMessage = "Staged package is a reparse point";
                result.success = false;
                m_stats.updatesFailed++;
                SS_LOG_ERROR(kLogCategory,
                    L"Staged package is a reparse point — rejected");
                NotifyError(result.errorMessage, -7);
                return result;
            }
            const auto stagedSz = fs::file_size(stagingPath, ec);
            if (ec || stagedSz == 0 || stagedSz > kMaxDatabaseFileSize) {
                result.errorMessage =
                    "Staged package size invalid or exceeds cap";
                result.success = false;
                m_stats.updatesFailed++;
                SS_LOG_ERROR(kLogCategory,
                    L"Staged package size invalid (size=%llu, cap=%llu)",
                    static_cast<unsigned long long>(stagedSz),
                    static_cast<unsigned long long>(kMaxDatabaseFileSize));
                NotifyError(result.errorMessage, -7);
                return result;
            }
            result.bytesDownloaded = stagedSz;
            m_stats.fullDownloads++;
        }
        else {
            // Incremental: similar to delta
            if (!stagingExists) {
                result.errorMessage = "Incremental package not found in staging directory";
                result.success = false;
                m_stats.updatesFailed++;
                NotifyError(result.errorMessage, -8);
                return result;
            }
            if (IsReparsePoint(stagingPath)) {
                result.errorMessage = "Staged incremental package is a reparse point";
                result.success = false;
                m_stats.updatesFailed++;
                NotifyError(result.errorMessage, -8);
                return result;
            }
            const auto stagedSz = fs::file_size(stagingPath, ec);
            if (ec || stagedSz == 0 || stagedSz > kMaxDatabaseFileSize) {
                result.errorMessage =
                    "Staged incremental package size invalid or exceeds cap";
                result.success = false;
                m_stats.updatesFailed++;
                NotifyError(result.errorMessage, -8);
                return result;
            }
            result.bytesDownloaded = stagedSz;
        }

        UpdateProgress(package.type, SigUpdateState::Patching, 70,
            "Update staged");

        // --- State: Validating ---
        TransitionState(SigUpdateState::Validating);
        UpdateProgress(package.type, SigUpdateState::Validating, 75,
            "Verifying integrity");

        // Verify the staged file
        if (!fs::exists(stagingPath, ec) || ec) {
            result.errorMessage = "Staged file missing after patching";
            result.success = false;
            m_stats.updatesFailed++;
            NotifyError(result.errorMessage, -9);
            return result;
        }

        // Hash verification
        if (!package.targetVersion.checksum.empty()) {
            auto actualHash = HashFileSha256(stagingPath);
            if (!actualHash.has_value()) {
                result.errorMessage = "Failed to compute hash of staged file";
                result.success = false;
                m_stats.updatesFailed++;
                NotifyError(result.errorMessage, -10);
                return result;
            }

            // Constant-time comparison via HashUtils::Equal
            const auto& expected = package.targetVersion.checksum;
            const auto& actual = *actualHash;
            if (expected.size() != actual.size() ||
                !HU::Equal(
                    reinterpret_cast<const uint8_t*>(actual.data()),
                    reinterpret_cast<const uint8_t*>(expected.data()),
                    actual.size()))
            {
                result.errorMessage = "Hash mismatch for staged database";
                result.success = false;
                m_stats.updatesFailed++;
                NotifyError(result.errorMessage, -11);
                return result;
            }
        }

        // Signature verification via UpdateVerifier — FAIL CLOSED.
        // If the verifier is present and initialized, the staged file MUST
        // pass Authenticode verification. We will not install an unsigned
        // (or invalidly-signed) signature database on the basis of a
        // self-derived hash. The hash check above only proves the bytes
        // weren't corrupted in transit; only Authenticode proves origin.
        if (UpdateVerifier::HasInstance() &&
            UpdateVerifier::Instance().IsInitialized())
        {
            if (!UpdateVerifier::Instance().VerifyAuthenticode(stagingPath)) {
                result.errorMessage =
                    "Authenticode verification failed for staged database";
                result.success = false;
                m_stats.updatesFailed++;
                SS_LOG_ERROR(kLogCategory,
                    L"Authenticode verification FAILED for type %S — rejecting update",
                    std::string(GetDatabaseTypeName(package.type)).c_str());
                NotifyError(result.errorMessage, -16);
                return result;
            }
            SS_LOG_DEBUG(kLogCategory,
                L"Authenticode verification passed for type %S",
                std::string(GetDatabaseTypeName(package.type)).c_str());
        }
        else {
            // Verifier not configured at all — emit a high-visibility
            // warning so the operator notices, but do not block (matches
            // existing behaviour for unconfigured deployments).
            SS_LOG_WARN(kLogCategory,
                L"UpdateVerifier not initialized; installing staged database "
                L"of type %S without Authenticode verification — operator action required",
                std::string(GetDatabaseTypeName(package.type)).c_str());
        }

        UpdateProgress(package.type, SigUpdateState::Validating, 85,
            "Verification complete");

        // --- State: Reloading ---
        TransitionState(SigUpdateState::Reloading);
        UpdateProgress(package.type, SigUpdateState::Reloading, 90,
            "Hot-reloading database");

        // Atomic swap: rename staged file over the production database.
        // This is the "double-buffer swap" pattern — the staged file IS the
        // shadow buffer that was built/patched offline.
        fs::rename(stagingPath, dbPath, ec);
        if (ec) {
            // Fallback: copy + remove
            fs::copy_file(stagingPath, dbPath,
                fs::copy_options::overwrite_existing, ec);
            if (ec) {
                result.errorMessage = "Failed to install database: " + ec.message();
                result.success = false;
                m_stats.updatesFailed++;
                NotifyError(result.errorMessage, -13);
                return result;
            }
            fs::remove(stagingPath, ec);
        }

        // Update version metadata
        m_versions[package.type] = package.targetVersion;
        m_versions[package.type].type = package.type;
        if (!WriteVersionSidecar(package.type, package.targetVersion)) {
            SS_LOG_WARN(kLogCategory,
                L"Failed to write version sidecar for type %S",
                std::string(GetDatabaseTypeName(package.type)).c_str());
        }

        m_loadedDatabases.insert(package.type);

        // Notify reload callback
        if (m_config.enableHotReload) {
            m_stats.hotReloads++;
            NotifyReload(package.type);
        }

        UpdateProgress(package.type, SigUpdateState::Reloading, 100,
            "Database reloaded");

        // --- Completed ---
        auto endTime = Clock::now();
        auto durationSec = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime).count());

        result.success = true;
        result.durationSeconds = durationSec;
        result.appliedTime = std::chrono::system_clock::now();

        m_stats.updatesApplied++;
        m_stats.bytesDownloaded += result.bytesDownloaded;

        // Track savings for delta
        if (package.method == UpdateMethod::Delta) {
            uint64_t fullSize = package.targetVersion.sizeBytes;
            if (fullSize > result.bytesDownloaded) {
                m_stats.bytesSaved += (fullSize - result.bytesDownloaded);
            }
        }

        // Per-type counter
        auto typeIdx = static_cast<size_t>(package.type);
        if (typeIdx < m_stats.byDatabaseType.size()) {
            m_stats.byDatabaseType[typeIdx]++;
        }

        m_stats.lastUpdateTime = std::chrono::system_clock::now();

        SS_LOG_INFO(kLogCategory,
            L"Successfully updated %S database to version %llu in %u seconds",
            std::string(GetDatabaseTypeName(package.type)).c_str(),
            static_cast<unsigned long long>(package.targetVersion.versionNumber),
            durationSec);

        return result;
    }
};

// ============================================================================
// STATIC STATE
// ============================================================================

std::atomic<bool> SignatureUpdater::s_instanceCreated{false};

// ============================================================================
// STRUCT MEMBER IMPLEMENTATIONS
// ============================================================================

// --- DatabaseVersion ---

std::string DatabaseVersion::ToJson() const {
    std::ostringstream os;
    os << "{\"type\":" << static_cast<int>(type)
       << ",\"typeName\":\"" << JsonEscape(std::string(GetDatabaseTypeName(type))) << "\""
       << ",\"versionNumber\":" << versionNumber
       << ",\"versionString\":\"" << JsonEscape(versionString) << "\""
       << ",\"signatureCount\":" << signatureCount
       << ",\"sizeBytes\":" << sizeBytes
       << ",\"buildDate\":\"" << FormatIso8601(buildDate) << "\""
       << ",\"releaseDate\":\"" << FormatIso8601(releaseDate) << "\""
       << ",\"checksum\":\"" << JsonEscape(checksum) << "\""
       << "}";
    return os.str();
}

// --- DeltaPatchInfo ---

std::string DeltaPatchInfo::ToJson() const {
    std::ostringstream os;
    os << "{\"patchId\":\"" << JsonEscape(patchId) << "\""
       << ",\"fromVersion\":" << fromVersion
       << ",\"toVersion\":" << toVersion
       << ",\"patchSize\":" << patchSize
       << ",\"downloadUrl\":\"" << JsonEscape(downloadUrl) << "\""
       << ",\"checksum\":\"" << JsonEscape(checksum) << "\""
       << ",\"signatureLength\":" << signature.size()
       << "}";
    return os.str();
}

// --- SignaturePackage ---

std::string SignaturePackage::ToJson() const {
    std::ostringstream os;
    os << "{\"packageId\":\"" << JsonEscape(packageId) << "\""
       << ",\"type\":" << static_cast<int>(type)
       << ",\"typeName\":\"" << JsonEscape(std::string(GetDatabaseTypeName(type))) << "\""
       << ",\"method\":" << static_cast<int>(method)
       << ",\"methodName\":\"" << JsonEscape(std::string(GetUpdateMethodName(method))) << "\""
       << ",\"targetVersion\":" << targetVersion.ToJson()
       << ",\"downloadSize\":" << downloadSize
       << ",\"downloadUrl\":\"" << JsonEscape(downloadUrl) << "\""
       << ",\"deltaPatches\":[";
    for (size_t i = 0; i < deltaPatches.size(); ++i) {
        if (i > 0) os << ",";
        os << deltaPatches[i].ToJson();
    }
    os << "],\"isMandatory\":" << (isMandatory ? "true" : "false")
       << ",\"releaseNotes\":\"" << JsonEscape(releaseNotes) << "\""
       << "}";
    return os.str();
}

// --- SigUpdateProgress ---

std::string SigUpdateProgress::ToJson() const {
    std::ostringstream os;
    os << "{\"type\":" << static_cast<int>(type)
       << ",\"typeName\":\"" << JsonEscape(std::string(GetDatabaseTypeName(type))) << "\""
       << ",\"state\":" << static_cast<int>(state)
       << ",\"stateName\":\"" << JsonEscape(std::string(GetUpdateStateName(state))) << "\""
       << ",\"progressPercent\":" << static_cast<int>(progressPercent)
       << ",\"currentOperation\":\"" << JsonEscape(currentOperation) << "\""
       << ",\"bytesDownloaded\":" << bytesDownloaded
       << ",\"totalBytes\":" << totalBytes
       << ",\"speedBps\":" << speedBps
       << ",\"etaSeconds\":" << etaSeconds;
    if (!errorMessage.empty()) {
        os << ",\"errorMessage\":\"" << JsonEscape(errorMessage) << "\"";
    }
    os << "}";
    return os.str();
}

// --- SigUpdateResult ---

std::string SigUpdateResult::ToJson() const {
    std::ostringstream os;
    os << "{\"success\":" << (success ? "true" : "false")
       << ",\"type\":" << static_cast<int>(type)
       << ",\"typeName\":\"" << JsonEscape(std::string(GetDatabaseTypeName(type))) << "\""
       << ",\"oldVersion\":" << oldVersion.ToJson()
       << ",\"newVersion\":" << newVersion.ToJson()
       << ",\"methodUsed\":" << static_cast<int>(methodUsed)
       << ",\"methodName\":\"" << JsonEscape(std::string(GetUpdateMethodName(methodUsed))) << "\""
       << ",\"bytesDownloaded\":" << bytesDownloaded
       << ",\"durationSeconds\":" << durationSeconds
       << ",\"appliedTime\":\"" << FormatIso8601(appliedTime) << "\"";
    if (!errorMessage.empty()) {
        os << ",\"errorMessage\":\"" << JsonEscape(errorMessage) << "\"";
    }
    os << "}";
    return os.str();
}

// --- SigUpdaterStatistics ---

void SigUpdaterStatistics::Reset() noexcept {
    updatesApplied = 0;
    updatesFailed = 0;
    deltaPatchesApplied = 0;
    fullDownloads = 0;
    bytesDownloaded = 0;
    bytesSaved = 0;
    hotReloads = 0;
    for (auto& v : byDatabaseType) {
        v = 0;
    }
    startTime = Clock::now();
    lastUpdateTime.reset();
}

std::string SigUpdaterStatistics::ToJson() const {
    std::ostringstream os;
    os << "{\"updatesApplied\":" << updatesApplied
       << ",\"updatesFailed\":" << updatesFailed
       << ",\"deltaPatchesApplied\":" << deltaPatchesApplied
       << ",\"fullDownloads\":" << fullDownloads
       << ",\"bytesDownloaded\":" << bytesDownloaded
       << ",\"bytesSaved\":" << bytesSaved
       << ",\"hotReloads\":" << hotReloads
       << ",\"byDatabaseType\":[";
    for (size_t i = 0; i < byDatabaseType.size(); ++i) {
        if (i > 0) os << ",";
        os << byDatabaseType[i];
    }
    os << "]";
    if (lastUpdateTime.has_value()) {
        os << ",\"lastUpdateTime\":\"" << FormatIso8601(*lastUpdateTime) << "\"";
    }
    os << "}";
    return os.str();
}

// --- SignatureUpdaterConfiguration ---

bool SignatureUpdaterConfiguration::IsValid() const noexcept {
    if (!enabled) return true;  // disabled config is trivially valid
    if (databaseDirectory.empty()) return false;
    if (stagingDirectory.empty()) return false;
    if (updateIntervalMinutes == 0) return false;
    if (maxDeltaChain == 0 || maxDeltaChain > 100) return false;
    if (backupCount > kMaxBackupCount) return false;
    if (enabledTypes.empty()) return false;
    return true;
}

// ============================================================================
// SINGLETON
// ============================================================================

SignatureUpdater& SignatureUpdater::Instance() noexcept {
    static SignatureUpdater instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool SignatureUpdater::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

SignatureUpdater::SignatureUpdater()
    : m_impl(std::make_unique<SignatureUpdaterImpl>())
{
}

SignatureUpdater::~SignatureUpdater() {
    if (m_impl && m_impl->m_initialized.load(std::memory_order_acquire)) {
        Shutdown();
    }
}

// ============================================================================
// LIFECYCLE
// ============================================================================

bool SignatureUpdater::Initialize(const SignatureUpdaterConfiguration& config) {
    if (!m_impl) return false;

    std::unique_lock lock(m_impl->m_mutex);

    if (m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(kLogCategory, L"Already initialized — skipping re-initialization");
        return true;
    }

    m_impl->m_status = SigUpdaterStatus::Initializing;
    SS_LOG_INFO(kLogCategory, L"Initializing SignatureUpdater v%u.%u.%u",
        SigUpdateConstants::VERSION_MAJOR,
        SigUpdateConstants::VERSION_MINOR,
        SigUpdateConstants::VERSION_PATCH);

    // The shipped default has enabled = true but leaves databaseDirectory and
    // stagingDirectory empty, and IsValid() rejects an empty path - so the
    // default configuration could never validate, and any caller that did not
    // set both paths itself failed here with "Invalid configuration provided".
    //
    // The consequence was not a missing feature, it was a missing product: with
    // the signature updater dead there is no path by which signature or hash
    // content can ever be installed, which is why signatures.sdb does not exist
    // on disk and the hash store comes up empty on every start. The cheapest and
    // most valuable tier of the scan cascade had nothing to match against, so
    // every file fell through to the expensive stages.
    //
    // Resolve the same data directory the rest of the product uses, then
    // validate what will actually be used. An explicitly configured path is
    // still honoured, and a genuinely invalid configuration is still rejected.
    SignatureUpdaterConfiguration effectiveConfig = config;
    if (effectiveConfig.enabled) {
        if (effectiveConfig.databaseDirectory.empty()) {
            effectiveConfig.databaseDirectory =
                fs::path(::ShadowStrike::Utils::DataStorePaths::GetDataDirectory());
        }
        if (effectiveConfig.stagingDirectory.empty()) {
            effectiveConfig.stagingDirectory =
                effectiveConfig.databaseDirectory / L"staging";
        }
    }

    if (!effectiveConfig.IsValid()) {
        SS_LOG_ERROR(kLogCategory, L"Invalid configuration provided");
        m_impl->m_status = SigUpdaterStatus::Error;
        return false;
    }

    m_impl->m_config = effectiveConfig;

    SS_LOG_INFO(kLogCategory,
        L"Signature database directory: %ls (staging: %ls)",
        effectiveConfig.databaseDirectory.c_str(),
        effectiveConfig.stagingDirectory.c_str());

    // Ensure directories exist
    std::error_code ec;
    if (!config.databaseDirectory.empty()) {
        fs::create_directories(config.databaseDirectory, ec);
        if (ec) {
            SS_LOG_ERROR(kLogCategory, L"Failed to create database directory: %s",
                config.databaseDirectory.wstring().c_str());
            m_impl->m_status = SigUpdaterStatus::Error;
            return false;
        }
        if (IsReparsePoint(config.databaseDirectory)) {
            SS_LOG_ERROR(kLogCategory,
                L"Refusing to initialize: database directory is a reparse point: %s",
                config.databaseDirectory.wstring().c_str());
            m_impl->m_status = SigUpdaterStatus::Error;
            return false;
        }
    }
    if (!config.stagingDirectory.empty()) {
        fs::create_directories(config.stagingDirectory, ec);
        if (ec) {
            SS_LOG_ERROR(kLogCategory, L"Failed to create staging directory: %s",
                config.stagingDirectory.wstring().c_str());
            m_impl->m_status = SigUpdaterStatus::Error;
            return false;
        }
        if (IsReparsePoint(config.stagingDirectory)) {
            SS_LOG_ERROR(kLogCategory,
                L"Refusing to initialize: staging directory is a reparse point: %s",
                config.stagingDirectory.wstring().c_str());
            m_impl->m_status = SigUpdaterStatus::Error;
            return false;
        }
    }

    // Load current database versions for all enabled types
    for (const auto dbType : config.enabledTypes) {
        if (m_impl->LoadDatabaseVersion(dbType)) {
            SS_LOG_INFO(kLogCategory,
                L"Loaded version info for %S: version %llu (%S)",
                std::string(GetDatabaseTypeName(dbType)).c_str(),
                static_cast<unsigned long long>(m_impl->m_versions[dbType].versionNumber),
                m_impl->m_versions[dbType].versionString.c_str());
        }
        else {
            SS_LOG_INFO(kLogCategory,
                L"No existing database found for type %S — will require full download",
                std::string(GetDatabaseTypeName(dbType)).c_str());
        }
    }

    // Reset statistics for this session
    m_impl->m_stats.Reset();

    m_impl->m_initialized.store(true, std::memory_order_release);
    m_impl->m_status = SigUpdaterStatus::Running;
    m_impl->m_updateState = SigUpdateState::Idle;

    SS_LOG_INFO(kLogCategory,
        L"Initialized with %zu enabled database types, autoUpdate=%s, "
        L"preferDelta=%s, hotReload=%s",
        config.enabledTypes.size(),
        config.autoUpdate ? L"true" : L"false",
        config.preferDeltaUpdates ? L"true" : L"false",
        config.enableHotReload ? L"true" : L"false");

    return true;
}

void SignatureUpdater::Shutdown() {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_mutex);

    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    SS_LOG_INFO(kLogCategory, L"Shutting down SignatureUpdater");

    m_impl->m_status = SigUpdaterStatus::Stopping;
    m_impl->m_updateState = SigUpdateState::Idle;

    // Clear callbacks
    {
        std::lock_guard cbLock(m_impl->m_callbackMutex);
        m_impl->m_progressCallback = nullptr;
        m_impl->m_completionCallback = nullptr;
        m_impl->m_reloadCallback = nullptr;
        m_impl->m_errorCallback = nullptr;
    }

    // Clear runtime state
    m_impl->m_progress.clear();

    m_impl->m_initialized.store(false, std::memory_order_release);
    m_impl->m_status = SigUpdaterStatus::Stopped;

    SS_LOG_INFO(kLogCategory, L"SignatureUpdater shut down");
}

bool SignatureUpdater::IsInitialized() const noexcept {
    return m_impl && m_impl->m_initialized.load(std::memory_order_acquire);
}

SigUpdaterStatus SignatureUpdater::GetStatus() const noexcept {
    if (!m_impl) return SigUpdaterStatus::Uninitialized;
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_status;
}

bool SignatureUpdater::UpdateConfiguration(const SignatureUpdaterConfiguration& config) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory, L"Cannot update configuration: not initialized");
        return false;
    }

    if (!config.IsValid()) {
        SS_LOG_ERROR(kLogCategory, L"Invalid configuration provided for update");
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);

    // Don't allow config change while updating
    if (m_impl->m_updateState != SigUpdateState::Idle &&
        m_impl->m_updateState != SigUpdateState::Completed &&
        m_impl->m_updateState != SigUpdateState::Failed)
    {
        SS_LOG_ERROR(kLogCategory,
            L"Cannot update configuration while update is in progress (state=%S)",
            std::string(GetUpdateStateName(m_impl->m_updateState)).c_str());
        return false;
    }

    m_impl->m_config = config;

    // Ensure new directories exist
    std::error_code ec;
    fs::create_directories(config.databaseDirectory, ec);
    fs::create_directories(config.stagingDirectory, ec);

    SS_LOG_INFO(kLogCategory, L"Configuration updated successfully");
    return true;
}

SignatureUpdaterConfiguration SignatureUpdater::GetConfiguration() const {
    if (!m_impl) return {};
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config;
}

// ============================================================================
// UPDATE OPERATIONS
// ============================================================================

bool SignatureUpdater::UpdateSignatures() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory, L"UpdateSignatures called while not initialized");
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);

    if (m_impl->m_updateState != SigUpdateState::Idle &&
        m_impl->m_updateState != SigUpdateState::Completed &&
        m_impl->m_updateState != SigUpdateState::Failed)
    {
        SS_LOG_WARN(kLogCategory, L"Update already in progress, state=%S",
            std::string(GetUpdateStateName(m_impl->m_updateState)).c_str());
        return false;
    }

    m_impl->m_status = SigUpdaterStatus::Updating;

    SS_LOG_INFO(kLogCategory, L"Starting signature update for %zu enabled database types",
        m_impl->m_config.enabledTypes.size());

    bool allSuccess = true;
    std::vector<SigUpdateResult> results;

    for (const auto dbType : m_impl->m_config.enabledTypes) {
        SS_LOG_INFO(kLogCategory, L"Updating database type: %S",
            std::string(GetDatabaseTypeName(dbType)).c_str());

        // Check for available package in staging
        auto stagingPath = m_impl->GetStagingPath(dbType);
        std::error_code ec;
        if (!fs::exists(stagingPath, ec) || ec) {
            SS_LOG_INFO(kLogCategory,
                L"No staged package available for type %S — "
                L"network transport not configured for remote download",
                std::string(GetDatabaseTypeName(dbType)).c_str());
            continue;
        }

        // Build a package descriptor from the staged file.
        // NOTE: do not derive targetVersion.checksum from the staged file
        // itself — verifying a file against a hash computed from that
        // same file is a no-op. ApplyPackageInternal will rely on
        // Authenticode (UpdateVerifier) as the authenticity boundary
        // when no manifest-derived hash is available.
        SignaturePackage pkg;
        pkg.packageId = std::string(GetDatabaseTypeName(dbType)) + "_update";
        pkg.type = dbType;
        pkg.method = UpdateMethod::Full;

        pkg.targetVersion.type = dbType;
        pkg.targetVersion.sizeBytes = fs::file_size(stagingPath, ec);
        if (ec) pkg.targetVersion.sizeBytes = 0;

        // If there's a current version, bump by 1 for the new version
        auto verIt = m_impl->m_versions.find(dbType);
        if (verIt != m_impl->m_versions.end()) {
            pkg.targetVersion.versionNumber = verIt->second.versionNumber + 1;
        }
        else {
            pkg.targetVersion.versionNumber = 1;
        }
        pkg.targetVersion.releaseDate = std::chrono::system_clock::now();

        // Create backup before applying
        lock.unlock();
        (void)CreateBackup(dbType);
        lock.lock();

        auto result = m_impl->ApplyPackageInternal(pkg);
        results.push_back(result);

        if (!result.success) {
            allSuccess = false;
            SS_LOG_ERROR(kLogCategory,
                L"Failed to update database type %S: %S",
                std::string(GetDatabaseTypeName(dbType)).c_str(),
                result.errorMessage.c_str());
        }

        m_impl->NotifyCompletion(result);
    }

    m_impl->TransitionState(allSuccess ? SigUpdateState::Completed : SigUpdateState::Failed);
    m_impl->m_status = SigUpdaterStatus::Running;

    SS_LOG_INFO(kLogCategory,
        L"Signature update cycle complete: %zu/%zu successful",
        std::count_if(results.begin(), results.end(),
            [](const auto& r) { return r.success; }),
        results.size());

    return allSuccess;
}

bool SignatureUpdater::UpdateDatabase(SignatureDatabaseType type) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory, L"UpdateDatabase called while not initialized");
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);

    if (m_impl->m_updateState != SigUpdateState::Idle &&
        m_impl->m_updateState != SigUpdateState::Completed &&
        m_impl->m_updateState != SigUpdateState::Failed)
    {
        SS_LOG_WARN(kLogCategory, L"Update already in progress");
        return false;
    }

    m_impl->m_status = SigUpdaterStatus::Updating;

    auto stagingPath = m_impl->GetStagingPath(type);
    std::error_code ec;
    if (!fs::exists(stagingPath, ec) || ec) {
        SS_LOG_ERROR(kLogCategory,
            L"No staged package for type %S in staging directory",
            std::string(GetDatabaseTypeName(type)).c_str());
        m_impl->TransitionState(SigUpdateState::Failed);
        m_impl->m_status = SigUpdaterStatus::Running;
        return false;
    }

    SignaturePackage pkg;
    pkg.packageId = std::string(GetDatabaseTypeName(type)) + "_single_update";
    pkg.type = type;
    pkg.method = UpdateMethod::Full;

    // See note in UpdateSignatures(): no self-derived hash.
    pkg.targetVersion.type = type;
    pkg.targetVersion.sizeBytes = fs::file_size(stagingPath, ec);
    if (ec) pkg.targetVersion.sizeBytes = 0;

    auto verIt = m_impl->m_versions.find(type);
    if (verIt != m_impl->m_versions.end()) {
        pkg.targetVersion.versionNumber = verIt->second.versionNumber + 1;
    }
    else {
        pkg.targetVersion.versionNumber = 1;
    }
    pkg.targetVersion.releaseDate = std::chrono::system_clock::now();

    // Create backup before applying
    lock.unlock();
    (void)CreateBackup(type);
    lock.lock();

    auto result = m_impl->ApplyPackageInternal(pkg);

    m_impl->TransitionState(result.success ? SigUpdateState::Completed
                                           : SigUpdateState::Failed);
    m_impl->m_status = SigUpdaterStatus::Running;

    m_impl->NotifyCompletion(result);

    return result.success;
}

std::vector<SignaturePackage> SignatureUpdater::CheckForUpdates() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory, L"CheckForUpdates called while not initialized");
        return {};
    }

    std::shared_lock lock(m_impl->m_mutex);

    SS_LOG_INFO(kLogCategory, L"Checking for updates across %zu enabled types",
        m_impl->m_config.enabledTypes.size());

    std::vector<SignaturePackage> available;

    for (const auto dbType : m_impl->m_config.enabledTypes) {
        auto stagingPath = m_impl->GetStagingPath(dbType);
        std::error_code ec;
        if (fs::exists(stagingPath, ec) && !ec) {
            SignaturePackage pkg;
            pkg.packageId = std::string(GetDatabaseTypeName(dbType)) + "_staged";
            pkg.type = dbType;
            pkg.method = UpdateMethod::Full;
            pkg.downloadSize = fs::file_size(stagingPath, ec);
            if (ec) pkg.downloadSize = 0;
            pkg.targetVersion.type = dbType;

            auto hashOpt = HashFileSha256(stagingPath);
            if (hashOpt) {
                pkg.targetVersion.checksum = *hashOpt;
            }

            available.push_back(std::move(pkg));

            SS_LOG_INFO(kLogCategory, L"Found staged package for type %S",
                std::string(GetDatabaseTypeName(dbType)).c_str());
        }
    }

    // Network check would happen here, but transport is not configured
    if (available.empty()) {
        SS_LOG_INFO(kLogCategory,
            L"No local staged packages found; network transport not configured");
    }

    return available;
}

std::optional<SignaturePackage> SignatureUpdater::CheckForUpdate(
    SignatureDatabaseType type)
{
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory, L"CheckForUpdate called while not initialized");
        return std::nullopt;
    }

    std::shared_lock lock(m_impl->m_mutex);

    auto stagingPath = m_impl->GetStagingPath(type);
    std::error_code ec;
    if (fs::exists(stagingPath, ec) && !ec) {
        SignaturePackage pkg;
        pkg.packageId = std::string(GetDatabaseTypeName(type)) + "_staged";
        pkg.type = type;
        pkg.method = UpdateMethod::Full;
        pkg.downloadSize = fs::file_size(stagingPath, ec);
        if (ec) pkg.downloadSize = 0;
        pkg.targetVersion.type = type;

        auto hashOpt = HashFileSha256(stagingPath);
        if (hashOpt) {
            pkg.targetVersion.checksum = *hashOpt;
        }

        SS_LOG_INFO(kLogCategory, L"Staged package available for type %S",
            std::string(GetDatabaseTypeName(type)).c_str());
        return pkg;
    }

    SS_LOG_DEBUG(kLogCategory,
        L"No staged package found for type %S; network transport not configured",
        std::string(GetDatabaseTypeName(type)).c_str());
    return std::nullopt;
}

bool SignatureUpdater::ApplyPackage(const SignaturePackage& package) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory, L"ApplyPackage called while not initialized");
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);

    if (m_impl->m_updateState != SigUpdateState::Idle &&
        m_impl->m_updateState != SigUpdateState::Completed &&
        m_impl->m_updateState != SigUpdateState::Failed)
    {
        SS_LOG_WARN(kLogCategory, L"Cannot apply package: update in progress");
        return false;
    }

    if (package.downloadSize > kMaxPackageSize) {
        SS_LOG_ERROR(kLogCategory,
            L"Package size %llu exceeds maximum allowed %llu",
            static_cast<unsigned long long>(package.downloadSize),
            static_cast<unsigned long long>(kMaxPackageSize));
        return false;
    }

    m_impl->m_status = SigUpdaterStatus::Updating;

    // Create backup before applying
    lock.unlock();
    (void)CreateBackup(package.type);
    lock.lock();

    auto result = m_impl->ApplyPackageInternal(package);

    m_impl->TransitionState(result.success ? SigUpdateState::Completed
                                           : SigUpdateState::Failed);
    m_impl->m_status = SigUpdaterStatus::Running;

    m_impl->NotifyCompletion(result);

    return result.success;
}

SigUpdateState SignatureUpdater::GetUpdateState() const noexcept {
    if (!m_impl) return SigUpdateState::Idle;
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_updateState;
}

bool SignatureUpdater::IsUpdating() const noexcept {
    if (!m_impl) return false;
    std::shared_lock lock(m_impl->m_mutex);
    const auto state = m_impl->m_updateState;
    return state != SigUpdateState::Idle &&
           state != SigUpdateState::Completed &&
           state != SigUpdateState::Failed;
}

// ============================================================================
// VERSION INFORMATION
// ============================================================================

std::string SignatureUpdater::GetCurrentVersion() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return "0.0.0";
    }

    std::shared_lock lock(m_impl->m_mutex);

    // Return the main database version as the "current version"
    auto it = m_impl->m_versions.find(SignatureDatabaseType::Main);
    if (it != m_impl->m_versions.end() && !it->second.versionString.empty()) {
        return it->second.versionString;
    }

    // Fallback: compose from version number
    if (it != m_impl->m_versions.end()) {
        return std::to_string(it->second.versionNumber);
    }

    return "0";
}

DatabaseVersion SignatureUpdater::GetDatabaseVersion(
    SignatureDatabaseType type) const
{
    if (!m_impl) return {};
    std::shared_lock lock(m_impl->m_mutex);

    auto it = m_impl->m_versions.find(type);
    if (it != m_impl->m_versions.end()) {
        return it->second;
    }

    DatabaseVersion empty;
    empty.type = type;
    return empty;
}

std::map<SignatureDatabaseType, DatabaseVersion> SignatureUpdater::GetAllVersions() const {
    if (!m_impl) return {};
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_versions;
}

// ============================================================================
// PROGRESS
// ============================================================================

std::optional<SigUpdateProgress> SignatureUpdater::GetProgress() const {
    if (!m_impl) return std::nullopt;
    std::shared_lock lock(m_impl->m_mutex);

    if (m_impl->m_progress.empty()) return std::nullopt;

    // Return the progress of the most recently active type
    for (const auto& [type, prog] : m_impl->m_progress) {
        if (prog.state != SigUpdateState::Idle &&
            prog.state != SigUpdateState::Completed &&
            prog.state != SigUpdateState::Failed)
        {
            return prog;
        }
    }

    // Return the last entry if none active
    return m_impl->m_progress.rbegin()->second;
}

std::vector<SigUpdateProgress> SignatureUpdater::GetAllProgress() const {
    if (!m_impl) return {};
    std::shared_lock lock(m_impl->m_mutex);

    std::vector<SigUpdateProgress> result;
    result.reserve(m_impl->m_progress.size());
    for (const auto& [type, prog] : m_impl->m_progress) {
        result.push_back(prog);
    }
    return result;
}

// ============================================================================
// HOT-RELOAD
// ============================================================================

bool SignatureUpdater::TriggerHotReload(SignatureDatabaseType type) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory, L"TriggerHotReload called while not initialized");
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);

    if (!m_impl->m_config.enableHotReload) {
        SS_LOG_WARN(kLogCategory, L"Hot-reload is disabled in configuration");
        return false;
    }

    auto dbPath = m_impl->GetDatabasePath(type);
    std::error_code ec;
    if (!fs::exists(dbPath, ec) || ec) {
        SS_LOG_ERROR(kLogCategory,
            L"Cannot hot-reload: database file not found for type %S",
            std::string(GetDatabaseTypeName(type)).c_str());
        return false;
    }

    SS_LOG_INFO(kLogCategory, L"Triggering hot-reload for database type %S",
        std::string(GetDatabaseTypeName(type)).c_str());

    // Refresh version info from disk
    if (!m_impl->LoadDatabaseVersion(type)) {
        SS_LOG_WARN(kLogCategory,
            L"Failed to refresh version info during hot-reload for type %S",
            std::string(GetDatabaseTypeName(type)).c_str());
    }

    m_impl->m_stats.hotReloads++;

    // Notify subscribers to reload the database
    lock.unlock();
    m_impl->NotifyReload(type);

    SS_LOG_INFO(kLogCategory, L"Hot-reload triggered for type %S",
        std::string(GetDatabaseTypeName(type)).c_str());
    return true;
}

bool SignatureUpdater::IsDatabaseLoaded(SignatureDatabaseType type) const {
    if (!m_impl) return false;
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_loadedDatabases.contains(type);
}

// ============================================================================
// BACKUP/RESTORE
// ============================================================================

bool SignatureUpdater::CreateBackup(SignatureDatabaseType type) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory, L"CreateBackup called while not initialized");
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);

    auto dbPath = m_impl->GetDatabasePath(type);
    std::error_code ec;
    if (!fs::exists(dbPath, ec) || ec) {
        SS_LOG_DEBUG(kLogCategory,
            L"No database file to back up for type %S",
            std::string(GetDatabaseTypeName(type)).c_str());
        return false;
    }

    // Rotate backups: shift existing indices up, capping at backupCount
    const uint32_t maxBackups = m_impl->m_config.backupCount;
    if (maxBackups == 0) {
        SS_LOG_DEBUG(kLogCategory, L"Backup disabled (backupCount=0)");
        return false;
    }

    // Remove oldest backup if at capacity
    auto oldestDir = m_impl->GetBackupDir(type, maxBackups - 1);
    if (fs::exists(oldestDir, ec) && !ec) {
        fs::remove_all(oldestDir, ec);
        if (ec) {
            SS_LOG_WARN(kLogCategory, L"Failed to remove oldest backup: %s",
                oldestDir.wstring().c_str());
        }
    }

    // Shift backups up: (n-2) -> (n-1), (n-3) -> (n-2), etc.
    for (uint32_t i = maxBackups - 1; i > 0; --i) {
        auto srcDir = m_impl->GetBackupDir(type, i - 1);
        auto dstDir = m_impl->GetBackupDir(type, i);
        if (fs::exists(srcDir, ec) && !ec) {
            fs::rename(srcDir, dstDir, ec);
            if (ec) {
                SS_LOG_WARN(kLogCategory,
                    L"Failed to rotate backup %u -> %u for type %S",
                    i - 1, i,
                    std::string(GetDatabaseTypeName(type)).c_str());
            }
        }
    }

    // Create new backup at index 0
    auto backupDir = m_impl->GetBackupDir(type, 0);
    fs::create_directories(backupDir, ec);
    if (ec) {
        SS_LOG_ERROR(kLogCategory, L"Failed to create backup directory: %s",
            backupDir.wstring().c_str());
        return false;
    }

    auto backupFile = backupDir / dbPath.filename();
    fs::copy_file(dbPath, backupFile, fs::copy_options::overwrite_existing, ec);
    if (ec) {
        SS_LOG_ERROR(kLogCategory, L"Failed to copy database to backup: %S",
            ec.message().c_str());
        return false;
    }

    // Also back up the version sidecar
    auto verPath = dbPath;
    verPath += ".ver";
    if (fs::exists(verPath, ec) && !ec) {
        auto backupVerFile = backupDir / verPath.filename();
        fs::copy_file(verPath, backupVerFile,
            fs::copy_options::overwrite_existing, ec);
    }

    // Update backup metadata. Record the checksum of the *backup file*
    // (not the live m_versions entry, which may be stale) so that a
    // future RestoreFromBackup can cross-check integrity at restore time
    // rather than trusting whatever was on disk by then.
    {
        DatabaseVersion backupVer;
        auto verIt = m_impl->m_versions.find(type);
        if (verIt != m_impl->m_versions.end()) {
            backupVer = verIt->second;
        }
        backupVer.type = type;
        if (auto h = HashFileSha256(backupFile); h.has_value()) {
            backupVer.checksum = *h;
        }
        std::error_code szEc;
        backupVer.sizeBytes = fs::file_size(backupFile, szEc);
        if (szEc) backupVer.sizeBytes = 0;

        auto& backupList = m_impl->m_backups[type];
        backupList.insert(backupList.begin(), std::move(backupVer));
        if (backupList.size() > maxBackups) {
            backupList.resize(maxBackups);
        }
    }

    // Also create a snapshot via RollbackManager if available
    if (RollbackManager::HasInstance() &&
        RollbackManager::Instance().IsInitialized())
    {
        auto snapshotId = RollbackManager::Instance().CreateSnapshot(
            SnapshotType::Database,
            "Pre-update backup for " + std::string(GetDatabaseTypeName(type)));
        if (!snapshotId.empty()) {
            SS_LOG_DEBUG(kLogCategory,
                L"Created rollback snapshot %S for type %S",
                snapshotId.c_str(),
                std::string(GetDatabaseTypeName(type)).c_str());
        }
    }

    SS_LOG_INFO(kLogCategory, L"Created backup for database type %S",
        std::string(GetDatabaseTypeName(type)).c_str());
    return true;
}

bool SignatureUpdater::RestoreFromBackup(SignatureDatabaseType type,
                                          uint32_t backupIndex)
{
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory, L"RestoreFromBackup called while not initialized");
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);

    if (backupIndex >= m_impl->m_config.backupCount) {
        SS_LOG_ERROR(kLogCategory,
            L"Backup index %u out of range (max %u) for type %S",
            backupIndex, m_impl->m_config.backupCount,
            std::string(GetDatabaseTypeName(type)).c_str());
        return false;
    }

    auto backupDir = m_impl->GetBackupDir(type, backupIndex);
    std::error_code ec;
    if (!fs::exists(backupDir, ec) || ec) {
        SS_LOG_ERROR(kLogCategory,
            L"Backup directory does not exist: %s",
            backupDir.wstring().c_str());
        return false;
    }

    auto dbPath = m_impl->GetDatabasePath(type);
    auto backupFile = backupDir / dbPath.filename();

    if (!fs::exists(backupFile, ec) || ec) {
        SS_LOG_ERROR(kLogCategory,
            L"Backup file does not exist: %s",
            backupFile.wstring().c_str());
        return false;
    }

    // Verify backup file integrity by cross-checking against the stored
    // checksum (recorded at CreateBackup-time). A self-derived hash with
    // nothing to compare to is meaningless, so we look up the expected
    // hash from m_backups (newest-first) and require an exact match.
    auto actualHashOpt = HashFileSha256(backupFile);
    if (!actualHashOpt) {
        SS_LOG_ERROR(kLogCategory,
            L"Failed to compute hash of backup file for type %S",
            std::string(GetDatabaseTypeName(type)).c_str());
        return false;
    }
    {
        const auto bIt = m_impl->m_backups.find(type);
        if (bIt != m_impl->m_backups.end() &&
            backupIndex < bIt->second.size())
        {
            const auto& expected = bIt->second[backupIndex].checksum;
            if (!expected.empty()) {
                const auto& actual = *actualHashOpt;
                if (expected.size() != actual.size() ||
                    !HU::Equal(
                        reinterpret_cast<const uint8_t*>(actual.data()),
                        reinterpret_cast<const uint8_t*>(expected.data()),
                        actual.size()))
                {
                    SS_LOG_ERROR(kLogCategory,
                        L"Backup checksum mismatch for type %S — refusing restore",
                        std::string(GetDatabaseTypeName(type)).c_str());
                    m_impl->NotifyError(
                        "Backup integrity check failed", -21);
                    return false;
                }
            }
        }
    }

    // Restore: copy backup over current database
    fs::copy_file(backupFile, dbPath,
        fs::copy_options::overwrite_existing, ec);
    if (ec) {
        SS_LOG_ERROR(kLogCategory, L"Failed to restore from backup: %S",
            ec.message().c_str());
        m_impl->NotifyError("Restore from backup failed: " + ec.message(), -20);
        return false;
    }

    // Restore version sidecar if present
    auto verPath = dbPath;
    verPath += ".ver";
    auto backupVerFile = backupDir / verPath.filename();
    if (fs::exists(backupVerFile, ec) && !ec) {
        fs::copy_file(backupVerFile, verPath,
            fs::copy_options::overwrite_existing, ec);
    }

    // Reload version info
    if (!m_impl->LoadDatabaseVersion(type)) {
        SS_LOG_WARN(kLogCategory,
            L"Failed to reload version info after restore for type %S",
            std::string(GetDatabaseTypeName(type)).c_str());
    }

    // Trigger hot-reload to notify consumers
    if (m_impl->m_config.enableHotReload) {
        m_impl->m_stats.hotReloads++;
        lock.unlock();
        m_impl->NotifyReload(type);
        lock.lock();
    }

    SS_LOG_INFO(kLogCategory,
        L"Restored database type %S from backup index %u",
        std::string(GetDatabaseTypeName(type)).c_str(), backupIndex);
    return true;
}

std::vector<DatabaseVersion> SignatureUpdater::GetAvailableBackups(
    SignatureDatabaseType type) const
{
    if (!m_impl) return {};
    std::shared_lock lock(m_impl->m_mutex);

    auto it = m_impl->m_backups.find(type);
    if (it != m_impl->m_backups.end()) {
        return it->second;
    }

    // Scan disk for existing backups
    std::vector<DatabaseVersion> result;
    for (uint32_t i = 0; i < m_impl->m_config.backupCount; ++i) {
        auto backupDir = m_impl->GetBackupDir(type, i);
        std::error_code ec;
        if (fs::exists(backupDir, ec) && !ec) {
            auto dbPath = m_impl->GetDatabasePath(type);
            auto backupFile = backupDir / dbPath.filename();
            if (fs::exists(backupFile, ec) && !ec) {
                DatabaseVersion ver;
                ver.type = type;
                ver.sizeBytes = fs::file_size(backupFile, ec);
                if (ec) ver.sizeBytes = 0;

                auto hashOpt = HashFileSha256(backupFile);
                if (hashOpt) ver.checksum = *hashOpt;

                result.push_back(std::move(ver));
            }
        }
    }
    return result;
}

// ============================================================================
// CALLBACKS
// ============================================================================

void SignatureUpdater::RegisterProgressCallback(SigProgressCallback callback) {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_progressCallback = std::move(callback);
    SS_LOG_DEBUG(kLogCategory, L"Progress callback registered");
}

void SignatureUpdater::RegisterCompletionCallback(SigCompletionCallback callback) {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_completionCallback = std::move(callback);
    SS_LOG_DEBUG(kLogCategory, L"Completion callback registered");
}

void SignatureUpdater::RegisterReloadCallback(SigReloadCallback callback) {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_reloadCallback = std::move(callback);
    SS_LOG_DEBUG(kLogCategory, L"Reload callback registered");
}

void SignatureUpdater::RegisterErrorCallback(ErrorCallback callback) {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_errorCallback = std::move(callback);
    SS_LOG_DEBUG(kLogCategory, L"Error callback registered");
}

void SignatureUpdater::UnregisterCallbacks() {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_progressCallback = nullptr;
    m_impl->m_completionCallback = nullptr;
    m_impl->m_reloadCallback = nullptr;
    m_impl->m_errorCallback = nullptr;
    SS_LOG_DEBUG(kLogCategory, L"All callbacks unregistered");
}

// ============================================================================
// STATISTICS
// ============================================================================

SigUpdaterStatistics SignatureUpdater::GetStatistics() const {
    if (!m_impl) {
        SigUpdaterStatistics empty;
        empty.Reset();
        return empty;
    }
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_stats;
}

void SignatureUpdater::ResetStatistics() {
    if (!m_impl) return;
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_stats.Reset();
    SS_LOG_DEBUG(kLogCategory, L"Statistics reset");
}

bool SignatureUpdater::SelfTest() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory, L"SelfTest called while not initialized");
        return false;
    }

    SS_LOG_INFO(kLogCategory, L"Running self-test");

    bool allPassed = true;

    // Test 1: Configuration validity
    {
        std::shared_lock lock(m_impl->m_mutex);
        if (!m_impl->m_config.IsValid()) {
            SS_LOG_ERROR(kLogCategory, L"Self-test FAILED: configuration is invalid");
            allPassed = false;
        }
    }

    // Test 2: Database directory accessibility
    {
        std::shared_lock lock(m_impl->m_mutex);
        std::error_code ec;
        if (!fs::exists(m_impl->m_config.databaseDirectory, ec) || ec) {
            SS_LOG_ERROR(kLogCategory,
                L"Self-test FAILED: database directory inaccessible: %s",
                m_impl->m_config.databaseDirectory.wstring().c_str());
            allPassed = false;
        }
    }

    // Test 3: Staging directory accessibility
    {
        std::shared_lock lock(m_impl->m_mutex);
        std::error_code ec;
        if (!fs::exists(m_impl->m_config.stagingDirectory, ec) || ec) {
            SS_LOG_ERROR(kLogCategory,
                L"Self-test FAILED: staging directory inaccessible: %s",
                m_impl->m_config.stagingDirectory.wstring().c_str());
            allPassed = false;
        }
    }

    // Test 4: Hash computation capability
    {
        const char testData[] = "ShadowStrike-SelfTest";
        std::vector<uint8_t> digest;
        if (!HU::Compute(HU::Algorithm::SHA256, testData,
                         sizeof(testData) - 1, digest))
        {
            SS_LOG_ERROR(kLogCategory,
                L"Self-test FAILED: hash computation unavailable");
            allPassed = false;
        }
        else if (digest.size() != 32) {
            SS_LOG_ERROR(kLogCategory,
                L"Self-test FAILED: unexpected hash digest length %zu",
                digest.size());
            allPassed = false;
        }
    }

    // Test 5: Version metadata integrity for loaded databases
    {
        std::shared_lock lock(m_impl->m_mutex);
        for (const auto& [type, ver] : m_impl->m_versions) {
            auto dbPath = m_impl->GetDatabasePath(type);
            std::error_code ec;
            if (fs::exists(dbPath, ec) && !ec && !ver.checksum.empty()) {
                auto currentHash = HashFileSha256(dbPath);
                if (currentHash.has_value() && *currentHash != ver.checksum) {
                    SS_LOG_ERROR(kLogCategory,
                        L"Self-test FAILED: checksum mismatch for database type %S "
                        L"(expected=%S, actual=%S)",
                        std::string(GetDatabaseTypeName(type)).c_str(),
                        ver.checksum.c_str(),
                        currentHash->c_str());
                    allPassed = false;
                }
            }
        }
    }

    // Test 6: Dependency availability
    if (UpdateVerifier::HasInstance()) {
        if (!UpdateVerifier::Instance().IsInitialized()) {
            SS_LOG_WARN(kLogCategory,
                L"Self-test WARNING: UpdateVerifier exists but not initialized");
        }
    }
    if (DeltaUpdater::HasInstance()) {
        if (!DeltaUpdater::Instance().IsInitialized()) {
            SS_LOG_WARN(kLogCategory,
                L"Self-test WARNING: DeltaUpdater exists but not initialized");
        }
    }

    if (allPassed) {
        SS_LOG_INFO(kLogCategory, L"Self-test PASSED: all checks OK");
    }
    else {
        SS_LOG_ERROR(kLogCategory, L"Self-test FAILED: one or more checks failed");
    }
    return allPassed;
}

std::string SignatureUpdater::GetVersionString() noexcept {
    return std::to_string(SigUpdateConstants::VERSION_MAJOR) + "." +
           std::to_string(SigUpdateConstants::VERSION_MINOR) + "." +
           std::to_string(SigUpdateConstants::VERSION_PATCH);
}

// ============================================================================
// FREE FUNCTIONS — name lookups
// ============================================================================

std::string_view GetDatabaseTypeName(SignatureDatabaseType type) noexcept {
    switch (type) {
    case SignatureDatabaseType::Main:       return "Main";
    case SignatureDatabaseType::Heuristic:  return "Heuristic";
    case SignatureDatabaseType::YARA:       return "YARA";
    case SignatureDatabaseType::URLs:       return "URLs";
    case SignatureDatabaseType::Hashes:     return "Hashes";
    case SignatureDatabaseType::Patterns:   return "Patterns";
    case SignatureDatabaseType::Behavioral: return "Behavioral";
    case SignatureDatabaseType::Emergency:  return "Emergency";
    default:                                return "Unknown";
    }
}

std::string_view GetUpdateStateName(SigUpdateState state) noexcept {
    switch (state) {
    case SigUpdateState::Idle:        return "Idle";
    case SigUpdateState::Checking:    return "Checking";
    case SigUpdateState::Downloading: return "Downloading";
    case SigUpdateState::Patching:    return "Patching";
    case SigUpdateState::Validating:  return "Validating";
    case SigUpdateState::Reloading:   return "Reloading";
    case SigUpdateState::Completed:   return "Completed";
    case SigUpdateState::Failed:      return "Failed";
    default:                          return "Unknown";
    }
}

std::string_view GetUpdateMethodName(UpdateMethod method) noexcept {
    switch (method) {
    case UpdateMethod::Full:        return "Full";
    case UpdateMethod::Delta:       return "Delta";
    case UpdateMethod::Incremental: return "Incremental";
    case UpdateMethod::Rollup:      return "Rollup";
    default:                        return "Unknown";
    }
}

std::string_view GetDatabaseExtension(SignatureDatabaseType type) noexcept {
    switch (type) {
    case SignatureDatabaseType::Main:       return ".sdb";
    case SignatureDatabaseType::Heuristic:  return ".hdb";
    case SignatureDatabaseType::YARA:       return ".yar";
    case SignatureDatabaseType::URLs:       return ".udb";
    case SignatureDatabaseType::Hashes:     return ".hsh";
    case SignatureDatabaseType::Patterns:   return ".pdb";
    case SignatureDatabaseType::Behavioral: return ".bdb";
    case SignatureDatabaseType::Emergency:  return ".edb";
    default:                                return ".dat";
    }
}

// ============================================================================
// FREE FUNCTION — CalculateDeltaPath (BFS shortest path)
// ============================================================================

std::vector<DeltaPatchInfo> CalculateDeltaPath(
    uint64_t fromVersion,
    uint64_t toVersion,
    const std::vector<DeltaPatchInfo>& availablePatches)
{
    if (fromVersion == toVersion || availablePatches.empty()) {
        return {};
    }

    if (fromVersion > toVersion) {
        SS_LOG_WARN(kLogCategory,
            L"CalculateDeltaPath: fromVersion (%llu) > toVersion (%llu) — downgrade not supported via delta",
            static_cast<unsigned long long>(fromVersion),
            static_cast<unsigned long long>(toVersion));
        return {};
    }

    // Build adjacency list: version -> list of (target_version, patch_index)
    std::unordered_map<uint64_t, std::vector<std::pair<uint64_t, size_t>>> adj;
    for (size_t i = 0; i < availablePatches.size(); ++i) {
        const auto& patch = availablePatches[i];
        if (patch.fromVersion < patch.toVersion) {
            adj[patch.fromVersion].emplace_back(patch.toVersion, i);
        }
    }

    // BFS for shortest path (fewest patches)
    // Each node in the queue: (version, path of patch indices)
    struct BfsNode {
        uint64_t version;
        std::vector<size_t> path;
    };

    std::queue<BfsNode> bfsQueue;
    std::set<uint64_t> visited;

    bfsQueue.push({fromVersion, {}});
    visited.insert(fromVersion);

    // Cap the BFS to avoid runaway exploration
    constexpr size_t kMaxBfsNodes = 100000;
    size_t nodesExplored = 0;

    while (!bfsQueue.empty() && nodesExplored < kMaxBfsNodes) {
        auto current = std::move(bfsQueue.front());
        bfsQueue.pop();
        ++nodesExplored;

        // Cap chain length
        if (current.path.size() >= SigUpdateConstants::MAX_DELTA_CHAIN_LENGTH) {
            continue;
        }

        auto adjIt = adj.find(current.version);
        if (adjIt == adj.end()) continue;

        for (const auto& [nextVer, patchIdx] : adjIt->second) {
            if (visited.contains(nextVer)) continue;

            auto newPath = current.path;
            newPath.push_back(patchIdx);

            if (nextVer == toVersion) {
                // Found shortest path — reconstruct
                std::vector<DeltaPatchInfo> result;
                result.reserve(newPath.size());
                for (const auto idx : newPath) {
                    result.push_back(availablePatches[idx]);
                }
                return result;
            }

            visited.insert(nextVer);
            bfsQueue.push({nextVer, std::move(newPath)});
        }
    }

    // No path found
    SS_LOG_DEBUG(kLogCategory,
        L"No delta path found from version %llu to %llu (%zu patches available)",
        static_cast<unsigned long long>(fromVersion),
        static_cast<unsigned long long>(toVersion),
        availablePatches.size());
    return {};
}

}  // namespace Update
}  // namespace ShadowStrike

