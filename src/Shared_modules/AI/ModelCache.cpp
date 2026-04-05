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
 * ShadowStrike PhantomCortex - MODEL CACHE IMPLEMENTATION
 * ============================================================================
 *
 * @file ModelCache.cpp
 * @brief Implementation of model file management with atomic swap and
 *        SHA-256 integrity verification.
 *
 * Reuses:
 *   - HashUtils::Hasher / ComputeFile  for SHA-256
 *   - FileUtils                        for file I/O, path validation
 *   - NetworkUtils::HttpGet / HttpDownloadFile for downloads
 *   - JSONUtils (nlohmann wrapper)     for manifest persistence
 *   - StringUtils                      for UTF-8 / UTF-16 conversion
 *
 * ============================================================================
 */

#include "pch.h"
#include "ModelCache.hpp"

#include <array>
#include <mutex>
#include <shared_mutex>
#include <filesystem>
#include <algorithm>
#include <cstring>
#include <chrono>
#include <sstream>
#include <iomanip>

#include "../Utils/Logger.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/JSONUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/StringUtils.hpp"

namespace ShadowStrike {
namespace AI {

// ============================================================================
// Anonymous Namespace — Internal Helpers
// ============================================================================

namespace {

    /// Log category for all ModelCache messages
    constexpr const wchar_t* kLogCategory = L"PhantomCortex";

    /// File names within each model slot directory
    constexpr const wchar_t* kCurrentFileName  = L"current.onnx";
    constexpr const wchar_t* kPreviousFileName = L"previous.onnx";
    constexpr const wchar_t* kStagingFileName  = L"staging.onnx";
    constexpr const wchar_t* kManifestFileName = L"manifest.json";

    /// Slot directory names indexed by CortexModelType ordinal
    constexpr std::array<const wchar_t*, CortexConstants::MODEL_COUNT> kSlotNames = {
        L"static",
        L"behavioral",
        L"memory",
        L"network",
        L"emulation"
    };

    // ----------------------------------------------------------------
    // Index Validation
    // ----------------------------------------------------------------

    [[nodiscard]] bool IsValidSlotIndex(CortexModelType type) noexcept {
        return static_cast<size_t>(type) < CortexConstants::MODEL_COUNT;
    }

    [[nodiscard]] size_t SlotIndex(CortexModelType type) noexcept {
        return static_cast<size_t>(type);
    }

    // ----------------------------------------------------------------
    // Path Security
    // ----------------------------------------------------------------

    [[nodiscard]] bool ContainsTraversal(const std::filesystem::path& p) noexcept {
        try {
            const auto str = p.wstring();
            if (str.find(L"..") != std::wstring::npos) {
                return true;
            }
        }
        catch (...) {
            return true;
        }
        return false;
    }

    [[nodiscard]] bool ValidateModelFilePath(const std::filesystem::path& p) noexcept {
        if (ContainsTraversal(p)) {
            SS_LOG_ERROR(kLogCategory, L"Path traversal detected: %ls", p.c_str());
            return false;
        }
        return true;
    }

    // ----------------------------------------------------------------
    // HTTPS URL Scheme Enforcement
    // ----------------------------------------------------------------

    [[nodiscard]] bool IsHttpsUrl(const std::wstring& url) noexcept {
        constexpr std::wstring_view kHttpsPrefix = L"https://";
        if (url.size() < kHttpsPrefix.size()) return false;
        for (size_t i = 0; i < kHttpsPrefix.size(); ++i) {
            if (towlower(static_cast<wint_t>(url[i])) != kHttpsPrefix[i]) {
                return false;
            }
        }
        return true;
    }

    // ----------------------------------------------------------------
    // Symlink / Reparse Point Guard
    // ----------------------------------------------------------------

    [[nodiscard]] bool IsReparsePoint(const std::filesystem::path& p) noexcept {
        try {
            Utils::FileUtils::FileStat stat;
            Utils::FileUtils::Error fErr;
            if (!Utils::FileUtils::Stat(p.wstring(), stat, &fErr)) {
                return false;  // file doesn't exist — not a reparse point
            }
            return stat.isReparsePoint;
        }
        catch (...) { return true; }  // err on the side of caution
    }

    [[nodiscard]] bool RejectIfReparsePoint(const std::filesystem::path& p) noexcept {
        if (IsReparsePoint(p)) {
            SS_LOG_ERROR(kLogCategory,
                L"Reparse point (symlink/junction) detected, refusing operation: %ls",
                p.c_str());
            return false;
        }
        return true;
    }

    // ----------------------------------------------------------------
    // Disk Space Guard
    // ----------------------------------------------------------------

    [[nodiscard]] bool HasSufficientDiskSpace(
            const std::filesystem::path& dir,
            uintmax_t requiredBytes) noexcept {
        try {
            std::error_code ec;
            const auto spaceInfo = std::filesystem::space(dir, ec);
            if (ec) {
                SS_LOG_WARN(kLogCategory,
                    L"Cannot query disk space for %ls: %hs",
                    dir.c_str(), ec.message().c_str());
                return true;  // don't block on query failure
            }
            constexpr uintmax_t kHeadroomBytes = 64ULL * 1024 * 1024;  // 64 MB
            const uintmax_t needed = requiredBytes + kHeadroomBytes;
            if (spaceInfo.available < needed) {
                SS_LOG_ERROR(kLogCategory,
                    L"Insufficient disk space in %ls: available=%llu, required=%llu bytes",
                    dir.c_str(),
                    static_cast<unsigned long long>(spaceInfo.available),
                    static_cast<unsigned long long>(needed));
                return false;
            }
            return true;
        }
        catch (...) {
            return true;  // don't block on exception
        }
    }

    // ----------------------------------------------------------------
    // File-Size Guard
    // ----------------------------------------------------------------

    [[nodiscard]] bool CheckFileSize(const std::filesystem::path& p) noexcept {
        try {
            std::error_code ec;
            const auto size = std::filesystem::file_size(p, ec);
            if (ec) {
                SS_LOG_ERROR(kLogCategory, L"Cannot read file size for %ls: %hs",
                             p.c_str(), ec.message().c_str());
                return false;
            }
            if (size > CortexConstants::MAX_MODEL_FILE_SIZE) {
                SS_LOG_ERROR(kLogCategory,
                    L"Model file %ls exceeds maximum size (%llu > %llu bytes)",
                    p.c_str(),
                    static_cast<unsigned long long>(size),
                    static_cast<unsigned long long>(CortexConstants::MAX_MODEL_FILE_SIZE));
                return false;
            }
            return true;
        }
        catch (...) {
            SS_LOG_ERROR(kLogCategory, L"Exception checking file size for %ls", p.c_str());
            return false;
        }
    }

    // ----------------------------------------------------------------
    // SHA-256 Helpers (delegates to HashUtils)
    // ----------------------------------------------------------------

    [[nodiscard]] bool ComputeFileSha256Hex(const std::filesystem::path& filePath,
                                            std::wstring& outHex) noexcept {
        try {
            std::vector<uint8_t> digest;
            Utils::HashUtils::Error hashErr{};
            if (!Utils::HashUtils::ComputeFile(
                    Utils::HashUtils::Algorithm::SHA256,
                    filePath.wstring(), digest, &hashErr)) {
                SS_LOG_ERROR(kLogCategory,
                    L"SHA-256 computation failed for %ls (NTSTATUS=0x%08X)",
                    filePath.c_str(), static_cast<unsigned>(hashErr.ntstatus));
                return false;
            }
            const std::string hex = Utils::HashUtils::ToHexLower(digest);
            outHex = Utils::StringUtils::ToWide(hex);
            return !outHex.empty();
        }
        catch (...) {
            SS_LOG_ERROR(kLogCategory,
                L"Exception during SHA-256 computation for %ls", filePath.c_str());
            return false;
        }
    }

    [[nodiscard]] bool ConstantTimeHashCompare(const std::wstring& a,
                                               const std::wstring& b) noexcept {
        if (a.size() != b.size()) return false;
        // Accumulator must hold full wchar_t width (16-bit on Windows).
        // Using unsigned char here would truncate XOR results to 8 bits,
        // allowing crafted strings differing only in high byte to pass.
        volatile uint32_t result = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            result |= static_cast<uint32_t>(
                static_cast<uint16_t>(a[i]) ^ static_cast<uint16_t>(b[i]));
        }
        return result == 0;
    }

    // ----------------------------------------------------------------
    // Time Helpers
    // ----------------------------------------------------------------

    [[nodiscard]] std::wstring FormatIso8601(
            std::chrono::system_clock::time_point tp) noexcept {
        try {
            const auto tt = std::chrono::system_clock::to_time_t(tp);
            std::tm gm{};
#ifdef _WIN32
            gmtime_s(&gm, &tt);
#else
            gmtime_r(&tt, &gm);
#endif
            std::ostringstream oss;
            oss << std::put_time(&gm, "%Y-%m-%dT%H:%M:%SZ");
            return Utils::StringUtils::ToWide(oss.str());
        }
        catch (...) {
            return L"1970-01-01T00:00:00Z";
        }
    }

    [[nodiscard]] std::chrono::system_clock::time_point ParseIso8601(
            const std::string& iso) noexcept {
        try {
            std::tm tm{};
            std::istringstream iss(iso);
            iss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
            if (iss.fail()) {
                return {};
            }
#ifdef _WIN32
            const auto tt = _mkgmtime(&tm);
#else
            const auto tt = timegm(&tm);
#endif
            if (tt == static_cast<time_t>(-1)) return {};
            return std::chrono::system_clock::from_time_t(tt);
        }
        catch (...) {
            return {};
        }
    }

    // ----------------------------------------------------------------
    // Safe filesystem wrappers
    // ----------------------------------------------------------------

    [[nodiscard]] bool SafeRename(const std::filesystem::path& from,
                                  const std::filesystem::path& to) noexcept {
        try {
            std::error_code ec;
            std::filesystem::rename(from, to, ec);
            if (ec) {
                SS_LOG_ERROR(kLogCategory, L"Rename failed: %ls -> %ls (%hs)",
                             from.c_str(), to.c_str(), ec.message().c_str());
                return false;
            }
            return true;
        }
        catch (...) {
            SS_LOG_ERROR(kLogCategory, L"Exception renaming %ls -> %ls",
                         from.c_str(), to.c_str());
            return false;
        }
    }

    [[nodiscard]] bool SafeCopyFile(const std::filesystem::path& from,
                                    const std::filesystem::path& to) noexcept {
        try {
            std::error_code ec;
            std::filesystem::copy_file(from, to,
                std::filesystem::copy_options::overwrite_existing, ec);
            if (ec) {
                SS_LOG_ERROR(kLogCategory, L"Copy failed: %ls -> %ls (%hs)",
                             from.c_str(), to.c_str(), ec.message().c_str());
                return false;
            }
            return true;
        }
        catch (...) {
            SS_LOG_ERROR(kLogCategory, L"Exception copying %ls -> %ls",
                         from.c_str(), to.c_str());
            return false;
        }
    }

    void SafeRemove(const std::filesystem::path& p) noexcept {
        try {
            std::error_code ec;
            std::filesystem::remove(p, ec);
        }
        catch (...) { /* best-effort cleanup */ }
    }

    [[nodiscard]] bool SafeExists(const std::filesystem::path& p) noexcept {
        try {
            std::error_code ec;
            return std::filesystem::exists(p, ec) && !ec;
        }
        catch (...) { return false; }
    }

}  // anonymous namespace

// ============================================================================
// Impl Definition
// ============================================================================

struct ModelCache::Impl {

    struct SlotState {
        std::filesystem::path currentModel;
        std::filesystem::path previousModel;
        std::filesystem::path stagingModel;
        std::filesystem::path manifestPath;
        std::wstring          currentHash;
        std::wstring          previousHash;
        ModelVersion          version{};
        bool                  hasModel    = false;
        bool                  hasPrevious = false;
    };

    std::filesystem::path                                           cacheDir;
    std::array<SlotState, CortexConstants::MODEL_COUNT>             slots;
    mutable std::array<std::shared_mutex, CortexConstants::MODEL_COUNT> slotMutexes;
    bool initialized = false;

    // ----------------------------------------------------------------
    // Internal helpers accessible to all member functions
    // ----------------------------------------------------------------

    [[nodiscard]] std::filesystem::path SlotDir(size_t idx) const noexcept {
        try {
            return cacheDir / kSlotNames[idx];
        }
        catch (...) { return {}; }
    }

    /// Populate a SlotState from on-disk files.
    [[nodiscard]] bool ProbeSlot(size_t idx) noexcept {
        auto& s = slots[idx];
        const auto dir = SlotDir(idx);

        s.currentModel  = dir / kCurrentFileName;
        s.previousModel = dir / kPreviousFileName;
        s.stagingModel  = dir / kStagingFileName;
        s.manifestPath  = dir / kManifestFileName;

        // Clean any leftover staging file from a prior interrupted operation
        SafeRemove(s.stagingModel);

        s.hasModel    = SafeExists(s.currentModel);
        s.hasPrevious = SafeExists(s.previousModel);

        if (!s.hasModel) {
            return true;  // slot is empty — acceptable
        }

        // Load manifest
        if (!LoadManifest(idx)) {
            SS_LOG_WARN(kLogCategory,
                L"Manifest load failed for slot '%ls'; will verify from scratch",
                kSlotNames[idx]);
            // Compute hash directly
            if (!ComputeFileSha256Hex(s.currentModel, s.currentHash)) {
                SS_LOG_ERROR(kLogCategory,
                    L"Cannot hash current model for slot '%ls'", kSlotNames[idx]);
                return false;
            }
        }
        return true;
    }

    /// Read manifest.json for a slot and populate version/hash fields.
    [[nodiscard]] bool LoadManifest(size_t idx) noexcept {
        auto& s = slots[idx];
        if (!SafeExists(s.manifestPath)) return false;

        try {
            Utils::JSON::Json doc;
            Utils::JSON::Error jsonErr;
            if (!Utils::JSON::LoadFromFile(s.manifestPath, doc, &jsonErr)) {
                SS_LOG_WARN(kLogCategory,
                    L"Failed to parse manifest for slot '%ls': %hs",
                    kSlotNames[idx], jsonErr.message.c_str());
                return false;
            }

            // SHA-256 hash
            std::string sha;
            if (Utils::JSON::Get<std::string>(doc, "sha256", sha)) {
                s.currentHash = Utils::StringUtils::ToWide(sha);
            }
            else {
                return false;
            }

            // Version
            uint32_t major = 0, minor = 0, patch = 0;
            Utils::JSON::Get<uint32_t>(doc, "version.major", major);
            Utils::JSON::Get<uint32_t>(doc, "version.minor", minor);
            Utils::JSON::Get<uint32_t>(doc, "version.patch", patch);
            s.version.major = major;
            s.version.minor = minor;
            s.version.patch = patch;
            s.version.modelHash = s.currentHash;

            // Trained-at timestamp
            std::string trainedAt;
            if (Utils::JSON::Get<std::string>(doc, "trained_at", trainedAt)) {
                s.version.trainedAt = ParseIso8601(trainedAt);
            }

            return true;
        }
        catch (...) {
            SS_LOG_ERROR(kLogCategory,
                L"Exception loading manifest for slot '%ls'", kSlotNames[idx]);
            return false;
        }
    }

    /// Write manifest.json for a slot using current SlotState fields.
    [[nodiscard]] bool SaveManifest(size_t idx) noexcept {
        auto& s = slots[idx];
        try {
            Utils::JSON::Json doc;

            Utils::JSON::Set(doc, "model_type",
                Utils::StringUtils::ToNarrow(kSlotNames[idx]));

            Utils::JSON::Json ver;
            ver["major"] = s.version.major;
            ver["minor"] = s.version.minor;
            ver["patch"] = s.version.patch;
            Utils::JSON::Set(doc, "version", ver);

            Utils::JSON::Set(doc, "sha256",
                Utils::StringUtils::ToNarrow(s.currentHash));

            Utils::JSON::Set(doc, "trained_at",
                Utils::StringUtils::ToNarrow(
                    FormatIso8601(s.version.trainedAt)));

            // File size
            std::error_code ec;
            const auto sz = std::filesystem::file_size(s.currentModel, ec);
            Utils::JSON::Set(doc, "file_size",
                ec ? static_cast<uint64_t>(0) : sz);

            Utils::JSON::SaveOptions saveOpt;
            saveOpt.pretty = true;
            saveOpt.indentSpaces = 4;
            saveOpt.atomicReplace = true;

            Utils::JSON::Error jsonErr;
            if (!Utils::JSON::SaveToFile(s.manifestPath, doc, &jsonErr, saveOpt)) {
                SS_LOG_ERROR(kLogCategory,
                    L"Failed to save manifest for slot '%ls': %hs",
                    kSlotNames[idx], jsonErr.message.c_str());
                return false;
            }
            return true;
        }
        catch (...) {
            SS_LOG_ERROR(kLogCategory,
                L"Exception saving manifest for slot '%ls'", kSlotNames[idx]);
            return false;
        }
    }

    /// Verify that current.onnx matches the stored hash.
    [[nodiscard]] bool VerifySlotIntegrity(size_t idx) const noexcept {
        const auto& s = slots[idx];
        if (!s.hasModel) return false;
        if (s.currentHash.empty()) return false;
        if (!SafeExists(s.currentModel)) return false;

        std::wstring diskHash;
        if (!ComputeFileSha256Hex(s.currentModel, diskHash)) {
            return false;
        }
        return ConstantTimeHashCompare(diskHash, s.currentHash);
    }
};

// ============================================================================
// Singleton
// ============================================================================

ModelCache& ModelCache::Instance() noexcept {
    static ModelCache instance;
    return instance;
}

// ============================================================================
// Initialize
// ============================================================================

bool ModelCache::Initialize(const std::filesystem::path& cacheDir) noexcept {
    try {
        // Serialize concurrent Initialize calls
        static std::mutex initMutex;
        std::unique_lock initLock(initMutex);
        // Validate input path
        if (cacheDir.empty()) {
            SS_LOG_ERROR(kLogCategory, L"ModelCache::Initialize called with empty cacheDir");
            return false;
        }
        if (ContainsTraversal(cacheDir)) {
            SS_LOG_ERROR(kLogCategory,
                L"ModelCache::Initialize rejected path with traversal: %ls",
                cacheDir.c_str());
            return false;
        }

        // Lazy-construct Impl
        if (!m_impl) {
            try {
                m_impl = std::make_unique<Impl>();
            }
            catch (const std::bad_alloc&) {
                SS_LOG_ERROR(kLogCategory, L"Failed to allocate ModelCache::Impl");
                return false;
            }
        }

        m_impl->cacheDir     = cacheDir;
        m_impl->initialized  = false;

        // Create root cache directory
        {
            Utils::FileUtils::Error fErr;
            if (!Utils::FileUtils::CreateDirectories(cacheDir.wstring(), &fErr)) {
                SS_LOG_ERROR(kLogCategory,
                    L"Cannot create cache root %ls (Win32=%lu)",
                    cacheDir.c_str(), fErr.win32);
                return false;
            }
        }

        // Create per-slot directories and probe existing state
        for (size_t i = 0; i < CortexConstants::MODEL_COUNT; ++i) {
            std::unique_lock lock(m_impl->slotMutexes[i]);

            const auto slotDir = m_impl->SlotDir(i);
            {
                Utils::FileUtils::Error fErr;
                if (!Utils::FileUtils::CreateDirectories(slotDir.wstring(), &fErr)) {
                    SS_LOG_ERROR(kLogCategory,
                        L"Cannot create slot directory %ls (Win32=%lu)",
                        slotDir.c_str(), fErr.win32);
                    return false;
                }
            }

            if (!m_impl->ProbeSlot(i)) {
                SS_LOG_WARN(kLogCategory,
                    L"Slot '%ls' probe failed; attempting rollback",
                    kSlotNames[i]);

                // If current model is corrupt but previous exists, try rollback
                auto& s = m_impl->slots[i];
                if (s.hasPrevious && SafeExists(s.previousModel)) {
                    SafeRemove(s.currentModel);
                    if (SafeRename(s.previousModel, s.currentModel)) {
                        s.hasPrevious = false;
                        s.hasModel = true;

                        if (!ComputeFileSha256Hex(s.currentModel, s.currentHash)) {
                            SS_LOG_ERROR(kLogCategory,
                                L"Rollback hash computation failed for '%ls'",
                                kSlotNames[i]);
                            s.hasModel = false;
                        }
                        else {
                            s.version.modelHash = s.currentHash;
                            m_impl->SaveManifest(i);
                            SS_LOG_INFO(kLogCategory,
                                L"Rolled back slot '%ls' to previous model",
                                kSlotNames[i]);
                        }
                    }
                    else {
                        SS_LOG_ERROR(kLogCategory,
                            L"Rollback rename failed for slot '%ls'", kSlotNames[i]);
                    }
                }
            }
            else {
                // Verify integrity of successfully probed slot
                auto& s = m_impl->slots[i];
                if (s.hasModel && !m_impl->VerifySlotIntegrity(i)) {
                    SS_LOG_WARN(kLogCategory,
                        L"Integrity check failed for slot '%ls'; attempting rollback",
                        kSlotNames[i]);

                    if (s.hasPrevious && SafeExists(s.previousModel)) {
                        SafeRemove(s.currentModel);
                        if (SafeRename(s.previousModel, s.currentModel)) {
                            s.hasPrevious = false;
                            if (ComputeFileSha256Hex(s.currentModel, s.currentHash)) {
                                s.version.modelHash = s.currentHash;
                                m_impl->SaveManifest(i);
                                SS_LOG_INFO(kLogCategory,
                                    L"Integrity rollback succeeded for slot '%ls'",
                                    kSlotNames[i]);
                            }
                            else {
                                s.hasModel = false;
                                SS_LOG_ERROR(kLogCategory,
                                    L"Post-rollback hash failed for slot '%ls'",
                                    kSlotNames[i]);
                            }
                        }
                        else {
                            s.hasModel = false;
                        }
                    }
                    else {
                        SS_LOG_WARN(kLogCategory,
                            L"No previous model for rollback in slot '%ls'; "
                            L"marking slot empty", kSlotNames[i]);
                        s.hasModel = false;
                    }
                }
            }

            if (m_impl->slots[i].hasModel) {
                SS_LOG_INFO(kLogCategory,
                    L"Slot '%ls' ready: v%u.%u.%u sha256=%ls",
                    kSlotNames[i],
                    m_impl->slots[i].version.major,
                    m_impl->slots[i].version.minor,
                    m_impl->slots[i].version.patch,
                    m_impl->slots[i].currentHash.c_str());
            }
            else {
                SS_LOG_INFO(kLogCategory,
                    L"Slot '%ls' is empty (no model loaded)", kSlotNames[i]);
            }
        }

        m_impl->initialized = true;
        SS_LOG_INFO(kLogCategory,
            L"ModelCache initialized at %ls", cacheDir.c_str());
        return true;
    }
    catch (...) {
        SS_LOG_ERROR(kLogCategory,
            L"Unhandled exception in ModelCache::Initialize");
        return false;
    }
}

// ============================================================================
// GetModelPath
// ============================================================================

std::optional<std::filesystem::path> ModelCache::GetModelPath(
        CortexModelType type) const noexcept {
    try {
        if (!m_impl || !m_impl->initialized) return std::nullopt;
        if (!IsValidSlotIndex(type)) return std::nullopt;

        const auto idx = SlotIndex(type);
        std::shared_lock lock(m_impl->slotMutexes[idx]);

        const auto& s = m_impl->slots[idx];
        if (!s.hasModel) return std::nullopt;
        if (!SafeExists(s.currentModel)) return std::nullopt;

        return s.currentModel;
    }
    catch (...) {
        return std::nullopt;
    }
}

// ============================================================================
// VerifyIntegrity
// ============================================================================

bool ModelCache::VerifyIntegrity(CortexModelType type) const noexcept {
    try {
        if (!m_impl || !m_impl->initialized) return false;
        if (!IsValidSlotIndex(type)) return false;

        const auto idx = SlotIndex(type);
        std::shared_lock lock(m_impl->slotMutexes[idx]);

        return m_impl->VerifySlotIntegrity(idx);
    }
    catch (...) {
        return false;
    }
}

// ============================================================================
// SwapModel — Five-Step Atomic Protocol
// ============================================================================

bool ModelCache::SwapModel(CortexModelType type,
                           const std::filesystem::path& newModel) noexcept {
    try {
        if (!m_impl || !m_impl->initialized) {
            SS_LOG_ERROR(kLogCategory,
                L"SwapModel called before initialization");
            return false;
        }
        if (!IsValidSlotIndex(type)) {
            SS_LOG_ERROR(kLogCategory,
                L"SwapModel called with invalid slot index %u",
                static_cast<unsigned>(type));
            return false;
        }
        if (!ValidateModelFilePath(newModel)) return false;
        if (!SafeExists(newModel)) {
            SS_LOG_ERROR(kLogCategory,
                L"SwapModel: source file does not exist: %ls", newModel.c_str());
            return false;
        }
        if (!CheckFileSize(newModel)) return false;

        const auto idx = SlotIndex(type);
        std::unique_lock lock(m_impl->slotMutexes[idx]);
        auto& s = m_impl->slots[idx];

        SS_LOG_INFO(kLogCategory,
            L"SwapModel: beginning atomic swap for slot '%ls'", kSlotNames[idx]);

        // ---- Step 1: Copy newModel → staging.onnx ----
        SafeRemove(s.stagingModel);
        if (!SafeCopyFile(newModel, s.stagingModel)) {
            SS_LOG_ERROR(kLogCategory,
                L"SwapModel step 1 (stage) failed for slot '%ls'", kSlotNames[idx]);
            return false;
        }

        // Post-copy validation on staging (closes TOCTOU gap with source file)
        if (!CheckFileSize(s.stagingModel)) {
            SS_LOG_ERROR(kLogCategory,
                L"SwapModel: staged file exceeds size limit for slot '%ls'",
                kSlotNames[idx]);
            SafeRemove(s.stagingModel);
            return false;
        }
        if (!RejectIfReparsePoint(s.stagingModel)) {
            SafeRemove(s.stagingModel);
            return false;
        }

        // ---- Step 2: Compute SHA-256 of staged file ----
        std::wstring newHash;
        if (!ComputeFileSha256Hex(s.stagingModel, newHash)) {
            SS_LOG_ERROR(kLogCategory,
                L"SwapModel step 2 (hash) failed for slot '%ls'", kSlotNames[idx]);
            SafeRemove(s.stagingModel);
            return false;
        }

        // ---- Step 3: Rename current.onnx → previous.onnx (if exists) ----
        if (s.hasModel && SafeExists(s.currentModel)) {
            SafeRemove(s.previousModel);
            if (!SafeRename(s.currentModel, s.previousModel)) {
                SS_LOG_ERROR(kLogCategory,
                    L"SwapModel step 3 (backup) failed for slot '%ls'",
                    kSlotNames[idx]);
                SafeRemove(s.stagingModel);
                return false;
            }
            s.previousHash = s.currentHash;
            s.hasPrevious  = true;
        }

        // ---- Step 4: Rename staging.onnx → current.onnx ----
        if (!SafeRename(s.stagingModel, s.currentModel)) {
            SS_LOG_ERROR(kLogCategory,
                L"SwapModel step 4 (activate) failed for slot '%ls'; "
                L"restoring previous model", kSlotNames[idx]);

            // Restore from previous
            if (s.hasPrevious && SafeExists(s.previousModel)) {
                SafeRename(s.previousModel, s.currentModel);
                s.hasPrevious = false;
            }
            SafeRemove(s.stagingModel);
            return false;
        }

        // ---- Step 5: Update manifest.json ----
        s.currentHash = newHash;
        s.hasModel    = true;
        s.version.modelHash = newHash;
        // Bump patch version as a minimal version increment
        s.version.patch += 1;
        s.version.trainedAt = std::chrono::system_clock::now();

        if (!m_impl->SaveManifest(idx)) {
            SS_LOG_WARN(kLogCategory,
                L"SwapModel step 5 (manifest) failed for slot '%ls'; "
                L"swap succeeded but manifest is stale", kSlotNames[idx]);
            // Swap itself succeeded — don't roll back for a manifest write failure
        }

        SS_LOG_INFO(kLogCategory,
            L"SwapModel completed for slot '%ls': sha256=%ls v%u.%u.%u",
            kSlotNames[idx], s.currentHash.c_str(),
            s.version.major, s.version.minor, s.version.patch);
        return true;
    }
    catch (...) {
        SS_LOG_ERROR(kLogCategory,
            L"Unhandled exception in ModelCache::SwapModel");
        return false;
    }
}

// ============================================================================
// Rollback
// ============================================================================

bool ModelCache::Rollback(CortexModelType type) noexcept {
    try {
        if (!m_impl || !m_impl->initialized) {
            SS_LOG_ERROR(kLogCategory,
                L"Rollback called before initialization");
            return false;
        }
        if (!IsValidSlotIndex(type)) {
            SS_LOG_ERROR(kLogCategory,
                L"Rollback called with invalid slot index %u",
                static_cast<unsigned>(type));
            return false;
        }

        const auto idx = SlotIndex(type);
        std::unique_lock lock(m_impl->slotMutexes[idx]);
        auto& s = m_impl->slots[idx];

        if (!s.hasPrevious || !SafeExists(s.previousModel)) {
            SS_LOG_WARN(kLogCategory,
                L"Rollback: no previous model available for slot '%ls'",
                kSlotNames[idx]);
            return false;
        }

        // Clean any leftover staging file
        SafeRemove(s.stagingModel);

        // Remove current (may be corrupt)
        SafeRemove(s.currentModel);

        // Promote previous → current
        if (!SafeRename(s.previousModel, s.currentModel)) {
            SS_LOG_ERROR(kLogCategory,
                L"Rollback: rename failed for slot '%ls'", kSlotNames[idx]);
            s.hasModel    = false;
            s.hasPrevious = false;
            return false;
        }

        s.currentHash = s.previousHash;
        s.hasModel    = true;
        s.hasPrevious = false;
        s.previousHash.clear();
        s.version.modelHash = s.currentHash;

        // Recompute hash to ensure integrity
        std::wstring verifyHash;
        if (ComputeFileSha256Hex(s.currentModel, verifyHash)) {
            if (!s.currentHash.empty() && !ConstantTimeHashCompare(verifyHash, s.currentHash)) {
                SS_LOG_WARN(kLogCategory,
                    L"Rollback: previous model hash mismatch for slot '%ls'; "
                    L"updating stored hash", kSlotNames[idx]);
            }
            s.currentHash       = verifyHash;
            s.version.modelHash = verifyHash;
        }

        m_impl->SaveManifest(idx);

        SS_LOG_INFO(kLogCategory,
            L"Rollback succeeded for slot '%ls': sha256=%ls",
            kSlotNames[idx], s.currentHash.c_str());
        return true;
    }
    catch (...) {
        SS_LOG_ERROR(kLogCategory,
            L"Unhandled exception in ModelCache::Rollback");
        return false;
    }
}

// ============================================================================
// DownloadModel
// ============================================================================

bool ModelCache::DownloadModel(CortexModelType type,
                               const std::wstring& url,
                               const std::wstring& expectedSha256) noexcept {
    try {
        if (!m_impl || !m_impl->initialized) {
            SS_LOG_ERROR(kLogCategory,
                L"DownloadModel called before initialization");
            return false;
        }
        if (!IsValidSlotIndex(type)) {
            SS_LOG_ERROR(kLogCategory,
                L"DownloadModel called with invalid slot index %u",
                static_cast<unsigned>(type));
            return false;
        }
        if (url.empty()) {
            SS_LOG_ERROR(kLogCategory, L"DownloadModel called with empty URL");
            return false;
        }
        if (expectedSha256.empty()) {
            SS_LOG_ERROR(kLogCategory,
                L"DownloadModel called with empty expected SHA-256");
            return false;
        }
        if (!IsHttpsUrl(url)) {
            SS_LOG_ERROR(kLogCategory,
                L"DownloadModel rejected non-HTTPS URL: %ls", url.c_str());
            return false;
        }

        const auto idx = SlotIndex(type);
        std::unique_lock lock(m_impl->slotMutexes[idx]);
        auto& s = m_impl->slots[idx];

        // Verify slot directory hasn't been replaced with a symlink/junction
        if (!RejectIfReparsePoint(m_impl->SlotDir(idx))) {
            return false;
        }

        // Pre-flight disk space check (conservative: MAX_MODEL_FILE_SIZE + headroom)
        if (!HasSufficientDiskSpace(m_impl->SlotDir(idx),
                CortexConstants::MAX_MODEL_FILE_SIZE)) {
            return false;
        }

        SS_LOG_INFO(kLogCategory,
            L"Downloading model for slot '%ls' from %ls",
            kSlotNames[idx], url.c_str());

        // Clean any prior staging file
        SafeRemove(s.stagingModel);

        // Download to staging path using NetworkUtils
        Utils::NetworkUtils::HttpRequestOptions reqOpt;
        reqOpt.verifySSL     = true;
        reqOpt.timeoutMs     = 300000;  // 5 min timeout for large models
        reqOpt.allowRedirects = true;
        reqOpt.maxRedirects  = 5;

        Utils::NetworkUtils::Error netErr;
        if (!Utils::NetworkUtils::HttpDownloadFile(
                url, s.stagingModel, reqOpt, nullptr, &netErr)) {
            SS_LOG_ERROR(kLogCategory,
                L"Download failed for slot '%ls': Win32=%lu, msg=%ls",
                kSlotNames[idx], netErr.win32, netErr.message.c_str());
            SafeRemove(s.stagingModel);
            return false;
        }

        // Validate file size
        if (!CheckFileSize(s.stagingModel)) {
            SafeRemove(s.stagingModel);
            return false;
        }

        // Verify SHA-256
        std::wstring downloadedHash;
        if (!ComputeFileSha256Hex(s.stagingModel, downloadedHash)) {
            SS_LOG_ERROR(kLogCategory,
                L"SHA-256 computation failed for downloaded model in slot '%ls'",
                kSlotNames[idx]);
            SafeRemove(s.stagingModel);
            return false;
        }

        // Constant-time comparison: normalize to lowercase
        std::wstring expectedLower = expectedSha256;
        std::transform(expectedLower.begin(), expectedLower.end(),
                       expectedLower.begin(), ::towlower);

        if (!ConstantTimeHashCompare(downloadedHash, expectedLower)) {
            SS_LOG_ERROR(kLogCategory,
                L"SHA-256 mismatch for slot '%ls': expected=%ls got=%ls",
                kSlotNames[idx], expectedLower.c_str(), downloadedHash.c_str());
            SafeRemove(s.stagingModel);
            return false;
        }

        // ---- Atomic Swap: Steps 3-5 (staging already written and verified) ----

        // Step 3: Backup current → previous (if exists)
        if (s.hasModel && SafeExists(s.currentModel)) {
            SafeRemove(s.previousModel);
            if (!SafeRename(s.currentModel, s.previousModel)) {
                SS_LOG_ERROR(kLogCategory,
                    L"DownloadModel step 3 (backup) failed for slot '%ls'",
                    kSlotNames[idx]);
                SafeRemove(s.stagingModel);
                return false;
            }
            s.previousHash = s.currentHash;
            s.hasPrevious  = true;
        }

        // Step 4: Rename staging → current
        if (!SafeRename(s.stagingModel, s.currentModel)) {
            SS_LOG_ERROR(kLogCategory,
                L"DownloadModel step 4 (activate) failed for slot '%ls'; "
                L"restoring previous model", kSlotNames[idx]);
            if (s.hasPrevious && SafeExists(s.previousModel)) {
                SafeRename(s.previousModel, s.currentModel);
                s.hasPrevious = false;
            }
            SafeRemove(s.stagingModel);
            return false;
        }

        // Step 5: Update manifest
        s.currentHash       = downloadedHash;
        s.hasModel          = true;
        s.version.modelHash = downloadedHash;
        s.version.patch += 1;
        s.version.trainedAt = std::chrono::system_clock::now();

        if (!m_impl->SaveManifest(idx)) {
            SS_LOG_WARN(kLogCategory,
                L"DownloadModel step 5 (manifest) failed for slot '%ls'; "
                L"swap succeeded but manifest is stale", kSlotNames[idx]);
        }

        SS_LOG_INFO(kLogCategory,
            L"DownloadModel completed for slot '%ls': sha256=%ls v%u.%u.%u",
            kSlotNames[idx], s.currentHash.c_str(),
            s.version.major, s.version.minor, s.version.patch);
        return true;
    }
    catch (...) {
        SS_LOG_ERROR(kLogCategory,
            L"Unhandled exception in ModelCache::DownloadModel");
        return false;
    }
}

// ============================================================================
// CheckForUpdates
// ============================================================================

bool ModelCache::CheckForUpdates(const std::wstring& manifestUrl) noexcept {
    try {
        if (!m_impl || !m_impl->initialized) {
            SS_LOG_ERROR(kLogCategory,
                L"CheckForUpdates called before initialization");
            return false;
        }
        if (manifestUrl.empty()) {
            SS_LOG_ERROR(kLogCategory,
                L"CheckForUpdates called with empty manifest URL");
            return false;
        }
        if (!IsHttpsUrl(manifestUrl)) {
            SS_LOG_ERROR(kLogCategory,
                L"CheckForUpdates rejected non-HTTPS URL: %ls",
                manifestUrl.c_str());
            return false;
        }

        SS_LOG_INFO(kLogCategory,
            L"Checking for model updates from %ls", manifestUrl.c_str());

        // Download remote manifest
        std::vector<uint8_t> responseBody;
        Utils::NetworkUtils::HttpRequestOptions reqOpt;
        reqOpt.verifySSL      = true;
        reqOpt.timeoutMs      = 30000;
        reqOpt.allowRedirects = true;
        reqOpt.maxRedirects   = 5;

        Utils::NetworkUtils::Error netErr;
        if (!Utils::NetworkUtils::HttpGet(
                manifestUrl, responseBody, reqOpt, &netErr)) {
            SS_LOG_ERROR(kLogCategory,
                L"Failed to fetch remote manifest: Win32=%lu, msg=%ls",
                netErr.win32, netErr.message.c_str());
            return false;
        }

        if (responseBody.empty() || responseBody.size() > Utils::JSON::MAX_JSON_SIZE) {
            SS_LOG_ERROR(kLogCategory,
                L"Remote manifest response invalid (size=%llu)",
                static_cast<unsigned long long>(responseBody.size()));
            return false;
        }

        // Parse JSON
        const std::string jsonStr(
            reinterpret_cast<const char*>(responseBody.data()),
            responseBody.size());

        Utils::JSON::Json remoteDoc;
        Utils::JSON::Error jsonErr;
        if (!Utils::JSON::Parse(jsonStr, remoteDoc, &jsonErr)) {
            SS_LOG_ERROR(kLogCategory,
                L"Failed to parse remote manifest JSON: %hs",
                jsonErr.message.c_str());
            return false;
        }

        bool anyUpdatesAvailable = false;

        // Compare each slot's hash against the remote manifest
        for (size_t i = 0; i < CortexConstants::MODEL_COUNT; ++i) {
            std::shared_lock lock(m_impl->slotMutexes[i]);

            const std::string slotKey =
                Utils::StringUtils::ToNarrow(kSlotNames[i]);

            if (!remoteDoc.contains(slotKey)) continue;

            const auto& slotNode = remoteDoc[slotKey];
            std::string remoteSha;
            if (!Utils::JSON::Get<std::string>(slotNode, "sha256", remoteSha)) {
                continue;
            }

            const std::wstring remoteShaW = Utils::StringUtils::ToWide(remoteSha);
            const auto& localHash = m_impl->slots[i].currentHash;

            if (localHash.empty() || !ConstantTimeHashCompare(localHash, remoteShaW)) {
                SS_LOG_INFO(kLogCategory,
                    L"Update available for slot '%ls'", kSlotNames[i]);
                anyUpdatesAvailable = true;
            }
        }

        if (!anyUpdatesAvailable) {
            SS_LOG_INFO(kLogCategory,
                L"All models are up to date");
        }

        return anyUpdatesAvailable;
    }
    catch (...) {
        SS_LOG_ERROR(kLogCategory,
            L"Unhandled exception in ModelCache::CheckForUpdates");
        return false;
    }
}

}  // namespace AI
}  // namespace ShadowStrike
