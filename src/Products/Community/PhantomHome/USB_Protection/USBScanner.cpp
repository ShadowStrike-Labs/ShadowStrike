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
 * ShadowStrike NGAV - USB SCANNER IMPLEMENTATION
 * ============================================================================
 *
 * @file USBScanner.cpp
 * @brief Enterprise-grade USB drive malware scanner implementation.
 *
 * Implements comprehensive USB scanning using PhantomCore infrastructure:
 * - HashUtils (BCrypt SHA-256/SHA-1/MD5) for file hashing
 * - HashStore for known-malware hash lookups (sub-microsecond)
 * - PatternStore for byte-pattern/Aho-Corasick signature matching
 * - SignatureStore for YARA rule scanning
 * - QuarantineManager for active file quarantine
 * - ThreadPool for concurrent scanning with priority scheduling
 * - Logger (SS_LOG_*) for enterprise audit logging
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: AGPL-3.0-or-later
 * ============================================================================
 */

#include "pch.h"
#include "USBScanner.hpp"
#include "USBDeviceMonitor.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "PhantomCore/Utils/FileUtils.hpp"
#include "PhantomCore/Utils/HashUtils.hpp"
#include "PhantomCore/Utils/JSONUtils.hpp"
#include "PhantomCore/HashStore/HashStore.hpp"
#include "PhantomCore/PatternStore/PatternStore.hpp"
#include "PhantomCore/SignatureStore/SignatureStore.hpp"
#include "PhantomCore/ThreatIntel/ThreatIntelManager.hpp"
#include "PhantomCore/Utils/ThreadPool.hpp"
#include "PhantomCore/Core/Engine/QuarantineManager.hpp"

#include <filesystem>
#include <fstream>
#include <algorithm>
#include <condition_variable>
#include <sstream>
#include <iomanip>
#include <cmath>

namespace fs = std::filesystem;

namespace ShadowStrike {
namespace USB {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================

static constexpr const wchar_t* LOG_CATEGORY = L"USBScanner";

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> USBScanner::s_instanceCreated{false};

// ============================================================================
// ANONYMOUS NAMESPACE — LOCAL HELPERS
// ============================================================================

namespace {

// ────────────────────────────────────────────────────────────────────────────
// RAII wrapper for Win32 HANDLE (prevents leaks on every exit path)
// ────────────────────────────────────────────────────────────────────────────

struct ScopedHandle {
    HANDLE handle = INVALID_HANDLE_VALUE;

    ScopedHandle() = default;
    explicit ScopedHandle(HANDLE h) noexcept : handle(h) {}
    ~ScopedHandle() { Close(); }

    void Close() noexcept {
        if (handle != INVALID_HANDLE_VALUE) {
            ::CloseHandle(handle);
            handle = INVALID_HANDLE_VALUE;
        }
    }

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    ScopedHandle(ScopedHandle&& o) noexcept : handle(o.handle) {
        o.handle = INVALID_HANDLE_VALUE;
    }
    ScopedHandle& operator=(ScopedHandle&& o) noexcept {
        if (this != &o) { Close(); handle = o.handle; o.handle = INVALID_HANDLE_VALUE; }
        return *this;
    }

    [[nodiscard]] bool IsValid() const noexcept { return handle != INVALID_HANDLE_VALUE; }
    [[nodiscard]] HANDLE Get() const noexcept { return handle; }
};

// ────────────────────────────────────────────────────────────────────────────
// Hash computation helpers
// ────────────────────────────────────────────────────────────────────────────

/// Compute SHA-256 from an already-opened HANDLE.  Reads in streaming
/// chunks so arbitrarily large files never blow the working set.
/// Returns lowercase hex or empty string on failure.
[[nodiscard]] std::string ComputeSHA256FromHandle(HANDLE hFile) noexcept {
    try {
        Utils::HashUtils::Hasher hasher(Utils::HashUtils::Algorithm::SHA256);
        if (!hasher.Init()) return {};

        constexpr DWORD kChunkSize = 256 * 1024;   // 256 KB read buffer
        uint8_t buf[kChunkSize];
        DWORD bytesRead = 0;

        for (;;) {
            if (!::ReadFile(hFile, buf, kChunkSize, &bytesRead, nullptr)) break;
            if (bytesRead == 0) break;
            if (!hasher.Update(buf, bytesRead)) return {};
        }

        std::vector<uint8_t> digest;
        if (!hasher.Final(digest) || digest.size() != 32) return {};
        return Utils::HashUtils::ToHexLower(digest);
    } catch (...) {
        return {};
    }
}

/// Compute SHA-1 of a file by path (forensic hash, used only post-detection).
[[nodiscard]] bool ComputeFileSHA1(const fs::path& filePath,
                                    std::string& outHex) noexcept {
    try {
        std::vector<uint8_t> digest;
        Utils::HashUtils::Error err{};
        if (!Utils::HashUtils::ComputeFile(
                Utils::HashUtils::Algorithm::SHA1,
                filePath.wstring(), digest, &err)) {
            return false;
        }
        outHex = Utils::HashUtils::ToHexLower(digest);
        return true;
    } catch (...) {
        return false;
    }
}

/// Compute MD5 of a file by path (forensic hash, used only post-detection).
[[nodiscard]] bool ComputeFileMD5(const fs::path& filePath,
                                   std::string& outHex) noexcept {
    try {
        std::vector<uint8_t> digest;
        Utils::HashUtils::Error err{};
        if (!Utils::HashUtils::ComputeFile(
                Utils::HashUtils::Algorithm::MD5,
                filePath.wstring(), digest, &err)) {
            return false;
        }
        outHex = Utils::HashUtils::ToHexLower(digest);
        return true;
    } catch (...) {
        return false;
    }
}

/// Check if a file extension is among priority scan extensions (case-insensitive).
[[nodiscard]] bool IsPriorityScanExtension(std::string_view ext) noexcept {
    for (const char* pe : USBScannerConstants::PRIORITY_EXTENSIONS) {
        if (ext.size() == std::string_view(pe).size()) {
            bool match = true;
            for (size_t i = 0; i < ext.size(); ++i) {
                if (std::tolower(static_cast<unsigned char>(ext[i])) !=
                    std::tolower(static_cast<unsigned char>(pe[i]))) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
    }
    return false;
}

/// Check whether a file is a reparse point (symlink, junction, etc.).
[[nodiscard]] bool IsReparsePoint(const std::wstring& path) noexcept {
    DWORD attrs = ::GetFileAttributesW(path.c_str());
    return (attrs != INVALID_FILE_ATTRIBUTES) &&
           (attrs & FILE_ATTRIBUTE_REPARSE_POINT);
}

/// Map a SignatureStore ThreatLevel to a 0-100 risk score.
[[nodiscard]] int ThreatLevelToRiskScore(SignatureStore::ThreatLevel level) noexcept {
    switch (level) {
        case SignatureStore::ThreatLevel::Critical: return 100;
        case SignatureStore::ThreatLevel::High:     return 85;
        case SignatureStore::ThreatLevel::Medium:   return 60;
        case SignatureStore::ThreatLevel::Low:      return 30;
        default:                                    return 10;
    }
}

}  // anonymous namespace

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class USBScannerImpl {
public:
    USBScannerImpl() = default;

    ~USBScannerImpl() {
        Shutdown();
    }

    USBScannerImpl(const USBScannerImpl&) = delete;
    USBScannerImpl& operator=(const USBScannerImpl&) = delete;
    USBScannerImpl(USBScannerImpl&&) = delete;
    USBScannerImpl& operator=(USBScannerImpl&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const USBScannerConfiguration& config) {
        std::unique_lock lock(m_mutex);

        if (m_status != ScannerModuleStatus::Uninitialized &&
            m_status != ScannerModuleStatus::Stopped) {
            SS_LOG_WARN(LOG_CATEGORY, L"USBScanner already initialized");
            return false;
        }

        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid scanner configuration");
            m_status = ScannerModuleStatus::Error;
            return false;
        }

        m_status = ScannerModuleStatus::Initializing;
        m_config = config;
        m_statistics.Reset();

        // Initialize the thread pool for scan workers
        Utils::ThreadPoolConfig tpConfig{};
        tpConfig.minThreads = 1;
        tpConfig.maxThreads = std::max<size_t>(2, config.threadPoolSize);
        tpConfig.threadNamePrefix = L"ShadowStrike-USBScan";
        tpConfig.enableETW = false;
        tpConfig.enableDeadlockDetection = false;

        m_threadPool = std::make_unique<Utils::ThreadPool>(tpConfig);
        if (!m_threadPool->Initialize()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to initialize scan thread pool");
            m_status = ScannerModuleStatus::Error;
            return false;
        }

        // Log detection layer readiness
        if (!m_hashStore.IsInitialized()) {
            SS_LOG_WARN(LOG_CATEGORY,
                L"HashStore not initialized — hash-based detection layer disabled");
        }
        if (!m_signatureStore.IsInitialized()) {
            SS_LOG_WARN(LOG_CATEGORY,
                L"SignatureStore not initialized — YARA detection layer disabled");
        }
        if (!m_patternStore.IsInitialized()) {
            SS_LOG_WARN(LOG_CATEGORY,
                L"PatternStore not initialized — pattern detection layer disabled");
        }

        m_status = ScannerModuleStatus::Running;

        SS_LOG_INFO(LOG_CATEGORY, L"USBScanner initialized successfully");
        SS_LOG_INFO(LOG_CATEGORY, L"  Thread pool size: %zu", config.threadPoolSize);
        SS_LOG_INFO(LOG_CATEGORY, L"  Auto-scan on mount: %ls",
            config.autoScanOnMount ? L"enabled" : L"disabled");
        SS_LOG_INFO(LOG_CATEGORY, L"  Max file size: %llu MB",
            config.defaultScanConfig.maxFileSize / (1024 * 1024));

        return true;
    }

    void Shutdown() {
        std::unique_lock lock(m_mutex);

        if (m_status == ScannerModuleStatus::Uninitialized ||
            m_status == ScannerModuleStatus::Stopped) {
            return;
        }

        m_status = ScannerModuleStatus::Stopping;

        // Cancel any active scan
        if (m_scanActive.load(std::memory_order_acquire)) {
            m_cancelRequested.store(true, std::memory_order_release);
            m_pauseFlag.store(false, std::memory_order_release);
            m_pauseCV.notify_all();
        }

        // Wait for scan thread to complete
        if (m_scanFuture.valid()) {
            lock.unlock();
            try { m_scanFuture.wait(); } catch (...) {}
            lock.lock();
        }

        // Shutdown thread pool
        if (m_threadPool) {
            m_threadPool->Shutdown(true);
            m_threadPool.reset();
        }

        // Clear callbacks under lock
        m_progressCallback = nullptr;
        m_threatCallback = nullptr;
        m_completeCallback = nullptr;
        m_errorCallback = nullptr;

        // Clear drive root
        m_currentDriveRoot.clear();

        m_status = ScannerModuleStatus::Stopped;
        SS_LOG_INFO(LOG_CATEGORY, L"USBScanner shutdown complete");
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        auto s = m_status.load(std::memory_order_acquire);
        return s == ScannerModuleStatus::Running ||
               s == ScannerModuleStatus::Scanning;
    }

    [[nodiscard]] ScannerModuleStatus GetStatus() const noexcept {
        return m_status.load(std::memory_order_acquire);
    }

    [[nodiscard]] bool UpdateConfiguration(const USBScannerConfiguration& config) {
        std::unique_lock lock(m_mutex);

        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid scanner configuration");
            return false;
        }

        m_config = config;
        SS_LOG_INFO(LOG_CATEGORY, L"Scanner configuration updated");
        return true;
    }

    [[nodiscard]] USBScannerConfiguration GetConfiguration() const {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    // ========================================================================
    // SCANNING
    // ========================================================================

    [[nodiscard]] bool ScanDrive(const std::string& rootPath,
                                  const USBScanConfig& config) {
        std::unique_lock lock(m_mutex);

        if (m_status != ScannerModuleStatus::Running) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ScanDrive called but module is not running");
            return false;
        }

        if (m_scanActive.load(std::memory_order_acquire)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Scan already in progress");
            return false;
        }

        if (rootPath.empty() || rootPath.size() > 4) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid drive root path");
            return false;
        }

        // Store drive root for symlink/junction validation (H2)
        {
            std::wstring wideRoot(rootPath.begin(), rootPath.end());
            m_currentDriveRoot = std::move(wideRoot);
        }

        // Reset scan state
        m_cancelRequested.store(false, std::memory_order_release);
        m_pauseFlag.store(false, std::memory_order_release);
        m_scanActive.store(true, std::memory_order_release);

        m_progress = {};
        m_summary = {};
        m_summary.drivePath = rootPath;
        m_summary.startTime = std::chrono::system_clock::now();
        m_summary.status = ScanStatus::Initializing;
        m_progress.status = ScanStatus::Initializing;

        m_statistics.totalScans.fetch_add(1, std::memory_order_relaxed);

        SS_LOG_INFO(LOG_CATEGORY, L"Starting scan of drive: %hs", rootPath.c_str());

        USBScanConfig scanConfig = config;
        m_scanFuture = m_threadPool->Submit(
            [this, rootPath, scanConfig](const Utils::TaskContext& ctx) {
                ExecuteScan(rootPath, scanConfig, ctx);
            },
            Utils::TaskPriority::High,
            "USB Drive Scan: " + rootPath
        );

        return true;
    }

    [[nodiscard]] bool ScanDriveAsync(const std::string& rootPath,
                                       ProgressCallback progressCallback) {
        if (progressCallback) {
            std::unique_lock lock(m_mutex);
            m_progressCallback = std::move(progressCallback);
        }
        return ScanDrive(rootPath, m_config.defaultScanConfig);
    }
    // ────────────────────────────────────────────────────────────────────────
    // ScanFile — the per-file detection pipeline
    // ────────────────────────────────────────────────────────────────────────
    //
    // Detection order (layered, cheapest first):
    //   1. Path validation (symlink / junction / reparse point — H2)
    //   2. Open with TOCTOU lock (FILE_SHARE_READ — H1)
    //   3. SHA-256 hash from handle
    //   4. HashStore lookup (C1)
    //   5. SignatureStore YARA scan (C2)
    //   6. PatternStore byte-pattern scan (C3)
    //   7. Heuristic analysis
    //   8. Forensic hashes (SHA-1/MD5) on detection
    // ────────────────────────────────────────────────────────────────────────

    [[nodiscard]] FileScanResultInfo ScanFile(const fs::path& filePath) {
        FileScanResultInfo result;
        result.filePath = filePath;
        result.scanTime = std::chrono::system_clock::now();
        auto scanStart = Clock::now();
        const std::wstring widePath = filePath.wstring();

        // ── Validate file exists ────────────────────────────────────────────
        std::error_code ec;
        if (!fs::exists(filePath, ec) || ec) {
            result.result = FileScanResult::Error;
            return result;
        }

        // ── H2: Symlink / junction / reparse-point guard ───────────────────
        if (IsReparsePoint(widePath)) {
            SS_LOG_DEBUG(LOG_CATEGORY,
                L"Skipping reparse point: %ls", widePath.c_str());
            result.result = FileScanResult::Skipped;
            m_statistics.totalFilesScanned.fetch_add(1, std::memory_order_relaxed);
            return result;
        }

        // If we are inside a drive scan, verify the resolved path stays
        // under the USB drive root.  This prevents symlink-escape attacks.
        {
            std::wstring driveRoot;
            {
                std::shared_lock lock(m_mutex);
                driveRoot = m_currentDriveRoot;
            }
            if (!driveRoot.empty()) {
                Utils::FileUtils::Error fuErr{};
                if (!Utils::FileUtils::IsPathUnderRoot(
                        widePath, driveRoot, true, &fuErr)) {
                    SS_LOG_WARN(LOG_CATEGORY,
                        L"File resolves outside drive root, skipping: %ls",
                        widePath.c_str());
                    result.result = FileScanResult::Skipped;
                    m_statistics.totalFilesScanned.fetch_add(1, std::memory_order_relaxed);
                    return result;
                }
            }
        }

        // ── H1: Open file with TOCTOU lock ─────────────────────────────────
        // FILE_SHARE_READ allows our detection stores to read the same file
        // while preventing any writer from modifying / replacing it.
        ScopedHandle fileHandle(::CreateFileW(
            widePath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,           // deny writes and deletes
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_SEQUENTIAL_SCAN, // optimise for sequential read
            nullptr));

        if (!fileHandle.IsValid()) {
            DWORD lastErr = ::GetLastError();
            if (lastErr == ERROR_ACCESS_DENIED || lastErr == ERROR_SHARING_VIOLATION) {
                result.result = FileScanResult::AccessDenied;
            } else {
                result.result = FileScanResult::Error;
            }
            SS_LOG_DEBUG(LOG_CATEGORY,
                L"Cannot open file (error %lu): %ls", lastErr, widePath.c_str());
            m_statistics.totalFilesScanned.fetch_add(1, std::memory_order_relaxed);
            return result;
        }

        // ── Get file size from the locked handle ────────────────────────────
        LARGE_INTEGER fileSize{};
        if (!::GetFileSizeEx(fileHandle.Get(), &fileSize)) {
            result.result = FileScanResult::Error;
            m_statistics.totalFilesScanned.fetch_add(1, std::memory_order_relaxed);
            return result;
        }
        result.fileSize = static_cast<uint64_t>(fileSize.QuadPart);

        // Cap — skip files exceeding the configured size limit
        if (result.fileSize > m_config.defaultScanConfig.maxFileSize) {
            result.result = FileScanResult::Skipped;
            m_statistics.totalFilesScanned.fetch_add(1, std::memory_order_relaxed);
            return result;
        }

        // ── Phase 1: SHA-256 from the locked handle ─────────────────────────
        result.sha256 = ComputeSHA256FromHandle(fileHandle.Get());
        if (result.sha256.empty()) {
            result.result = FileScanResult::AccessDenied;
            m_statistics.totalFilesScanned.fetch_add(1, std::memory_order_relaxed);
            return result;
        }

        // Reset file pointer for any subsequent reads by stores
        LARGE_INTEGER zero{};
        ::SetFilePointerEx(fileHandle.Get(), zero, nullptr, FILE_BEGIN);

        // ── Phase 2 (C1): HashStore lookup ──────────────────────────────────
        if (m_hashStore.IsInitialized()) {
            auto hashHit = m_hashStore.LookupHashString(
                result.sha256, SignatureStore::HashType::SHA256);

            if (hashHit.has_value()) {
                const auto& det = hashHit.value();
                DetectedThreat threat;
                threat.type        = DetectionType::HashMatch;
                threat.threatName  = det.signatureName;
                threat.signatureId = det.signatureId;
                threat.riskScore   = ThreatLevelToRiskScore(det.threatLevel);
                threat.confidence  = 100;
                threat.details     = det.description;
                result.threats.push_back(std::move(threat));
                result.result = FileScanResult::Infected;
                result.primaryThreatName = det.signatureName;
                m_statistics.hashMatches.fetch_add(1, std::memory_order_relaxed);

                SS_LOG_INFO(LOG_CATEGORY,
                    L"HashStore hit: %ls — %hs",
                    widePath.c_str(), det.signatureName.c_str());
            }
        }

        // ── Phase 3 (C2): SignatureStore / YARA scan ────────────────────────
        // Use SignatureStore with YARA-only (hash & pattern handled separately).
        if (m_signatureStore.IsInitialized()) {
            SignatureStore::ScanOptions sigOpts;
            sigOpts.enableHashLookup  = false;   // handled in Phase 2
            sigOpts.enablePatternScan = false;   // handled in Phase 4
            sigOpts.enableYaraScan    = true;

            auto sigResult = m_signatureStore.ScanFile(widePath, sigOpts);

            for (auto& det : sigResult.detections) {
                DetectedThreat threat;
                threat.type        = DetectionType::YARAMatch;
                threat.threatName  = det.signatureName;
                threat.signatureId = det.signatureId;
                threat.riskScore   = ThreatLevelToRiskScore(det.threatLevel);
                threat.confidence  = 95;
                threat.details     = det.description;
                result.threats.push_back(std::move(threat));
                m_statistics.yaraMatches.fetch_add(1, std::memory_order_relaxed);
            }

            for (const auto& ym : sigResult.yaraMatches) {
                m_statistics.signatureMatches.fetch_add(1, std::memory_order_relaxed);
            }

            if (sigResult.HasDetections() &&
                result.result != FileScanResult::Infected) {
                result.result = FileScanResult::Infected;
                if (result.primaryThreatName.empty() &&
                    !sigResult.detections.empty()) {
                    result.primaryThreatName =
                        sigResult.detections.front().signatureName;
                }
            }
        }

        // ── Phase 4 (C3): PatternStore byte-pattern scan ────────────────────
        if (m_patternStore.IsInitialized()) {
            SignatureStore::QueryOptions patOpts;
            auto patternHits = m_patternStore.ScanFile(widePath, patOpts);

            for (auto& det : patternHits) {
                DetectedThreat threat;
                threat.type        = DetectionType::SignatureMatch;
                threat.threatName  = det.signatureName;
                threat.signatureId = det.signatureId;
                threat.riskScore   = ThreatLevelToRiskScore(det.threatLevel);
                threat.confidence  = 90;
                threat.details     = det.description;
                result.threats.push_back(std::move(threat));
                m_statistics.signatureMatches.fetch_add(1, std::memory_order_relaxed);
            }

            if (!patternHits.empty() &&
                result.result != FileScanResult::Infected) {
                result.result = FileScanResult::Infected;
                if (result.primaryThreatName.empty()) {
                    result.primaryThreatName =
                        patternHits.front().signatureName;
                }
            }
        }

        // ── Phase 5: Heuristic analysis ─────────────────────────────────────
        if (m_config.defaultScanConfig.useHeuristics) {
            PerformHeuristicAnalysis(filePath, result);
        }

        // ── Close the TOCTOU handle BEFORE quarantine (so quarantine can
        //    move / delete the file). ────────────────────────────────────────
        fileHandle.Close();

        // ── Phase 6: Forensic hashes on detection ───────────────────────────
        if (result.result == FileScanResult::Infected ||
            result.result == FileScanResult::Suspicious) {
            ComputeFileSHA1(filePath, result.sha1);
            ComputeFileMD5(filePath, result.md5);
        }

        // Default to clean if no detection layer triggered
        if (result.result != FileScanResult::Infected &&
            result.result != FileScanResult::Suspicious &&
            result.result != FileScanResult::Skipped &&
            result.result != FileScanResult::Error &&
            result.result != FileScanResult::AccessDenied) {
            result.result = FileScanResult::Clean;
        }

        // Update statistics
        m_statistics.totalFilesScanned.fetch_add(1, std::memory_order_relaxed);
        m_statistics.totalBytesScanned.fetch_add(result.fileSize, std::memory_order_relaxed);

        auto scanEnd = Clock::now();
        result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(
            scanEnd - scanStart);

        return result;
    }

    // ────────────────────────────────────────────────────────────────────────
    // Scan control
    // ────────────────────────────────────────────────────────────────────────

    void PauseScan() {
        if (m_scanActive.load(std::memory_order_acquire)) {
            m_pauseFlag.store(true, std::memory_order_release);
            {
                std::unique_lock lock(m_mutex);
                m_progress.status = ScanStatus::Paused;
                m_summary.status  = ScanStatus::Paused;
            }
            SS_LOG_INFO(LOG_CATEGORY, L"Scan paused");
        }
    }

    void ResumeScan() {
        if (m_scanActive.load(std::memory_order_acquire) &&
            m_pauseFlag.load(std::memory_order_acquire)) {
            m_pauseFlag.store(false, std::memory_order_release);
            m_pauseCV.notify_all();
            {
                std::unique_lock lock(m_mutex);
                m_progress.status = ScanStatus::Scanning;
                m_summary.status  = ScanStatus::Scanning;
            }
            SS_LOG_INFO(LOG_CATEGORY, L"Scan resumed");
        }
    }

    void CancelScan() {
        if (m_scanActive.load(std::memory_order_acquire)) {
            m_cancelRequested.store(true, std::memory_order_release);
            m_pauseFlag.store(false, std::memory_order_release);
            m_pauseCV.notify_all();
            SS_LOG_INFO(LOG_CATEGORY, L"Scan cancellation requested");
        }
    }

    [[nodiscard]] USBScanResultSummary WaitForCompletion() {
        if (m_scanFuture.valid()) {
            try { m_scanFuture.wait(); } catch (...) {}
        }
        std::shared_lock lock(m_mutex);
        return m_summary;
    }

    // ========================================================================
    // STATUS
    // ========================================================================

    [[nodiscard]] USBScanProgress GetProgress() const {
        std::shared_lock lock(m_mutex);
        return m_progress;
    }

    [[nodiscard]] bool IsScanning() const noexcept {
        return m_scanActive.load(std::memory_order_acquire);
    }

    [[nodiscard]] std::optional<USBScanResultSummary> GetLastScanResult() const {
        std::shared_lock lock(m_mutex);
        if (m_summary.status != ScanStatus::NotStarted) {
            return m_summary;
        }
        return std::nullopt;
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void RegisterProgressCallback(ProgressCallback cb) {
        std::unique_lock lock(m_mutex);
        m_progressCallback = std::move(cb);
    }

    void RegisterThreatCallback(ThreatDetectedCallback cb) {
        std::unique_lock lock(m_mutex);
        m_threatCallback = std::move(cb);
    }

    void RegisterCompleteCallback(ScanCompleteCallback cb) {
        std::unique_lock lock(m_mutex);
        m_completeCallback = std::move(cb);
    }

    void RegisterErrorCallback(ErrorCallback cb) {
        std::unique_lock lock(m_mutex);
        m_errorCallback = std::move(cb);
    }

    void UnregisterCallbacks() {
        std::unique_lock lock(m_mutex);
        m_progressCallback = nullptr;
        m_threatCallback   = nullptr;
        m_completeCallback = nullptr;
        m_errorCallback    = nullptr;
    }

    // ========================================================================
    // STATISTICS  (H4 — snapshot of atomics)
    // ========================================================================

    [[nodiscard]] USBScanStatisticsSnapshot GetStatistics() const {
        USBScanStatisticsSnapshot snap;
        snap.totalScans           = m_statistics.totalScans.load(std::memory_order_relaxed);
        snap.completedScans       = m_statistics.completedScans.load(std::memory_order_relaxed);
        snap.cancelledScans       = m_statistics.cancelledScans.load(std::memory_order_relaxed);
        snap.erroredScans         = m_statistics.erroredScans.load(std::memory_order_relaxed);
        snap.totalFilesScanned    = m_statistics.totalFilesScanned.load(std::memory_order_relaxed);
        snap.totalBytesScanned    = m_statistics.totalBytesScanned.load(std::memory_order_relaxed);
        snap.totalThreatsFound    = m_statistics.totalThreatsFound.load(std::memory_order_relaxed);
        snap.totalFilesQuarantined = m_statistics.totalFilesQuarantined.load(std::memory_order_relaxed);
        snap.totalFilesDeleted    = m_statistics.totalFilesDeleted.load(std::memory_order_relaxed);
        snap.hashMatches          = m_statistics.hashMatches.load(std::memory_order_relaxed);
        snap.signatureMatches     = m_statistics.signatureMatches.load(std::memory_order_relaxed);
        snap.yaraMatches          = m_statistics.yaraMatches.load(std::memory_order_relaxed);
        snap.heuristicDetections  = m_statistics.heuristicDetections.load(std::memory_order_relaxed);

        for (size_t i = 0; i < m_statistics.byDetectionType.size(); ++i) {
            snap.byDetectionType[i] = m_statistics.byDetectionType[i].load(std::memory_order_relaxed);
        }

        snap.startTime = m_statistics.startTime;
        return snap;
    }

    void ResetStatistics() {
        m_statistics.Reset();
    }

    // ========================================================================
    // SELF-TEST
    // ========================================================================

    [[nodiscard]] bool SelfTest() {
        SS_LOG_INFO(LOG_CATEGORY, L"Starting USBScanner self-test...");

        try {
            USBScannerConfiguration goodConfig;
            if (!goodConfig.IsValid()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: default config invalid");
                return false;
            }

            // SHA-256 hasher smoke test
            {
                Utils::HashUtils::Hasher hasher(Utils::HashUtils::Algorithm::SHA256);
                if (!hasher.Init()) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: SHA-256 hasher init");
                    return false;
                }
                const char testData[] = "ShadowStrike USBScanner SelfTest";
                if (!hasher.Update(testData, sizeof(testData) - 1)) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: SHA-256 update");
                    return false;
                }
                std::vector<uint8_t> digest;
                if (!hasher.Final(digest) || digest.size() != 32) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: SHA-256 final");
                    return false;
                }
            }

            // Priority extension check
            if (!IsPriorityScanExtension(".exe")) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: .exe not detected as priority");
                return false;
            }
            if (IsPriorityScanExtension(".txt")) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: .txt false positive");
                return false;
            }

            // Thread pool health
            if (m_threadPool && !m_threadPool->IsInitialized()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: thread pool not initialized");
                return false;
            }

            SS_LOG_INFO(LOG_CATEGORY, L"USBScanner self-test completed successfully");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Self-test exception: %hs", e.what());
            return false;
        }
    }
private:
    // ========================================================================
    // PRIVATE: SCAN EXECUTION
    // ========================================================================

    void ExecuteScan(const std::string& rootPath,
                     const USBScanConfig& config,
                     const Utils::TaskContext& ctx) {

        SS_LOG_INFO(LOG_CATEGORY, L"Scan execution started for %hs", rootPath.c_str());

        {
            std::unique_lock lock(m_mutex);
            m_summary.status  = ScanStatus::Scanning;
            m_progress.status = ScanStatus::Scanning;
        }

        m_status.store(ScannerModuleStatus::Scanning, std::memory_order_release);

        try {
            // Phase 1: Enumerate files
            UpdateProgressStatus(0.0f);

            std::vector<fs::path> priorityFiles;
            std::vector<fs::path> normalFiles;

            EnumerateFiles(rootPath, config, priorityFiles, normalFiles);

            const uint64_t totalFiles = priorityFiles.size() + normalFiles.size();

            {
                std::unique_lock lock(m_mutex);
                m_progress.totalFiles = totalFiles;
                m_summary.filesScanned = 0;
            }

            if (totalFiles == 0) {
                SS_LOG_INFO(LOG_CATEGORY, L"No files to scan on %hs", rootPath.c_str());
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Enumerated %llu files (%zu priority, %zu normal)",
                totalFiles, priorityFiles.size(), normalFiles.size());

            // Phase 2: Scan priority files first, then normal files
            uint64_t scannedCount = 0;
            auto scanStartTime = Clock::now();

            auto scanFileList = [&](const std::vector<fs::path>& files) {
                for (const auto& filePath : files) {
                    if (CheckCancellation(ctx)) return;
                    HandlePause();

                    // Copy current-file name under lock, then release
                    {
                        std::unique_lock lock(m_mutex);
                        m_progress.currentFile = filePath.filename().string();
                        m_progress.currentDirectory = filePath.parent_path().string();
                    }

                    FileScanResultInfo result = ScanFile(filePath);
                    result.relativePath = fs::relative(filePath, rootPath);

                    // Handle detection
                    if (result.result == FileScanResult::Infected) {
                        HandleInfectedFile(result, config);
                    } else if (result.result == FileScanResult::Suspicious) {
                        HandleSuspiciousFile(result);
                    } else if (result.result == FileScanResult::Skipped) {
                        std::unique_lock lock(m_mutex);
                        m_summary.filesSkipped++;
                    } else if (result.result == FileScanResult::Error ||
                               result.result == FileScanResult::AccessDenied) {
                        std::unique_lock lock(m_mutex);
                        m_summary.errors++;
                    }

                    // Update counters and progress
                    scannedCount++;

                    ProgressCallback progressCb;
                    USBScanProgress progressCopy;
                    {
                        std::unique_lock lock(m_mutex);
                        m_progress.filesScanned = scannedCount;
                        m_progress.bytesScanned += result.fileSize;
                        m_summary.filesScanned = scannedCount;
                        m_summary.bytesScanned += result.fileSize;

                        if (totalFiles > 0) {
                            m_progress.progressPercent =
                                (static_cast<float>(scannedCount) /
                                 static_cast<float>(totalFiles)) * 100.0f;
                        }

                        // Calculate scan speed and ETA
                        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                            Clock::now() - scanStartTime);
                        if (elapsed.count() > 0) {
                            m_progress.scanSpeedBps =
                                (static_cast<double>(m_progress.bytesScanned) * 1000.0) /
                                static_cast<double>(elapsed.count());

                            if (scannedCount > 0 && totalFiles > scannedCount) {
                                double msPerFile = static_cast<double>(elapsed.count()) /
                                                   static_cast<double>(scannedCount);
                                uint64_t remaining = totalFiles - scannedCount;
                                m_progress.estimatedTimeRemaining =
                                    std::chrono::seconds(static_cast<int64_t>(
                                        (msPerFile * remaining) / 1000.0));
                            }
                        }

                        // Copy callback + progress UNDER the lock for safe invocation
                        if (scannedCount % USBScannerConstants::PROGRESS_UPDATE_INTERVAL == 0) {
                            progressCb   = m_progressCallback;
                            progressCopy = m_progress;
                        }
                    }

                    // Invoke callback OUTSIDE the lock to avoid deadlock
                    if (progressCb) {
                        try { progressCb(progressCopy); } catch (...) {}
                    }
                }
            };

            scanFileList(priorityFiles);
            if (!CheckCancellation(ctx)) {
                scanFileList(normalFiles);
            }

            // Phase 3: Completion
            ScanCompleteCallback completeCb;
            USBScanResultSummary summaryCopy;
            {
                std::unique_lock lock(m_mutex);
                m_summary.endTime = std::chrono::system_clock::now();
                m_summary.totalDuration = std::chrono::duration_cast<std::chrono::seconds>(
                    m_summary.endTime - m_summary.startTime);

                if (m_summary.totalDuration.count() > 0) {
                    m_summary.averageSpeedBps =
                        static_cast<double>(m_summary.bytesScanned) /
                        static_cast<double>(m_summary.totalDuration.count());
                }

                if (m_cancelRequested.load(std::memory_order_acquire)) {
                    m_summary.status  = ScanStatus::Cancelled;
                    m_progress.status = ScanStatus::Cancelled;
                    m_statistics.cancelledScans.fetch_add(1, std::memory_order_relaxed);
                } else {
                    m_summary.status  = ScanStatus::Completed;
                    m_progress.status = ScanStatus::Completed;
                    m_progress.progressPercent = 100.0f;
                    m_statistics.completedScans.fetch_add(1, std::memory_order_relaxed);
                }

                completeCb  = m_completeCallback;
                summaryCopy = m_summary;
            }

            m_scanActive.store(false, std::memory_order_release);
            m_status.store(ScannerModuleStatus::Running, std::memory_order_release);

            // Notify completion outside the lock
            if (completeCb) {
                try { completeCb(summaryCopy); } catch (...) {}
            }

            SS_LOG_INFO(LOG_CATEGORY,
                L"Scan completed: %hs — Scanned: %llu, Infected: %llu, "
                L"Suspicious: %llu, Duration: %llds",
                rootPath.c_str(), summaryCopy.filesScanned,
                summaryCopy.filesInfected, summaryCopy.filesSuspicious,
                summaryCopy.totalDuration.count());

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Scan failed with exception: %hs", e.what());

            ErrorCallback errCb;
            {
                std::unique_lock lock(m_mutex);
                m_summary.status  = ScanStatus::Error;
                m_progress.status = ScanStatus::Error;
                m_summary.endTime = std::chrono::system_clock::now();
                m_statistics.erroredScans.fetch_add(1, std::memory_order_relaxed);
                errCb = m_errorCallback;
            }

            m_scanActive.store(false, std::memory_order_release);
            m_status.store(ScannerModuleStatus::Running, std::memory_order_release);

            if (errCb) {
                try { errCb(e.what(), -1); } catch (...) {}
            }
        }
    }

    // ========================================================================
    // PRIVATE: FILE ENUMERATION  (H2 — skip reparse points + root check)
    // ========================================================================

    void EnumerateFiles(const std::string& rootPath,
                        const USBScanConfig& config,
                        std::vector<fs::path>& priorityFiles,
                        std::vector<fs::path>& normalFiles) {

        const std::wstring wideRoot(rootPath.begin(), rootPath.end());

        try {
            for (auto it = fs::recursive_directory_iterator(
                     rootPath, fs::directory_options::skip_permission_denied);
                 it != fs::recursive_directory_iterator(); ++it) {

                if (CheckCancellation()) return;

                if (static_cast<size_t>(it.depth()) > config.scanDepth) {
                    it.disable_recursion_pending();
                    continue;
                }

                std::error_code ec;
                const auto& path = it->path();

#ifdef _WIN32
                // Skip reparse points (symlinks / junctions) early in enumeration
                DWORD attrs = ::GetFileAttributesW(path.c_str());
                if (attrs != INVALID_FILE_ATTRIBUTES) {
                    if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) {
                        it.disable_recursion_pending();
                        continue;
                    }
                    if (!config.scanHiddenFiles && (attrs & FILE_ATTRIBUTE_HIDDEN)) {
                        continue;
                    }
                    if (!config.scanSystemFiles && (attrs & FILE_ATTRIBUTE_SYSTEM)) {
                        continue;
                    }
                }
#endif

                if (!it->is_regular_file(ec) || ec) {
                    if (it->is_directory(ec) && !ec) {
                        std::unique_lock lock(m_mutex);
                        m_summary.directoriesScanned++;
                    }
                    continue;
                }

                // Validate the resolved path stays under the drive root
                {
                    Utils::FileUtils::Error fuErr{};
                    if (!Utils::FileUtils::IsPathUnderRoot(
                            path.wstring(), wideRoot, true, &fuErr)) {
                        SS_LOG_WARN(LOG_CATEGORY,
                            L"Enumeration: path escapes drive root, skipping: %ls",
                            path.c_str());
                        continue;
                    }
                }

                if (IsPathExcluded(path, config)) {
                    continue;
                }

                std::string ext = path.extension().string();
                if (config.priorityFilesFirst && IsPriorityScanExtension(ext)) {
                    priorityFiles.push_back(path);
                } else {
                    normalFiles.push_back(path);
                }
            }
        } catch (const fs::filesystem_error& e) {
            SS_LOG_WARN(LOG_CATEGORY, L"Enumeration error in %hs: %hs",
                rootPath.c_str(), e.what());
        }
    }

    [[nodiscard]] bool IsPathExcluded(const fs::path& path,
                                       const USBScanConfig& config) const {
        std::string pathStr = path.string();
        for (const auto& excluded : config.excludedPaths) {
            if (pathStr.find(excluded) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    // ========================================================================
    // PRIVATE: HEURISTIC ANALYSIS
    // ========================================================================

    void PerformHeuristicAnalysis(const fs::path& filePath,
                                  FileScanResultInfo& result) {
        std::string filename = filePath.filename().string();

        // Heuristic 1: Double extension (e.g. "document.pdf.exe")
        size_t firstDot = filename.find('.');
        size_t lastDot  = filename.rfind('.');
        if (firstDot != lastDot && firstDot != std::string::npos) {
            std::string realExt = filename.substr(lastDot);
            if (IsPriorityScanExtension(realExt)) {
                std::string innerExt = filename.substr(firstDot, lastDot - firstDot);
                if (innerExt == ".pdf" || innerExt == ".doc" || innerExt == ".docx" ||
                    innerExt == ".xls" || innerExt == ".xlsx" || innerExt == ".txt" ||
                    innerExt == ".jpg" || innerExt == ".png" || innerExt == ".mp3") {
                    DetectedThreat threat;
                    threat.type       = DetectionType::Heuristic;
                    threat.threatName = "Heuristic.DoubleExtension";
                    threat.details    = "Double extension detected: " + filename;
                    threat.riskScore  = 60;
                    threat.confidence = 70;
                    result.threats.push_back(std::move(threat));
                    result.result = FileScanResult::Suspicious;
                    result.primaryThreatName = "Heuristic.DoubleExtension";
                    m_statistics.heuristicDetections.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }

        // Heuristic 2: Hidden executable
#ifdef _WIN32
        DWORD attrs = ::GetFileAttributesW(filePath.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES &&
            (attrs & FILE_ATTRIBUTE_HIDDEN) &&
            IsPriorityScanExtension(filePath.extension().string())) {
            DetectedThreat threat;
            threat.type       = DetectionType::Heuristic;
            threat.threatName = "Heuristic.HiddenExecutable";
            threat.details    = "Hidden executable: " + filename;
            threat.riskScore  = 50;
            threat.confidence = 60;
            result.threats.push_back(std::move(threat));
            if (result.result == FileScanResult::Clean) {
                result.result = FileScanResult::Suspicious;
                result.primaryThreatName = "Heuristic.HiddenExecutable";
            }
            m_statistics.heuristicDetections.fetch_add(1, std::memory_order_relaxed);
        }
#endif
    }
    // ========================================================================
    // PRIVATE: THREAT HANDLING  (C4 — real quarantine via QuarantineManager)
    // ========================================================================

    void HandleInfectedFile(FileScanResultInfo& result,
                            const USBScanConfig& config) {
        m_statistics.totalThreatsFound.fetch_add(1, std::memory_order_relaxed);

        // Copy info needed for logging before acquiring lock
        const std::string pathStr  = result.filePath.string();
        const std::string threatNm = result.primaryThreatName;
        const std::string sha256   = result.sha256;

        ThreatDetectedCallback threatCb;
        {
            std::unique_lock lock(m_mutex);
            m_summary.filesInfected++;
            m_summary.infectedFiles.push_back(result);
            m_progress.threatsFound++;
            threatCb = m_threatCallback;
        }

        SS_LOG_WARN(LOG_CATEGORY,
            L"THREAT DETECTED: %hs — %hs (SHA-256: %hs)",
            pathStr.c_str(), threatNm.c_str(), sha256.c_str());

        // Execute configured response action
        switch (config.detectionAction) {
            case DetectionAction::Quarantine:
            {
                // C4: Actually quarantine via QuarantineManager
                auto& qm = Core::Engine::QuarantineManager::Instance();
                if (qm.IsInitialized()) {
                    std::wstring widePath(result.filePath.wstring());
                    std::wstring wideThreat(threatNm.begin(), threatNm.end());
                    auto qResult = qm.QuarantineFile(widePath, wideThreat, 0);

                    if (qResult.IsSuccess()) {
                        result.actionTaken = DetectionAction::Quarantine;
                        {
                            std::unique_lock lock(m_mutex);
                            m_summary.filesQuarantined++;
                        }
                        m_statistics.totalFilesQuarantined.fetch_add(
                            1, std::memory_order_relaxed);
                        SS_LOG_INFO(LOG_CATEGORY,
                            L"File quarantined successfully: %hs", pathStr.c_str());
                    } else {
                        SS_LOG_ERROR(LOG_CATEGORY,
                            L"Quarantine failed for %hs: %ls",
                            pathStr.c_str(), qResult.message.c_str());
                        result.actionTaken = DetectionAction::Report;
                    }
                } else {
                    SS_LOG_WARN(LOG_CATEGORY,
                        L"QuarantineManager not initialized — falling back to report");
                    result.actionTaken = DetectionAction::Report;
                }
                break;
            }

            case DetectionAction::Delete:
            {
                std::error_code ec;
                fs::remove(result.filePath, ec);
                if (!ec) {
                    result.actionTaken = DetectionAction::Delete;
                    {
                        std::unique_lock lock(m_mutex);
                        m_summary.filesDeleted++;
                    }
                    m_statistics.totalFilesDeleted.fetch_add(1, std::memory_order_relaxed);
                    SS_LOG_WARN(LOG_CATEGORY,
                        L"Infected file deleted: %hs", pathStr.c_str());
                } else {
                    SS_LOG_ERROR(LOG_CATEGORY,
                        L"Failed to delete infected file: %hs (error: %hs)",
                        pathStr.c_str(), ec.message().c_str());
                }
                break;
            }

            case DetectionAction::Report:
                result.actionTaken = DetectionAction::Report;
                break;

            case DetectionAction::Block:
                result.actionTaken = DetectionAction::Block;
                break;

            default:
                break;
        }

        // Notify threat callback OUTSIDE the lock
        if (threatCb) {
            try { threatCb(result); } catch (...) {
                SS_LOG_WARN(LOG_CATEGORY, L"Threat callback threw exception");
            }
        }
    }

    void HandleSuspiciousFile(FileScanResultInfo& result) {
        ThreatDetectedCallback threatCb;
        {
            std::unique_lock lock(m_mutex);
            m_summary.filesSuspicious++;
            m_summary.suspiciousFiles.push_back(result);
            threatCb = m_threatCallback;
        }

        SS_LOG_INFO(LOG_CATEGORY,
            L"Suspicious file: %hs — %hs",
            result.filePath.string().c_str(),
            result.primaryThreatName.c_str());

        if (threatCb) {
            try { threatCb(result); } catch (...) {}
        }
    }

    // ========================================================================
    // PRIVATE: SYNCHRONIZATION HELPERS  (H3)
    // ========================================================================

    [[nodiscard]] bool CheckCancellation() const noexcept {
        return m_cancelRequested.load(std::memory_order_acquire);
    }

    [[nodiscard]] bool CheckCancellation(const Utils::TaskContext& ctx) const noexcept {
        return m_cancelRequested.load(std::memory_order_acquire) || ctx.IsCancelled();
    }

    void HandlePause() {
        std::unique_lock lock(m_pauseMutex);
        while (m_pauseFlag.load(std::memory_order_acquire) &&
               !m_cancelRequested.load(std::memory_order_acquire)) {
            m_pauseCV.wait(lock);
        }
    }

    // ========================================================================
    // PRIVATE: NOTIFICATION HELPERS
    // ========================================================================

    void UpdateProgressStatus(float percent) {
        std::unique_lock lock(m_mutex);
        m_progress.progressPercent = percent;
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    std::atomic<ScannerModuleStatus> m_status{ScannerModuleStatus::Uninitialized};
    USBScannerConfiguration m_config;

    // Thread pool (owned)
    std::unique_ptr<Utils::ThreadPool> m_threadPool;

    // Detection stores (owned; optionally initialized)
    HashStore::HashStore           m_hashStore;
    PatternStore::PatternStore     m_patternStore;
    SignatureStore::SignatureStore  m_signatureStore;

    // Scan state (atomics for lock-free reads from worker thread)
    std::atomic<bool> m_scanActive{false};
    std::atomic<bool> m_cancelRequested{false};
    std::atomic<bool> m_pauseFlag{false};
    std::mutex m_pauseMutex;
    std::condition_variable m_pauseCV;
    std::shared_future<void> m_scanFuture;

    // Drive root for symlink validation (protected by m_mutex)
    std::wstring m_currentDriveRoot;

    // Progress and summary (protected by m_mutex)
    USBScanProgress m_progress;
    USBScanResultSummary m_summary;

    // Statistics (all atomic — no lock needed for individual reads)
    USBScanStatistics m_statistics;

    // Callbacks (protected by m_mutex)
    ProgressCallback       m_progressCallback;
    ThreatDetectedCallback m_threatCallback;
    ScanCompleteCallback   m_completeCallback;
    ErrorCallback          m_errorCallback;
};

// ============================================================================
// USBScanner SINGLETON IMPLEMENTATION
// ============================================================================

USBScanner& USBScanner::Instance() noexcept {
    static USBScanner instance;
    return instance;
}

bool USBScanner::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

USBScanner::USBScanner()
    : m_impl(std::make_unique<USBScannerImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

USBScanner::~USBScanner() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    s_instanceCreated.store(false, std::memory_order_release);
}

// ============================================================================
// LIFECYCLE DELEGATIONS
// ============================================================================

bool USBScanner::Initialize(const USBScannerConfiguration& config) {
    return m_impl->Initialize(config);
}

void USBScanner::Shutdown() {
    m_impl->Shutdown();
}

bool USBScanner::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ScannerModuleStatus USBScanner::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool USBScanner::UpdateConfiguration(const USBScannerConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

USBScannerConfiguration USBScanner::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

// ============================================================================
// SCANNING DELEGATIONS
// ============================================================================

bool USBScanner::ScanDrive(const std::string& rootPath, const USBScanConfig& config) {
    return m_impl->ScanDrive(rootPath, config);
}

bool USBScanner::ScanDriveAsync(const std::string& rootPath, ProgressCallback cb) {
    return m_impl->ScanDriveAsync(rootPath, std::move(cb));
}

FileScanResultInfo USBScanner::ScanFile(const fs::path& filePath) {
    return m_impl->ScanFile(filePath);
}

void USBScanner::PauseScan() {
    m_impl->PauseScan();
}

void USBScanner::ResumeScan() {
    m_impl->ResumeScan();
}

void USBScanner::CancelScan() {
    m_impl->CancelScan();
}

USBScanResultSummary USBScanner::WaitForCompletion() {
    return m_impl->WaitForCompletion();
}

// ============================================================================
// STATUS DELEGATIONS
// ============================================================================

USBScanProgress USBScanner::GetProgress() const {
    return m_impl->GetProgress();
}

bool USBScanner::IsScanning() const noexcept {
    return m_impl->IsScanning();
}

std::optional<USBScanResultSummary> USBScanner::GetLastScanResult() const {
    return m_impl->GetLastScanResult();
}

// ============================================================================
// CALLBACK DELEGATIONS
// ============================================================================

void USBScanner::RegisterProgressCallback(ProgressCallback cb) {
    m_impl->RegisterProgressCallback(std::move(cb));
}

void USBScanner::RegisterThreatCallback(ThreatDetectedCallback cb) {
    m_impl->RegisterThreatCallback(std::move(cb));
}

void USBScanner::RegisterCompleteCallback(ScanCompleteCallback cb) {
    m_impl->RegisterCompleteCallback(std::move(cb));
}

void USBScanner::RegisterErrorCallback(ErrorCallback cb) {
    m_impl->RegisterErrorCallback(std::move(cb));
}

void USBScanner::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

// ============================================================================
// STATISTICS DELEGATIONS  (H4 — returns snapshot, not the live struct)
// ============================================================================

USBScanStatisticsSnapshot USBScanner::GetStatistics() const {
    return m_impl->GetStatistics();
}

void USBScanner::ResetStatistics() {
    m_impl->ResetStatistics();
}

bool USBScanner::SelfTest() {
    return m_impl->SelfTest();
}

std::string USBScanner::GetVersionString() noexcept {
    return std::to_string(USBScannerConstants::VERSION_MAJOR) + "." +
           std::to_string(USBScannerConstants::VERSION_MINOR) + "." +
           std::to_string(USBScannerConstants::VERSION_PATCH);
}
// ============================================================================
// STRUCTURE IMPLEMENTATIONS — ToJson()
// ============================================================================

bool USBScanConfig::IsValid() const noexcept {
    if (maxFileSize == 0) return false;
    if (scanDepth == 0 || scanDepth > USBScannerConstants::MAX_SCAN_DEPTH) return false;
    if (maxArchiveDepth > 20) return false;
    return true;
}

std::string USBScanConfig::ToJson() const {
    Utils::JSON::Json json;
    json["scanArchives"]      = scanArchives;
    json["scanHiddenFiles"]   = scanHiddenFiles;
    json["scanSystemFiles"]   = scanSystemFiles;
    json["useHeuristics"]     = useHeuristics;
    json["useYARA"]           = useYARA;
    json["checkThreatIntel"]  = checkThreatIntel;
    json["maxFileSize"]       = maxFileSize;
    json["scanDepth"]         = scanDepth;
    json["maxArchiveDepth"]   = maxArchiveDepth;
    json["priority"]          = static_cast<uint8_t>(priority);
    json["detectionAction"]   = static_cast<uint8_t>(detectionAction);
    json["priorityFilesFirst"] = priorityFilesFirst;
    json["resumeOnReconnect"] = resumeOnReconnect;
    return json.dump();
}

std::string DetectedThreat::ToJson() const {
    Utils::JSON::Json json;
    json["type"]         = static_cast<uint8_t>(type);
    json["typeName"]     = std::string(GetDetectionTypeName(type));
    json["threatName"]   = threatName;
    json["threatFamily"] = threatFamily;
    json["signatureId"]  = signatureId;
    json["riskScore"]    = riskScore;
    json["confidence"]   = confidence;
    json["mitreAttackId"] = mitreAttackId;
    json["details"]      = details;
    return json.dump();
}

std::string FileScanResultInfo::ToJson() const {
    Utils::JSON::Json json;
    json["filePath"]          = filePath.string();
    json["relativePath"]      = relativePath.string();
    json["result"]            = static_cast<uint8_t>(result);
    json["resultName"]        = std::string(GetFileScanResultName(result));
    json["primaryThreatName"] = primaryThreatName;
    json["fileSize"]          = fileSize;
    json["sha256"]            = sha256;
    json["sha1"]              = sha1;
    json["md5"]               = md5;
    json["actionTaken"]       = static_cast<uint8_t>(actionTaken);
    json["actionName"]        = std::string(GetDetectionActionName(actionTaken));
    json["scanDurationUs"]    = scanDuration.count();

    json["threats"] = Utils::JSON::Json::array();
    for (const auto& threat : threats) {
        Utils::JSON::Json tj;
        Utils::JSON::Parse(threat.ToJson(), tj);
        json["threats"].push_back(tj);
    }

    return json.dump();
}

std::string USBScanProgress::ToJson() const {
    Utils::JSON::Json json;
    json["status"]              = static_cast<uint8_t>(status);
    json["statusName"]          = std::string(GetScanStatusName(status));
    json["progressPercent"]     = progressPercent;
    json["filesScanned"]        = filesScanned;
    json["totalFiles"]          = totalFiles;
    json["bytesScanned"]        = bytesScanned;
    json["totalBytes"]          = totalBytes;
    json["currentFile"]         = currentFile;
    json["currentDirectory"]    = currentDirectory;
    json["threatsFound"]        = threatsFound;
    json["estimatedTimeRemainingSeconds"] = estimatedTimeRemaining.count();
    json["scanSpeedBps"]        = scanSpeedBps;
    return json.dump();
}

std::string USBScanResultSummary::ToJson() const {
    Utils::JSON::Json json;
    json["status"]                = static_cast<uint8_t>(status);
    json["statusName"]            = std::string(GetScanStatusName(status));
    json["drivePath"]             = drivePath;
    json["volumeLabel"]           = volumeLabel;
    json["filesScanned"]          = filesScanned;
    json["directoriesScanned"]    = directoriesScanned;
    json["bytesScanned"]          = bytesScanned;
    json["filesInfected"]         = filesInfected;
    json["filesSuspicious"]       = filesSuspicious;
    json["filesQuarantined"]      = filesQuarantined;
    json["filesDeleted"]          = filesDeleted;
    json["filesSkipped"]          = filesSkipped;
    json["errors"]                = errors;
    json["totalDurationSeconds"]  = totalDuration.count();
    json["averageSpeedBps"]       = averageSpeedBps;

    json["infectedFiles"] = Utils::JSON::Json::array();
    for (const auto& f : infectedFiles) {
        Utils::JSON::Json fj;
        Utils::JSON::Parse(f.ToJson(), fj);
        json["infectedFiles"].push_back(fj);
    }

    json["suspiciousFiles"] = Utils::JSON::Json::array();
    for (const auto& f : suspiciousFiles) {
        Utils::JSON::Json fj;
        Utils::JSON::Parse(f.ToJson(), fj);
        json["suspiciousFiles"].push_back(fj);
    }

    return json.dump();
}

bool USBScanResultSummary::IsClean() const noexcept {
    return filesInfected == 0;
}

// ============================================================================
// STATISTICS IMPLEMENTATION
// ============================================================================

void USBScanStatistics::Reset() noexcept {
    totalScans.store(0, std::memory_order_relaxed);
    completedScans.store(0, std::memory_order_relaxed);
    cancelledScans.store(0, std::memory_order_relaxed);
    erroredScans.store(0, std::memory_order_relaxed);
    totalFilesScanned.store(0, std::memory_order_relaxed);
    totalBytesScanned.store(0, std::memory_order_relaxed);
    totalThreatsFound.store(0, std::memory_order_relaxed);
    totalFilesQuarantined.store(0, std::memory_order_relaxed);
    totalFilesDeleted.store(0, std::memory_order_relaxed);
    hashMatches.store(0, std::memory_order_relaxed);
    signatureMatches.store(0, std::memory_order_relaxed);
    yaraMatches.store(0, std::memory_order_relaxed);
    heuristicDetections.store(0, std::memory_order_relaxed);

    for (auto& counter : byDetectionType) {
        counter.store(0, std::memory_order_relaxed);
    }

    startTime = Clock::now();
}

// ============================================================================
// USBScanStatisticsSnapshot::ToJson  (H4)
// ============================================================================

std::string USBScanStatisticsSnapshot::ToJson() const {
    Utils::JSON::Json json;
    json["totalScans"]            = totalScans;
    json["completedScans"]        = completedScans;
    json["cancelledScans"]        = cancelledScans;
    json["erroredScans"]          = erroredScans;
    json["totalFilesScanned"]     = totalFilesScanned;
    json["totalBytesScanned"]     = totalBytesScanned;
    json["totalThreatsFound"]     = totalThreatsFound;
    json["totalFilesQuarantined"] = totalFilesQuarantined;
    json["totalFilesDeleted"]     = totalFilesDeleted;
    json["hashMatches"]           = hashMatches;
    json["signatureMatches"]      = signatureMatches;
    json["yaraMatches"]           = yaraMatches;
    json["heuristicDetections"]   = heuristicDetections;

    auto uptimeSeconds = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();
    json["uptimeSeconds"]         = uptimeSeconds;
    return json.dump();
}

// ============================================================================
// CONFIGURATION VALIDATION
// ============================================================================

bool USBScannerConfiguration::IsValid() const noexcept {
    if (threadPoolSize == 0 || threadPoolSize > 32) return false;
    if (cacheHours > 8760) return false;  // Max 1 year
    return defaultScanConfig.IsValid();
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetScanStatusName(ScanStatus status) noexcept {
    switch (status) {
        case ScanStatus::NotStarted:    return "NotStarted";
        case ScanStatus::Initializing:  return "Initializing";
        case ScanStatus::Scanning:      return "Scanning";
        case ScanStatus::Paused:        return "Paused";
        case ScanStatus::Completing:    return "Completing";
        case ScanStatus::Completed:     return "Completed";
        case ScanStatus::Cancelled:     return "Cancelled";
        case ScanStatus::Error:         return "Error";
        case ScanStatus::DeviceRemoved: return "DeviceRemoved";
        default:                        return "Unknown";
    }
}

std::string_view GetFileScanResultName(FileScanResult result) noexcept {
    switch (result) {
        case FileScanResult::Clean:        return "Clean";
        case FileScanResult::Infected:     return "Infected";
        case FileScanResult::Suspicious:   return "Suspicious";
        case FileScanResult::Encrypted:    return "Encrypted";
        case FileScanResult::Corrupted:    return "Corrupted";
        case FileScanResult::AccessDenied: return "AccessDenied";
        case FileScanResult::Skipped:      return "Skipped";
        case FileScanResult::Error:        return "Error";
        default:                           return "Unknown";
    }
}

std::string_view GetDetectionTypeName(DetectionType type) noexcept {
    switch (type) {
        case DetectionType::None:            return "None";
        case DetectionType::HashMatch:       return "HashMatch";
        case DetectionType::SignatureMatch:  return "SignatureMatch";
        case DetectionType::YARAMatch:       return "YARAMatch";
        case DetectionType::Heuristic:       return "Heuristic";
        case DetectionType::Behavioral:      return "Behavioral";
        case DetectionType::ThreatIntel:     return "ThreatIntel";
        case DetectionType::MachineLearning: return "MachineLearning";
        default:                             return "Unknown";
    }
}

std::string_view GetScanPriorityName(ScanPriority priority) noexcept {
    switch (priority) {
        case ScanPriority::Low:      return "Low";
        case ScanPriority::Normal:   return "Normal";
        case ScanPriority::High:     return "High";
        case ScanPriority::Critical: return "Critical";
        default:                     return "Unknown";
    }
}

std::string_view GetDetectionActionName(DetectionAction action) noexcept {
    switch (action) {
        case DetectionAction::None:       return "None";
        case DetectionAction::Report:     return "Report";
        case DetectionAction::Quarantine: return "Quarantine";
        case DetectionAction::Delete:     return "Delete";
        case DetectionAction::Block:      return "Block";
        case DetectionAction::Disinfect:  return "Disinfect";
        default:                          return "Unknown";
    }
}

bool IsPriorityFileExtension(std::string_view extension) noexcept {
    return IsPriorityScanExtension(extension);
}

}  // namespace USB
}  // namespace ShadowStrike