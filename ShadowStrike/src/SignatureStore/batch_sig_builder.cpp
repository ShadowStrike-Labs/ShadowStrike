
/**
 * @file batch_sig_builder.cpp
 * @brief Batch Signature Builder - Enterprise-Grade Parallel Processing
 *
 * This file implements high-performance batch signature building with
 * parallel file processing for large-scale malware signature database creation.
 *
 * Architecture:
 * - RAII-based resource management (FindHandleGuard)
 * - Parallel processing via std::execution::par
 * - Lock-free progress tracking with atomic counters
 * - Serialized builder access (SignatureBuilder not thread-safe)
 *
 * Security Features:
 * - Path traversal attack prevention
 * - Symlink/junction loop detection
 * - Resource limits (file count, path length, recursion depth)
 * - Timeout protection for long operations
 * - Input validation on all public methods
 *
 * Thread Safety:
 * - Progress tracking: atomic counters for hot path
 * - Error collection: mutex-protected cold path
 * - Builder access: fully serialized via builderMutex
 * - File list: mutex-protected during modification
 *
 * Performance:
 * - Auto-scaling thread pool (75% of CPU cores)
 * - Lock-free progress updates
 * - Pre-allocated containers to minimize allocations
 * - Efficient parallel file iteration
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 */

#include "SignatureBuilder.hpp"

#include <unordered_set>
#include <algorithm>
#include <execution>
#include <atomic>
#include <memory>
#include <limits>
#include <stdexcept>
#include <thread>
#include <functional>
#include <cwctype>


// ============================================================================
// BATCH SIGNATURE BUILDER - PRODUCTION-GRADE IMPLEMENTATION
// ============================================================================

namespace ShadowStrike {
namespace SignatureStore {

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

namespace {

/// @brief Maximum number of files in a batch (DoS prevention)
constexpr size_t MAX_BATCH_FILES = 1'000'000;

/// @brief Maximum path length (Windows extended path limit)
constexpr size_t MAX_PATH_LENGTH = 32767;

/// @brief Maximum recursion depth for directory scanning
constexpr int MAX_RECURSION_DEPTH = 20;

/// @brief Maximum file size for source files (500 MB)
constexpr uint64_t MAX_SOURCE_FILE_SIZE = 500ULL * 1024ULL * 1024ULL;

/// @brief Directory scan timeout in milliseconds (5 minutes)
constexpr uint64_t DIRECTORY_SCAN_TIMEOUT_MS = 300000;

/// @brief Build timeout in milliseconds (1 hour)
constexpr uint64_t BUILD_TIMEOUT_MS = 3600000;

/// @brief Maximum errors to collect before truncating
constexpr size_t MAX_COLLECTED_ERRORS = 10000;

/// @brief Progress report interval (files processed)
constexpr size_t PROGRESS_REPORT_INTERVAL = 100;

/**
 * @brief Safely check if addition would overflow
 * @param a First value
 * @param b Second value
 * @return True if a + b would overflow size_t
 */
[[nodiscard]] inline bool WouldOverflow(size_t a, size_t b) noexcept {
    return a > std::numeric_limits<size_t>::max() - b;
}

} // anonymous namespace

// ========================================================================
// RAII HANDLE GUARD FOR FindFirstFile/FindClose
// ========================================================================

/**
 * @brief RAII wrapper for Windows HANDLE (FindFirstFile/FindClose)
 *
 * Ensures proper cleanup of find handles on all exit paths.
 * Non-copyable, movable for use in containers.
 */
class FindHandleGuard {
public:
    /// @brief Construct with optional handle (defaults to invalid)
    explicit FindHandleGuard(HANDLE h = INVALID_HANDLE_VALUE) noexcept 
        : m_handle(h) 
    {}

    /// @brief Destructor - closes handle if valid
    ~FindHandleGuard() noexcept {
        Close();
    }

    // Non-copyable (prevent double-close)
    FindHandleGuard(const FindHandleGuard&) = delete;
    FindHandleGuard& operator=(const FindHandleGuard&) = delete;

    // Movable
    FindHandleGuard(FindHandleGuard&& other) noexcept 
        : m_handle(other.m_handle) 
    {
        other.m_handle = INVALID_HANDLE_VALUE;
    }

    FindHandleGuard& operator=(FindHandleGuard&& other) noexcept {
        if (this != &other) {
            Close();
            m_handle = other.m_handle;
            other.m_handle = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    /// @brief Check if handle is valid
    [[nodiscard]] bool IsValid() const noexcept {
        return m_handle != INVALID_HANDLE_VALUE;
    }

    /// @brief Get raw handle (for Windows API calls)
    [[nodiscard]] HANDLE Get() const noexcept {
        return m_handle;
    }

    /// @brief Release handle ownership (caller takes responsibility)
    [[nodiscard]] HANDLE Release() noexcept {
        HANDLE h = m_handle;
        m_handle = INVALID_HANDLE_VALUE;
        return h;
    }

    /// @brief Close handle and reset to invalid
    void Reset(HANDLE h = INVALID_HANDLE_VALUE) noexcept {
        Close();
        m_handle = h;
    }

private:
    /// @brief Close the handle if valid
    void Close() noexcept {
        if (m_handle != INVALID_HANDLE_VALUE) {
            FindClose(m_handle);
            m_handle = INVALID_HANDLE_VALUE;
        }
    }

    HANDLE m_handle;
};

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

/**
 * @brief Default constructor with default configuration
 */
BatchSignatureBuilder::BatchSignatureBuilder()
    : BatchSignatureBuilder(BuildConfiguration{})
{
}

/**
 * @brief Construct with specified build configuration
 * @param config Build configuration settings
 */
BatchSignatureBuilder::BatchSignatureBuilder(const BuildConfiguration& config)
    : m_config(config)
    , m_builder(config)
{
    // Initialize progress to clean state
    m_progress = BatchProgress{};
}

/**
 * @brief Destructor - cleanup handled by RAII members
 */
BatchSignatureBuilder::~BatchSignatureBuilder() {
    // All resources managed by RAII containers (std::vector, std::mutex)
    // Explicitly clear for defense-in-depth
    try {
        std::lock_guard<std::mutex> lock(m_progressMutex);
        m_sourceFiles.clear();
        m_progress = BatchProgress{};
    }
    catch (...) {
        // Destructor must not throw - ignore any exception
    }
}

// ============================================================================
// SOURCE FILE MANAGEMENT
// ============================================================================

/**
 * @brief Add source files for batch processing
 * @param filePaths Span of file paths to add
 * @return StoreError indicating success or failure reason
 *
 * Validates each path for security (traversal attacks, symlinks) and
 * existence before adding to the batch. Duplicates are silently skipped.
 */
StoreError BatchSignatureBuilder::AddSourceFiles(
    std::span<const std::wstring> filePaths
) noexcept {
    // ========================================================================
    // STEP 1: INPUT VALIDATION
    // ========================================================================

    if (filePaths.empty()) {
        SS_LOG_WARN(L"BatchSignatureBuilder", L"AddSourceFiles: Empty file list");
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "No files provided" };
    }

    // DoS prevention: check input batch size
    if (filePaths.size() > MAX_BATCH_FILES) {
        SS_LOG_ERROR(L"BatchSignatureBuilder",
            L"AddSourceFiles: Too many files (%zu > %zu)",
            filePaths.size(), MAX_BATCH_FILES);
        return StoreError{ SignatureStoreError::TooLarge, 0,
                          "Batch exceeds maximum file count (1M)" };
    }

    // Check if adding these files would exceed limit (with overflow check)
    {
        std::lock_guard<std::mutex> lock(m_progressMutex);

        // Overflow-safe addition check
        if (WouldOverflow(m_sourceFiles.size(), filePaths.size()) ||
            m_sourceFiles.size() + filePaths.size() > MAX_BATCH_FILES) {
            SS_LOG_ERROR(L"BatchSignatureBuilder",
                L"AddSourceFiles: Total would exceed limit (%zu + %zu > %zu)",
                m_sourceFiles.size(), filePaths.size(), MAX_BATCH_FILES);
            return StoreError{ SignatureStoreError::TooLarge, 0,
                              "Total batch size would exceed limit" };
        }
    }

    // ========================================================================
    // STEP 2: VALIDATE EACH FILE PATH
    // ========================================================================

    std::vector<std::wstring> validatedPaths;
    validatedPaths.reserve(filePaths.size());
    std::unordered_set<std::wstring> seenPaths;
    seenPaths.reserve(filePaths.size());

    for (size_t i = 0; i < filePaths.size(); ++i) {
        const auto& filePath = filePaths[i];

        // Validate path is not empty
        if (filePath.empty()) {
            SS_LOG_WARN(L"BatchSignatureBuilder",
                L"AddSourceFiles: Empty path at index %zu - skipping", i);
            continue;
        }

        // Validate path length (Windows extended path limit)
        if (filePath.length() > MAX_PATH_LENGTH) {
            SS_LOG_WARN(L"BatchSignatureBuilder",
                L"AddSourceFiles: Path too long at index %zu (%zu > %zu) - skipping",
                i, filePath.length(), MAX_PATH_LENGTH);
            continue;
        }

        // ====================================================================
        // PATH TRAVERSAL ATTACK PREVENTION
        // ====================================================================

        // Reject paths with directory traversal attempts
        if (filePath.find(L"..") != std::wstring::npos) {
            SS_LOG_WARN(L"BatchSignatureBuilder",
                L"AddSourceFiles: Path contains '..' (directory traversal) - skipping");
            continue;
        }

        // Reject paths with home directory reference (Unix-style, but be safe)
        if (filePath.find(L"~") != std::wstring::npos) {
            SS_LOG_WARN(L"BatchSignatureBuilder",
                L"AddSourceFiles: Path contains '~' (home directory) - skipping");
            continue;
        }

        // Reject paths with null bytes (security risk)
        if (filePath.find(L'\0') != std::wstring::npos) {
            SS_LOG_WARN(L"BatchSignatureBuilder",
                L"AddSourceFiles: Path contains null byte at index %zu - skipping", i);
            continue;
        }

        // ====================================================================
        // FILE EXISTENCE & ATTRIBUTE CHECKING
        // ====================================================================

        const DWORD attribs = GetFileAttributesW(filePath.c_str());

        // File must exist and be accessible
        if (attribs == INVALID_FILE_ATTRIBUTES) {
            const DWORD err = GetLastError();

            if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
                SS_LOG_WARN(L"BatchSignatureBuilder",
                    L"AddSourceFiles: File not found at index %zu", i);
            }
            else if (err == ERROR_ACCESS_DENIED) {
                SS_LOG_WARN(L"BatchSignatureBuilder",
                    L"AddSourceFiles: Access denied at index %zu", i);
            }
            else {
                SS_LOG_WARN(L"BatchSignatureBuilder",
                    L"AddSourceFiles: Cannot access file at index %zu (error: %lu)",
                    i, err);
            }
            continue;
        }

        // Must not be directory
        if (attribs & FILE_ATTRIBUTE_DIRECTORY) {
            SS_LOG_WARN(L"BatchSignatureBuilder",
                L"AddSourceFiles: Path is directory, not file at index %zu", i);
            continue;
        }

        // Skip system files (potential security risk)
        if (attribs & FILE_ATTRIBUTE_SYSTEM) {
            SS_LOG_WARN(L"BatchSignatureBuilder",
                L"AddSourceFiles: File is system file at index %zu - skipping", i);
            continue;
        }

        // Skip offline files (would cause delays)
        if (attribs & FILE_ATTRIBUTE_OFFLINE) {
            SS_LOG_WARN(L"BatchSignatureBuilder",
                L"AddSourceFiles: File is offline at index %zu - skipping", i);
            continue;
        }

        // ====================================================================
        // SYMLINK DETECTION (prevent infinite loops and security issues)
        // ====================================================================

        if (attribs & FILE_ATTRIBUTE_REPARSE_POINT) {
            SS_LOG_WARN(L"BatchSignatureBuilder",
                L"AddSourceFiles: File is symlink/reparse point at index %zu - skipping", i);
            continue;
        }

        // ====================================================================
        // DUPLICATE DETECTION (prevent processing same file twice)
        // ====================================================================

        auto [it, inserted] = seenPaths.insert(filePath);
        if (!inserted) {
            SS_LOG_DEBUG(L"BatchSignatureBuilder",
                L"AddSourceFiles: Duplicate file at index %zu - skipping", i);
            continue;
        }

        validatedPaths.push_back(filePath);
    }

    // ========================================================================
    // STEP 3: ADD VALIDATED PATHS TO BATCH
    // ========================================================================

    if (validatedPaths.empty()) {
        SS_LOG_ERROR(L"BatchSignatureBuilder",
            L"AddSourceFiles: No valid paths after validation (had %zu, validated 0)",
            filePaths.size());
        return StoreError{ SignatureStoreError::InvalidFormat, 0,
                          "No valid files to process" };
    }

    {
        std::lock_guard<std::mutex> lock(m_progressMutex);

        // Final overflow check before insertion
        if (WouldOverflow(m_sourceFiles.size(), validatedPaths.size())) {
            SS_LOG_ERROR(L"BatchSignatureBuilder",
                L"AddSourceFiles: Overflow would occur during insertion");
            return StoreError{ SignatureStoreError::TooLarge, 0,
                              "File count overflow" };
        }

        m_sourceFiles.insert(m_sourceFiles.end(),
            validatedPaths.begin(), validatedPaths.end());

        m_progress.totalFiles = m_sourceFiles.size();

        SS_LOG_INFO(L"BatchSignatureBuilder",
            L"AddSourceFiles: Added %zu valid files (total: %zu)",
            validatedPaths.size(), m_sourceFiles.size());
    }

    return StoreError{ SignatureStoreError::Success };
}

// ============================================================================
// DIRECTORY SCANNING
// ============================================================================

/**
 * @brief Add all signature files from a directory
 * @param directoryPath Path to the directory to scan
 * @param recursive Whether to scan subdirectories
 * @return StoreError indicating success or failure reason
 *
 * Scans directory for supported signature file types (.yar, .yara, .txt, .csv, .clamav, .sigs)
 * with comprehensive security validation.
 */
StoreError BatchSignatureBuilder::AddSourceDirectory(
    const std::wstring& directoryPath,
    bool recursive
) noexcept {
    // ========================================================================
    // STEP 1: DIRECTORY PATH VALIDATION
    // ========================================================================

    if (directoryPath.empty()) {
        SS_LOG_ERROR(L"BatchSignatureBuilder", L"AddSourceDirectory: Empty directory path");
        return StoreError{ SignatureStoreError::InvalidFormat, 0,
                          "Directory path cannot be empty" };
    }

    // Check path length (Windows extended path limit)
    if (directoryPath.length() > MAX_PATH_LENGTH) {
        SS_LOG_ERROR(L"BatchSignatureBuilder",
            L"AddSourceDirectory: Path too long (%zu > %zu)",
            directoryPath.length(), MAX_PATH_LENGTH);
        return StoreError{ SignatureStoreError::InvalidFormat, 0,
                          "Directory path too long" };
    }

    // Prevent directory traversal attacks
    if (directoryPath.find(L"..") != std::wstring::npos) {
        SS_LOG_ERROR(L"BatchSignatureBuilder",
            L"AddSourceDirectory: Path contains directory traversal");
        return StoreError{ SignatureStoreError::InvalidFormat, 0,
                          "Path contains directory traversal" };
    }

    // Reject null bytes in path
    if (directoryPath.find(L'\0') != std::wstring::npos) {
        SS_LOG_ERROR(L"BatchSignatureBuilder",
            L"AddSourceDirectory: Path contains null byte");
        return StoreError{ SignatureStoreError::InvalidFormat, 0,
                          "Path contains null byte" };
    }

    // ========================================================================
    // STEP 2: VERIFY DIRECTORY EXISTS
    // ========================================================================

    const DWORD attribs = GetFileAttributesW(directoryPath.c_str());

    if (attribs == INVALID_FILE_ATTRIBUTES) {
        const DWORD err = GetLastError();
        SS_LOG_ERROR(L"BatchSignatureBuilder",
            L"AddSourceDirectory: Directory not accessible (error: %lu)",
            err);
        return StoreError{ SignatureStoreError::FileNotFound, err,
                          "Directory not found or not accessible" };
    }

    if (!(attribs & FILE_ATTRIBUTE_DIRECTORY)) {
        SS_LOG_ERROR(L"BatchSignatureBuilder",
            L"AddSourceDirectory: Path is not a directory");
        return StoreError{ SignatureStoreError::InvalidFormat, 0,
                          "Path is not a directory" };
    }

    // Reject reparse points at root level (potential symlink attack)
    if (attribs & FILE_ATTRIBUTE_REPARSE_POINT) {
        SS_LOG_ERROR(L"BatchSignatureBuilder",
            L"AddSourceDirectory: Directory is a reparse point/symlink");
        return StoreError{ SignatureStoreError::InvalidFormat, 0,
                          "Directory is a symlink/junction" };
    }

    // ========================================================================
    // STEP 3: SCAN CONTEXT INITIALIZATION
    // ========================================================================

    struct ScanContext {
        std::vector<std::wstring> foundFiles;
        size_t maxFiles = MAX_BATCH_FILES;
        int maxDepth = MAX_RECURSION_DEPTH;
        int currentDepth = 0;
        LARGE_INTEGER startTime{};
        LARGE_INTEGER perfFreq{};
        uint64_t timeoutMs = DIRECTORY_SCAN_TIMEOUT_MS;
        std::unordered_set<std::wstring> processedDirs;  // Prevent loops
        std::atomic<bool> timedOut{ false };  // Timeout flag
        size_t filesExamined = 0;  // Statistics
        size_t dirsExamined = 0;
    };

    ScanContext context;
    context.foundFiles.reserve(10000);
    context.processedDirs.reserve(1000);

    if (!QueryPerformanceFrequency(&context.perfFreq) ||
        context.perfFreq.QuadPart == 0) {
        // Fallback: disable timeout if QPC not available
        context.timeoutMs = UINT64_MAX;
        SS_LOG_WARN(L"BatchSignatureBuilder",
            L"AddSourceDirectory: QueryPerformanceFrequency failed, timeout disabled");
    }
    QueryPerformanceCounter(&context.startTime);

            // Define supported file extensions
            auto isSupportedExtension = [](const std::wstring& filePath) -> bool {
                constexpr std::wstring_view extensions[] = {
                    L".yar", L".yara",   // YARA rules
                    L".txt",             // Text/list files
                    L".csv",             // CSV files
                    L".clamav",          // ClamAV signatures
                    L".sigs"             // Generic signatures
                };

                // Bounds check on find_last_of result
                const auto dotPos = filePath.find_last_of(L'.');
                if (dotPos == std::wstring::npos || dotPos >= filePath.length() - 1) {
                    return false;
                }

                // Extract extension safely
                std::wstring extStr = filePath.substr(dotPos);

                // Limit extension length (security: prevent DoS via very long "extension")
                if (extStr.length() > 10) {
                    return false;
                }

                // Case-insensitive comparison (safe towlower usage)
                std::transform(extStr.begin(), extStr.end(), extStr.begin(),
                    [](wchar_t c) -> wchar_t { 
                        return static_cast<wchar_t>(std::towlower(static_cast<wint_t>(c))); 
                    });

                for (const auto& validExt : extensions) {
                    if (extStr == validExt) return true;
                }

                return false;
            };

    // ========================================================================
    // STEP 4: RECURSIVE DIRECTORY SCANNER
    // ========================================================================

    std::function<void(const std::wstring&, ScanContext&)> scanDir =
        [&](const std::wstring& dirPath, ScanContext& ctx) -> void {

        // Early exit if already timed out
        if (ctx.timedOut.load(std::memory_order_relaxed)) {
            return;
        }

        // ====================================================================
        // DEPTH CHECK (prevent deep recursion DoS)
        // ====================================================================

        if (ctx.currentDepth >= ctx.maxDepth) {
            SS_LOG_WARN(L"BatchSignatureBuilder",
                L"AddSourceDirectory: Max recursion depth (%d) reached",
                ctx.maxDepth);
            return;
        }

        // ====================================================================
        // TIMEOUT CHECK (check periodically to minimize QPC overhead)
        // ====================================================================

        if ((ctx.dirsExamined % 100) == 0 && ctx.perfFreq.QuadPart > 0) {
            LARGE_INTEGER currentTime{};
            QueryPerformanceCounter(&currentTime);

            const uint64_t elapsedMs = 
                ((currentTime.QuadPart - ctx.startTime.QuadPart) * 1000ULL) /
                ctx.perfFreq.QuadPart;

            if (elapsedMs > ctx.timeoutMs) {
                ctx.timedOut.store(true, std::memory_order_relaxed);
                SS_LOG_WARN(L"BatchSignatureBuilder",
                    L"AddSourceDirectory: Scan timeout after %llu ms", elapsedMs);
                return;
            }
        }

        ctx.dirsExamined++;

        // ====================================================================
        // SYMLINK/LOOP DETECTION
        // ====================================================================

        // Canonicalize path to detect loops
        std::wstring canonPath = dirPath;

        // Remove trailing backslash for consistent comparison
        while (!canonPath.empty() && canonPath.back() == L'\\') {
            canonPath.pop_back();
        }

        // Check for empty path after normalization
        if (canonPath.empty()) {
            return;
        }

        // Check if we've already processed this directory (loop detection)
        auto [it, inserted] = ctx.processedDirs.insert(canonPath);
        if (!inserted) {
            SS_LOG_DEBUG(L"BatchSignatureBuilder",
                L"AddSourceDirectory: Directory already processed (loop detected)");
            return;
        }

        // ====================================================================
        // FILE ENUMERATION
        // ====================================================================

        WIN32_FIND_DATAW findData{};

        // Construct search path safely
        std::wstring searchPath = dirPath;
        if (searchPath.empty()) {
            return;  // Should never happen, but be safe
        }

        // Ensure trailing backslash
        if (searchPath.back() != L'\\') {
            searchPath += L'\\';
        }

        // Check for path length overflow before adding wildcard
        if (searchPath.length() >= MAX_PATH_LENGTH - 1) {
            SS_LOG_WARN(L"BatchSignatureBuilder",
                L"AddSourceDirectory: Path too long for search pattern");
            return;
        }

        searchPath += L'*';

        // RAII handle management - no leaks on any exit path
        FindHandleGuard hFindGuard(FindFirstFileW(searchPath.c_str(), &findData));

        if (!hFindGuard.IsValid()) {
            const DWORD err = GetLastError();

            // ERROR_NO_MORE_FILES means empty directory - not an error
            if (err == ERROR_NO_MORE_FILES) {
                return;
            }
            else if (err == ERROR_ACCESS_DENIED) {
                SS_LOG_WARN(L"BatchSignatureBuilder",
                    L"AddSourceDirectory: Access denied to directory");
            }
            else {
                SS_LOG_WARN(L"BatchSignatureBuilder",
                    L"AddSourceDirectory: Cannot enumerate directory (error: %lu)", err);
            }
            return;
        }

        // ====================================================================
        // PROCESS FOUND ENTRIES
        // ====================================================================

        do {
            // Early exit check for timeout
            if (ctx.timedOut.load(std::memory_order_relaxed)) {
                break;
            }

            // Skip . and ..
            if (wcscmp(findData.cFileName, L".") == 0 ||
                wcscmp(findData.cFileName, L"..") == 0) {
                continue;
            }

            // Validate filename is not empty (shouldn't happen, but be safe)
            if (findData.cFileName[0] == L'\0') {
                continue;
            }

            // Build full path safely
            std::wstring fullPath = dirPath;
            if (!fullPath.empty() && fullPath.back() != L'\\') {
                fullPath += L'\\';
            }

            // Check for path length overflow before appending filename
            const size_t filenameLen = wcsnlen(findData.cFileName, MAX_PATH);
            if (WouldOverflow(fullPath.length(), filenameLen) ||
                fullPath.length() + filenameLen > MAX_PATH_LENGTH) {
                SS_LOG_WARN(L"BatchSignatureBuilder",
                    L"AddSourceDirectory: Full path would be too long, skipping entry");
                continue;
            }

            fullPath += findData.cFileName;
            ctx.filesExamined++;

            // ============================================================
            // HANDLE DIRECTORY RECURSION
            // ============================================================

            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                // Skip reparse points (symlinks/junctions) to prevent loops
                if (findData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
                    SS_LOG_DEBUG(L"BatchSignatureBuilder",
                        L"AddSourceDirectory: Skipping reparse point directory");
                    continue;
                }

                // Recurse into subdirectory if enabled
                if (recursive) {
                    ctx.currentDepth++;
                    scanDir(fullPath, ctx);
                    ctx.currentDepth--;
                }
                continue;
            }

            // ============================================================
            // HANDLE FILES
            // ============================================================

            // Skip reparse points (symlinked files)
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
                continue;
            }

            // Check file size (skip very large files)
            ULARGE_INTEGER fileSize;
            fileSize.LowPart = findData.nFileSizeLow;
            fileSize.HighPart = findData.nFileSizeHigh;

            if (fileSize.QuadPart > MAX_SOURCE_FILE_SIZE) {
                SS_LOG_WARN(L"BatchSignatureBuilder",
                    L"AddSourceDirectory: File too large (%llu MB) - skipping",
                    fileSize.QuadPart / (1024ULL * 1024ULL));
                continue;
            }

            // Check extension (filters by supported types)
            if (!isSupportedExtension(fullPath)) {
                continue;
            }

            // ============================================================
            // ADD FILE IF NOT EXCEEDING LIMITS
            // ============================================================

            if (ctx.foundFiles.size() < ctx.maxFiles) {
                ctx.foundFiles.push_back(std::move(fullPath));
            }
            else {
                SS_LOG_WARN(L"BatchSignatureBuilder",
                    L"AddSourceDirectory: Max files reached (%zu)", ctx.maxFiles);
                break;
            }

        } while (FindNextFileW(hFindGuard.Get(), &findData));

        // FindClose is handled by RAII FindHandleGuard destructor
    };

    // ========================================================================
    // STEP 5: EXECUTE SCAN
    // ========================================================================

    SS_LOG_INFO(L"BatchSignatureBuilder",
        L"AddSourceDirectory: Starting scan (recursive: %s)",
        recursive ? L"yes" : L"no");

    try {
        scanDir(directoryPath, context);
    }
    catch (const std::exception& ex) {
        SS_LOG_ERROR(L"BatchSignatureBuilder",
            L"AddSourceDirectory: Exception during scan: %S", ex.what());
        return StoreError{ SignatureStoreError::Unknown, 0,
                          "Exception during directory scan" };
    }
    catch (...) {
        SS_LOG_ERROR(L"BatchSignatureBuilder",
            L"AddSourceDirectory: Unknown exception during scan");
        return StoreError{ SignatureStoreError::Unknown, 0,
                          "Unknown exception during directory scan" };
    }

    // Log scan statistics
    SS_LOG_DEBUG(L"BatchSignatureBuilder",
        L"AddSourceDirectory: Examined %zu files, %zu directories",
        context.filesExamined, context.dirsExamined);

    // ========================================================================
    // STEP 6: VALIDATE RESULTS
    // ========================================================================

    if (context.timedOut.load(std::memory_order_relaxed)) {
        SS_LOG_WARN(L"BatchSignatureBuilder",
            L"AddSourceDirectory: Scan timed out, results may be incomplete");
    }

    if (context.foundFiles.empty()) {
        SS_LOG_ERROR(L"BatchSignatureBuilder",
            L"AddSourceDirectory: No signature files found");
        return StoreError{ SignatureStoreError::FileNotFound, 0,
                          "No signature files found in directory" };
    }

    // ========================================================================
    // STEP 7: ADD DISCOVERED FILES
    // ========================================================================

    SS_LOG_INFO(L"BatchSignatureBuilder",
        L"AddSourceDirectory: Found %zu signature files", context.foundFiles.size());

    return AddSourceFiles(context.foundFiles);
}

// ============================================================================
// PARALLEL BUILD
// ============================================================================

/**
 * @brief Build signatures from all source files in parallel
 * @return StoreError indicating success or failure
 *
 * Processes all added source files using parallel execution. Progress is
 * tracked via atomic counters and errors are aggregated for reporting.
 */
StoreError BatchSignatureBuilder::BuildParallel() noexcept {
    // ========================================================================
    // STEP 1: VALIDATION & INITIALIZATION
    // ========================================================================

    size_t totalFiles = 0;

    {
        std::lock_guard<std::mutex> lock(m_progressMutex);

        if (m_sourceFiles.empty()) {
            SS_LOG_ERROR(L"BatchSignatureBuilder",
                L"BuildParallel: No source files configured");
            return StoreError{ SignatureStoreError::InvalidFormat, 0,
                              "No source files to process" };
        }

        totalFiles = m_sourceFiles.size();
        m_progress.totalFiles = totalFiles;
        m_progress.processedFiles = 0;
        m_progress.successfulFiles = 0;
        m_progress.failedFiles = 0;
        m_progress.errors.clear();

        SS_LOG_INFO(L"BatchSignatureBuilder",
            L"BuildParallel: Starting build with %zu files", totalFiles);
    }

    // ========================================================================
    // STEP 2: THREAD POOL CONFIGURATION
    // ========================================================================

    uint32_t threadCount = m_config.threadCount;

    if (threadCount == 0) {
        // Auto-detect based on CPU count
        threadCount = std::thread::hardware_concurrency();

        if (threadCount == 0) {
            threadCount = 4;  // Fallback if detection fails
        }
        else {
            // Use 75% of available cores (reserve 25% for OS/other tasks)
            threadCount = std::max(1u, threadCount * 3 / 4);
        }
    }

    // Clamp thread count (min 1, max 256)
    threadCount = std::clamp(threadCount, 1u, 256u);

    SS_LOG_INFO(L"BatchSignatureBuilder",
        L"BuildParallel: Using %u threads", threadCount);

    // ========================================================================
    // STEP 3: PERFORMANCE TIMING INITIALIZATION
    // ========================================================================

    LARGE_INTEGER buildStartTime{};
    LARGE_INTEGER perfFrequency{};

    if (!QueryPerformanceFrequency(&perfFrequency) || perfFrequency.QuadPart == 0) {
        // Fallback: use a reasonable default
        perfFrequency.QuadPart = 10'000'000;  // 10 MHz as fallback
        SS_LOG_WARN(L"BatchSignatureBuilder",
            L"BuildParallel: QueryPerformanceFrequency failed, using fallback");
    }

    QueryPerformanceCounter(&buildStartTime);

    // ========================================================================
    // STEP 4: ATOMIC PROGRESS COUNTERS (lock-free for hot path)
    // ========================================================================

    std::atomic<size_t> processedCount{ 0 };
    std::atomic<size_t> successCount{ 0 };
    std::atomic<size_t> failedCount{ 0 };
    std::atomic<bool> timeoutReached{ false };

    // Mutex only for error collection (cold path)
    std::mutex errorMutex;
    std::vector<BatchError> collectedErrors;
    collectedErrors.reserve(std::min(size_t(1000), totalFiles / 10 + 1));

    // ========================================================================
    // STEP 5: BUILDER MUTEX (SignatureBuilder is NOT thread-safe)
    // ========================================================================
    // CRITICAL: m_builder.Import* methods modify internal state
    // They MUST be serialized to prevent data corruption
    std::mutex builderMutex;

    // Capture perfFrequency by value for lambda
    const int64_t perfFreq = perfFrequency.QuadPart;
    const int64_t startTime = buildStartTime.QuadPart;

    auto processFile = [this, startTime, perfFreq, &processedCount, &successCount,
        &failedCount, &timeoutReached, &errorMutex, &collectedErrors,
        &builderMutex, totalFiles](const std::wstring& filePath) -> void {

        // Early exit if timeout already reached
        if (timeoutReached.load(std::memory_order_relaxed)) {
            return;
        }

        // Check timeout periodically (QPC is fast ~20ns)
        LARGE_INTEGER currentTime{};
        QueryPerformanceCounter(&currentTime);

        const uint64_t elapsedMs = (perfFreq > 0) ?
            ((currentTime.QuadPart - startTime) * 1000ULL) / perfFreq : 0;

        if (elapsedMs > BUILD_TIMEOUT_MS) {
            if (!timeoutReached.exchange(true, std::memory_order_acq_rel)) {
                SS_LOG_ERROR(L"BatchSignatureBuilder",
                    L"BuildParallel: Build timeout (%llu ms)", elapsedMs);
            }
            return;
        }

        // Validate file path
        if (filePath.empty()) {
            failedCount.fetch_add(1, std::memory_order_relaxed);
            processedCount.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        // Get file extension with bounds check
        const auto extPos = filePath.find_last_of(L'.');
        if (extPos == std::wstring::npos || extPos >= filePath.length() - 1) {
            SS_LOG_WARN(L"BatchSignatureBuilder",
                L"BuildParallel: No valid extension for file");
            failedCount.fetch_add(1, std::memory_order_relaxed);
            processedCount.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        std::wstring ext = filePath.substr(extPos);

        // Limit extension length (security)
        if (ext.length() > 10) {
            failedCount.fetch_add(1, std::memory_order_relaxed);
            processedCount.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        // Convert to lowercase for comparison (safe towlower)
        for (auto& c : ext) {
            c = static_cast<wchar_t>(std::towlower(static_cast<wint_t>(c)));
        }

        // Import file with builder mutex protection
        StoreError err{};
        {
            std::lock_guard<std::mutex> builderLock(builderMutex);

            try {
                if (ext == L".yar" || ext == L".yara") {
                    err = m_builder.ImportYaraRulesFromFile(filePath);
                }
                else if (ext == L".csv") {
                    err = m_builder.ImportHashesFromCsv(filePath);
                }
                else if (ext == L".txt") {
                    // Auto-detect: try hash file first, then patterns
                    err = m_builder.ImportHashesFromFile(filePath);
                    if (!err.IsSuccess()) {
                        err = m_builder.ImportPatternsFromFile(filePath);
                    }
                }
                else if (ext == L".clamav" || ext == L".sigs") {
                    err = m_builder.ImportPatternsFromFile(filePath);
                }
                else {
                    SS_LOG_WARN(L"BatchSignatureBuilder",
                        L"BuildParallel: Unsupported extension");
                    failedCount.fetch_add(1, std::memory_order_relaxed);
                    processedCount.fetch_add(1, std::memory_order_relaxed);
                    return;
                }
            }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(L"BatchSignatureBuilder",
                    L"BuildParallel: Exception importing file: %S", ex.what());
                err = StoreError{ SignatureStoreError::Unknown, 0, ex.what() };
            }
            catch (...) {
                SS_LOG_ERROR(L"BatchSignatureBuilder",
                    L"BuildParallel: Unknown exception importing file");
                err = StoreError{ SignatureStoreError::Unknown, 0, "Unknown exception" };
            }
        }

        if (!err.IsSuccess()) {
            // Collect error (cold path - mutex is fine)
            {
                std::lock_guard<std::mutex> errLock(errorMutex);
                // Limit error collection to prevent memory bloat
                if (collectedErrors.size() < MAX_COLLECTED_ERRORS) {
                    collectedErrors.push_back({ filePath, err.message });
                }
            }

            failedCount.fetch_add(1, std::memory_order_relaxed);
        }
        else {
            successCount.fetch_add(1, std::memory_order_relaxed);
        }

        // Update processed count and report progress
        const size_t processed = processedCount.fetch_add(1, std::memory_order_relaxed) + 1;

        // Report progress periodically (every PROGRESS_REPORT_INTERVAL files)
        if (processed % PROGRESS_REPORT_INTERVAL == 0) {
            SS_LOG_DEBUG(L"BatchSignatureBuilder",
                L"BuildParallel: Progress %zu/%zu",
                processed, totalFiles);

            // Call progress callback if configured (outside any lock)
            if (m_config.progressCallback) {
                try {
                    m_config.progressCallback("Processing batch files",
                        processed, totalFiles);
                }
                catch (...) {
                    // Don't let callback exceptions break the build
                }
            }
        }
    };

    // ========================================================================
    // STEP 6: PARALLEL EXECUTION
    // ========================================================================

    try {
        // Create copy of file paths for parallel iteration
        std::vector<std::wstring> filesToProcess;
        {
            std::lock_guard<std::mutex> lock(m_progressMutex);
            filesToProcess = m_sourceFiles;
        }

        // Validate we have files to process
        if (filesToProcess.empty()) {
            SS_LOG_ERROR(L"BatchSignatureBuilder",
                L"BuildParallel: File list became empty");
            return StoreError{ SignatureStoreError::InvalidFormat, 0,
                              "No files to process" };
        }

        // Use standard execution policy for maximum performance
        std::for_each(std::execution::par,
            filesToProcess.begin(),
            filesToProcess.end(),
            [&processFile](const std::wstring& filePath) {
                processFile(filePath);
            });
    }
    catch (const std::exception& ex) {
        SS_LOG_ERROR(L"BatchSignatureBuilder",
            L"BuildParallel: Exception during parallel processing: %S", ex.what());
        return StoreError{ SignatureStoreError::Unknown, 0,
                          "Exception during parallel processing" };
    }
    catch (...) {
        SS_LOG_ERROR(L"BatchSignatureBuilder",
            L"BuildParallel: Unknown exception during parallel processing");
        return StoreError{ SignatureStoreError::Unknown, 0,
                          "Unknown exception during parallel processing" };
    }

    // ========================================================================
    // STEP 7: FINALIZE PROGRESS (copy atomic results to m_progress)
    // ========================================================================

    {
        std::lock_guard<std::mutex> lock(m_progressMutex);
        m_progress.processedFiles = processedCount.load(std::memory_order_acquire);
        m_progress.successfulFiles = successCount.load(std::memory_order_acquire);
        m_progress.failedFiles = failedCount.load(std::memory_order_acquire);

        // Move collected errors efficiently
        {
            std::lock_guard<std::mutex> errLock(errorMutex);
            m_progress.errors = std::move(collectedErrors);
        }
    }

    // ========================================================================
    // STEP 8: PERFORMANCE METRICS
    // ========================================================================

    LARGE_INTEGER buildEndTime{};
    QueryPerformanceCounter(&buildEndTime);

    const uint64_t totalTimeMs = (perfFreq > 0) ?
        ((buildEndTime.QuadPart - startTime) * 1000ULL) / perfFreq : 0;

    // Use atomic values directly for final metrics
    const size_t finalProcessed = processedCount.load(std::memory_order_acquire);
    const size_t finalSuccess = successCount.load(std::memory_order_acquire);
    const size_t finalFailed = failedCount.load(std::memory_order_acquire);

    const double filesPerSecond = (totalTimeMs > 0) ?
        (static_cast<double>(finalProcessed) * 1000.0 / static_cast<double>(totalTimeMs)) : 0.0;

    // ========================================================================
    // STEP 9: FINAL LOGGING & STATISTICS
    // ========================================================================

    {
        std::lock_guard<std::mutex> lock(m_progressMutex);

        SS_LOG_INFO(L"BatchSignatureBuilder", L"BuildParallel: COMPLETE");
        SS_LOG_INFO(L"BatchSignatureBuilder",
            L"  Files processed: %zu/%zu", finalProcessed, m_progress.totalFiles);
        SS_LOG_INFO(L"BatchSignatureBuilder",
            L"  Successful: %zu", finalSuccess);
        SS_LOG_INFO(L"BatchSignatureBuilder",
            L"  Failed: %zu", finalFailed);
        SS_LOG_INFO(L"BatchSignatureBuilder",
            L"  Time: %llu ms (%.2f files/sec)", totalTimeMs, filesPerSecond);

        // Log sample of errors (limit to first 10)
        if (!m_progress.errors.empty()) {
            const size_t errorsToLog = std::min(m_progress.errors.size(), size_t(10));
            SS_LOG_WARN(L"BatchSignatureBuilder",
                L"  Errors (%zu total, showing %zu):",
                m_progress.errors.size(), errorsToLog);

            for (size_t i = 0; i < errorsToLog; ++i) {
                SS_LOG_ERROR(L"BatchSignatureBuilder",
                    L"    [%zu] Error: %S",
                    i + 1,
                    m_progress.errors[i].errorMessage.c_str());
            }

            if (m_progress.errors.size() > 10) {
                SS_LOG_WARN(L"BatchSignatureBuilder",
                    L"    ... and %zu more errors",
                    m_progress.errors.size() - 10);
            }
        }
    }

    // ========================================================================
    // STEP 10: DETERMINE OVERALL SUCCESS
    // ========================================================================

    if (timeoutReached.load(std::memory_order_relaxed)) {
        SS_LOG_WARN(L"BatchSignatureBuilder",
            L"BuildParallel: Build timed out, results may be incomplete");
    }

    if (finalSuccess == 0) {
        SS_LOG_ERROR(L"BatchSignatureBuilder",
            L"BuildParallel: No files processed successfully");
        return StoreError{ SignatureStoreError::InvalidFormat, 0,
                          "No files processed successfully" };
    }

    if (finalFailed > 0) {
        SS_LOG_WARN(L"BatchSignatureBuilder",
            L"BuildParallel: Partial success (%zu/%zu files)",
            finalSuccess, totalFiles);
        // Continue to build even with some failures - partial success is acceptable
    }

    // ========================================================================
    // STEP 11: BUILD OUTPUT DATABASE
    // ========================================================================

    SS_LOG_INFO(L"BatchSignatureBuilder",
        L"BuildParallel: All files processed - building output database");

    try {
        return m_builder.Build();
    }
    catch (const std::exception& ex) {
        SS_LOG_ERROR(L"BatchSignatureBuilder",
            L"BuildParallel: Exception during final build: %S", ex.what());
        return StoreError{ SignatureStoreError::Unknown, 0,
                          "Exception during final build" };
    }
    catch (...) {
        SS_LOG_ERROR(L"BatchSignatureBuilder",
            L"BuildParallel: Unknown exception during final build");
        return StoreError{ SignatureStoreError::Unknown, 0,
                          "Unknown exception during final build" };
    }
}

// ============================================================================
// PROGRESS REPORTING
// ============================================================================

/**
 * @brief Get current build progress
 * @return Copy of current progress state (thread-safe)
 */
BatchSignatureBuilder::BatchProgress BatchSignatureBuilder::GetProgress() const noexcept {
    std::lock_guard<std::mutex> lock(m_progressMutex);
    return m_progress;
}

} // namespace SignatureStore
} // namespace ShadowStrike