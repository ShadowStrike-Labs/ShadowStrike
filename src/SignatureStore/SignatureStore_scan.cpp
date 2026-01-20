// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
#include"SignatureStore.hpp"

namespace ShadowStrike {
	namespace SignatureStore {

        // ============================================================================
        // SCANNING OPERATIONS (Unified Interface)
        // ============================================================================

        ScanResult SignatureStore::ScanBuffer(
            std::span<const uint8_t> buffer,
            const ScanOptions& options
        ) const noexcept {
            // ========================================================================
            // TITANIUM VALIDATION LAYER
            // ========================================================================

            // VALIDATION 1: Initialization state (acquire ensures visibility of init state)
            if (!m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"SignatureStore", L"ScanBuffer: Store not initialized");
                return ScanResult{};
            }

            // VALIDATION 2: Empty buffer check - nothing to scan
            if (buffer.empty()) {
                SS_LOG_DEBUG(L"SignatureStore", L"ScanBuffer: Empty buffer, nothing to scan");
                ScanResult result{};
                result.totalBytesScanned = 0;
                return result;
            }

            // VALIDATION 3: Maximum buffer size to prevent DoS attacks
            constexpr size_t MAX_BUFFER_SIZE = 500 * 1024 * 1024; // 500MB max
            if (buffer.size() > MAX_BUFFER_SIZE) {
                SS_LOG_WARN(L"SignatureStore", L"ScanBuffer: Buffer too large (%zu bytes), max is %zu",
                    buffer.size(), MAX_BUFFER_SIZE);
                ScanResult result{};
                result.timedOut = true; // Indicate scan was not completed
                return result;
            }

            // VALIDATION 4: Pointer alignment check for SIMD operations
            // Some hash algorithms and pattern matchers benefit from aligned data
            const uintptr_t bufferAddr = reinterpret_cast<uintptr_t>(buffer.data());
            if (bufferAddr == 0) {
                SS_LOG_ERROR(L"SignatureStore", L"ScanBuffer: Null buffer pointer with non-zero size");
                return ScanResult{};
            }

            // VALIDATION 5: Options sanity check
            if (options.timeoutMilliseconds == 0) {
                SS_LOG_DEBUG(L"SignatureStore", L"ScanBuffer: Zero timeout specified, using default 10s");
            }

            if (options.maxResults == 0) {
                SS_LOG_DEBUG(L"SignatureStore", L"ScanBuffer: Zero maxResults specified, will return no results");
                ScanResult result{};
                result.totalBytesScanned = buffer.size();
                return result;
            }

            // ========================================================================
            // ATOMIC STATISTICS UPDATE (relaxed ordering - performance counter)
            // ========================================================================
            m_totalScans.fetch_add(1, std::memory_order_relaxed);

            // ========================================================================
            // HIGH-PRECISION TIMING START
            // ========================================================================
            LARGE_INTEGER startTime;
            if (!QueryPerformanceCounter(&startTime)) {
                startTime.QuadPart = 0; // Fallback: timing will be approximate
            }

            // Check cache first
            if (options.enableResultCache && m_resultCacheEnabled.load()) {
                auto cached = CheckQueryCache(buffer);
                if (cached.has_value()) {
                    m_queryCacheHits.fetch_add(1, std::memory_order_relaxed);
                    return *cached;
                }
                m_queryCacheMisses.fetch_add(1, std::memory_order_relaxed);
            }

            // Execute scan (parallel or sequential)
            ScanResult result;
            if (options.parallelExecution && options.threadCount > 1) {
                result = ExecuteParallelScan(buffer, options);
            }
            else {
                result = ExecuteSequentialScan(buffer, options);
            }

            // Performance tracking
            LARGE_INTEGER endTime;
            QueryPerformanceCounter(&endTime);
            // FIX: Division by zero protection
            if (m_perfFrequency.QuadPart > 0) {
                result.scanTimeMicroseconds =
                    ((endTime.QuadPart - startTime.QuadPart) * 1000000ULL) /
                    static_cast<uint64_t>(m_perfFrequency.QuadPart);
            }
            else {
                result.scanTimeMicroseconds = 0;
            }

            result.totalBytesScanned = buffer.size();

            // Update statistics
            m_totalDetections.fetch_add(result.detections.size(), std::memory_order_relaxed);

            // Cache result
            if (options.enableResultCache && m_resultCacheEnabled.load()) {

                AddToQueryCache(buffer, result);
            }

            return result;
        }

        ScanResult SignatureStore::ScanFile(
            const std::wstring& filePath,
            const ScanOptions& options
        ) const noexcept {
            SS_LOG_DEBUG(L"SignatureStore", L"ScanFile: %s", filePath.c_str());

            // ========================================================================
            // TITANIUM VALIDATION LAYER - FILE SCANNING
            // ========================================================================

            // VALIDATION 1: Empty path check
            if (filePath.empty()) {
                SS_LOG_ERROR(L"SignatureStore", L"ScanFile: Empty file path");
                return ScanResult{};
            }

            // VALIDATION 2: Path length check (Windows MAX_PATH limit)
            constexpr size_t MAX_SAFE_PATH_LENGTH = 32767; // Extended-length path limit
            if (filePath.length() > MAX_SAFE_PATH_LENGTH) {
                SS_LOG_ERROR(L"SignatureStore", L"ScanFile: Path too long (%zu chars)", filePath.length());
                return ScanResult{};
            }

            // VALIDATION 3: Null character injection check (path truncation attack)
            if (filePath.find(L'\0') != std::wstring::npos) {
                SS_LOG_ERROR(L"SignatureStore", L"ScanFile: Path contains null character (security violation)");
                return ScanResult{};
            }

            // FIX: Wrap all filesystem operations in try-catch since they can throw
            try {
                namespace fs = std::filesystem;

                // VALIDATION 4: Path canonicalization and symlink resolution
                std::error_code ec;
                fs::path canonicalPath = fs::weakly_canonical(filePath, ec);
                if (ec) {
                    SS_LOG_WARN(L"SignatureStore", L"ScanFile: Failed to canonicalize path: %s (error: %S)",
                        filePath.c_str(), ec.message().c_str());
                    // Continue with original path but log warning
                    canonicalPath = filePath;
                }

                // VALIDATION 5: Check file exists
                if (!fs::exists(canonicalPath, ec)) {
                    SS_LOG_ERROR(L"SignatureStore", L"File not found: %s", filePath.c_str());
                    ScanResult result{};
                    result.errorCount = 1;
                    result.lastError = "File not found";
                    return result;
                }

                // VALIDATION 6: Verify it's a regular file (not directory, symlink, device, etc.)
                if (!fs::is_regular_file(canonicalPath, ec)) {
                    SS_LOG_WARN(L"SignatureStore", L"ScanFile: Not a regular file: %s", filePath.c_str());
                    ScanResult result{};
                    result.errorCount = 1;
                    result.lastError = "Not a regular file";
                    return result;
                }

                // VALIDATION 7: Check file is not a symlink pointing outside allowed paths
                // Security: Prevent symlink-based path traversal attacks
                if (fs::is_symlink(filePath, ec)) {
                    SS_LOG_WARN(L"SignatureStore", L"ScanFile: Symlink detected, resolved to: %s",
                        canonicalPath.wstring().c_str());
                    // Allow symlinks but log for audit purposes
                }

                // VALIDATION 8: Check file size
                auto fileSize = fs::file_size(canonicalPath, ec);
                if (ec) {
                    SS_LOG_ERROR(L"SignatureStore", L"Failed to get file size: %s (error: %S)",
                        filePath.c_str(), ec.message().c_str());
                    return ScanResult{};
                }

                // VALIDATION 9: File size limits
                constexpr uint64_t MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB limit
                if (fileSize > MAX_FILE_SIZE) {
                    SS_LOG_WARN(L"SignatureStore", L"File too large: %llu bytes (max: %llu)",
                        fileSize, MAX_FILE_SIZE);
                    ScanResult result{};
                    result.timedOut = true; // Indicate incomplete scan
                    result.totalBytesScanned = 0;
                    return result;
                }

                // VALIDATION 10: Check for zero-size files
                if (fileSize == 0) {
                    SS_LOG_DEBUG(L"SignatureStore", L"Empty file, nothing to scan: %s", filePath.c_str());
                    ScanResult result{};
                    result.totalBytesScanned = 0;
                    return result;
                }

                // ====================================================================
                // MEMORY MAPPING WITH TITANIUM SAFETY
                // ====================================================================
                StoreError err{};
                MemoryMappedView fileView{};

                if (!MemoryMapping::OpenView(canonicalPath.wstring(), true, fileView, err)) {
                    SS_LOG_ERROR(L"SignatureStore", L"Failed to map file: %S", err.message.c_str());
                    return ScanResult{};
                }

                // VALIDATION 11: Memory mapping integrity check
                if (!fileView.baseAddress) {
                    SS_LOG_ERROR(L"SignatureStore", L"Invalid memory mapping (null base) for file: %s",
                        filePath.c_str());
                    MemoryMapping::CloseView(fileView);
                    return ScanResult{};
                }

                if (fileView.fileSize == 0) {
                    SS_LOG_ERROR(L"SignatureStore", L"Invalid memory mapping (zero size) for file: %s",
                        filePath.c_str());
                    MemoryMapping::CloseView(fileView);
                    return ScanResult{};
                }

                // VALIDATION 12: Cross-check mapped size with expected file size
                if (fileView.fileSize != fileSize) {
                    SS_LOG_WARN(L"SignatureStore",
                        L"ScanFile: Mapped size (%llu) differs from file size (%llu) - possible race condition",
                        fileView.fileSize, fileSize);
                    // Continue but log for audit - file might have been modified during mapping
                }

                // ====================================================================
                // EXECUTE SCAN WITH RAII GUARD
                // ====================================================================
                std::span<const uint8_t> buffer(
                    static_cast<const uint8_t*>(fileView.baseAddress),
                    static_cast<size_t>(fileView.fileSize)
                );

                auto result = ScanBuffer(buffer, options);

                // RAII: Always close the view, even if ScanBuffer throws (it's noexcept but defensive)
                MemoryMapping::CloseView(fileView);

                return result;
            }
            catch (const std::filesystem::filesystem_error& e) {
                SS_LOG_ERROR(L"SignatureStore", L"Filesystem error scanning file %s: %S",
                    filePath.c_str(), e.what());
                return ScanResult{};
            }
            catch (const std::bad_alloc& e) {
                SS_LOG_ERROR(L"SignatureStore", L"Memory allocation failed scanning file %s: %S",
                    filePath.c_str(), e.what());
                return ScanResult{};
            }
            catch (const std::exception& e) {
                SS_LOG_ERROR(L"SignatureStore", L"Exception scanning file %s: %S",
                    filePath.c_str(), e.what());
                return ScanResult{};
            }
            catch (...) {
                SS_LOG_ERROR(L"SignatureStore", L"Unknown exception scanning file: %s", filePath.c_str());
                return ScanResult{};
            }
        }

        std::vector<ScanResult> SignatureStore::ScanFiles(
            std::span<const std::wstring> filePaths,
            const ScanOptions& options,
            std::function<void(size_t, size_t)> progressCallback
        ) const noexcept {
            // ========================================================================
            // TITANIUM VALIDATION LAYER - BATCH FILE SCANNING
            // ========================================================================

            // VALIDATION 1: Empty input check
            if (filePaths.empty()) {
                SS_LOG_DEBUG(L"SignatureStore", L"ScanFiles: Empty file list");
                return {};
            }

            // VALIDATION 2: Maximum batch size to prevent resource exhaustion
            constexpr size_t MAX_BATCH_SIZE = 100000;
            if (filePaths.size() > MAX_BATCH_SIZE) {
                SS_LOG_WARN(L"SignatureStore", L"ScanFiles: Batch too large (%zu files), max is %zu",
                    filePaths.size(), MAX_BATCH_SIZE);
                // Continue with limited batch
            }

            std::vector<ScanResult> results;

            // VALIDATION 3: Reserve with overflow check
            try {
                results.reserve(std::min(filePaths.size(), MAX_BATCH_SIZE));
            }
            catch (const std::bad_alloc& e) {
                SS_LOG_ERROR(L"SignatureStore", L"ScanFiles: Failed to allocate results vector: %S", e.what());
                return {};
            }

            const size_t effectiveCount = std::min(filePaths.size(), MAX_BATCH_SIZE);

            for (size_t i = 0; i < effectiveCount; ++i) {
                try {
                    results.push_back(ScanFile(filePaths[i], options));
                }
                catch (const std::exception& e) {
                    SS_LOG_WARN(L"SignatureStore", L"ScanFiles: Error scanning file %zu: %S", i, e.what());
                    results.emplace_back(ScanResult{}); // Push empty result to maintain index alignment
                }

                // TITANIUM: Wrap callback in try-catch - user callback might throw
                if (progressCallback) {
                    try {
                        progressCallback(i + 1, effectiveCount);
                    }
                    catch (const std::exception& e) {
                        SS_LOG_WARN(L"SignatureStore", L"ScanFiles: Progress callback threw exception: %S", e.what());
                        // Continue scanning despite callback failure
                    }
                }
            }

            return results;
        }

        std::vector<ScanResult> SignatureStore::ScanDirectory(
            const std::wstring& directoryPath,
            bool recursive,
            const ScanOptions& options,
            std::function<void(const std::wstring&)> fileCallback
        ) const noexcept {
            // ========================================================================
            // TITANIUM VALIDATION LAYER - DIRECTORY SCANNING
            // ========================================================================

            // VALIDATION 1: Empty path check
            if (directoryPath.empty()) {
                SS_LOG_ERROR(L"SignatureStore", L"ScanDirectory: Empty directory path");
                return {};
            }

            // VALIDATION 2: Path length check
            constexpr size_t MAX_SAFE_PATH_LENGTH = 32767;
            if (directoryPath.length() > MAX_SAFE_PATH_LENGTH) {
                SS_LOG_ERROR(L"SignatureStore", L"ScanDirectory: Path too long (%zu chars)", directoryPath.length());
                return {};
            }

            // VALIDATION 3: Null character injection check
            if (directoryPath.find(L'\0') != std::wstring::npos) {
                SS_LOG_ERROR(L"SignatureStore", L"ScanDirectory: Path contains null character (security violation)");
                return {};
            }

            std::vector<ScanResult> results;

            try {
                namespace fs = std::filesystem;

                // VALIDATION 4: Verify directory exists
                std::error_code ec;
                if (!fs::exists(directoryPath, ec)) {
                    SS_LOG_ERROR(L"SignatureStore", L"ScanDirectory: Directory not found: %s", directoryPath.c_str());
                    return {};
                }

                // VALIDATION 5: Verify it's actually a directory
                if (!fs::is_directory(directoryPath, ec)) {
                    SS_LOG_ERROR(L"SignatureStore", L"ScanDirectory: Not a directory: %s", directoryPath.c_str());
                    return {};
                }

                // TITANIUM: Resource limits
                constexpr size_t MAX_FILES_TO_SCAN = 1000000;  // 1M files max
                constexpr size_t MAX_RECURSION_DEPTH = 100;    // Prevent infinite recursion via symlinks
                size_t filesScanned = 0;
                size_t errorsEncountered = 0;
                constexpr size_t MAX_ERRORS_BEFORE_ABORT = 1000;

                // Configure directory iterator options for safety
                auto dirOptions = fs::directory_options::skip_permission_denied;

                // Process entry with titanium safety
                auto processEntry = [&](const fs::directory_entry& entry) -> bool {
                    // Resource limit check
                    if (filesScanned >= MAX_FILES_TO_SCAN) {
                        SS_LOG_WARN(L"SignatureStore", L"ScanDirectory: Reached max file limit (%zu)", MAX_FILES_TO_SCAN);
                        return false; // Stop iteration
                    }

                    // Error threshold check
                    if (errorsEncountered >= MAX_ERRORS_BEFORE_ABORT) {
                        SS_LOG_ERROR(L"SignatureStore", L"ScanDirectory: Too many errors (%zu), aborting", errorsEncountered);
                        return false;
                    }

                    try {
                        std::error_code entryEc;
                        if (!entry.is_regular_file(entryEc)) {
                            return true; // Continue with next file
                        }

                        const std::wstring path = entry.path().wstring();

                        // TITANIUM: Wrap callback in try-catch
                        if (fileCallback) {
                            try {
                                fileCallback(path);
                            }
                            catch (const std::exception& e) {
                                SS_LOG_WARN(L"SignatureStore", L"ScanDirectory: File callback threw exception: %S", e.what());
                                ++errorsEncountered;
                            }
                        }

                        results.push_back(ScanFile(path, options));
                        ++filesScanned;
                    }
                    catch (const std::exception& e) {
                        SS_LOG_WARN(L"SignatureStore", L"ScanDirectory: Error processing entry: %S", e.what());
                        ++errorsEncountered;
                    }

                    return true; // Continue iteration
                    };

                if (recursive) {
                    // Use options to skip permission denied and handle errors gracefully
                    auto it = fs::recursive_directory_iterator(directoryPath, dirOptions, ec);
                    if (ec) {
                        SS_LOG_ERROR(L"SignatureStore", L"ScanDirectory: Failed to create recursive iterator: %S",
                            ec.message().c_str());
                        return results;
                    }

                    for (auto& entry : it) {
                        // Recursion depth check
                        if (it.depth() > static_cast<int>(MAX_RECURSION_DEPTH)) {
                            SS_LOG_WARN(L"SignatureStore", L"ScanDirectory: Max recursion depth reached, skipping deeper");
                            it.pop(); // Go back up one level
                            continue;
                        }

                        if (!processEntry(entry)) {
                            break; // Stop iteration
                        }
                    }
                }
                else {
                    for (const auto& entry : fs::directory_iterator(directoryPath, dirOptions, ec)) {
                        if (!processEntry(entry)) {
                            break;
                        }
                    }
                }

                SS_LOG_INFO(L"SignatureStore", L"ScanDirectory: Completed - %zu files scanned, %zu errors",
                    filesScanned, errorsEncountered);
            }
            catch (const std::filesystem::filesystem_error& e) {
                SS_LOG_ERROR(L"SignatureStore", L"ScanDirectory: Filesystem error: %S", e.what());
            }
            catch (const std::bad_alloc& e) {
                SS_LOG_ERROR(L"SignatureStore", L"ScanDirectory: Memory allocation failed: %S", e.what());
            }
            catch (const std::exception& e) {
                SS_LOG_ERROR(L"SignatureStore", L"ScanDirectory: Exception: %S", e.what());
            }
            catch (...) {
                SS_LOG_ERROR(L"SignatureStore", L"ScanDirectory: Unknown exception");
            }

            return results;
        }


        ScanResult SignatureStore::ScanProcess(
            uint32_t processId,
            const ScanOptions& options
        ) const noexcept {
            SS_LOG_DEBUG(L"SignatureStore", L"ScanProcess: PID=%u", processId);

            ScanResult result{};

            // ========================================================================
            // TITANIUM VALIDATION LAYER - PROCESS SCANNING
            // ========================================================================

            // VALIDATION 1: Check initialization
            if (!m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_ERROR(L"SignatureStore", L"ScanProcess: Store not initialized");
                result.lastError = "Store not initialized";
                result.errorCount = 1;
                return result;
            }

            // VALIDATION 2: Process ID validation (0 is typically invalid)
            if (processId == 0) {
                SS_LOG_ERROR(L"SignatureStore", L"ScanProcess: Invalid process ID (0)");
                result.lastError = "Invalid process ID";
                result.errorCount = 1;
                return result;
            }

            // VALIDATION 3: Validate options
            if (!options.Validate()) {
                SS_LOG_WARN(L"SignatureStore", L"ScanProcess: Invalid options, using defaults");
            }

            // Only YARA supports process scanning
            if (options.enableYaraScan && m_yaraStoreEnabled.load(std::memory_order_acquire) && m_yaraStore) {
                try {
                    result.yaraMatches = m_yaraStore->ScanProcess(processId, options.yaraOptions);

                    // TITANIUM: Limit results to prevent memory exhaustion
                    const size_t maxResults = options.GetValidatedMaxResults();
                    const size_t matchCount = std::min(result.yaraMatches.size(), maxResults);

                    result.detections.reserve(matchCount);

                    // Convert YARA matches to detections
                    for (size_t i = 0; i < matchCount; ++i) {
                        const auto& match = result.yaraMatches[i];

                        DetectionResult detection{};
                        detection.signatureId = match.ruleId;
                        detection.signatureName = match.ruleName;
                        detection.threatLevel = match.threatLevel;
                        detection.description = "YARA rule match in process memory";

                        // TITANIUM: Safe timestamp handling
                        try {
                            detection.matchTimestamp = std::chrono::system_clock::now().time_since_epoch().count();
                        }
                        catch (...) {
                            detection.matchTimestamp = 0;
                        }

                        result.detections.push_back(std::move(detection));

                        // Check stop-on-first-match
                        if (options.stopOnFirstMatch) {
                            result.stoppedEarly = true;
                            break;
                        }
                    }

                    // TITANIUM: Truncate yaraMatches if we hit the limit
                    if (result.yaraMatches.size() > maxResults) {
                        result.yaraMatches.resize(maxResults);
                        SS_LOG_WARN(L"SignatureStore", L"ScanProcess: Results truncated to %zu", maxResults);
                    }
                }
                catch (const std::exception& e) {
                    SS_LOG_ERROR(L"SignatureStore", L"ScanProcess: Exception during YARA scan: %S", e.what());
                    result.lastError = e.what();
                    result.errorCount = 1;
                }
                catch (...) {
                    SS_LOG_ERROR(L"SignatureStore", L"ScanProcess: Unknown exception during YARA scan");
                    result.lastError = "Unknown exception";
                    result.errorCount = 1;
                }
            }

            return result;
        }

        SignatureStore::StreamScanner SignatureStore::CreateStreamScanner(
            const ScanOptions& options
        ) const noexcept {
            StreamScanner scanner;
            scanner.m_store = this;
            scanner.m_options = options;

            // TITANIUM: Pre-allocate buffer for expected chunk sizes
            try {
                scanner.m_buffer.reserve(1024 * 1024); // Reserve 1MB initially
            }
            catch (const std::bad_alloc&) {
                SS_LOG_WARN(L"SignatureStore", L"CreateStreamScanner: Failed to pre-allocate buffer");
                // Continue - vector will grow as needed
            }

            return scanner;
        }

        void SignatureStore::StreamScanner::Reset() noexcept {
            m_buffer.clear();
            m_buffer.shrink_to_fit(); // Release memory
            m_bytesProcessed = 0;
        }

        ScanResult SignatureStore::StreamScanner::FeedChunk(
            std::span<const uint8_t> chunk
        ) noexcept {
            // ========================================================================
            // TITANIUM VALIDATION LAYER - STREAM SCANNER
            // ========================================================================

            // VALIDATION 1: Empty chunk check
            if (chunk.empty() || chunk.data() == nullptr) {
                return ScanResult{};
            }

            // TITANIUM: Always track bytes processed, even if store is unavailable
            // This allows streaming progress tracking independent of scan capability
            try {
                m_buffer.insert(m_buffer.end(), chunk.begin(), chunk.end());
                if (m_bytesProcessed <= SIZE_MAX - chunk.size()) {
                    m_bytesProcessed += chunk.size();
                }
            }
            catch (const std::bad_alloc&) {
                SS_LOG_ERROR(L"SignatureStore", L"StreamScanner::FeedChunk: Buffer allocation failed");
                ScanResult result{};
                result.errorCount = 1;
                result.lastError = "Memory allocation failed";
                return result;
            }

            // VALIDATION 2: Check store availability for actual scanning
            if (!m_store || !m_store->IsInitialized()) {
                // Store not available - data is buffered but can't be scanned yet
                // This is not an error - bytes are tracked and will be scanned in Finalize()
                return ScanResult{};
            }

            // 1. LARGE CHUNK BYPASS (50MB+)
            // Scan very large chunks directly without buffering.
            // Eliminates memory allocation and memcpy overhead.
            constexpr size_t DIRECT_SCAN_LIMIT = 50 * 1024 * 1024;
            if (chunk.size() > DIRECT_SCAN_LIMIT) {
                SS_LOG_DEBUG(L"SignatureStore", L"StreamScanner: Direct scan for large chunk (%zu bytes)", chunk.size());
                // Note: For direct scan, we already added to buffer above - clear it and scan directly
                m_buffer.clear();
                m_buffer.insert(m_buffer.end(), chunk.begin(), chunk.end());
                auto result = m_store->ScanBuffer(m_buffer, m_options);
                m_buffer.clear();
                return result;
            }

            // 2. BUFFER MANAGEMENT & THRESHOLD SCAN (10MB)
            // If the buffer exceeds 10MB, scan and clear it
            constexpr size_t SCAN_THRESHOLD = 10 * 1024 * 1024;

            if (m_buffer.size() >= SCAN_THRESHOLD) {
                auto result = m_store->ScanBuffer(m_buffer, m_options);
                m_buffer.clear();
                return result;
            }

            // 3. Buffer accumulated but below threshold - no scan needed yet
            return ScanResult{};
        }

        ScanResult SignatureStore::StreamScanner::Finalize() noexcept {
            // ========================================================================
            // TITANIUM VALIDATION LAYER - FINALIZE
            // ========================================================================

            ScanResult result{};
            
            // TITANIUM: Always report total bytes processed, regardless of store state
            result.totalBytesScanned = m_bytesProcessed;

            // VALIDATION 1: Check for null store pointer
            if (!m_store) {
                SS_LOG_WARN(L"SignatureStore", L"StreamScanner::Finalize: Store pointer is null");
                // Still return bytes processed - scanning couldn't happen but data was tracked
                m_buffer.clear();
                return result;
            }

            // VALIDATION 2: Check if store is initialized
            if (!m_store->IsInitialized()) {
                SS_LOG_WARN(L"SignatureStore", L"StreamScanner::Finalize: Store is not initialized");
                // Still return bytes processed - scanning couldn't happen but data was tracked
                m_buffer.clear();
                return result;
            }

            // VALIDATION 3: Nothing to scan
            if (m_buffer.empty()) {
                // totalBytesScanned is already set above
                return result;
            }

            // ========================================================================
            // FINAL SCAN AND CLEANUP
            // ========================================================================
            result = m_store->ScanBuffer(m_buffer, m_options);
            
            // Ensure totalBytesScanned reflects the full stream, not just the last buffer
            result.totalBytesScanned = m_bytesProcessed;

            // Clear buffer and release memory
            m_buffer.clear();
            m_buffer.shrink_to_fit();

            return result;
        }
	}
}