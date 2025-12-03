/**
 * @file CompressionUtils.cpp
 * @brief Implementation of Windows Compression API utilities.
 *
 * @copyright Copyright (c) 2025 ShadowStrike Security
 * @license Proprietary - All rights reserved
 */

#include "CompressionUtils.hpp"

#include <mutex>
#include <atomic>
#include <limits>
#include <cstring>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#endif

namespace ShadowStrike {
    namespace Utils {
        namespace CompressionUtils {

            // ============================================================================
            // Runtime-resolved Windows Compression API Types and Function Pointers
            // ============================================================================

            /// Compressor handle type (opaque pointer)
            using COMPRESSOR_HANDLE = void*;

            /// Decompressor handle type (opaque pointer)
            using DECOMPRESSOR_HANDLE = void*;

            // Function pointer types matching compressapi.h signatures
            using PFN_CreateCompressor = BOOL(WINAPI*)(DWORD, void*, COMPRESSOR_HANDLE*);
            using PFN_Compress = BOOL(WINAPI*)(COMPRESSOR_HANDLE, const void*, SIZE_T, void*, SIZE_T, SIZE_T*);
            using PFN_CloseCompressor = BOOL(WINAPI*)(COMPRESSOR_HANDLE);
            using PFN_CreateDecompressor = BOOL(WINAPI*)(DWORD, void*, DECOMPRESSOR_HANDLE*);
            using PFN_Decompress = BOOL(WINAPI*)(DECOMPRESSOR_HANDLE, const void*, SIZE_T, void*, SIZE_T, SIZE_T*);
            using PFN_CloseDecompressor = BOOL(WINAPI*)(DECOMPRESSOR_HANDLE);

            /**
             * @brief API function table for runtime-resolved cabinet.dll functions.
             *
             * Populated once during first access via GetApi().
             */
            struct ApiTable {
                HMODULE hCabinet = nullptr;
                PFN_CreateCompressor pCreateCompressor = nullptr;
                PFN_Compress pCompress = nullptr;
                PFN_CloseCompressor pCloseCompressor = nullptr;
                PFN_CreateDecompressor pCreateDecompressor = nullptr;
                PFN_Decompress pDecompress = nullptr;
                PFN_CloseDecompressor pCloseDecompressor = nullptr;

                /**
                 * @brief Validates that all required function pointers are resolved.
                 * @return true if all pointers are valid.
                 */
                [[nodiscard]] bool valid() const noexcept {
                    return hCabinet != nullptr &&
                           pCreateCompressor != nullptr &&
                           pCompress != nullptr &&
                           pCloseCompressor != nullptr &&
                           pCreateDecompressor != nullptr &&
                           pDecompress != nullptr &&
                           pCloseDecompressor != nullptr;
                }
            };

            /**
             * @brief Returns the singleton API table, initializing on first call.
             *
             * Uses std::call_once for thread-safe one-time initialization.
             *
             * @return Reference to the API table.
             */
            static ApiTable& GetApi() noexcept {
                static ApiTable g{};
                static std::once_flag once;

                std::call_once(once, []() noexcept {
                    // Try to get already-loaded cabinet.dll first
                    HMODULE h = ::GetModuleHandleW(L"cabinet.dll");
                    if (h == nullptr) {
                        // Load if not already present
                        h = ::LoadLibraryW(L"cabinet.dll");
                    }

                    if (h == nullptr) {
                        SS_LOG_LAST_ERROR(L"CompressionUtils", L"cabinet.dll failed to load");
                        return;
                    }

                    g.hCabinet = h;

                    // Resolve all function pointers
                    g.pCreateCompressor = reinterpret_cast<PFN_CreateCompressor>(
                        ::GetProcAddress(h, "CreateCompressor"));
                    g.pCompress = reinterpret_cast<PFN_Compress>(
                        ::GetProcAddress(h, "Compress"));
                    g.pCloseCompressor = reinterpret_cast<PFN_CloseCompressor>(
                        ::GetProcAddress(h, "CloseCompressor"));
                    g.pCreateDecompressor = reinterpret_cast<PFN_CreateDecompressor>(
                        ::GetProcAddress(h, "CreateDecompressor"));
                    g.pDecompress = reinterpret_cast<PFN_Decompress>(
                        ::GetProcAddress(h, "Decompress"));
                    g.pCloseDecompressor = reinterpret_cast<PFN_CloseDecompressor>(
                        ::GetProcAddress(h, "CloseDecompressor"));

                    if (!g.valid()) {
                        SS_LOG_ERROR(L"CompressionUtils",
                            L"Failed to resolve compression API functions from cabinet.dll");
                        // Invalidate the table on partial resolution
                        g = ApiTable{};
                    }
                });

                return g;
            }

            /**
             * @brief Converts Algorithm enum to Windows DWORD algorithm identifier.
             */
            [[nodiscard]] static inline DWORD ToWinAlg(Algorithm alg) noexcept {
                return static_cast<DWORD>(alg);
            }

            /**
             * @brief Validates that a size value fits in SIZE_T without overflow.
             */
            [[nodiscard]] static inline bool SizeToSizeT(size_t value, SIZE_T& out) noexcept {
                // SIZE_T is typically same as size_t on Windows, but be safe
                if (value > static_cast<size_t>(std::numeric_limits<SIZE_T>::max())) {
                    return false;
                }
                out = static_cast<SIZE_T>(value);
                return true;
            }

            // ============================================================================
            // SEH-Protected Wrappers (Windows Only)
            // ============================================================================

#ifdef _WIN32
            /**
             * @brief SEH-protected decompression wrapper.
             *
             * Catches structured exceptions (access violations, etc.) that may occur
             * when decompressing malformed or corrupted data, preventing process crash.
             *
             * @param api The API table.
             * @param h Decompressor handle.
             * @param src Source compressed data.
             * @param srcSize Source data size.
             * @param dst Destination buffer.
             * @param dstCap Destination capacity.
             * @param outSize Output: actual decompressed size.
             * @param lastErr Output: Win32 error code on failure.
             * @return TRUE on success, FALSE on failure.
             */
            static inline BOOL SafeDecompress(
                const ApiTable& api,
                DECOMPRESSOR_HANDLE h,
                const void* src,
                SIZE_T srcSize,
                void* dst,
                SIZE_T dstCap,
                SIZE_T* outSize,
                DWORD& lastErr) noexcept
            {
                BOOL ok = FALSE;
                lastErr = ERROR_SUCCESS;

                // Validate parameters before SEH block
                if (h == nullptr || api.pDecompress == nullptr) {
                    lastErr = ERROR_INVALID_HANDLE;
                    return FALSE;
                }

                if (outSize == nullptr) {
                    lastErr = ERROR_INVALID_PARAMETER;
                    return FALSE;
                }

                __try {
                    ok = api.pDecompress(h, src, srcSize, dst, dstCap, outSize);
                    if (ok == FALSE) {
                        lastErr = ::GetLastError();
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    // Map structured exception to invalid data error
                    lastErr = ERROR_INVALID_DATA;
                    ok = FALSE;
                    *outSize = 0;
                }

                return ok;
            }

            /**
             * @brief SEH-protected compression wrapper.
             *
             * Catches structured exceptions during compression to prevent crashes.
             *
             * @param api The API table.
             * @param h Compressor handle.
             * @param src Source data.
             * @param srcSize Source data size.
             * @param dst Destination buffer.
             * @param dstCap Destination capacity.
             * @param outSize Output: actual compressed size.
             * @param lastErr Output: Win32 error code on failure.
             * @return TRUE on success, FALSE on failure.
             */
            static inline BOOL SafeCompress(
                const ApiTable& api,
                COMPRESSOR_HANDLE h,
                const void* src,
                SIZE_T srcSize,
                void* dst,
                SIZE_T dstCap,
                SIZE_T* outSize,
                DWORD& lastErr) noexcept
            {
                BOOL ok = FALSE;
                lastErr = ERROR_SUCCESS;

                // Validate parameters before SEH block
                if (h == nullptr || api.pCompress == nullptr) {
                    lastErr = ERROR_INVALID_HANDLE;
                    return FALSE;
                }

                if (outSize == nullptr) {
                    lastErr = ERROR_INVALID_PARAMETER;
                    return FALSE;
                }

                __try {
                    ok = api.pCompress(h, src, srcSize, dst, dstCap, outSize);
                    if (ok == FALSE) {
                        lastErr = ::GetLastError();
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    // Map structured exception to invalid data error
                    lastErr = ERROR_INVALID_DATA;
                    ok = FALSE;
                    *outSize = 0;
                }

                return ok;
            }
#endif // _WIN32

            // ============================================================================
            // API Availability Functions
            // ============================================================================

            bool IsCompressionApiAvailable() noexcept {
                return GetApi().valid();
            }

            bool IsAlgorithmSupported(Algorithm alg) noexcept {
                const auto& api = GetApi();
                if (!api.valid()) {
                    return false;
                }

                // Validate algorithm value is in expected range
                const DWORD winAlg = ToWinAlg(alg);
                if (winAlg < 0x0002 || winAlg > 0x0005) {
                    return false;
                }

                // Try to create a compressor to test support
                COMPRESSOR_HANDLE h = nullptr;
                if (api.pCreateCompressor(winAlg, nullptr, &h) == FALSE || h == nullptr) {
                    return false;
                }

                // Clean up test handle
                api.pCloseCompressor(h);
                return true;
            }

            // ============================================================================
            // Core Compression Implementation
            // ============================================================================

            /**
             * @brief Internal compression implementation.
             *
             * @param alg Windows algorithm identifier.
             * @param src Source data pointer.
             * @param srcSize Source data size.
             * @param dst Output vector for compressed data.
             * @return true on success, false on failure.
             */
            static bool CompressCore(
                DWORD alg,
                const void* src,
                size_t srcSize,
                std::vector<uint8_t>& dst) noexcept
            {
                // Clear output first
                dst.clear();

                // Validate input parameters
                if (src == nullptr && srcSize > 0) {
                    return false;
                }

                // Empty input is valid - return empty output
                if (srcSize == 0) {
                    return true;
                }

                // Enforce size limits
                if (srcSize > MAX_COMPRESSED_SIZE) {
                    SS_LOG_WARN(L"CompressionUtils",
                        L"CompressCore: input size %zu exceeds limit %zu",
                        srcSize, MAX_COMPRESSED_SIZE);
                    return false;
                }

                // Validate SIZE_T compatibility
                SIZE_T srcSizeT = 0;
                if (!SizeToSizeT(srcSize, srcSizeT)) {
                    return false;
                }

                // Get API table
                const auto& api = GetApi();
                if (!api.valid()) {
                    return false;
                }

                // Create compressor handle
                COMPRESSOR_HANDLE h = nullptr;
                if (api.pCreateCompressor(alg, nullptr, &h) == FALSE || h == nullptr) {
                    SS_LOG_LAST_ERROR(L"CompressionUtils",
                        L"CreateCompressor failed (alg=%lu)", alg);
                    return false;
                }

                // RAII guard for compressor handle
                struct CompressorGuard {
                    COMPRESSOR_HANDLE handle;
                    const ApiTable& api;
                    ~CompressorGuard() {
                        if (handle != nullptr && api.pCloseCompressor != nullptr) {
                            api.pCloseCompressor(handle);
                        }
                    }
                } guard{ h, api };

                // First pass: query required output size using small scratch buffer
                SIZE_T required = 0;
                BYTE scratch[SCRATCH_BUFFER_SIZE] = {};
                DWORD err = ERROR_SUCCESS;

#ifdef _WIN32
                BOOL ok = SafeCompress(api, h, src, srcSizeT,
                    scratch, sizeof(scratch), &required, err);
#else
                BOOL ok = api.pCompress(h, src, srcSizeT,
                    scratch, sizeof(scratch), &required);
                err = ok ? ERROR_SUCCESS : GetLastError();
#endif

                // If compression succeeded into scratch buffer, use it
                if (ok != FALSE) {
                    if (required <= sizeof(scratch)) {
                        try {
                            dst.assign(scratch, scratch + required);
                            return true;
                        }
                        catch (const std::bad_alloc&) {
                            return false;
                        }
                    }
                    // Required > scratch but compression succeeded - shouldn't happen
                    return false;
                }

                // Check if we got the required size
                if (err != ERROR_INSUFFICIENT_BUFFER || required == 0) {
                    return false;
                }

                // Validate required size is reasonable
                if (required > MAX_DECOMPRESSED_SIZE) {
                    return false;
                }

                // Allocate output buffer
                try {
                    dst.resize(static_cast<size_t>(required));
                }
                catch (const std::bad_alloc&) {
                    return false;
                }

                // Second pass: actual compression
                SIZE_T outSize = 0;

#ifdef _WIN32
                ok = SafeCompress(api, h, src, srcSizeT,
                    dst.data(), required, &outSize, err);
#else
                ok = api.pCompress(h, src, srcSizeT,
                    dst.data(), required, &outSize);
#endif

                if (ok == FALSE) {
                    dst.clear();
                    return false;
                }

                // Validate output size
                if (outSize > required) {
                    dst.clear();
                    return false;
                }

                // Shrink to actual size
                dst.resize(static_cast<size_t>(outSize));
                return true;
            }

            // ============================================================================
            // Core Decompression Implementation
            // ============================================================================

            /**
             * @brief Internal decompression implementation.
             *
             * Includes decompression bomb protection via size limits.
             *
             * @param alg Windows algorithm identifier.
             * @param src Compressed data pointer.
             * @param srcSize Compressed data size.
             * @param dst Output vector for decompressed data.
             * @param expectedSize Optional expected decompressed size for validation.
             * @return true on success, false on failure.
             */
            static bool DecompressCore(
                DWORD alg,
                const void* src,
                size_t srcSize,
                std::vector<uint8_t>& dst,
                size_t expectedSize) noexcept
            {
                // Clear output first
                dst.clear();

                // Validate input parameters
                if (src == nullptr && srcSize > 0) {
                    return false;
                }

                // Empty input is valid - return empty output
                if (srcSize == 0) {
                    return true;
                }

                // Enforce input size limit
                if (srcSize > MAX_COMPRESSED_SIZE) {
                    SS_LOG_ERROR(L"CompressionUtils",
                        L"DecompressCore: input size %zu exceeds limit %zu",
                        srcSize, MAX_COMPRESSED_SIZE);
                    return false;
                }

                // Validate expected size if provided
                if (expectedSize > MAX_DECOMPRESSED_SIZE) {
                    SS_LOG_ERROR(L"CompressionUtils",
                        L"DecompressCore: expected size %zu exceeds limit %zu",
                        expectedSize, MAX_DECOMPRESSED_SIZE);
                    return false;
                }

                // Validate SIZE_T compatibility
                SIZE_T srcSizeT = 0;
                if (!SizeToSizeT(srcSize, srcSizeT)) {
                    return false;
                }

                // Get API table
                const auto& api = GetApi();
                if (!api.valid()) {
                    return false;
                }

                // Create decompressor handle
                DECOMPRESSOR_HANDLE h = nullptr;
                if (api.pCreateDecompressor(alg, nullptr, &h) == FALSE || h == nullptr) {
                    SS_LOG_ERROR(L"CompressionUtils",
                        L"CreateDecompressor failed (alg=%lu)", alg);
                    return false;
                }

                // RAII guard for decompressor handle
                struct DecompressorGuard {
                    DECOMPRESSOR_HANDLE handle;
                    const ApiTable& api;
                    ~DecompressorGuard() {
                        if (handle != nullptr && api.pCloseDecompressor != nullptr) {
                            api.pCloseDecompressor(handle);
                        }
                    }
                } guard{ h, api };

                // First pass: query required output size using small scratch buffer
                SIZE_T required = 0;
                BYTE scratch[SCRATCH_BUFFER_SIZE] = {};
                DWORD err = ERROR_SUCCESS;

#ifdef _WIN32
                BOOL ok = SafeDecompress(api, h, src, srcSizeT,
                    scratch, sizeof(scratch), &required, err);
#else
                BOOL ok = api.pDecompress(h, src, srcSizeT,
                    scratch, sizeof(scratch), &required);
                err = ok ? ERROR_SUCCESS : GetLastError();
#endif

                // If decompression succeeded into scratch buffer, use it
                if (ok != FALSE) {
                    if (required <= sizeof(scratch)) {
                        try {
                            dst.assign(scratch, scratch + required);
                            return true;
                        }
                        catch (const std::bad_alloc&) {
                            return false;
                        }
                    }
                    // Required > scratch but decompression succeeded - shouldn't happen
                    return false;
                }

                // Check if we got the required size
                if (err != ERROR_INSUFFICIENT_BUFFER || required == 0) {
                    return false;
                }

                // CRITICAL: Decompression bomb protection
                if (required > MAX_DECOMPRESSED_SIZE) {
                    SS_LOG_WARN(L"CompressionUtils",
                        L"DecompressCore: decompressed size %zu exceeds limit %zu (potential bomb)",
                        static_cast<size_t>(required), MAX_DECOMPRESSED_SIZE);
                    return false;
                }

                // Check compression ratio for additional bomb detection
                if (srcSize > 0) {
                    const size_t ratio = static_cast<size_t>(required) / srcSize;
                    if (ratio > MAX_COMPRESSION_RATIO) {
                        SS_LOG_WARN(L"CompressionUtils",
                            L"DecompressCore: compression ratio %zu:1 exceeds limit (potential bomb)",
                            ratio);
                        return false;
                    }
                }

                // Validate against expected size if provided
                if (expectedSize > 0 && static_cast<size_t>(required) != expectedSize) {
                    SS_LOG_WARN(L"CompressionUtils",
                        L"DecompressCore: size mismatch (expected %zu, got %zu)",
                        expectedSize, static_cast<size_t>(required));
                    return false;
                }

                // Allocate output buffer
                try {
                    dst.resize(static_cast<size_t>(required));
                }
                catch (const std::bad_alloc&) {
                    return false;
                }

                // Second pass: actual decompression
                SIZE_T outSize = 0;

#ifdef _WIN32
                ok = SafeDecompress(api, h, src, srcSizeT,
                    dst.data(), required, &outSize, err);
#else
                ok = api.pDecompress(h, src, srcSizeT,
                    dst.data(), required, &outSize);
#endif

                if (ok == FALSE) {
                    dst.clear();
                    return false;
                }

                // Adjust size if different (shouldn't happen but be safe)
                if (outSize != required) {
                    if (outSize > required) {
                        // Buffer overflow - critical error
                        dst.clear();
                        return false;
                    }
                    dst.resize(static_cast<size_t>(outSize));
                }

                return true;
            }

            // ============================================================================
            // Public One-Shot Functions
            // ============================================================================

            bool CompressBuffer(
                Algorithm alg,
                const void* src,
                size_t srcSize,
                std::vector<uint8_t>& dst) noexcept
            {
                // Validate input before passing to core
                if (src == nullptr && srcSize > 0) {
                    dst.clear();
                    return false;
                }

                return CompressCore(ToWinAlg(alg), src, srcSize, dst);
            }

            bool DecompressBuffer(
                Algorithm alg,
                const void* src,
                size_t srcSize,
                std::vector<uint8_t>& dst,
                size_t expectedUncompressedSize) noexcept
            {
                // Validate input before passing to core
                if (src == nullptr && srcSize > 0) {
                    dst.clear();
                    return false;
                }

                return DecompressCore(ToWinAlg(alg), src, srcSize, dst, expectedUncompressedSize);
            }

            // ============================================================================
            // Compressor Class Implementation
            // ============================================================================

            Compressor::Compressor(Compressor&& other) noexcept
                : m_handle(nullptr)
                , m_alg(Algorithm::Xpress)
            {
                moveFrom(std::move(other));
            }

            Compressor& Compressor::operator=(Compressor&& other) noexcept {
                if (this != &other) {
                    close();
                    moveFrom(std::move(other));
                }
                return *this;
            }

            bool Compressor::open(Algorithm alg) noexcept {
                // Close any existing handle first
                close();

                const auto& api = GetApi();
                if (!api.valid()) {
                    return false;
                }

                // Validate algorithm
                const DWORD winAlg = ToWinAlg(alg);
                if (winAlg < 0x0002 || winAlg > 0x0005) {
                    return false;
                }

                COMPRESSOR_HANDLE h = nullptr;
                if (api.pCreateCompressor(winAlg, nullptr, &h) == FALSE || h == nullptr) {
                    SS_LOG_LAST_ERROR(L"CompressionUtils",
                        L"Compressor::open - CreateCompressor failed (alg=%lu)", winAlg);
                    return false;
                }

                m_handle = h;
                m_alg = alg;
                return true;
            }

            void Compressor::close() noexcept {
                if (m_handle == nullptr) {
                    return;
                }

                const auto& api = GetApi();
                if (api.pCloseCompressor != nullptr) {
                    if (api.pCloseCompressor(static_cast<COMPRESSOR_HANDLE>(m_handle)) == FALSE) {
                        SS_LOG_LAST_ERROR(L"CompressionUtils",
                            L"Compressor::close - CloseCompressor failed");
                    }
                }

                m_handle = nullptr;
            }

            bool Compressor::compress(
                const void* src,
                size_t srcSize,
                std::vector<uint8_t>& dst) const noexcept
            {
                // Clear output first
                dst.clear();

                // Validate handle
                if (m_handle == nullptr) {
                    return false;
                }

                // Validate input parameters
                if (src == nullptr && srcSize > 0) {
                    return false;
                }

                // Empty input is valid
                if (srcSize == 0) {
                    return true;
                }

                // Enforce size limits
                if (srcSize > MAX_COMPRESSED_SIZE) {
                    return false;
                }

                // Validate SIZE_T compatibility
                SIZE_T srcSizeT = 0;
                if (!SizeToSizeT(srcSize, srcSizeT)) {
                    return false;
                }

                const auto& api = GetApi();
                if (!api.valid()) {
                    return false;
                }

                // First pass: query required size using scratch buffer
                SIZE_T required = 0;
                BYTE scratch[SCRATCH_BUFFER_SIZE] = {};
                DWORD err = ERROR_SUCCESS;

#ifdef _WIN32
                BOOL ok = SafeCompress(api, static_cast<COMPRESSOR_HANDLE>(m_handle),
                    src, srcSizeT, scratch, sizeof(scratch), &required, err);
#else
                BOOL ok = api.pCompress(static_cast<COMPRESSOR_HANDLE>(m_handle),
                    src, srcSizeT, scratch, sizeof(scratch), &required);
                err = ok ? ERROR_SUCCESS : GetLastError();
#endif

                // If compression succeeded into scratch buffer
                if (ok != FALSE) {
                    if (required <= sizeof(scratch)) {
                        try {
                            dst.assign(scratch, scratch + required);
                            return true;
                        }
                        catch (const std::bad_alloc&) {
                            return false;
                        }
                    }
                    return false;
                }

                // Check for valid error condition
                if (err != ERROR_INSUFFICIENT_BUFFER || required == 0) {
                    return false;
                }

                // Validate required size
                if (required > MAX_DECOMPRESSED_SIZE) {
                    return false;
                }

                // Allocate output buffer
                try {
                    dst.resize(static_cast<size_t>(required));
                }
                catch (const std::bad_alloc&) {
                    return false;
                }

                // Second pass: actual compression
                SIZE_T outSize = 0;

#ifdef _WIN32
                ok = SafeCompress(api, static_cast<COMPRESSOR_HANDLE>(m_handle),
                    src, srcSizeT, dst.data(), required, &outSize, err);
#else
                ok = api.pCompress(static_cast<COMPRESSOR_HANDLE>(m_handle),
                    src, srcSizeT, dst.data(), required, &outSize);
#endif

                if (ok == FALSE) {
                    dst.clear();
                    return false;
                }

                // Validate output
                if (outSize > required) {
                    dst.clear();
                    return false;
                }

                dst.resize(static_cast<size_t>(outSize));
                return true;
            }


            // ============================================================================
            // Decompressor Class Implementation
            // ============================================================================

            Decompressor::Decompressor(Decompressor&& other) noexcept
                : m_handle(nullptr)
                , m_alg(Algorithm::Xpress)
            {
                moveFrom(std::move(other));
            }

            Decompressor& Decompressor::operator=(Decompressor&& other) noexcept {
                if (this != &other) {
                    close();
                    moveFrom(std::move(other));
                }
                return *this;
            }

            bool Decompressor::open(Algorithm alg) noexcept {
                // Close any existing handle first
                close();

                const auto& api = GetApi();
                if (!api.valid()) {
                    return false;
                }

                // Validate algorithm
                const DWORD winAlg = ToWinAlg(alg);
                if (winAlg < 0x0002 || winAlg > 0x0005) {
                    return false;
                }

                DECOMPRESSOR_HANDLE h = nullptr;
                if (api.pCreateDecompressor(winAlg, nullptr, &h) == FALSE || h == nullptr) {
                    SS_LOG_LAST_ERROR(L"CompressionUtils",
                        L"Decompressor::open - CreateDecompressor failed (alg=%lu)", winAlg);
                    return false;
                }

                m_handle = h;
                m_alg = alg;
                return true;
            }

            void Decompressor::close() noexcept {
                if (m_handle == nullptr) {
                    return;
                }

                const auto& api = GetApi();
                if (api.pCloseDecompressor != nullptr) {
                    if (api.pCloseDecompressor(static_cast<DECOMPRESSOR_HANDLE>(m_handle)) == FALSE) {
                        SS_LOG_LAST_ERROR(L"CompressionUtils",
                            L"Decompressor::close - CloseDecompressor failed");
                    }
                }

                m_handle = nullptr;
            }

            bool Decompressor::decompress(
                const void* src,
                size_t srcSize,
                std::vector<uint8_t>& dst,
                size_t expectedUncompressedSize) const noexcept
            {
                // Clear output first
                dst.clear();

                // Validate handle
                if (m_handle == nullptr) {
                    return false;
                }

                // Validate input parameters
                if (src == nullptr && srcSize > 0) {
                    return false;
                }

                // Empty input is valid
                if (srcSize == 0) {
                    return true;
                }

                // Enforce size limits
                if (srcSize > MAX_COMPRESSED_SIZE) {
                    return false;
                }

                // Validate expected size if provided
                if (expectedUncompressedSize > MAX_DECOMPRESSED_SIZE) {
                    return false;
                }

                // Validate SIZE_T compatibility
                SIZE_T srcSizeT = 0;
                if (!SizeToSizeT(srcSize, srcSizeT)) {
                    return false;
                }

                const auto& api = GetApi();
                if (!api.valid()) {
                    return false;
                }

                // First pass: query required size using scratch buffer
                SIZE_T required = 0;
                BYTE scratch[SCRATCH_BUFFER_SIZE] = {};
                DWORD err = ERROR_SUCCESS;

#ifdef _WIN32
                BOOL ok = SafeDecompress(api, static_cast<DECOMPRESSOR_HANDLE>(m_handle),
                    src, srcSizeT, scratch, sizeof(scratch), &required, err);
#else
                BOOL ok = api.pDecompress(static_cast<DECOMPRESSOR_HANDLE>(m_handle),
                    src, srcSizeT, scratch, sizeof(scratch), &required);
                err = ok ? ERROR_SUCCESS : GetLastError();
#endif

                // If decompression succeeded into scratch buffer
                if (ok != FALSE) {
                    if (required <= sizeof(scratch)) {
                        try {
                            dst.assign(scratch, scratch + required);
                            return true;
                        }
                        catch (const std::bad_alloc&) {
                            return false;
                        }
                    }
                    return false;
                }

                // Check for valid error condition
                if (err != ERROR_INSUFFICIENT_BUFFER || required == 0) {
                    return false;
                }

                // CRITICAL: Decompression bomb protection
                if (required > MAX_DECOMPRESSED_SIZE) {
                    return false;
                }

                // Check compression ratio
                if (srcSize > 0) {
                    const size_t ratio = static_cast<size_t>(required) / srcSize;
                    if (ratio > MAX_COMPRESSION_RATIO) {
                        return false;
                    }
                }

                // Validate against expected size if provided
                if (expectedUncompressedSize > 0 &&
                    static_cast<size_t>(required) != expectedUncompressedSize) {
                    return false;
                }

                // Allocate output buffer
                try {
                    dst.resize(static_cast<size_t>(required));
                }
                catch (const std::bad_alloc&) {
                    return false;
                }

                // Second pass: actual decompression
                SIZE_T outSize = 0;

#ifdef _WIN32
                ok = SafeDecompress(api, static_cast<DECOMPRESSOR_HANDLE>(m_handle),
                    src, srcSizeT, dst.data(), required, &outSize, err);
#else
                ok = api.pDecompress(static_cast<DECOMPRESSOR_HANDLE>(m_handle),
                    src, srcSizeT, dst.data(), required, &outSize);
#endif

                if (ok == FALSE) {
                    dst.clear();
                    return false;
                }

                // Validate output size
                if (outSize != required) {
                    if (outSize > required) {
                        // Buffer overflow - critical error
                        dst.clear();
                        return false;
                    }
                    dst.resize(static_cast<size_t>(outSize));
                }

                return true;
            }


            // ============================================================================
            // Move Helper Implementations
            // ============================================================================

            void Compressor::moveFrom(Compressor&& other) noexcept {
                m_handle = other.m_handle;
                m_alg = other.m_alg;

                // Clear source to prevent double-close
                other.m_handle = nullptr;
                other.m_alg = Algorithm::Xpress;
            }

            void Decompressor::moveFrom(Decompressor&& other) noexcept {
                m_handle = other.m_handle;
                m_alg = other.m_alg;

                // Clear source to prevent double-close
                other.m_handle = nullptr;
                other.m_alg = Algorithm::Xpress;
            }

        } // namespace CompressionUtils
    } // namespace Utils
} // namespace ShadowStrike
