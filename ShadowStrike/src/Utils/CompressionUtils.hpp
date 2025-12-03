/**
 * @file CompressionUtils.hpp
 * @brief Windows Compression API utilities with security hardening.
 *
 * Provides RAII wrappers for Windows Compression API (cabinet.dll) with
 * protection against decompression bombs and malformed data.
 *
 * @copyright Copyright (c) 2025 ShadowStrike Security
 * @license Proprietary - All rights reserved
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

#include "Logger.hpp"

namespace ShadowStrike {
    namespace Utils {
        namespace CompressionUtils {

            // ============================================================================
            // Security Constants - Decompression Bomb Protection
            // ============================================================================

            /// Maximum allowed decompressed output size (512 MB)
            /// Prevents memory exhaustion from decompression bombs
            constexpr size_t MAX_DECOMPRESSED_SIZE = 512ULL * 1024 * 1024;

            /// Maximum allowed compressed input size (256 MB)
            /// Reasonable limit for compressed data processing
            constexpr size_t MAX_COMPRESSED_SIZE = 256ULL * 1024 * 1024;

            /// Maximum allowed compression ratio (100:1)
            /// Ratios above this are suspicious and may indicate an attack
            constexpr size_t MAX_COMPRESSION_RATIO = 100;

            /// Minimum buffer allocation size
            constexpr size_t MIN_BUFFER_SIZE = 64;

            /// Scratch buffer size for small compressions
            constexpr size_t SCRATCH_BUFFER_SIZE = 64;

            // ============================================================================
            // Windows Compression API Algorithm Identifiers
            // ============================================================================

            /**
             * @brief Compression algorithm identifiers.
             *
             * Maps to Windows Compression API algorithm constants from compressapi.h:
             * - COMPRESS_ALGORITHM_MSZIP       (0x0002) - MS-ZIP format
             * - COMPRESS_ALGORITHM_XPRESS      (0x0003) - XPRESS format
             * - COMPRESS_ALGORITHM_XPRESS_HUFF (0x0004) - XPRESS with Huffman
             * - COMPRESS_ALGORITHM_LZMS        (0x0005) - LZMS format
             */
            enum class Algorithm : uint32_t {
                Mszip = 0x0002,       ///< MS-ZIP compression
                Xpress = 0x0003,      ///< XPRESS compression (fastest)
                XpressHuff = 0x0004,  ///< XPRESS with Huffman encoding
                Lzms = 0x0005         ///< LZMS compression (best ratio)
            };

            // ============================================================================
            // API Availability Functions
            // ============================================================================

            /**
             * @brief Checks if the Windows Compression API is available.
             *
             * @return true if cabinet.dll is loaded and all required functions resolved.
             */
            [[nodiscard]] bool IsCompressionApiAvailable() noexcept;

            /**
             * @brief Checks if a specific compression algorithm is supported.
             *
             * @param alg The algorithm to check.
             * @return true if the algorithm is supported on this system.
             */
            [[nodiscard]] bool IsAlgorithmSupported(Algorithm alg) noexcept;

            // ============================================================================
            // One-Shot Compression/Decompression Functions
            // ============================================================================

            /**
             * @brief Compresses a buffer using the specified algorithm.
             *
             * @param alg Compression algorithm to use.
             * @param src Pointer to source data (may be nullptr if srcSize == 0).
             * @param srcSize Size of source data in bytes.
             * @param dst Output vector for compressed data.
             * @return true on success, false on failure.
             *
             * @note Thread-safe. Creates temporary compressor for each call.
             */
            [[nodiscard]] bool CompressBuffer(
                Algorithm alg,
                const void* src,
                size_t srcSize,
                std::vector<uint8_t>& dst) noexcept;

            /**
             * @brief Decompresses a buffer using the specified algorithm.
             *
             * @param alg Decompression algorithm to use.
             * @param src Pointer to compressed data (may be nullptr if srcSize == 0).
             * @param srcSize Size of compressed data in bytes.
             * @param dst Output vector for decompressed data.
             * @param expectedUncompressedSize Optional expected size for validation.
             * @return true on success, false on failure.
             *
             * @note Thread-safe. Creates temporary decompressor for each call.
             * @warning Enforces MAX_DECOMPRESSED_SIZE limit to prevent bombs.
             */
            [[nodiscard]] bool DecompressBuffer(
                Algorithm alg,
                const void* src,
                size_t srcSize,
                std::vector<uint8_t>& dst,
                size_t expectedUncompressedSize = 0) noexcept;

            // ============================================================================
            // RAII Compressor Class
            // ============================================================================

            /**
             * @brief RAII wrapper for Windows Compression API compressor handle.
             *
             * Provides persistent compressor for multiple compression operations.
             * More efficient than CompressBuffer() for repeated compressions.
             *
             * @note Not thread-safe. Each thread should have its own instance.
             */
            class Compressor {
            public:
                /// Default constructor - creates invalid compressor
                Compressor() noexcept = default;

                /// Destructor - releases compressor handle
                ~Compressor() noexcept { close(); }

                // Non-copyable
                Compressor(const Compressor&) = delete;
                Compressor& operator=(const Compressor&) = delete;

                /// Move constructor
                Compressor(Compressor&& other) noexcept;

                /// Move assignment
                Compressor& operator=(Compressor&& other) noexcept;

                /**
                 * @brief Opens the compressor with specified algorithm.
                 *
                 * @param alg Algorithm to use.
                 * @return true on success, false on failure.
                 */
                [[nodiscard]] bool open(Algorithm alg) noexcept;

                /**
                 * @brief Closes the compressor and releases resources.
                 */
                void close() noexcept;

                /**
                 * @brief Compresses data into the output buffer.
                 *
                 * @param src Source data pointer.
                 * @param srcSize Source data size.
                 * @param dst Output vector for compressed data.
                 * @return true on success, false on failure.
                 */
                [[nodiscard]] bool compress(
                    const void* src,
                    size_t srcSize,
                    std::vector<uint8_t>& dst) const noexcept;

                /// @brief Returns true if compressor is valid and ready.
                [[nodiscard]] bool valid() const noexcept { return m_handle != nullptr; }

                /// @brief Returns the current algorithm.
                [[nodiscard]] Algorithm algorithm() const noexcept { return m_alg; }

                /// @brief Explicit bool conversion for validity check.
                [[nodiscard]] explicit operator bool() const noexcept { return valid(); }

            private:
                void moveFrom(Compressor&& other) noexcept;

                void* m_handle = nullptr;           ///< COMPRESSOR_HANDLE
                Algorithm m_alg = Algorithm::Xpress; ///< Current algorithm
            };

            // ============================================================================
            // RAII Decompressor Class
            // ============================================================================

            /**
             * @brief RAII wrapper for Windows Compression API decompressor handle.
             *
             * Provides persistent decompressor for multiple decompression operations.
             * More efficient than DecompressBuffer() for repeated decompressions.
             *
             * @note Not thread-safe. Each thread should have its own instance.
             */
            class Decompressor {
            public:
                /// Default constructor - creates invalid decompressor
                Decompressor() noexcept = default;

                /// Destructor - releases decompressor handle
                ~Decompressor() noexcept { close(); }

                // Non-copyable
                Decompressor(const Decompressor&) = delete;
                Decompressor& operator=(const Decompressor&) = delete;

                /// Move constructor
                Decompressor(Decompressor&& other) noexcept;

                /// Move assignment
                Decompressor& operator=(Decompressor&& other) noexcept;

                /**
                 * @brief Opens the decompressor with specified algorithm.
                 *
                 * @param alg Algorithm to use.
                 * @return true on success, false on failure.
                 */
                [[nodiscard]] bool open(Algorithm alg) noexcept;

                /**
                 * @brief Closes the decompressor and releases resources.
                 */
                void close() noexcept;

                /**
                 * @brief Decompresses data into the output buffer.
                 *
                 * @param src Compressed data pointer.
                 * @param srcSize Compressed data size.
                 * @param dst Output vector for decompressed data.
                 * @param expectedUncompressedSize Optional expected size for validation.
                 * @return true on success, false on failure.
                 *
                 * @warning Enforces MAX_DECOMPRESSED_SIZE limit.
                 */
                [[nodiscard]] bool decompress(
                    const void* src,
                    size_t srcSize,
                    std::vector<uint8_t>& dst,
                    size_t expectedUncompressedSize = 0) const noexcept;

                /// @brief Returns true if decompressor is valid and ready.
                [[nodiscard]] bool valid() const noexcept { return m_handle != nullptr; }

                /// @brief Returns the current algorithm.
                [[nodiscard]] Algorithm algorithm() const noexcept { return m_alg; }

                /// @brief Explicit bool conversion for validity check.
                [[nodiscard]] explicit operator bool() const noexcept { return valid(); }

            private:
                void moveFrom(Decompressor&& other) noexcept;

                void* m_handle = nullptr;           ///< DECOMPRESSOR_HANDLE
                Algorithm m_alg = Algorithm::Xpress; ///< Current algorithm
            };

        } // namespace CompressionUtils
    } // namespace Utils
} // namespace ShadowStrike