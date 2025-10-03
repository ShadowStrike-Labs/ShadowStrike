
#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#endif

#include "Logger.hpp"

namespace ShadowStrike {
    namespace Utils {
        namespace CompressionUtils {
            // Windows Compression API algorithm values (compressapi.h)
            // COMPRESS_ALGORITHM_MSZIP       0x0002
            // COMPRESS_ALGORITHM_XPRESS      0x0003
            // COMPRESS_ALGORITHM_XPRESS_HUFF 0x0004
            // COMPRESS_ALGORITHM_LZMS        0x0005
            enum class Algorithm : uint32_t {
                Mszip = 0x0002,
                Xpress = 0x0003,
                XpressHuff = 0x0004,
                Lzms = 0x0005
            };

            //is API exists
            bool IsCompressionApiAvailable() noexcept;

            bool IsAlgorithmSupported(Algorithm alg) noexcept;

            bool CompressBuffer(Algorithm alg,
                const void* src, size_t srcSize,
                std::vector<uint8_t>& dst) noexcept;

            bool DecompressBuffer(Algorithm alg,
                const void* src, size_t srcSize,
                std::vector<uint8_t>& dst,
                size_t expectedUncompressedSize = 0) noexcept;


            class Compressor {
            public:
                Compressor() noexcept = default;
                ~Compressor() { close(); }

                Compressor(const Compressor&) = delete;
                Compressor& operator=(const Compressor&) = delete;

                Compressor(Compressor&& other) noexcept { moveFrom(std::move(other)); }
                Compressor& operator=(Compressor&& other) noexcept {
                    if (this != &other) { close(); moveFrom(std::move(other)); }
                    return *this;
                }

                bool open(Algorithm alg) noexcept;
                void close() noexcept;


                bool compress(const void* src, size_t srcSize, std::vector<uint8_t>& dst) const noexcept;

                bool valid() const noexcept { return m_handle != nullptr; }
                Algorithm algorithm() const noexcept { return m_alg; }

            private:
                void moveFrom(Compressor&& other) noexcept;
                void* m_handle = nullptr; // COMPRESSOR_HANDLE
                Algorithm m_alg = Algorithm::Xpress;
            };

            class Decompressor {
            public:
                Decompressor() noexcept = default;
                ~Decompressor() { close(); }

                Decompressor(const Decompressor&) = delete;
                Decompressor& operator=(const Decompressor&) = delete;

                Decompressor(Decompressor&& other) noexcept { moveFrom(std::move(other)); }
                Decompressor& operator=(Decompressor&& other) noexcept {
                    if (this != &other) { close(); moveFrom(std::move(other)); }
                    return *this;
                }

                bool open(Algorithm alg) noexcept;
                void close() noexcept;

                bool decompress(const void* src, size_t srcSize, std::vector<uint8_t>& dst,
                    size_t expectedUncompressedSize = 0) const noexcept;

                bool valid() const noexcept { return m_handle != nullptr; }
                Algorithm algorithm() const noexcept { return m_alg; }

            private:
                void moveFrom(Decompressor&& other) noexcept;
                void* m_handle = nullptr; // DECOMPRESSOR_HANDLE
                Algorithm m_alg = Algorithm::Xpress;
            };
        } //namespace CompressionUtils

    }// namespace Utils

}// namespace ShadowStrike