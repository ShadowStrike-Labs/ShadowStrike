#include "CompressionUtils.hpp"


#include <mutex>
#include <atomic>

namespace ShadowStrike {
	namespace Utils {
		namespace CompressionUtils {

			//compressorapi.h run-time resolved types and function pointers
            using COMPRESSOR_HANDLE = void*;
            using DECOMPRESSOR_HANDLE = void*;

            using PFN_CreateCompressor = BOOL(WINAPI*)(DWORD, void*, COMPRESSOR_HANDLE*);
            using PFN_Compress = BOOL(WINAPI*)(COMPRESSOR_HANDLE, const void*, SIZE_T, void*, SIZE_T, SIZE_T*);
            using PFN_CloseCompressor = BOOL(WINAPI*)(COMPRESSOR_HANDLE);
            using PFN_CreateDecompressor = BOOL(WINAPI*)(DWORD, void*, DECOMPRESSOR_HANDLE*);
            using PFN_Decompress = BOOL(WINAPI*)(DECOMPRESSOR_HANDLE, const void*, SIZE_T, void*, SIZE_T, SIZE_T*);
            using PFN_CloseDecompressor = BOOL(WINAPI*)(DECOMPRESSOR_HANDLE);

            struct ApiTable {
                HMODULE                  hCabinet = nullptr;
                PFN_CreateCompressor     pCreateCompressor = nullptr;
                PFN_Compress             pCompress = nullptr;
                PFN_CloseCompressor      pCloseCompressor = nullptr;
                PFN_CreateDecompressor   pCreateDecompressor = nullptr;
                PFN_Decompress           pDecompress = nullptr;
                PFN_CloseDecompressor    pCloseDecompressor = nullptr;

                bool valid() const noexcept {
                    return hCabinet && pCreateCompressor && pCompress && pCloseCompressor &&
                        pCreateDecompressor && pDecompress && pCloseDecompressor;
                }
            };

            static ApiTable& GetApi() {
                static ApiTable g{};
                static std::once_flag once;
                std::call_once(once, [] {
                    HMODULE h = ::GetModuleHandleW(L"cabinet.dll");
                    if (!h) h = ::LoadLibraryW(L"cabinet.dll");
                    if (!h) {
                        SS_LOG_LAST_ERROR(L"CompressionUtils", L"cabinet.dll yüklenemedi");
                        return;
                    }
                    g.hCabinet = h;
                    g.pCreateCompressor = reinterpret_cast<PFN_CreateCompressor>(GetProcAddress(h, "CreateCompressor"));
                    g.pCompress = reinterpret_cast<PFN_Compress>(GetProcAddress(h, "Compress"));
                    g.pCloseCompressor = reinterpret_cast<PFN_CloseCompressor>(GetProcAddress(h, "CloseCompressor"));
                    g.pCreateDecompressor = reinterpret_cast<PFN_CreateDecompressor>(GetProcAddress(h, "CreateDecompressor"));
                    g.pDecompress = reinterpret_cast<PFN_Decompress>(GetProcAddress(h, "Decompress"));
                    g.pCloseDecompressor = reinterpret_cast<PFN_CloseDecompressor>(GetProcAddress(h, "CloseDecompressor"));

                    if (!g.valid()) {
                        SS_LOG_ERROR(L"CompressionUtils", L"Failed to find compress API functions");
                        g = ApiTable{}; // invalidate
                    }
                    });
                return g;
            }

            static inline DWORD ToWinAlg(Algorithm alg) noexcept {
                return static_cast<DWORD>(alg);
            }

            bool IsCompressionApiAvailable() noexcept {
                return GetApi().valid();
            }

            bool IsAlgorithmSupported(Algorithm alg) noexcept {
                const auto& api = GetApi();
                if (!api.valid()) return false;
                COMPRESSOR_HANDLE h = nullptr;
                if (!api.pCreateCompressor(ToWinAlg(alg), nullptr, &h) || !h)
                    return false;
                api.pCloseCompressor(h);
                return true;
            }

           //Compress
            static bool CompressCore(DWORD alg, const void* src, size_t srcSize, std::vector<uint8_t>& dst) noexcept {
                dst.clear();
				if (srcSize == 0) { //empty input -> empty output
                    return true;
                }

                const auto& api = GetApi();
                if (!api.valid()) return false;

                COMPRESSOR_HANDLE h = nullptr;
                if (!api.pCreateCompressor(alg, nullptr, &h) || !h) {
                    SS_LOG_LAST_ERROR(L"CompressionUtils", L"CreateCompressor Failed (alg=%lu)", alg);
                    return false;
                }

                bool ok = false;
                SIZE_T outSize = 0;

                // First Capacity src + src/16 + 64KB (buffer size)
                SIZE_T cap = static_cast<SIZE_T>(srcSize + (srcSize / 16) + 65536ull);
                if (cap < 64) cap = 64;
                dst.resize(static_cast<size_t>(cap));

                if (api.pCompress(h, src, static_cast<SIZE_T>(srcSize), dst.data(), cap, &outSize)) {
                    dst.resize(static_cast<size_t>(outSize));
                    ok = true;
                }
                else {
                    DWORD err = GetLastError();
                    if (err == ERROR_INSUFFICIENT_BUFFER && outSize > 0) {
                        dst.resize(static_cast<size_t>(outSize));
                        if (api.pCompress(h, src, static_cast<SIZE_T>(srcSize), dst.data(), outSize, &outSize)) {
                            dst.resize(static_cast<size_t>(outSize));
                            ok = true;
                        }
                        else {
                            SS_LOG_LAST_ERROR(L"CompressionUtils", L"Compress try again failed");
                        }
                    }
                    else if (err == ERROR_INSUFFICIENT_BUFFER) {
                        SIZE_T tryCap = cap * 2;
                        for (int rounds = 0; rounds < 6; ++rounds) {
                            dst.resize(static_cast<size_t>(tryCap));
                            if (api.pCompress(h, src, static_cast<SIZE_T>(srcSize), dst.data(), tryCap, &outSize)) {
                                dst.resize(static_cast<size_t>(outSize));
                                ok = true;
                                break;
                            }
                            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                                SS_LOG_LAST_ERROR(L"CompressionUtils", L"Compress Failed");
                                break;
                            }
                            tryCap = (outSize > tryCap) ? outSize : (tryCap * 2);
                        }
                        if (!ok) SS_LOG_ERROR(L"CompressionUtils", L"Compress Failed againly");
                    }
                    else {
                        SS_LOG_LAST_ERROR(L"CompressionUtils", L"Compress Failed");
                    }
                }

                if (!api.pCloseCompressor(h)) {
                    SS_LOG_LAST_ERROR(L"CompressionUtils", L"CloseCompressor Failed");
                }
                if (!ok) dst.clear();
                return ok;
            }

            //Decompress
            static bool DecompressCore(DWORD alg, const void* src, size_t srcSize, std::vector<uint8_t>& dst, size_t expectedSize) noexcept {
                dst.clear();
				if (srcSize == 0) { // empty input -> empty output
                    return true;
                }

                const auto& api = GetApi();
                if (!api.valid()) return false;

                DECOMPRESSOR_HANDLE h = nullptr;
                if (!api.pCreateDecompressor(alg, nullptr, &h) || !h) {
                    SS_LOG_LAST_ERROR(L"CompressionUtils", L"CreateDecompressor Failed (alg=%lu)", alg);
                    return false;
                }

                bool ok = false;
                SIZE_T outSize = 0;

                // start conservative if its unknown : 4x source + 64KB
                SIZE_T cap = expectedSize ? static_cast<SIZE_T>(expectedSize)
                    : static_cast<SIZE_T>(srcSize * 4ull + 65536ull);
                if (cap < 65536) cap = 65536;
                dst.resize(static_cast<size_t>(cap));

                if (api.pDecompress(h, src, static_cast<SIZE_T>(srcSize), dst.data(), cap, &outSize)) {
                    dst.resize(static_cast<size_t>(outSize));
                    ok = true;
                }
                else {
                    DWORD err = GetLastError();
                    if (err == ERROR_INSUFFICIENT_BUFFER && outSize > 0) {
                        dst.resize(static_cast<size_t>(outSize));
                        if (api.pDecompress(h, src, static_cast<SIZE_T>(srcSize), dst.data(), outSize, &outSize)) {
                            dst.resize(static_cast<size_t>(outSize));
                            ok = true;
                        }
                        else {
                            SS_LOG_LAST_ERROR(L"CompressionUtils", L"Decompress Failed againly");
                        }
                    }
                    else if (err == ERROR_INSUFFICIENT_BUFFER) {
                        SIZE_T tryCap = cap * 2;
                        for (int rounds = 0; rounds < 7; ++rounds) {
                            if (tryCap > (SIZE_T(1) << 31)) { // 2GB security
                                SS_LOG_ERROR(L"CompressionUtils", L"Decompress output way too big, cancelling...");
                                break;
                            }
                            dst.resize(static_cast<size_t>(tryCap));
                            if (api.pDecompress(h, src, static_cast<SIZE_T>(srcSize), dst.data(), tryCap, &outSize)) {
                                dst.resize(static_cast<size_t>(outSize));
                                ok = true;
                                break;
                            }
                            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                                SS_LOG_LAST_ERROR(L"CompressionUtils", L"Decompress Failed");
                                break;
                            }
                            tryCap = (outSize > tryCap) ? outSize : (tryCap * 2);
                        }
                        if (!ok) SS_LOG_ERROR(L"CompressionUtils", L"Decompress failed againly");
                    }
                    else {
                        SS_LOG_LAST_ERROR(L"CompressionUtils", L"Decompress failed");
                    }
                }

                if (!api.pCloseDecompressor(h)) {
                    SS_LOG_LAST_ERROR(L"CompressionUtils", L"CloseDecompressor failed");
                }
                if (!ok) dst.clear();
                return ok;
            }

            bool CompressBuffer(Algorithm alg, const void* src, size_t srcSize, std::vector<uint8_t>& dst) noexcept {
                return CompressCore(ToWinAlg(alg), src, srcSize, dst);
            }

            bool DecompressBuffer(Algorithm alg, const void* src, size_t srcSize, std::vector<uint8_t>& dst, size_t expectedUncompressedSize) noexcept {
                return DecompressCore(ToWinAlg(alg), src, srcSize, dst, expectedUncompressedSize);
            }

            // RAII Compressor
            bool Compressor::open(Algorithm alg) noexcept {
                close();
                const auto& api = GetApi();
                if (!api.valid()) return false;
                COMPRESSOR_HANDLE h = nullptr;
                if (!api.pCreateCompressor(ToWinAlg(alg), nullptr, &h) || !h) {
                    SS_LOG_LAST_ERROR(L"CompressionUtils", L"CreateCompressor failed (alg=%lu)", ToWinAlg(alg));
                    return false;
                }
                m_handle = h;
                m_alg = alg;
                return true;
            }

            void Compressor::close() noexcept {
                if (!m_handle) return;
                const auto& api = GetApi();
                if (api.pCloseCompressor) {
                    if (!api.pCloseCompressor(static_cast<COMPRESSOR_HANDLE>(m_handle))) {
                        SS_LOG_LAST_ERROR(L"CompressionUtils", L"CloseCompressor failed");
                    }
                }
                m_handle = nullptr;
            }

            bool Compressor::compress(const void* src, size_t srcSize, std::vector<uint8_t>& dst) const noexcept {
                dst.clear();
                if (!m_handle) return false;
                if (srcSize == 0) return true;

                const auto& api = GetApi();
                SIZE_T outSize = 0;

                SIZE_T cap = static_cast<SIZE_T>(srcSize + (srcSize / 16) + 65536ull);
                if (cap < 64) cap = 64;
                dst.resize(static_cast<size_t>(cap));

                if (api.pCompress(static_cast<COMPRESSOR_HANDLE>(m_handle), src, static_cast<SIZE_T>(srcSize), dst.data(), cap, &outSize)) {
                    dst.resize(static_cast<size_t>(outSize));
                    return true;
                }

                DWORD err = GetLastError();
                if (err == ERROR_INSUFFICIENT_BUFFER && outSize > 0) {
                    dst.resize(static_cast<size_t>(outSize));
                    if (api.pCompress(static_cast<COMPRESSOR_HANDLE>(m_handle), src, static_cast<SIZE_T>(srcSize), dst.data(), outSize, &outSize)) {
                        dst.resize(static_cast<size_t>(outSize));
                        return true;
                    }
                    SS_LOG_LAST_ERROR(L"CompressionUtils", L"Compress failed againly");
                    dst.clear();
                    return false;
                }

                if (err == ERROR_INSUFFICIENT_BUFFER) {
                    SIZE_T tryCap = cap * 2;
                    for (int rounds = 0; rounds < 6; ++rounds) {
                        dst.resize(static_cast<size_t>(tryCap));
                        if (api.pCompress(static_cast<COMPRESSOR_HANDLE>(m_handle), src, static_cast<SIZE_T>(srcSize), dst.data(), tryCap, &outSize)) {
                            dst.resize(static_cast<size_t>(outSize));
                            return true;
                        }
                        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                            SS_LOG_LAST_ERROR(L"CompressionUtils", L"Compress failed");
                            break;
                        }
                        tryCap = (outSize > tryCap) ? outSize : (tryCap * 2);
                    }
                    SS_LOG_ERROR(L"CompressionUtils", L"Compress  failed againly ");
                    dst.clear();
                    return false;
                }

                SS_LOG_LAST_ERROR(L"CompressionUtils", L"Compress failed");
                dst.clear();
                return false;
            }


            // RAII Decompressor
            bool Decompressor::open(Algorithm alg) noexcept {
                close();
                const auto& api = GetApi();
                if (!api.valid()) return false;
                DECOMPRESSOR_HANDLE h = nullptr;
                if (!api.pCreateDecompressor(ToWinAlg(alg), nullptr, &h) || !h) {
                    SS_LOG_LAST_ERROR(L"CompressionUtils", L"CreateDecompressor failed (alg=%lu)", ToWinAlg(alg));
                    return false;
                }
                m_handle = h;
                m_alg = alg;
                return true;
            }

            void Decompressor::close() noexcept {
                if (!m_handle) return;
                const auto& api = GetApi();
                if (api.pCloseDecompressor) {
                    if (!api.pCloseDecompressor(static_cast<DECOMPRESSOR_HANDLE>(m_handle))) {
                        SS_LOG_LAST_ERROR(L"CompressionUtils", L"CloseDecompressor failed");
                    }
                }
                m_handle = nullptr;
            }

            bool Decompressor::decompress(const void* src, size_t srcSize, std::vector<uint8_t>& dst, size_t expectedUncompressedSize) const noexcept {
                dst.clear();
                if (!m_handle) return false;
                if (srcSize == 0) return true;

                const auto& api = GetApi();
                SIZE_T outSize = 0;

                SIZE_T cap = expectedUncompressedSize ? static_cast<SIZE_T>(expectedUncompressedSize)
                    : static_cast<SIZE_T>(srcSize * 4ull + 65536ull);
                if (cap < 65536) cap = 65536;
                dst.resize(static_cast<size_t>(cap));

                if (api.pDecompress(static_cast<DECOMPRESSOR_HANDLE>(m_handle), src, static_cast<SIZE_T>(srcSize), dst.data(), cap, &outSize)) {
                    dst.resize(static_cast<size_t>(outSize));
                    return true;
                }

                DWORD err = GetLastError();
                if (err == ERROR_INSUFFICIENT_BUFFER && outSize > 0) {
                    dst.resize(static_cast<size_t>(outSize));
                    if (api.pDecompress(static_cast<DECOMPRESSOR_HANDLE>(m_handle), src, static_cast<SIZE_T>(srcSize), dst.data(), outSize, &outSize)) {
                        dst.resize(static_cast<size_t>(outSize));
                        return true;
                    }
                    SS_LOG_LAST_ERROR(L"CompressionUtils", L"Decompress failed againly");
                    dst.clear();
                    return false;
                }

                if (err == ERROR_INSUFFICIENT_BUFFER) {
                    SIZE_T tryCap = cap * 2;
                    for (int rounds = 0; rounds < 7; ++rounds) {
                        if (tryCap > (SIZE_T(1) << 31)) {
                            SS_LOG_ERROR(L"CompressionUtils", L"Decompress output way too big, cancelling...");
                            break;
                        }
                        dst.resize(static_cast<size_t>(tryCap));
                        if (api.pDecompress(static_cast<DECOMPRESSOR_HANDLE>(m_handle), src, static_cast<SIZE_T>(srcSize), dst.data(), tryCap, &outSize)) {
                            dst.resize(static_cast<size_t>(outSize));
                            return true;
                        }
                        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                            SS_LOG_LAST_ERROR(L"CompressionUtils", L"Decompress failed");
                            break;
                        }
                        tryCap = (outSize > tryCap) ? outSize : (tryCap * 2);
                    }
                    SS_LOG_ERROR(L"CompressionUtils", L"Decompress tekrarlarýnda failed");
                    dst.clear();
                    return false;
                }

                SS_LOG_LAST_ERROR(L"CompressionUtils", L"Decompress failed");
                dst.clear();
                return false;
            }


            void Compressor::moveFrom(Compressor&& other) noexcept {
                m_handle = other.m_handle; other.m_handle = nullptr;
                m_alg = other.m_alg;
            }

            void Decompressor::moveFrom(Decompressor&& other) noexcept {
                m_handle = other.m_handle; other.m_handle = nullptr;
                m_alg = other.m_alg;
            }




		}// namespace CompressionUtils
	}// namespace Utils
}// namespace ShadowStrike
