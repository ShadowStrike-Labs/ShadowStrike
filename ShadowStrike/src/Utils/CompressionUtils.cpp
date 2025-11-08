#include "CompressionUtils.hpp"


#include <mutex>
#include <atomic>
#ifdef _WIN32
#include <windows.h>
#endif

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

#ifdef _WIN32
            // SEH-protected wrappers to avoid process crash on malformed/corrupted data
            static inline BOOL SafeDecompress(const ApiTable& api, DECOMPRESSOR_HANDLE h,
                                              const void* src, SIZE_T srcSize,
                                              void* dst, SIZE_T dstCap,
                                              SIZE_T* outSize, DWORD& lastErr) noexcept {
                BOOL ok = FALSE;
                lastErr = ERROR_SUCCESS;
                __try {
                    ok = api.pDecompress(h, src, srcSize, dst, dstCap, outSize);
                    if (!ok) lastErr = GetLastError();
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    lastErr = ERROR_INVALID_DATA; // map AV to invalid data
                    ok = FALSE;
                }
                return ok;
            }

            static inline BOOL SafeCompress(const ApiTable& api, COMPRESSOR_HANDLE h,
                                            const void* src, SIZE_T srcSize,
                                            void* dst, SIZE_T dstCap,
                                            SIZE_T* outSize, DWORD& lastErr) noexcept {
                BOOL ok = FALSE;
                lastErr = ERROR_SUCCESS;
                __try {
                    ok = api.pCompress(h, src, srcSize, dst, dstCap, outSize);
                    if (!ok) lastErr = GetLastError();
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    lastErr = ERROR_INVALID_DATA;
                    ok = FALSE;
                }
                return ok;
            }
#endif

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
                
                if (!src && srcSize > 0) { return false; }
                if (srcSize == 0) { return true; }
                if (srcSize > MAX_COMPRESSED_SIZE) { return false; }
                if (srcSize > ULONG_MAX) { return false; }

                const auto& api = GetApi();
                if (!api.valid()) { return false; }

                COMPRESSOR_HANDLE h = nullptr;
                if (!api.pCreateCompressor(alg, nullptr, &h) || !h) {
                    SS_LOG_LAST_ERROR(L"CompressionUtils", L"CreateCompressor Failed (alg=%lu)", alg);
                    return false;
                }
                struct CompressorGuard { COMPRESSOR_HANDLE handle; const ApiTable& api; ~CompressorGuard(){ if(handle&&api.pCloseCompressor) api.pCloseCompressor(handle);} } guard{h, api};

                SIZE_T required = 0; BYTE scratch[64] = {};
#ifdef _WIN32
                DWORD err = ERROR_SUCCESS;
                if (SafeCompress(api, h, src, static_cast<SIZE_T>(srcSize), scratch, sizeof(scratch), &required, err)) {
#else
                if (api.pCompress(h, src, static_cast<SIZE_T>(srcSize), scratch, sizeof(scratch), &required)) {
                    DWORD err = GetLastError();
#endif
                    if (required <= sizeof(scratch)) { dst.assign(scratch, scratch + required); return true; }
                    return false;
                }
#ifndef _WIN32
                DWORD err = GetLastError();
#endif
                if (err != ERROR_INSUFFICIENT_BUFFER || required == 0) {
                    return false;
                }

                try { dst.resize(static_cast<size_t>(required)); }
                catch (...) { return false; }

                SIZE_T outSize = 0;
#ifdef _WIN32
                if (!SafeCompress(api, h, src, static_cast<SIZE_T>(srcSize), dst.data(), required, &outSize, err)) {
#else
                if (!api.pCompress(h, src, static_cast<SIZE_T>(srcSize), dst.data(), required, &outSize)) {
                    DWORD err2 = GetLastError(); (void)err2;
#endif
                    dst.clear(); return false; }
                if (outSize > required) { dst.clear(); return false; }
                dst.resize(static_cast<size_t>(outSize));
                return true;
            }

            //Decompress
            static bool DecompressCore(DWORD alg, const void* src, size_t srcSize, std::vector<uint8_t>& dst, size_t expectedSize) noexcept {
                dst.clear();
                if (!src && srcSize > 0) { return false; }
                if (srcSize == 0) { return true; }
                if (srcSize > MAX_COMPRESSED_SIZE) { return false; }
                if (expectedSize > MAX_DECOMPRESSED_SIZE) { return false; }
                if (srcSize > ULONG_MAX) { return false; }

                const auto& api = GetApi();
                if (!api.valid()) { return false; }

                DECOMPRESSOR_HANDLE h = nullptr;
                if (!api.pCreateDecompressor(alg, nullptr, &h) || !h) {
                    SS_LOG_LAST_ERROR(L"CompressionUtils", L"CreateDecompressor Failed (alg=%lu)", alg);
                    return false; }
                struct DecompressorGuard { DECOMPRESSOR_HANDLE handle; const ApiTable& api; ~DecompressorGuard(){ if(handle&&api.pCloseDecompressor) api.pCloseDecompressor(handle);} } guard{h, api};

                SIZE_T required = 0; BYTE scratch[64] = {};
#ifdef _WIN32
                DWORD err = ERROR_SUCCESS;
                if (SafeDecompress(api, h, src, static_cast<SIZE_T>(srcSize), scratch, sizeof(scratch), &required, err)) {
#else
                if (api.pDecompress(h, src, static_cast<SIZE_T>(srcSize), scratch, sizeof(scratch), &required)) {
                    DWORD err = GetLastError();
#endif
                    if (required <= sizeof(scratch)) { dst.assign(scratch, scratch + required); return true; }
                    return false;
                }
#ifndef _WIN32
                DWORD err = GetLastError();
#endif
                if (err != ERROR_INSUFFICIENT_BUFFER || required == 0) {
                    return false;
                }
                if (required > MAX_DECOMPRESSED_SIZE) { return false; }
                if (expectedSize > 0 && required != expectedSize) { return false; }

                try { dst.resize(static_cast<size_t>(required)); }
                catch (...) { return false; }

                SIZE_T outSize = 0;
#ifdef _WIN32
                if (!SafeDecompress(api, h, src, static_cast<SIZE_T>(srcSize), dst.data(), required, &outSize, err)) {
#else
                if (!api.pDecompress(h, src, static_cast<SIZE_T>(srcSize), dst.data(), required, &outSize)) {
                    DWORD err2 = GetLastError(); (void)err2;
#endif
                    dst.clear(); return false; }
                if (outSize != required) { dst.resize(static_cast<size_t>(outSize)); }
                return true;
            }

            bool CompressBuffer(Algorithm alg, const void* src, size_t srcSize, std::vector<uint8_t>& dst) noexcept {
                //  Validate input before passing to core
                if (!src && srcSize > 0) {
                    // avoid logging here to ensure no side-effects in error path
                    return false;
                }
                return CompressCore(ToWinAlg(alg), src, srcSize, dst);
            }

            bool DecompressBuffer(Algorithm alg, const void* src, size_t srcSize, std::vector<uint8_t>& dst, size_t expectedUncompressedSize) noexcept {
                // Validate input before passing to core
                if (!src && srcSize > 0) {
                    // avoid logging here to ensure no side-effects in error path
                    return false;
                }
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
                
                // Validate input
                if (!src && srcSize > 0) {
                    return false;
                }
                
                if (srcSize == 0) return true;

                // Enforce size limits
                if (srcSize > MAX_COMPRESSED_SIZE) {
                    return false;
                }

                //  Validate ULONG compatibility
                if (srcSize > ULONG_MAX) {
                    return false;
                }

                const auto& api = GetApi();

                // Query size then allocate
                SIZE_T required = 0; BYTE scratch[64] = {};
#ifdef _WIN32
                DWORD err = ERROR_SUCCESS;
                if (SafeCompress(api, static_cast<COMPRESSOR_HANDLE>(m_handle), src, static_cast<SIZE_T>(srcSize), scratch, sizeof(scratch), &required, err)) {
#else
                if (api.pCompress(static_cast<COMPRESSOR_HANDLE>(m_handle), src, static_cast<SIZE_T>(srcSize), scratch, sizeof(scratch), &required)) {
                    DWORD err = GetLastError();
#endif
                    if (required <= sizeof(scratch)) { dst.assign(scratch, scratch + required); return true; }
                    return false;
                }
#ifndef _WIN32
                DWORD err = GetLastError();
#endif
                if (err != ERROR_INSUFFICIENT_BUFFER || required == 0) {
                    return false;
                }
                if (required > MAX_DECOMPRESSED_SIZE) return false;

                try { dst.resize(static_cast<size_t>(required)); } catch (...) { return false; }

                SIZE_T outSize = 0;
#ifdef _WIN32
                if (!SafeCompress(api, static_cast<COMPRESSOR_HANDLE>(m_handle), src, static_cast<SIZE_T>(srcSize), dst.data(), required, &outSize, err)) {
#else
                if (!api.pCompress(static_cast<COMPRESSOR_HANDLE>(m_handle), src, static_cast<SIZE_T>(srcSize), dst.data(), required, &outSize)) {
                    DWORD err2 = GetLastError(); (void)err2;
#endif
                    dst.clear(); return false; }
                if (outSize > required) { dst.clear(); return false; }
                dst.resize(static_cast<size_t>(outSize));
                return true;
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
                
                //  Validate input
                if (!src && srcSize > 0) {
                    return false;
                }
                
                if (srcSize == 0) return true;

                // Enforce size limits
                if (srcSize > MAX_COMPRESSED_SIZE) {
                    return false;
                }

                // Validate expectedSize
                if (expectedUncompressedSize > MAX_DECOMPRESSED_SIZE) {
                    return false;
                }

                //  ULONG compatibility check
                if (srcSize > ULONG_MAX) {
                    return false;
                }

                const auto& api = GetApi();

                // Query size then allocate
                SIZE_T required = 0; BYTE scratch[64] = {};
#ifdef _WIN32
                DWORD err = ERROR_SUCCESS;
                if (SafeDecompress(api, static_cast<DECOMPRESSOR_HANDLE>(m_handle), src, static_cast<SIZE_T>(srcSize), scratch, sizeof(scratch), &required, err)) {
#else
                if (api.pDecompress(static_cast<DECOMPRESSOR_HANDLE>(m_handle), src, static_cast<SIZE_T>(srcSize), scratch, sizeof(scratch), &required)) {
                    DWORD err = GetLastError();
#endif
                    if (required <= sizeof(scratch)) { dst.assign(scratch, scratch + required); return true; }
                    return false;
                }
#ifndef _WIN32
                DWORD err = GetLastError();
#endif
                if (err != ERROR_INSUFFICIENT_BUFFER || required == 0) {
                    return false;
                }
                if (required > MAX_DECOMPRESSED_SIZE) return false;
                if (expectedUncompressedSize > 0 && required != expectedUncompressedSize) return false;

                try { dst.resize(static_cast<size_t>(required)); } catch (...) { return false; }
                SIZE_T outSize = 0;
#ifdef _WIN32
                if (!SafeDecompress(api, static_cast<DECOMPRESSOR_HANDLE>(m_handle), src, static_cast<SIZE_T>(srcSize), dst.data(), required, &outSize, err)) {
#else
                if (!api.pDecompress(static_cast<DECOMPRESSOR_HANDLE>(m_handle), src, static_cast<SIZE_T>(srcSize), dst.data(), required, &outSize)) {
                    DWORD err2 = GetLastError(); (void)err2;
#endif
                    dst.clear(); return false; }
                if (outSize != required) { dst.resize(static_cast<size_t>(outSize)); }
                return true;
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
