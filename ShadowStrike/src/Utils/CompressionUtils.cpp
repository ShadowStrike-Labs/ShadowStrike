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
                
                // ? FIX: Validate input parameters
                if (!src && srcSize > 0) {
                    SS_LOG_ERROR(L"CompressionUtils", L"CompressCore: nullptr with non-zero size");
                    return false;
                }
                
                if (srcSize == 0) { //empty input -> empty output
                    return true;
                }

                // ? FIX: Enforce maximum input size
                if (srcSize > MAX_COMPRESSED_SIZE) {
                    SS_LOG_ERROR(L"CompressionUtils", L"CompressCore: Input size %zu exceeds maximum %zu", 
                                 srcSize, MAX_COMPRESSED_SIZE);
                    return false;
                }

                // ? FIX: Validate size fits in ULONG (Windows API limitation)
                if (srcSize > ULONG_MAX) {
                    SS_LOG_ERROR(L"CompressionUtils", L"CompressCore: Size %zu exceeds ULONG_MAX", srcSize);
                    return false;
                }

                const auto& api = GetApi();
                if (!api.valid()) return false;

                COMPRESSOR_HANDLE h = nullptr;
                if (!api.pCreateCompressor(alg, nullptr, &h) || !h) {
                    SS_LOG_LAST_ERROR(L"CompressionUtils", L"CreateCompressor Failed (alg=%lu)", alg);
                    return false;
                }

                // ? FIX: RAII guard for handle cleanup
                struct CompressorGuard {
                    COMPRESSOR_HANDLE handle;
                    const ApiTable& api;
                    ~CompressorGuard() {
                        if (handle && api.pCloseCompressor) {
                            if (!api.pCloseCompressor(handle)) {
                                SS_LOG_LAST_ERROR(L"CompressionUtils", L"CloseCompressor Failed");
                            }
                        }
                    }
                } guard{h, api};

                bool ok = false;
                SIZE_T outSize = 0;

                // ? FIX: Safe capacity calculation with overflow check
                SIZE_T cap = 0;
                if (srcSize > SIZE_MAX - 65536 || srcSize > (SIZE_MAX - 65536) * 16 / 17) {
                    cap = srcSize + 65536;
                } else {
                    cap = static_cast<SIZE_T>(srcSize + (srcSize / 16) + 65536ull);
                }
                
                if (cap < MIN_BUFFER_SIZE) cap = MIN_BUFFER_SIZE;
                if (cap > MAX_DECOMPRESSED_SIZE) cap = MAX_DECOMPRESSED_SIZE;

                try {
                    dst.resize(static_cast<size_t>(cap));
                } catch (const std::bad_alloc&) {
                    SS_LOG_ERROR(L"CompressionUtils", L"CompressCore: Failed to allocate %zu bytes", cap);
                    return false;
                }

                if (api.pCompress(h, src, static_cast<SIZE_T>(srcSize), dst.data(), cap, &outSize)) {
                    dst.resize(static_cast<size_t>(outSize));
                    ok = true;
                }
                else {
                    DWORD err = GetLastError();
                    if (err == ERROR_INSUFFICIENT_BUFFER && outSize > 0) {
                        // ? FIX: Validate outSize before retry
                        if (outSize > MAX_DECOMPRESSED_SIZE) {
                            SS_LOG_ERROR(L"CompressionUtils", L"CompressCore: Requested size %zu exceeds maximum", outSize);
                            return false;
                        }
                        
                        try {
                            dst.resize(static_cast<size_t>(outSize));
                        } catch (const std::bad_alloc&) {
                            SS_LOG_ERROR(L"CompressionUtils", L"CompressCore: Failed to allocate %zu bytes", outSize);
                            return false;
                        }
                        
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
                            // ? FIX: Prevent exponential growth beyond limits
                            if (tryCap > MAX_DECOMPRESSED_SIZE) {
                                SS_LOG_ERROR(L"CompressionUtils", L"CompressCore: Buffer size exceeds maximum");
                                break;
                            }
                            
                            try {
                                dst.resize(static_cast<size_t>(tryCap));
                            } catch (const std::bad_alloc&) {
                                SS_LOG_ERROR(L"CompressionUtils", L"CompressCore: Failed to allocate %zu bytes", tryCap);
                                break;
                            }
                            
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

                if (!ok) dst.clear();
                return ok;
            }

            //Decompress
            static bool DecompressCore(DWORD alg, const void* src, size_t srcSize, std::vector<uint8_t>& dst, size_t expectedSize) noexcept {
                dst.clear();
    
                // ? FIX: Validate input parameters
                if (!src && srcSize > 0) {
                    SS_LOG_ERROR(L"CompressionUtils", L"DecompressCore: nullptr with non-zero size");
                    return false;
                }
                
                if (srcSize == 0) { // empty input -> empty output
                    return true;
                }

                // ? FIX: Enforce maximum compressed input size
                if (srcSize > MAX_COMPRESSED_SIZE) {
                    SS_LOG_ERROR(L"CompressionUtils", L"DecompressCore: Compressed size %zu exceeds maximum %zu", 
                                 srcSize, MAX_COMPRESSED_SIZE);
                    return false;
                }

                // ? FIX: Validate expectedSize is within safe bounds
                if (expectedSize > MAX_DECOMPRESSED_SIZE) {
                    SS_LOG_ERROR(L"CompressionUtils", L"DecompressCore: Expected size %zu exceeds maximum %zu", 
                                 expectedSize, MAX_DECOMPRESSED_SIZE);
                    return false;
                }

                // ? FIX: Validate compression ratio (decompression bomb protection)
                if (expectedSize > 0 && srcSize > 0) {
                    size_t ratio = expectedSize / srcSize;
                    if (ratio > MAX_COMPRESSION_RATIO) {
                        SS_LOG_ERROR(L"CompressionUtils", L"DecompressCore: Compression ratio %zu:1 exceeds maximum %zu:1", 
                                     ratio, MAX_COMPRESSION_RATIO);
                        return false;
                    }
                }

                // ? FIX: Validate size fits in ULONG
                if (srcSize > ULONG_MAX) {
                    SS_LOG_ERROR(L"CompressionUtils", L"DecompressCore: Size %zu exceeds ULONG_MAX", srcSize);
                    return false;
                }

                const auto& api = GetApi();
                if (!api.valid()) return false;

                DECOMPRESSOR_HANDLE h = nullptr;
                if (!api.pCreateDecompressor(alg, nullptr, &h) || !h) {
                    SS_LOG_LAST_ERROR(L"CompressionUtils", L"CreateDecompressor Failed (alg=%lu)", alg);
                    return false;
                }

                // ? FIX: RAII guard for handle cleanup
                struct DecompressorGuard {
                    DECOMPRESSOR_HANDLE handle;
                    const ApiTable& api;
                    ~DecompressorGuard() {
                        if (handle && api.pCloseDecompressor) {
                            if (!api.pCloseDecompressor(handle)) {
                                SS_LOG_LAST_ERROR(L"CompressionUtils", L"CloseDecompressor failed");
                            }
                        }
                    }
                } guard{h, api};

                bool ok = false;
                SIZE_T outSize = 0;

                // ? FIX: Safe capacity calculation
                SIZE_T cap = 0;
                if (expectedSize > 0) {
                    cap = static_cast<SIZE_T>(expectedSize);
                } else {
                    if (srcSize > (SIZE_MAX - 65536) / 4) {
                        cap = SIZE_MAX;
                    } else {
                        cap = static_cast<SIZE_T>(srcSize * 4ull + 65536ull);
                    }
                }
                
                if (cap < 65536) cap = 65536;
                if (cap > MAX_DECOMPRESSED_SIZE) cap = MAX_DECOMPRESSED_SIZE;

                try {
                    dst.resize(static_cast<size_t>(cap));
                } catch (const std::bad_alloc&) {
                    SS_LOG_ERROR(L"CompressionUtils", L"DecompressCore: Failed to allocate %zu bytes", cap);
                    return false;
                }

                if (api.pDecompress(h, src, static_cast<SIZE_T>(srcSize), dst.data(), cap, &outSize)) {
                    dst.resize(static_cast<size_t>(outSize));
                    ok = true;
                }
                else {
                    DWORD err = GetLastError();
                    if (err == ERROR_INSUFFICIENT_BUFFER && outSize > 0) {
                        // ? FIX: Validate outSize before retry
                        if (outSize > MAX_DECOMPRESSED_SIZE) {
                            SS_LOG_ERROR(L"CompressionUtils", L"DecompressCore: Requested size %zu exceeds maximum", outSize);
                            return false;
                        }
                        
                        // ? FIX: Additional ratio check
                        if (srcSize > 0 && outSize / srcSize > MAX_COMPRESSION_RATIO) {
                            SS_LOG_ERROR(L"CompressionUtils", L"DecompressCore: Detected potential decompression bomb (ratio %zu:1)", 
                                         outSize / srcSize);
                            return false;
                        }
                        
                        try {
                            dst.resize(static_cast<size_t>(outSize));
                        } catch (const std::bad_alloc&) {
                            SS_LOG_ERROR(L"CompressionUtils", L"DecompressCore: Failed to allocate %zu bytes", outSize);
                            return false;
                        }
                        
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
                            // ? FIX: Lower limit from 2GB to MAX_DECOMPRESSED_SIZE
                            if (tryCap > MAX_DECOMPRESSED_SIZE) {
                                SS_LOG_ERROR(L"CompressionUtils", L"DecompressCore: Buffer size %zu exceeds maximum %zu", 
                                             tryCap, MAX_DECOMPRESSED_SIZE);
                                break;
                            }
                            
                            // ? FIX: Check compression ratio during retry
                            if (srcSize > 0 && tryCap / srcSize > MAX_COMPRESSION_RATIO) {
                                SS_LOG_ERROR(L"CompressionUtils", L"DecompressCore: Detected potential decompression bomb during retry");
                                break;
                            }
                            
                            try {
                                dst.resize(static_cast<size_t>(tryCap));
                            } catch (const std::bad_alloc&) {
                                SS_LOG_ERROR(L"CompressionUtils", L"DecompressCore: Failed to allocate %zu bytes", tryCap);
                                break;
                            }
                            
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

                if (!ok) dst.clear();
                return ok;
            }

            bool CompressBuffer(Algorithm alg, const void* src, size_t srcSize, std::vector<uint8_t>& dst) noexcept {
                // ? FIX: Validate input before passing to core
                if (!src && srcSize > 0) {
                    SS_LOG_ERROR(L"CompressionUtils", L"CompressBuffer: nullptr with non-zero size");
                    return false;
                }
                return CompressCore(ToWinAlg(alg), src, srcSize, dst);
            }

            bool DecompressBuffer(Algorithm alg, const void* src, size_t srcSize, std::vector<uint8_t>& dst, size_t expectedUncompressedSize) noexcept {
                // ? FIX: Validate input before passing to core
                if (!src && srcSize > 0) {
                    SS_LOG_ERROR(L"CompressionUtils", L"DecompressBuffer: nullptr with non-zero size");
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
                
                // ? FIX: Validate input
                if (!src && srcSize > 0) {
                    SS_LOG_ERROR(L"CompressionUtils", L"Compressor::compress: nullptr with non-zero size");
                    return false;
                }
                
                if (srcSize == 0) return true;

                // ? FIX: Enforce size limits
                if (srcSize > MAX_COMPRESSED_SIZE) {
                    SS_LOG_ERROR(L"CompressionUtils", L"Compressor::compress: Size %zu exceeds maximum %zu", 
                                 srcSize, MAX_COMPRESSED_SIZE);
                    return false;
                }

                // ? FIX: Validate ULONG compatibility
                if (srcSize > ULONG_MAX) {
                    SS_LOG_ERROR(L"CompressionUtils", L"Compressor::compress: Size exceeds ULONG_MAX");
                    return false;
                }

                const auto& api = GetApi();
                SIZE_T outSize = 0;

                // ? FIX: Safe capacity calculation
                SIZE_T cap = 0;
                if (srcSize > SIZE_MAX - 65536 || srcSize > (SIZE_MAX - 65536) * 16 / 17) {
                    cap = srcSize + 65536;
                } else {
                    cap = static_cast<SIZE_T>(srcSize + (srcSize / 16) + 65536ull);
                }
                
                if (cap < MIN_BUFFER_SIZE) cap = MIN_BUFFER_SIZE;
                if (cap > MAX_DECOMPRESSED_SIZE) cap = MAX_DECOMPRESSED_SIZE;

                try {
                    dst.resize(static_cast<size_t>(cap));
                } catch (const std::bad_alloc&) {
                    SS_LOG_ERROR(L"CompressionUtils", L"Compressor::compress: Failed to allocate %zu bytes", cap);
                    return false;
                }

                if (api.pCompress(static_cast<COMPRESSOR_HANDLE>(m_handle), src, static_cast<SIZE_T>(srcSize), dst.data(), cap, &outSize)) {
                    dst.resize(static_cast<size_t>(outSize));
                    return true;
                }

                DWORD err = GetLastError();
                if (err == ERROR_INSUFFICIENT_BUFFER && outSize > 0) {
                    // ? FIX: Validate outSize
                    if (outSize > MAX_DECOMPRESSED_SIZE) {
                        SS_LOG_ERROR(L"CompressionUtils", L"Compressor::compress: Requested size exceeds maximum");
                        dst.clear();
                        return false;
                    }
                    
                    try {
                        dst.resize(static_cast<size_t>(outSize));
                    } catch (const std::bad_alloc&) {
                        SS_LOG_ERROR(L"CompressionUtils", L"Compressor::compress: Failed to allocate %zu bytes", outSize);
                        dst.clear();
                        return false;
                    }
                    
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
                        // ? FIX: Enforce limits
                        if (tryCap > MAX_DECOMPRESSED_SIZE) {
                            SS_LOG_ERROR(L"CompressionUtils", L"Compressor::compress: Buffer size exceeds maximum");
                            break;
                        }
                        
                        try {
                            dst.resize(static_cast<size_t>(tryCap));
                        } catch (const std::bad_alloc&) {
                            SS_LOG_ERROR(L"CompressionUtils", L"Compressor::compress: Failed to allocate %zu bytes", tryCap);
                            break;
                        }
                        
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
                
                // ? FIX: Validate input
                if (!src && srcSize > 0) {
                    SS_LOG_ERROR(L"CompressionUtils", L"Decompressor::decompress: nullptr with non-zero size");
                    return false;
                }
                
                if (srcSize == 0) return true;

                // ? FIX: Enforce size limits
                if (srcSize > MAX_COMPRESSED_SIZE) {
                    SS_LOG_ERROR(L"CompressionUtils", L"Decompressor::decompress: Compressed size %zu exceeds maximum %zu", 
                                 srcSize, MAX_COMPRESSED_SIZE);
                    return false;
                }

                // ? FIX: Validate expectedSize
                if (expectedUncompressedSize > MAX_DECOMPRESSED_SIZE) {
                    SS_LOG_ERROR(L"CompressionUtils", L"Decompressor::decompress: Expected size %zu exceeds maximum %zu", 
                                 expectedUncompressedSize, MAX_DECOMPRESSED_SIZE);
                    return false;
                }

                // ? FIX: Compression ratio check
                if (expectedUncompressedSize > 0 && srcSize > 0) {
                    size_t ratio = expectedUncompressedSize / srcSize;
                    if (ratio > MAX_COMPRESSION_RATIO) {
                        SS_LOG_ERROR(L"CompressionUtils", L"Decompressor::decompress: Ratio %zu:1 exceeds maximum %zu:1", 
                                     ratio, MAX_COMPRESSION_RATIO);
                        return false;
                    }
                }

                // ? FIX: ULONG compatibility check
                if (srcSize > ULONG_MAX) {
                    SS_LOG_ERROR(L"CompressionUtils", L"Decompressor::decompress: Size exceeds ULONG_MAX");
                    return false;
                }

                const auto& api = GetApi();
                SIZE_T outSize = 0;

                // ? FIX: Safe capacity calculation
                SIZE_T cap = 0;
                if (expectedUncompressedSize > 0) {
                    cap = static_cast<SIZE_T>(expectedUncompressedSize);
                } else {
                    if (srcSize > (SIZE_MAX - 65536) / 4) {
                        cap = SIZE_MAX;
                    } else {
                        cap = static_cast<SIZE_T>(srcSize * 4ull + 65536ull);
                    }
                }
                
                if (cap < 65536) cap = 65536;
                if (cap > MAX_DECOMPRESSED_SIZE) cap = MAX_DECOMPRESSED_SIZE;

                try {
                    dst.resize(static_cast<size_t>(cap));
                } catch (const std::bad_alloc&) {
                    SS_LOG_ERROR(L"CompressionUtils", L"Decompressor::decompress: Failed to allocate %zu bytes", cap);
                    return false;
                }

                if (api.pDecompress(static_cast<DECOMPRESSOR_HANDLE>(m_handle), src, static_cast<SIZE_T>(srcSize), dst.data(), cap, &outSize)) {
                    dst.resize(static_cast<size_t>(outSize));
                    return true;
                }

                DWORD err = GetLastError();
                if (err == ERROR_INSUFFICIENT_BUFFER && outSize > 0) {
                    // ? FIX: Validate outSize
                    if (outSize > MAX_DECOMPRESSED_SIZE) {
                        SS_LOG_ERROR(L"CompressionUtils", L"Decompressor::decompress: Requested size exceeds maximum");
                        dst.clear();
                        return false;
                    }
                    
                    // ? FIX: Ratio check
                    if (srcSize > 0 && outSize / srcSize > MAX_COMPRESSION_RATIO) {
                        SS_LOG_ERROR(L"CompressionUtils", L"Decompressor::decompress: Detected potential decompression bomb");
                        dst.clear();
                        return false;
                    }
                    
                    try {
                        dst.resize(static_cast<size_t>(outSize));
                    } catch (const std::bad_alloc&) {
                        SS_LOG_ERROR(L"CompressionUtils", L"Decompressor::decompress: Failed to allocate %zu bytes", outSize);
                        dst.clear();
                        return false;
                    }
                    
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
                        // ? FIX: Enforce strict limit
                        if (tryCap > MAX_DECOMPRESSED_SIZE) {
                            SS_LOG_ERROR(L"CompressionUtils", L"Decompressor::decompress: Buffer size %zu exceeds maximum %zu", 
                                         tryCap, MAX_DECOMPRESSED_SIZE);
                            break;
                        }
                        
                        // ? FIX: Ratio check in retry loop
                        if (srcSize > 0 && tryCap / srcSize > MAX_COMPRESSION_RATIO) {
                            SS_LOG_ERROR(L"CompressionUtils", L"Decompressor::decompress: Detected potential decompression bomb during retry");
                            break;
                        }
                        
                        try {
                            dst.resize(static_cast<size_t>(tryCap));
                        } catch (const std::bad_alloc&) {
                            SS_LOG_ERROR(L"CompressionUtils", L"Decompressor::decompress: Failed to allocate %zu bytes", tryCap);
                            break;
                        }
                        
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
