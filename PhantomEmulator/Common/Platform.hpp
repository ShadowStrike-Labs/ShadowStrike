/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#pragma once

#include "Types.hpp"
#include <cstdint>
#include <cstring>
#include <memory>

// Platform detection
#if defined(_WIN32) || defined(_WIN64)
    #define PHANTOM_WINDOWS 1
#elif defined(__linux__)
    #define PHANTOM_LINUX 1
#else
    #error "Unsupported platform"
#endif

#ifdef PHANTOM_WINDOWS
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #ifndef NOMINMAX
        #define NOMINMAX
    #endif
#endif

namespace Phantom {
namespace Platform {

// ============================================================================
// Host Memory Allocation (for guest address space backing)
// ============================================================================

[[nodiscard]] inline uint8_t* AllocatePages(uint32_t pageCount) noexcept {
    if (pageCount == 0 || pageCount > kMaxPages) return nullptr;
    const size_t bytes = static_cast<size_t>(pageCount) * kPageSize;
    auto* ptr = static_cast<uint8_t*>(std::calloc(pageCount, kPageSize));
    return ptr;
}

inline void FreePages(uint8_t* ptr, [[maybe_unused]] uint32_t pageCount) noexcept {
    std::free(ptr);
}

[[nodiscard]] inline uint8_t* AllocatePage() noexcept {
    return AllocatePages(1);
}

inline void FreePage(uint8_t* ptr) noexcept {
    FreePages(ptr, 1);
}

// ============================================================================
// Safe Memory Operations
// ============================================================================

inline void SecureZero(void* ptr, size_t size) noexcept {
    if (ptr && size > 0) {
        volatile uint8_t* vp = static_cast<volatile uint8_t*>(ptr);
        while (size--) { *vp++ = 0; }
    }
}

[[nodiscard]] inline bool SafeMemcpy(void* dst, size_t dstSize,
                                      const void* src, size_t count) noexcept {
    if (!dst || !src || count == 0) return false;
    if (count > dstSize) return false;
    std::memcpy(dst, src, count);
    return true;
}

// ============================================================================
// High-Resolution Timing (for emulation wall-clock limits)
// ============================================================================

#ifdef PHANTOM_WINDOWS

[[nodiscard]] uint64_t GetHighResolutionTicks() noexcept;
[[nodiscard]] uint64_t GetTickFrequency() noexcept;

#else

[[nodiscard]] inline uint64_t GetHighResolutionTicks() noexcept {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1'000'000'000ULL + ts.tv_nsec;
}

[[nodiscard]] inline uint64_t GetTickFrequency() noexcept {
    return 1'000'000'000ULL; // nanoseconds
}

#endif

// ============================================================================
// Compiler Intrinsics
// ============================================================================

#if defined(_MSC_VER)
    #include <intrin.h>
    #define PHANTOM_BSWAP16(x) _byteswap_ushort(x)
    #define PHANTOM_BSWAP32(x) _byteswap_ulong(x)
    #define PHANTOM_BSWAP64(x) _byteswap_uint64(x)
    #define PHANTOM_POPCOUNT32(x) __popcnt(x)
    #define PHANTOM_POPCOUNT64(x) __popcnt64(x)
    #define PHANTOM_BSF32(result, value) _BitScanForward(result, value)
    #define PHANTOM_BSR32(result, value) _BitScanReverse(result, value)
    #define PHANTOM_BSF64(result, value) _BitScanForward64(result, value)
    #define PHANTOM_BSR64(result, value) _BitScanReverse64(result, value)
    #define PHANTOM_ROTL32(x, n) _rotl(x, n)
    #define PHANTOM_ROTR32(x, n) _rotr(x, n)
    #define PHANTOM_ROTL64(x, n) _rotl64(x, n)
    #define PHANTOM_ROTR64(x, n) _rotr64(x, n)
    #define PHANTOM_UNLIKELY(x) (x)
    #define PHANTOM_LIKELY(x)   (x)
    #define PHANTOM_FORCEINLINE __forceinline
    #define PHANTOM_NOINLINE    __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
    #define PHANTOM_BSWAP16(x) __builtin_bswap16(x)
    #define PHANTOM_BSWAP32(x) __builtin_bswap32(x)
    #define PHANTOM_BSWAP64(x) __builtin_bswap64(x)
    #define PHANTOM_POPCOUNT32(x) __builtin_popcount(x)
    #define PHANTOM_POPCOUNT64(x) __builtin_popcountll(x)
    #define PHANTOM_UNLIKELY(x) __builtin_expect(!!(x), 0)
    #define PHANTOM_LIKELY(x)   __builtin_expect(!!(x), 1)
    #define PHANTOM_FORCEINLINE __attribute__((always_inline)) inline
    #define PHANTOM_NOINLINE    __attribute__((noinline))
#endif

} // namespace Platform
} // namespace Phantom
