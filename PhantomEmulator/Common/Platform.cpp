/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Platform primitives (Windows implementation)
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#include "Platform.hpp"

#ifdef PHANTOM_WINDOWS

#include <windows.h>
#include <profileapi.h>

namespace Phantom {
namespace Platform {

// ---------------------------------------------------------------------------
// High-resolution timing backed by QueryPerformanceCounter.  The performance
// counter frequency is queried once at process start (per MSDN it is fixed
// at system boot) and cached for lock-free access from the emulator hot
// path.  QueryPerformanceCounter never fails on systems running Windows XP
// or later, so we can safely ignore the BOOL return value after the initial
// probe.
// ---------------------------------------------------------------------------

namespace {

[[nodiscard]] uint64_t ProbeFrequency() noexcept {
    LARGE_INTEGER freq{};
    if (!::QueryPerformanceFrequency(&freq) || freq.QuadPart <= 0) {
        // Fallback: report 1 tick/second so callers can still compute
        // non-negative elapsed durations without dividing by zero.
        return 1;
    }
    return static_cast<uint64_t>(freq.QuadPart);
}

const uint64_t kCachedFrequency = ProbeFrequency();

} // anonymous namespace

uint64_t GetHighResolutionTicks() noexcept {
    LARGE_INTEGER counter{};
    ::QueryPerformanceCounter(&counter);
    return static_cast<uint64_t>(counter.QuadPart);
}

uint64_t GetTickFrequency() noexcept {
    return kCachedFrequency;
}

} // namespace Platform
} // namespace Phantom

#endif // PHANTOM_WINDOWS
