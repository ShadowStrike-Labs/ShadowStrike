/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * TimeAPI.cpp — Kernel32 timing API handlers
 *
 * CRITICAL INVARIANT: All timing functions derive from the same base —
 * the CPU instruction counter. This guarantees that paired timing calls
 * (e.g., two GetTickCounts, or GetTickCount + QPC) produce consistent
 * deltas. Malware commonly uses timing pairs to detect emulation.
 *
 * Timing derivation:
 *   elapsed_tsc   = instructionCount * tscIncrement
 *   elapsed_sec   = elapsed_tsc / fakeTSCFrequency
 *   elapsed_ms    = elapsed_tsc * 1000 / fakeTSCFrequency
 *   qpc_value     = elapsed_tsc * QPCFrequency / fakeTSCFrequency
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "TimeAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"

#include <cstring>

// DESIGN: WriteU64 / Write on guest memory are [[nodiscard]] to expose
// guest-side access violations; here the address has already been
// null-checked and any AV is a guest-side fault the caller must cope with.
// The Win32 BOOL return is driven from the preceding validation. Pragma is
// namespace-scoped; all input-validation guards remain explicit.
#pragma warning(push)
#pragma warning(disable : 4834 6031)

namespace Phantom::WinAPI::Kernel32 {

// ============================================================================
// Timing Constants
// ============================================================================

namespace {

// Default tick count if config.fakeTickCount == 0: ~57 minutes uptime.
// Realistic for an enterprise workstation that booted in the morning.
constexpr uint64_t kDefaultBaseTickCount = 3'456'789;

// QueryPerformanceFrequency: 10 MHz (standard on modern Windows)
constexpr uint64_t kQPCFrequency = 10'000'000;

// Base FILETIME: approximately 2024-06-15 14:30:00 UTC
// (100-nanosecond intervals since 1601-01-01 00:00:00 UTC)
constexpr uint64_t kBaseFileTime = 133'630'218'000'000'000ULL;

// Base time-of-day in milliseconds past midnight (14:30:00.000 UTC)
constexpr uint64_t kBaseTimeMsUTC = (14ULL * 3600 + 30 * 60) * 1000;

// Local time offset: UTC-5 (Eastern Standard Time, typical US corp)
constexpr int64_t kLocalTimeOffsetMs = -5LL * 3600 * 1000;

// ============================================================================
// Helpers — derive all timing from CPU instruction counter
// ============================================================================

uint64_t GetBaseTickCount(const EmulationConfig& config) {
    return config.fakeTickCount != 0 ? config.fakeTickCount : kDefaultBaseTickCount;
}

uint64_t ComputeElapsedMs(const CPUState& cpu, const EmulationConfig& config) {
    // Avoid division by zero
    uint64_t freq = config.fakeTSCFrequency;
    if (freq == 0) freq = 3'800'000'000ULL;

    uint64_t tscElapsed = cpu.instructionCount * cpu.tscIncrement;
    return tscElapsed * 1000 / freq;
}

uint64_t ComputeQPCValue(const CPUState& cpu, const EmulationConfig& config) {
    uint64_t freq = config.fakeTSCFrequency;
    if (freq == 0) freq = 3'800'000'000ULL;

    uint64_t tscElapsed = cpu.instructionCount * cpu.tscIncrement;
    return tscElapsed * kQPCFrequency / freq;
}

// SYSTEMTIME structure layout (16 bytes):
// Offset  0: WORD wYear
// Offset  2: WORD wMonth
// Offset  4: WORD wDayOfWeek
// Offset  6: WORD wDay
// Offset  8: WORD wHour
// Offset 10: WORD wMinute
// Offset 12: WORD wSecond
// Offset 14: WORD wMilliseconds

void WriteU16Buf(uint8_t* buf, size_t off, uint16_t v) {
    std::memcpy(buf + off, &v, sizeof(v));
}

void FillSystemTime(uint8_t* buf, uint64_t timeMsPastMidnight) {
    // Base date: 2024-06-15 (Saturday = day-of-week 6)
    WriteU16Buf(buf, 0,  2024);                                                   // wYear
    WriteU16Buf(buf, 2,  6);                                                      // wMonth
    WriteU16Buf(buf, 4,  6);                                                      // wDayOfWeek (Saturday)
    WriteU16Buf(buf, 6,  15);                                                     // wDay
    WriteU16Buf(buf, 8,  static_cast<uint16_t>((timeMsPastMidnight / 3'600'000) % 24));  // wHour
    WriteU16Buf(buf, 10, static_cast<uint16_t>((timeMsPastMidnight / 60'000) % 60));     // wMinute
    WriteU16Buf(buf, 12, static_cast<uint16_t>((timeMsPastMidnight / 1000) % 60));       // wSecond
    WriteU16Buf(buf, 14, static_cast<uint16_t>(timeMsPastMidnight % 1000));              // wMilliseconds
}

} // anonymous namespace

// ============================================================================
// Registration
// ============================================================================

void RegisterTimeAPI(APIDispatcher& dispatcher) noexcept {
    static const APIRegistration regs[] = {
        { "kernel32.dll", "GetTickCount",              HandleGetTickCount,              0, false },
        { "kernel32.dll", "GetTickCount64",            HandleGetTickCount64,            0, false },
        { "kernel32.dll", "QueryPerformanceCounter",   HandleQueryPerformanceCounter,   1, false },
        { "kernel32.dll", "QueryPerformanceFrequency", HandleQueryPerformanceFrequency, 1, false },
        { "kernel32.dll", "GetSystemTime",             HandleGetSystemTime,             1, false },
        { "kernel32.dll", "GetLocalTime",              HandleGetLocalTime,              1, false },
        { "kernel32.dll", "GetSystemTimeAsFileTime",   HandleGetSystemTimeAsFileTime,   1, false },
    };
    dispatcher.RegisterBatch(regs, static_cast<uint32_t>(std::size(regs)));
}

// ============================================================================
// GetTickCount / GetTickCount64
// ============================================================================

bool HandleGetTickCount(APIContext& ctx) {
    uint64_t base    = GetBaseTickCount(ctx.Config());
    uint64_t elapsed = ComputeElapsedMs(ctx.CPU(), ctx.Config());
    // GetTickCount returns a 32-bit DWORD (wraps at ~49.7 days)
    ctx.SetReturn32(static_cast<uint32_t>((base + elapsed) & 0xFFFFFFFF));
    return true;
}

bool HandleGetTickCount64(APIContext& ctx) {
    uint64_t base    = GetBaseTickCount(ctx.Config());
    uint64_t elapsed = ComputeElapsedMs(ctx.CPU(), ctx.Config());
    ctx.SetReturn(base + elapsed);
    return true;
}

// ============================================================================
// QueryPerformanceCounter / QueryPerformanceFrequency
// ============================================================================

bool HandleQueryPerformanceCounter(APIContext& ctx) {
    GuestAddress counterAddr = ctx.GetArgPtr(0);
    if (counterAddr == 0) {
        ctx.SetReturnBool(false);
        return true;
    }

    // Base QPC is derived from base tick count for consistency
    // base_qpc = base_tick_ms * (QPCFreq / 1000) = base_tick_ms * 10000
    uint64_t baseQPC    = GetBaseTickCount(ctx.Config()) * 10'000;
    uint64_t elapsedQPC = ComputeQPCValue(ctx.CPU(), ctx.Config());
    uint64_t qpc        = baseQPC + elapsedQPC;

    ctx.Memory().WriteU64(counterAddr, qpc);
    ctx.SetReturnBool(true);
    return true;
}

bool HandleQueryPerformanceFrequency(APIContext& ctx) {
    GuestAddress freqAddr = ctx.GetArgPtr(0);
    if (freqAddr == 0) {
        ctx.SetReturnBool(false);
        return true;
    }

    ctx.Memory().WriteU64(freqAddr, kQPCFrequency);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// GetSystemTime / GetLocalTime
// ============================================================================

bool HandleGetSystemTime(APIContext& ctx) {
    GuestAddress addr = ctx.GetArgPtr(0);
    if (addr == 0) return true;

    uint64_t elapsedMs    = ComputeElapsedMs(ctx.CPU(), ctx.Config());
    uint64_t currentMsUTC = kBaseTimeMsUTC + elapsedMs;

    uint8_t buf[16] = {};
    FillSystemTime(buf, currentMsUTC);
    ctx.Memory().Write(addr, buf, 16);
    return true;
}

bool HandleGetLocalTime(APIContext& ctx) {
    GuestAddress addr = ctx.GetArgPtr(0);
    if (addr == 0) return true;

    uint64_t elapsedMs = ComputeElapsedMs(ctx.CPU(), ctx.Config());
    // Apply timezone offset (may wrap negative — add 24h to keep positive)
    int64_t localMs = static_cast<int64_t>(kBaseTimeMsUTC + elapsedMs) + kLocalTimeOffsetMs;
    if (localMs < 0) localMs += 24LL * 3600 * 1000;
    auto currentMsLocal = static_cast<uint64_t>(localMs);

    uint8_t buf[16] = {};
    FillSystemTime(buf, currentMsLocal);
    ctx.Memory().Write(addr, buf, 16);
    return true;
}

// ============================================================================
// GetSystemTimeAsFileTime
// ============================================================================

bool HandleGetSystemTimeAsFileTime(APIContext& ctx) {
    GuestAddress addr = ctx.GetArgPtr(0);
    if (addr == 0) return true;

    uint64_t elapsedMs = ComputeElapsedMs(ctx.CPU(), ctx.Config());
    // FILETIME is in 100-nanosecond intervals; 1 ms = 10,000 intervals
    uint64_t fileTime = kBaseFileTime + elapsedMs * 10'000;

    // FILETIME: { DWORD dwLowDateTime, DWORD dwHighDateTime } — just write as u64
    ctx.Memory().WriteU64(addr, fileTime);
    return true;
}

} // namespace Phantom::WinAPI::Kernel32

#pragma warning(pop)
