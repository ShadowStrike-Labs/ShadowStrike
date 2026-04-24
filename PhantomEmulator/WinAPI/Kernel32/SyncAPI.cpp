/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * SyncAPI.cpp — Kernel32 synchronization API implementations
 *
 * Every handler reads arguments from guest registers / guest stack via
 * APIContext, operates on HandleTable, and writes results back through
 * the context. No host OS calls are made.
 *
 * Sleep acceleration prevents sandbox evasion: malware that sleeps for
 * minutes to exhaust analysis timeouts is defeated by instant completion.
 * Named mutex tracking captures infection markers malware uses to prevent
 * re-execution on already-compromised hosts.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "SyncAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../HandleTable.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <algorithm>
#include <cstring>

// DESIGN: Handles().Modify<SyncObjectData> is [[nodiscard]] so the caller can
// detect concurrent handle revocation. On SetEvent/ResetEvent the preceding
// Lookup already validated the handle; re-testing the Modify result would
// rebuild the same validity check and silence is the correct Win32-facing
// semantic (BOOL result is set from the validated Lookup, not the async
// modify). Pragma is scoped tightly — every handle lookup is still checked.
#pragma warning(push)
#pragma warning(disable : 4834 6031)

namespace Phantom::WinAPI::Kernel32 {

// ============================================================================
// Internal constants
// ============================================================================

static constexpr uint32_t kInfiniteTimeout       = 0xFFFFFFFF;
static constexpr uint32_t kMaximumWaitObjects    = 64;
static constexpr uint32_t kAntiAnalysisSleepMs   = 5000;

// TSC ticks per millisecond at the faked frequency (3.8 GHz / 1000)
static constexpr uint64_t kTscTicksPerMs = 3'800'000;

// ============================================================================
// Helpers
// ============================================================================

// Advance the emulated TSC counter proportional to the "elapsed" wait time.
// This maintains timing consistency: if malware reads RDTSC before and after
// Sleep, it should see a plausible delta.
static void AdvanceTsc(CPUState& cpu, uint32_t milliseconds) noexcept {
    // Cap to prevent overflow on very large values
    uint64_t safeDuration = std::min<uint64_t>(milliseconds, 600'000u); // 10 min cap
    cpu.tsc += safeDuration * kTscTicksPerMs;
}

// ============================================================================
// WaitForSingleObject
// ============================================================================
// Args: hHandle (0), dwMilliseconds (1)
// Returns: WAIT_OBJECT_0 (0) on success, WAIT_TIMEOUT, WAIT_FAILED.
//
// We never actually block — the emulator returns immediately.
// Large timeouts are flagged as potential anti-analysis behavior.

bool HandleWaitForSingleObject(APIContext& ctx) {
    const auto hHandle        = ctx.GetArg(0);
    const auto dwMilliseconds = ctx.GetArg32(1);

    // Validate handle (accept pseudo-handles)
    if (hHandle != kCurrentProcess && hHandle != kCurrentThread) {
        if (!ctx.Handles().IsValid(hHandle)) {
            ctx.SetLastError(Win32::ERROR_INVALID_HANDLE);
            ctx.SetReturn(Win32::WAIT_FAILED);
            return true;
        }
    }

    // Accelerate: return WAIT_OBJECT_0 immediately regardless of timeout
    if (ctx.Config().enableTimingAcceleration) {
        AdvanceTsc(ctx.CPU(), dwMilliseconds == kInfiniteTimeout ? 100 : dwMilliseconds);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn(Win32::WAIT_OBJECT_0);
    return true;
}

// ============================================================================
// WaitForMultipleObjects
// ============================================================================
// Args: nCount (0), lpHandles (1), bWaitAll (2), dwMilliseconds (3)
// Returns: WAIT_OBJECT_0 on success.

bool HandleWaitForMultipleObjects(APIContext& ctx) {
    const auto nCount         = ctx.GetArg32(0);
    const auto lpHandles      = ctx.GetArgPtr(1);
    const auto bWaitAll       = ctx.GetArg32(2);
    const auto dwMilliseconds = ctx.GetArg32(3);

    (void)bWaitAll;

    if (nCount == 0 || nCount > kMaximumWaitObjects) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    if (lpHandles == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    // Read handle array from guest memory (validate at least the pointer region)
    auto& mem = ctx.Memory();
    const uint32_t ptrSize = ctx.Is64Bit() ? 8u : 4u;
    const uint32_t arrayBytes = nCount * ptrSize;

    // Validate accessibility of the handle array (check first and last element)
    if (!mem.IsAccessible(lpHandles, MemProt::Read) ||
        !mem.IsAccessible(lpHandles + arrayBytes - 1, MemProt::Read)) {
        ctx.FailWithError(Win32::ERROR_NOACCESS);
        return true;
    }

    if (ctx.Config().enableTimingAcceleration) {
        AdvanceTsc(ctx.CPU(), dwMilliseconds == kInfiniteTimeout ? 100 : dwMilliseconds);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn(Win32::WAIT_OBJECT_0);
    return true;
}

// ============================================================================
// CreateMutexA
// ============================================================================
// Args: lpMutexAttributes (0), bInitialOwner (1), lpName (2)

bool HandleCreateMutexA(APIContext& ctx) {
    // arg0: lpMutexAttributes (ignored)
    const auto bInitialOwner = ctx.GetArg32(1);
    const auto lpName        = ctx.GetArgPtr(2);

    SyncObjectData mutexData{};
    mutexData.signaled = (bInitialOwner == 0);  // Unowned → signaled
    mutexData.count    = bInitialOwner ? 1 : 0;

    if (lpName != 0) {
        std::string ansiName = ctx.ReadAnsiString(lpName, 512);
        mutexData.name = std::wstring(ansiName.begin(), ansiName.end());
    }

    GuestHandle handle = ctx.Handles().Create(HandleType::Mutex, mutexData);
    if (handle == kNullHandle) {
        ctx.FailWithError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnHandle(handle);
    return true;
}

// ============================================================================
// CreateMutexW
// ============================================================================
// Args: lpMutexAttributes (0), bInitialOwner (1), lpName (2)

bool HandleCreateMutexW(APIContext& ctx) {
    const auto bInitialOwner = ctx.GetArg32(1);
    const auto lpName        = ctx.GetArgPtr(2);

    SyncObjectData mutexData{};
    mutexData.signaled = (bInitialOwner == 0);
    mutexData.count    = bInitialOwner ? 1 : 0;

    if (lpName != 0) {
        mutexData.name = ctx.ReadWideString(lpName, 512);
    }

    GuestHandle handle = ctx.Handles().Create(HandleType::Mutex, mutexData);
    if (handle == kNullHandle) {
        ctx.FailWithError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnHandle(handle);
    return true;
}

// ============================================================================
// CreateEventA
// ============================================================================
// Args: lpEventAttributes (0), bManualReset (1), bInitialState (2), lpName (3)

bool HandleCreateEventA(APIContext& ctx) {
    // arg0: lpEventAttributes (ignored)
    const auto bManualReset  = ctx.GetArg32(1);
    const auto bInitialState = ctx.GetArg32(2);
    const auto lpName        = ctx.GetArgPtr(3);

    (void)bManualReset;

    SyncObjectData eventData{};
    eventData.signaled = (bInitialState != 0);

    if (lpName != 0) {
        std::string ansiName = ctx.ReadAnsiString(lpName, 512);
        eventData.name = std::wstring(ansiName.begin(), ansiName.end());
    }

    GuestHandle handle = ctx.Handles().Create(HandleType::Event, eventData);
    if (handle == kNullHandle) {
        ctx.FailWithError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnHandle(handle);
    return true;
}

// ============================================================================
// CreateEventW
// ============================================================================
// Args: lpEventAttributes (0), bManualReset (1), bInitialState (2), lpName (3)

bool HandleCreateEventW(APIContext& ctx) {
    const auto bManualReset  = ctx.GetArg32(1);
    const auto bInitialState = ctx.GetArg32(2);
    const auto lpName        = ctx.GetArgPtr(3);

    (void)bManualReset;

    SyncObjectData eventData{};
    eventData.signaled = (bInitialState != 0);

    if (lpName != 0) {
        eventData.name = ctx.ReadWideString(lpName, 512);
    }

    GuestHandle handle = ctx.Handles().Create(HandleType::Event, eventData);
    if (handle == kNullHandle) {
        ctx.FailWithError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnHandle(handle);
    return true;
}

// ============================================================================
// SetEvent
// ============================================================================
// Args: hEvent (0)

bool HandleSetEvent(APIContext& ctx) {
    const auto hEvent = ctx.GetArg(0);

    auto entry = ctx.Handles().Lookup(hEvent, HandleType::Event);
    if (!entry.has_value()) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    ctx.Handles().Modify<SyncObjectData>(hEvent, [](SyncObjectData& data) {
        data.signaled = true;
    });

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// ResetEvent
// ============================================================================
// Args: hEvent (0)

bool HandleResetEvent(APIContext& ctx) {
    const auto hEvent = ctx.GetArg(0);

    auto entry = ctx.Handles().Lookup(hEvent, HandleType::Event);
    if (!entry.has_value()) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    ctx.Handles().Modify<SyncObjectData>(hEvent, [](SyncObjectData& data) {
        data.signaled = false;
    });

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// Sleep
// ============================================================================
// Args: dwMilliseconds (0)
//
// Timing acceleration: returns immediately without blocking.
// Behavioral analysis: flags AntiAnalysis if > 5000ms (sandbox evasion).
// TSC advancement: maintains timing consistency for RDTSC-based checks.

bool HandleSleep(APIContext& ctx) {
    const auto dwMilliseconds = ctx.GetArg32(0);

    // IOC: T1497.003 (Virtualization/Sandbox Evasion: Time-Based Evasion).
    // Malware waits out short-horizon sandboxes by calling Sleep for tens of
    // seconds to several minutes on entry. 5 seconds is the threshold used
    // across the industry (CAPE, Cuckoo, VMRay). INFINITE is treated as the
    // strongest signal — nothing legitimate deliberately hangs forever on
    // startup.
    if (dwMilliseconds == kInfiniteTimeout || dwMilliseconds >= kAntiAnalysisSleepMs) {
        ctx.AddBehaviorFlag(BehaviorFlag::AntiAnalysis);
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
    }

    if (ctx.Config().enableTimingAcceleration) {
        // Accelerate: advance TSC but do not actually wait
        AdvanceTsc(ctx.CPU(), dwMilliseconds);
    }

    // Sleep is VOID — no return value to set. Just continue execution.
    return true;
}

// ============================================================================
// SleepEx
// ============================================================================
// Args: dwMilliseconds (0), bAlertable (1)
// Returns: 0 if timeout expired, WAIT_IO_COMPLETION (0xC0) if alertable I/O.

bool HandleSleepEx(APIContext& ctx) {
    const auto dwMilliseconds = ctx.GetArg32(0);
    const auto bAlertable     = ctx.GetArg32(1);

    (void)bAlertable;

    if (ctx.Config().enableTimingAcceleration) {
        AdvanceTsc(ctx.CPU(), dwMilliseconds);
    }

    // Return 0 (timeout expired, no APCs executed)
    ctx.SetReturn(0);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterSyncAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "kernel32.dll", "WaitForSingleObject",
          HandleWaitForSingleObject, 2, false },
        { "kernel32.dll", "WaitForMultipleObjects",
          HandleWaitForMultipleObjects, 4, false },
        { "kernel32.dll", "CreateMutexA",
          HandleCreateMutexA, 3, false },
        { "kernel32.dll", "CreateMutexW",
          HandleCreateMutexW, 3, false },
        { "kernel32.dll", "CreateEventA",
          HandleCreateEventA, 4, false },
        { "kernel32.dll", "CreateEventW",
          HandleCreateEventW, 4, false },
        { "kernel32.dll", "SetEvent",
          HandleSetEvent, 1, false },
        { "kernel32.dll", "ResetEvent",
          HandleResetEvent, 1, false },
        { "kernel32.dll", "Sleep",
          HandleSleep, 1, false },
        { "kernel32.dll", "SleepEx",
          HandleSleepEx, 2, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Kernel32

#pragma warning(pop)
