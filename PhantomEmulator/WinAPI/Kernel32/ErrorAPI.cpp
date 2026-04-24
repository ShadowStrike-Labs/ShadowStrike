/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ErrorAPI.cpp — Kernel32 error handling and anti-debug API handlers
 *
 * MISSION CRITICAL — Anti-debug handlers:
 *
 * IsDebuggerPresent:
 *   Malware universally calls this as a first-pass debugger check.
 *   We ALWAYS return FALSE. There is NO code path that returns TRUE.
 *
 * CheckRemoteDebuggerPresent:
 *   Malware calls this to detect remote debugging (e.g., via
 *   DebugActiveProcess). We ALWAYS write FALSE to the output
 *   parameter and return TRUE (indicating the call succeeded).
 *
 * These are the most common anti-analysis checks. Failure to
 * return the correct values will cause the majority of evasive
 * malware to terminate or alter behavior.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "ErrorAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"

// DESIGN: VirtualMemory::WriteValue returns [[nodiscard]] ErrorCode. Kernel32
// anti-debug APIs ignore write failures on output BOOLs — the guest contract
// only exposes GetLastError. Scope: this TU only.
#pragma warning(push)
#pragma warning(disable: 4834 6031)

namespace Phantom::WinAPI::Kernel32 {

// ============================================================================
// Registration
// ============================================================================

void RegisterErrorAPI(APIDispatcher& dispatcher) noexcept {
    static const APIRegistration regs[] = {
        { "kernel32.dll", "SetLastError",              HandleSetLastError,              1, false },
        { "kernel32.dll", "GetLastError",              HandleGetLastError,              0, false },
        { "kernel32.dll", "IsDebuggerPresent",         HandleIsDebuggerPresent,         0, true  },
        { "kernel32.dll", "CheckRemoteDebuggerPresent",HandleCheckRemoteDebuggerPresent,2, true  },
    };
    dispatcher.RegisterBatch(regs, static_cast<uint32_t>(std::size(regs)));
}

// ============================================================================
// SetLastError / GetLastError
// ============================================================================

bool HandleSetLastError(APIContext& ctx) {
    GuestDword errCode = ctx.GetArg32(0);
    ctx.SetLastError(errCode);
    // SetLastError returns void — no return value
    return true;
}

bool HandleGetLastError(APIContext& ctx) {
    ctx.SetReturn32(ctx.GetLastError());
    return true;
}

// ============================================================================
// IsDebuggerPresent — ANTI-DEBUG (ALWAYS returns FALSE)
// ============================================================================
// The PEB.BeingDebugged field should also be 0, but that is handled
// by the PEB initialization in the loader. This handler covers the
// explicit API call path.

bool HandleIsDebuggerPresent(APIContext& ctx) {
    // High-signal anti-analysis probe — the call itself is the IOC, independent
    // of the (always-FALSE) answer we return.
    ctx.AddBehaviorFlag(BehaviorFlag::AntiAnalysis);
    ctx.SetReturnBool(false);
    return true;
}

// ============================================================================
// CheckRemoteDebuggerPresent — ANTI-DEBUG (ALWAYS writes FALSE)
// ============================================================================
// BOOL CheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent)
//
// hProcess:          Handle to the process to check (typically self)
// pbDebuggerPresent: [out] pointer to BOOL — we always write FALSE (0)
// Return:            TRUE on success (the call itself succeeded)

bool HandleCheckRemoteDebuggerPresent(APIContext& ctx) {
    // arg0: hProcess (ignored — always report no debugger regardless of target)
    GuestAddress pbDebuggerPresent = ctx.GetArgPtr(1);

    if (pbDebuggerPresent == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    // High-signal anti-analysis probe — record it.
    ctx.AddBehaviorFlag(BehaviorFlag::AntiAnalysis);

    // Write FALSE (0) — no debugger present
    GuestBool falseValue = 0;
    ctx.Memory().WriteValue(pbDebuggerPresent, falseValue);

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

} // namespace Phantom::WinAPI::Kernel32

#pragma warning(pop)
