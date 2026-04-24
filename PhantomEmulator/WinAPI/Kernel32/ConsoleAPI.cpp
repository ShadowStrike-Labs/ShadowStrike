/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ConsoleAPI.cpp — Kernel32 console and debug output API handlers
 *
 * OutputDebugString captures malware debug output for analysis logs.
 * WriteConsole is a no-op that reports success.
 * GetStdHandle returns pseudo-handle constants.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "ConsoleAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"

// DESIGN: The emulator deliberately discards the [[nodiscard]] ErrorCode from
// VirtualMemory::Write* calls. A write failure on a caller-supplied output
// pointer is never actionable — we return success to the guest anyway because
// WriteConsole semantically completes once the bytes are accepted. Scope:
// this TU only.
#pragma warning(push)
#pragma warning(disable: 4834 6031)

namespace Phantom::WinAPI::Kernel32 {

// ============================================================================
// Constants
// ============================================================================

namespace {

// STD_INPUT_HANDLE / STD_OUTPUT_HANDLE / STD_ERROR_HANDLE values
constexpr uint32_t kStdInputHandleId  = static_cast<uint32_t>(-10);
constexpr uint32_t kStdOutputHandleId = static_cast<uint32_t>(-11);
constexpr uint32_t kStdErrorHandleId  = static_cast<uint32_t>(-12);

} // anonymous namespace

// ============================================================================
// Registration
// ============================================================================

void RegisterConsoleAPI(APIDispatcher& dispatcher) noexcept {
    static const APIRegistration regs[] = {
        { "kernel32.dll", "OutputDebugStringA", HandleOutputDebugStringA, 1, false },
        { "kernel32.dll", "OutputDebugStringW", HandleOutputDebugStringW, 1, false },
        { "kernel32.dll", "GetStdHandle",       HandleGetStdHandle,       1, false },
        { "kernel32.dll", "WriteConsoleA",      HandleWriteConsoleA,      5, false },
        { "kernel32.dll", "WriteConsoleW",      HandleWriteConsoleW,      5, false },
    };
    dispatcher.RegisterBatch(regs, static_cast<uint32_t>(std::size(regs)));
}

// ============================================================================
// OutputDebugStringA/W
// ============================================================================
// Read the debug string from guest memory. The string content is valuable
// for behavioral analysis — malware sometimes emits debug output revealing
// internal state, C2 configuration, or error conditions.

bool HandleOutputDebugStringA(APIContext& ctx) {
    GuestAddress strAddr = ctx.GetArgPtr(0);
    if (strAddr != 0) {
        // Read and discard — the string is captured in the API call log
        // by the dispatcher's argument recording mechanism.
        (void)ctx.ReadAnsiString(strAddr, 4096);
    }
    // OutputDebugString returns void — no return value to set.
    return true;
}

bool HandleOutputDebugStringW(APIContext& ctx) {
    GuestAddress strAddr = ctx.GetArgPtr(0);
    if (strAddr != 0) {
        (void)ctx.ReadWideString(strAddr, 2048);
    }
    return true;
}

// ============================================================================
// GetStdHandle
// ============================================================================

bool HandleGetStdHandle(APIContext& ctx) {
    uint32_t nStdHandle = ctx.GetArg32(0);

    GuestHandle result = kInvalidHandleValue;

    switch (nStdHandle) {
        case kStdInputHandleId:  result = kStdInputHandle;  break;
        case kStdOutputHandleId: result = kStdOutputHandle; break;
        case kStdErrorHandleId:  result = kStdErrorHandle;  break;
        default:
            ctx.SetLastError(Win32::ERROR_INVALID_PARAMETER);
            ctx.SetReturnHandle(kInvalidHandleValue);
            return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnHandle(result);
    return true;
}

// ============================================================================
// WriteConsoleA/W
// ============================================================================
// No-op: report success with the requested number of characters written.
// Console output is not meaningful in the emulation environment.

bool HandleWriteConsoleA(APIContext& ctx) {
    // arg0: hConsoleOutput (ignored)
    // arg1: lpBuffer (ignored)
    uint32_t charsToWrite   = ctx.GetArg32(2);
    GuestAddress writtenAddr = ctx.GetArgPtr(3);
    // arg4: lpReserved (ignored)

    if (writtenAddr != 0) {
        ctx.Memory().WriteU32(writtenAddr, charsToWrite);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

bool HandleWriteConsoleW(APIContext& ctx) {
    uint32_t charsToWrite    = ctx.GetArg32(2);
    GuestAddress writtenAddr = ctx.GetArgPtr(3);

    if (writtenAddr != 0) {
        ctx.Memory().WriteU32(writtenAddr, charsToWrite);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

} // namespace Phantom::WinAPI::Kernel32

#pragma warning(pop)
