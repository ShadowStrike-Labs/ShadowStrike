/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ProcessAPI.cpp — Kernel32 process management API implementations
 *
 * Every handler reads arguments via APIContext, creates/manipulates
 * handles in the HandleTable, and flags suspicious behavioral patterns.
 * No host OS calls are made.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "ProcessAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../HandleTable.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <algorithm>
#include <cstring>
#include <string>
#include <atomic>

namespace Phantom::WinAPI::Kernel32 {

// ============================================================================
// Internal constants
// ============================================================================

static constexpr uint32_t kOurPid          = 4444;
static constexpr uint32_t kMaxPathChars    = 1024;

// CreateProcess dwCreationFlags
static constexpr uint32_t CREATE_SUSPENDED     = 0x00000004;
static constexpr uint32_t CREATE_NEW_CONSOLE   = 0x00000010;
static constexpr uint32_t CREATE_NO_WINDOW     = 0x08000000;

// PROCESS_INFORMATION structure layout (x64):
//   +0x00 HANDLE hProcess  (8 bytes)
//   +0x08 HANDLE hThread   (8 bytes)
//   +0x10 DWORD  dwProcessId (4 bytes)
//   +0x14 DWORD  dwThreadId  (4 bytes)
static constexpr uint32_t kProcessInfoSize = 24;

// Monotonic counters for unique PIDs/TIDs
static std::atomic<uint32_t> s_nextPid{5000};
static std::atomic<uint32_t> s_nextTid{6000};

// ============================================================================
// Helpers
// ============================================================================

static std::wstring AnsiToWide(const std::string& ansi) noexcept {
    std::wstring result;
    result.reserve(ansi.size());
    for (char c : ansi) {
        result.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
    }
    return result;
}

// ============================================================================
// Internal: CreateProcess core logic (shared by A and W variants)
// ============================================================================

static bool CreateProcessCore(APIContext& ctx,
                              const std::wstring& applicationName,
                              const std::wstring& commandLine,
                              uint32_t dwCreationFlags,
                              GuestAddress lpProcessInfo) {
    if (lpProcessInfo == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    // Assign unique PIDs for the child
    const uint32_t childPid = s_nextPid.fetch_add(1, std::memory_order_relaxed);
    const uint32_t childTid = s_nextTid.fetch_add(1, std::memory_order_relaxed);

    // Create a process handle
    ProcessHandleData phd;
    phd.pid        = childPid;
    phd.accessMask = NT::PROCESS_ALL_ACCESS;
    phd.isSelf     = false;

    auto& handles = ctx.Handles();
    GuestHandle hProcess = handles.Create(HandleType::Process, phd);
    if (hProcess == kNullHandle) {
        ctx.FailWithError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    // Create a thread handle for the primary thread
    ThreadHandleData thd;
    thd.tid        = childTid;
    thd.ownerPid   = childPid;
    thd.accessMask = NT::THREAD_ALL_ACCESS;
    thd.suspended  = (dwCreationFlags & CREATE_SUSPENDED) != 0;

    GuestHandle hThread = handles.Create(HandleType::Thread, thd);
    if (hThread == kNullHandle) {
        handles.Close(hProcess);
        ctx.FailWithError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    // Fill PROCESS_INFORMATION structure in guest memory
    auto& mem = ctx.Memory();
    uint8_t pi[kProcessInfoSize] = {};

    std::memcpy(pi + 0x00, &hProcess, 8);
    std::memcpy(pi + 0x08, &hThread, 8);
    std::memcpy(pi + 0x10, &childPid, 4);
    std::memcpy(pi + 0x14, &childTid, 4);

    if (mem.Write(lpProcessInfo, pi, kProcessInfoSize) != ErrorCode::Success) {
        handles.Close(hProcess);
        handles.Close(hThread);
        ctx.FailWithError(Win32::ERROR_NOACCESS);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// CreateProcessA — lpApplicationName(0), lpCommandLine(1),
//                  lpProcessAttributes(2), lpThreadAttributes(3),
//                  bInheritHandles(4), dwCreationFlags(5),
//                  lpEnvironment(6), lpCurrentDirectory(7),
//                  lpStartupInfo(8), lpProcessInformation(9)
// ============================================================================

bool HandleCreateProcessA(APIContext& ctx) {
    const auto lpAppName       = ctx.GetArgPtr(0);
    const auto lpCmdLine       = ctx.GetArgPtr(1);
    // args 2-4 ignored in emulation
    const auto dwCreationFlags = ctx.GetArg32(5);
    // args 6-8 ignored
    const auto lpProcessInfo   = ctx.GetArgPtr(9);

    std::wstring appName;
    std::wstring cmdLine;

    if (lpAppName != 0) {
        std::string ansi = ctx.ReadAnsiString(lpAppName, kMaxPathChars);
        appName = AnsiToWide(ansi);
    }
    if (lpCmdLine != 0) {
        std::string ansi = ctx.ReadAnsiString(lpCmdLine, kMaxPathChars);
        cmdLine = AnsiToWide(ansi);
    }

    if (appName.empty() && cmdLine.empty()) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    return CreateProcessCore(ctx, appName, cmdLine, dwCreationFlags, lpProcessInfo);
}

// ============================================================================
// CreateProcessW — same layout, wide strings
// ============================================================================

bool HandleCreateProcessW(APIContext& ctx) {
    const auto lpAppName       = ctx.GetArgPtr(0);
    const auto lpCmdLine       = ctx.GetArgPtr(1);
    const auto dwCreationFlags = ctx.GetArg32(5);
    const auto lpProcessInfo   = ctx.GetArgPtr(9);

    std::wstring appName;
    std::wstring cmdLine;

    if (lpAppName != 0) {
        appName = ctx.ReadWideString(lpAppName, kMaxPathChars);
    }
    if (lpCmdLine != 0) {
        cmdLine = ctx.ReadWideString(lpCmdLine, kMaxPathChars);
    }

    if (appName.empty() && cmdLine.empty()) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    return CreateProcessCore(ctx, appName, cmdLine, dwCreationFlags, lpProcessInfo);
}

// ============================================================================
// OpenProcess — dwDesiredAccess(0), bInheritHandle(1), dwProcessId(2)
// ============================================================================

bool HandleOpenProcess(APIContext& ctx) {
    const auto dwAccess   = ctx.GetArg32(0);
    // arg1 = bInheritHandle (not enforced)
    const auto dwPid      = ctx.GetArg32(2);

    const bool isSelf = (dwPid == kOurPid);

    ProcessHandleData phd;
    phd.pid        = dwPid;
    phd.accessMask = dwAccess;
    phd.isSelf     = isSelf;

    auto& handles = ctx.Handles();
    GuestHandle gh = handles.Create(HandleType::Process, phd);
    if (gh == kNullHandle) {
        ctx.FailWithInvalidHandle(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnHandle(gh);
    return true;
}

// ============================================================================
// TerminateProcess — hProcess(0), uExitCode(1)
// ============================================================================

bool HandleTerminateProcess(APIContext& ctx) {
    const auto hProcess  = ctx.GetArg(0);

    // Check if this is self-termination
    if (hProcess == kCurrentProcess || hProcess == kNullHandle) {
        // Self-termination stops emulation
        return false;
    }

    auto& handles = ctx.Handles();
    auto entry = handles.Lookup(hProcess, HandleType::Process);
    if (entry.has_value()) {
        auto* pd = std::get_if<ProcessHandleData>(&entry->data);
        if (pd && pd->isSelf) {
            return false;
        }
    }

    // Remote process termination — succeed silently
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// ExitProcess — uExitCode(0)
// ============================================================================

bool HandleExitProcess(APIContext& ctx) {
    // Returning false stops the emulation with StopReason::ExitProcess
    return false;
}

// ============================================================================
// GetCurrentProcessId — no arguments
// ============================================================================

bool HandleGetCurrentProcessId(APIContext& ctx) {
    ctx.SetReturn32(kOurPid);
    return true;
}

// ============================================================================
// GetCurrentProcess — no arguments
// ============================================================================

bool HandleGetCurrentProcess(APIContext& ctx) {
    ctx.SetReturnHandle(kCurrentProcess);
    return true;
}

// ============================================================================
// GetExitCodeProcess — hProcess(0), lpExitCode(1)
// ============================================================================

bool HandleGetExitCodeProcess(APIContext& ctx) {
    const auto hProcess   = ctx.GetArg(0);
    const auto lpExitCode = ctx.GetArgPtr(1);

    if (lpExitCode == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    // If the handle is valid (even remote), report STILL_ACTIVE
    auto& handles = ctx.Handles();
    bool validHandle = (hProcess == kCurrentProcess) ||
                       handles.IsValid(hProcess);

    if (!validHandle) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    ctx.Memory().WriteU32(lpExitCode, Win32::STILL_ACTIVE);

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// IsWow64Process — hProcess(0), Wow64Process(1)
// ============================================================================

bool HandleIsWow64Process(APIContext& ctx) {
    const auto hProcess     = ctx.GetArg(0);
    const auto lpWow64Flag  = ctx.GetArgPtr(1);

    if (lpWow64Flag == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    // If 64-bit emulation → WoW64 = FALSE; 32-bit → WoW64 = TRUE
    const GuestBool isWow64 = ctx.CPU().Is64Bit() ? 0 : 1;
    ctx.Memory().WriteU32(lpWow64Flag, static_cast<uint32_t>(isWow64));

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterProcessAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "kernel32.dll", "CreateProcessA",
          HandleCreateProcessA, 10, true },
        { "kernel32.dll", "CreateProcessW",
          HandleCreateProcessW, 10, true },
        { "kernel32.dll", "OpenProcess",
          HandleOpenProcess, 3, true },
        { "kernel32.dll", "TerminateProcess",
          HandleTerminateProcess, 2, false },
        { "kernel32.dll", "ExitProcess",
          HandleExitProcess, 1, true },
        { "kernel32.dll", "GetCurrentProcessId",
          HandleGetCurrentProcessId, 0, true },
        { "kernel32.dll", "GetCurrentProcess",
          HandleGetCurrentProcess, 0, true },
        { "kernel32.dll", "GetExitCodeProcess",
          HandleGetExitCodeProcess, 2, false },
        { "kernel32.dll", "IsWow64Process",
          HandleIsWow64Process, 2, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Kernel32
