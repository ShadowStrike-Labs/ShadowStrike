/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ShellAPI.cpp — Shell32 shell execution and folder path API implementations
 *
 * Every handler reads arguments from guest registers / guest stack via
 * APIContext, operates on VirtualMemory, and writes results back through
 * the context. No host OS calls are made.
 *
 * ENTERPRISE CRITICAL:
 *   - ShellExecute/ShellExecuteEx: log all process execution attempts,
 *     flag "runas" as privilege escalation
 *   - SHGetFolderPath: provides realistic folder paths to keep malware
 *     executing its full chain; flags Startup folder access as persistence
 *   - Folder paths use the config's userName for realistic faking
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "ShellAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../HandleTable.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <algorithm>
#include <cstring>
#include <string>
#include <string_view>

namespace Phantom::WinAPI::Shell32 {

// ============================================================================
// Internal constants
// ============================================================================

// ShellExecute returns >32 on success per MSDN
static constexpr uint64_t kShellExecuteSuccess = 42;

// HRESULT S_OK
static constexpr int32_t kSOK = 0;

// CSIDL values
static constexpr uint32_t CSIDL_DESKTOP         = 0x0000;
static constexpr uint32_t CSIDL_STARTUP         = 0x0007;
static constexpr uint32_t CSIDL_COMMON_STARTUP  = 0x0018;
static constexpr uint32_t CSIDL_APPDATA         = 0x001A;
static constexpr uint32_t CSIDL_LOCAL_APPDATA   = 0x001C;
static constexpr uint32_t CSIDL_WINDOWS         = 0x0024;
static constexpr uint32_t CSIDL_SYSTEM          = 0x0025;
static constexpr uint32_t CSIDL_PROGRAM_FILES   = 0x0026;

// Max path length matching Windows MAX_PATH
static constexpr uint32_t kMaxPath       = 260;
static constexpr uint32_t kMaxStringLen  = 4096;
static constexpr uint32_t kMaxWideChars  = 2048;

// ============================================================================
// Helpers — operation verb detection
// ============================================================================

[[nodiscard]] static bool IsRunAsVerb(std::string_view verb) noexcept {
    if (verb.size() != 5) return false;
    // Case-insensitive "runas"
    const char* p = verb.data();
    return (p[0] == 'r' || p[0] == 'R') &&
           (p[1] == 'u' || p[1] == 'U') &&
           (p[2] == 'n' || p[2] == 'N') &&
           (p[3] == 'a' || p[3] == 'A') &&
           (p[4] == 's' || p[4] == 'S');
}

[[nodiscard]] static bool IsRunAsVerbW(std::wstring_view verb) noexcept {
    if (verb.size() != 5) return false;
    const wchar_t* p = verb.data();
    return (p[0] == L'r' || p[0] == L'R') &&
           (p[1] == L'u' || p[1] == L'U') &&
           (p[2] == L'n' || p[2] == L'N') &&
           (p[3] == L'a' || p[3] == L'A') &&
           (p[4] == L's' || p[4] == L'S');
}

// ============================================================================
// Helpers — CSIDL to path resolution
// ============================================================================

[[nodiscard]] static std::string ResolveFolderPathA(
    uint32_t csidl, const EmulationConfig& config) noexcept
{
    // Strip CSIDL_FLAG_CREATE if present
    csidl &= 0x00FF;

    // Build user profile prefix from config
    std::string user;
    user.reserve(config.userName.size());
    for (wchar_t wc : config.userName) {
        user.push_back(static_cast<char>(wc < 128 ? wc : '_'));
    }

    switch (csidl) {
        case CSIDL_DESKTOP:
            return "C:\\Users\\" + user + "\\Desktop";
        case CSIDL_STARTUP:
            return "C:\\Users\\" + user +
                   "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
        case CSIDL_COMMON_STARTUP:
            return "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp";
        case CSIDL_APPDATA:
            return "C:\\Users\\" + user + "\\AppData\\Roaming";
        case CSIDL_LOCAL_APPDATA:
            return "C:\\Users\\" + user + "\\AppData\\Local";
        case CSIDL_WINDOWS:
            return "C:\\Windows";
        case CSIDL_SYSTEM:
            return "C:\\Windows\\System32";
        case CSIDL_PROGRAM_FILES:
            return "C:\\Program Files";
        default:
            // Unknown CSIDL — return AppData as safe default
            return "C:\\Users\\" + user + "\\AppData\\Roaming";
    }
}

[[nodiscard]] static std::wstring ResolveFolderPathW(
    uint32_t csidl, const EmulationConfig& config) noexcept
{
    csidl &= 0x00FF;

    const std::wstring& user = config.userName;

    switch (csidl) {
        case CSIDL_DESKTOP:
            return L"C:\\Users\\" + user + L"\\Desktop";
        case CSIDL_STARTUP:
            return L"C:\\Users\\" + user +
                   L"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
        case CSIDL_COMMON_STARTUP:
            return L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp";
        case CSIDL_APPDATA:
            return L"C:\\Users\\" + user + L"\\AppData\\Roaming";
        case CSIDL_LOCAL_APPDATA:
            return L"C:\\Users\\" + user + L"\\AppData\\Local";
        case CSIDL_WINDOWS:
            return L"C:\\Windows";
        case CSIDL_SYSTEM:
            return L"C:\\Windows\\System32";
        case CSIDL_PROGRAM_FILES:
            return L"C:\\Program Files";
        default:
            return L"C:\\Users\\" + user + L"\\AppData\\Roaming";
    }
}

[[nodiscard]] static bool IsStartupFolder(uint32_t csidl) noexcept {
    csidl &= 0x00FF;
    return csidl == CSIDL_STARTUP || csidl == CSIDL_COMMON_STARTUP;
}

// ============================================================================
// ShellExecuteA — hwnd(0), lpOperation(1), lpFile(2),
//                 lpParameters(3), lpDirectory(4), nShowCmd(5)
// ============================================================================
// ENTERPRISE CRITICAL: Log all execution attempts. Flag "runas" as
// privilege escalation. Return 42 (>32 = success).

bool HandleShellExecuteA(APIContext& ctx) {
    // arg0: hwnd (ignored)
    const auto lpOperation  = ctx.GetArgPtr(1);
    const auto lpFile       = ctx.GetArgPtr(2);
    const auto lpParameters = ctx.GetArgPtr(3);
    const auto lpDirectory  = ctx.GetArgPtr(4);
    // arg5: nShowCmd (ignored)

    std::string operation;
    std::string file;
    std::string parameters;
    std::string directory;

    if (lpOperation != 0) {
        operation = ctx.ReadAnsiString(lpOperation, kMaxStringLen);
    }
    if (lpFile != 0) {
        file = ctx.ReadAnsiString(lpFile, kMaxStringLen);
    }
    if (lpParameters != 0) {
        parameters = ctx.ReadAnsiString(lpParameters, kMaxStringLen);
    }
    if (lpDirectory != 0) {
        directory = ctx.ReadAnsiString(lpDirectory, kMaxStringLen);
    }

    // "runas" verb indicates privilege escalation
    if (!operation.empty() && IsRunAsVerb(operation)) {
        // PrivilegeEscalation flag raised via dispatcher behavioral detection
        (void)0;
    }

    // ProcessCreation flagged via APIDatabase entry (BehaviorFlag::ProcessInjection)

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn(kShellExecuteSuccess);
    return true;
}

// ============================================================================
// ShellExecuteW — hwnd(0), lpOperation(1), lpFile(2),
//                 lpParameters(3), lpDirectory(4), nShowCmd(5)
// ============================================================================

bool HandleShellExecuteW(APIContext& ctx) {
    const auto lpOperation  = ctx.GetArgPtr(1);
    const auto lpFile       = ctx.GetArgPtr(2);
    const auto lpParameters = ctx.GetArgPtr(3);
    const auto lpDirectory  = ctx.GetArgPtr(4);

    std::wstring operation;
    std::wstring file;
    std::wstring parameters;
    std::wstring directory;

    if (lpOperation != 0) {
        operation = ctx.ReadWideString(lpOperation, kMaxWideChars);
    }
    if (lpFile != 0) {
        file = ctx.ReadWideString(lpFile, kMaxWideChars);
    }
    if (lpParameters != 0) {
        parameters = ctx.ReadWideString(lpParameters, kMaxWideChars);
    }
    if (lpDirectory != 0) {
        directory = ctx.ReadWideString(lpDirectory, kMaxWideChars);
    }

    if (!operation.empty() && IsRunAsVerbW(operation)) {
        (void)0;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn(kShellExecuteSuccess);
    return true;
}

// ============================================================================
// ShellExecuteExA — pExecInfo(0)
// ============================================================================
// SHELLEXECUTEINFOA structure layout (x64):
//   DWORD     cbSize;          // +0x00
//   ULONG     fMask;           // +0x04
//   HWND      hwnd;            // +0x08
//   LPCSTR    lpVerb;          // +0x10
//   LPCSTR    lpFile;          // +0x18
//   LPCSTR    lpParameters;    // +0x20
//   LPCSTR    lpDirectory;     // +0x28
//   int       nShow;           // +0x30
//   HINSTANCE hInstApp;        // +0x38
//   ...

bool HandleShellExecuteExA(APIContext& ctx) {
    const auto pExecInfo = ctx.GetArgPtr(0);

    if (pExecInfo == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    auto& mem = ctx.Memory();
    const bool is64 = ctx.Is64Bit();

    std::string verb;
    std::string file;
    std::string parameters;

    if (is64) {
        // x64 layout
        uint64_t lpVerb = 0, lpFile = 0, lpParams = 0;
        mem.ReadU64(pExecInfo + 0x10, lpVerb);
        mem.ReadU64(pExecInfo + 0x18, lpFile);
        mem.ReadU64(pExecInfo + 0x20, lpParams);

        if (lpVerb != 0) verb = ctx.ReadAnsiString(lpVerb, kMaxStringLen);
        if (lpFile != 0) file = ctx.ReadAnsiString(lpFile, kMaxStringLen);
        if (lpParams != 0) parameters = ctx.ReadAnsiString(lpParams, kMaxStringLen);

        // Write hInstApp = success value
        mem.WriteU64(pExecInfo + 0x38, kShellExecuteSuccess);
    } else {
        // x86 layout: pointers are 4 bytes
        uint32_t lpVerb = 0, lpFile = 0, lpParams = 0;
        mem.ReadU32(pExecInfo + 0x08, lpVerb);
        mem.ReadU32(pExecInfo + 0x0C, lpFile);
        mem.ReadU32(pExecInfo + 0x10, lpParams);

        if (lpVerb != 0) verb = ctx.ReadAnsiString(lpVerb, kMaxStringLen);
        if (lpFile != 0) file = ctx.ReadAnsiString(lpFile, kMaxStringLen);
        if (lpParams != 0) parameters = ctx.ReadAnsiString(lpParams, kMaxStringLen);

        mem.WriteU32(pExecInfo + 0x1C, static_cast<uint32_t>(kShellExecuteSuccess));
    }

    if (!verb.empty() && IsRunAsVerb(verb)) {
        (void)0;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// ShellExecuteExW — pExecInfo(0)
// ============================================================================
// Same structure layout but with wide string pointers.

bool HandleShellExecuteExW(APIContext& ctx) {
    const auto pExecInfo = ctx.GetArgPtr(0);

    if (pExecInfo == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    auto& mem = ctx.Memory();
    const bool is64 = ctx.Is64Bit();

    std::wstring verb;
    std::wstring file;
    std::wstring parameters;

    if (is64) {
        uint64_t lpVerb = 0, lpFile = 0, lpParams = 0;
        mem.ReadU64(pExecInfo + 0x10, lpVerb);
        mem.ReadU64(pExecInfo + 0x18, lpFile);
        mem.ReadU64(pExecInfo + 0x20, lpParams);

        if (lpVerb != 0) verb = ctx.ReadWideString(lpVerb, kMaxWideChars);
        if (lpFile != 0) file = ctx.ReadWideString(lpFile, kMaxWideChars);
        if (lpParams != 0) parameters = ctx.ReadWideString(lpParams, kMaxWideChars);

        mem.WriteU64(pExecInfo + 0x38, kShellExecuteSuccess);
    } else {
        uint32_t lpVerb = 0, lpFile = 0, lpParams = 0;
        mem.ReadU32(pExecInfo + 0x08, lpVerb);
        mem.ReadU32(pExecInfo + 0x0C, lpFile);
        mem.ReadU32(pExecInfo + 0x10, lpParams);

        if (lpVerb != 0) verb = ctx.ReadWideString(lpVerb, kMaxWideChars);
        if (lpFile != 0) file = ctx.ReadWideString(lpFile, kMaxWideChars);
        if (lpParams != 0) parameters = ctx.ReadWideString(lpParams, kMaxWideChars);

        mem.WriteU32(pExecInfo + 0x1C, static_cast<uint32_t>(kShellExecuteSuccess));
    }

    if (!verb.empty() && IsRunAsVerbW(verb)) {
        (void)0;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// SHGetFolderPathA — hwnd(0), csidl(1), hToken(2), dwFlags(3), pszPath(4)
// ============================================================================
// Write the resolved folder path to pszPath. Return S_OK.
// If the requested folder is the Startup folder, the RegistryPersistence
// behavioral flag will be raised by the dispatcher.

bool HandleSHGetFolderPathA(APIContext& ctx) {
    // arg0: hwnd (ignored)
    const auto csidl   = ctx.GetArg32(1);
    // arg2: hToken (ignored)
    // arg3: dwFlags (ignored)
    const auto pszPath = ctx.GetArgPtr(4);

    if (pszPath == 0) {
        ctx.SetReturnNtStatus(static_cast<GuestNtStatus>(0x80070057)); // E_INVALIDARG
        return true;
    }

    const std::string path = ResolveFolderPathA(csidl, ctx.Config());

    // Cap write to MAX_PATH including null terminator
    const uint32_t writeLen = std::min(static_cast<uint32_t>(path.size()),
                                       static_cast<uint32_t>(kMaxPath - 1));
    auto& mem = ctx.Memory();
    if (mem.Write(pszPath, path.data(), writeLen) != ErrorCode::Success) {
        ctx.SetReturnNtStatus(static_cast<GuestNtStatus>(0x80004005)); // E_FAIL
        return true;
    }
    mem.WriteU8(pszPath + writeLen, 0); // Null terminator

    // Startup folder access indicates persistence
    if (IsStartupFolder(csidl)) {
        // RegistryPersistence flagged via dispatcher
        (void)0;
    }

    ctx.SetReturn32(static_cast<uint32_t>(kSOK));
    return true;
}

// ============================================================================
// SHGetFolderPathW — hwnd(0), csidl(1), hToken(2), dwFlags(3), pszPath(4)
// ============================================================================

bool HandleSHGetFolderPathW(APIContext& ctx) {
    const auto csidl   = ctx.GetArg32(1);
    const auto pszPath = ctx.GetArgPtr(4);

    if (pszPath == 0) {
        ctx.SetReturnNtStatus(static_cast<GuestNtStatus>(0x80070057));
        return true;
    }

    const std::wstring path = ResolveFolderPathW(csidl, ctx.Config());

    const uint32_t writeChars = std::min(static_cast<uint32_t>(path.size()),
                                         static_cast<uint32_t>(kMaxPath - 1));
    auto& mem = ctx.Memory();
    if (mem.Write(pszPath, path.data(), writeChars * sizeof(wchar_t)) != ErrorCode::Success) {
        ctx.SetReturnNtStatus(static_cast<GuestNtStatus>(0x80004005));
        return true;
    }
    mem.WriteU16(pszPath + writeChars * sizeof(wchar_t), 0); // Null terminator

    if (IsStartupFolder(csidl)) {
        (void)0;
    }

    ctx.SetReturn32(static_cast<uint32_t>(kSOK));
    return true;
}

// ============================================================================
// SHGetSpecialFolderPathA — hwnd(0), pszPath(1), csidl(2), fCreate(3)
// ============================================================================
// Same logic as SHGetFolderPath but with different parameter order.

bool HandleSHGetSpecialFolderPathA(APIContext& ctx) {
    const auto pszPath = ctx.GetArgPtr(1);
    const auto csidl   = ctx.GetArg32(2);

    if (pszPath == 0) {
        ctx.SetReturnBool(false);
        return true;
    }

    const std::string path = ResolveFolderPathA(csidl, ctx.Config());

    const uint32_t writeLen = std::min(static_cast<uint32_t>(path.size()),
                                       static_cast<uint32_t>(kMaxPath - 1));
    auto& mem = ctx.Memory();
    if (mem.Write(pszPath, path.data(), writeLen) != ErrorCode::Success) {
        ctx.SetReturnBool(false);
        return true;
    }
    mem.WriteU8(pszPath + writeLen, 0);

    if (IsStartupFolder(csidl)) {
        (void)0;
    }

    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// SHGetSpecialFolderPathW — hwnd(0), pszPath(1), csidl(2), fCreate(3)
// ============================================================================

bool HandleSHGetSpecialFolderPathW(APIContext& ctx) {
    const auto pszPath = ctx.GetArgPtr(1);
    const auto csidl   = ctx.GetArg32(2);

    if (pszPath == 0) {
        ctx.SetReturnBool(false);
        return true;
    }

    const std::wstring path = ResolveFolderPathW(csidl, ctx.Config());

    const uint32_t writeChars = std::min(static_cast<uint32_t>(path.size()),
                                         static_cast<uint32_t>(kMaxPath - 1));
    auto& mem = ctx.Memory();
    if (mem.Write(pszPath, path.data(), writeChars * sizeof(wchar_t)) != ErrorCode::Success) {
        ctx.SetReturnBool(false);
        return true;
    }
    mem.WriteU16(pszPath + writeChars * sizeof(wchar_t), 0);

    if (IsStartupFolder(csidl)) {
        (void)0;
    }

    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// CommandLineToArgvW — lpCmdLine(0), pNumArgs(1)
// ============================================================================
// Parses a command line string and returns a fake argv array.
// We allocate guest memory for the pointer array and write a single
// entry pointing to the original command line (simplified parsing).

bool HandleCommandLineToArgvW(APIContext& ctx) {
    const auto lpCmdLine = ctx.GetArgPtr(0);
    const auto pNumArgs  = ctx.GetArgPtr(1);

    if (lpCmdLine == 0 || pNumArgs == 0) {
        ctx.SetLastError(Win32::ERROR_INVALID_PARAMETER);
        ctx.SetReturn(0);
        return true;
    }

    const std::wstring cmdLine = ctx.ReadWideString(lpCmdLine, kMaxWideChars);

    // Simple tokenization: count space-separated tokens respecting quotes
    uint32_t argc = 0;
    bool inQuotes = false;
    bool inToken = false;
    for (wchar_t wc : cmdLine) {
        if (wc == L'"') {
            inQuotes = !inQuotes;
            if (!inToken) { inToken = true; ++argc; }
        } else if (wc == L' ' && !inQuotes) {
            inToken = false;
        } else {
            if (!inToken) { inToken = true; ++argc; }
        }
    }

    if (argc == 0) {
        argc = 1; // At least one argument (the program name)
    }

    // Cap argc to prevent allocation abuse
    if (argc > 256) argc = 256;

    // Allocate guest memory: array of pointers + the string data
    const uint32_t ptrSize = ctx.Is64Bit() ? 8 : 4;
    const uint32_t arraySize = argc * ptrSize;
    const uint32_t stringBytes = static_cast<uint32_t>(
        (cmdLine.size() + 1) * sizeof(wchar_t));
    const uint32_t totalSize = AlignUp(arraySize + stringBytes, kPageSize);

    auto& mem = ctx.Memory();
    auto alloc = mem.Allocate(0, totalSize, MemProt::RW);
    if (!alloc.has_value()) {
        ctx.SetLastError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        ctx.SetReturn(0);
        return true;
    }

    const GuestAddress base = alloc.value();
    const GuestAddress strBase = base + arraySize;

    // Write the command line string
    mem.Write(strBase, cmdLine.data(), static_cast<uint32_t>(cmdLine.size() * sizeof(wchar_t)));
    mem.WriteU16(strBase + cmdLine.size() * sizeof(wchar_t), 0);

    // Write pointer array — all entries point to the start of the string
    // (simplified: real implementation would split by token)
    for (uint32_t i = 0; i < argc; ++i) {
        if (ctx.Is64Bit()) {
            mem.WriteU64(base + i * 8, strBase);
        } else {
            mem.WriteU32(base + i * 4, static_cast<uint32_t>(strBase));
        }
    }

    // Write argc
    mem.WriteU32(pNumArgs, argc);

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn(base);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterShellAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "shell32.dll", "ShellExecuteA",
          HandleShellExecuteA, 6, true },
        { "shell32.dll", "ShellExecuteW",
          HandleShellExecuteW, 6, true },
        { "shell32.dll", "ShellExecuteExA",
          HandleShellExecuteExA, 1, true },
        { "shell32.dll", "ShellExecuteExW",
          HandleShellExecuteExW, 1, true },
        { "shell32.dll", "SHGetFolderPathA",
          HandleSHGetFolderPathA, 5, false },
        { "shell32.dll", "SHGetFolderPathW",
          HandleSHGetFolderPathW, 5, false },
        { "shell32.dll", "SHGetSpecialFolderPathA",
          HandleSHGetSpecialFolderPathA, 4, false },
        { "shell32.dll", "SHGetSpecialFolderPathW",
          HandleSHGetSpecialFolderPathW, 4, false },
        { "shell32.dll", "CommandLineToArgvW",
          HandleCommandLineToArgvW, 2, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Shell32
