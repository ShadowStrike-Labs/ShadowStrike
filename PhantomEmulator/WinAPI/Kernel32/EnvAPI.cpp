/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * EnvAPI.cpp — Kernel32 environment and system information API handlers
 *
 * Anti-evasion: All environment values emulate a realistic enterprise
 * Windows 10 workstation. Computer/user names come from EmulationConfig
 * and must never contain sandbox-revealing strings.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "EnvAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"

#include <algorithm>
#include <cstring>
#include <optional>
#include <string>

namespace Phantom::WinAPI::Kernel32 {

// ============================================================================
// Local Constants
// ============================================================================

namespace {

constexpr GuestDword kErrorBufferOverflow  = 111;
constexpr GuestDword kErrorEnvvarNotFound  = 203;
constexpr uint32_t   kMaxEnvValueLen       = 32768;
constexpr uint32_t   kMaxStringWrite       = 4096;

// Win32 VER_PLATFORM_WIN32_NT
constexpr uint32_t kVerPlatformWin32NT = 2;

// SYSTEM_INFO sizes
constexpr uint32_t kSystemInfoSize64 = 48;
constexpr uint32_t kSystemInfoSize32 = 36;

// PROCESSOR_ARCHITECTURE_AMD64
constexpr uint16_t kProcArchAMD64 = 9;
// PROCESSOR_ARCHITECTURE_INTEL
constexpr uint16_t kProcArchIntel = 0;

// OSVERSIONINFO sizes
constexpr uint32_t kOsVersionInfoSizeA   = 148;
constexpr uint32_t kOsVersionInfoExSizeA = 156;
constexpr uint32_t kOsVersionInfoSizeW   = 276;
constexpr uint32_t kOsVersionInfoExSizeW = 284;

// Processor feature IDs (subset)
constexpr uint32_t PF_COMPARE_EXCHANGE_DOUBLE        = 2;
constexpr uint32_t PF_MMX_INSTRUCTIONS_AVAILABLE     = 3;
constexpr uint32_t PF_XMMI_INSTRUCTIONS_AVAILABLE    = 6;  // SSE
constexpr uint32_t PF_RDTSC_INSTRUCTION_AVAILABLE    = 8;
constexpr uint32_t PF_PAE_ENABLED                    = 9;
constexpr uint32_t PF_XMMI64_INSTRUCTIONS_AVAILABLE  = 10; // SSE2
constexpr uint32_t PF_NX_ENABLED                     = 12;
constexpr uint32_t PF_SSE3_INSTRUCTIONS_AVAILABLE    = 13;
constexpr uint32_t PF_COMPARE_EXCHANGE128            = 14;
constexpr uint32_t PF_COMPARE64_EXCHANGE128          = 15;
constexpr uint32_t PF_XSAVE_ENABLED                  = 17;
constexpr uint32_t PF_RDWRFSGSBASE_AVAILABLE         = 22;
constexpr uint32_t PF_FASTFAIL_AVAILABLE             = 23;
constexpr uint32_t PF_RDRAND_INSTRUCTION_AVAILABLE   = 28;
constexpr uint32_t PF_SSSE3_INSTRUCTIONS_AVAILABLE   = 36;

// ============================================================================
// Helpers
// ============================================================================

std::string WideToNarrow(std::wstring_view wide) {
    std::string result;
    result.reserve(wide.size());
    for (wchar_t wc : wide) {
        result.push_back(wc > 127 ? '?' : static_cast<char>(wc));
    }
    return result;
}

bool WideEqualCI(std::wstring_view a, std::wstring_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        wchar_t ca = a[i], cb = b[i];
        if (ca >= L'A' && ca <= L'Z') ca += 32;
        if (cb >= L'A' && cb <= L'Z') cb += 32;
        if (ca != cb) return false;
    }
    return true;
}

std::wstring NarrowToWide(std::string_view narrow) {
    std::wstring result;
    result.reserve(narrow.size());
    for (char c : narrow) {
        result.push_back(static_cast<wchar_t>(static_cast<uint8_t>(c)));
    }
    return result;
}

std::optional<std::wstring> LookupEnvVar(std::wstring_view name,
                                          const EmulationConfig& config) {
    if (WideEqualCI(name, L"COMPUTERNAME"))
        return std::wstring(config.computerName);
    if (WideEqualCI(name, L"USERNAME"))
        return std::wstring(config.userName);
    if (WideEqualCI(name, L"USERDOMAIN"))
        return std::wstring(config.domainName);
    if (WideEqualCI(name, L"USERPROFILE"))
        return L"C:\\Users\\" + std::wstring(config.userName);
    if (WideEqualCI(name, L"SYSTEMROOT"))
        return std::wstring(L"C:\\Windows");
    if (WideEqualCI(name, L"WINDIR"))
        return std::wstring(L"C:\\Windows");
    if (WideEqualCI(name, L"TEMP") || WideEqualCI(name, L"TMP"))
        return L"C:\\Users\\" + std::wstring(config.userName) +
               L"\\AppData\\Local\\Temp";
    if (WideEqualCI(name, L"PATH"))
        return std::wstring(
            L"C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem");
    if (WideEqualCI(name, L"PROCESSOR_ARCHITECTURE"))
        return std::wstring(L"AMD64");
    if (WideEqualCI(name, L"NUMBER_OF_PROCESSORS"))
        return std::to_wstring(config.processorCount);
    if (WideEqualCI(name, L"OS"))
        return std::wstring(L"Windows_NT");
    if (WideEqualCI(name, L"COMSPEC"))
        return std::wstring(L"C:\\Windows\\system32\\cmd.exe");
    if (WideEqualCI(name, L"APPDATA"))
        return L"C:\\Users\\" + std::wstring(config.userName) +
               L"\\AppData\\Roaming";
    if (WideEqualCI(name, L"LOCALAPPDATA"))
        return L"C:\\Users\\" + std::wstring(config.userName) +
               L"\\AppData\\Local";
    if (WideEqualCI(name, L"PROGRAMFILES"))
        return std::wstring(L"C:\\Program Files");
    if (WideEqualCI(name, L"PROGRAMFILES(X86)"))
        return std::wstring(L"C:\\Program Files (x86)");

    return std::nullopt;
}

// Write raw bytes to guest at offset using memcpy-safe helpers
void WriteU16ToBuffer(uint8_t* buf, size_t off, uint16_t v) {
    std::memcpy(buf + off, &v, sizeof(v));
}

void WriteU32ToBuffer(uint8_t* buf, size_t off, uint32_t v) {
    std::memcpy(buf + off, &v, sizeof(v));
}

void WriteU64ToBuffer(uint8_t* buf, size_t off, uint64_t v) {
    std::memcpy(buf + off, &v, sizeof(v));
}

} // anonymous namespace

// ============================================================================
// Registration
// ============================================================================

void RegisterEnvAPI(APIDispatcher& dispatcher) noexcept {
    static const APIRegistration regs[] = {
        { "kernel32.dll", "GetComputerNameA",          HandleGetComputerNameA,          2, false },
        { "kernel32.dll", "GetComputerNameW",          HandleGetComputerNameW,          2, false },
        { "kernel32.dll", "GetUserNameA",              HandleGetUserNameA,              2, false },
        { "kernel32.dll", "GetUserNameW",              HandleGetUserNameW,              2, false },
        { "kernel32.dll", "GetSystemDirectoryA",       HandleGetSystemDirectoryA,       2, false },
        { "kernel32.dll", "GetSystemDirectoryW",       HandleGetSystemDirectoryW,       2, false },
        { "kernel32.dll", "GetWindowsDirectoryA",      HandleGetWindowsDirectoryA,      2, false },
        { "kernel32.dll", "GetWindowsDirectoryW",      HandleGetWindowsDirectoryW,      2, false },
        { "kernel32.dll", "GetEnvironmentVariableA",   HandleGetEnvironmentVariableA,   3, false },
        { "kernel32.dll", "GetEnvironmentVariableW",   HandleGetEnvironmentVariableW,   3, false },
        { "kernel32.dll", "GetVersionExA",             HandleGetVersionExA,             1, false },
        { "kernel32.dll", "GetVersionExW",             HandleGetVersionExW,             1, false },
        { "kernel32.dll", "GetVersion",                HandleGetVersion,                0, false },
        { "kernel32.dll", "GetSystemInfo",             HandleGetSystemInfo,             1, false },
        { "kernel32.dll", "GetNativeSystemInfo",       HandleGetNativeSystemInfo,       1, false },
        { "kernel32.dll", "IsProcessorFeaturePresent", HandleIsProcessorFeaturePresent, 1, false },
        { "kernel32.dll", "GetDiskFreeSpaceExA",       HandleGetDiskFreeSpaceExA,       4, false },
    };
    dispatcher.RegisterBatch(regs, static_cast<uint32_t>(std::size(regs)));
}

// ============================================================================
// GetComputerNameA/W
// ============================================================================

bool HandleGetComputerNameA(APIContext& ctx) {
    GuestAddress bufAddr  = ctx.GetArgPtr(0);
    GuestAddress sizeAddr = ctx.GetArgPtr(1);

    uint32_t bufSize = 0;
    if (ctx.Memory().ReadU32(sizeAddr, bufSize) != ErrorCode::Success) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    std::string name = WideToNarrow(ctx.Config().computerName);
    auto nameLen = static_cast<uint32_t>(name.size());

    if (bufSize <= nameLen) {
        ctx.Memory().WriteU32(sizeAddr, nameLen + 1);
        ctx.SetLastError(kErrorBufferOverflow);
        ctx.SetReturnBool(false);
        return true;
    }

    ctx.WriteAnsiString(bufAddr, name, bufSize);
    ctx.Memory().WriteU32(sizeAddr, nameLen);
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

bool HandleGetComputerNameW(APIContext& ctx) {
    GuestAddress bufAddr  = ctx.GetArgPtr(0);
    GuestAddress sizeAddr = ctx.GetArgPtr(1);

    uint32_t bufSize = 0;
    if (ctx.Memory().ReadU32(sizeAddr, bufSize) != ErrorCode::Success) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    const auto& name = ctx.Config().computerName;
    auto nameLen = static_cast<uint32_t>(name.size());

    if (bufSize <= nameLen) {
        ctx.Memory().WriteU32(sizeAddr, nameLen + 1);
        ctx.SetLastError(kErrorBufferOverflow);
        ctx.SetReturnBool(false);
        return true;
    }

    ctx.WriteWideString(bufAddr, name, bufSize);
    ctx.Memory().WriteU32(sizeAddr, nameLen);
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// GetUserNameA/W (advapi32 forwards through kernel32)
// ============================================================================

bool HandleGetUserNameA(APIContext& ctx) {
    GuestAddress bufAddr  = ctx.GetArgPtr(0);
    GuestAddress sizeAddr = ctx.GetArgPtr(1);

    uint32_t bufSize = 0;
    if (ctx.Memory().ReadU32(sizeAddr, bufSize) != ErrorCode::Success) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    std::string name = WideToNarrow(ctx.Config().userName);
    auto nameLen = static_cast<uint32_t>(name.size());
    uint32_t requiredSize = nameLen + 1; // includes null

    if (bufSize < requiredSize) {
        ctx.Memory().WriteU32(sizeAddr, requiredSize);
        ctx.SetLastError(Win32::ERROR_INSUFFICIENT_BUFFER);
        ctx.SetReturnBool(false);
        return true;
    }

    ctx.WriteAnsiString(bufAddr, name, bufSize);
    ctx.Memory().WriteU32(sizeAddr, requiredSize);
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

bool HandleGetUserNameW(APIContext& ctx) {
    GuestAddress bufAddr  = ctx.GetArgPtr(0);
    GuestAddress sizeAddr = ctx.GetArgPtr(1);

    uint32_t bufSize = 0;
    if (ctx.Memory().ReadU32(sizeAddr, bufSize) != ErrorCode::Success) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    const auto& name = ctx.Config().userName;
    auto nameLen = static_cast<uint32_t>(name.size());
    uint32_t requiredSize = nameLen + 1;

    if (bufSize < requiredSize) {
        ctx.Memory().WriteU32(sizeAddr, requiredSize);
        ctx.SetLastError(Win32::ERROR_INSUFFICIENT_BUFFER);
        ctx.SetReturnBool(false);
        return true;
    }

    ctx.WriteWideString(bufAddr, name, bufSize);
    ctx.Memory().WriteU32(sizeAddr, requiredSize);
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// GetSystemDirectoryA/W
// ============================================================================

bool HandleGetSystemDirectoryA(APIContext& ctx) {
    GuestAddress bufAddr = ctx.GetArgPtr(0);
    uint32_t     uSize   = ctx.GetArg32(1);

    static constexpr std::string_view kSysDir = "C:\\Windows\\System32";
    auto dirLen = static_cast<uint32_t>(kSysDir.size());

    if (uSize == 0 || bufAddr == 0) {
        ctx.SetReturn32(dirLen);
        return true;
    }

    if (uSize <= dirLen) {
        ctx.SetReturn32(dirLen + 1);
        return true;
    }

    ctx.WriteAnsiString(bufAddr, kSysDir, uSize);
    ctx.SetReturn32(dirLen);
    return true;
}

bool HandleGetSystemDirectoryW(APIContext& ctx) {
    GuestAddress bufAddr = ctx.GetArgPtr(0);
    uint32_t     uSize   = ctx.GetArg32(1);

    static constexpr std::wstring_view kSysDir = L"C:\\Windows\\System32";
    auto dirLen = static_cast<uint32_t>(kSysDir.size());

    if (uSize == 0 || bufAddr == 0) {
        ctx.SetReturn32(dirLen);
        return true;
    }

    if (uSize <= dirLen) {
        ctx.SetReturn32(dirLen + 1);
        return true;
    }

    ctx.WriteWideString(bufAddr, kSysDir, uSize);
    ctx.SetReturn32(dirLen);
    return true;
}

// ============================================================================
// GetWindowsDirectoryA/W
// ============================================================================

bool HandleGetWindowsDirectoryA(APIContext& ctx) {
    GuestAddress bufAddr = ctx.GetArgPtr(0);
    uint32_t     uSize   = ctx.GetArg32(1);

    static constexpr std::string_view kWinDir = "C:\\Windows";
    auto dirLen = static_cast<uint32_t>(kWinDir.size());

    if (uSize == 0 || bufAddr == 0) {
        ctx.SetReturn32(dirLen);
        return true;
    }

    if (uSize <= dirLen) {
        ctx.SetReturn32(dirLen + 1);
        return true;
    }

    ctx.WriteAnsiString(bufAddr, kWinDir, uSize);
    ctx.SetReturn32(dirLen);
    return true;
}

bool HandleGetWindowsDirectoryW(APIContext& ctx) {
    GuestAddress bufAddr = ctx.GetArgPtr(0);
    uint32_t     uSize   = ctx.GetArg32(1);

    static constexpr std::wstring_view kWinDir = L"C:\\Windows";
    auto dirLen = static_cast<uint32_t>(kWinDir.size());

    if (uSize == 0 || bufAddr == 0) {
        ctx.SetReturn32(dirLen);
        return true;
    }

    if (uSize <= dirLen) {
        ctx.SetReturn32(dirLen + 1);
        return true;
    }

    ctx.WriteWideString(bufAddr, kWinDir, uSize);
    ctx.SetReturn32(dirLen);
    return true;
}

// ============================================================================
// GetEnvironmentVariableA/W
// ============================================================================

bool HandleGetEnvironmentVariableA(APIContext& ctx) {
    GuestAddress nameAddr = ctx.GetArgPtr(0);
    GuestAddress bufAddr  = ctx.GetArgPtr(1);
    uint32_t     nSize    = ctx.GetArg32(2);

    std::string nameNarrow = ctx.ReadAnsiString(nameAddr, kMaxStringWrite);
    std::wstring nameWide  = NarrowToWide(nameNarrow);

    auto result = LookupEnvVar(nameWide, ctx.Config());
    if (!result) {
        ctx.SetLastError(kErrorEnvvarNotFound);
        ctx.SetReturn32(0);
        return true;
    }

    std::string value    = WideToNarrow(*result);
    auto        valueLen = static_cast<uint32_t>(value.size());

    if (nSize <= valueLen) {
        ctx.SetLastError(Win32::ERROR_INSUFFICIENT_BUFFER);
        ctx.SetReturn32(valueLen + 1);
        return true;
    }

    ctx.WriteAnsiString(bufAddr, value, nSize);
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn32(valueLen);
    return true;
}

bool HandleGetEnvironmentVariableW(APIContext& ctx) {
    GuestAddress nameAddr = ctx.GetArgPtr(0);
    GuestAddress bufAddr  = ctx.GetArgPtr(1);
    uint32_t     nSize    = ctx.GetArg32(2);

    std::wstring nameWide = ctx.ReadWideString(nameAddr, 2048);

    auto result = LookupEnvVar(nameWide, ctx.Config());
    if (!result) {
        ctx.SetLastError(kErrorEnvvarNotFound);
        ctx.SetReturn32(0);
        return true;
    }

    auto valueLen = static_cast<uint32_t>(result->size());

    if (nSize <= valueLen) {
        ctx.SetLastError(Win32::ERROR_INSUFFICIENT_BUFFER);
        ctx.SetReturn32(valueLen + 1);
        return true;
    }

    ctx.WriteWideString(bufAddr, *result, nSize);
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn32(valueLen);
    return true;
}

// ============================================================================
// GetVersionExA/W
// ============================================================================

bool HandleGetVersionExA(APIContext& ctx) {
    GuestAddress addr = ctx.GetArgPtr(0);
    if (addr == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    uint32_t infoSize = 0;
    ctx.Memory().ReadU32(addr, infoSize);

    if (infoSize != kOsVersionInfoSizeA && infoSize != kOsVersionInfoExSizeA) {
        ctx.FailWithError(Win32::ERROR_INSUFFICIENT_BUFFER);
        return true;
    }

    auto& mem = ctx.Memory();
    uint32_t buildNum = ctx.Config().osBuildNumber;

    // Common OSVERSIONINFOA fields
    mem.WriteU32(addr + 4,  10);               // dwMajorVersion
    mem.WriteU32(addr + 8,  0);                // dwMinorVersion
    mem.WriteU32(addr + 12, buildNum);         // dwBuildNumber
    mem.WriteU32(addr + 16, kVerPlatformWin32NT); // dwPlatformId

    // szCSDVersion[128]: empty (no service pack)
    uint8_t zeros[128] = {};
    mem.Write(addr + 20, zeros, 128);

    // OSVERSIONINFOEXA extended fields
    if (infoSize == kOsVersionInfoExSizeA) {
        mem.WriteU16(addr + 148, 0);           // wServicePackMajor
        mem.WriteU16(addr + 150, 0);           // wServicePackMinor
        mem.WriteU16(addr + 152, 0x0300);      // wSuiteMask
        mem.WriteU8(addr + 154, 1);            // wProductType = VER_NT_WORKSTATION
        mem.WriteU8(addr + 155, 0);            // wReserved
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

bool HandleGetVersionExW(APIContext& ctx) {
    GuestAddress addr = ctx.GetArgPtr(0);
    if (addr == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    uint32_t infoSize = 0;
    ctx.Memory().ReadU32(addr, infoSize);

    if (infoSize != kOsVersionInfoSizeW && infoSize != kOsVersionInfoExSizeW) {
        ctx.FailWithError(Win32::ERROR_INSUFFICIENT_BUFFER);
        return true;
    }

    auto& mem = ctx.Memory();
    uint32_t buildNum = ctx.Config().osBuildNumber;

    mem.WriteU32(addr + 4,  10);
    mem.WriteU32(addr + 8,  0);
    mem.WriteU32(addr + 12, buildNum);
    mem.WriteU32(addr + 16, kVerPlatformWin32NT);

    // szCSDVersion[128] as WCHAR = 256 bytes of zeros
    uint8_t zeros[256] = {};
    mem.Write(addr + 20, zeros, 256);

    if (infoSize == kOsVersionInfoExSizeW) {
        mem.WriteU16(addr + 276, 0);           // wServicePackMajor
        mem.WriteU16(addr + 278, 0);           // wServicePackMinor
        mem.WriteU16(addr + 280, 0x0300);      // wSuiteMask
        mem.WriteU8(addr + 282, 1);            // wProductType = VER_NT_WORKSTATION
        mem.WriteU8(addr + 283, 0);            // wReserved
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// GetVersion (legacy)
// ============================================================================

bool HandleGetVersion(APIContext& ctx) {
    // Return format: MAKELONG(MAKEWORD(major, minor), build)
    // Low byte of low word  = major version (10)
    // High byte of low word = minor version (0)
    // High word             = build number
    uint32_t buildNum = ctx.Config().osBuildNumber;
    uint32_t result = (buildNum << 16) | (0 << 8) | 10;
    ctx.SetReturn32(result);
    return true;
}

// ============================================================================
// GetSystemInfo / GetNativeSystemInfo
// ============================================================================

static bool FillSystemInfo(APIContext& ctx) {
    GuestAddress addr = ctx.GetArgPtr(0);
    if (addr == 0) {
        return true;
    }

    uint32_t procCount = ctx.Config().processorCount;
    if (procCount == 0) procCount = 1;
    if (procCount > 64) procCount = 64;

    if (ctx.Is64Bit()) {
        uint8_t buf[kSystemInfoSize64] = {};
        WriteU16ToBuffer(buf, 0,  kProcArchAMD64);       // wProcessorArchitecture
        // wReserved = 0 at offset 2
        WriteU32ToBuffer(buf, 4,  4096);                  // dwPageSize
        WriteU64ToBuffer(buf, 8,  0x10000);               // lpMinimumApplicationAddress
        WriteU64ToBuffer(buf, 16, 0x7FFFFFFEFFFFULL);     // lpMaximumApplicationAddress
        uint64_t mask = (procCount >= 64) ? ~0ULL : ((1ULL << procCount) - 1);
        WriteU64ToBuffer(buf, 24, mask);                  // dwActiveProcessorMask
        WriteU32ToBuffer(buf, 32, procCount);             // dwNumberOfProcessors
        WriteU32ToBuffer(buf, 36, 8664);                  // dwProcessorType (AMD64)
        WriteU32ToBuffer(buf, 40, 65536);                 // dwAllocationGranularity
        WriteU16ToBuffer(buf, 44, 6);                     // wProcessorLevel (Family 6)
        WriteU16ToBuffer(buf, 46, 0x0A05);                // wProcessorRevision
        ctx.Memory().Write(addr, buf, kSystemInfoSize64);
    } else {
        uint8_t buf[kSystemInfoSize32] = {};
        WriteU16ToBuffer(buf, 0,  kProcArchIntel);        // wProcessorArchitecture
        WriteU32ToBuffer(buf, 4,  4096);                  // dwPageSize
        WriteU32ToBuffer(buf, 8,  0x10000);               // lpMinimumApplicationAddress
        WriteU32ToBuffer(buf, 12, 0x7FFEFFFF);            // lpMaximumApplicationAddress
        uint32_t mask32 = (procCount >= 32) ? ~0U : ((1U << procCount) - 1);
        WriteU32ToBuffer(buf, 16, mask32);                // dwActiveProcessorMask
        WriteU32ToBuffer(buf, 20, procCount);             // dwNumberOfProcessors
        WriteU32ToBuffer(buf, 24, 586);                   // dwProcessorType (Pentium)
        WriteU32ToBuffer(buf, 28, 65536);                 // dwAllocationGranularity
        WriteU16ToBuffer(buf, 32, 6);                     // wProcessorLevel
        WriteU16ToBuffer(buf, 34, 0x0A05);                // wProcessorRevision
        ctx.Memory().Write(addr, buf, kSystemInfoSize32);
    }

    return true;
}

bool HandleGetSystemInfo(APIContext& ctx) {
    return FillSystemInfo(ctx);
}

bool HandleGetNativeSystemInfo(APIContext& ctx) {
    return FillSystemInfo(ctx);
}

// ============================================================================
// IsProcessorFeaturePresent
// ============================================================================

bool HandleIsProcessorFeaturePresent(APIContext& ctx) {
    uint32_t feature = ctx.GetArg32(0);

    bool present = false;
    switch (feature) {
        case PF_COMPARE_EXCHANGE_DOUBLE:
        case PF_MMX_INSTRUCTIONS_AVAILABLE:
        case PF_XMMI_INSTRUCTIONS_AVAILABLE:    // SSE
        case PF_RDTSC_INSTRUCTION_AVAILABLE:
        case PF_PAE_ENABLED:
        case PF_XMMI64_INSTRUCTIONS_AVAILABLE:  // SSE2
        case PF_NX_ENABLED:
        case PF_SSE3_INSTRUCTIONS_AVAILABLE:
        case PF_COMPARE_EXCHANGE128:
        case PF_COMPARE64_EXCHANGE128:
        case PF_XSAVE_ENABLED:
        case PF_RDWRFSGSBASE_AVAILABLE:
        case PF_FASTFAIL_AVAILABLE:
        case PF_RDRAND_INSTRUCTION_AVAILABLE:
        case PF_SSSE3_INSTRUCTIONS_AVAILABLE:
            present = true;
            break;
        default:
            present = false;
            break;
    }

    ctx.SetReturnBool(present);
    return true;
}

// ============================================================================
// GetDiskFreeSpaceExA
// ============================================================================

bool HandleGetDiskFreeSpaceExA(APIContext& ctx) {
    // arg0: lpDirectoryName (ignored — always report C: drive)
    GuestAddress freeAvailAddr = ctx.GetArgPtr(1);
    GuestAddress totalAddr     = ctx.GetArgPtr(2);
    GuestAddress totalFreeAddr = ctx.GetArgPtr(3);

    // Anti-evasion: realistic disk sizes for an enterprise workstation
    constexpr uint64_t kTotalBytes = 256ULL * 1024 * 1024 * 1024;  // 256 GB
    constexpr uint64_t kFreeBytes  = 180ULL * 1024 * 1024 * 1024;  // 180 GB

    if (freeAvailAddr != 0) {
        ctx.Memory().WriteU64(freeAvailAddr, kFreeBytes);
    }
    if (totalAddr != 0) {
        ctx.Memory().WriteU64(totalAddr, kTotalBytes);
    }
    if (totalFreeAddr != 0) {
        ctx.Memory().WriteU64(totalFreeAddr, kFreeBytes);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

} // namespace Phantom::WinAPI::Kernel32
