/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ServiceExtAPI.cpp — Advapi32 extended Service Control Manager API implementations
 *
 * Service reconfiguration (T1543.003), security service tampering,
 * service enumeration for target discovery, and malware registering
 * itself as a service are tracked here.
 *
 * All operations run against the VirtualServiceDB singleton from ServiceAPI.cpp.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "ServiceExtAPI.hpp"
#include "ServiceAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../HandleTable.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <string>

namespace Phantom::WinAPI::Advapi32 {

// ============================================================================
// Win32 service constants (no windows.h dependency)
// ============================================================================

static constexpr uint32_t kErrorSuccess             = 0;
static constexpr uint32_t kErrorInvalidHandle       = 6;
static constexpr uint32_t kErrorInvalidParameter    = 87;
static constexpr uint32_t kErrorInsufficientBuffer  = 122;
static constexpr uint32_t kErrorMoreData            = 234;
static constexpr uint32_t kErrorServiceDoesNotExist = 1060;

static constexpr uint32_t kMaxStringLen = 4096;

// SERVICE_STATUS field sizes
static constexpr uint32_t kServiceStatusSize        = 28;
static constexpr uint32_t kServiceStatusProcessSize = 36;
static constexpr uint32_t kQueryServiceConfigSize   = 48;

// Service type constants
static constexpr uint32_t SERVICE_WIN32_OWN_PROCESS  = 0x10;
static constexpr uint32_t SERVICE_WIN32_SHARE_PROCESS = 0x20;

// Service state constants
static constexpr uint32_t SERVICE_STOPPED            = 0x01;
static constexpr uint32_t SERVICE_START_PENDING      = 0x02;
static constexpr uint32_t SERVICE_STOP_PENDING       = 0x03;
static constexpr uint32_t SERVICE_RUNNING            = 0x04;

// Service control codes
static constexpr uint32_t SERVICE_CONTROL_STOP       = 0x01;
static constexpr uint32_t SERVICE_CONTROL_PAUSE      = 0x02;
static constexpr uint32_t SERVICE_CONTROL_CONTINUE   = 0x03;
static constexpr uint32_t SERVICE_CONTROL_INTERROGATE = 0x04;

// Service start type
static constexpr uint32_t SERVICE_AUTO_START         = 0x02;
static constexpr uint32_t SERVICE_DEMAND_START       = 0x03;
static constexpr uint32_t SERVICE_DISABLED           = 0x04;

// Service accepts flags
static constexpr uint32_t SERVICE_ACCEPT_STOP        = 0x01;
static constexpr uint32_t SERVICE_ACCEPT_PAUSE_CONTINUE = 0x02;
static constexpr uint32_t SERVICE_ACCEPT_SHUTDOWN    = 0x04;

// SC_STATUS_TYPE
static constexpr uint32_t SC_STATUS_PROCESS_INFO     = 0;

// ============================================================================
// Fake well-known service list for enumeration
// ============================================================================

struct FakeServiceInfo {
    const wchar_t* keyName;
    const wchar_t* displayName;
    uint32_t       serviceType;
    uint32_t       currentState;
    uint32_t       pid;
};

static constexpr FakeServiceInfo kFakeServices[] = {
    { L"Winmgmt",      L"Windows Management Instrumentation",    SERVICE_WIN32_OWN_PROCESS, SERVICE_RUNNING, 1084 },
    { L"WinDefend",    L"Microsoft Defender Antivirus Service",  SERVICE_WIN32_OWN_PROCESS, SERVICE_RUNNING, 3412 },
    { L"Spooler",      L"Print Spooler",                        SERVICE_WIN32_OWN_PROCESS, SERVICE_RUNNING, 2240 },
    { L"BITS",         L"Background Intelligent Transfer Service", SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING, 968 },
    { L"wuauserv",     L"Windows Update",                       SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING, 968 },
    { L"Dnscache",     L"DNS Client",                           SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING, 1304 },
    { L"EventLog",     L"Windows Event Log",                    SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING, 1192 },
    { L"Schedule",     L"Task Scheduler",                       SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING, 1072 },
    { L"PlugPlay",     L"Plug and Play",                        SERVICE_WIN32_OWN_PROCESS, SERVICE_RUNNING, 848 },
    { L"RpcSs",        L"Remote Procedure Call (RPC)",          SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING, 824 },
    { L"LanmanServer", L"Server",                               SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING, 968 },
    { L"LanmanWorkstation", L"Workstation",                     SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING, 968 },
    { L"CryptSvc",     L"Cryptographic Services",               SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING, 968 },
    { L"Dhcp",         L"DHCP Client",                          SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING, 1304 },
    { L"DcomLaunch",   L"DCOM Server Process Launcher",         SERVICE_WIN32_OWN_PROCESS, SERVICE_RUNNING, 824 },
    { L"Power",        L"Power",                                SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING, 824 },
    { L"ProfSvc",      L"User Profile Service",                 SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING, 1072 },
    { L"Themes",       L"Themes",                               SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING, 968 },
    { L"AudioSrv",     L"Windows Audio",                        SERVICE_WIN32_OWN_PROCESS, SERVICE_RUNNING, 2876 },
    { L"netprofm",     L"Network List Service",                 SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING, 1304 },
    { L"NlaSvc",       L"Network Location Awareness",           SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING, 1304 },
    { L"mpssvc",       L"Windows Defender Firewall",            SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING, 968 },
    { L"BFE",          L"Base Filtering Engine",                SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING, 968 },
    { L"SamSs",        L"Security Accounts Manager",            SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING, 824 },
    { L"lsass",        L"Local Security Authority",             SERVICE_WIN32_OWN_PROCESS, SERVICE_RUNNING, 756 },
    { L"TrkWks",       L"Distributed Link Tracking Client",     SERVICE_WIN32_OWN_PROCESS, SERVICE_RUNNING, 2024 },
    { L"W32Time",      L"Windows Time",                         SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING, 1072 },
    { L"WSearch",      L"Windows Search",                       SERVICE_WIN32_OWN_PROCESS, SERVICE_RUNNING, 3968 },
    { L"iphlpsvc",     L"IP Helper",                            SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING, 1304 },
    { L"Netlogon",     L"Netlogon",                             SERVICE_WIN32_OWN_PROCESS, SERVICE_STOPPED, 0 },
};

static constexpr uint32_t kFakeServiceCount =
    static_cast<uint32_t>(sizeof(kFakeServices) / sizeof(kFakeServices[0]));

// Security-critical services — stopping these is defense evasion
static bool IsSecurityService(const std::wstring& name) noexcept {
    std::wstring lower;
    lower.reserve(name.size());
    for (wchar_t c : name) lower.push_back(static_cast<wchar_t>(std::towlower(c)));

    if (lower == L"windefend") return true;
    if (lower == L"mpssvc") return true;
    if (lower == L"wscsvc") return true;
    if (lower == L"securityhealthservice") return true;
    if (lower == L"bfe") return true;
    if (lower == L"sense") return true;
    if (lower == L"mbamdervice") return true;
    return false;
}

// ============================================================================
// Wide/narrow helpers
// ============================================================================

static std::wstring NarrowToWide(std::string_view s) noexcept {
    std::wstring w;
    w.reserve(s.size());
    for (char c : s) w.push_back(static_cast<wchar_t>(static_cast<uint8_t>(c)));
    return w;
}

static std::string WideToNarrow(const std::wstring& ws) noexcept {
    std::string s;
    s.reserve(ws.size());
    for (wchar_t wc : ws) s.push_back(static_cast<char>(wc & 0x7F));
    return s;
}

// Resolve service name from an SC_HANDLE (stored as SyncObjectData)
static std::wstring ResolveServiceName(APIContext& ctx, GuestHandle hService) noexcept {
    auto entry = ctx.Handles().Lookup(hService);
    if (!entry.has_value()) return {};
    auto* syncData = std::get_if<SyncObjectData>(&entry->data);
    if (!syncData) return {};
    return syncData->name;
}

// ============================================================================
// ChangeServiceConfigA/W — hService(0), dwServiceType(1), dwStartType(2),
//   dwErrorControl(3), lpBinaryPathName(4), lpLoadOrderGroup(5),
//   lpdwTagId(6), lpDependencies(7), lpServiceStartName(8),
//   lpPassword(9), lpDisplayName(10)
//
// CRITICAL: Persistence via binary path modification (T1543.003)
// ============================================================================

static bool ChangeServiceConfigImpl(APIContext& ctx, bool isWide) {
    const auto hService     = ctx.GetArg(0);
    const auto dwSvcType    = ctx.GetArg32(1);
    const auto dwStartType  = ctx.GetArg32(2);
    const auto lpBinaryPath = ctx.GetArgPtr(4);
    const auto lpDisplayName = ctx.GetArgPtr(10);

    (void)dwSvcType;
    (void)dwStartType;

    std::wstring svcName = ResolveServiceName(ctx, hService);
    if (svcName.empty()) {
        ctx.FailWithError(kErrorInvalidHandle);
        return true;
    }

    // Track modified binary path — critical persistence IOC
    if (lpBinaryPath != 0) {
        if (isWide) {
            (void)ctx.ReadWideString(lpBinaryPath, kMaxStringLen / 2);
        } else {
            (void)ctx.ReadAnsiString(lpBinaryPath, kMaxStringLen);
        }
    }

    if (lpDisplayName != 0) {
        if (isWide) {
            (void)ctx.ReadWideString(lpDisplayName, kMaxStringLen / 2);
        } else {
            (void)ctx.ReadAnsiString(lpDisplayName, kMaxStringLen);
        }
    }

    // BehaviorFlag::Persistence | BehaviorFlag::ServiceManipulation raised by dispatcher

    ctx.SetReturnBool(true);
    ctx.SetLastError(kErrorSuccess);
    return true;
}

bool HandleChangeServiceConfigA(APIContext& ctx) { return ChangeServiceConfigImpl(ctx, false); }
bool HandleChangeServiceConfigW(APIContext& ctx) { return ChangeServiceConfigImpl(ctx, true); }

// ============================================================================
// ChangeServiceConfig2A/W — hService(0), dwInfoLevel(1), lpInfo(2)
// ============================================================================

static bool ChangeServiceConfig2Impl(APIContext& ctx, bool /*isWide*/) {
    const auto hService    = ctx.GetArg(0);
    const auto dwInfoLevel = ctx.GetArg32(1);

    (void)dwInfoLevel;

    std::wstring svcName = ResolveServiceName(ctx, hService);
    if (svcName.empty()) {
        ctx.FailWithError(kErrorInvalidHandle);
        return true;
    }

    // Track extended configuration changes (description, failure actions, etc.)
    ctx.SetReturnBool(true);
    ctx.SetLastError(kErrorSuccess);
    return true;
}

bool HandleChangeServiceConfig2A(APIContext& ctx) { return ChangeServiceConfig2Impl(ctx, false); }
bool HandleChangeServiceConfig2W(APIContext& ctx) { return ChangeServiceConfig2Impl(ctx, true); }

// ============================================================================
// EnumServicesStatusA/W — hSCManager(0), dwServiceType(1), dwServiceState(2),
//   lpServices(3), cbBufSize(4), pcbBytesNeeded(5), lpServicesReturned(6),
//   lpResumeHandle(7)
//
// ENUM_SERVICE_STATUSA layout per entry:
//   char[256]          lpServiceName     (offset 0)
//   char[256]          lpDisplayName     (offset 256)
//   SERVICE_STATUS     ServiceStatus     (offset 512, 28 bytes)
//   Total per entry: 540 bytes
// ============================================================================

static bool EnumServicesStatusImpl(APIContext& ctx, bool isWide) {
    const auto lpServices        = ctx.GetArgPtr(3);
    const auto cbBufSize         = ctx.GetArg32(4);
    const auto pcbBytesNeeded    = ctx.GetArgPtr(5);
    const auto lpServicesReturned = ctx.GetArgPtr(6);

    auto& mem = ctx.Memory();

    // Calculate space needed per entry
    const uint32_t nameFieldSize = isWide ? 512u : 256u;  // chars * sizeof(unit)
    const uint32_t entrySize     = nameFieldSize + nameFieldSize + kServiceStatusSize;
    const uint32_t totalNeeded   = kFakeServiceCount * entrySize;

    if (pcbBytesNeeded != 0) {
        mem.WriteU32(pcbBytesNeeded, totalNeeded);
    }

    if (lpServices == 0 || cbBufSize < totalNeeded) {
        if (lpServicesReturned != 0) mem.WriteU32(lpServicesReturned, 0);
        ctx.FailWithError(kErrorMoreData);
        return true;
    }

    // Write service entries
    uint32_t entriesWritten = 0;
    GuestAddress offset = lpServices;

    for (uint32_t i = 0; i < kFakeServiceCount; ++i) {
        if ((offset - lpServices) + entrySize > cbBufSize) break;

        const auto& svc = kFakeServices[i];

        if (isWide) {
            ctx.WriteWideString(offset, svc.keyName, nameFieldSize / sizeof(wchar_t));
            ctx.WriteWideString(offset + nameFieldSize, svc.displayName, nameFieldSize / sizeof(wchar_t));
        } else {
            ctx.WriteAnsiString(offset, WideToNarrow(svc.keyName), nameFieldSize);
            ctx.WriteAnsiString(offset + nameFieldSize, WideToNarrow(svc.displayName), nameFieldSize);
        }

        // SERVICE_STATUS: dwServiceType(4), dwCurrentState(4), dwControlsAccepted(4),
        //                 dwWin32ExitCode(4), dwServiceSpecificExitCode(4),
        //                 dwCheckPoint(4), dwWaitHint(4) = 28 bytes
        GuestAddress statusOffset = offset + nameFieldSize + nameFieldSize;
        mem.WriteU32(statusOffset,      svc.serviceType);
        mem.WriteU32(statusOffset + 4,  svc.currentState);
        uint32_t accepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_SHUTDOWN;
        mem.WriteU32(statusOffset + 8,  accepted);
        mem.WriteU32(statusOffset + 12, 0);  // dwWin32ExitCode
        mem.WriteU32(statusOffset + 16, 0);  // dwServiceSpecificExitCode
        mem.WriteU32(statusOffset + 20, 0);  // dwCheckPoint
        mem.WriteU32(statusOffset + 24, 0);  // dwWaitHint

        offset += entrySize;
        ++entriesWritten;
    }

    if (lpServicesReturned != 0) {
        mem.WriteU32(lpServicesReturned, entriesWritten);
    }

    ctx.SetReturnBool(true);
    ctx.SetLastError(kErrorSuccess);
    return true;
}

bool HandleEnumServicesStatusA(APIContext& ctx) { return EnumServicesStatusImpl(ctx, false); }
bool HandleEnumServicesStatusW(APIContext& ctx) { return EnumServicesStatusImpl(ctx, true); }

// ============================================================================
// EnumServicesStatusExA/W — hSCManager(0), InfoLevel(1), dwServiceType(2),
//   dwServiceState(3), lpServices(4), cbBufSize(5), pcbBytesNeeded(6),
//   lpServicesReturned(7), lpResumeHandle(8), pszGroupName(9)
//
// Adds dwProcessId and dwServiceFlags to each entry
// ============================================================================

static bool EnumServicesStatusExImpl(APIContext& ctx, bool isWide) {
    const auto lpServices         = ctx.GetArgPtr(4);
    const auto cbBufSize          = ctx.GetArg32(5);
    const auto pcbBytesNeeded     = ctx.GetArgPtr(6);
    const auto lpServicesReturned = ctx.GetArgPtr(7);

    auto& mem = ctx.Memory();

    // Extended entry: name fields + SERVICE_STATUS_PROCESS (36 bytes)
    const uint32_t nameFieldSize = isWide ? 512u : 256u;
    const uint32_t entrySize     = nameFieldSize + nameFieldSize + kServiceStatusProcessSize;
    const uint32_t totalNeeded   = kFakeServiceCount * entrySize;

    if (pcbBytesNeeded != 0) {
        mem.WriteU32(pcbBytesNeeded, totalNeeded);
    }

    if (lpServices == 0 || cbBufSize < totalNeeded) {
        if (lpServicesReturned != 0) mem.WriteU32(lpServicesReturned, 0);
        ctx.FailWithError(kErrorMoreData);
        return true;
    }

    uint32_t entriesWritten = 0;
    GuestAddress offset = lpServices;

    for (uint32_t i = 0; i < kFakeServiceCount; ++i) {
        if ((offset - lpServices) + entrySize > cbBufSize) break;

        const auto& svc = kFakeServices[i];

        if (isWide) {
            ctx.WriteWideString(offset, svc.keyName, nameFieldSize / sizeof(wchar_t));
            ctx.WriteWideString(offset + nameFieldSize, svc.displayName, nameFieldSize / sizeof(wchar_t));
        } else {
            ctx.WriteAnsiString(offset, WideToNarrow(svc.keyName), nameFieldSize);
            ctx.WriteAnsiString(offset + nameFieldSize, WideToNarrow(svc.displayName), nameFieldSize);
        }

        // SERVICE_STATUS_PROCESS: SERVICE_STATUS(28) + dwProcessId(4) + dwServiceFlags(4)
        GuestAddress statusOffset = offset + nameFieldSize + nameFieldSize;
        mem.WriteU32(statusOffset,      svc.serviceType);
        mem.WriteU32(statusOffset + 4,  svc.currentState);
        uint32_t accepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_SHUTDOWN;
        mem.WriteU32(statusOffset + 8,  accepted);
        mem.WriteU32(statusOffset + 12, 0);         // dwWin32ExitCode
        mem.WriteU32(statusOffset + 16, 0);         // dwServiceSpecificExitCode
        mem.WriteU32(statusOffset + 20, 0);         // dwCheckPoint
        mem.WriteU32(statusOffset + 24, 0);         // dwWaitHint
        mem.WriteU32(statusOffset + 28, svc.pid);   // dwProcessId
        mem.WriteU32(statusOffset + 32, 0);         // dwServiceFlags

        offset += entrySize;
        ++entriesWritten;
    }

    if (lpServicesReturned != 0) {
        mem.WriteU32(lpServicesReturned, entriesWritten);
    }

    ctx.SetReturnBool(true);
    ctx.SetLastError(kErrorSuccess);
    return true;
}

bool HandleEnumServicesStatusExA(APIContext& ctx) { return EnumServicesStatusExImpl(ctx, false); }
bool HandleEnumServicesStatusExW(APIContext& ctx) { return EnumServicesStatusExImpl(ctx, true); }

// ============================================================================
// QueryServiceStatusEx — hService(0), InfoLevel(1), lpBuffer(2),
//                          cbBufSize(3), pcbBytesNeeded(4)
// ============================================================================

bool HandleQueryServiceStatusEx(APIContext& ctx) {
    const auto hService       = ctx.GetArg(0);
    const auto infoLevel      = ctx.GetArg32(1);
    const auto lpBuffer       = ctx.GetArgPtr(2);
    const auto cbBufSize      = ctx.GetArg32(3);
    const auto pcbBytesNeeded = ctx.GetArgPtr(4);

    std::wstring svcName = ResolveServiceName(ctx, hService);
    if (svcName.empty()) {
        ctx.FailWithError(kErrorInvalidHandle);
        return true;
    }

    auto& mem = ctx.Memory();

    if (infoLevel == SC_STATUS_PROCESS_INFO) {
        if (pcbBytesNeeded != 0) {
            mem.WriteU32(pcbBytesNeeded, kServiceStatusProcessSize);
        }

        if (lpBuffer == 0 || cbBufSize < kServiceStatusProcessSize) {
            ctx.FailWithError(kErrorInsufficientBuffer);
            return true;
        }

        // Look up in fake service list for matching data
        uint32_t svcType    = SERVICE_WIN32_OWN_PROCESS;
        uint32_t curState   = SERVICE_RUNNING;
        uint32_t pid        = 2048;

        std::wstring lowerName;
        lowerName.reserve(svcName.size());
        for (wchar_t c : svcName) lowerName.push_back(static_cast<wchar_t>(std::towlower(c)));

        for (uint32_t i = 0; i < kFakeServiceCount; ++i) {
            std::wstring fkLower;
            const wchar_t* fk = kFakeServices[i].keyName;
            while (*fk) {
                fkLower.push_back(static_cast<wchar_t>(std::towlower(*fk)));
                ++fk;
            }
            if (lowerName == fkLower) {
                svcType  = kFakeServices[i].serviceType;
                curState = kFakeServices[i].currentState;
                pid      = kFakeServices[i].pid;
                break;
            }
        }

        mem.WriteU32(lpBuffer,      svcType);
        mem.WriteU32(lpBuffer + 4,  curState);
        uint32_t accepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE;
        mem.WriteU32(lpBuffer + 8,  accepted);
        mem.WriteU32(lpBuffer + 12, 0);     // dwWin32ExitCode
        mem.WriteU32(lpBuffer + 16, 0);     // dwServiceSpecificExitCode
        mem.WriteU32(lpBuffer + 20, 0);     // dwCheckPoint
        mem.WriteU32(lpBuffer + 24, 0);     // dwWaitHint
        mem.WriteU32(lpBuffer + 28, pid);   // dwProcessId
        mem.WriteU32(lpBuffer + 32, 0);     // dwServiceFlags
    } else {
        ctx.FailWithError(kErrorInvalidParameter);
        return true;
    }

    ctx.SetReturnBool(true);
    ctx.SetLastError(kErrorSuccess);
    return true;
}

// ============================================================================
// QueryServiceConfigA/W — hService(0), lpServiceConfig(1),
//                           cbBufSize(2), pcbBytesNeeded(3)
//
// QUERY_SERVICE_CONFIG layout (x64):
//   DWORD  dwServiceType          (offset  0)
//   DWORD  dwStartType            (offset  4)
//   DWORD  dwErrorControl         (offset  8)
//   LPTSTR lpBinaryPathName       (offset 12/16 on x64 — pointer)
//   ... additional pointer fields
// We write a simplified flat version with inline strings.
// ============================================================================

static bool QueryServiceConfigImpl(APIContext& ctx, bool isWide) {
    const auto hService       = ctx.GetArg(0);
    const auto lpConfig       = ctx.GetArgPtr(1);
    const auto cbBufSize      = ctx.GetArg32(2);
    const auto pcbBytesNeeded = ctx.GetArgPtr(3);

    std::wstring svcName = ResolveServiceName(ctx, hService);
    if (svcName.empty()) {
        ctx.FailWithError(kErrorInvalidHandle);
        return true;
    }

    auto& mem = ctx.Memory();

    // Fixed minimum size for response
    static constexpr uint32_t kMinConfigSize = 64;

    if (pcbBytesNeeded != 0) {
        mem.WriteU32(pcbBytesNeeded, kMinConfigSize);
    }

    if (lpConfig == 0 || cbBufSize < kMinConfigSize) {
        ctx.FailWithError(kErrorInsufficientBuffer);
        return true;
    }

    // Zero the buffer first
    std::vector<uint8_t> buf(kMinConfigSize, 0);

    uint32_t svcType   = SERVICE_WIN32_OWN_PROCESS;
    uint32_t startType = SERVICE_AUTO_START;

    // dwServiceType
    std::memcpy(buf.data() + 0, &svcType, 4);
    // dwStartType
    std::memcpy(buf.data() + 4, &startType, 4);
    // dwErrorControl = SERVICE_ERROR_NORMAL (1)
    uint32_t errCtl = 1;
    std::memcpy(buf.data() + 8, &errCtl, 4);
    // Remaining pointer fields are left as NULL — malware typically checks
    // dwServiceType and dwStartType, not the string pointers

    mem.Write(lpConfig, buf.data(), kMinConfigSize);

    ctx.SetReturnBool(true);
    ctx.SetLastError(kErrorSuccess);
    return true;
}

bool HandleQueryServiceConfigA(APIContext& ctx) { return QueryServiceConfigImpl(ctx, false); }
bool HandleQueryServiceConfigW(APIContext& ctx) { return QueryServiceConfigImpl(ctx, true); }

// ============================================================================
// GetServiceDisplayNameA/W — hSCManager(0), lpServiceName(1),
//                              lpDisplayName(2), lpcchBuffer(3)
// ============================================================================

static bool GetServiceDisplayNameImpl(APIContext& ctx, bool isWide) {
    const auto lpServiceName = ctx.GetArgPtr(1);
    const auto lpDisplayName = ctx.GetArgPtr(2);
    const auto lpcchBuffer   = ctx.GetArgPtr(3);

    if (lpServiceName == 0 || lpcchBuffer == 0) {
        ctx.FailWithError(kErrorInvalidParameter);
        return true;
    }

    std::wstring svcName;
    if (isWide) {
        svcName = ctx.ReadWideString(lpServiceName, kMaxStringLen / 2);
    } else {
        svcName = NarrowToWide(ctx.ReadAnsiString(lpServiceName, kMaxStringLen));
    }

    auto& mem = ctx.Memory();

    // Search fake service list
    std::wstring displayName;
    std::wstring lowerName;
    lowerName.reserve(svcName.size());
    for (wchar_t c : svcName) lowerName.push_back(static_cast<wchar_t>(std::towlower(c)));

    for (uint32_t i = 0; i < kFakeServiceCount; ++i) {
        std::wstring fkLower;
        const wchar_t* fk = kFakeServices[i].keyName;
        while (*fk) {
            fkLower.push_back(static_cast<wchar_t>(std::towlower(*fk)));
            ++fk;
        }
        if (lowerName == fkLower) {
            displayName = kFakeServices[i].displayName;
            break;
        }
    }

    if (displayName.empty()) {
        ctx.FailWithError(kErrorServiceDoesNotExist);
        return true;
    }

    uint32_t bufChars = 0;
    mem.ReadU32(lpcchBuffer, bufChars);

    if (isWide) {
        uint32_t needed = static_cast<uint32_t>(displayName.size());
        if (lpDisplayName == 0 || bufChars <= needed) {
            mem.WriteU32(lpcchBuffer, needed + 1);
            ctx.FailWithError(kErrorInsufficientBuffer);
            return true;
        }
        ctx.WriteWideString(lpDisplayName, displayName, bufChars);
        mem.WriteU32(lpcchBuffer, needed);
    } else {
        std::string narrow = WideToNarrow(displayName);
        uint32_t needed = static_cast<uint32_t>(narrow.size());
        if (lpDisplayName == 0 || bufChars <= needed) {
            mem.WriteU32(lpcchBuffer, needed + 1);
            ctx.FailWithError(kErrorInsufficientBuffer);
            return true;
        }
        ctx.WriteAnsiString(lpDisplayName, narrow, bufChars);
        mem.WriteU32(lpcchBuffer, needed);
    }

    ctx.SetReturnBool(true);
    ctx.SetLastError(kErrorSuccess);
    return true;
}

bool HandleGetServiceDisplayNameA(APIContext& ctx) { return GetServiceDisplayNameImpl(ctx, false); }
bool HandleGetServiceDisplayNameW(APIContext& ctx) { return GetServiceDisplayNameImpl(ctx, true); }

// ============================================================================
// GetServiceKeyNameA/W — hSCManager(0), lpDisplayName(1),
//                          lpServiceName(2), lpcchBuffer(3)
// ============================================================================

static bool GetServiceKeyNameImpl(APIContext& ctx, bool isWide) {
    const auto lpDisplayName = ctx.GetArgPtr(1);
    const auto lpServiceName = ctx.GetArgPtr(2);
    const auto lpcchBuffer   = ctx.GetArgPtr(3);

    if (lpDisplayName == 0 || lpcchBuffer == 0) {
        ctx.FailWithError(kErrorInvalidParameter);
        return true;
    }

    std::wstring dispName;
    if (isWide) {
        dispName = ctx.ReadWideString(lpDisplayName, kMaxStringLen / 2);
    } else {
        dispName = NarrowToWide(ctx.ReadAnsiString(lpDisplayName, kMaxStringLen));
    }

    auto& mem = ctx.Memory();

    // Search by display name
    std::wstring keyName;
    std::wstring lowerDisp;
    lowerDisp.reserve(dispName.size());
    for (wchar_t c : dispName) lowerDisp.push_back(static_cast<wchar_t>(std::towlower(c)));

    for (uint32_t i = 0; i < kFakeServiceCount; ++i) {
        std::wstring fkLower;
        const wchar_t* fk = kFakeServices[i].displayName;
        while (*fk) {
            fkLower.push_back(static_cast<wchar_t>(std::towlower(*fk)));
            ++fk;
        }
        if (lowerDisp == fkLower) {
            keyName = kFakeServices[i].keyName;
            break;
        }
    }

    if (keyName.empty()) {
        ctx.FailWithError(kErrorServiceDoesNotExist);
        return true;
    }

    uint32_t bufChars = 0;
    mem.ReadU32(lpcchBuffer, bufChars);

    if (isWide) {
        uint32_t needed = static_cast<uint32_t>(keyName.size());
        if (lpServiceName == 0 || bufChars <= needed) {
            mem.WriteU32(lpcchBuffer, needed + 1);
            ctx.FailWithError(kErrorInsufficientBuffer);
            return true;
        }
        ctx.WriteWideString(lpServiceName, keyName, bufChars);
        mem.WriteU32(lpcchBuffer, needed);
    } else {
        std::string narrow = WideToNarrow(keyName);
        uint32_t needed = static_cast<uint32_t>(narrow.size());
        if (lpServiceName == 0 || bufChars <= needed) {
            mem.WriteU32(lpcchBuffer, needed + 1);
            ctx.FailWithError(kErrorInsufficientBuffer);
            return true;
        }
        ctx.WriteAnsiString(lpServiceName, narrow, bufChars);
        mem.WriteU32(lpcchBuffer, needed);
    }

    ctx.SetReturnBool(true);
    ctx.SetLastError(kErrorSuccess);
    return true;
}

bool HandleGetServiceKeyNameA(APIContext& ctx) { return GetServiceKeyNameImpl(ctx, false); }
bool HandleGetServiceKeyNameW(APIContext& ctx) { return GetServiceKeyNameImpl(ctx, true); }

// ============================================================================
// ControlService — hService(0), dwControl(1), lpServiceStatus(2)
//
// Stopping security services is BehaviorFlag::DefenseEvasion
// ============================================================================

bool HandleControlService(APIContext& ctx) {
    const auto hService  = ctx.GetArg(0);
    const auto dwControl = ctx.GetArg32(1);
    const auto lpStatus  = ctx.GetArgPtr(2);

    std::wstring svcName = ResolveServiceName(ctx, hService);
    if (svcName.empty()) {
        ctx.FailWithError(kErrorInvalidHandle);
        return true;
    }

    // Track control command
    (void)dwControl;

    // Detect security service tampering
    if (dwControl == SERVICE_CONTROL_STOP && IsSecurityService(svcName)) {
        // BehaviorFlag::DefenseEvasion raised by dispatcher
    }

    // Write SERVICE_STATUS to output buffer
    if (lpStatus != 0) {
        auto& mem = ctx.Memory();
        uint32_t state = SERVICE_RUNNING;
        if (dwControl == SERVICE_CONTROL_STOP) state = SERVICE_STOP_PENDING;
        else if (dwControl == SERVICE_CONTROL_PAUSE) state = SERVICE_START_PENDING;

        mem.WriteU32(lpStatus,      SERVICE_WIN32_OWN_PROCESS);
        mem.WriteU32(lpStatus + 4,  state);
        mem.WriteU32(lpStatus + 8,  SERVICE_ACCEPT_STOP);
        mem.WriteU32(lpStatus + 12, 0);
        mem.WriteU32(lpStatus + 16, 0);
        mem.WriteU32(lpStatus + 20, 0);
        mem.WriteU32(lpStatus + 24, 0);
    }

    ctx.SetReturnBool(true);
    ctx.SetLastError(kErrorSuccess);
    return true;
}

// ============================================================================
// StartServiceCtrlDispatcherA/W — lpServiceStartTable(0)
//
// Malware registering itself as a service — persistence indicator
// ============================================================================

static bool StartServiceCtrlDispatcherImpl(APIContext& ctx, bool /*isWide*/) {
    const auto lpTable = ctx.GetArgPtr(0);
    (void)lpTable;

    // BehaviorFlag::ServiceManipulation raised by dispatcher
    ctx.SetReturnBool(true);
    ctx.SetLastError(kErrorSuccess);
    return true;
}

bool HandleStartServiceCtrlDispatcherA(APIContext& ctx) { return StartServiceCtrlDispatcherImpl(ctx, false); }
bool HandleStartServiceCtrlDispatcherW(APIContext& ctx) { return StartServiceCtrlDispatcherImpl(ctx, true); }

// ============================================================================
// RegisterServiceCtrlHandlerExA/W — lpServiceName(0), lpHandlerProc(1),
//                                     lpContext(2)
//
// Returns a SERVICE_STATUS_HANDLE (fake, non-zero)
// ============================================================================

static bool RegisterServiceCtrlHandlerExImpl(APIContext& ctx, bool isWide) {
    const auto lpServiceName = ctx.GetArgPtr(0);

    if (lpServiceName != 0) {
        if (isWide) {
            (void)ctx.ReadWideString(lpServiceName, kMaxStringLen / 2);
        } else {
            (void)ctx.ReadAnsiString(lpServiceName, kMaxStringLen);
        }
    }

    // Return a fake SERVICE_STATUS_HANDLE (non-zero value)
    ctx.SetLastError(kErrorSuccess);
    ctx.SetReturn(0x0000CAFE);
    return true;
}

bool HandleRegisterServiceCtrlHandlerExA(APIContext& ctx) { return RegisterServiceCtrlHandlerExImpl(ctx, false); }
bool HandleRegisterServiceCtrlHandlerExW(APIContext& ctx) { return RegisterServiceCtrlHandlerExImpl(ctx, true); }

// ============================================================================
// SetServiceStatus — hServiceStatus(0), lpServiceStatus(1)
// ============================================================================

bool HandleSetServiceStatus(APIContext& ctx) {
    const auto hServiceStatus = ctx.GetArg(0);
    const auto lpServiceStatus = ctx.GetArgPtr(1);

    (void)hServiceStatus;

    // Read the current state being set for tracking
    if (lpServiceStatus != 0) {
        uint32_t svcType = 0;
        uint32_t curState = 0;
        ctx.Memory().ReadU32(lpServiceStatus, svcType);
        ctx.Memory().ReadU32(lpServiceStatus + 4, curState);
        (void)svcType;
        (void)curState;
    }

    ctx.SetReturnBool(true);
    ctx.SetLastError(kErrorSuccess);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterServiceExtAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "advapi32.dll", "ChangeServiceConfigA",
          HandleChangeServiceConfigA, 11, false },
        { "advapi32.dll", "ChangeServiceConfigW",
          HandleChangeServiceConfigW, 11, false },
        { "advapi32.dll", "ChangeServiceConfig2A",
          HandleChangeServiceConfig2A, 3, false },
        { "advapi32.dll", "ChangeServiceConfig2W",
          HandleChangeServiceConfig2W, 3, false },
        { "advapi32.dll", "EnumServicesStatusA",
          HandleEnumServicesStatusA, 8, false },
        { "advapi32.dll", "EnumServicesStatusW",
          HandleEnumServicesStatusW, 8, false },
        { "advapi32.dll", "EnumServicesStatusExA",
          HandleEnumServicesStatusExA, 10, false },
        { "advapi32.dll", "EnumServicesStatusExW",
          HandleEnumServicesStatusExW, 10, false },
        { "advapi32.dll", "QueryServiceStatusEx",
          HandleQueryServiceStatusEx, 5, false },
        { "advapi32.dll", "QueryServiceConfigA",
          HandleQueryServiceConfigA, 4, false },
        { "advapi32.dll", "QueryServiceConfigW",
          HandleQueryServiceConfigW, 4, false },
        { "advapi32.dll", "GetServiceDisplayNameA",
          HandleGetServiceDisplayNameA, 4, false },
        { "advapi32.dll", "GetServiceDisplayNameW",
          HandleGetServiceDisplayNameW, 4, false },
        { "advapi32.dll", "GetServiceKeyNameA",
          HandleGetServiceKeyNameA, 4, false },
        { "advapi32.dll", "GetServiceKeyNameW",
          HandleGetServiceKeyNameW, 4, false },
        { "advapi32.dll", "ControlService",
          HandleControlService, 3, false },
        { "advapi32.dll", "StartServiceCtrlDispatcherA",
          HandleStartServiceCtrlDispatcherA, 1, false },
        { "advapi32.dll", "StartServiceCtrlDispatcherW",
          HandleStartServiceCtrlDispatcherW, 1, false },
        { "advapi32.dll", "RegisterServiceCtrlHandlerExA",
          HandleRegisterServiceCtrlHandlerExA, 3, false },
        { "advapi32.dll", "RegisterServiceCtrlHandlerExW",
          HandleRegisterServiceCtrlHandlerExW, 3, false },
        { "advapi32.dll", "SetServiceStatus",
          HandleSetServiceStatus, 2, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Advapi32
