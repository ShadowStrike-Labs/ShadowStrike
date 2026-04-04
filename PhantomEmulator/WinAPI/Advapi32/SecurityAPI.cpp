/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * SecurityAPI.cpp — Advapi32 security/token API handler implementations
 *
 * All token/privilege operations succeed to allow malware to proceed along
 * its intended path. Privilege escalation attempts are flagged for
 * behavioral analysis.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "SecurityAPI.hpp"
#include "../APIDispatcher.hpp"

#include <cstring>
#include <string>
#include <unordered_map>

namespace Phantom::WinAPI::Advapi32 {

// ============================================================================
// Win32 security constants (no windows.h dependency)
// ============================================================================

static constexpr uint32_t ERROR_SUCCESS            = 0;
static constexpr uint32_t ERROR_INVALID_HANDLE     = 6;
static constexpr uint32_t ERROR_INVALID_PARAMETER  = 87;
static constexpr uint32_t ERROR_INSUFFICIENT_BUFFER = 122;
static constexpr uint32_t ERROR_NOT_ALL_ASSIGNED   = 1300;

static constexpr uint32_t TOKEN_QUERY              = 0x0008;
static constexpr uint32_t TOKEN_ADJUST_PRIVILEGES  = 0x0020;
static constexpr uint32_t TOKEN_ALL_ACCESS         = 0x000F01FF;

// TokenInformationClass values
static constexpr uint32_t TokenUser                = 1;
static constexpr uint32_t TokenPrivileges          = 3;
static constexpr uint32_t TokenElevationType       = 18;
static constexpr uint32_t TokenIntegrityLevel      = 25;

// TokenElevationType values
static constexpr uint32_t TokenElevationTypeDefault = 1;
static constexpr uint32_t TokenElevationTypeFull    = 2;
static constexpr uint32_t TokenElevationTypeLimited = 3;

// Privilege LUIDs — well-known values matching Windows
struct PrivilegeLUID {
    uint32_t lowPart;
    int32_t  highPart;
};

static const std::unordered_map<std::string, PrivilegeLUID>& GetPrivilegeMap() noexcept {
    static const std::unordered_map<std::string, PrivilegeLUID> s_map = {
        { "SeDebugPrivilege",            { 20, 0 } },
        { "SeShutdownPrivilege",         { 19, 0 } },
        { "SeBackupPrivilege",           { 17, 0 } },
        { "SeRestorePrivilege",          { 18, 0 } },
        { "SeTakeOwnershipPrivilege",    { 9,  0 } },
        { "SeSecurityPrivilege",         { 8,  0 } },
        { "SeLoadDriverPrivilege",       { 10, 0 } },
        { "SeSystemtimePrivilege",       { 12, 0 } },
        { "SeIncreaseQuotaPrivilege",    { 5,  0 } },
        { "SeChangeNotifyPrivilege",     { 23, 0 } },
        { "SeImpersonatePrivilege",      { 29, 0 } },
        { "SeCreateGlobalPrivilege",     { 30, 0 } },
        { "SeAssignPrimaryTokenPrivilege", { 3, 0 } },
        { "SeTcbPrivilege",              { 7,  0 } },
        { "SeIncreaseBasePriorityPrivilege", { 14, 0 } },
        { "SeRemoteShutdownPrivilege",   { 24, 0 } },
        { "SeUndockPrivilege",           { 25, 0 } },
        { "SeManageVolumePrivilege",     { 28, 0 } },
        { "SeCreatePagefilePrivilege",   { 15, 0 } },
        { "SeProfileSingleProcessPrivilege", { 13, 0 } },
        { "SeSystemProfilePrivilege",    { 11, 0 } },
        { "SeAuditPrivilege",            { 21, 0 } },
    };
    return s_map;
}

static std::string WideToNarrow(const std::wstring& ws) noexcept {
    std::string s;
    s.reserve(ws.size());
    for (wchar_t wc : ws) s.push_back(static_cast<char>(wc & 0x7F));
    return s;
}

// ============================================================================
// OpenProcessToken
// ============================================================================

bool HandleOpenProcessToken(APIContext& ctx) {
    // arg0 = ProcessHandle, arg1 = DesiredAccess, arg2 = TokenHandle*
    GuestAddress pTokenHandle = ctx.GetArgPtr(2);

    if (pTokenHandle == 0) {
        ctx.FailWithError(ERROR_INVALID_PARAMETER);
        return true;
    }

    // Create a synthetic token handle
    SyncObjectData tokenData;
    tokenData.name = L"ProcessToken";
    tokenData.signaled = true;

    GuestHandle token = ctx.Handles().Create(HandleType::Token, std::move(tokenData));

    if (ctx.Is64Bit()) {
        ctx.Memory().WriteU64(pTokenHandle, token);
    } else {
        ctx.Memory().WriteU32(pTokenHandle, static_cast<uint32_t>(token));
    }

    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

// ============================================================================
// AdjustTokenPrivileges
// ============================================================================

bool HandleAdjustTokenPrivileges(APIContext& ctx) {
    // arg0 = TokenHandle
    // arg1 = DisableAllPrivileges
    // arg2 = NewState (TOKEN_PRIVILEGES*)
    // arg3 = BufferLength
    // arg4 = PreviousState (TOKEN_PRIVILEGES*)
    // arg5 = ReturnLength*

    GuestHandle tokenHandle = ctx.GetArg(0);

    // Validate the token handle exists (but don't require exact type —
    // some malware uses pseudo-handles)
    if (!ctx.Handles().IsValid(tokenHandle) &&
        tokenHandle != kCurrentProcess && tokenHandle != kCurrentThread) {
        ctx.FailWithError(ERROR_INVALID_HANDLE);
        return true;
    }

    // Always succeed — let malware think it has the privileges.
    // The dispatcher's behavioral flag system handles PrivilegeEscalation.

    // If PreviousState buffer is provided, write an empty TOKEN_PRIVILEGES
    GuestAddress pPrevState   = ctx.GetArgPtr(4);
    GuestAddress pReturnLen   = ctx.GetArgPtr(5);

    if (pReturnLen != 0) {
        ctx.Memory().WriteU32(pReturnLen, 0);
    }

    if (pPrevState != 0) {
        // PrivilegeCount = 0
        ctx.Memory().WriteU32(pPrevState, 0);
    }

    ctx.SetReturnBool(true);
    // Set last error to ERROR_NOT_ALL_ASSIGNED to mimic Windows behavior
    // when not all requested privileges were assigned (common path)
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

// ============================================================================
// LookupPrivilegeValueA/W — common implementation
// ============================================================================

static bool LookupPrivilegeValueImpl(APIContext& ctx, bool isWide) {
    // arg0 = lpSystemName (can be NULL for local machine)
    GuestAddress lpName = ctx.GetArgPtr(1);
    GuestAddress lpLuid = ctx.GetArgPtr(2);

    if (lpLuid == 0 || lpName == 0) {
        ctx.FailWithError(ERROR_INVALID_PARAMETER);
        return true;
    }

    std::string privName;
    if (isWide) {
        privName = WideToNarrow(ctx.ReadWideString(lpName));
    } else {
        privName = ctx.ReadAnsiString(lpName);
    }

    const auto& privMap = GetPrivilegeMap();
    auto it = privMap.find(privName);
    if (it == privMap.end()) {
        // Unknown privilege — return a generic LUID anyway to keep execution flowing
        ctx.Memory().WriteU32(lpLuid, 99);
        ctx.Memory().WriteU32(lpLuid + 4, 0);
        ctx.SetReturnBool(true);
        ctx.SetLastError(ERROR_SUCCESS);
        return true;
    }

    // LUID structure: { DWORD LowPart; LONG HighPart; }
    ctx.Memory().WriteU32(lpLuid, it->second.lowPart);
    ctx.Memory().WriteU32(lpLuid + 4, static_cast<uint32_t>(it->second.highPart));

    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

bool HandleLookupPrivilegeValueA(APIContext& ctx) { return LookupPrivilegeValueImpl(ctx, false); }
bool HandleLookupPrivilegeValueW(APIContext& ctx) { return LookupPrivilegeValueImpl(ctx, true); }

// ============================================================================
// GetTokenInformation
// ============================================================================

bool HandleGetTokenInformation(APIContext& ctx) {
    // arg0 = TokenHandle
    // arg1 = TokenInformationClass
    // arg2 = TokenInformation buffer
    // arg3 = TokenInformationLength
    // arg4 = ReturnLength*

    uint32_t infoClass   = ctx.GetArg32(1);
    GuestAddress pBuffer = ctx.GetArgPtr(2);
    uint32_t bufferLen   = ctx.GetArg32(3);
    GuestAddress pRetLen = ctx.GetArgPtr(4);

    switch (infoClass) {
        case TokenElevationType: {
            // TOKEN_ELEVATION_TYPE is a DWORD
            static constexpr uint32_t kSize = 4;
            if (pRetLen != 0) ctx.Memory().WriteU32(pRetLen, kSize);

            if (pBuffer == 0 || bufferLen < kSize) {
                ctx.FailWithError(ERROR_INSUFFICIENT_BUFFER);
                return true;
            }

            // Report as fully elevated — malware expects admin rights
            ctx.Memory().WriteU32(pBuffer, TokenElevationTypeFull);
            ctx.SetReturnBool(true);
            ctx.SetLastError(ERROR_SUCCESS);
            return true;
        }

        case TokenIntegrityLevel: {
            // TOKEN_MANDATORY_LABEL: SID_AND_ATTRIBUTES { SID* Sid; DWORD Attributes; }
            // followed by SID bytes. We fake a High integrity SID.
            //
            // Layout (x64):
            //   [0..7]   SID* Sid (pointer to offset 16)
            //   [8..11]  DWORD Attributes (SE_GROUP_INTEGRITY = 0x20)
            //   [12..15] padding
            //   [16..]   SID structure
            //
            // High integrity SID: S-1-16-12288 (0x3000)
            // SID binary: Revision=1, SubAuthCount=1, Authority={0,0,0,0,0,16},
            //             SubAuth[0]=12288

            static constexpr uint32_t kSidOffset64 = 16;
            static constexpr uint32_t kSidOffset32 = 8;
            static constexpr uint32_t kSidSize     = 12;  // 1+1+6+4

            bool is64 = ctx.Is64Bit();
            uint32_t sidOffset = is64 ? kSidOffset64 : kSidOffset32;
            uint32_t totalSize = sidOffset + kSidSize;

            if (pRetLen != 0) ctx.Memory().WriteU32(pRetLen, totalSize);

            if (pBuffer == 0 || bufferLen < totalSize) {
                ctx.FailWithError(ERROR_INSUFFICIENT_BUFFER);
                return true;
            }

            // Write SID pointer (absolute guest address)
            GuestAddress sidAddr = pBuffer + sidOffset;
            if (is64) {
                ctx.Memory().WriteU64(pBuffer, sidAddr);
            } else {
                ctx.Memory().WriteU32(pBuffer, static_cast<uint32_t>(sidAddr));
            }

            // Attributes = SE_GROUP_INTEGRITY (0x20)
            uint32_t attrOffset = is64 ? 8u : 4u;
            ctx.Memory().WriteU32(pBuffer + attrOffset, 0x00000020);

            // SID for S-1-16-12288
            uint8_t sid[12] = {
                1,                    // Revision
                1,                    // SubAuthorityCount
                0, 0, 0, 0, 0, 16,   // IdentifierAuthority (SECURITY_MANDATORY_LABEL_AUTHORITY)
                0x00, 0x30, 0x00, 0x00  // SubAuthority[0] = 12288 (0x3000) little-endian
            };
            ctx.Memory().Write(sidAddr, sid, sizeof(sid));

            ctx.SetReturnBool(true);
            ctx.SetLastError(ERROR_SUCCESS);
            return true;
        }

        case TokenUser: {
            // Provide a minimal fake TokenUser
            bool is64 = ctx.Is64Bit();
            uint32_t sidOffset = is64 ? 16u : 8u;
            // SID for a local user: S-1-5-21-1234567890-1234567890-1234567890-1001
            static constexpr uint32_t kUserSidSize = 28;  // 1+1+6+4*5
            uint32_t totalSize = sidOffset + kUserSidSize;

            if (pRetLen != 0) ctx.Memory().WriteU32(pRetLen, totalSize);

            if (pBuffer == 0 || bufferLen < totalSize) {
                ctx.FailWithError(ERROR_INSUFFICIENT_BUFFER);
                return true;
            }

            GuestAddress sidAddr = pBuffer + sidOffset;
            if (is64) {
                ctx.Memory().WriteU64(pBuffer, sidAddr);
            } else {
                ctx.Memory().WriteU32(pBuffer, static_cast<uint32_t>(sidAddr));
            }
            // Attributes
            ctx.Memory().WriteU32(pBuffer + (is64 ? 8u : 4u), 0);

            uint8_t sid[28] = {
                1,                          // Revision
                5,                          // SubAuthorityCount
                0, 0, 0, 0, 0, 5,          // SECURITY_NT_AUTHORITY
            };
            // SubAuthority[0..4]
            uint32_t subAuth[] = { 21, 1234567890u, 1234567890u, 1234567890u, 1001 };
            std::memcpy(sid + 8, subAuth, sizeof(subAuth));
            ctx.Memory().Write(sidAddr, sid, sizeof(sid));

            ctx.SetReturnBool(true);
            ctx.SetLastError(ERROR_SUCCESS);
            return true;
        }

        case TokenPrivileges: {
            // Return a minimal TOKEN_PRIVILEGES with SeDebugPrivilege enabled
            // TOKEN_PRIVILEGES: { DWORD PrivilegeCount; LUID_AND_ATTRIBUTES Privileges[]; }
            // LUID_AND_ATTRIBUTES: { LUID Luid; DWORD Attributes; } = 12 bytes
            static constexpr uint32_t kPrivCount = 1;
            static constexpr uint32_t kTotalSize = 4 + 12;  // count + 1 entry

            if (pRetLen != 0) ctx.Memory().WriteU32(pRetLen, kTotalSize);

            if (pBuffer == 0 || bufferLen < kTotalSize) {
                ctx.FailWithError(ERROR_INSUFFICIENT_BUFFER);
                return true;
            }

            ctx.Memory().WriteU32(pBuffer, kPrivCount);
            // LUID for SeDebugPrivilege (20, 0)
            ctx.Memory().WriteU32(pBuffer + 4, 20);   // LowPart
            ctx.Memory().WriteU32(pBuffer + 8, 0);    // HighPart
            // SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x03
            ctx.Memory().WriteU32(pBuffer + 12, 0x00000003);

            ctx.SetReturnBool(true);
            ctx.SetLastError(ERROR_SUCCESS);
            return true;
        }

        default: {
            // Unsupported class — return a minimal buffer
            if (pRetLen != 0) ctx.Memory().WriteU32(pRetLen, 0);
            ctx.SetReturnBool(true);
            ctx.SetLastError(ERROR_SUCCESS);
            return true;
        }
    }
}

// ============================================================================
// ImpersonateLoggedOnUser
// ============================================================================

bool HandleImpersonateLoggedOnUser(APIContext& ctx) {
    // arg0 = hToken
    // Always succeed — behavioral flag PrivilegeEscalation is raised by dispatcher.
    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

// ============================================================================
// RevertToSelf
// ============================================================================

bool HandleRevertToSelf(APIContext& ctx) {
    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterSecurityAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "advapi32.dll", "OpenProcessToken",        HandleOpenProcessToken,        3, false },
        { "advapi32.dll", "AdjustTokenPrivileges",   HandleAdjustTokenPrivileges,   6, false },
        { "advapi32.dll", "LookupPrivilegeValueA",   HandleLookupPrivilegeValueA,   3, false },
        { "advapi32.dll", "LookupPrivilegeValueW",   HandleLookupPrivilegeValueW,   3, false },
        { "advapi32.dll", "GetTokenInformation",     HandleGetTokenInformation,     5, false },
        { "advapi32.dll", "ImpersonateLoggedOnUser", HandleImpersonateLoggedOnUser, 1, false },
        { "advapi32.dll", "RevertToSelf",            HandleRevertToSelf,            0, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Advapi32
