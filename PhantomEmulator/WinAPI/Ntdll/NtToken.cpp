/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * NtToken.cpp — Nt* token and privilege syscall handlers
 *
 * Returns a fake elevated admin token so malware proceeds along its
 * privileged code path, exposing maximum behavioral surface for analysis.
 * All privilege adjustments succeed unconditionally — we want to observe
 * what the malware attempts, not block it prematurely.
 *
 * Token queries return:
 *   - TokenUser: SID for "CORP\JSmith"
 *   - TokenElevationType: Full (admin)
 *   - TokenIntegrityLevel: High
 *   - TokenSessionId: 1
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "NtToken.hpp"
#include "../APIDispatcher.hpp"

#include <cstring>
#include <vector>

namespace Phantom::WinAPI::Ntdll {

// ============================================================================
// NT status codes not in the common header
// ============================================================================

static constexpr GuestNtStatus STATUS_NO_TOKEN = static_cast<int32_t>(0xC000007C);

// ============================================================================
// Token information class constants
// ============================================================================

namespace {

static constexpr uint32_t kTokenUser               = 1;
static constexpr uint32_t kTokenSessionId           = 12;
static constexpr uint32_t kTokenElevationType       = 18;
static constexpr uint32_t kTokenIntegrityLevel      = 25;

// TokenElevationType values
static constexpr uint32_t kTokenElevationTypeFull   = 2;

// ============================================================================
// SID construction helpers
// ============================================================================

// SID layout:
//   Revision (1) + SubAuthorityCount (1) + IdentifierAuthority (6) +
//   SubAuthority[count] (4 * count)

// Domain SID for fake user "CORP\JSmith":
// S-1-5-21-1234567890-987654321-1122334455-1001
// Revision=1, SubAuthCount=5, Authority={0,0,0,0,0,5}
// SubAuth: 21, 1234567890, 987654321, 1122334455, 1001

static std::vector<uint8_t> BuildUserSID() {
    std::vector<uint8_t> sid;
    sid.push_back(1);  // Revision
    sid.push_back(5);  // SubAuthorityCount

    // IdentifierAuthority: SECURITY_NT_AUTHORITY {0,0,0,0,0,5}
    sid.push_back(0); sid.push_back(0); sid.push_back(0);
    sid.push_back(0); sid.push_back(0); sid.push_back(5);

    // SubAuthority[0]: SECURITY_NT_NON_UNIQUE (21)
    auto putU32 = [&](uint32_t val) {
        uint8_t bytes[4];
        std::memcpy(bytes, &val, 4);
        sid.insert(sid.end(), bytes, bytes + 4);
    };

    putU32(21);
    putU32(1234567890);
    putU32(987654321);
    putU32(1122334455);
    putU32(1001); // RID for JSmith

    return sid;
}

// High integrity level SID: S-1-16-12288
// Revision=1, SubAuthCount=1, Authority={0,0,0,0,0,16}
// SubAuth[0]: 12288 (0x3000 = SECURITY_MANDATORY_HIGH_RID)

static std::vector<uint8_t> BuildHighIntegritySID() {
    std::vector<uint8_t> sid;
    sid.push_back(1);  // Revision
    sid.push_back(1);  // SubAuthorityCount

    // IdentifierAuthority: SECURITY_MANDATORY_LABEL_AUTHORITY {0,0,0,0,0,16}
    sid.push_back(0); sid.push_back(0); sid.push_back(0);
    sid.push_back(0); sid.push_back(0); sid.push_back(16);

    // SubAuthority[0]: SECURITY_MANDATORY_HIGH_RID
    uint32_t rid = 12288;
    uint8_t bytes[4];
    std::memcpy(bytes, &rid, 4);
    sid.insert(sid.end(), bytes, bytes + 4);

    return sid;
}

// ============================================================================
// Helper: write TOKEN_USER / TOKEN_MANDATORY_LABEL to guest memory
// ============================================================================
// Both structures are SID_AND_ATTRIBUTES:
//   x64 layout: PSID (8 bytes) + Attributes (4 bytes) + pad (4 bytes) = 16 bytes
// Followed by the actual SID data.

static bool WriteSidAndAttributes(APIContext& ctx, GuestAddress infoAddr,
                                  uint32_t infoLength, GuestAddress retLenAddr,
                                  const std::vector<uint8_t>& sid, uint32_t attributes) {
    uint32_t sidSize = static_cast<uint32_t>(sid.size());
    // SID_AND_ATTRIBUTES (16 bytes) + SID data
    uint32_t requiredSize = 16 + sidSize;

    if (retLenAddr != 0)
        ctx.Memory().WriteU32(retLenAddr, requiredSize);

    if (infoLength < requiredSize) {
        ctx.SetReturnNtStatus(NT::STATUS_BUFFER_TOO_SMALL);
        return true;
    }

    // SID data lives immediately after the SID_AND_ATTRIBUTES struct
    GuestAddress sidAddr = infoAddr + 16;

    // Write PSID pointer
    ctx.Memory().WriteU64(infoAddr + 0x00, sidAddr);
    // Write Attributes
    ctx.Memory().WriteU32(infoAddr + 0x08, attributes);
    // Padding
    ctx.Memory().WriteU32(infoAddr + 0x0C, 0);
    // Write actual SID bytes
    ctx.Memory().Write(sidAddr, sid.data(), sidSize);

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

} // anonymous namespace

// ============================================================================
// HandleNtOpenProcessToken
// ============================================================================

bool HandleNtOpenProcessToken(APIContext& ctx) {
    // Arg0: HANDLE ProcessHandle (typically -1 for current process)
    // Arg1: ACCESS_MASK DesiredAccess
    auto tokenHandleAddr = ctx.GetArgPtr(2);

    if (tokenHandleAddr == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    // Create a token handle. We use std::monostate for the handle data
    // since all tokens share the same fake elevated admin identity.
    GuestHandle handle = ctx.Handles().Create(HandleType::Token, std::monostate{});
    ctx.Memory().WriteU64(tokenHandleAddr, handle);
    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// HandleNtOpenThreadToken
// ============================================================================

bool HandleNtOpenThreadToken(APIContext& ctx) {
    // Arg0: HANDLE ThreadHandle
    // Arg1: ACCESS_MASK DesiredAccess
    // Arg2: BOOLEAN OpenAsSelf
    // Arg3: PHANDLE TokenHandle (output)

    // Most threads are not impersonating — return STATUS_NO_TOKEN.
    // This is the most common real-world result and what malware expects
    // when checking if the thread has an impersonation token.
    ctx.SetReturnNtStatus(STATUS_NO_TOKEN);
    return true;
}

// ============================================================================
// HandleNtQueryInformationToken
// ============================================================================

bool HandleNtQueryInformationToken(APIContext& ctx) {
    auto tokenHandle = ctx.GetArg(0);
    auto infoClass   = ctx.GetArg32(1);
    auto infoAddr    = ctx.GetArgPtr(2);
    auto infoLength  = ctx.GetArg32(3);
    auto retLenAddr  = ctx.GetArgPtr(4);

    auto writeRetLen = [&](uint32_t len) {
        if (retLenAddr != 0)
            ctx.Memory().WriteU32(retLenAddr, len);
    };

    // Validate token handle (or pseudo-handle)
    if (tokenHandle != kCurrentProcess && tokenHandle != kCurrentThread) {
        auto entry = ctx.Handles().Lookup(tokenHandle, HandleType::Token);
        if (!entry) {
            ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
            return true;
        }
    }

    switch (infoClass) {
    // ------------------------------------------------------------------
    case kTokenUser: {
        // TOKEN_USER: SID_AND_ATTRIBUTES + SID data
        static const auto userSid = BuildUserSID();
        return WriteSidAndAttributes(ctx, infoAddr, infoLength, retLenAddr,
                                     userSid, 0);
    }

    // ------------------------------------------------------------------
    case kTokenSessionId: {
        // Returns a DWORD session ID
        uint32_t requiredSize = 4;
        writeRetLen(requiredSize);

        if (infoLength < requiredSize) {
            ctx.SetReturnNtStatus(NT::STATUS_BUFFER_TOO_SMALL);
            return true;
        }

        ctx.Memory().WriteU32(infoAddr, 1); // Session 1 (console session)
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    // ------------------------------------------------------------------
    case kTokenElevationType: {
        // Returns TOKEN_ELEVATION_TYPE (DWORD)
        uint32_t requiredSize = 4;
        writeRetLen(requiredSize);

        if (infoLength < requiredSize) {
            ctx.SetReturnNtStatus(NT::STATUS_BUFFER_TOO_SMALL);
            return true;
        }

        // Return Full elevation — malware expects admin to proceed
        ctx.Memory().WriteU32(infoAddr, kTokenElevationTypeFull);
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    // ------------------------------------------------------------------
    case kTokenIntegrityLevel: {
        // TOKEN_MANDATORY_LABEL: SID_AND_ATTRIBUTES + SID data
        // High integrity: S-1-16-12288
        static const auto highSid = BuildHighIntegritySID();
        static constexpr uint32_t SE_GROUP_INTEGRITY = 0x00000020;
        return WriteSidAndAttributes(ctx, infoAddr, infoLength, retLenAddr,
                                     highSid, SE_GROUP_INTEGRITY);
    }

    // ------------------------------------------------------------------
    default:
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_INFO_CLASS);
        return true;
    }
}

// ============================================================================
// HandleNtAdjustPrivilegesToken
// ============================================================================

bool HandleNtAdjustPrivilegesToken(APIContext& ctx) {
    // Arg0: HANDLE TokenHandle
    // Arg1: BOOLEAN DisableAllPrivileges
    // Arg2: PTOKEN_PRIVILEGES NewState
    // Arg3: ULONG BufferLength
    // Arg4: PTOKEN_PRIVILEGES PreviousState (output, optional)
    // Arg5: PULONG ReturnLength (output, optional)

    auto tokenHandle     = ctx.GetArg(0);
    auto prevStateAddr   = ctx.GetArgPtr(4);
    auto retLenAddr      = ctx.GetArgPtr(5);

    // Validate token handle
    if (tokenHandle != kCurrentProcess && tokenHandle != kCurrentThread) {
        auto entry = ctx.Handles().Lookup(tokenHandle, HandleType::Token);
        if (!entry) {
            ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
            return true;
        }
    }

    // Always succeed — we want malware to think it has the requested privileges.
    // The dispatcher's behavioral analysis flags this call automatically via
    // BehaviorFlag::PrivilegeEscalation in the KnownAPIEntry metadata.

    // If PreviousState is requested, write an empty TOKEN_PRIVILEGES
    // (PrivilegeCount = 0) to indicate no changes were needed.
    if (prevStateAddr != 0) {
        ctx.Memory().WriteU32(prevStateAddr, 0); // PrivilegeCount = 0
    }

    // Return required size for PreviousState buffer
    if (retLenAddr != 0) {
        ctx.Memory().WriteU32(retLenAddr, 4); // Just the PrivilegeCount field
    }

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterNtToken(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration regs[] = {
        { "ntdll.dll", "NtOpenProcessToken",       HandleNtOpenProcessToken,       3, true  },
        { "ntdll.dll", "NtOpenThreadToken",        HandleNtOpenThreadToken,        4, false },
        { "ntdll.dll", "NtQueryInformationToken",  HandleNtQueryInformationToken,  5, true  },
        { "ntdll.dll", "NtAdjustPrivilegesToken",  HandleNtAdjustPrivilegesToken,  6, false },
    };
    dispatcher.RegisterBatch(regs, static_cast<uint32_t>(std::size(regs)));
}

} // namespace Phantom::WinAPI::Ntdll
