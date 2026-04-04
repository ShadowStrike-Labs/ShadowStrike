/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * CredentialAPI.cpp — Advapi32 credential and LSA API implementations
 *
 * Every handler reads arguments from guest registers / guest stack via
 * APIContext, operates on HandleTable, and writes results back through
 * the context. No host OS calls are made.
 *
 * ENTERPRISE CRITICAL:
 *   - CredRead/CredEnumerate: Infostealers harvest cached credentials
 *     (browser passwords, RDP creds, Wi-Fi keys) via these APIs.
 *   - LsaRetrievePrivateData: Mimikatz-class tools use this to extract
 *     LSA secrets — service account passwords, DPAPI master keys, and
 *     cached domain credentials. Any call is a HIGH-SEVERITY indicator.
 *   - CredWrite with persistence: credential planting for lateral
 *     movement and backdoor access.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "CredentialAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../HandleTable.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <algorithm>
#include <cstring>
#include <string>

namespace Phantom::WinAPI::Advapi32 {

// ============================================================================
// Win32 credential constants (no windows.h dependency)
// ============================================================================

static constexpr uint32_t ERROR_SUCCESS            = 0;
static constexpr uint32_t ERROR_INVALID_PARAMETER  = 87;
static constexpr uint32_t ERROR_INVALID_HANDLE     = 6;
static constexpr uint32_t ERROR_NOT_FOUND          = 1168;
static constexpr uint32_t ERROR_NOT_ENOUGH_MEMORY  = 8;

// CREDENTIAL_TYPE values
static constexpr uint32_t CRED_TYPE_GENERIC                = 1;
static constexpr uint32_t CRED_TYPE_DOMAIN_PASSWORD        = 2;
static constexpr uint32_t CRED_TYPE_DOMAIN_CERTIFICATE     = 3;
static constexpr uint32_t CRED_TYPE_DOMAIN_VISIBLE_PASSWORD = 4;

// CREDENTIAL_PERSIST values
static constexpr uint32_t CRED_PERSIST_SESSION             = 1;
static constexpr uint32_t CRED_PERSIST_LOCAL_MACHINE       = 2;
static constexpr uint32_t CRED_PERSIST_ENTERPRISE          = 3;

// LSA status codes (NTSTATUS)
static constexpr int32_t STATUS_SUCCESS                    = 0;
static constexpr int32_t STATUS_INVALID_HANDLE             = static_cast<int32_t>(0xC0000008);
static constexpr int32_t STATUS_INVALID_PARAMETER          = static_cast<int32_t>(0xC000000D);
static constexpr int32_t STATUS_ACCESS_DENIED              = static_cast<int32_t>(0xC0000022);
static constexpr int32_t STATUS_OBJECT_NAME_NOT_FOUND      = static_cast<int32_t>(0xC0000034);

// CREDENTIAL structure offsets (x64)
// typedef struct _CREDENTIALW {
//   DWORD Flags;           // +0x00
//   DWORD Type;            // +0x04
//   LPWSTR TargetName;     // +0x08
//   LPWSTR Comment;        // +0x10
//   FILETIME LastWritten;  // +0x18
//   DWORD CredentialBlobSize; // +0x20
//   LPBYTE CredentialBlob; // +0x28
//   DWORD Persist;         // +0x30
//   DWORD AttributeCount;  // +0x34
//   PCREDENTIAL_ATTRIBUTEW Attributes; // +0x38
//   LPWSTR TargetAlias;    // +0x40
//   LPWSTR UserName;       // +0x48
// } CREDENTIALW;

static constexpr uint32_t kCredStructSize64 = 0x50;  // 80 bytes
static constexpr uint32_t kCredStructSize32 = 0x2C;  // 44 bytes

// LSA_UNICODE_STRING: { USHORT Length; USHORT MaximumLength; PWSTR Buffer; }
static constexpr uint32_t kLsaUnicodeString64 = 16;  // 2+2+4(pad)+8
static constexpr uint32_t kLsaUnicodeString32 = 8;   // 2+2+4

// Fake LSA policy handle base
static uint32_t s_nextPolicyId = 1;

// ============================================================================
// Helpers
// ============================================================================

static std::string WideToNarrow(const std::wstring& ws) noexcept {
    std::string s;
    s.reserve(ws.size());
    for (wchar_t wc : ws) s.push_back(static_cast<char>(wc & 0x7F));
    return s;
}

// Write a fake CREDENTIALW structure to guest memory (x64 layout).
// Returns the number of bytes written.
static uint32_t WriteFakeCredential(APIContext& ctx, GuestAddress base,
                                    uint32_t credType, const wchar_t* targetName,
                                    const wchar_t* userName) noexcept {
    auto& mem = ctx.Memory();
    bool is64 = ctx.Is64Bit();

    // Zero the structure first
    uint32_t structSize = is64 ? kCredStructSize64 : kCredStructSize32;
    uint8_t zeros[kCredStructSize64] = {};
    mem.Write(base, zeros, structSize);

    if (is64) {
        // Flags = 0
        mem.WriteU32(base + 0x00, 0);
        // Type
        mem.WriteU32(base + 0x04, credType);
        // TargetName pointer — write inline after the struct
        GuestAddress targetAddr = base + structSize;
        mem.WriteU64(base + 0x08, targetAddr);
        // Comment = NULL
        mem.WriteU64(base + 0x10, 0);
        // LastWritten = { 0, 0 }
        mem.WriteU64(base + 0x18, 0);
        // CredentialBlobSize = 0 (never return real credential data)
        mem.WriteU32(base + 0x20, 0);
        // CredentialBlob = NULL
        mem.WriteU64(base + 0x28, 0);
        // Persist
        mem.WriteU32(base + 0x30, CRED_PERSIST_LOCAL_MACHINE);
        // AttributeCount = 0
        mem.WriteU32(base + 0x34, 0);
        // Attributes = NULL
        mem.WriteU64(base + 0x38, 0);
        // TargetAlias = NULL
        mem.WriteU64(base + 0x40, 0);
        // UserName pointer — after target name
        size_t targetLen = 0;
        for (const wchar_t* p = targetName; *p; ++p) ++targetLen;
        GuestAddress userAddr = targetAddr + (targetLen + 1) * 2;
        mem.WriteU64(base + 0x48, userAddr);

        // Write target name string (UTF-16LE)
        ctx.WriteWideString(targetAddr, targetName, 256);
        // Write user name string
        ctx.WriteWideString(userAddr, userName, 256);

        size_t userLen = 0;
        for (const wchar_t* p = userName; *p; ++p) ++userLen;
        return structSize + static_cast<uint32_t>((targetLen + 1 + userLen + 1) * 2);
    } else {
        // x86 layout (compressed pointers)
        mem.WriteU32(base + 0x00, 0);               // Flags
        mem.WriteU32(base + 0x04, credType);         // Type
        GuestAddress targetAddr = base + structSize;
        mem.WriteU32(base + 0x08, static_cast<uint32_t>(targetAddr));  // TargetName
        mem.WriteU32(base + 0x0C, 0);               // Comment
        mem.WriteU64(base + 0x10, 0);               // LastWritten
        mem.WriteU32(base + 0x18, 0);               // CredentialBlobSize
        mem.WriteU32(base + 0x1C, 0);               // CredentialBlob
        mem.WriteU32(base + 0x20, CRED_PERSIST_LOCAL_MACHINE); // Persist
        mem.WriteU32(base + 0x24, 0);               // AttributeCount + Attributes

        size_t targetLen = 0;
        for (const wchar_t* p = targetName; *p; ++p) ++targetLen;
        GuestAddress userAddr = targetAddr + (targetLen + 1) * 2;
        mem.WriteU32(base + 0x28, static_cast<uint32_t>(userAddr)); // UserName

        ctx.WriteWideString(targetAddr, targetName, 256);
        ctx.WriteWideString(userAddr, userName, 256);

        size_t userLen = 0;
        for (const wchar_t* p = userName; *p; ++p) ++userLen;
        return structSize + static_cast<uint32_t>((targetLen + 1 + userLen + 1) * 2);
    }
}

// ============================================================================
// CredReadA/W — Read a single credential from the store
// ============================================================================
// Args: TargetName (0), Type (1), Flags (2), Credential** (3)
// Returns: BOOL — TRUE on success.
//
// We return a fake credential to allow the malware to continue.
// The actual credential blob is empty (never return real data).

static bool CredReadImpl(APIContext& ctx, bool isWide) {
    const auto lpTargetName = ctx.GetArgPtr(0);
    const auto dwType       = ctx.GetArg32(1);
    // arg2: Flags (reserved, must be 0)
    const auto ppCredential = ctx.GetArgPtr(3);

    if (lpTargetName == 0 || ppCredential == 0) {
        ctx.FailWithError(ERROR_INVALID_PARAMETER);
        return true;
    }

    (void)dwType;

    // Read the target name for behavioral logging (the dispatcher captures args)
    // We do not log the actual target name to avoid leaking sensitive info.

    // Allocate guest memory for the fake credential structure
    bool is64 = ctx.Is64Bit();
    uint32_t allocSize = (is64 ? kCredStructSize64 : kCredStructSize32) + 1024;
    GuestSize alignedSize = AlignUp(allocSize, kPageSize);

    auto credMem = ctx.Memory().Allocate(0, alignedSize, MemProt::RW);
    if (!credMem.has_value()) {
        ctx.FailWithError(ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    GuestAddress credBase = *credMem;

    WriteFakeCredential(ctx, credBase, CRED_TYPE_GENERIC,
                        L"FakeTarget", L"DOMAIN\\FakeUser");

    // Write the pointer to the credential structure
    if (is64) {
        ctx.Memory().WriteU64(ppCredential, credBase);
    } else {
        ctx.Memory().WriteU32(ppCredential, static_cast<uint32_t>(credBase));
    }

    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

bool HandleCredReadA(APIContext& ctx) { return CredReadImpl(ctx, false); }
bool HandleCredReadW(APIContext& ctx) { return CredReadImpl(ctx, true); }

// ============================================================================
// CredEnumerateA/W — Enumerate credentials in the store
// ============================================================================
// Args: Filter (0), Flags (1), Count* (2), Credentials*** (3)
// Returns: BOOL — TRUE on success.
//
// We return a small list of fake credential entries.

static bool CredEnumerateImpl(APIContext& ctx, bool isWide) {
    const auto lpFilter     = ctx.GetArgPtr(0);
    const auto dwFlags      = ctx.GetArg32(1);
    const auto pCount       = ctx.GetArgPtr(2);
    const auto pppCredentials = ctx.GetArgPtr(3);

    (void)lpFilter;
    (void)dwFlags;

    if (pCount == 0 || pppCredentials == 0) {
        ctx.FailWithError(ERROR_INVALID_PARAMETER);
        return true;
    }

    bool is64 = ctx.Is64Bit();
    static constexpr uint32_t kFakeCredCount = 2;

    // Allocate memory for pointer array + credential structures
    uint32_t structSize = is64 ? kCredStructSize64 : kCredStructSize32;
    uint32_t ptrSize    = is64 ? 8u : 4u;
    uint32_t totalSize  = (ptrSize * kFakeCredCount) +
                          ((structSize + 1024) * kFakeCredCount);
    GuestSize alignedTotal = AlignUp(totalSize, kPageSize);

    auto allocResult = ctx.Memory().Allocate(0, alignedTotal, MemProt::RW);
    if (!allocResult.has_value()) {
        ctx.FailWithError(ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    GuestAddress arrayBase = *allocResult;
    GuestAddress credStart = arrayBase + (ptrSize * kFakeCredCount);

    // Fake credential entries
    struct FakeCredEntry {
        const wchar_t* target;
        const wchar_t* user;
        uint32_t       type;
    };

    static constexpr FakeCredEntry kFakeCreds[kFakeCredCount] = {
        { L"WindowsLive:target=virtualapp/didlogical", L"FakeUser@outlook.com",
          CRED_TYPE_GENERIC },
        { L"TERMSRV/server.contoso.com", L"CONTOSO\\FakeAdmin",
          CRED_TYPE_DOMAIN_PASSWORD },
    };

    GuestAddress currentCred = credStart;
    for (uint32_t i = 0; i < kFakeCredCount; ++i) {
        // Write pointer in the array
        if (is64) {
            ctx.Memory().WriteU64(arrayBase + i * ptrSize, currentCred);
        } else {
            ctx.Memory().WriteU32(arrayBase + i * ptrSize,
                                  static_cast<uint32_t>(currentCred));
        }

        uint32_t bytesWritten = WriteFakeCredential(
            ctx, currentCred, kFakeCreds[i].type,
            kFakeCreds[i].target, kFakeCreds[i].user);
        currentCred += AlignUp(bytesWritten, 16);
    }

    // Write count
    ctx.Memory().WriteU32(pCount, kFakeCredCount);

    // Write pointer to the array
    if (is64) {
        ctx.Memory().WriteU64(pppCredentials, arrayBase);
    } else {
        ctx.Memory().WriteU32(pppCredentials, static_cast<uint32_t>(arrayBase));
    }

    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

bool HandleCredEnumerateA(APIContext& ctx) { return CredEnumerateImpl(ctx, false); }
bool HandleCredEnumerateW(APIContext& ctx) { return CredEnumerateImpl(ctx, true); }

// ============================================================================
// CredWriteA/W — Write a credential to the store
// ============================================================================
// Args: Credential* (0), Flags (1)
// Returns: BOOL — TRUE on success.
//
// We accept the write (allow malware to continue) but flag it as
// CredentialAccess + Persistence (credential planting).

static bool CredWriteImpl(APIContext& ctx, bool isWide) {
    const auto pCredential = ctx.GetArgPtr(0);
    const auto dwFlags     = ctx.GetArg32(1);

    (void)isWide;
    (void)dwFlags;

    if (pCredential == 0) {
        ctx.FailWithError(ERROR_INVALID_PARAMETER);
        return true;
    }

    // We do not read or log the credential blob contents (security policy).
    // The dispatcher's behavioral flagging records CredentialAccess + Persistence.

    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

bool HandleCredWriteA(APIContext& ctx) { return CredWriteImpl(ctx, false); }
bool HandleCredWriteW(APIContext& ctx) { return CredWriteImpl(ctx, true); }

// ============================================================================
// CredDeleteA/W — Delete a credential from the store
// ============================================================================
// Args: TargetName (0), Type (1), Flags (2)
// Returns: BOOL — TRUE on success.

static bool CredDeleteImpl(APIContext& ctx, bool isWide) {
    const auto lpTargetName = ctx.GetArgPtr(0);
    const auto dwType       = ctx.GetArg32(1);
    // arg2: Flags (reserved)

    (void)dwType;

    if (lpTargetName == 0) {
        ctx.FailWithError(ERROR_INVALID_PARAMETER);
        return true;
    }

    // Deletion always succeeds in emulation.
    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

bool HandleCredDeleteA(APIContext& ctx) { return CredDeleteImpl(ctx, false); }
bool HandleCredDeleteW(APIContext& ctx) { return CredDeleteImpl(ctx, true); }

// ============================================================================
// CredFree — Free credential memory
// ============================================================================
// Args: Buffer (0)
// Returns: void

bool HandleCredFree(APIContext& ctx) {
    // No-op: the guest memory was allocated by our emulator and will be
    // cleaned up on session teardown. We do not actively free here to
    // avoid use-after-free issues if malware still references the buffer.
    (void)ctx;
    return true;
}

// ============================================================================
// LsaOpenPolicy — Open a handle to the local LSA policy object
// ============================================================================
// Args: SystemName* (0), ObjectAttributes* (1), DesiredAccess (2), PolicyHandle* (3)
// Returns: NTSTATUS
//
// Any attempt to open LSA policy is flagged as PrivilegeEscalation.
// This is the first step in Mimikatz-style credential extraction chains.

bool HandleLsaOpenPolicy(APIContext& ctx) {
    // arg0: SystemName (LSA_UNICODE_STRING*, can be NULL for local)
    // arg1: ObjectAttributes (required but contents ignored)
    // arg2: DesiredAccess
    const auto pPolicyHandle = ctx.GetArgPtr(3);

    if (pPolicyHandle == 0) {
        ctx.SetReturnNtStatus(STATUS_INVALID_PARAMETER);
        return true;
    }

    // Create a fake policy handle (use Mutex handle type as a surrogate
    // since there is no dedicated LSA handle type)
    SyncObjectData policyData{};
    policyData.name     = L"LsaPolicy_" + std::to_wstring(s_nextPolicyId++);
    policyData.signaled = true;
    policyData.count    = 0;

    GuestHandle handle = ctx.Handles().Create(HandleType::Token, policyData);
    if (handle == kNullHandle) {
        ctx.SetReturnNtStatus(static_cast<int32_t>(0xC000009A)); // STATUS_INSUFFICIENT_RESOURCES
        return true;
    }

    // Write the policy handle
    if (ctx.Is64Bit()) {
        ctx.Memory().WriteU64(pPolicyHandle, handle);
    } else {
        ctx.Memory().WriteU32(pPolicyHandle, static_cast<uint32_t>(handle));
    }

    ctx.SetReturnNtStatus(STATUS_SUCCESS);
    return true;
}

// ============================================================================
// LsaRetrievePrivateData — CRITICAL: Mimikatz attack surface
// ============================================================================
// Args: PolicyHandle (0), KeyName* (1), PrivateData** (2)
// Returns: NTSTATUS
//
// This API retrieves secret data stored in the LSA database. It is the
// core API abused by credential-dumping tools. We return a small fake
// LSA_UNICODE_STRING with empty data — never real secrets.

bool HandleLsaRetrievePrivateData(APIContext& ctx) {
    const auto hPolicy      = ctx.GetArg(0);
    const auto pKeyName     = ctx.GetArgPtr(1);
    const auto ppPrivateData = ctx.GetArgPtr(2);

    if (ppPrivateData == 0) {
        ctx.SetReturnNtStatus(STATUS_INVALID_PARAMETER);
        return true;
    }

    // Validate policy handle
    if (!ctx.Handles().IsValid(hPolicy)) {
        ctx.SetReturnNtStatus(STATUS_INVALID_HANDLE);
        return true;
    }

    (void)pKeyName;

    bool is64 = ctx.Is64Bit();

    // Allocate memory for a fake LSA_UNICODE_STRING with empty buffer
    uint32_t lsaStrSize = is64 ? kLsaUnicodeString64 : kLsaUnicodeString32;
    uint32_t totalAlloc = lsaStrSize + 64;  // string struct + small buffer
    GuestSize alignedSize = AlignUp(totalAlloc, kPageSize);

    auto allocResult = ctx.Memory().Allocate(0, alignedSize, MemProt::RW);
    if (!allocResult.has_value()) {
        ctx.SetReturnNtStatus(static_cast<int32_t>(0xC000009A));
        return true;
    }

    GuestAddress strBase = *allocResult;
    GuestAddress bufAddr = strBase + lsaStrSize;

    // Write the LSA_UNICODE_STRING: empty (Length=0, MaximumLength=0, Buffer=ptr)
    ctx.Memory().WriteU16(strBase + 0, 0);   // Length
    ctx.Memory().WriteU16(strBase + 2, 0);   // MaximumLength
    if (is64) {
        ctx.Memory().WriteU64(strBase + 8, bufAddr);
    } else {
        ctx.Memory().WriteU32(strBase + 4, static_cast<uint32_t>(bufAddr));
    }

    // Write pointer to the LSA_UNICODE_STRING
    if (is64) {
        ctx.Memory().WriteU64(ppPrivateData, strBase);
    } else {
        ctx.Memory().WriteU32(ppPrivateData, static_cast<uint32_t>(strBase));
    }

    ctx.SetReturnNtStatus(STATUS_SUCCESS);
    return true;
}

// ============================================================================
// LsaStorePrivateData — Store data in LSA secret storage
// ============================================================================
// Args: PolicyHandle (0), KeyName* (1), PrivateData* (2)
// Returns: NTSTATUS
//
// Writing to LSA private store is a persistence mechanism.

bool HandleLsaStorePrivateData(APIContext& ctx) {
    const auto hPolicy      = ctx.GetArg(0);
    const auto pKeyName     = ctx.GetArgPtr(1);
    const auto pPrivateData = ctx.GetArgPtr(2);

    (void)pKeyName;
    (void)pPrivateData;

    if (!ctx.Handles().IsValid(hPolicy)) {
        ctx.SetReturnNtStatus(STATUS_INVALID_HANDLE);
        return true;
    }

    // Accept the store operation — behavioral flagging handles the rest.
    ctx.SetReturnNtStatus(STATUS_SUCCESS);
    return true;
}

// ============================================================================
// LsaClose — Close an LSA policy handle
// ============================================================================
// Args: ObjectHandle (0)
// Returns: NTSTATUS

bool HandleLsaClose(APIContext& ctx) {
    const auto hObject = ctx.GetArg(0);

    if (hObject != kNullHandle && ctx.Handles().IsValid(hObject)) {
        ctx.Handles().Close(hObject);
    }

    ctx.SetReturnNtStatus(STATUS_SUCCESS);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterCredentialAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "advapi32.dll", "CredReadA",
          HandleCredReadA, 4, false },
        { "advapi32.dll", "CredReadW",
          HandleCredReadW, 4, false },
        { "advapi32.dll", "CredEnumerateA",
          HandleCredEnumerateA, 4, false },
        { "advapi32.dll", "CredEnumerateW",
          HandleCredEnumerateW, 4, false },
        { "advapi32.dll", "CredWriteA",
          HandleCredWriteA, 2, false },
        { "advapi32.dll", "CredWriteW",
          HandleCredWriteW, 2, false },
        { "advapi32.dll", "CredDeleteA",
          HandleCredDeleteA, 3, false },
        { "advapi32.dll", "CredDeleteW",
          HandleCredDeleteW, 3, false },
        { "advapi32.dll", "CredFree",
          HandleCredFree, 1, false },
        { "advapi32.dll", "LsaOpenPolicy",
          HandleLsaOpenPolicy, 4, true },
        { "advapi32.dll", "LsaRetrievePrivateData",
          HandleLsaRetrievePrivateData, 3, true },
        { "advapi32.dll", "LsaStorePrivateData",
          HandleLsaStorePrivateData, 3, false },
        { "advapi32.dll", "LsaClose",
          HandleLsaClose, 1, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Advapi32
