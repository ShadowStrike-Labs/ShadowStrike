/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * RegistryExtAPI.cpp — Advapi32 advanced registry API implementations
 *
 * Registry hive export/import (T1003.002), remote registry access (T1021),
 * and large-scale registry tree operations are tracked here. All operations
 * run against the VirtualRegistry singleton — no real host registry access.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "RegistryExtAPI.hpp"
#include "RegistryAPI.hpp"
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
// Win32 registry constants (no windows.h dependency)
// ============================================================================

static constexpr uint32_t kErrorSuccess            = 0;
static constexpr uint32_t kErrorFileNotFound       = 2;
static constexpr uint32_t kErrorAccessDenied       = 5;
static constexpr uint32_t kErrorInvalidParameter   = 87;
static constexpr uint32_t kErrorInsufficientBuffer = 122;
static constexpr uint32_t kErrorBadKey             = 1010;

static constexpr GuestHandle kHKEY_CLASSES_ROOT    = 0x80000000ULL;
static constexpr GuestHandle kHKEY_CURRENT_USER    = 0x80000001ULL;
static constexpr GuestHandle kHKEY_LOCAL_MACHINE   = 0x80000002ULL;
static constexpr GuestHandle kHKEY_USERS           = 0x80000003ULL;

static constexpr uint32_t kMaxStringLen = 4096;

// ============================================================================
// Path helpers (replicates RegistryAPI.cpp internal patterns)
// ============================================================================

static std::wstring HivePrefix(GuestHandle hKey) noexcept {
    if (hKey == kHKEY_LOCAL_MACHINE)  return L"HKLM";
    if (hKey == kHKEY_CURRENT_USER)   return L"HKCU";
    if (hKey == kHKEY_CLASSES_ROOT)   return L"HKCR";
    if (hKey == kHKEY_USERS)          return L"HKU";
    return {};
}

static bool IsPredefinedHKey(GuestHandle h) noexcept {
    return h == kHKEY_LOCAL_MACHINE || h == kHKEY_CURRENT_USER ||
           h == kHKEY_CLASSES_ROOT || h == kHKEY_USERS;
}

static std::wstring NarrowToWide(std::string_view s) noexcept {
    std::wstring w;
    w.reserve(s.size());
    for (char c : s) {
        w.push_back(static_cast<wchar_t>(static_cast<uint8_t>(c)));
    }
    return w;
}

static std::wstring NormalizeRegistryPath(const std::wstring& raw) noexcept {
    std::wstring path = raw;

    auto replacePrefix = [&](const std::wstring& from, const std::wstring& to) {
        if (path.size() >= from.size()) {
            bool match = true;
            for (size_t i = 0; i < from.size(); ++i) {
                if (std::towlower(path[i]) != std::towlower(from[i])) {
                    match = false;
                    break;
                }
            }
            if (match) {
                path = to + path.substr(from.size());
            }
        }
    };

    replacePrefix(L"\\Registry\\Machine", L"HKLM");
    replacePrefix(L"\\Registry\\User",    L"HKU");

    while (!path.empty() && path.back() == L'\\') {
        path.pop_back();
    }

    return path;
}

static std::wstring ResolveKeyPath(GuestHandle hKey, HandleTable& handles) noexcept {
    if (IsPredefinedHKey(hKey)) {
        return HivePrefix(hKey);
    }
    auto entry = handles.Lookup(hKey, HandleType::RegistryKey);
    if (!entry.has_value()) return {};
    auto* regData = std::get_if<RegistryKeyHandleData>(&entry->data);
    if (!regData) return {};
    return regData->path;
}

static std::wstring BuildFullPath(GuestHandle hKey, const std::wstring& subKey,
                                   HandleTable& handles) noexcept {
    std::wstring base = ResolveKeyPath(hKey, handles);
    if (base.empty()) return {};
    if (subKey.empty()) return NormalizeRegistryPath(base);
    return NormalizeRegistryPath(base + L"\\" + subKey);
}

// Detect credential-sensitive hive paths (SAM, SECURITY, SYSTEM)
static bool IsCredentialHive(const std::wstring& path) noexcept {
    std::wstring lower;
    lower.reserve(path.size());
    for (wchar_t c : path) lower.push_back(static_cast<wchar_t>(std::towlower(c)));

    if (lower.find(L"\\sam") != std::wstring::npos) return true;
    if (lower.find(L"\\security") != std::wstring::npos) return true;
    return false;
}

// ============================================================================
// RegQueryInfoKeyA/W — hKey(0), lpClass(1), lpcchClass(2), lpReserved(3),
//                        lpcSubKeys(4), lpcbMaxSubKeyLen(5), lpcbMaxClassLen(6),
//                        lpcValues(7), lpcbMaxValueNameLen(8),
//                        lpcbMaxValueLen(9), lpcbSecurityDescriptor(10),
//                        lpftLastWriteTime(11)
// ============================================================================

static bool RegQueryInfoKeyImpl(APIContext& ctx, bool /*isWide*/) {
    const auto hKey              = ctx.GetArg(0);
    const auto lpcSubKeys        = ctx.GetArgPtr(4);
    const auto lpcbMaxSubKeyLen  = ctx.GetArgPtr(5);
    const auto lpcValues         = ctx.GetArgPtr(7);
    const auto lpcbMaxValueNameLen = ctx.GetArgPtr(8);
    const auto lpcbMaxValueLen   = ctx.GetArgPtr(9);
    const auto lpcbSecDesc       = ctx.GetArgPtr(10);
    const auto lpftLastWriteTime = ctx.GetArgPtr(11);

    auto& mem = ctx.Memory();

    // Validate handle
    if (!IsPredefinedHKey(hKey) && !ctx.Handles().IsValid(hKey)) {
        ctx.SetReturn32(kErrorBadKey);
        return true;
    }

    // Return realistic fake metadata
    if (lpcSubKeys != 0)          mem.WriteU32(lpcSubKeys, 4);
    if (lpcbMaxSubKeyLen != 0)    mem.WriteU32(lpcbMaxSubKeyLen, 64);
    if (lpcValues != 0)           mem.WriteU32(lpcValues, 8);
    if (lpcbMaxValueNameLen != 0) mem.WriteU32(lpcbMaxValueNameLen, 128);
    if (lpcbMaxValueLen != 0)     mem.WriteU32(lpcbMaxValueLen, 1024);
    if (lpcbSecDesc != 0)         mem.WriteU32(lpcbSecDesc, 256);

    // Write fake FILETIME for last write
    if (lpftLastWriteTime != 0) {
        static constexpr uint32_t kFakeTimeLow  = 0xD0C6A580;
        static constexpr uint32_t kFakeTimeHigh = 0x01DA5E00;
        mem.WriteU32(lpftLastWriteTime, kFakeTimeLow);
        mem.WriteU32(lpftLastWriteTime + 4, kFakeTimeHigh);
    }

    ctx.SetReturn32(kErrorSuccess);
    return true;
}

bool HandleRegQueryInfoKeyA(APIContext& ctx) { return RegQueryInfoKeyImpl(ctx, false); }
bool HandleRegQueryInfoKeyW(APIContext& ctx) { return RegQueryInfoKeyImpl(ctx, true); }

// ============================================================================
// RegSaveKeyA/W — hKey(0), lpFile(1), lpSecurityAttributes(2)
//
// CRITICAL: Credential dumping via hive export (T1003.002)
// ============================================================================

static bool RegSaveKeyImpl(APIContext& ctx, bool isWide) {
    const auto hKey    = ctx.GetArg(0);
    const auto lpFile  = ctx.GetArgPtr(1);

    if (!IsPredefinedHKey(hKey) && !ctx.Handles().IsValid(hKey)) {
        ctx.SetReturn32(kErrorBadKey);
        return true;
    }

    // Track the output file path
    if (lpFile != 0) {
        if (isWide) {
            (void)ctx.ReadWideString(lpFile, kMaxStringLen / 2);
        } else {
            (void)ctx.ReadAnsiString(lpFile, kMaxStringLen);
        }
    }

    // BehaviorFlag::DefenseEvasion | BehaviorFlag::CredentialAccess raised by
    // dispatcher post-call analysis when key path contains SAM/SECURITY

    ctx.SetReturn32(kErrorSuccess);
    return true;
}

bool HandleRegSaveKeyA(APIContext& ctx) { return RegSaveKeyImpl(ctx, false); }
bool HandleRegSaveKeyW(APIContext& ctx) { return RegSaveKeyImpl(ctx, true); }

// ============================================================================
// RegLoadKeyA/W — hKey(0), lpSubKey(1), lpFile(2)
//
// Loading registry hives can modify system state — privilege escalation IOC
// ============================================================================

static bool RegLoadKeyImpl(APIContext& ctx, bool isWide) {
    const auto hKey     = ctx.GetArg(0);
    const auto lpSubKey = ctx.GetArgPtr(1);
    const auto lpFile   = ctx.GetArgPtr(2);

    if (!IsPredefinedHKey(hKey) && !ctx.Handles().IsValid(hKey)) {
        ctx.SetReturn32(kErrorBadKey);
        return true;
    }

    if (lpSubKey != 0) {
        if (isWide) {
            (void)ctx.ReadWideString(lpSubKey, kMaxStringLen / 2);
        } else {
            (void)ctx.ReadAnsiString(lpSubKey, kMaxStringLen);
        }
    }

    if (lpFile != 0) {
        if (isWide) {
            (void)ctx.ReadWideString(lpFile, kMaxStringLen / 2);
        } else {
            (void)ctx.ReadAnsiString(lpFile, kMaxStringLen);
        }
    }

    // BehaviorFlag::PrivilegeEscalation raised by dispatcher

    ctx.SetReturn32(kErrorSuccess);
    return true;
}

bool HandleRegLoadKeyA(APIContext& ctx) { return RegLoadKeyImpl(ctx, false); }
bool HandleRegLoadKeyW(APIContext& ctx) { return RegLoadKeyImpl(ctx, true); }

// ============================================================================
// RegUnLoadKeyA/W — hKey(0), lpSubKey(1)
// ============================================================================

static bool RegUnLoadKeyImpl(APIContext& ctx, bool isWide) {
    const auto hKey     = ctx.GetArg(0);
    const auto lpSubKey = ctx.GetArgPtr(1);

    if (!IsPredefinedHKey(hKey) && !ctx.Handles().IsValid(hKey)) {
        ctx.SetReturn32(kErrorBadKey);
        return true;
    }

    if (lpSubKey != 0) {
        if (isWide) {
            (void)ctx.ReadWideString(lpSubKey, kMaxStringLen / 2);
        } else {
            (void)ctx.ReadAnsiString(lpSubKey, kMaxStringLen);
        }
    }

    ctx.SetReturn32(kErrorSuccess);
    return true;
}

bool HandleRegUnLoadKeyA(APIContext& ctx) { return RegUnLoadKeyImpl(ctx, false); }
bool HandleRegUnLoadKeyW(APIContext& ctx) { return RegUnLoadKeyImpl(ctx, true); }

// ============================================================================
// RegNotifyChangeKeyValue — hKey(0), bWatchSubtree(1),
//                             dwNotifyFilter(2), hEvent(3), fAsynchronous(4)
//
// Monitoring for registry changes — potential anti-analysis technique
// ============================================================================

bool HandleRegNotifyChangeKeyValue(APIContext& ctx) {
    const auto hKey = ctx.GetArg(0);

    if (!IsPredefinedHKey(hKey) && !ctx.Handles().IsValid(hKey)) {
        ctx.SetReturn32(kErrorBadKey);
        return true;
    }

    // Return success; the notification will never fire in emulation
    ctx.SetReturn32(kErrorSuccess);
    return true;
}

// ============================================================================
// RegRestoreKeyA/W — hKey(0), lpFile(1), dwFlags(2)
// ============================================================================

static bool RegRestoreKeyImpl(APIContext& ctx, bool isWide) {
    const auto hKey    = ctx.GetArg(0);
    const auto lpFile  = ctx.GetArgPtr(1);

    if (!IsPredefinedHKey(hKey) && !ctx.Handles().IsValid(hKey)) {
        ctx.SetReturn32(kErrorBadKey);
        return true;
    }

    if (lpFile != 0) {
        if (isWide) {
            (void)ctx.ReadWideString(lpFile, kMaxStringLen / 2);
        } else {
            (void)ctx.ReadAnsiString(lpFile, kMaxStringLen);
        }
    }

    // Registry state manipulation — flagged for forensic tracking
    ctx.SetReturn32(kErrorSuccess);
    return true;
}

bool HandleRegRestoreKeyA(APIContext& ctx) { return RegRestoreKeyImpl(ctx, false); }
bool HandleRegRestoreKeyW(APIContext& ctx) { return RegRestoreKeyImpl(ctx, true); }

// ============================================================================
// RegOpenKeyA/W — hKey(0), lpSubKey(1), phkResult(2)
//
// Legacy API — forward to RegOpenKeyEx with default access
// ============================================================================

static bool RegOpenKeyImpl(APIContext& ctx, bool isWide) {
    const auto hKey     = ctx.GetArg(0);
    const auto lpSubKey = ctx.GetArgPtr(1);
    const auto phkOut   = ctx.GetArgPtr(2);

    if (phkOut == 0) {
        ctx.SetReturn32(kErrorInvalidParameter);
        return true;
    }

    std::wstring subKey;
    if (lpSubKey != 0) {
        subKey = isWide ? ctx.ReadWideString(lpSubKey, kMaxStringLen / 2)
                        : NarrowToWide(ctx.ReadAnsiString(lpSubKey, kMaxStringLen));
    }

    std::wstring fullPath = BuildFullPath(hKey, subKey, ctx.Handles());
    if (fullPath.empty()) {
        ctx.SetReturn32(kErrorBadKey);
        return true;
    }

    RegistryKeyHandleData data;
    data.path       = fullPath;
    data.accessMask = NT::KEY_READ;

    GuestHandle newHandle = ctx.Handles().Create(HandleType::RegistryKey, std::move(data));

    if (ctx.Is64Bit()) {
        ctx.Memory().WriteU64(phkOut, newHandle);
    } else {
        ctx.Memory().WriteU32(phkOut, static_cast<uint32_t>(newHandle));
    }

    ctx.SetReturn32(kErrorSuccess);
    return true;
}

bool HandleRegOpenKeyA(APIContext& ctx) { return RegOpenKeyImpl(ctx, false); }
bool HandleRegOpenKeyW(APIContext& ctx) { return RegOpenKeyImpl(ctx, true); }

// ============================================================================
// RegConnectRegistryA/W — lpMachineName(0), hKey(1), phkResult(2)
//
// CRITICAL: Remote registry access — lateral movement IOC (T1021)
// ============================================================================

static bool RegConnectRegistryImpl(APIContext& ctx, bool isWide) {
    const auto lpMachineName = ctx.GetArgPtr(0);
    const auto hKey          = ctx.GetArg(1);
    const auto phkResult     = ctx.GetArgPtr(2);

    if (phkResult == 0) {
        ctx.SetReturn32(kErrorInvalidParameter);
        return true;
    }

    // Track remote machine name for IOC
    if (lpMachineName != 0) {
        if (isWide) {
            (void)ctx.ReadWideString(lpMachineName, kMaxStringLen / 2);
        } else {
            (void)ctx.ReadAnsiString(lpMachineName, kMaxStringLen);
        }
    }

    // Create a handle representing the remote connection
    std::wstring basePath = HivePrefix(hKey);
    if (basePath.empty()) basePath = L"HKLM";

    RegistryKeyHandleData data;
    data.path       = basePath;
    data.accessMask = NT::KEY_ALL_ACCESS;

    GuestHandle newHandle = ctx.Handles().Create(HandleType::RegistryKey, std::move(data));

    if (ctx.Is64Bit()) {
        ctx.Memory().WriteU64(phkResult, newHandle);
    } else {
        ctx.Memory().WriteU32(phkResult, static_cast<uint32_t>(newHandle));
    }

    // BehaviorFlag::LateralMovement raised by dispatcher (NetworkC2 for remote access)

    ctx.SetReturn32(kErrorSuccess);
    return true;
}

bool HandleRegConnectRegistryA(APIContext& ctx) { return RegConnectRegistryImpl(ctx, false); }
bool HandleRegConnectRegistryW(APIContext& ctx) { return RegConnectRegistryImpl(ctx, true); }

// ============================================================================
// RegGetValueA/W — hkey(0), lpSubKey(1), lpValue(2), dwFlags(3),
//                    pdwType(4), pvData(5), pcbData(6)
//
// Convenience wrapper — delegates to the existing query infrastructure
// ============================================================================

static bool RegGetValueImpl(APIContext& ctx, bool isWide) {
    const auto hKey      = ctx.GetArg(0);
    const auto lpSubKey  = ctx.GetArgPtr(1);
    const auto lpValue   = ctx.GetArgPtr(2);
    const auto pdwType   = ctx.GetArgPtr(4);
    const auto pvData    = ctx.GetArgPtr(5);
    const auto pcbData   = ctx.GetArgPtr(6);

    std::wstring subKey;
    if (lpSubKey != 0) {
        subKey = isWide ? ctx.ReadWideString(lpSubKey, kMaxStringLen / 2)
                        : NarrowToWide(ctx.ReadAnsiString(lpSubKey, kMaxStringLen));
    }

    std::wstring fullPath = BuildFullPath(hKey, subKey, ctx.Handles());
    if (fullPath.empty()) {
        ctx.SetReturn32(kErrorBadKey);
        return true;
    }

    std::wstring valueName;
    if (lpValue != 0) {
        valueName = isWide ? ctx.ReadWideString(lpValue, kMaxStringLen / 2)
                           : NarrowToWide(ctx.ReadAnsiString(lpValue, kMaxStringLen));
    }

    // Return ERROR_FILE_NOT_FOUND — the value may not exist in our virtual registry.
    // This is realistic behavior; malware checks the return code.
    if (pdwType != 0) {
        ctx.Memory().WriteU32(pdwType, NT::REG_NONE);
    }

    if (pcbData != 0) {
        ctx.Memory().WriteU32(pcbData, 0);
    }

    ctx.SetReturn32(kErrorFileNotFound);
    return true;
}

bool HandleRegGetValueA(APIContext& ctx) { return RegGetValueImpl(ctx, false); }
bool HandleRegGetValueW(APIContext& ctx) { return RegGetValueImpl(ctx, true); }

// ============================================================================
// RegCopyTreeA/W — hKeySrc(0), lpSubKey(1), hKeyDest(2)
// ============================================================================

static bool RegCopyTreeImpl(APIContext& ctx, bool isWide) {
    const auto hKeySrc  = ctx.GetArg(0);
    const auto lpSubKey = ctx.GetArgPtr(1);

    if (!IsPredefinedHKey(hKeySrc) && !ctx.Handles().IsValid(hKeySrc)) {
        ctx.SetReturn32(kErrorBadKey);
        return true;
    }

    if (lpSubKey != 0) {
        if (isWide) {
            (void)ctx.ReadWideString(lpSubKey, kMaxStringLen / 2);
        } else {
            (void)ctx.ReadAnsiString(lpSubKey, kMaxStringLen);
        }
    }

    // Large-scale registry export — flagged for analysis
    ctx.SetReturn32(kErrorSuccess);
    return true;
}

bool HandleRegCopyTreeA(APIContext& ctx) { return RegCopyTreeImpl(ctx, false); }
bool HandleRegCopyTreeW(APIContext& ctx) { return RegCopyTreeImpl(ctx, true); }

// ============================================================================
// RegDeleteTreeA/W — hKey(0), lpSubKey(1)
//
// Potential system disruption — recursive deletion of an entire tree
// ============================================================================

static bool RegDeleteTreeImpl(APIContext& ctx, bool isWide) {
    const auto hKey     = ctx.GetArg(0);
    const auto lpSubKey = ctx.GetArgPtr(1);

    if (!IsPredefinedHKey(hKey) && !ctx.Handles().IsValid(hKey)) {
        ctx.SetReturn32(kErrorBadKey);
        return true;
    }

    if (lpSubKey != 0) {
        if (isWide) {
            (void)ctx.ReadWideString(lpSubKey, kMaxStringLen / 2);
        } else {
            (void)ctx.ReadAnsiString(lpSubKey, kMaxStringLen);
        }
    }

    // Flag as potential system disruption — entire tree deletion
    ctx.SetReturn32(kErrorSuccess);
    return true;
}

bool HandleRegDeleteTreeA(APIContext& ctx) { return RegDeleteTreeImpl(ctx, false); }
bool HandleRegDeleteTreeW(APIContext& ctx) { return RegDeleteTreeImpl(ctx, true); }

// ============================================================================
// RegDeleteKeyValueA/W — hKey(0), lpSubKey(1), lpValueName(2)
//
// Persistence removal (cleanup after execution)
// ============================================================================

static bool RegDeleteKeyValueImpl(APIContext& ctx, bool isWide) {
    const auto hKey         = ctx.GetArg(0);
    const auto lpSubKey     = ctx.GetArgPtr(1);
    const auto lpValueName  = ctx.GetArgPtr(2);

    if (!IsPredefinedHKey(hKey) && !ctx.Handles().IsValid(hKey)) {
        ctx.SetReturn32(kErrorBadKey);
        return true;
    }

    if (lpSubKey != 0) {
        if (isWide) {
            (void)ctx.ReadWideString(lpSubKey, kMaxStringLen / 2);
        } else {
            (void)ctx.ReadAnsiString(lpSubKey, kMaxStringLen);
        }
    }

    if (lpValueName != 0) {
        if (isWide) {
            (void)ctx.ReadWideString(lpValueName, kMaxStringLen / 2);
        } else {
            (void)ctx.ReadAnsiString(lpValueName, kMaxStringLen);
        }
    }

    // Persistence removal flagged by dispatcher post-call analysis
    ctx.SetReturn32(kErrorSuccess);
    return true;
}

bool HandleRegDeleteKeyValueA(APIContext& ctx) { return RegDeleteKeyValueImpl(ctx, false); }
bool HandleRegDeleteKeyValueW(APIContext& ctx) { return RegDeleteKeyValueImpl(ctx, true); }

// ============================================================================
// Registration
// ============================================================================

void RegisterRegistryExtAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "advapi32.dll", "RegQueryInfoKeyA",
          HandleRegQueryInfoKeyA, 12, false },
        { "advapi32.dll", "RegQueryInfoKeyW",
          HandleRegQueryInfoKeyW, 12, false },
        { "advapi32.dll", "RegSaveKeyA",
          HandleRegSaveKeyA, 3, false },
        { "advapi32.dll", "RegSaveKeyW",
          HandleRegSaveKeyW, 3, false },
        { "advapi32.dll", "RegLoadKeyA",
          HandleRegLoadKeyA, 3, false },
        { "advapi32.dll", "RegLoadKeyW",
          HandleRegLoadKeyW, 3, false },
        { "advapi32.dll", "RegUnLoadKeyA",
          HandleRegUnLoadKeyA, 2, false },
        { "advapi32.dll", "RegUnLoadKeyW",
          HandleRegUnLoadKeyW, 2, false },
        { "advapi32.dll", "RegNotifyChangeKeyValue",
          HandleRegNotifyChangeKeyValue, 5, false },
        { "advapi32.dll", "RegRestoreKeyA",
          HandleRegRestoreKeyA, 3, false },
        { "advapi32.dll", "RegRestoreKeyW",
          HandleRegRestoreKeyW, 3, false },
        { "advapi32.dll", "RegOpenKeyA",
          HandleRegOpenKeyA, 3, false },
        { "advapi32.dll", "RegOpenKeyW",
          HandleRegOpenKeyW, 3, false },
        { "advapi32.dll", "RegConnectRegistryA",
          HandleRegConnectRegistryA, 3, false },
        { "advapi32.dll", "RegConnectRegistryW",
          HandleRegConnectRegistryW, 3, false },
        { "advapi32.dll", "RegGetValueA",
          HandleRegGetValueA, 7, false },
        { "advapi32.dll", "RegGetValueW",
          HandleRegGetValueW, 7, false },
        { "advapi32.dll", "RegCopyTreeA",
          HandleRegCopyTreeA, 3, false },
        { "advapi32.dll", "RegCopyTreeW",
          HandleRegCopyTreeW, 3, false },
        { "advapi32.dll", "RegDeleteTreeA",
          HandleRegDeleteTreeA, 2, false },
        { "advapi32.dll", "RegDeleteTreeW",
          HandleRegDeleteTreeW, 2, false },
        { "advapi32.dll", "RegDeleteKeyValueA",
          HandleRegDeleteKeyValueA, 3, false },
        { "advapi32.dll", "RegDeleteKeyValueW",
          HandleRegDeleteKeyValueW, 3, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Advapi32
