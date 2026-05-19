/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef NOMINMAX
#  define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

// Standard library before Logger.hpp (Logger uses std::format)
#include <algorithm>
#include <cwctype>
#include <format>
#include <limits>
#include <string>
#include <vector>

#include "AmsiProviderRegistration.hpp"
#include "PhantomCore/Utils/Logger.hpp"

namespace ShadowStrike {
namespace Products {
namespace Home {

namespace {

// ─────────────────────────────────────────────────────────────────────────────
// CLSID string — generated once 2026-01-15. NEVER regenerate.
// ─────────────────────────────────────────────────────────────────────────────
constexpr const wchar_t* kClsid       =
    L"{6F2E9D28-4A1C-4B3E-8E1F-0C7A6F0DA1FF}";
constexpr const wchar_t* kDisplayName =
    L"ShadowStrike PhantomHome AMSI Provider";
constexpr const wchar_t* kThreadingModel = L"Both";

constexpr const wchar_t* kAmsiProvidersKey =
    L"SOFTWARE\\Microsoft\\AMSI\\Providers";
constexpr const wchar_t* kMachineClassesRoot = L"SOFTWARE\\Classes\\CLSID";

constexpr const wchar_t* kLogCategory = L"AmsiProviderRegistration";
constexpr std::size_t    kMaxRegSzChars = 32767u;
constinit const BYTE     kModuleAddressAnchor = 0;

[[nodiscard]] bool ComputeRegSzByteLength(const wchar_t* data,
                                           DWORD& byteLength) noexcept {
    byteLength = 0;
    if (!data) {
        SS_LOG_ERROR(kLogCategory,
            L"ComputeRegSzByteLength: REG_SZ data pointer is null");
        return false;
    }

    const std::size_t charLength = wcsnlen_s(data, kMaxRegSzChars + 1u);
    if (charLength > kMaxRegSzChars) {
        SS_LOG_ERROR(kLogCategory,
            L"ComputeRegSzByteLength: REG_SZ data exceeds %zu characters",
            kMaxRegSzChars);
        return false;
    }

    const std::size_t bytes = (charLength + 1u) * sizeof(wchar_t);
    if (bytes > static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())) {
        SS_LOG_ERROR(kLogCategory,
            L"ComputeRegSzByteLength: REG_SZ byte length overflows DWORD");
        return false;
    }

    byteLength = static_cast<DWORD>(bytes);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: create / open a key and write a REG_SZ value.
// Returns false and logs an actionable error on failure.
// ─────────────────────────────────────────────────────────────────────────────
[[nodiscard]] bool SetRegSz(HKEY         hParent,
                              const wchar_t* subKey,
                              const wchar_t* valueName,
                              const wchar_t* data) noexcept {
    if (!subKey || subKey[0] == L'\0') {
        SS_LOG_ERROR(kLogCategory,
            L"SetRegSz: registry subkey must not be empty");
        return false;
    }

    DWORD dataLen = 0;
    if (!ComputeRegSzByteLength(data, dataLen)) {
        return false;
    }

    HKEY  hKey = nullptr;
    DWORD disp = 0;
    LSTATUS ls = RegCreateKeyExW(
        hParent, subKey, 0, nullptr, REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_WOW64_64KEY,
        nullptr, &hKey, &disp);
    if (ls != ERROR_SUCCESS) {
        if (ls == ERROR_ACCESS_DENIED) {
            SS_LOG_ERROR(kLogCategory,
                L"SetRegSz: RegCreateKeyEx '%ls' access denied — "
                L"RegisterAmsiProvider requires elevation (run as Administrator)",
                subKey);
        } else {
            SS_LOG_ERROR(kLogCategory,
                L"SetRegSz: RegCreateKeyEx '%ls' failed ls=%ld",
                subKey, static_cast<long>(ls));
        }
        return false;
    }

    ls = RegSetValueExW(
        hKey, valueName, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(data), dataLen);
    RegCloseKey(hKey);

    if (ls != ERROR_SUCCESS) {
        SS_LOG_ERROR(kLogCategory,
            L"SetRegSz: RegSetValueEx '%ls'@'%ls' failed ls=%ld",
            subKey,
            valueName ? valueName : L"(Default)",
            static_cast<long>(ls));
        return false;
    }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: delete a registry key tree; ignores key-not-found.
// ─────────────────────────────────────────────────────────────────────────────
[[nodiscard]] bool DeleteRegKey(HKEY           hRoot,
                                  const wchar_t* subKey) noexcept {
    LSTATUS ls = RegDeleteTreeW(hRoot, subKey);
    if (ls == ERROR_SUCCESS || ls == ERROR_FILE_NOT_FOUND) return true;
    if (ls == ERROR_ACCESS_DENIED) {
        SS_LOG_ERROR(kLogCategory,
            L"DeleteRegKey: access denied deleting '%ls' — requires elevation",
            subKey);
    } else {
        SS_LOG_ERROR(kLogCategory,
            L"DeleteRegKey: RegDeleteTree '%ls' failed ls=%ld",
            subKey, static_cast<long>(ls));
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Retrieve the full path of the executing module (hosting service EXE).
// ─────────────────────────────────────────────────────────────────────────────
[[nodiscard]] std::wstring GetCurrentModulePath() noexcept {
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&kModuleAddressAnchor),
            &module)) {
        SS_LOG_ERROR(kLogCategory,
            L"GetCurrentModulePath: GetModuleHandleExW failed gle=%lu",
            GetLastError());
        return {};
    }

    std::vector<wchar_t> buffer(MAX_PATH);
    for (;;) {
        const DWORD len = GetModuleFileNameW(
            module,
            buffer.data(),
            static_cast<DWORD>(buffer.size()));
        if (len == 0) {
            SS_LOG_ERROR(kLogCategory,
                L"GetCurrentModulePath: GetModuleFileNameW failed gle=%lu",
                GetLastError());
            return {};
        }

        if (len < buffer.size() - 1u) {
            return std::wstring(buffer.data(), len);
        }

        if (buffer.size() >= kMaxRegSzChars) {
            SS_LOG_ERROR(kLogCategory,
                L"GetCurrentModulePath: module path exceeds registry-safe limit");
            return {};
        }

        const std::size_t nextSize = std::min<std::size_t>(
            buffer.size() * 2u,
            kMaxRegSzChars + 1u);
        buffer.assign(nextSize, L'\0');
    }
}

[[nodiscard]] bool IsComServerDllPath(std::wstring path) noexcept {
    if (path.size() < 4u) {
        return false;
    }

    std::transform(path.begin(), path.end(), path.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });

    return path.ends_with(L".dll");
}

[[nodiscard]] bool ValidateComServerPath(const std::wstring& modulePath) noexcept {
    if (modulePath.empty()) {
        return false;
    }

    if (!IsComServerDllPath(modulePath)) {
        SS_LOG_ERROR(kLogCategory,
            L"ValidateComServerPath: refusing AMSI InprocServer32 registration "
            L"because containing module is not a DLL; path=%ls",
            modulePath.c_str());
        return false;
    }

    return true;
}

}  // namespace

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

bool RegisterAmsiProvider() noexcept {
    const std::wstring modulePath = GetCurrentModulePath();
    if (!ValidateComServerPath(modulePath)) return false;

    bool ok = true;

    // HKLM\SOFTWARE\Microsoft\AMSI\Providers\{CLSID}
    {
        std::wstring key =
            std::wstring(kAmsiProvidersKey) + L"\\" + kClsid;
        ok &= SetRegSz(HKEY_LOCAL_MACHINE, key.c_str(), nullptr, kDisplayName);
    }

    // HKLM\SOFTWARE\Classes\CLSID\{CLSID}; avoid HKCR merge-view ambiguity.
    {
        std::wstring clsidKey =
            std::wstring(kMachineClassesRoot) + L"\\" + kClsid;
        ok &= SetRegSz(HKEY_LOCAL_MACHINE, clsidKey.c_str(),
                       nullptr, kDisplayName);

        // HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32
        std::wstring inprocKey = clsidKey + L"\\InprocServer32";
        ok &= SetRegSz(HKEY_LOCAL_MACHINE, inprocKey.c_str(),
                       nullptr, modulePath.c_str());
        ok &= SetRegSz(HKEY_LOCAL_MACHINE, inprocKey.c_str(),
                       L"ThreadingModel", kThreadingModel);
    }

    if (ok) {
        SS_LOG_INFO(kLogCategory,
            L"RegisterAmsiProvider: CLSID %ls registered; server=%ls",
            kClsid, modulePath.c_str());
    } else {
        SS_LOG_ERROR(kLogCategory,
            L"RegisterAmsiProvider: one or more registry writes failed "
            L"(see prior error messages); AMSI provider may not load correctly");
    }
    return ok;
}

bool UnregisterAmsiProvider() noexcept {
    bool ok = true;

    {
        std::wstring key =
            std::wstring(kAmsiProvidersKey) + L"\\" + kClsid;
        ok &= DeleteRegKey(HKEY_LOCAL_MACHINE, key.c_str());
    }

    {
        std::wstring clsidKey =
            std::wstring(kMachineClassesRoot) + L"\\" + kClsid;
        ok &= DeleteRegKey(HKEY_LOCAL_MACHINE, clsidKey.c_str());
    }

    if (ok) {
        SS_LOG_INFO(kLogCategory,
            L"UnregisterAmsiProvider: CLSID %ls removed", kClsid);
    }
    return ok;
}

}  // namespace Home
}  // namespace Products
}  // namespace ShadowStrike
