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
#include <format>
#include <string>

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
constexpr const wchar_t* kClsidRoot = L"CLSID";

constexpr const wchar_t* kLogCategory = L"AmsiProviderRegistration";

// ─────────────────────────────────────────────────────────────────────────────
// Helper: create / open a key and write a REG_SZ value.
// Returns false and logs an actionable error on failure.
// ─────────────────────────────────────────────────────────────────────────────
[[nodiscard]] bool SetRegSz(HKEY         hParent,
                             const wchar_t* subKey,
                             const wchar_t* valueName,
                             const wchar_t* data) noexcept {
    HKEY  hKey = nullptr;
    DWORD disp = 0;
    LSTATUS ls = RegCreateKeyExW(
        hParent, subKey, 0, nullptr, REG_OPTION_NON_VOLATILE,
        KEY_WRITE, nullptr, &hKey, &disp);
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

    const auto dataLen =
        static_cast<DWORD>((wcslen(data) + 1u) * sizeof(wchar_t));
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
    wchar_t buf[MAX_PATH + 1]{};
    const DWORD len = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        SS_LOG_ERROR(kLogCategory,
            L"GetCurrentModulePath: GetModuleFileNameW failed gle=%lu",
            GetLastError());
        return {};
    }
    return std::wstring(buf, len);
}

}  // namespace

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

bool RegisterAmsiProvider() noexcept {
    const std::wstring modulePath = GetCurrentModulePath();
    if (modulePath.empty()) return false;

    bool ok = true;

    // HKLM\SOFTWARE\Microsoft\AMSI\Providers\{CLSID}
    {
        std::wstring key =
            std::wstring(kAmsiProvidersKey) + L"\\" + kClsid;
        ok &= SetRegSz(HKEY_LOCAL_MACHINE, key.c_str(), nullptr, kDisplayName);
    }

    // HKCR\CLSID\{CLSID}
    {
        std::wstring clsidKey =
            std::wstring(kClsidRoot) + L"\\" + kClsid;
        ok &= SetRegSz(HKEY_CLASSES_ROOT, clsidKey.c_str(),
                       nullptr, kDisplayName);

        // HKCR\CLSID\{CLSID}\InprocServer32
        std::wstring inprocKey = clsidKey + L"\\InprocServer32";
        ok &= SetRegSz(HKEY_CLASSES_ROOT, inprocKey.c_str(),
                       nullptr, modulePath.c_str());
        ok &= SetRegSz(HKEY_CLASSES_ROOT, inprocKey.c_str(),
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
            std::wstring(kClsidRoot) + L"\\" + kClsid;
        ok &= DeleteRegKey(HKEY_CLASSES_ROOT, clsidKey.c_str());
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
