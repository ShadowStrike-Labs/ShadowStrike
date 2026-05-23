/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * InstallProbe.cpp - implementation.  See header for design.
 *
 * Security notes:
 *   - All registry reads are done with KEY_READ | KEY_WOW64_64KEY so a
 *     32-bit tray (should one ever ship) still hits the 64-bit hive.
 *   - All buffers are bounded; no allocations driven by registry-supplied
 *     sizes without an explicit cap.
 *   - SCM probe uses OpenSCManager with SC_MANAGER_CONNECT only and
 *     OpenService with SERVICE_QUERY_STATUS — minimum rights principle.
 */

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>
#include <winsvc.h>

#include <algorithm>
#include <cwctype>
#include <format>
#include <string>

#include "InstallProbe.hpp"
#include "PhantomCore/Utils/Logger.hpp"

namespace ShadowStrike::PhantomHome::Tray {

namespace {

constexpr wchar_t kInstallSubKey[]    = L"SOFTWARE\\ShadowStrike\\PhantomHome\\Install";
constexpr wchar_t kInstallValueName[] = L"InstallFolder";
constexpr wchar_t kServiceName[]      = L"ShadowStrikePhantomService";
constexpr wchar_t kLogCategory[]      = L"InstallProbe";

// Cap registry-supplied string sizes at 32 KiB to guard against hostile hives.
constexpr DWORD   kMaxRegStringBytes  = 32u * 1024u;

[[nodiscard]] std::wstring ReadInstallFolder() noexcept {
    HKEY hKey{nullptr};
    LSTATUS ls = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kInstallSubKey, 0,
                               KEY_READ | KEY_WOW64_64KEY, &hKey);
    if (ls != ERROR_SUCCESS) {
        SS_LOG_DEBUG(kLogCategory,
            L"RegOpenKeyExW(HKLM\\%ls) failed (status=%ld); product not installed",
            kInstallSubKey, ls);
        return {};
    }
    DWORD type{0};
    DWORD cb{0};
    ls = RegQueryValueExW(hKey, kInstallValueName, nullptr, &type, nullptr, &cb);
    if (ls != ERROR_SUCCESS || type != REG_SZ || cb < sizeof(wchar_t) || cb > kMaxRegStringBytes) {
        SS_LOG_DEBUG(kLogCategory,
            L"InstallFolder value missing/invalid (status=%ld, type=%lu, cb=%lu)",
            ls, type, cb);
        RegCloseKey(hKey);
        return {};
    }
    std::wstring out(cb / sizeof(wchar_t), L'\0');
    ls = RegQueryValueExW(hKey, kInstallValueName, nullptr, &type,
                          reinterpret_cast<LPBYTE>(out.data()), &cb);
    RegCloseKey(hKey);
    if (ls != ERROR_SUCCESS) {
        SS_LOG_WARN(kLogCategory, L"InstallFolder read failed (status=%ld)", ls);
        return {};
    }
    while (!out.empty() && out.back() == L'\0') out.pop_back();
    return out;
}

[[nodiscard]] std::wstring GetOwnModulePath() noexcept {
    std::wstring buf(MAX_PATH + 1, L'\0');
    for (;;) {
        const DWORD n = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
        if (n == 0) {
            SS_LOG_LAST_ERROR(kLogCategory, L"GetModuleFileNameW failed");
            return {};
        }
        if (n < buf.size()) { buf.resize(n); return buf; }
        if (buf.size() >= 32768) {
            SS_LOG_ERROR(kLogCategory, L"Tray exe path exceeds 32768 chars");
            return {};
        }
        buf.assign(32768, L'\0');
    }
}

[[nodiscard]] bool ServiceIsRegistered() noexcept {
    const SC_HANDLE scm = OpenSCManagerW(nullptr, SERVICES_ACTIVE_DATABASEW, SC_MANAGER_CONNECT);
    if (!scm) {
        SS_LOG_LAST_ERROR(kLogCategory, L"OpenSCManagerW(SC_MANAGER_CONNECT) failed");
        return false;
    }
    const SC_HANDLE svc = OpenServiceW(scm, kServiceName, SERVICE_QUERY_STATUS);
    const DWORD gle = svc ? ERROR_SUCCESS : GetLastError();
    if (svc) CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    if (!svc) {
        if (gle == ERROR_SERVICE_DOES_NOT_EXIST) {
            SS_LOG_WARN(kLogCategory,
                L"SCM reports service '%ls' is NOT registered", kServiceName);
        } else {
            SS_LOG_ERROR(kLogCategory,
                L"OpenServiceW('%ls') failed (GLE=%lu)", kServiceName, gle);
        }
        return false;
    }
    return true;
}

[[nodiscard]] std::wstring ToLower(std::wstring s) noexcept {
    std::transform(s.begin(), s.end(), s.begin(),
        [](wchar_t c){ return static_cast<wchar_t>(std::towlower(c)); });
    return s;
}

[[nodiscard]] std::wstring NormalizePath(const std::wstring& p) noexcept {
    if (p.empty()) return p;
    std::wstring n = ToLower(p);
    for (auto& c : n) if (c == L'/') c = L'\\';
    while (n.size() > 1 && n.back() == L'\\') n.pop_back();
    return n;
}

} // namespace

bool IsTrayUnderInstallFolder(const InstallProbeResult& r) noexcept {
    if (r.installFolder.empty() || r.runningExePath.empty()) return false;
    const std::wstring folder = NormalizePath(r.installFolder) + L"\\";
    const std::wstring exe    = NormalizePath(r.runningExePath);
    return exe.size() > folder.size() &&
           exe.compare(0, folder.size(), folder) == 0;
}

InstallProbeResult ProbeInstall() noexcept {
    InstallProbeResult r{};
    r.runningExePath    = GetOwnModulePath();
    r.installFolder     = ReadInstallFolder();
    r.serviceRegistered = ServiceIsRegistered();

    const bool anchorOk = !r.installFolder.empty() && IsTrayUnderInstallFolder(r);

    if (!anchorOk) {
        SS_LOG_ERROR(kLogCategory,
            L"Tray is ORPHANED: anchor=[%ls] running=[%ls] svc=%ls",
            r.installFolder.c_str(), r.runningExePath.c_str(),
            r.serviceRegistered ? L"yes" : L"no");
        r.state = InstallState::Orphaned;
    } else if (!r.serviceRegistered) {
        SS_LOG_ERROR(kLogCategory,
            L"Tray is installed but service is missing: anchor=[%ls]",
            r.installFolder.c_str());
        r.state = InstallState::InstalledNoSvc;
    } else {
        r.state = InstallState::Installed;
    }
    return r;
}

} // namespace ShadowStrike::PhantomHome::Tray
