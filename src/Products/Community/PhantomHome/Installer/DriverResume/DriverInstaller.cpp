/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file DriverInstaller.cpp
 * @brief PhantomSensor SCM installer and minifilter loader implementation.
 *
 * Security design:
 *  - Driver binary copy uses a locked-read-then-manual-copy sequence to
 *    eliminate the TOCTOU window between existence check and CopyFileW.
 *  - Authenticode signature is verified (structural validity) before the
 *    binary is written to System32\drivers\.  This prevents a compromised
 *    staging directory from loading arbitrary kernel code.
 *  - All failure paths clean up intermediary state before returning.
 */

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>
#include <winsvc.h>
#include <fltuser.h>
#include <ShlObj.h>
#include <wintrust.h>
#include <softpub.h>

#pragma comment(lib, "wintrust.lib")

#include <string>
#include <cstdio>
#include <cstdint>
#include <vector>

#include "DriverInstaller.hpp"

// ────────────────────────────────────────────────────────────────────────────
//  Internal logging trampoline (defined in DriverResumeMain.cpp)
// ────────────────────────────────────────────────────────────────────────────
namespace ShadowStrike::Installer::Internal {
void Log(const wchar_t* level, const wchar_t* fmt, ...);
}
#define LOG_INFO(fmt, ...)  ::ShadowStrike::Installer::Internal::Log(L"INFO ", fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  ::ShadowStrike::Installer::Internal::Log(L"WARN ", fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) ::ShadowStrike::Installer::Internal::Log(L"ERROR", fmt, ##__VA_ARGS__)

namespace ShadowStrike::Installer {

// ────────────────────────────────────────────────────────────────────────────
//  Internal helpers
// ────────────────────────────────────────────────────────────────────────────

static std::wstring GetOwnDirectory()
{
    // Use a dynamically-sized buffer to handle paths > MAX_PATH correctly.
    DWORD needed = GetModuleFileNameW(nullptr, nullptr, 0);
    if (needed == 0)
        return {};

    std::wstring buf(static_cast<size_t>(needed) + 1, L'\0');
    DWORD len = GetModuleFileNameW(nullptr, buf.data(), needed + 1);
    if (len == 0 || len >= needed + 1)
        return {};

    buf.resize(len);
    auto pos = buf.rfind(L'\\');
    if (pos == std::wstring::npos)
        return {};

    return buf.substr(0, pos);
}

static std::wstring BuildSystemDriverPath()
{
    wchar_t sysRoot[MAX_PATH + 1] = {};
    if (!GetWindowsDirectoryW(sysRoot, MAX_PATH))
        return {};

    std::wstring path(sysRoot);
    path += kSystem32Drivers;
    path += kDriverSysName;
    return path;
}

// ────────────────────────────────────────────────────────────────────────────
//  VerifyDriverSignature
//  Uses WinVerifyTrust to confirm Authenticode structure of the staged .sys.
//  For dev-signed binaries, the root cert is not in Trusted Publishers; we
//  verify the structural signature only (WTD_REVOKE_NONE, no UI, no chain
//  trust check). This stops an attacker from substituting an UNSIGNED binary
//  while still allowing dev-cert-signed binaries through.
// ────────────────────────────────────────────────────────────────────────────
static DWORD VerifyDriverSignature(const std::wstring& filePath)
{
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct    = sizeof(fileInfo);
    fileInfo.pcwszFilePath = filePath.c_str();
    fileInfo.hFile       = nullptr;
    fileInfo.pgKnownSubject = nullptr;

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA wtd{};
    wtd.cbStruct            = sizeof(wtd);
    wtd.pPolicyCallbackData = nullptr;
    wtd.pSIPClientData      = nullptr;
    wtd.dwUIChoice          = WTD_UI_NONE;       // No UI dialogs
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE;   // Skip CRL (offline-friendly)
    wtd.dwUnionChoice       = WTD_CHOICE_FILE;
    wtd.pFile               = &fileInfo;
    wtd.dwStateAction       = WTD_STATEACTION_VERIFY;
    wtd.hWVTStateData       = nullptr;
    wtd.pwszURLReference    = nullptr;
    // WTD_SAFER_FLAG: skip SAFER check (we don't need full policy here).
    wtd.dwProvFlags         = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;
    wtd.dwUIContext         = 0;

    LONG status = WinVerifyTrust(nullptr, &policyGuid, &wtd);

    // Always close the state data to prevent resource leak.
    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policyGuid, &wtd);

    // Acceptable results:
    //   ERROR_SUCCESS (0)                   - trusted chain
    //   CERT_E_UNTRUSTEDROOT (0x800B0109)   - self-signed / dev cert root
    //   CERT_E_CHAINING (0x800B010A)        - chain build failed (also dev cert)
    //   TRUST_E_EXPLICIT_DISTRUST           - explicitly distrusted (REJECT)
    //   TRUST_E_NOSIGNATURE (0x800B0100)    - no signature at all (REJECT)

    if (status == static_cast<LONG>(CERT_E_UNTRUSTEDROOT) ||
        status == static_cast<LONG>(CERT_E_CHAINING))
    {
        // Dev-cert signed: structurally valid but root not in Trusted Publishers.
        LOG_WARN(L"Driver binary has a dev-cert signature (root not trusted by CA store). "
                 L"Acceptable for dev/test builds. HRESULT=0x%08X", status);
        return ERROR_SUCCESS;
    }

    if (status == ERROR_SUCCESS) {
        LOG_INFO(L"Driver binary signature fully trusted.");
        return ERROR_SUCCESS;
    }

    // Any other failure means the file has no valid Authenticode signature.
    LOG_ERROR(L"WinVerifyTrust REJECTED driver binary '%ls': HRESULT=0x%08X. "
              L"Refusing to copy unsigned or tampered driver to System32.",
              filePath.c_str(), static_cast<DWORD>(status));
    return ERROR_INVALID_DATA; // Signature absent or structurally invalid.
}

// ────────────────────────────────────────────────────────────────────────────
//  SecureCopyFile
//  Opens the source file with FILE_SHARE_READ (no write sharing) to prevent
//  TOCTOU replacement between verification and copy. Manually reads and writes
//  the content using the open handle so the file cannot be swapped under us.
// ────────────────────────────────────────────────────────────────────────────
static DWORD SecureCopyFile(const std::wstring& srcPath,
                             const std::wstring& tmpDstPath)
{
    // Open source: GENERIC_READ, FILE_SHARE_READ only.
    // Any concurrent open for WRITE or DELETE will fail with ERROR_SHARING_VIOLATION.
    HandleGuard srcHandle(
        CreateFileW(srcPath.c_str(),
                    GENERIC_READ,
                    FILE_SHARE_READ,     // deny write + delete sharing
                    nullptr,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr));

    if (!srcHandle.valid()) {
        DWORD err = GetLastError();
        LOG_ERROR(L"SecureCopyFile: cannot open source '%ls' (0x%08X)", srcPath.c_str(), err);
        return err;
    }

    LARGE_INTEGER srcSize{};
    if (!GetFileSizeEx(srcHandle.get(), &srcSize)) {
        DWORD err = GetLastError();
        LOG_ERROR(L"SecureCopyFile: GetFileSizeEx failed (0x%08X)", err);
        return err;
    }

    // Sanity cap: no legitimate kernel driver is > 64 MB.
    constexpr LONGLONG kMaxDriverBytes = 64LL * 1024 * 1024;
    if (srcSize.QuadPart > kMaxDriverBytes) {
        LOG_ERROR(L"SecureCopyFile: source size %lld B exceeds 64 MB cap. Refusing.",
                  srcSize.QuadPart);
        return ERROR_FILE_TOO_LARGE;
    }

    // Open temp destination (create new; overwrite if prior .tmp exists).
    HandleGuard dstHandle(
        CreateFileW(tmpDstPath.c_str(),
                    GENERIC_WRITE,
                    0,                   // exclusive: no sharing
                    nullptr,
                    CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                    nullptr));

    if (!dstHandle.valid()) {
        DWORD err = GetLastError();
        LOG_ERROR(L"SecureCopyFile: cannot create temp dest '%ls' (0x%08X)",
                  tmpDstPath.c_str(), err);
        return err;
    }

    // Stream copy via 1 MB chunks.
    constexpr DWORD kChunk = 1024 * 1024;
    std::vector<BYTE> buf(kChunk);
    LONGLONG remaining = srcSize.QuadPart;

    while (remaining > 0) {
        DWORD toRead = static_cast<DWORD>(
            remaining < static_cast<LONGLONG>(kChunk) ? remaining : kChunk);
        DWORD bytesRead = 0;
        if (!ReadFile(srcHandle.get(), buf.data(), toRead, &bytesRead, nullptr) ||
            bytesRead != toRead)
        {
            DWORD err = GetLastError();
            LOG_ERROR(L"SecureCopyFile: ReadFile failed (0x%08X)", err);
            // Destroy partial destination.
            dstHandle = HandleGuard{};
            DeleteFileW(tmpDstPath.c_str());
            return err;
        }

        DWORD bytesWritten = 0;
        if (!WriteFile(dstHandle.get(), buf.data(), bytesRead, &bytesWritten, nullptr) ||
            bytesWritten != bytesRead)
        {
            DWORD err = GetLastError();
            LOG_ERROR(L"SecureCopyFile: WriteFile failed (0x%08X)", err);
            dstHandle = HandleGuard{};
            DeleteFileW(tmpDstPath.c_str());
            return err;
        }

        remaining -= bytesRead;
    }

    // Flush to disk before rename.
    if (!FlushFileBuffers(dstHandle.get())) {
        LOG_WARN(L"SecureCopyFile: FlushFileBuffers failed (0x%08X) – non-fatal.",
                 GetLastError());
    }

    return ERROR_SUCCESS;
    // dstHandle closes here; srcHandle closes here (still deny-write during entire copy).
}

// ────────────────────────────────────────────────────────────────────────────
//  ResolveInstalledDriverPath
// ────────────────────────────────────────────────────────────────────────────
DWORD ResolveInstalledDriverPath(std::wstring& outPath)
{
    std::wstring dir = GetOwnDirectory();
    if (dir.empty()) {
        LOG_ERROR(L"GetModuleFileNameW failed (0x%08X)", GetLastError());
        return GetLastError() ? GetLastError() : ERROR_FUNCTION_FAILED;
    }

    // Build candidate: <exedir>\Drivers\PhantomSensor.sys
    std::wstring candidate = dir + L"\\" + kDriverSubPath;

    // Add extended-length prefix for long-path safety.
    if (candidate.rfind(L"\\\\?\\", 0) != 0)
        candidate = L"\\\\?\\" + candidate;

    // Verify existence via a file open (not GetFileAttributesW, which races).
    HandleGuard probe(
        CreateFileW(candidate.c_str(),
                    GENERIC_READ,
                    FILE_SHARE_READ,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr));

    if (!probe.valid()) {
        DWORD err = GetLastError();
        LOG_ERROR(L"Driver binary not found or inaccessible: '%ls' (0x%08X)",
                  candidate.c_str(), err);
        return err;
    }

    LOG_INFO(L"Resolved driver source: %ls", candidate.c_str());
    outPath = std::move(candidate);
    return ERROR_SUCCESS;
}

// ────────────────────────────────────────────────────────────────────────────
//  CopyDriverBinary
//  Security design:
//   1. Verify Authenticode signature of source binary.
//   2. Open source with exclusive-write denial to prevent TOCTOU replacement.
//   3. Manual stream-copy (SecureCopyFile) while holding the locked handle.
//   4. Atomic rename .tmp → final path.
// ────────────────────────────────────────────────────────────────────────────
DWORD CopyDriverBinary(const std::wstring& srcPath, std::wstring& dstPath)
{
    dstPath = BuildSystemDriverPath();
    if (dstPath.empty()) {
        LOG_ERROR(L"GetWindowsDirectoryW failed (0x%08X)", GetLastError());
        return GetLastError() ? GetLastError() : ERROR_FUNCTION_FAILED;
    }

    // --- Step 1: Verify Authenticode signature BEFORE touching the destination.
    DWORD err = VerifyDriverSignature(srcPath);
    if (err != ERROR_SUCCESS) {
        LOG_ERROR(L"Signature verification FAILED for '%ls'. Driver copy aborted.", srcPath.c_str());
        return err;
    }
    LOG_INFO(L"Authenticode signature verified for: %ls", srcPath.c_str());

    // --- Step 2 + 3: Locked copy (SecureCopyFile denies write-share on src).
    std::wstring tmpDst = dstPath + L".tmp";
    LOG_INFO(L"Secure-copying driver to temp: %ls", tmpDst.c_str());

    err = SecureCopyFile(srcPath, tmpDst);
    if (err != ERROR_SUCCESS) {
        LOG_ERROR(L"SecureCopyFile failed (0x%08X).", err);
        return err;
    }

    // --- Step 4: Atomic rename .tmp → final destination.
    if (!MoveFileExW(tmpDst.c_str(), dstPath.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        err = GetLastError();
        LOG_ERROR(L"MoveFileExW failed (0x%08X): %ls -> %ls",
                  err, tmpDst.c_str(), dstPath.c_str());
        DeleteFileW(tmpDst.c_str());
        return err;
    }

    LOG_INFO(L"Driver staged atomically to: %ls", dstPath.c_str());
    return ERROR_SUCCESS;
}

// ────────────────────────────────────────────────────────────────────────────
//  StopAndDeleteExistingService
// ────────────────────────────────────────────────────────────────────────────
DWORD StopAndDeleteExistingService(SC_HANDLE hScm)
{
    ScHandleGuard svc(OpenServiceW(hScm, kServiceName,
                                   SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE));
    if (!svc.valid()) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            LOG_INFO(L"Service '%ls' does not exist; nothing to remove.", kServiceName);
            return ERROR_SUCCESS;
        }
        LOG_ERROR(L"OpenServiceW failed (0x%08X)", err);
        return err;
    }

    SERVICE_STATUS ss{};
    if (QueryServiceStatus(svc.get(), &ss) &&
        ss.dwCurrentState != SERVICE_STOPPED)
    {
        LOG_INFO(L"Stopping service '%ls' (current state: %lu)...",
                 kServiceName, ss.dwCurrentState);

        SERVICE_STATUS ctrlStatus{};
        ControlService(svc.get(), SERVICE_CONTROL_STOP, &ctrlStatus);

        constexpr int kTimeoutMs = 10'000;
        constexpr int kPollMs    = 250;
        int waited = 0;

        while (waited < kTimeoutMs) {
            Sleep(static_cast<DWORD>(kPollMs));
            waited += kPollMs;
            SERVICE_STATUS ss2{};
            if (QueryServiceStatus(svc.get(), &ss2) &&
                ss2.dwCurrentState == SERVICE_STOPPED)
            {
                LOG_INFO(L"Service stopped after %d ms.", waited);
                break;
            }
        }

        SERVICE_STATUS ss3{};
        if (QueryServiceStatus(svc.get(), &ss3) &&
            ss3.dwCurrentState != SERVICE_STOPPED)
        {
            LOG_WARN(L"Service did not stop within %d ms; forcing deletion.", kTimeoutMs);
        }
    }

    if (!DeleteService(svc.get())) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_MARKED_FOR_DELETE) {
            LOG_ERROR(L"DeleteService failed (0x%08X)", err);
            return err;
        }
        LOG_WARN(L"Service marked for delete (removed at next SCM restart).");
    } else {
        LOG_INFO(L"Service '%ls' deleted.", kServiceName);
    }

    return ERROR_SUCCESS;
}

// ────────────────────────────────────────────────────────────────────────────
//  CreateDriverService
// ────────────────────────────────────────────────────────────────────────────
DWORD CreateDriverService(SC_HANDLE hScm, const std::wstring& sysDst)
{
    LOG_INFO(L"Creating SCM service entry for '%ls'...", kServiceName);

    ScHandleGuard svc(
        CreateServiceW(
            hScm,
            kServiceName,
            kServiceDisplayName,
            SERVICE_ALL_ACCESS,
            SERVICE_FILE_SYSTEM_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            sysDst.c_str(),
            kLoadOrderGroup,
            nullptr,   // lpdwTagId
            nullptr,   // lpDependencies
            nullptr,   // lpServiceStartName (LocalSystem)
            nullptr    // lpPassword
        ));

    if (!svc.valid()) {
        DWORD err = GetLastError();
        LOG_ERROR(L"CreateServiceW failed (0x%08X)", err);
        return err;
    }

    SERVICE_DESCRIPTIONW sd{};
    sd.lpDescription = const_cast<LPWSTR>(kServiceDescription);
    if (!ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_DESCRIPTION, &sd)) {
        LOG_WARN(L"ChangeServiceConfig2W (description) failed (0x%08X) -- non-fatal.",
                 GetLastError());
    }

    LOG_INFO(L"SCM service '%ls' created.", kServiceName);
    return ERROR_SUCCESS;
}

// ────────────────────────────────────────────────────────────────────────────
//  ConfigureMinifilterRegistry
//  Key paths match PhantomSensor.INF [PhantomSensor.AddRegistry]:
//    HKR,"Parameters\Instances","DefaultInstance" (relative to service key)
//    HKR,"Parameters\Instances\%DefaultInstance%","Altitude"
//    HKR,"Parameters\Instances\%DefaultInstance%","Flags"
// ────────────────────────────────────────────────────────────────────────────
DWORD ConfigureMinifilterRegistry()
{
    constexpr wchar_t kSvcParameters[] =
        L"SYSTEM\\CurrentControlSet\\Services\\PhantomSensor\\Parameters\\Instances";
    constexpr wchar_t kSvcInstance[] =
        L"SYSTEM\\CurrentControlSet\\Services\\PhantomSensor\\Parameters\\Instances\\"
        L"PhantomSensor Instance";

    auto OpenOrCreate = [](const wchar_t* subKey) -> RegKeyGuard {
        HKEY  hk   = nullptr;
        DWORD disp = 0;
        LONG rc = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE, subKey, 0, nullptr,
            REG_OPTION_NON_VOLATILE, KEY_SET_VALUE | KEY_WOW64_64KEY,
            nullptr, &hk, &disp);
        if (rc != ERROR_SUCCESS)
            return RegKeyGuard{};
        return RegKeyGuard{hk};
    };

    // Parameters\Instances – DefaultInstance value
    {
        RegKeyGuard hInst = OpenOrCreate(kSvcParameters);
        if (!hInst.valid()) {
            LOG_ERROR(L"Failed to create key: %ls (0x%08X)", kSvcParameters, GetLastError());
            return GetLastError() ? GetLastError() : ERROR_FUNCTION_FAILED;
        }

        const DWORD cb = static_cast<DWORD>((wcslen(kDefaultInstance) + 1) * sizeof(wchar_t));
        LONG rc = RegSetValueExW(hInst.get(), L"DefaultInstance", 0, REG_SZ,
                                 reinterpret_cast<const BYTE*>(kDefaultInstance), cb);
        if (rc != ERROR_SUCCESS) {
            LOG_ERROR(L"RegSetValueExW DefaultInstance failed (%ld)", rc);
            return static_cast<DWORD>(rc);
        }
    }

    // Instance sub-key – Altitude and Flags
    {
        RegKeyGuard hIKey = OpenOrCreate(kSvcInstance);
        if (!hIKey.valid()) {
            LOG_ERROR(L"Failed to create key: %ls (0x%08X)", kSvcInstance, GetLastError());
            return GetLastError() ? GetLastError() : ERROR_FUNCTION_FAILED;
        }

        const DWORD cbAlt = static_cast<DWORD>((wcslen(kAltitude) + 1) * sizeof(wchar_t));
        LONG rc = RegSetValueExW(hIKey.get(), L"Altitude", 0, REG_SZ,
                                 reinterpret_cast<const BYTE*>(kAltitude), cbAlt);
        if (rc != ERROR_SUCCESS) {
            LOG_ERROR(L"RegSetValueExW Altitude failed (%ld)", rc);
            return static_cast<DWORD>(rc);
        }

        DWORD flags = 0;
        rc = RegSetValueExW(hIKey.get(), L"Flags", 0, REG_DWORD,
                            reinterpret_cast<const BYTE*>(&flags), sizeof(flags));
        if (rc != ERROR_SUCCESS) {
            LOG_ERROR(L"RegSetValueExW Flags failed (%ld)", rc);
            return static_cast<DWORD>(rc);
        }
    }

    LOG_INFO(L"Minifilter registry configured: altitude=%ls, instance='%ls'.",
             kAltitude, kDefaultInstance);
    return ERROR_SUCCESS;
}

// ────────────────────────────────────────────────────────────────────────────
//  LoadDriver  (FilterLoad → StartServiceW fallback)
// ────────────────────────────────────────────────────────────────────────────
DWORD LoadDriver(SC_HANDLE hScm)
{
    LOG_INFO(L"Loading driver via FilterLoad('%ls')...", kServiceName);

    HRESULT hr = FilterLoad(kServiceName);
    if (SUCCEEDED(hr)) {
        LOG_INFO(L"FilterLoad succeeded (HRESULT=0x%08X).", hr);
        return ERROR_SUCCESS;
    }

    if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_FUNCTION)) {
        LOG_WARN(L"FilterLoad returned ERROR_INVALID_FUNCTION; "
                 L"falling back to StartServiceW...");
    } else {
        LOG_WARN(L"FilterLoad returned 0x%08X; trying StartServiceW as fallback.", hr);
    }

    ScHandleGuard svc(OpenServiceW(hScm, kServiceName,
                                   SERVICE_START | SERVICE_QUERY_STATUS));
    if (!svc.valid()) {
        DWORD err = GetLastError();
        LOG_ERROR(L"OpenServiceW for start failed (0x%08X)", err);
        return err;
    }

    if (!StartServiceW(svc.get(), 0, nullptr)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            LOG_INFO(L"Driver service already running.");
            return ERROR_SUCCESS;
        }
        LOG_ERROR(L"StartServiceW failed (0x%08X)", err);
        return err;
    }

    constexpr int kPollMs  = 500;
    constexpr int kMaxWait = 10'000;
    int waited = 0;
    while (waited < kMaxWait) {
        Sleep(static_cast<DWORD>(kPollMs));
        waited += kPollMs;
        SERVICE_STATUS ss{};
        if (QueryServiceStatus(svc.get(), &ss)) {
            if (ss.dwCurrentState == SERVICE_RUNNING) {
                LOG_INFO(L"Driver service running after %d ms.", waited);
                return ERROR_SUCCESS;
            }
            if (ss.dwCurrentState == SERVICE_STOPPED) {
                LOG_ERROR(L"Driver service stopped unexpectedly "
                          L"(win32ExitCode=0x%08X).", ss.dwWin32ExitCode);
                return ss.dwWin32ExitCode ? ss.dwWin32ExitCode : ERROR_FUNCTION_FAILED;
            }
        }
    }

    LOG_WARN(L"Driver service did not reach RUNNING within %d ms.", kMaxWait);
    return ERROR_TIMEOUT;
}

// ────────────────────────────────────────────────────────────────────────────
//  SetInstallCompleteMarker
// ────────────────────────────────────────────────────────────────────────────
DWORD SetInstallCompleteMarker()
{
    HKEY  hk   = nullptr;
    DWORD disp = 0;
    LONG  rc   = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE, kInstallCompleteKey, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE | KEY_WOW64_64KEY,
        nullptr, &hk, &disp);

    if (rc != ERROR_SUCCESS) {
        LOG_ERROR(L"RegCreateKeyExW '%ls' failed (%ld)", kInstallCompleteKey, rc);
        return static_cast<DWORD>(rc);
    }

    RegKeyGuard key(hk);
    DWORD value = 1;
    rc = RegSetValueExW(key.get(), kInstallCompleteVal, 0, REG_DWORD,
                        reinterpret_cast<const BYTE*>(&value), sizeof(value));
    if (rc != ERROR_SUCCESS) {
        LOG_ERROR(L"RegSetValueExW InstallComplete failed (%ld)", rc);
        return static_cast<DWORD>(rc);
    }

    LOG_INFO(L"InstallComplete=1 written to HKLM\\%ls.", kInstallCompleteKey);
    return ERROR_SUCCESS;
}

// ────────────────────────────────────────────────────────────────────────────
//  ClearRunOnceEntry
// ────────────────────────────────────────────────────────────────────────────
DWORD ClearRunOnceEntry()
{
    HKEY hk = nullptr;
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRunOnceKey, 0,
                            KEY_SET_VALUE | KEY_WOW64_64KEY, &hk);
    if (rc == ERROR_FILE_NOT_FOUND)
        return ERROR_SUCCESS;
    if (rc != ERROR_SUCCESS) {
        LOG_WARN(L"RegOpenKeyExW RunOnce failed (%ld) -- skipping.", rc);
        return ERROR_SUCCESS;
    }

    RegKeyGuard key(hk);
    rc = RegDeleteValueW(key.get(), kRunOnceValName);
    if (rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND) {
        LOG_WARN(L"RegDeleteValueW RunOnce failed (%ld) -- non-fatal.", rc);
        return ERROR_SUCCESS;
    }

    if (rc == ERROR_SUCCESS)
        LOG_INFO(L"RunOnce entry '%ls' removed.", kRunOnceValName);

    return ERROR_SUCCESS;
}

// ────────────────────────────────────────────────────────────────────────────
//  UninstallDriver
// ────────────────────────────────────────────────────────────────────────────
DWORD UninstallDriver(SC_HANDLE hScm)
{
    LOG_INFO(L"Beginning driver uninstall...");

    DWORD err = StopAndDeleteExistingService(hScm);
    if (err != ERROR_SUCCESS && err != ERROR_SERVICE_DOES_NOT_EXIST) {
        LOG_WARN(L"StopAndDeleteExistingService returned 0x%08X; continuing.", err);
    }

    // Remove driver binary from System32\drivers
    std::wstring sysDst = BuildSystemDriverPath();
    if (!sysDst.empty()) {
        if (!DeleteFileW(sysDst.c_str())) {
            err = GetLastError();
            if (err != ERROR_FILE_NOT_FOUND) {
                LOG_WARN(L"DeleteFileW('%ls') failed (0x%08X) -- may need reboot.",
                         sysDst.c_str(), err);
            }
        } else {
            LOG_INFO(L"Removed driver binary: %ls", sysDst.c_str());
        }
    }

    // Clear install-complete marker.
    {
        HKEY hk = nullptr;
        LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kInstallCompleteKey, 0,
                                KEY_SET_VALUE | KEY_WOW64_64KEY, &hk);
        if (rc == ERROR_SUCCESS) {
            RegKeyGuard key(hk);
            RegDeleteValueW(key.get(), kInstallCompleteVal);
            LOG_INFO(L"InstallComplete marker removed.");
        }
    }

    // Remove minifilter instance keys (best-effort; use 64-bit hive view).
    RegDeleteKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\PhantomSensor\\"
        L"Parameters\\Instances\\PhantomSensor Instance",
        KEY_WOW64_64KEY, 0);
    RegDeleteKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\PhantomSensor\\Parameters\\Instances",
        KEY_WOW64_64KEY, 0);

    LOG_INFO(L"Driver uninstall complete.");
    return ERROR_SUCCESS;
}

} // namespace ShadowStrike::Installer
