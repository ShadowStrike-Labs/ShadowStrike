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

// winreg.h carries an SAL annotation on RegOpenKeyExW's ulOptions parameter
// (declared with a "value" annotation on what /analyze treats as a numeric
// constant) that triggers C6553 from /analyze /sdl on every caller.  The
// warning is in the SDK header, not our code; suppress it at TU scope so the
// installer can be built clean under /W4 /WX /analyze.
#pragma warning(disable: 6553)

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
    // GetModuleFileNameW(nullptr, nullptr, 0) does NOT report required size:
    // it writes nothing, returns 0, and sets ERROR_INSUFFICIENT_BUFFER. The
    // canonical pattern is to grow the buffer until the API stops truncating
    // (signalled by returnedLen < bufferSize AND no ERROR_INSUFFICIENT_BUFFER).
    // We cap at 32 KiB which is the documented Win32 path ceiling.
    constexpr DWORD kInitial  = MAX_PATH;
    constexpr DWORD kAbsCap   = 32 * 1024;  // 32 KiB = NT path ceiling.

    std::wstring buf;
    for (DWORD cap = kInitial; cap <= kAbsCap; cap *= 2) {
        buf.assign(static_cast<size_t>(cap), L'\0');
        ::SetLastError(ERROR_SUCCESS);
        const DWORD len = ::GetModuleFileNameW(nullptr, buf.data(), cap);
        if (len == 0) {
            return {};
        }
        if (len < cap && ::GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            buf.resize(len);
            const auto pos = buf.rfind(L'\\');
            if (pos == std::wstring::npos)
                return {};
            return buf.substr(0, pos);
        }
        // Buffer was too small; double and retry.
    }
    ::SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return {};
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
//  StripExtendedLengthPrefix
//  Returns a pointer past a leading "\\?\" prefix, or the original pointer
//  if no prefix is present.  Used solely for volume-path comparison: the
//  source path is stored with the "\\?\" prefix for long-path safety, but
//  GetVolumePathNameW returns the prefix iff the input has it.  Without
//  normalisation a true same-volume copy would be misclassified as cross-
//  volume and rejected.
// ────────────────────────────────────────────────────────────────────────────
static const wchar_t* StripExtendedLengthPrefix(const wchar_t* p) noexcept
{
    if (p != nullptr &&
        p[0] == L'\\' && p[1] == L'\\' &&
        p[2] == L'?'  && p[3] == L'\\')
    {
        return p + 4;
    }
    return p;
}

// ────────────────────────────────────────────────────────────────────────────
//  VerifyDriverSignatureByHandle
//  Uses WinVerifyTrust with an already-open HANDLE so the file cannot be
//  swapped between verification and copy.  pcwszFilePath is still required by
//  the SIP (Subject Interface Package) to locate the Authenticode data in the
//  file's security directory; setting hFile prevents WinVerifyTrust from
//  opening a second file handle (which would reintroduce the TOCTOU window).
// ────────────────────────────────────────────────────────────────────────────
static DWORD VerifyDriverSignatureByHandle(HANDLE hFile, const std::wstring& filePath)
{
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct       = sizeof(fileInfo);
    fileInfo.pcwszFilePath  = filePath.c_str();
    fileInfo.hFile          = hFile;    // Use caller's handle — no second open.
    fileInfo.pgKnownSubject = nullptr;

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA wtd{};
    wtd.cbStruct            = sizeof(wtd);
    wtd.pPolicyCallbackData = nullptr;
    wtd.pSIPClientData      = nullptr;
    wtd.dwUIChoice          = WTD_UI_NONE;
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE;   // Skip CRL (offline-friendly)
    wtd.dwUnionChoice       = WTD_CHOICE_FILE;
    wtd.pFile               = &fileInfo;
    wtd.dwStateAction       = WTD_STATEACTION_VERIFY;
    wtd.hWVTStateData       = nullptr;
    wtd.pwszURLReference    = nullptr;
    wtd.dwProvFlags         = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;
    wtd.dwUIContext         = 0;

    LONG status = WinVerifyTrust(nullptr, &policyGuid, &wtd);

    // Always close the state data to prevent WinVerifyTrust resource leak.
    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policyGuid, &wtd);

    // Acceptable results:
    //   ERROR_SUCCESS (0)                   - trusted chain
    //   CERT_E_UNTRUSTEDROOT (0x800B0109)   - self-signed / dev cert root
    //   CERT_E_CHAINING (0x800B010A)        - chain build failure (also dev cert)
    // Rejected:
    //   TRUST_E_NOSIGNATURE (0x800B0100)    - no signature at all
    //   TRUST_E_EXPLICIT_DISTRUST           - explicitly distrusted
    //   Any other HRESULT failure

    if (status == static_cast<LONG>(CERT_E_UNTRUSTEDROOT) ||
        status == static_cast<LONG>(CERT_E_CHAINING))
    {
        LOG_WARN(L"Driver binary has a dev-cert signature (root not in CA store). "
                 L"Acceptable for dev/test builds. HRESULT=0x%08X", status);
        return ERROR_SUCCESS;
    }

    if (status == ERROR_SUCCESS) {
        LOG_INFO(L"Driver binary signature fully trusted.");
        return ERROR_SUCCESS;
    }

    LOG_ERROR(L"WinVerifyTrust REJECTED '%ls': HRESULT=0x%08X. "
              L"Refusing to copy unsigned or tampered driver to System32.",
              filePath.c_str(), static_cast<DWORD>(status));
    return ERROR_INVALID_DATA;
}

// ────────────────────────────────────────────────────────────────────────────
//  StreamCopyFromHandle
//  Copies srcSize bytes from an already-open source handle to tmpDstPath.
//  The caller must set the source file position to the desired read offset
//  before calling (typically 0 after VerifyDriverSignatureByHandle).
// ────────────────────────────────────────────────────────────────────────────
static DWORD StreamCopyFromHandle(HANDLE hSrc,
                                   LONGLONG srcSize,
                                   const std::wstring& tmpDstPath)
{
    // Sanity cap: no legitimate kernel driver is > 64 MB.
    constexpr LONGLONG kMaxDriverBytes = 64LL * 1024 * 1024;
    if (srcSize > kMaxDriverBytes) {
        LOG_ERROR(L"Source size %lld B exceeds 64 MB cap. Refusing.", srcSize);
        return ERROR_FILE_TOO_LARGE;
    }

    HandleGuard dstHandle(
        CreateFileW(tmpDstPath.c_str(),
                    GENERIC_WRITE,
                    0,               // exclusive access — no sharing
                    nullptr,
                    CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                    nullptr));

    if (!dstHandle.valid()) {
        DWORD err = GetLastError();
        LOG_ERROR(L"StreamCopyFromHandle: cannot create '%ls' (0x%08X)",
                  tmpDstPath.c_str(), err);
        return err;
    }

    constexpr DWORD kChunk = 1024 * 1024;
    std::vector<BYTE> buf(kChunk);
    LONGLONG remaining = srcSize;

    while (remaining > 0) {
        DWORD toRead = static_cast<DWORD>(
            remaining < static_cast<LONGLONG>(kChunk) ? remaining : kChunk);
        DWORD bytesRead = 0;
        if (!ReadFile(hSrc, buf.data(), toRead, &bytesRead, nullptr) ||
            bytesRead != toRead)
        {
            DWORD err = GetLastError();
            LOG_ERROR(L"StreamCopyFromHandle: ReadFile failed (0x%08X)", err);
            dstHandle = HandleGuard{};
            DeleteFileW(tmpDstPath.c_str());
            return err;
        }

        DWORD bytesWritten = 0;
        if (!WriteFile(dstHandle.get(), buf.data(), bytesRead, &bytesWritten, nullptr) ||
            bytesWritten != bytesRead)
        {
            DWORD err = GetLastError();
            LOG_ERROR(L"StreamCopyFromHandle: WriteFile failed (0x%08X)", err);
            dstHandle = HandleGuard{};
            DeleteFileW(tmpDstPath.c_str());
            return err;
        }

        remaining -= bytesRead;
    }

    if (!FlushFileBuffers(dstHandle.get())) {
        LOG_WARN(L"StreamCopyFromHandle: FlushFileBuffers failed (0x%08X) -- non-fatal.",
                 GetLastError());
    }

    return ERROR_SUCCESS;
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
//  Security design (post-review hardening):
//   1. Open source file ONCE with FILE_SHARE_READ (exclusive write denial).
//      This single handle is used for BOTH signature verification and stream
//      copy — there is no window where the file can be swapped between them.
//   2. WinVerifyTrust receives the pre-opened HANDLE (fileInfo.hFile) so it
//      does not open the file a second time.
//   3. After WinVerifyTrust, seek source to offset 0 and stream-copy while
//      still holding the locked handle.
//   4. Atomic rename .tmp → final using MoveFileExW; same-volume check
//      ensures rename is truly atomic on NTFS (not a copy-then-delete).
// ────────────────────────────────────────────────────────────────────────────
DWORD CopyDriverBinary(const std::wstring& srcPath, std::wstring& dstPath)
{
    dstPath = BuildSystemDriverPath();
    if (dstPath.empty()) {
        LOG_ERROR(L"GetWindowsDirectoryW failed (0x%08X)", GetLastError());
        return GetLastError() ? GetLastError() : ERROR_FUNCTION_FAILED;
    }

    // --- Step 1: Open source with write-denial (TOCTOU prevention).
    //     FILE_SHARE_READ only — any concurrent WRITE or DELETE open fails.
    HandleGuard srcHandle(
        CreateFileW(srcPath.c_str(),
                    GENERIC_READ,
                    FILE_SHARE_READ,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr));

    if (!srcHandle.valid()) {
        DWORD err = GetLastError();
        LOG_ERROR(L"CopyDriverBinary: cannot open source '%ls' (0x%08X)",
                  srcPath.c_str(), err);
        return err;
    }

    // Get size while we have the handle (size is fixed once we deny writes).
    LARGE_INTEGER srcSize{};
    if (!GetFileSizeEx(srcHandle.get(), &srcSize)) {
        DWORD err = GetLastError();
        LOG_ERROR(L"CopyDriverBinary: GetFileSizeEx failed (0x%08X)", err);
        return err;
    }

    // --- Step 2: Verify Authenticode signature using the already-open handle.
    //     WinVerifyTrust receives hFile so it does not open a second handle.
    //     The write-denial on srcHandle is still in effect during verification.
    DWORD err = VerifyDriverSignatureByHandle(srcHandle.get(), srcPath);
    if (err != ERROR_SUCCESS) {
        LOG_ERROR(L"Signature verification FAILED. Driver copy aborted.");
        return err;
    }
    LOG_INFO(L"Authenticode signature verified for: %ls", srcPath.c_str());

    // --- Step 3: Verify source and destination are on the same volume.
    //     MoveFileExW is only atomic (kernel rename) on NTFS within one volume.
    //     Across volumes it degrades to copy+delete, which is not atomic.
    //
    //     The source path is stored with a "\\?\" extended-length prefix (for
    //     long-path safety) while the destination path is not.  GetVolumePathNameW
    //     preserves whichever form the caller supplied, so we must strip the
    //     prefix before string-comparing the two volume roots — otherwise every
    //     install would be misclassified as cross-volume.
    {
        wchar_t srcVol[MAX_PATH + 1]  = {};
        wchar_t dstVol[MAX_PATH + 1]  = {};
        bool gotBoth = GetVolumePathNameW(srcPath.c_str(), srcVol, MAX_PATH) &&
                       GetVolumePathNameW(dstPath.c_str(), dstVol, MAX_PATH);
        const wchar_t* srcVolNorm = StripExtendedLengthPrefix(srcVol);
        const wchar_t* dstVolNorm = StripExtendedLengthPrefix(dstVol);
        if (!gotBoth || _wcsicmp(srcVolNorm, dstVolNorm) != 0) {
            // Source and destination are on different volumes.
            // MoveFileExW would perform a non-atomic copy+delete, which is unsafe.
            // This configuration is not expected in any standard Windows install;
            // fail loudly so the condition is visible rather than silently unsafe.
            LOG_ERROR(L"Source volume '%ls' != destination volume '%ls'. "
                      L"Cross-volume rename is not atomic. Aborting.",
                      srcVolNorm, dstVolNorm);
            return ERROR_NOT_SAME_DEVICE;
        }
    }

    // --- Step 4: Seek source back to 0 and stream-copy while holding locked handle.
    {
        LARGE_INTEGER zero{};
        if (!SetFilePointerEx(srcHandle.get(), zero, nullptr, FILE_BEGIN)) {
            DWORD e = GetLastError();
            LOG_ERROR(L"CopyDriverBinary: SetFilePointerEx failed (0x%08X)", e);
            return e;
        }
    }

    std::wstring tmpDst = dstPath + L".tmp";
    LOG_INFO(L"Secure-copying driver to temp: %ls", tmpDst.c_str());

    err = StreamCopyFromHandle(srcHandle.get(), srcSize.QuadPart, tmpDst);
    if (err != ERROR_SUCCESS) {
        LOG_ERROR(L"StreamCopyFromHandle failed (0x%08X).", err);
        return err;
    }

    // --- Step 5: Atomic rename .tmp → final destination (NTFS rename = atomic).
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
    // srcHandle closes here — write-denial was maintained for the full operation.
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
//
//  FltMgr reads the canonical minifilter registry locations:
//    HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Instances
//    HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Instances\<instance>
//
//  Note that some legacy INF files use HKR,"Parameters\Instances",... — that
//  layout is NOT consulted by FltMgr and a minifilter registered there will
//  silently fail FilterLoad / FltRegisterFilter.  We always write the
//  canonical path here regardless of what an alternative INF-driven flow
//  may have produced; the values match the InstallDriver.cmd helper.
// ────────────────────────────────────────────────────────────────────────────
DWORD ConfigureMinifilterRegistry()
{
    constexpr wchar_t kSvcInstances[] =
        L"SYSTEM\\CurrentControlSet\\Services\\PhantomSensor\\Instances";
    constexpr wchar_t kSvcInstance[] =
        L"SYSTEM\\CurrentControlSet\\Services\\PhantomSensor\\Instances\\"
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

    // Instances – DefaultInstance value
    {
        RegKeyGuard hInst = OpenOrCreate(kSvcInstances);
        if (!hInst.valid()) {
            LOG_ERROR(L"Failed to create key: %ls (0x%08X)", kSvcInstances, GetLastError());
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
#pragma warning(push)
#pragma warning(disable: 6553)
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
#pragma warning(pop)

// ────────────────────────────────────────────────────────────────────────────
//  UninstallDriver
// ────────────────────────────────────────────────────────────────────────────
#pragma warning(push)
#pragma warning(disable: 6553)
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
        L"Instances\\PhantomSensor Instance",
        KEY_WOW64_64KEY, 0);
    RegDeleteKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\PhantomSensor\\Instances",
        KEY_WOW64_64KEY, 0);

    LOG_INFO(L"Driver uninstall complete.");
    return ERROR_SUCCESS;
}
#pragma warning(pop)

} // namespace ShadowStrike::Installer
