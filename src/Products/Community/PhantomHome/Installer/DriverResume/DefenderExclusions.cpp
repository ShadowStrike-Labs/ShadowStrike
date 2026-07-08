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
 * @file DefenderExclusions.cpp
 * @brief Best-effort Defender path-exclusion registration.
 *
 * Reuses SpawnAndCapture from TestSigningPivot (publicly declared in
 * TestSigningPivot.hpp) so all child-process spawning goes through the
 * single hardened code path (handle-list inheritance, NUL stdin, timeout,
 * dedicated drain thread).
 *
 * Failure semantics: this is best-effort hygiene; signed binaries should
 * already pass Defender.  The function succeeds if AT LEAST ONE path was
 * accepted, and only returns failure when every attempt fails.
 */

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>
#include <shlobj.h>

#include <string>
#include <vector>

#include "DefenderExclusions.hpp"
#include "TestSigningPivot.hpp"  // SpawnAndCapture

namespace ShadowStrike::Installer::Internal {
void Log(const wchar_t* level, const wchar_t* fmt, ...);
}
#define LOG_INFO(fmt, ...)  ::ShadowStrike::Installer::Internal::Log(L"INFO ", fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  ::ShadowStrike::Installer::Internal::Log(L"WARN ", fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) ::ShadowStrike::Installer::Internal::Log(L"ERROR", fmt, ##__VA_ARGS__)

namespace ShadowStrike::Installer {

namespace {

constexpr DWORD kPerCallTimeoutMs = 10'000;

// A single batched Add-MpPreference call pays the (slow) Defender PowerShell
// module load ONCE. On a fresh VM that cold-load alone can approach the 10 s
// per-call budget, which is why the previous per-path calls timed out and lost
// 3 of 4 exclusions. The one batched call gets a wider budget.
constexpr DWORD kBatchTimeoutMs   = 45'000;

// Strip trailing path separators so we don't pass "C:\foo\" which can be
// rejected by some Defender code paths.
[[nodiscard]] std::wstring NormalisePath(std::wstring p)
{
    while (p.size() > 3 && (p.back() == L'\\' || p.back() == L'/')) {
        p.pop_back();
    }
    return p;
}

// PowerShell single-quoted strings escape ' as ''.  Wrap the path in single
// quotes after escaping any embedded quote.
[[nodiscard]] std::wstring EscapeForPowerShellSingleQuoted(const std::wstring& s)
{
    std::wstring out;
    out.reserve(s.size() + 2);
    out.push_back(L'\'');
    for (wchar_t c : s) {
        if (c == L'\'') out.append(L"''");
        else            out.push_back(c);
    }
    out.push_back(L'\'');
    return out;
}

// For wmic command-line: backslashes inside a double-quoted token are fine,
// but a double quote inside the path would be catastrophic.  Reject any path
// containing a double quote (defence-in-depth – real install paths never do).
[[nodiscard]] bool PathIsSafeForCli(const std::wstring& p) noexcept
{
    return p.find(L'"') == std::wstring::npos;
}

[[nodiscard]] DWORD ResolveSystemTool(const wchar_t* leaf, std::wstring& out) noexcept
{
    wchar_t sysDir[MAX_PATH] = {};
    if (GetSystemDirectoryW(sysDir, MAX_PATH) == 0) {
        const DWORD e = GetLastError();
        LOG_ERROR(L"DefenderExclusions: GetSystemDirectoryW failed (0x%08X).", e);
        return e ? e : ERROR_FUNCTION_FAILED;
    }
    out.assign(sysDir);
    out.push_back(L'\\');
    out.append(leaf);
    if (GetFileAttributesW(out.c_str()) == INVALID_FILE_ATTRIBUTES) {
        const DWORD e = GetLastError();
        LOG_INFO(L"DefenderExclusions: tool not found at '%ls' (0x%08X).",
                 out.c_str(), e);
        return e ? e : ERROR_FILE_NOT_FOUND;
    }
    return ERROR_SUCCESS;
}

// Attempt a single Add-MpPreference -ExclusionPath via powershell.exe.
[[nodiscard]] DWORD AddViaPowerShell(const std::wstring& psPath,
                                     const std::wstring& target) noexcept
{
    if (!PathIsSafeForCli(target)) {
        LOG_ERROR(L"DefenderExclusions: rejecting unsafe path '%ls'.", target.c_str());
        return ERROR_INVALID_NAME;
    }
    const std::wstring quoted = EscapeForPowerShellSingleQuoted(target);

    // Build: "<psPath>" -NoProfile -NonInteractive -ExecutionPolicy Bypass
    //        -Command "Add-MpPreference -ExclusionPath '<p>' -ErrorAction SilentlyContinue"
    std::wstring cmd;
    cmd.reserve(256 + quoted.size());
    cmd.push_back(L'"');
    cmd.append(psPath);
    cmd.append(L"\" -NoProfile -NonInteractive -ExecutionPolicy Bypass "
               L"-Command \"Add-MpPreference -ExclusionPath ");
    cmd.append(quoted);
    cmd.append(L" -ErrorAction SilentlyContinue\"");

    std::string output;
    DWORD       exitCode = 0;
    const DWORD spawnErr = SpawnAndCapture(cmd, output, exitCode, kPerCallTimeoutMs);
    if (spawnErr != ERROR_SUCCESS) {
        LOG_WARN(L"DefenderExclusions: PowerShell spawn failed for '%ls' "
                 L"(0x%08X).", target.c_str(), spawnErr);
        return spawnErr;
    }
    if (exitCode != 0) {
        LOG_WARN(L"DefenderExclusions: PowerShell exited %lu for '%ls'.",
                 exitCode, target.c_str());
        return ERROR_FUNCTION_FAILED;
    }
    LOG_INFO(L"DefenderExclusions: PowerShell added exclusion '%ls'.",
             target.c_str());
    return ERROR_SUCCESS;
}

// Register ALL exclusion paths in a SINGLE powershell.exe invocation.
// Add-MpPreference -ExclusionPath accepts an array; batching pays the heavy
// Defender-module load once instead of once per path -- the per-path cold-start
// was the root cause of the install-time timeouts (3 of 4 lost on a fresh VM).
[[nodiscard]] DWORD AddAllViaPowerShell(const std::wstring& psPath,
                                        const std::vector<std::wstring>& targets,
                                        size_t& acceptedOut) noexcept
{
    acceptedOut = 0;

    std::wstring list;
    size_t counted = 0;
    for (const auto& t : targets) {
        if (t.empty()) {
            continue;
        }
        if (!PathIsSafeForCli(t)) {
            LOG_ERROR(L"DefenderExclusions: rejecting unsafe path '%ls'.", t.c_str());
            continue;
        }
        if (!list.empty()) {
            list.push_back(L',');
        }
        list.append(EscapeForPowerShellSingleQuoted(t));
        ++counted;
    }
    if (counted == 0) {
        return ERROR_INVALID_PARAMETER;
    }

    // "<psPath>" -NoProfile -NonInteractive -ExecutionPolicy Bypass
    //   -Command "Add-MpPreference -ExclusionPath 'p1','p2',... -ErrorAction SilentlyContinue"
    std::wstring cmd;
    cmd.reserve(320 + list.size());
    cmd.push_back(L'"');
    cmd.append(psPath);
    cmd.append(L"\" -NoProfile -NonInteractive -ExecutionPolicy Bypass "
               L"-Command \"Add-MpPreference -ExclusionPath ");
    cmd.append(list);
    cmd.append(L" -ErrorAction SilentlyContinue\"");

    std::string output;
    DWORD       exitCode = 0;
    const DWORD spawnErr = SpawnAndCapture(cmd, output, exitCode, kBatchTimeoutMs);
    if (spawnErr != ERROR_SUCCESS) {
        LOG_WARN(L"DefenderExclusions: batched PowerShell spawn failed (0x%08X).",
                 spawnErr);
        return spawnErr;
    }
    if (exitCode != 0) {
        LOG_WARN(L"DefenderExclusions: batched PowerShell exited %lu.", exitCode);
        return ERROR_FUNCTION_FAILED;
    }
    acceptedOut = counted;
    LOG_INFO(L"DefenderExclusions: batched PowerShell added %zu exclusion(s).",
             counted);
    return ERROR_SUCCESS;
}

// Fallback path: wmic.exe.  Note: wmic is deprecated in modern Windows and may
// be absent entirely.  This is gated on a successful ResolveSystemTool first.
[[nodiscard]] DWORD AddViaWmic(const std::wstring& wmicPath,
                               const std::wstring& target) noexcept
{
    if (!PathIsSafeForCli(target)) {
        return ERROR_INVALID_NAME;
    }

    // wmic /Namespace:\\root\Microsoft\Windows\Defender path MSFT_MpPreference
    //   call Add ExclusionPath="<p>"
    std::wstring cmd;
    cmd.reserve(256 + target.size());
    cmd.push_back(L'"');
    cmd.append(wmicPath);
    cmd.append(L"\" /Namespace:\\\\root\\Microsoft\\Windows\\Defender "
               L"path MSFT_MpPreference call Add ExclusionPath=\"");
    cmd.append(target);
    cmd.push_back(L'"');

    std::string output;
    DWORD       exitCode = 0;
    const DWORD spawnErr = SpawnAndCapture(cmd, output, exitCode, kPerCallTimeoutMs);
    if (spawnErr != ERROR_SUCCESS) {
        LOG_WARN(L"DefenderExclusions: wmic spawn failed for '%ls' (0x%08X).",
                 target.c_str(), spawnErr);
        return spawnErr;
    }
    if (exitCode != 0) {
        LOG_WARN(L"DefenderExclusions: wmic exited %lu for '%ls'.",
                 exitCode, target.c_str());
        return ERROR_FUNCTION_FAILED;
    }
    LOG_INFO(L"DefenderExclusions: wmic added exclusion '%ls'.", target.c_str());
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD GetProgramDataShadowStrike(std::wstring& out)
{
    wchar_t pd[MAX_PATH + 1] = {};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr,
                                SHGFP_TYPE_CURRENT, pd)))
    {
        const DWORD e = GetLastError();
        LOG_WARN(L"DefenderExclusions: SHGetFolderPathW failed (0x%08X).", e);
        return e ? e : ERROR_PATH_NOT_FOUND;
    }
    out.assign(pd);
    out.append(L"\\ShadowStrike");
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD GetSystem32DriverPath(std::wstring& out)
{
    wchar_t sys[MAX_PATH + 1] = {};
    if (GetSystemDirectoryW(sys, MAX_PATH) == 0) {
        const DWORD e = GetLastError();
        LOG_WARN(L"DefenderExclusions: GetSystemDirectoryW failed (0x%08X).", e);
        return e ? e : ERROR_FUNCTION_FAILED;
    }
    out.assign(sys);
    out.append(L"\\drivers\\PhantomSensor.sys");
    return ERROR_SUCCESS;
}

} // anonymous namespace

DWORD AddPhantomDefenderExclusions(const std::wstring& installFolder) noexcept
{
    if (installFolder.empty()) {
        LOG_ERROR(L"DefenderExclusions: empty install folder.");
        return ERROR_INVALID_PARAMETER;
    }

    LOG_INFO(L"DefenderExclusions: starting (installFolder='%ls').",
             installFolder.c_str());

    // Build the list of paths.
    std::vector<std::wstring> targets;
    targets.reserve(4);
    targets.emplace_back(NormalisePath(installFolder));

    std::wstring programData;
    if (GetProgramDataShadowStrike(programData) == ERROR_SUCCESS) {
        targets.emplace_back(std::move(programData));
    }

    {
        std::wstring inTreeDriver = NormalisePath(installFolder);
        inTreeDriver.append(L"\\Drivers\\PhantomSensor.sys");
        targets.emplace_back(std::move(inTreeDriver));
    }

    std::wstring sysDrv;
    if (GetSystem32DriverPath(sysDrv) == ERROR_SUCCESS) {
        targets.emplace_back(std::move(sysDrv));
    }

    // Resolve PowerShell first; if missing, fall back to wmic.
    std::wstring psPath;
    const DWORD psFound = ResolveSystemTool(
        L"WindowsPowerShell\\v1.0\\powershell.exe", psPath);

    std::wstring wmicPath;
    DWORD        wmicFound = ERROR_FILE_NOT_FOUND;
    if (psFound != ERROR_SUCCESS) {
        wmicFound = ResolveSystemTool(L"wbem\\wmic.exe", wmicPath);
    }

    if (psFound != ERROR_SUCCESS && wmicFound != ERROR_SUCCESS) {
        LOG_WARN(L"DefenderExclusions: neither PowerShell nor wmic is "
                 L"available; skipping (best-effort).");
        return ERROR_FILE_NOT_FOUND;
    }

    DWORD  lastErr   = ERROR_SUCCESS;
    size_t successes = 0;

    // Fast path: one batched PowerShell call for all paths (pays the slow
    // Defender module load once instead of once per path). This is the fix for
    // the install-time timeouts where per-path cold-starts lost most exclusions.
    if (psFound == ERROR_SUCCESS) {
        size_t accepted = 0;
        const DWORD batchErr = AddAllViaPowerShell(psPath, targets, accepted);
        if (batchErr == ERROR_SUCCESS) {
            successes = accepted;
        } else {
            lastErr = batchErr;
        }
    }

    // Fallback: per-path attempts (PowerShell then wmic), used only if the batch
    // did not succeed (e.g. PowerShell unavailable, or the single call failed).
    if (successes == 0) {
        for (const auto& target : targets) {
            if (target.empty()) {
                continue;
            }
            DWORD err = ERROR_FUNCTION_FAILED;
            if (psFound == ERROR_SUCCESS) {
                err = AddViaPowerShell(psPath, target);
            }
            if (err != ERROR_SUCCESS && wmicFound == ERROR_SUCCESS) {
                err = AddViaWmic(wmicPath, target);
            }
            if (err == ERROR_SUCCESS) {
                ++successes;
            } else {
                lastErr = err;
            }
        }
    }

    if (successes > 0) {
        LOG_INFO(L"DefenderExclusions: %zu of %zu exclusions accepted.",
                 successes, targets.size());
        return ERROR_SUCCESS;
    }

    LOG_WARN(L"DefenderExclusions: ALL %zu exclusion attempts failed "
             L"(last error 0x%08X). Continuing -- best-effort only.",
             targets.size(), lastErr);
    return lastErr == ERROR_SUCCESS ? ERROR_FUNCTION_FAILED : lastErr;
}

} // namespace ShadowStrike::Installer
