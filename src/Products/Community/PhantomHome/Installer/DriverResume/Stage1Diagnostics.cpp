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
 * @file Stage1Diagnostics.cpp
 * @brief Atomic snapshot writer for Stage 1 outcome.
 *
 * Output format: hand-rolled flat JSON (UTF-8).  No third-party deps.
 * Output path : %ProgramData%\ShadowStrike\State\driver-stage1.json
 * ACL (SDDL)  : O:SYG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)
 *
 * Atomicity: file is written first to "<name>.tmp" and then promoted via
 * MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH).
 */

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>
#include <shlobj.h>
#include <sddl.h>

#include <cstdio>
#include <string>
#include <vector>

#include "Stage1Diagnostics.hpp"
#include "DriverInstaller.hpp"  // HandleGuard

namespace ShadowStrike::Installer::Internal {
void Log(const wchar_t* level, const wchar_t* fmt, ...);
}
#define LOG_INFO(fmt, ...)  ::ShadowStrike::Installer::Internal::Log(L"INFO ", fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  ::ShadowStrike::Installer::Internal::Log(L"WARN ", fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) ::ShadowStrike::Installer::Internal::Log(L"ERROR", fmt, ##__VA_ARGS__)

namespace ShadowStrike::Installer {

namespace {

constexpr wchar_t kSddl[] = L"O:SYG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)";
constexpr wchar_t kStateRelDir[]   = L"ShadowStrike\\State";
constexpr wchar_t kFinalFileName[] = L"driver-stage1.json";
constexpr wchar_t kTempFileName[]  = L"driver-stage1.json.tmp";

// Hard cap on the serialised error message so a hostile or runaway error
// string cannot blow up the snapshot file.
constexpr size_t kMaxErrorMessageChars = 2048;

// ── JSON helpers ───────────────────────────────────────────────────────────

void AppendUtf8(std::string& out, const wchar_t* w, size_t wlen)
{
    if (wlen == 0 || w == nullptr) {
        return;
    }
    if (wlen > static_cast<size_t>(INT_MAX)) {
        wlen = static_cast<size_t>(INT_MAX);
    }
    const int needed = WideCharToMultiByte(
        CP_UTF8, 0, w, static_cast<int>(wlen),
        nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        return;
    }
    const size_t oldSize = out.size();
    out.resize(oldSize + static_cast<size_t>(needed));
    const int written = WideCharToMultiByte(
        CP_UTF8, 0, w, static_cast<int>(wlen),
        out.data() + oldSize, needed, nullptr, nullptr);
    if (written != needed) {
        out.resize(oldSize);
    }
}

// JSON-escape a wide string into UTF-8 inside ASCII double quotes.
void AppendJsonString(std::string& out, const std::wstring& in)
{
    out.push_back('"');
    // Bound the input length defensively.
    const size_t maxChars = in.size() > kMaxErrorMessageChars
                                ? kMaxErrorMessageChars
                                : in.size();
    for (size_t i = 0; i < maxChars; ++i) {
        const wchar_t ch = in[i];
        switch (ch) {
        case L'\\': out.append("\\\\"); break;
        case L'"':  out.append("\\\"");  break;
        case L'\b': out.append("\\b");  break;
        case L'\f': out.append("\\f");  break;
        case L'\n': out.append("\\n");  break;
        case L'\r': out.append("\\r");  break;
        case L'\t': out.append("\\t");  break;
        default:
            if (ch < 0x20) {
                char buf[8];
                _snprintf_s(buf, _countof(buf), _TRUNCATE,
                            "\\u%04X", static_cast<unsigned>(ch));
                out.append(buf);
            } else {
                AppendUtf8(out, &ch, 1);
            }
            break;
        }
    }
    out.push_back('"');
}

void AppendBool(std::string& out, bool v) { out.append(v ? "true" : "false"); }

void AppendDword(std::string& out, DWORD v)
{
    char buf[32];
    _snprintf_s(buf, _countof(buf), _TRUNCATE, "%lu", v);
    out.append(buf);
}

[[nodiscard]] std::string Serialise(const Stage1Snapshot& s)
{
    std::string j;
    j.reserve(512);
    j.push_back('{');

    auto field_bool = [&](const char* name, bool v, bool last) {
        j.push_back('"');
        j.append(name);
        j.append("\":");
        AppendBool(j, v);
        if (!last) j.push_back(',');
    };
    auto field_dword = [&](const char* name, DWORD v, bool last) {
        j.push_back('"');
        j.append(name);
        j.append("\":");
        AppendDword(j, v);
        if (!last) j.push_back(',');
    };

    field_bool ("service_registered",         s.service_registered,         false);
    field_dword("service_registration_error", s.service_registration_error, false);
    field_bool ("testsigning_state_before",   s.testsigning_state_before,   false);
    field_bool ("testsigning_state_after",    s.testsigning_state_after,    false);
    field_bool ("secureboot_blocks",          s.secureboot_blocks,          false);
    field_dword("bcdedit_exit",               s.bcdedit_exit,               false);
    field_bool ("stage2_task_registered",     s.stage2_task_registered,     false);
    field_bool ("reboot_required",            s.reboot_required,            false);

    j.append("\"last_error_message\":");
    AppendJsonString(j, s.last_error_message);

    j.push_back('}');
    return j;
}

// ── Path / directory helpers ───────────────────────────────────────────────

[[nodiscard]] DWORD GetStateDirectory(std::wstring& out)
{
    wchar_t pd[MAX_PATH + 1] = {};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr,
                                SHGFP_TYPE_CURRENT, pd)))
    {
        const DWORD err = GetLastError();
        LOG_ERROR(L"Stage1Diagnostics: SHGetFolderPathW failed (0x%08X).", err);
        return err ? err : ERROR_PATH_NOT_FOUND;
    }
    out.assign(pd);
    out.push_back(L'\\');
    out.append(kStateRelDir);
    const int rc = SHCreateDirectoryExW(nullptr, out.c_str(), nullptr);
    if (rc != ERROR_SUCCESS &&
        rc != ERROR_ALREADY_EXISTS &&
        rc != ERROR_FILE_EXISTS)
    {
        LOG_ERROR(L"Stage1Diagnostics: SHCreateDirectoryExW('%ls') failed "
                  L"(0x%08X).", out.c_str(), rc);
        return static_cast<DWORD>(rc);
    }
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD BuildSecurityAttributes(SECURITY_ATTRIBUTES& sa,
                                            PSECURITY_DESCRIPTOR& outSd) noexcept
{
    outSd = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            kSddl, SDDL_REVISION_1, &sd, nullptr))
    {
        const DWORD err = GetLastError();
        LOG_ERROR(L"Stage1Diagnostics: ConvertStringSecurityDescriptor failed "
                  L"(0x%08X).", err);
        return err ? err : ERROR_FUNCTION_FAILED;
    }
    sa.nLength              = sizeof(sa);
    sa.bInheritHandle       = FALSE;
    sa.lpSecurityDescriptor = sd;
    outSd = sd;
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD WriteAllBytes(HANDLE h, const void* data, size_t size) noexcept
{
    const BYTE* p = static_cast<const BYTE*>(data);
    size_t      remaining = size;
    while (remaining > 0) {
        const DWORD chunk = (remaining > 0x40000000u)
                                ? 0x40000000u
                                : static_cast<DWORD>(remaining);
        DWORD written = 0;
        if (!WriteFile(h, p, chunk, &written, nullptr) || written == 0) {
            const DWORD err = GetLastError();
            LOG_ERROR(L"Stage1Diagnostics: WriteFile failed (0x%08X).", err);
            return err ? err : ERROR_WRITE_FAULT;
        }
        p         += written;
        remaining -= written;
    }
    return ERROR_SUCCESS;
}

} // anonymous namespace

DWORD WriteStage1Snapshot(const Stage1Snapshot& snapshot) noexcept
{
    std::wstring dir;
    DWORD err = GetStateDirectory(dir);
    if (err != ERROR_SUCCESS) {
        return err;
    }

    std::wstring tmpPath   = dir + L"\\" + kTempFileName;
    std::wstring finalPath = dir + L"\\" + kFinalFileName;

    SECURITY_ATTRIBUTES  sa{};
    PSECURITY_DESCRIPTOR sd = nullptr;
    err = BuildSecurityAttributes(sa, sd);
    if (err != ERROR_SUCCESS) {
        return err;
    }
    // RAII for the LocalAlloc'd SD.
    struct LocalFreeGuard {
        PSECURITY_DESCRIPTOR p;
        ~LocalFreeGuard() noexcept { if (p) LocalFree(p); }
    } sdGuard{ sd };

    std::string body;
    try {
        body = Serialise(snapshot);
    } catch (const std::bad_alloc&) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    // Open the tmp file with the SDDL ACL applied at creation.
    HandleGuard hTmp(
        CreateFileW(tmpPath.c_str(),
                    GENERIC_WRITE,
                    0,                       // exclusive write
                    &sa,
                    CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                    nullptr));
    if (!hTmp.valid()) {
        const DWORD e = GetLastError();
        LOG_ERROR(L"Stage1Diagnostics: CreateFileW('%ls') failed (0x%08X).",
                  tmpPath.c_str(), e);
        return e ? e : ERROR_OPEN_FAILED;
    }

    err = WriteAllBytes(hTmp.get(), body.data(), body.size());
    if (err != ERROR_SUCCESS) {
        hTmp = HandleGuard{};
        DeleteFileW(tmpPath.c_str());
        return err;
    }
    if (!FlushFileBuffers(hTmp.get())) {
        const DWORD e = GetLastError();
        LOG_WARN(L"Stage1Diagnostics: FlushFileBuffers failed (0x%08X) "
                 L"-- non-fatal, continuing.", e);
    }
    // Close before the rename so MOVEFILE_REPLACE_EXISTING can replace
    // the destination atomically.
    hTmp = HandleGuard{};

    if (!MoveFileExW(tmpPath.c_str(),
                     finalPath.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    {
        const DWORD e = GetLastError();
        LOG_ERROR(L"Stage1Diagnostics: MoveFileExW('%ls' -> '%ls') failed "
                  L"(0x%08X).", tmpPath.c_str(), finalPath.c_str(), e);
        DeleteFileW(tmpPath.c_str());
        return e ? e : ERROR_FUNCTION_FAILED;
    }

    LOG_INFO(L"Stage1Diagnostics: wrote snapshot to '%ls' (%zu bytes).",
             finalPath.c_str(), body.size());
    return ERROR_SUCCESS;
}

} // namespace ShadowStrike::Installer
