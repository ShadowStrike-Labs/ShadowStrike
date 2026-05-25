/*
 * ShadowStrike - Enterprise NGAV Platform
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * Licensed under GNU AGPL-v3. See LICENSE.txt at the repository root.
 */

/**
 * @file BootTrace.cpp
 * @brief Synchronous, write-through implementation of the boot-trace channel.
 *
 * Writes a single timestamped line per call to
 *   %ProgramData%\ShadowStrike\Logs\PhantomHome.Service.boot.log
 * using FILE_APPEND_DATA + FILE_FLAG_WRITE_THROUGH so a hang or crash inside
 * the immediately-following code does not lose the trace.
 *
 * This is intentionally side-effect-only: it must never throw, never allocate
 * heap memory, and must work even when the rest of the service runtime is
 * mid-initialisation.  All buffers are on-stack and bounded.
 */

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif

#include <windows.h>
#include <stdlib.h>

#include <cstdio>
#include <cwchar>

#include "BootTrace.hpp"

namespace {

// One-line synchronous write to %ProgramData%\ShadowStrike\Logs\PhantomHome.Service.boot.log.
// Returns silently on any error: the boot trace is best-effort observability.
void AppendBootTraceLine(const wchar_t* stage) noexcept {
    if (stage == nullptr) {
        return;
    }

    wchar_t programData[MAX_PATH + 1] = {};
    if (::ExpandEnvironmentStringsW(L"%ProgramData%\\ShadowStrike\\Logs",
                                    programData, MAX_PATH) == 0) {
        return;
    }

    wchar_t parent[MAX_PATH + 1] = {};
    if (::ExpandEnvironmentStringsW(L"%ProgramData%\\ShadowStrike",
                                    parent, MAX_PATH) != 0) {
        (void)::CreateDirectoryW(parent, nullptr);
    }
    (void)::CreateDirectoryW(programData, nullptr);

    wchar_t path[MAX_PATH + 1] = {};
    if (::_snwprintf_s(path, _countof(path), _TRUNCATE,
                       L"%ls\\PhantomHome.Service.boot.log", programData) < 0)
    {
        return;
    }

    const HANDLE h = ::CreateFileW(
        path,
        FILE_APPEND_DATA,
        FILE_SHARE_READ,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
        nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return;
    }

    SYSTEMTIME st{};
    ::GetSystemTime(&st);

    DWORD sessionId = 0;
    (void)::ProcessIdToSessionId(::GetCurrentProcessId(), &sessionId);

    wchar_t line[1024] = {};
    const int written = ::_snwprintf_s(
        line, _countof(line), _TRUNCATE,
        L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ [BOOT] pid=%lu sid=%lu %ls\r\n",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        ::GetCurrentProcessId(),
        sessionId,
        stage);
    if (written < 0) {
        ::CloseHandle(h);
        return;
    }

    const int cbUtf8 = ::WideCharToMultiByte(CP_UTF8, 0, line, -1, nullptr, 0, nullptr, nullptr);
    if (cbUtf8 > 1) {
        char buf[2048] = {};
        const int cap = static_cast<int>(sizeof(buf));
        const int outBytes = (cbUtf8 < cap) ? cbUtf8 : cap;
        const int converted = ::WideCharToMultiByte(
            CP_UTF8, 0, line, -1, buf, outBytes, nullptr, nullptr);
        if (converted > 1) {
            const DWORD bytesToWrite = static_cast<DWORD>(converted - 1);
            DWORD writtenBytes = 0;
            (void)::WriteFile(h, buf, bytesToWrite, &writtenBytes, nullptr);
            (void)::FlushFileBuffers(h);
        }
    }

    ::CloseHandle(h);
}

} // namespace

void ShadowStrikeAppendBootTrace(const wchar_t* stage) noexcept {
    AppendBootTraceLine(stage);
}
