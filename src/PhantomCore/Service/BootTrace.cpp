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
#include <stdio.h>
#include <stdlib.h>

#include "BootTrace.hpp"

namespace {

// Absolute, env-var-free, long-path-prefixed trace path. We deliberately
// hard-code C: because ProgramData is always on the system volume on any
// supported Windows endpoint (Windows 10 RS1+ / Windows 11 / Server 2016+).
constexpr const wchar_t* kTraceDirParent    = L"\\\\?\\C:\\ProgramData\\ShadowStrike";
constexpr const wchar_t* kTraceDirPrefixed  = L"\\\\?\\C:\\ProgramData\\ShadowStrike\\Logs";
constexpr const wchar_t* kTracePathPrefixed = L"\\\\?\\C:\\ProgramData\\ShadowStrike\\Logs\\PhantomHome.Service.boot.log";

// noexcept, no heap, no exceptions. Safe to call from a static initializer
// before any C++ globals are constructed, and from signal/SEH context.
void AppendBootTraceLine(const wchar_t* stage) noexcept {
    if (stage == nullptr) {
        stage = L"<null>";
    }

    // Best-effort directory creation. Errors other than ERROR_ALREADY_EXISTS
    // are tolerated: CreateFileW below will fail naturally and we return.
    (void)::CreateDirectoryW(kTraceDirParent,   nullptr);
    (void)::CreateDirectoryW(kTraceDirPrefixed, nullptr);

    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, FALSE };
    const HANDLE h = ::CreateFileW(
        kTracePathPrefixed,
        FILE_APPEND_DATA | SYNCHRONIZE,
        FILE_SHARE_READ,
        &sa,
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

    wchar_t wline[1024] = {};
    const int wlen = ::_snwprintf_s(
        wline, _countof(wline), _TRUNCATE,
        L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ [BOOT] pid=%lu tid=%lu sid=%lu %ls\r\n",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        ::GetCurrentProcessId(),
        ::GetCurrentThreadId(),
        sessionId,
        stage);
    if (wlen < 0) {
        ::CloseHandle(h);
        return;
    }

    // Conservative bounded UTF-8 conversion. The size query (cchWideChar = -1)
    // returns a byte count *including* the trailing NUL; we provide a buffer
    // of at least that size and write `converted - 1` bytes to disk.
    const int cbUtf8 = ::WideCharToMultiByte(CP_UTF8, 0, wline, -1, nullptr, 0, nullptr, nullptr);
    if (cbUtf8 > 1) {
        char buf[2048] = {};
        const int outCap = static_cast<int>(sizeof(buf));
        const int outBytes = (cbUtf8 < outCap) ? cbUtf8 : outCap;
        const int converted = ::WideCharToMultiByte(
            CP_UTF8, 0, wline, -1, buf, outBytes, nullptr, nullptr);
        if (converted > 1) {
            const DWORD toWrite = static_cast<DWORD>(converted - 1);
            DWORD bytesWritten = 0;
            (void)::WriteFile(h, buf, toWrite, &bytesWritten, nullptr);
            (void)::FlushFileBuffers(h);
        }
    }

    ::CloseHandle(h);
}

} // namespace

extern "C" void ShadowStrikeAppendBootTrace(const wchar_t* stage) noexcept {
    AppendBootTraceLine(stage);
}

// ---------------------------------------------------------------------------
// PRE-WMAIN STATIC INITIALIZER
// Runs from the .CRT$XCT section, AFTER the CRT is initialized but BEFORE
// any user C++ static constructors. This lets us prove the PE loaded, the
// CRT armed, and the process is about to enter user globals -- invaluable
// when a static initializer throws and dies before wmain.
// ---------------------------------------------------------------------------
namespace {
int ShadowStrikePreWmainInitializer() noexcept {
    AppendBootTraceLine(L"pre-wmain-static-initializer");
    return 0;
}
} // namespace

#pragma section(".CRT$XCT", read)
__declspec(allocate(".CRT$XCT"))
extern "C" int (* const g_ssPreWmainInit)() = &ShadowStrikePreWmainInitializer;

// Force the linker to keep the symbol even with /OPT:REF.
#ifdef _M_X64
#pragma comment(linker, "/include:g_ssPreWmainInit")
#else
#pragma comment(linker, "/include:_g_ssPreWmainInit")
#endif
