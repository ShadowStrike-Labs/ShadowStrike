/*
 * ShadowStrike - Enterprise NGAV Platform
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * Licensed under GNU AGPL-v3. See LICENSE.txt at the repository root.
 */

#include "pch.h"
#include "DiagTrace.hpp"

#if SHADOWSTRIKE_DIAG_TRACE

#include <windows.h>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <atomic>

namespace ShadowStrike::Diag {
namespace {

// ---------------------------------------------------------------------------
// On-disk / in-memory layout
// ---------------------------------------------------------------------------
//
// Fixed-size records are used deliberately. Variable-length packing would fit
// more text into the same space, but a reader recovering the buffer after an
// unclean shutdown then has to trust length prefixes written by a process that
// may have been killed mid-write. Fixed slots mean a torn record damages only
// itself and the reader can always find the next one.

constexpr std::uint32_t kMagic        = 0x53534452u;  // 'SSDR'
constexpr std::uint32_t kVersion      = 1u;
constexpr std::uint32_t kRecordCount  = 32768u;       // ~8 MB total
constexpr std::uint32_t kCategoryMax  = 24u;
constexpr std::uint32_t kMessageMax   = 208u;   // 8+8+4+4+24+208 = 256 exactly

#pragma pack(push, 8)
struct Record {
    std::int64_t   qpc;                       // QueryPerformanceCounter at write
    std::int64_t   fileTime;                  // UTC FILETIME, for wall clock
    std::uint32_t  threadId;
    std::uint32_t  sequence;                  // 0 = never written, else complete
    char           category[kCategoryMax];
    char           message[kMessageMax];
};

struct RingHeader {
    std::uint32_t  magic;
    std::uint32_t  version;
    std::uint32_t  recordCount;
    std::uint32_t  recordSize;
    std::int64_t   head;                      // monotonic; slot = head % count
    std::int64_t   qpcFrequency;
    std::int64_t   sessionStartFileTime;
    std::uint32_t  sessionPid;
    std::uint32_t  dumped;                    // set once converted to text
    char           reserved[64];
};
#pragma pack(pop)

static_assert(sizeof(Record) == 256, "Record must stay a power-of-two size");

constexpr wchar_t kRingPath[] =
    L"\\\\?\\C:\\ProgramData\\ShadowStrike\\Logs\\PhantomHome.Service.trace.ring";
constexpr wchar_t kTextPath[] =
    L"\\\\?\\C:\\ProgramData\\ShadowStrike\\Logs\\PhantomHome.Service.trace.log";
constexpr wchar_t kLogDir[] =
    L"\\\\?\\C:\\ProgramData\\ShadowStrike\\Logs";

// ---------------------------------------------------------------------------
// Module state
// ---------------------------------------------------------------------------

HANDLE            g_file    = INVALID_HANDLE_VALUE;
HANDLE            g_mapping = nullptr;
RingHeader*       g_header  = nullptr;
Record*           g_records = nullptr;
std::atomic<bool> g_active{ false };
std::atomic<std::uint64_t> g_written{ 0 };
std::int64_t      g_qpcFreq = 0;
SRWLOCK           g_flushLock = SRWLOCK_INIT;   // serialises text dumps only

// Mapped writes land in the page cache and are written out on the cache
// manager's own schedule, so a hard power-off discards every dirty page. That
// defeated the entire purpose the first time this ran in the field: the ring
// file was the right size and the header said the session was active, yet all
// 8 MB read back as zeroes because nothing had ever been written to disk. The
// ring therefore needs an explicit periodic flush.
//
// It runs on its own thread rather than the write path: a flush is a syscall
// and the write path must stay free of them. It flushes only the slots filled
// since the previous pass, and does nothing at all when no record has been
// written, so an idle service performs no I/O for tracing.
constexpr DWORD   kFlushIntervalMs = 1000;

HANDLE            g_flushThread     = nullptr;
HANDLE            g_flushStop       = nullptr;
std::int64_t      g_lastFlushedHead = 0;        // flush thread and Shutdown only

[[nodiscard]] std::int64_t NowQpc() noexcept {
    LARGE_INTEGER li{};
    ::QueryPerformanceCounter(&li);
    return li.QuadPart;
}

[[nodiscard]] std::int64_t NowFileTime() noexcept {
    FILETIME ft{};
    ::GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u{};
    u.LowPart  = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return static_cast<std::int64_t>(u.QuadPart);
}

// Writes one record's text form. Returns characters emitted.
int FormatRecord(const Record& r, const RingHeader& hdr, char* out, size_t cap) noexcept {
    SYSTEMTIME st{};
    FILETIME   ft{};
    ULARGE_INTEGER u{};
    u.QuadPart = static_cast<ULONGLONG>(r.fileTime);
    ft.dwLowDateTime  = u.LowPart;
    ft.dwHighDateTime = u.HighPart;
    ::FileTimeToSystemTime(&ft, &st);

    // Microseconds since the session began, which is what matters when looking
    // for a gap: wall-clock alone hides sub-second stalls.
    double sinceStartMs = 0.0;
    if (hdr.qpcFrequency > 0) {
        sinceStartMs = 1000.0 * static_cast<double>(r.qpc) / static_cast<double>(hdr.qpcFrequency);
    }

    return _snprintf_s(out, cap, _TRUNCATE,
        "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ  %14.3f  tid=%-6u  %-24s %s\r\n",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        sinceStartMs, r.threadId, r.category, r.message);
}

// Pushes the slots written since the last pass out to disk. Flushes the record
// range first and the header second, so if power is lost between the two the
// on-disk head is behind the records rather than ahead of them - a reader then
// recovers slightly less than was written instead of reading slots that were
// never filled.
void FlushDirtyRange() noexcept {
    if (g_header == nullptr || g_records == nullptr) {
        return;
    }

    const std::int64_t head = g_header->head;
    if (head == g_lastFlushedHead) {
        return;                       // nothing written since last pass: no I/O
    }

    if (head - g_lastFlushedHead >= static_cast<std::int64_t>(kRecordCount)) {
        // Wrapped entirely since the last pass, so every slot is dirty.
        ::FlushViewOfFile(g_records, sizeof(Record) * kRecordCount);
    } else {
        const std::uint32_t from = static_cast<std::uint32_t>(g_lastFlushedHead % kRecordCount);
        const std::uint32_t to   = static_cast<std::uint32_t>(head % kRecordCount);
        if (from < to) {
            ::FlushViewOfFile(&g_records[from], sizeof(Record) * (to - from));
        } else {
            // The written range crosses the end of the buffer: two pieces.
            ::FlushViewOfFile(&g_records[from], sizeof(Record) * (kRecordCount - from));
            if (to > 0) {
                ::FlushViewOfFile(g_records, sizeof(Record) * to);
            }
        }
    }

    ::FlushViewOfFile(g_header, sizeof(RingHeader));
    g_lastFlushedHead = head;
}

DWORD WINAPI FlushThreadProc(LPVOID) noexcept {
    // Below normal: this thread exists to preserve evidence, never to compete
    // with the work being traced.
    ::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);

    for (;;) {
        const DWORD wait = ::WaitForSingleObject(g_flushStop, kFlushIntervalMs);
        FlushDirtyRange();
        if (wait == WAIT_OBJECT_0) {
            break;                    // stop requested, and we just flushed
        }
    }
    return 0;
}

} // namespace

// ---------------------------------------------------------------------------
// Initialize
// ---------------------------------------------------------------------------

void Initialize() noexcept {
    if (g_active.load(std::memory_order_acquire)) {
        return;
    }

    LARGE_INTEGER freq{};
    ::QueryPerformanceFrequency(&freq);
    g_qpcFreq = freq.QuadPart;

    ::CreateDirectoryW(kLogDir, nullptr);   // harmless if it exists

    const DWORD totalSize =
        static_cast<DWORD>(sizeof(RingHeader) + (sizeof(Record) * kRecordCount));

    // OPEN_ALWAYS, not CREATE_ALWAYS: the whole point is to inherit whatever the
    // previous session left behind so it can be recovered below.
    g_file = ::CreateFileW(kRingPath,
                           GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ,
                           nullptr,
                           OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL,
                           nullptr);
    if (g_file == INVALID_HANDLE_VALUE) {
        return;                            // degrade to no-op, never fail a caller
    }

    LARGE_INTEGER want{};
    want.QuadPart = totalSize;
    ::SetFilePointerEx(g_file, want, nullptr, FILE_BEGIN);
    ::SetEndOfFile(g_file);

    g_mapping = ::CreateFileMappingW(g_file, nullptr, PAGE_READWRITE, 0, totalSize, nullptr);
    if (g_mapping == nullptr) {
        ::CloseHandle(g_file);
        g_file = INVALID_HANDLE_VALUE;
        return;
    }

    void* view = ::MapViewOfFile(g_mapping, FILE_MAP_ALL_ACCESS, 0, 0, totalSize);
    if (view == nullptr) {
        ::CloseHandle(g_mapping);
        ::CloseHandle(g_file);
        g_mapping = nullptr;
        g_file    = INVALID_HANDLE_VALUE;
        return;
    }

    g_header  = static_cast<RingHeader*>(view);
    g_records = reinterpret_cast<Record*>(static_cast<std::uint8_t*>(view) + sizeof(RingHeader));

    // Recover the previous session before touching the header, otherwise the
    // evidence we came for is destroyed by our own start-up.
    const bool recoverable =
        g_header->magic == kMagic &&
        g_header->version == kVersion &&
        g_header->recordCount == kRecordCount &&
        g_header->recordSize == sizeof(Record) &&
        g_header->head > 0 &&
        g_header->dumped == 0;

    if (recoverable) {
        g_active.store(true, std::memory_order_release);
        (void)FlushToText(L"recovered-previous-session");
        g_active.store(false, std::memory_order_release);
    }

    // Start a clean session.
    ::SecureZeroMemory(g_records, sizeof(Record) * kRecordCount);
    g_header->magic                = kMagic;
    g_header->version              = kVersion;
    g_header->recordCount          = kRecordCount;
    g_header->recordSize           = sizeof(Record);
    g_header->head                 = 0;
    g_header->qpcFrequency         = g_qpcFreq;
    g_header->sessionStartFileTime = NowFileTime();
    g_header->sessionPid           = ::GetCurrentProcessId();
    g_header->dumped               = 0;

    g_written.store(0, std::memory_order_relaxed);
    g_lastFlushedHead = 0;
    g_active.store(true, std::memory_order_release);

    // Get the fresh header on disk immediately, so a crash seconds from now
    // still leaves a recoverable ring rather than a zeroed one.
    ::FlushViewOfFile(g_header, sizeof(RingHeader));

    g_flushStop = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (g_flushStop != nullptr) {
        g_flushThread = ::CreateThread(nullptr, 0, FlushThreadProc, nullptr, 0, nullptr);
        if (g_flushThread == nullptr) {
            ::CloseHandle(g_flushStop);
            g_flushStop = nullptr;
        }
    }

    SS_DIAG("Diag", "trace ring active: %u records, %u bytes/record, pid=%u, flush=%ums",
            kRecordCount, static_cast<unsigned>(sizeof(Record)),
            ::GetCurrentProcessId(), kFlushIntervalMs);
}

// ---------------------------------------------------------------------------
// Write - the hot path
// ---------------------------------------------------------------------------

void Write(const char* category, const char* format, ...) noexcept {
    if (!g_active.load(std::memory_order_acquire) || g_records == nullptr) {
        return;
    }

    // Claim a slot. A wrap simply overwrites the oldest record, which is the
    // correct trade: the moments immediately before a freeze are what matter,
    // and they are always the newest.
    const std::int64_t ticket =
        ::InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&g_header->head)) - 1;
    Record& r = g_records[static_cast<std::uint32_t>(ticket) % kRecordCount];

    // Mark incomplete first so a reader can tell a half-written slot from a
    // finished one even if this thread is killed mid-write.
    r.sequence = 0;

    r.qpc      = NowQpc();
    r.fileTime = NowFileTime();
    r.threadId = ::GetCurrentThreadId();

    if (category != nullptr) {
        ::strncpy_s(r.category, sizeof(r.category), category, _TRUNCATE);
    } else {
        r.category[0] = '\0';
    }

    va_list args;
    va_start(args, format);
    const int n = _vsnprintf_s(r.message, sizeof(r.message), _TRUNCATE, format, args);
    va_end(args);
    if (n < 0) {
        ::strncpy_s(r.message, sizeof(r.message), "<format error>", _TRUNCATE);
    }

    r.sequence = static_cast<std::uint32_t>(ticket + 1);   // publish
    g_written.fetch_add(1, std::memory_order_relaxed);
}

// ---------------------------------------------------------------------------
// FlushToText
// ---------------------------------------------------------------------------

bool FlushToText(const wchar_t* reason) noexcept {
    if (g_header == nullptr || g_records == nullptr) {
        return false;
    }

    ::AcquireSRWLockExclusive(&g_flushLock);

    const std::int64_t head = g_header->head;
    if (head <= 0) {
        ::ReleaseSRWLockExclusive(&g_flushLock);
        return false;
    }

    HANDLE out = ::CreateFileW(kTextPath,
                               FILE_APPEND_DATA,
                               FILE_SHARE_READ,
                               nullptr,
                               OPEN_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL,
                               nullptr);
    if (out == INVALID_HANDLE_VALUE) {
        ::ReleaseSRWLockExclusive(&g_flushLock);
        return false;
    }
    ::SetFilePointer(out, 0, nullptr, FILE_END);

    auto emit = [&](const char* text, int len) noexcept {
        if (len <= 0) return;
        DWORD wrote = 0;
        ::WriteFile(out, text, static_cast<DWORD>(len), &wrote, nullptr);
    };

    char banner[512];
    SYSTEMTIME st{};
    ::GetSystemTime(&st);
    int bl = _snprintf_s(banner, sizeof(banner), _TRUNCATE,
        "\r\n"
        "==================================================================\r\n"
        " ShadowStrike diagnostic trace\r\n"
        "   dumped        : %04u-%02u-%02uT%02u:%02u:%02u.%03uZ\r\n"
        "   reason        : %ls\r\n"
        "   session pid   : %u\r\n"
        "   records       : %lld written, ring holds %u\r\n"
        "   note          : the millisecond column is time since session start\r\n"
        "==================================================================\r\n",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        (reason ? reason : L"unspecified"),
        g_header->sessionPid,
        static_cast<long long>(head), kRecordCount);
    emit(banner, bl);

    // Oldest surviving record first.
    const std::int64_t total = head;
    const std::int64_t first = (total > kRecordCount) ? (total - kRecordCount) : 0;

    char line[512];
    std::int64_t emitted = 0;
    for (std::int64_t i = first; i < total; ++i) {
        const Record& r = g_records[static_cast<std::uint32_t>(i) % kRecordCount];
        if (r.sequence == 0) {
            continue;                       // never written, or torn
        }
        const int len = FormatRecord(r, *g_header, line, sizeof(line));
        emit(line, len);
        ++emitted;
    }

    char tail[128];
    int tl = _snprintf_s(tail, sizeof(tail), _TRUNCATE,
                         "-- end of trace, %lld record(s) --\r\n", static_cast<long long>(emitted));
    emit(tail, tl);

    ::FlushFileBuffers(out);
    ::CloseHandle(out);

    g_header->dumped = 1;                   // do not re-dump this session
    ::ReleaseSRWLockExclusive(&g_flushLock);
    return emitted > 0;
}

// ---------------------------------------------------------------------------
// Shutdown / queries
// ---------------------------------------------------------------------------

void Shutdown() noexcept {
    // Stop the flusher before unmapping, or it would flush a dead view.
    if (g_flushStop != nullptr) {
        ::SetEvent(g_flushStop);
    }
    if (g_flushThread != nullptr) {
        ::WaitForSingleObject(g_flushThread, 3000);
        ::CloseHandle(g_flushThread);
        g_flushThread = nullptr;
    }
    if (g_flushStop != nullptr) {
        ::CloseHandle(g_flushStop);
        g_flushStop = nullptr;
    }

    if (g_active.exchange(false, std::memory_order_acq_rel)) {
        (void)FlushToText(L"clean-shutdown");
    }
    if (g_header != nullptr) {
        ::FlushViewOfFile(g_header, 0);
        ::UnmapViewOfFile(g_header);
        g_header  = nullptr;
        g_records = nullptr;
    }
    if (g_mapping != nullptr) { ::CloseHandle(g_mapping); g_mapping = nullptr; }
    if (g_file != INVALID_HANDLE_VALUE) { ::CloseHandle(g_file); g_file = INVALID_HANDLE_VALUE; }
}

bool IsActive() noexcept { return g_active.load(std::memory_order_acquire); }

std::uint64_t RecordsWritten() noexcept { return g_written.load(std::memory_order_relaxed); }

// ---------------------------------------------------------------------------
// ScopeTrace
// ---------------------------------------------------------------------------

ScopeTrace::ScopeTrace(const char* category, const char* label) noexcept
    : m_category(category), m_label(label), m_startQpc(NowQpc()) {
    Write(m_category, "> %s", m_label ? m_label : "?");
}

ScopeTrace::~ScopeTrace() noexcept {
    const std::int64_t elapsed = NowQpc() - m_startQpc;
    double us = 0.0;
    if (g_qpcFreq > 0) {
        us = 1000000.0 * static_cast<double>(elapsed) / static_cast<double>(g_qpcFreq);
    }
    Write(m_category, "< %s  %.0f us", m_label ? m_label : "?", us);
}

} // namespace ShadowStrike::Diag

#else  // ---------------------- tracing compiled out ----------------------

namespace ShadowStrike::Diag {
void Initialize() noexcept {}
void Shutdown() noexcept {}
void Write(const char*, const char*, ...) noexcept {}
bool FlushToText(const wchar_t*) noexcept { return false; }
bool IsActive() noexcept { return false; }
std::uint64_t RecordsWritten() noexcept { return 0; }
ScopeTrace::ScopeTrace(const char* c, const char* l) noexcept
    : m_category(c), m_label(l), m_startQpc(0) {}
ScopeTrace::~ScopeTrace() noexcept {}
} // namespace ShadowStrike::Diag

#endif
