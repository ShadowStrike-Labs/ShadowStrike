/*
 * ShadowStrike - Enterprise NGAV Platform
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * Licensed under GNU AGPL-v3. See LICENSE.txt at the repository root.
 */

#pragma once

#include <cstdint>

/**
 * @file DiagTrace.hpp
 * @brief Compile-time gated, high-volume diagnostic tracing that survives a
 *        hard lock-up.
 *
 * WHY THIS EXISTS
 * ---------------
 * The system-wide freezes could only be diagnosed from the service log, and the
 * service log has two properties that make it the wrong instrument for a hang:
 *
 *   1. It is a FILE. Every write passes through our own minifilter, so verbose
 *      logging adds I/O to a machine that is already stalling on I/O - the
 *      instrument changes the thing it measures, and makes it worse.
 *   2. It stops at the freeze. The last log line before a hard lock-up is the
 *      last line that reached disk, not the last thing that happened, so the
 *      evidence we most need is exactly the evidence that is missing.
 *
 * This channel avoids both. Records are written into a fixed-size ring buffer
 * backed by a MEMORY-MAPPED FILE: the write path is a bounded format into a
 * stack buffer followed by a memcpy into mapped memory. No syscall, no file I/O,
 * no minifilter involvement, no allocation, no lock. The operating system
 * flushes the dirty pages on its own schedule, so the contents survive the
 * process being killed, the service being torn down, and - as far as the pages
 * that reached disk - a hard reset.
 *
 * The buffer is converted to readable text at the points where text is safe to
 * write: on the NEXT service start (dumping whatever the previous session left
 * behind), when the hang watchdog fires, and on clean shutdown. So the normal
 * workflow after a freeze is simply: reboot, start the service, collect
 * PhantomHome.Service.trace.log, which now contains the final moments of the
 * session that froze.
 *
 * ENABLING AND DISABLING
 * ----------------------
 * Flip the single line below. When SHADOWSTRIKE_DIAG_TRACE is 0 every SS_DIAG
 * call compiles to nothing at all - no string literal is emitted, no argument is
 * evaluated, no code is generated - so a release build carries neither the cost
 * nor the disclosure. It can also be forced from the build system by defining
 * SHADOWSTRIKE_DIAG_TRACE on the compiler command line.
 *
 * USAGE
 * -----
 *   SS_DIAG("Scan", "enter path=%ls pid=%u", path.c_str(), pid);
 *   SS_DIAG_SCOPE("Scan", "ScanFile");   // logs enter now, leave + duration at
 *                                        // end of scope, even on an exception
 *
 * Categories should be short, stable and grep-able. Keep them to a handful per
 * subsystem so a trace can be filtered by area.
 */

#ifndef SHADOWSTRIKE_DIAG_TRACE
    /* ==================================================================== *
     *  1 = verbose diagnostic tracing compiled in   (TEST / TRIAGE BUILDS) *
     *  0 = every SS_DIAG compiles away to nothing   (SHIPPING BUILDS)      *
     * ==================================================================== */
    #define SHADOWSTRIKE_DIAG_TRACE 1
#endif

namespace ShadowStrike::Diag {

/// @brief Maps the ring buffer and dumps any trace left by a previous session.
/// Safe to call more than once. Never throws; on failure tracing degrades to a
/// no-op rather than affecting the caller.
void Initialize() noexcept;

/// @brief Writes the ring to text and unmaps. Safe if Initialize failed.
void Shutdown() noexcept;

/// @brief Appends one record. Bounded, lock-free, no allocation, no file I/O.
void Write(const char* category, const char* format, ...) noexcept;

/// @brief Converts the current ring contents to readable text.
/// Call from places where file I/O is acceptable - the hang watchdog, shutdown,
/// or an operator request. Returns false if there was nothing to write.
bool FlushToText(const wchar_t* reason) noexcept;

/// @brief True when tracing is compiled in AND the ring is mapped.
[[nodiscard]] bool IsActive() noexcept;

/// @brief Records written this session, including those already overwritten.
[[nodiscard]] std::uint64_t RecordsWritten() noexcept;

/// @brief RAII enter/leave pair with elapsed microseconds on leave.
/// Reports the duration even if the scope exits via an exception, which is what
/// makes it useful for finding where time goes rather than only where it ended.
class ScopeTrace {
public:
    ScopeTrace(const char* category, const char* label) noexcept;
    ~ScopeTrace() noexcept;
    ScopeTrace(const ScopeTrace&)            = delete;
    ScopeTrace& operator=(const ScopeTrace&) = delete;
private:
    const char*        m_category;
    const char*        m_label;
    std::int64_t       m_startQpc;
};

} // namespace ShadowStrike::Diag

#if SHADOWSTRIKE_DIAG_TRACE

    #define SS_DIAG(category, ...) \
        ::ShadowStrike::Diag::Write((category), __VA_ARGS__)

    #define SS_DIAG_SCOPE(category, label) \
        ::ShadowStrike::Diag::ScopeTrace ss_diag_scope_##__LINE__((category), (label))

#else

    /* Arguments are deliberately left unevaluated: a trace call must not be able
     * to change behaviour by being compiled out. */
    #define SS_DIAG(category, ...)        ((void)0)
    #define SS_DIAG_SCOPE(category, label) ((void)0)

#endif
