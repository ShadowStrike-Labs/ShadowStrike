/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file PreMainTrace.cpp
 * @brief First boot-trace line of the service process, before any library static
 *        initialiser runs (task 334).
 *
 * WHY THIS FILE, AND WHY IN THE SERVICE PROJECT. BootTrace.cpp in PhantomCoreLib
 * placed a pointer in .CRT$XCT for this purpose. PhantomCoreLib is built with
 * whole-program optimisation, and that table entry never survived the link: not one
 * of the boot logs collected from 1.0.117 to 1.0.121 contains its line. So when the
 * service missed SCM's 30 s connect window on a first boot, the log was simply empty
 * and could not say whether the process reached the CRT at all.
 *
 * The compiler init_seg pragma below is the documented way to run a constructor in the
 * compiler's initialisation segment, ahead of library and user static objects. The
 * file is compiled directly into the service image, not linked from a library, so
 * there is no archive member for the linker to leave out.
 *
 * WHAT THE LINE SAYS. Milliseconds from process creation to this point: image and
 * static-import mapping, the imports' DllMain, and CRT start-up. On a start that
 * misses the window, its absence means the time was spent before the CRT ran.
 */

#include <Windows.h>
#include <stdio.h>

#include "BootTrace.hpp"

#pragma warning(push)
#pragma warning(disable : 4074)   // "initializers put in compiler reserved initialization area" - intended
#pragma init_seg(compiler)
#pragma warning(pop)

namespace {

struct PreMainTrace final {
    PreMainTrace() noexcept {
        FILETIME created{}, exited{}, kernel{}, user{}, now{};
        ::GetSystemTimeAsFileTime(&now);
        wchar_t tag[160] = L"pre-main sinceProcessCreateMs=?";
        if (::GetProcessTimes(::GetCurrentProcess(), &created, &exited, &kernel, &user)) {
            const ULONGLONG c = (static_cast<ULONGLONG>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
            const ULONGLONG n = (static_cast<ULONGLONG>(now.dwHighDateTime) << 32) | now.dwLowDateTime;
            const ULONGLONG k = (static_cast<ULONGLONG>(kernel.dwHighDateTime) << 32) | kernel.dwLowDateTime;
            const ULONGLONG u = (static_cast<ULONGLONG>(user.dwHighDateTime) << 32) | user.dwLowDateTime;
            (void)::_snwprintf_s(tag, sizeof(tag) / sizeof(tag[0]), _TRUNCATE,
                L"pre-main sinceProcessCreateMs=%llu cpuMs=%llu",
                (n > c) ? (n - c) / 10000ULL : 0ULL, (k + u) / 10000ULL);
        }
        ::ShadowStrikeAppendBootTrace(tag);
    }
};

const PreMainTrace g_preMainTrace;

} // namespace
