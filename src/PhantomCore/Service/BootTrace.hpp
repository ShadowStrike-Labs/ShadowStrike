/*
 * ShadowStrike - Enterprise NGAV Platform
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * Licensed under GNU AGPL-v3. See LICENSE.txt at the repository root.
 */

#pragma once

/**
 * @file BootTrace.hpp
 * @brief Synchronous, write-through, env-var-free boot-trace channel.
 *
 * The trace file is always at the absolute literal path
 *   \\?\C:\ProgramData\ShadowStrike\Logs\PhantomHome.Service.boot.log
 *
 * Rationale: under early service activation on certain Windows 11 builds,
 * the LocalSystem token's environment block may not yet have %ProgramData%
 * populated when ServiceMain begins.  Any env-var expansion here would
 * silently produce an unexpanded literal "%ProgramData%\..." and the trace
 * would be lost.  This module never reads environment variables.
 *
 * The trace is opened FILE_APPEND_DATA | FILE_FLAG_WRITE_THROUGH and closed
 * after every write so a hang in the next instruction cannot lose the entry.
 * All buffers are stack-allocated and bounded; no heap allocation, no C++
 * exceptions, no static-initializer dependencies beyond the CRT.
 *
 * INSTALLED CHOKEPOINTS (see ServiceMain.cpp / AntivirusService.cpp):
 *   pre-wmain  (.CRT$XCT static initializer)
 *   wmain-entry
 *   pre/post StartServiceCtrlDispatcherW
 *   ServiceMain-entry
 *   pre/post each SetServiceStatus(START_PENDING / RUNNING / STOPPED)
 *   unhandled-SEH filter
 *   std::set_terminate
 *   _set_invalid_parameter_handler
 *   _set_purecall_handler
 *   atexit
 *
 * Usage:
 *   ShadowStrikeAppendBootTrace(L"impl-initialize-enter");
 *
 *   Each stage tag should be a stable, grep-able identifier in kebab- or
 *   pascal-case.  Passing nullptr is harmless.
 */

extern "C" void ShadowStrikeAppendBootTrace(const wchar_t* stage) noexcept;
