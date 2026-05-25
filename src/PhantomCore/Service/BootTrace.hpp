/*
 * ShadowStrike - Enterprise NGAV Platform
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * Licensed under GNU AGPL-v3. See LICENSE.txt at the repository root.
 */

#pragma once

/**
 * @file BootTrace.hpp
 * @brief Synchronous, write-through boot-trace channel for service startup.
 *
 * Background:
 *   ShadowStrikePhantomService runs a substantial chain of subsystem
 *   Initialize() / Start() calls before reporting SERVICE_RUNNING.  When any
 *   step blocks (kernel handle wait, LSA call, profile load, ACL build, ...),
 *   the SCM eventually escalates the failure mode to a hung START_PENDING
 *   service, which in turn delays Windows shutdown and produces the
 *   grey-screen reboot symptom we have been chasing.
 *
 *   The async Logger writes asynchronously and is itself initialised relatively
 *   late, so its on-disk file frequently does not contain the line that
 *   immediately preceded a hang.  This helper writes a single timestamped line
 *   to %ProgramData%\ShadowStrike\Logs\PhantomHome.Service.boot.log using
 *   FILE_APPEND_DATA + FILE_FLAG_WRITE_THROUGH so post-mortem triage on the
 *   target machine reliably shows the *last* stage the service reached.
 *
 * Usage:
 *   #include "BootTrace.hpp"
 *   ShadowStrikeAppendBootTrace(L"impl-initialize-enter");
 *
 *   Each stage tag should be a stable, grep-able identifier in kebab- or
 *   pascal-case.  Pass nullptr is a no-op.
 *
 *   Definition lives in ServiceMain.cpp (a single TU owns the on-disk file
 *   path constants and the WideCharToMultiByte buffer logic).
 */

void ShadowStrikeAppendBootTrace(const wchar_t* stage) noexcept;
