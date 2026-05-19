/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file AmsiProviderRegistration.hpp
 * @brief Win32 registry helpers for installing / removing the
 *        ShadowStrike PhantomHome AMSI provider COM registration.
 *
 * CLSID: {6F2E9D28-4A1C-4B3E-8E1F-0C7A6F0DA1FF}
 *
 * Registry keys written by RegisterAmsiProvider():
 *
 *   HKLM\SOFTWARE\Microsoft\AMSI\Providers\
 *       {6F2E9D28-4A1C-4B3E-8E1F-0C7A6F0DA1FF}
 *           (Default)  = L"ShadowStrike PhantomHome AMSI Provider"
 *
 *   HKCR\CLSID\{6F2E9D28-4A1C-4B3E-8E1F-0C7A6F0DA1FF}
 *       (Default)  = L"ShadowStrike PhantomHome AMSI Provider"
 *       InprocServer32
 *           (Default)       = <path to the containing AMSI provider DLL>
 *           ThreadingModel  = L"Both"
 *
 * @note Requires elevation (SeBackupPrivilege / Administrator token).
 *       ACCESS_DENIED errors are logged as actionable SS_LOG_ERROR messages.
 */

#pragma once

#include <cstdint>

namespace ShadowStrike {
namespace Products {
namespace Home {

/**
 * @brief Write AMSI provider COM registration into HKLM / HKCR.
 *
 * Idempotent — safe to call on repeated service starts.
 * The server path written to InprocServer32 is the containing module's full
 * path. Registration fails closed if the provider is linked into an EXE,
 * because AMSI loads providers as in-process COM DLL servers.
 *
 * @return true on success; false if any registry operation failed.
 *         Access-denied conditions are logged with explicit "requires
 *         elevation" guidance.
 */
[[nodiscard]] bool RegisterAmsiProvider() noexcept;

/**
 * @brief Remove AMSI provider COM registration from HKLM / HKCR.
 *
 * Idempotent — no error if keys do not exist.
 * @return true on success; false if a deletion fails for a reason
 *         other than key-not-found.
 */
[[nodiscard]] bool UnregisterAmsiProvider() noexcept;

}  // namespace Home
}  // namespace Products
}  // namespace ShadowStrike
