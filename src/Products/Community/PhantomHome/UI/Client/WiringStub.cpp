/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file WiringStub.cpp
 * @brief UI-process stub for EnsureAllModulesWired().
 *
 * The service-side PhantomCoreLib expects EnsureAllModulesWired() to be
 * provided by the linking binary.  In the privileged service process it
 * is satisfied by WiringAnchor.cpp, which force-references every module's
 * registration TU.  The UI process does not host the PhantomHome module
 * registry, so a no-op stub is the correct and safe implementation here.
 *
 * The volatile read inside prevents optimisers from emitting a warning
 * about an empty non-void-returning function while leaving no runtime cost.
 */

namespace ShadowStrike::Products::Home {

void EnsureAllModulesWired() noexcept {
    // No-op: the UI process does not host the module registry.
    // Module wiring is performed in the privileged service process.
}

} // namespace ShadowStrike::Products::Home
