/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file ZeroTrustWiring.hpp
 * @brief Module descriptor factory for the Zero-Trust Execution Guard.
 *
 * Exposes a single factory function that builds the ModuleDescriptor that
 * HomeProductOrchestrator uses to manage the ZeroTrustGuard lifecycle.
 *
 * Adaptation note: the spec referenced ShadowStrike::PhantomHome::ModuleDescriptor
 * but the real type lives in ShadowStrike::Products::Home::ModuleDescriptor.
 * The real namespace is used here.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 */

#pragma once

#include "../../../Products/Community/PhantomHome/HomeProductOrchestrator.hpp"

namespace ShadowStrike::PhantomCore::RealTime::ZeroTrust {

/**
 * @brief Build the ModuleDescriptor that wires ZeroTrustGuard into the
 *        HomeProductOrchestrator lifecycle.
 */
[[nodiscard]] ShadowStrike::Products::Home::ModuleDescriptor
CreateZeroTrustModuleDescriptor();

} // namespace ShadowStrike::PhantomCore::RealTime::ZeroTrust
