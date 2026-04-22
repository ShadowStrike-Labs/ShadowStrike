/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file ZeroTrustWiring.hpp
 * @brief PhantomHome wiring header for the Zero-Trust Execution Guard module.
 *
 * Exposes:
 *  - RegisterZeroTrustGuard(): registers the module descriptor with the
 *    HomeProductOrchestrator. Also implements the PhantomCore factory
 *    function CreateZeroTrustModuleDescriptor() declared in
 *    PhantomCore/RealTime/ZeroTrust/ZeroTrustWiring.hpp.
 *  - InstallDefaults(): called once at service startup to load persisted
 *    config or apply Balanced-mode defaults.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 */

#pragma once

#include "../../HomeProductOrchestrator.hpp"

namespace ShadowStrike::Products::Home::ZeroTrust {

/**
 * @brief Register the ZeroTrustGuard ModuleDescriptor with the orchestrator.
 *
 * Called from the namespace-scope registrar in ZeroTrustWiring.cpp before
 * main(). Direct callers are NOT expected; use InstallDefaults() for explicit
 * startup ordering.
 */
void RegisterZeroTrustGuard(
    ::ShadowStrike::Products::Home::HomeProductOrchestrator& orch);

/**
 * @brief Apply Balanced defaults or load persisted config.
 *
 * Must be called once during service startup after ConfigManager is ready.
 * Idempotent; safe to call multiple times (no-op after the first call).
 */
void InstallDefaults();

} // namespace ShadowStrike::Products::Home::ZeroTrust
