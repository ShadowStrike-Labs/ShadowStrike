/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file ModeThresholds.hpp
 * @brief Shared helper for writing canonical per-module sensitivity thresholds
 *        to ConfigManager and signalling a hot-reload to interested subsystems.
 *
 * ApplyModeThresholds() is the single authority for what "Passive", "Balanced",
 * and "Aggressive" mean in terms of concrete config keys. Centralising these
 * constants here avoids drift between the orchestrator and any future IPC or
 * policy layer that needs to reason about mode transitions.
 *
 * Key layout written under "Home/<moduleName>/":
 *
 *   Key                     Passive   Balanced   Aggressive
 *   -------------------------------------------------------
 *   Sensitivity (int32)        25         60          90
 *   AIConfidenceThreshold (d)  0.85       0.70        0.55
 *   BlockOnSuspicion (bool)    false      true        true
 *   DetectOnly (bool)          true       false       false
 *
 * Callers MUST NOT pass ProtectionMode::Off — the orchestrator handles Off by
 * shutting down the module before calling into this helper.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 */

#pragma once

#include <string_view>
#include "HomeProductOrchestrator.hpp"

namespace ShadowStrike {
namespace Products {
namespace Home {

/**
 * @brief Write the canonical sensitivity / AI-confidence / block-on-suspicion
 *        keys for @p moduleName to ConfigManager.
 *
 * Each key is written under the "Home/<moduleName>/" prefix.
 * Change callbacks registered with ConfigManager fire automatically on each
 * successful SetValue call, delivering hot-reload notifications to any
 * subscriber watching those keys.
 *
 * @param moduleName  Stable internal module name (e.g. "BankingTrojanDetector").
 *                    Must match the ModuleDescriptor::name used at registration.
 * @param mode        Target protection intensity. Must not be ProtectionMode::Off;
 *                    Off is handled by the orchestrator's disable path.
 * @return true  iff all four ConfigManager writes succeeded.
 * @return false if mode == Off (logs an error) or any write fails.
 */
[[nodiscard]] bool ApplyModeThresholds(std::string_view moduleName,
                                       ProtectionMode    mode);

}  // namespace Home
}  // namespace Products
}  // namespace ShadowStrike
