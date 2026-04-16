/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * ============================================================================
 * ShadowStrike CryptoMiner Protection - SHARED TYPES
 * ============================================================================
 *
 * @file CryptoMinersTypes.hpp
 * @brief Canonical shared enumerations used across all CryptoMinersProtection
 *        sub-modules. Single definition prevents ODR violations when the
 *        orchestrator includes every sub-module header.
 */

#pragma once

#include <cstdint>
#include <functional>
#include <string>

namespace ShadowStrike {
namespace CryptoMiners {

// ============================================================================
// SHARED ENUMERATIONS
// ============================================================================

/**
 * @brief Threat severity level for mining detections.
 */
enum class ThreatSeverity : uint8_t {
    None        = 0,
    Low         = 1,
    Medium      = 2,
    High        = 3,
    Critical    = 4
};

/**
 * @brief Lifecycle status for CryptoMinersProtection modules.
 *
 * Superset of all states used by sub-modules and the orchestrator.
 * Individual modules may only transition through a subset of these states.
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Scanning        = 3,    ///< Active scan in progress (GPU/orchestrator)
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7,
    Degraded        = 8     ///< Running with reduced capability (some sub-detectors failed)
};

/**
 * @brief Common error callback shared by all CryptoMinersProtection modules.
 */
using ErrorCallback = std::function<void(const std::string& message, int code)>;

} // namespace CryptoMiners
} // namespace ShadowStrike
