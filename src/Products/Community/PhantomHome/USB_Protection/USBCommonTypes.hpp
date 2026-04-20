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
 * ShadowStrike NGAV - USB COMMON TYPES
 * ============================================================================
 *
 * @file USBCommonTypes.hpp
 * @brief Shared type definitions for USB_Protection modules.
 *
 * Centralises enumerations and type aliases that are referenced across
 * multiple USB_Protection headers (DeviceControlManager, USBDeviceMonitor,
 * USBAutorunBlocker, USBScanner, BadUSBDetector) to eliminate ODR
 * violations when a single translation unit includes more than one
 * sibling header.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma once

#include <cstdint>
#include <string_view>

namespace ShadowStrike {
namespace USB {

// ============================================================================
// UNIFIED ACCESS LEVEL
// ============================================================================

/**
 * @brief Unified access level for USB devices.
 *
 * Canonical definition shared by DeviceControlManager and
 * USBDeviceMonitor.  All USB_Protection modules must use this
 * single definition to avoid ODR violations.
 */
enum class AccessLevel : uint8_t {
    FullAccess      = 0,    ///< Read, write, execute
    ReadOnly        = 1,    ///< Read-only access
    WriteOnly       = 2,    ///< Write-only (rare, specialised scenarios)
    NoExecute       = 3,    ///< Read/write but no execute
    Blocked         = 4,    ///< No access allowed
    QuarantineOnly  = 5,    ///< Scan/quarantine only
    AuditOnly       = 6,    ///< Log but don't enforce
    Custom          = 255   ///< Custom permission set
};

/**
 * @brief Shared module lifecycle state.
 *
 * Canonical lifecycle state used by USB modules whose state machine does not
 * require module-specific substates such as Monitoring or Scanning.
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Paused          = 3,
    Stopping        = 4,
    Stopped         = 5,
    Error           = 6
};

/// @brief Human-readable name for an AccessLevel value.
[[nodiscard]] inline std::string_view GetAccessLevelName(AccessLevel level) noexcept {
    switch (level) {
        case AccessLevel::FullAccess:     return "FullAccess";
        case AccessLevel::ReadOnly:       return "ReadOnly";
        case AccessLevel::WriteOnly:      return "WriteOnly";
        case AccessLevel::NoExecute:      return "NoExecute";
        case AccessLevel::Blocked:        return "Blocked";
        case AccessLevel::QuarantineOnly: return "QuarantineOnly";
        case AccessLevel::AuditOnly:      return "AuditOnly";
        case AccessLevel::Custom:         return "Custom";
        default:                          return "Unknown";
    }
}

}  // namespace USB
}  // namespace ShadowStrike
