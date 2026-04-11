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
 * ShadowStrike Core Process - SHARED TYPE DEFINITIONS
 * ============================================================================
 *
 * @file ProcessTypes.hpp
 * @brief Common enumerations shared across multiple Process module headers.
 *
 * This header centralises enums that were previously duplicated in
 * AtomBombingDetector.hpp, ReflectiveDLLDetector.hpp, ThreadHijackDetector.hpp,
 * and DLLInjectionDetector.hpp.  Including this single header eliminates
 * redefinition errors when multiple detector headers are compiled together.
 *
 * @author ShadowStrike Security Team
 * @version 4.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <cstdint>

namespace ShadowStrike {
namespace Core {
namespace Process {

// ============================================================================
// SHARED ENUMERATIONS
// ============================================================================

/**
 * @enum DetectionConfidence
 * @brief Confidence level of detection — shared across all detectors.
 */
enum class DetectionConfidence : uint8_t {
    None = 0,
    Low = 1,              ///< Single weak indicator
    Medium = 2,           ///< Multiple indicators
    High = 3,             ///< Strong indicators / correlation
    Confirmed = 4         ///< Definitive evidence / attack chain confirmed
};

/**
 * @enum MonitoringMode
 * @brief Real-time monitoring mode — shared across detectors.
 */
enum class MonitoringMode : uint8_t {
    Disabled = 0,
    PassiveOnly = 1,          ///< Monitor and alert only
    Active = 2,               ///< Can block suspicious activity
    Aggressive = 3            ///< Block all suspicious cross-process activity
};

} // namespace Process
} // namespace Core
} // namespace ShadowStrike
