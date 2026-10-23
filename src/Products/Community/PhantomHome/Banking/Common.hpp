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
 * @file Common.hpp
 * @brief Types shared by every ShadowStrike::Banking module.
 *
 * A type that describes ONE concept across the namespace is defined here, once.
 * BankingTrojanDetector.hpp and KeyloggerProtection.hpp each declared their own
 * DetectionAction with Quarantine and Terminate transposed (3/4 against 4/3), so
 * the same number named a different response depending on which header a
 * translation unit saw - and two definitions of one enum in one namespace is an
 * ODR violation even before any file includes both.
 *
 * Do not guard a definition here with #ifndef/#define pairs: that makes the
 * meaning of a value depend on include order. Per-module types that only share a
 * NAME belong in a nested namespace, not here.
 */

#pragma once

#include <cstdint>

namespace ShadowStrike::Banking {

/// Response taken for a detection. Values are stable: they are serialised.
enum class DetectionAction : uint8_t {
    None       = 0,
    Alert      = 1,   ///< Alert only
    Block      = 2,   ///< Block the operation
    Quarantine = 3,   ///< Quarantine the file or process image
    Terminate  = 4,   ///< Terminate the process
    Remediate  = 5    ///< Full remediation
};

} // namespace ShadowStrike::Banking
