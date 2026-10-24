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
#include <optional>
#include <string>
#include <string_view>

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

/**
 * @brief Cryptocurrency being mined. ONE enum for the module (task 281):
 *        CryptoMinerDetector and PoolConnectionDetector each declared an identical
 *        layout under different names, so a value converted between them silently.
 *        MinedCryptocurrency is an alias of this.
 */
enum class Cryptocurrency : uint8_t {
    Unknown     = 0,
    Bitcoin     = 1,
    Ethereum    = 2,
    Monero      = 3,
    Litecoin    = 4,
    Ravencoin   = 5,
    Zcash       = 6,
    EthClassic  = 7,
    Ergo        = 8,
    Other       = 255
};

/**
 * @brief Whether an address has the form of a wallet of this currency. Fails closed
 *        for Unknown and Other. The one validator for the module (defined in
 *        CryptoMinerDetector.cpp); the regex table PoolConnectionDetector kept beside
 *        it disagreed on Monero integrated addresses, shielded Zcash and ltc1 Litecoin.
 */
/// Display name of a currency (defined in CryptoMinerDetector.cpp).
[[nodiscard]] std::string_view GetCryptocurrencyName(Cryptocurrency crypto) noexcept;

[[nodiscard]] bool ValidateWalletAddress(std::string_view address, Cryptocurrency crypto);

/**
 * @brief The currency whose wallet form an address has, tried in a fixed order
 *        (Bitcoin, Ethereum, Monero, Litecoin, Zcash, Ravencoin, Ergo). Ethereum
 *        Classic addresses are EVM addresses, indistinguishable from Ethereum's, so
 *        they classify as Ethereum. Nullopt when no form matches.
 */
[[nodiscard]] std::optional<Cryptocurrency> ClassifyWalletAddress(std::string_view address);

} // namespace CryptoMiners
} // namespace ShadowStrike
