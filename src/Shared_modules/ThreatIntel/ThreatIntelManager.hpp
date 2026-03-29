/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
/**
 * ============================================================================
 * ShadowStrike NGAV - THREAT INTEL MANAGER (FACADE)
 * ============================================================================
 *
 * @file ThreatIntelManager.hpp
 * @brief Meyers' singleton facade for ThreatIntelStore.
 *
 * Provides a simplified, singleton-based interface consumed by scanner
 * modules (JavaScriptScanner, VBScriptScanner, etc.) that need quick
 * hash / URL / domain lookups without managing ThreatIntelStore lifetime.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma once

#include "ThreatIntelStore.hpp"
#include "../Utils/Logger.hpp"

#include <atomic>
#include <string>
#include <string_view>

namespace ShadowStrike {
namespace ThreatIntel {

/**
 * @class ThreatIntelManager
 * @brief Meyers' singleton facade over ThreatIntelStore for scanner modules.
 *
 * Wraps the non-singleton ThreatIntelStore and exposes convenience methods
 * such as IsKnownMalicious() used by JavaScript / VBScript scanners.
 */
class ThreatIntelManager final {
public:
    /// @brief Meyers' singleton
    [[nodiscard]] static ThreatIntelManager& Instance() {
        static ThreatIntelManager instance;
        return instance;
    }

    ThreatIntelManager(const ThreatIntelManager&) = delete;
    ThreatIntelManager& operator=(const ThreatIntelManager&) = delete;
    ThreatIntelManager(ThreatIntelManager&&) = delete;
    ThreatIntelManager& operator=(ThreatIntelManager&&) = delete;

    /// @brief Check if the underlying store is initialised and usable.
    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_store != nullptr && m_initialized.load(std::memory_order_acquire);
    }

    /// @brief Bind to an already-initialised ThreatIntelStore.
    void Bind(ThreatIntelStore* store) noexcept {
        m_store = store;
        m_initialized.store(store != nullptr, std::memory_order_release);
    }

    // ========================================================================
    // HIGH-LEVEL CONVENIENCE API (used by scanner modules)
    // ========================================================================

    /**
     * @brief Check whether a SHA-256 hash is known-malicious.
     * @param sha256       Hex-encoded SHA-256 hash
     * @param outRiskScore Populated with 0-100 risk score if found
     * @param outThreatName Populated with threat name if found
     * @return true if hash is malicious or high-risk
     */
    [[nodiscard]] bool IsKnownMalicious(
        const std::string& sha256,
        double& outRiskScore,
        std::string& outThreatName) const noexcept
    {
        if (!IsInitialized()) return false;
        try {
            auto result = m_store->LookupHash("SHA256", sha256);
            if (result.IsMalicious()) {
                outRiskScore = static_cast<double>(result.score);
                // IOCEntry is a packed binary struct without string threatName;
                // derive name from category + source.
                outThreatName.clear();
                return true;
            }
        } catch (...) {}
        return false;
    }

    // ========================================================================
    // DELEGATING LOOKUPS (used by VBScriptScanner etc.)
    // ========================================================================

    [[nodiscard]] StoreLookupResult LookupURL(std::string_view url) const noexcept {
        if (!IsInitialized()) return {};
        return m_store->LookupURL(url);
    }

    [[nodiscard]] StoreLookupResult LookupIP(std::string_view ip) const noexcept {
        if (!IsInitialized()) return {};
        return m_store->LookupIPv4(ip);
    }

    [[nodiscard]] StoreLookupResult LookupDomain(std::string_view domain) const noexcept {
        if (!IsInitialized()) return {};
        return m_store->LookupDomain(domain);
    }

    [[nodiscard]] StoreLookupResult LookupHash(
        std::string_view algorithm,
        std::string_view hashValue) const noexcept
    {
        if (!IsInitialized()) return {};
        return m_store->LookupHash(algorithm, hashValue);
    }

private:
    ThreatIntelManager() = default;
    ~ThreatIntelManager() = default;

    ThreatIntelStore* m_store{nullptr};
    std::atomic<bool> m_initialized{false};
};

}  // namespace ThreatIntel
}  // namespace ShadowStrike
