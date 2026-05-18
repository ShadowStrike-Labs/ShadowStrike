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
        return m_store.load(std::memory_order_acquire) != nullptr;
    }

    /// @brief Bind to an already-initialised ThreatIntelStore.
    ///
    /// Single source of truth: the atomic store pointer. A non-null pointer
    /// means "ready"; nullptr means "not bound". This eliminates the prior
    /// race where readers could observe m_initialized==true with a stale
    /// m_store value (or vice versa).
    void Bind(ThreatIntelStore* store) noexcept {
        m_store.store(store, std::memory_order_release);
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
        auto* store = m_store.load(std::memory_order_acquire);
        if (store == nullptr) return false;

        // ThreatIntelStore::LookupHash is noexcept; no try/catch required.
        const auto result = store->LookupHash("SHA256", sha256);
        if (result.IsMalicious()) {
            outRiskScore = static_cast<double>(result.score);
            // IOCEntry is a packed binary struct without a string threatName;
            // callers derive a display name from category + source separately.
            outThreatName.clear();
            return true;
        }
        return false;
    }

    // ========================================================================
    // DELEGATING LOOKUPS (used by VBScriptScanner etc.)
    // ========================================================================

    [[nodiscard]] StoreLookupResult LookupURL(std::string_view url) const noexcept {
        auto* store = m_store.load(std::memory_order_acquire);
        if (store == nullptr) return {};
        return store->LookupURL(url);
    }

    [[nodiscard]] StoreLookupResult LookupIP(std::string_view ip) const noexcept {
        auto* store = m_store.load(std::memory_order_acquire);
        if (store == nullptr) return {};
        return store->LookupIPv4(ip);
    }

    [[nodiscard]] StoreLookupResult LookupDomain(std::string_view domain) const noexcept {
        auto* store = m_store.load(std::memory_order_acquire);
        if (store == nullptr) return {};
        return store->LookupDomain(domain);
    }

    [[nodiscard]] StoreLookupResult LookupHash(
        std::string_view algorithm,
        std::string_view hashValue) const noexcept
    {
        auto* store = m_store.load(std::memory_order_acquire);
        if (store == nullptr) return {};
        return store->LookupHash(algorithm, hashValue);
    }

private:
    ThreatIntelManager() = default;
    ~ThreatIntelManager() = default;

    // Single atomic pointer is both the "ready" flag and the target. Readers
    // load once with acquire semantics and operate on the local copy, so a
    // concurrent Bind(nullptr) cannot tear an in-flight lookup.
    std::atomic<ThreatIntelStore*> m_store{nullptr};
};

}  // namespace ThreatIntel
}  // namespace ShadowStrike
