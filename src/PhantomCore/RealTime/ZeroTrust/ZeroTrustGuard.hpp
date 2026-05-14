/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomCore - ZERO-TRUST EXECUTION GUARD
 * ============================================================================
 *
 * @file ZeroTrustGuard.hpp
 * @brief Decision-fusion layer for zero-trust process execution control.
 *
 * ROLE IN THE ARCHITECTURE:
 * =========================
 * ZeroTrustGuard is NOT a detection engine. It is a verdict aggregator that
 * sits in front of process execution and emits Allow / Block / Uncertain by
 * fusing outputs from the existing PhantomCore subsystems:
 *
 *   - AccessControlManager  — behavioral / policy context signals (bitmask).
 *   - WhitelistStore        — publisher + hash allow-list.
 *   - ThreatIntelManager    — reputation score (0-100, normalized to 0..1).
 *   - PhantomCortex         — static classifier benign confidence (0..1).
 *   - HashStore / SignatureStore — clean/malware store membership flags.
 *
 * Inputs are pre-resolved by the caller (the process-exec hook) and passed in
 * as a DecisionInputs struct. ZeroTrustGuard does NOT re-query subsystems
 * inside Decide(); this keeps the hot path fast and the logic testable.
 *
 * BLEND FORMULA:
 * ==============
 *   w_publisher = 0.25  (if publisherSigned && publisherTrusted, else 0)
 *   w_reputation = 0.30 * reputationScore  (if present, else weight omitted)
 *   w_static     = 0.30 * staticBenignConfidence  (if present, else omitted)
 *   w_acm        = 0.15 * (1.0 - RiskFromACM(riskSignals))
 *
 * Weights are normalized over the sum of active weights so missing inputs do
 * not drag the score toward zero.
 *
 * RiskFromACM(bitmask) = min(1.0, popcount(bitmask) / 6.0)
 *
 * ADAPTATIONS FROM SPECIFICATION:
 * ================================
 *  1. ModulePhase::Runtime does not exist in the real enum; CoreProtections
 *     is used instead (it is the correct phase for real-time process guards).
 *  2. WhitelistStore has no static Instance() singleton; all whitelist signals
 *     (publisherWhitelisted, hashInCleanStore) must be pre-resolved by the
 *     caller using a WhitelistStore reference they already own. This is
 *     documented in Initialize().
 *  3. ThreatIntelManager::IsKnownMalicious() returns a 0-100 risk score. The
 *     caller must normalize to 0..1 before populating reputationScore.
 *  4. The namespace ShadowStrike::PhantomHome used in the wiring spec does not
 *     match the real namespace ShadowStrike::Products::Home. The real namespace
 *     is used in ZeroTrustWiring.hpp/.cpp.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace ShadowStrike::PhantomCore::RealTime::ZeroTrust {

// ============================================================================
// VERDICT / POLICY ENUMERATIONS
// ============================================================================

enum class Verdict : std::uint8_t {
    Allow     = 0,
    Block     = 1,
    Uncertain = 2,
};

enum class UncertainBehavior : std::uint8_t {
    SilentAllow = 0,
    SilentBlock = 1,
    Prompt      = 2,   ///< Queues a user prompt via ZeroTrustPromptQueue.
};

// ============================================================================
// DECISION INPUT / OUTPUT
// ============================================================================

/**
 * @brief All signals relevant to a single process-launch decision.
 *
 * Callers fill whichever fields they have; missing optional fields are treated
 * as "unknown" and their weights are omitted from the blend. Boolean flags
 * default to the most restrictive safe assumption.
 */
struct DecisionInputs {
    std::wstring imagePath;
    std::string  sha256;             ///< Hex, lowercase.
    std::string  publisherSubject;   ///< Authenticode subject name, if any.
    bool         publisherSigned   = false;
    bool         publisherTrusted  = false;  ///< Chain verifies to trusted root.

    /// Reputation score 0.0..1.0 (higher = more reputable / more benign).
    /// Caller normalizes: ThreatIntelManager returns 0-100 risk, so
    /// reputationScore = 1.0 - (riskScore / 100.0) if hash is found.
    std::optional<double> reputationScore;

    /// PhantomCortex static-classifier benign confidence 0.0..1.0.
    std::optional<double> staticBenignConfidence;

    bool         hashInCleanStore   = false;
    bool         hashInMalwareStore = false;
    bool         publisherWhitelisted = false;

    std::uint32_t parentPid  = 0;
    std::wstring  parentImage;
    /// Bitmask from AccessControlManager risk signals (each set bit = 1 risk).
    std::uint32_t riskSignalsFromACM = 0;
};

struct DecisionResult {
    Verdict       verdict       = Verdict::Uncertain;
    double        computedTrust = 0.0;  ///< Blended score [0..1].
    double        threshold     = 0.0;  ///< Threshold used for this decision.
    std::string   reason;               ///< Human-readable explanation.
    bool          promptEnqueued = false;
    std::uint64_t promptId       = 0;
};

// ============================================================================
// CONFIGURATION SNAPSHOT
// ============================================================================

struct ZeroTrustConfigSnapshot {
    double            threshold            = 0.85;
    bool              zeroTrustMode        = false;  ///< Pins threshold to 0.999.
    UncertainBehavior uncertainBehavior    = UncertainBehavior::Prompt;
    bool              requirePublisherSigned = false;
    bool              requireWhitelist       = false;
    double            minReputation          = 0.0;
    double            minStaticBenign        = 0.0;
};

// ============================================================================
// ZERO TRUST GUARD — MEYERS' SINGLETON
// ============================================================================

class [[nodiscard]] ZeroTrustGuard final {
public:
    [[nodiscard]] static ZeroTrustGuard& Instance();

    ZeroTrustGuard(const ZeroTrustGuard&)            = delete;
    ZeroTrustGuard& operator=(const ZeroTrustGuard&) = delete;

    /// @brief Resolve references to underlying singletons; load config.
    [[nodiscard]] bool Initialize();

    /// @brief Arm the guard (no background threads needed currently).
    [[nodiscard]] bool Start();

    /// @brief Quiesce all pending operations.
    void Shutdown();

    /// @brief Apply per-mode threshold / behavior policy.
    /// @param modeOrdinal  Cast of ProtectionMode enum value.
    [[nodiscard]] bool ApplyMode(std::uint8_t modeOrdinal);

    /**
     * @brief Core decision entry-point. Thread-safe.
     *
     * Reads config under shared_lock so concurrent calls to Decide() do not
     * serialize against each other; only SetConfig() takes a unique_lock.
     */
    [[nodiscard]] DecisionResult Decide(const DecisionInputs& inputs);

    [[nodiscard]] ZeroTrustConfigSnapshot GetConfig() const;
    [[nodiscard]] bool SetConfig(const ZeroTrustConfigSnapshot& next);

private:
    ZeroTrustGuard();
    ~ZeroTrustGuard();
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace ShadowStrike::PhantomCore::RealTime::ZeroTrust

// ============================================================================
// UNIT-TEST HELPERS  (only compiled in test builds)
// ============================================================================
#ifdef SHADOWSTRIKE_UNIT_TEST
namespace ShadowStrike::PhantomCore::RealTime::ZeroTrust {

[[nodiscard]] double ZeroTrustGuard_BlendedTrust_ForTest(const DecisionInputs&);
[[nodiscard]] double ZeroTrustGuard_RiskFromAcm_ForTest(std::uint32_t bitmask);

} // namespace
#endif
