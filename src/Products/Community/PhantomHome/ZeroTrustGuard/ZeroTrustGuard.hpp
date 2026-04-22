/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomHome - ZERO-TRUST EXECUTION GUARD (PhantomHome adapter)
 * ============================================================================
 *
 * @file ZeroTrustGuard.hpp
 * @brief PhantomHome product-layer adapter for the PhantomCore Zero-Trust
 *        Execution Guard engine.
 *
 * ROLE IN THE ARCHITECTURE:
 * =========================
 * This class is the PhantomHome-facing surface of the zero-trust subsystem.
 * It translates between the PhantomHome type system (ZeroTrustInputs,
 * ZeroTrustDecision, ZeroTrustConfig) and the PhantomCore engine types
 * (DecisionInputs, Verdict, ZeroTrustConfigSnapshot).
 *
 * All blended scoring, hard-gate logic, and uncertain-band handling are
 * delegated to ShadowStrike::PhantomCore::RealTime::ZeroTrust::ZeroTrustGuard
 * to avoid logic duplication. See that module for the full algorithm
 * specification and threat model.
 *
 * THREAD SAFETY:
 * ==============
 * - Evaluate() is the hot path. It acquires only a shared_lock for the mode
 *   read, then delegates to the stateless PhantomCore engine. Multiple
 *   concurrent calls to Evaluate() do not contend with each other.
 * - SetConfig() / SetMode() acquire a unique_lock and are expected to be
 *   called infrequently (mode transitions, UI config changes).
 *
 * HOT-PATH INVARIANT:
 * ===================
 * Evaluate() is allocation-free for Allow/Block results. The only allocation
 * occurs on the Uncertain+Prompt path when a ZeroTrustPromptItem is enqueued.
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
#include <string_view>

#include "../HomeProductOrchestrator.hpp"

namespace ShadowStrike::Products::Home::ZeroTrust {

// ============================================================================
// VERDICT ENUMERATIONS
// ============================================================================

/// @brief Three-valued verdict returned by Evaluate().
enum class ZeroTrustDecision : std::uint8_t {
    Allow     = 0,  ///< Score sufficiently high; execution may proceed.
    Block     = 1,  ///< Score too low or hard gate failed; block execution.
    Uncertain = 2,  ///< Score in uncertain band; caller must check behavior policy.
};

/// @brief Policy applied when the blended score falls in the uncertain band.
enum class ZeroTrustUncertainBehavior : std::uint8_t {
    SilentAllow = 0,  ///< Silently promote Uncertain to Allow.
    SilentBlock = 1,  ///< Silently promote Uncertain to Block.
    Prompt      = 2,  ///< Return Uncertain to caller; enqueue a UI prompt.
};

// ============================================================================
// INPUT / CONFIG STRUCTS
// ============================================================================

/**
 * @brief All process-launch signals relevant to a single execution decision.
 *
 * Fields are zero-valued by default to the most restrictive safe assumption.
 * Optional fields whose values are unavailable should be left as nullopt;
 * missing signals are excluded from the blended score denominator so their
 * absence does not artificially drag the score toward zero.
 *
 * imagePath and publisherSubject are wstring_view to avoid copies on the hot
 * path. Callers must ensure the underlying storage outlives Evaluate().
 */
struct ZeroTrustInputs {
    /// @brief The executable image path of the process being evaluated.
    std::wstring_view imagePath;

    /// @brief Authenticode publisher subject name from the PE certificate chain.
    std::wstring_view publisherSubject;

    /// @brief The process session ID (for per-session prompt routing to the UI).
    std::uint32_t processSessionId = 0;

    /// @brief Whether the binary carries a valid Authenticode signature.
    bool publisherSigned  = false;

    /// @brief Whether the signature chain verifies to a trusted root CA.
    bool publisherTrusted = false;

    /// @brief Reputation score [0.0, 1.0]; higher = more reputable/benign.
    ///        Absent when the ThreatIntel subsystem has no record for this hash.
    std::optional<double> reputation;

    /// @brief PhantomCortex static-classifier benign confidence [0.0, 1.0].
    ///        Absent when the static analysis stage was skipped.
    std::optional<double> staticBenign;

    /// @brief ACM risk-signal bitmask (lower 6 bits used; each set bit = one
    ///        independent risk indicator from the Access Control Manager).
    ///        Absent means ACM data was unavailable; treated as zero risk
    ///        (optimistic, not included in weight sum).
    std::optional<std::uint8_t> acmRisk;
};

/**
 * @brief Policy snapshot applied to every call of Evaluate().
 *
 * All fields have safe defaults suitable for Balanced mode. zeroTrustMode
 * overrides threshold and all gate flags to their most restrictive values
 * when set to true.
 */
struct ZeroTrustConfig {
    /// @brief Blended score threshold for Allow/Block demarcation. [0.0, 1.0].
    double threshold = 0.70;

    /// @brief Half-width of the uncertain band around the threshold.
    ///        score >= threshold+band → Allow; score < threshold-band → Block.
    double uncertainBand = 0.05;

    /// @brief Block if the binary is not Authenticode-signed.
    bool requirePublisherSigned = false;

    /// @brief Block if the image path or publisher is not in the allow-list.
    bool requireWhitelist = false;

    /// @brief Minimum required reputation score; 0.0 disables the gate.
    double minReputation = 0.0;

    /// @brief Minimum required static-benign confidence; 0.0 disables the gate.
    double minStaticBenign = 0.0;

    /// @brief Policy when the blended score is inside the uncertain band.
    ZeroTrustUncertainBehavior uncertainBehavior = ZeroTrustUncertainBehavior::Prompt;

    /// @brief Zero-Trust strict mode: pins threshold=0.999 and all gates ON.
    ///        Independent of the ProtectionMode; must be set explicitly by the
    ///        administrator via SetConfig().
    bool zeroTrustMode = false;
};

// ============================================================================
// ZERO TRUST GUARD — MEYERS' SINGLETON
// ============================================================================

/**
 * @class ZeroTrustGuard
 * @brief PhantomHome adapter singleton over the PhantomCore zero-trust engine.
 *
 * Lifecycle is managed by the ZeroTrustWiring registrar. Callers on the
 * process-exec hot path call only Evaluate(), which is lock-light and
 * allocation-free for the common Allow/Block case.
 */
class ZeroTrustGuard final {
public:
    /// @brief Meyers' singleton accessor.
    [[nodiscard]] static ZeroTrustGuard& Instance();

    ZeroTrustGuard(const ZeroTrustGuard&)            = delete;
    ZeroTrustGuard& operator=(const ZeroTrustGuard&) = delete;

    // ---- Lifecycle ---------------------------------------------------------

    /// @brief Initialize the guard. Loads persisted config from ConfigManager.
    ///        Idempotent; safe to call multiple times.
    [[nodiscard]] bool Initialize();

    /// @brief Arm the guard. Must be called after Initialize().
    [[nodiscard]] bool Start();

    /// @brief Quiesce the guard. Idempotent.
    void Shutdown();

    // ---- Configuration -----------------------------------------------------

    /// @brief Apply a new configuration snapshot. Thread-safe.
    ///        Validates threshold in [0, 1] before accepting.
    void SetConfig(const ZeroTrustConfig& c);

    /// @brief Return the current configuration snapshot. Thread-safe.
    [[nodiscard]] ZeroTrustConfig GetConfig() const;

    // ---- Mode integration --------------------------------------------------

    /// @brief Transition to a new ProtectionMode.
    ///        Also persists ModeThresholds to ConfigManager.
    void SetMode(::ShadowStrike::Products::Home::ProtectionMode m);

    /// @brief Return the current ProtectionMode.
    [[nodiscard]] ::ShadowStrike::Products::Home::ProtectionMode Mode() const;

    // ---- Hot-path entry point ----------------------------------------------

    /**
     * @brief Evaluate a process launch request and return a verdict.
     *
     * Thread-safe. The hot path acquires only a shared_lock for the config
     * snapshot read; concurrent calls do not serialize.
     *
     * Hard-gate failures (requirePublisherSigned, requireWhitelist,
     * minReputation, minStaticBenign) always produce Block regardless of
     * the blended score.
     *
     * Uncertain verdicts are resolved via the configured UncertainBehavior:
     *   SilentAllow → returns Allow
     *   SilentBlock → returns Block
     *   Prompt      → enqueues a ZeroTrustPromptItem and returns Uncertain
     *
     * @param in       Pre-resolved signals for the process being evaluated.
     * @param outScore Optional out-parameter receiving the blended score [0,1].
     * @return         Final verdict after applying all policy gates.
     */
    [[nodiscard]] ZeroTrustDecision Evaluate(const ZeroTrustInputs& in,
                                             double* outScore = nullptr) const;

private:
    ZeroTrustGuard();
    ~ZeroTrustGuard();

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace ShadowStrike::Products::Home::ZeroTrust
