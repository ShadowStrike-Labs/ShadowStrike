/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file ZeroTrustGuard.cpp
 * @brief Zero-Trust Execution Guard implementation.
 *
 * See ZeroTrustGuard.hpp for the full design rationale and adaptation notes.
 *
 * CONFIG KEYS  (under "Home/ZeroTrust/"):
 *   Enabled                bool    default true
 *   Threshold              double  default 0.85
 *   ZeroTrustMode          bool    default false  (pins threshold to 0.999)
 *   UncertainBehavior      int32   default 2 (Prompt)
 *   RequirePublisherSigned bool    default false
 *   RequireWhitelist       bool    default false
 *   MinReputation          double  default 0.0
 *   MinStaticBenign        double  default 0.0
 */

#include "pch.h"

#include "ZeroTrustGuard.hpp"
#include "ZeroTrustPromptQueue.hpp"

#include "../../../PhantomCore/Config/ConfigManager.hpp"
#include "../../../PhantomCore/Utils/Logger.hpp"
#include "../../../Products/Community/PhantomHome/HomeProductOrchestrator.hpp"
#include "../../../Products/Community/PhantomHome/ModeThresholds.hpp"

#include <algorithm>
#include <atomic>
#include <bit>
#include <cmath>
#include <cstdio>
#include <mutex>
#include <shared_mutex>

namespace ShadowStrike::PhantomCore::RealTime::ZeroTrust {

namespace {

constexpr const wchar_t* kLogCategory = L"ZeroTrustGuard";

// ============================================================================
// CONFIG KEY CONSTANTS
// ============================================================================
constexpr const char* kKeyEnabled                = "Home/ZeroTrust/Enabled";
constexpr const char* kKeyThreshold              = "Home/ZeroTrust/Threshold";
constexpr const char* kKeyZeroTrustMode          = "Home/ZeroTrust/ZeroTrustMode";
constexpr const char* kKeyUncertainBehavior      = "Home/ZeroTrust/UncertainBehavior";
constexpr const char* kKeyRequirePublisherSigned = "Home/ZeroTrust/RequirePublisherSigned";
constexpr const char* kKeyRequireWhitelist       = "Home/ZeroTrust/RequireWhitelist";
constexpr const char* kKeyMinReputation          = "Home/ZeroTrust/MinReputation";
constexpr const char* kKeyMinStaticBenign        = "Home/ZeroTrust/MinStaticBenign";

constexpr double kZeroTrustModeThreshold = 0.999;

// Effective thresholds at each ProtectionMode level.
constexpr double kThresholdPassive    = 0.50;
constexpr double kThresholdBalanced   = 0.85;
constexpr double kThresholdAggressive = 0.95;

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

/// @brief Clamp a double to [0.0, 1.0]; treats NaN as 0.0 (most-restrictive).
[[nodiscard]] inline double Clamp01(double v) noexcept {
    if (std::isnan(v)) return 0.0;
    return (v < 0.0) ? 0.0 : (v > 1.0) ? 1.0 : v;
}

/// @brief Format a double in [0,1] to a fixed 3-decimal narrow string,
///        locale-independently. NaN/Inf collapse to "nan"/"inf" markers so
///        reason strings remain deterministic and safe to log.
[[nodiscard]] inline std::string FormatTrust(double v) {
    if (std::isnan(v)) return "nan";
    if (!std::isfinite(v)) return v < 0.0 ? "-inf" : "inf";
    char buf[16]{};
    const int n = std::snprintf(buf, sizeof(buf), "%.3f", v);
    if (n <= 0) return "0.000";
    return std::string(buf, static_cast<std::size_t>(
        (static_cast<std::size_t>(n) < sizeof(buf)) ? n : sizeof(buf) - 1));
}

/// @brief Strict lowercase-hex sanitiser for safe logging of caller-supplied
///        sha256 strings. Replaces any non-hex byte with '?' and truncates to
///        at most @p maxChars characters to prevent log injection / overflow.
[[nodiscard]] inline std::string SanitizeShaForLog(const std::string& sha,
                                                   std::size_t maxChars = 16) {
    std::string out;
    out.reserve(std::min(sha.size(), maxChars));
    for (std::size_t i = 0; i < sha.size() && i < maxChars; ++i) {
        const unsigned char c = static_cast<unsigned char>(sha[i]);
        const bool isHex = (c >= '0' && c <= '9')
                        || (c >= 'a' && c <= 'f')
                        || (c >= 'A' && c <= 'F');
        out.push_back(isHex ? static_cast<char>(c) : '?');
    }
    return out;
}

/**
 * @brief Derive a normalised risk value from an ACM risk-signal bitmask.
 *
 * Each set bit represents one independent risk indicator (e.g. elevated
 * integrity, suspicious parent, unexpected privilege). We cap at 6 bits for
 * the normalisation denominator so a single-bit risk is still meaningful.
 *
 * @return Value in [0.0, 1.0]; higher = more risky.
 */
[[nodiscard]] double RiskFromAcmBitmask(std::uint32_t bitmask) noexcept {
    const int bits = std::popcount(bitmask);
    constexpr double kDivisor = 6.0;
    return std::min(1.0, static_cast<double>(bits) / kDivisor);
}

/**
 * @brief Compute the blended trust score from a DecisionInputs struct.
 *
 * Weights are allocated as:
 *   publisher  0.25 (if publisherSigned && publisherTrusted)
 *   reputation 0.30 (if reputationScore present)
 *   static     0.30 (if staticBenignConfidence present)
 *   acm        0.15 (always present — missing ACM signals = zero risk)
 *
 * Missing optional weights are excluded from both numerator and denominator,
 * so the result remains in [0.0, 1.0] regardless of signal completeness.
 * If ALL weights sum to zero (degenerate), returns 0.5 (maximum uncertainty).
 *
 * @return Trust score in [0.0, 1.0]; higher = more trustworthy.
 */
[[nodiscard]] double ComputeBlendedTrust(const DecisionInputs& in) noexcept {
    double weightSum = 0.0;
    double scoreSum  = 0.0;

    // Publisher signal — only meaningful when both signed & trusted.
    if (in.publisherSigned && in.publisherTrusted) {
        constexpr double w = 0.25;
        scoreSum  += w * 1.0;
        weightSum += w;
    } else if (in.publisherSigned) {
        // Signed but chain not verified: half-weight, half-credit.
        constexpr double w = 0.25;
        scoreSum  += w * 0.5;
        weightSum += w;
    } else {
        // Unsigned: include weight so it drags the score down appropriately.
        constexpr double w = 0.25;
        scoreSum  += w * 0.0;
        weightSum += w;
    }

    // Reputation signal.
    if (in.reputationScore.has_value()) {
        constexpr double w = 0.30;
        scoreSum  += w * Clamp01(in.reputationScore.value());
        weightSum += w;
    }

    // Static classifier signal.
    if (in.staticBenignConfidence.has_value()) {
        constexpr double w = 0.30;
        scoreSum  += w * Clamp01(in.staticBenignConfidence.value());
        weightSum += w;
    }

    // ACM risk signal (always considered).
    {
        constexpr double w = 0.15;
        const double risk = RiskFromAcmBitmask(in.riskSignalsFromACM);
        scoreSum  += w * (1.0 - risk);
        weightSum += w;
    }

    if (weightSum <= 0.0) {
        return 0.5; // Maximum-uncertainty fallback.
    }

    return Clamp01(scoreSum / weightSum);
}

/**
 * @brief Truncate a wide string to at most maxChars characters for safe logging.
 *
 * We must never log unbounded external data; arbitrary paths can be very long.
 */
[[nodiscard]] std::wstring TruncateW(const std::wstring& s, std::size_t maxChars) {
    if (s.size() <= maxChars) return s;
    return s.substr(0, maxChars);
}

/**
 * @brief Load config snapshot from ConfigManager, applying defaults if keys
 *        are absent.
 */
[[nodiscard]] ZeroTrustConfigSnapshot LoadConfigFromManager() {
    auto& cfg = ::ShadowStrike::Config::ConfigManager::Instance();

    ZeroTrustConfigSnapshot snap;
    snap.threshold = cfg.GetValue<double>(kKeyThreshold, 0.85);
    snap.threshold = std::clamp(snap.threshold, 0.0, 1.0);

    snap.zeroTrustMode = cfg.GetValue<bool>(kKeyZeroTrustMode, false);

    const auto behaviorInt = cfg.GetValue<int32_t>(kKeyUncertainBehavior, 2);
    if (behaviorInt >= 0 && behaviorInt <= 2) {
        snap.uncertainBehavior = static_cast<UncertainBehavior>(behaviorInt);
    } else {
        snap.uncertainBehavior = UncertainBehavior::Prompt;
    }

    snap.requirePublisherSigned = cfg.GetValue<bool>(kKeyRequirePublisherSigned, false);
    snap.requireWhitelist       = cfg.GetValue<bool>(kKeyRequireWhitelist, false);
    snap.minReputation          = std::clamp(cfg.GetValue<double>(kKeyMinReputation, 0.0), 0.0, 1.0);
    snap.minStaticBenign        = std::clamp(cfg.GetValue<double>(kKeyMinStaticBenign, 0.0), 0.0, 1.0);

    return snap;
}

/**
 * @brief Persist a config snapshot to ConfigManager.
 * @return true iff all writes succeeded.
 */
[[nodiscard]] bool PersistConfigToManager(const ZeroTrustConfigSnapshot& snap) {
    auto& cfg = ::ShadowStrike::Config::ConfigManager::Instance();
    using Layer = ::ShadowStrike::Config::ConfigLayer;

    bool ok = true;
    ok &= cfg.SetValue<double> (kKeyThreshold,              snap.threshold,              Layer::User);
    ok &= cfg.SetValue<bool>   (kKeyZeroTrustMode,          snap.zeroTrustMode,          Layer::User);
    ok &= cfg.SetValue<int32_t>(kKeyUncertainBehavior,      static_cast<int32_t>(snap.uncertainBehavior), Layer::User);
    ok &= cfg.SetValue<bool>   (kKeyRequirePublisherSigned, snap.requirePublisherSigned, Layer::User);
    ok &= cfg.SetValue<bool>   (kKeyRequireWhitelist,       snap.requireWhitelist,       Layer::User);
    ok &= cfg.SetValue<double> (kKeyMinReputation,          snap.minReputation,          Layer::User);
    ok &= cfg.SetValue<double> (kKeyMinStaticBenign,        snap.minStaticBenign,        Layer::User);
    return ok;
}

} // anonymous namespace

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

struct ZeroTrustGuard::Impl {
    mutable std::shared_mutex    m_mutex;
    ZeroTrustConfigSnapshot      m_config;
    std::atomic<bool>            m_enabled{false};
    std::atomic<bool>            m_initialized{false};
    std::atomic<bool>            m_running{false};

    Impl()  = default;
    ~Impl() = default;

    Impl(const Impl&)            = delete;
    Impl& operator=(const Impl&) = delete;
};

// ============================================================================
// SINGLETON
// ============================================================================

ZeroTrustGuard& ZeroTrustGuard::Instance() {
    static ZeroTrustGuard s_instance;
    return s_instance;
}

ZeroTrustGuard::ZeroTrustGuard()
    : m_impl(std::make_unique<Impl>())
{}

ZeroTrustGuard::~ZeroTrustGuard() {
    // Shutdown() is idempotent; call it here in case the orchestrator did not.
    Shutdown();
}

// ============================================================================
// LIFECYCLE
// ============================================================================

bool ZeroTrustGuard::Initialize() {
    // Single-shot initialisation: only the thread that flips m_initialized
    // from false → true performs the load. Concurrent callers safely no-op
    // after the winning thread completes.
    bool expected = false;
    if (!m_impl->m_initialized.compare_exchange_strong(
            expected, true,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        return true;
    }

    SS_LOG_INFO(kLogCategory, L"ZeroTrustGuard: Initializing");

    // Check the orchestrator-level enabled gate.
    bool moduleEnabled = true;
    if (::ShadowStrike::Config::ConfigManager::HasInstance()) {
        moduleEnabled = ::ShadowStrike::Config::ConfigManager::Instance()
                            .GetValue<bool>(kKeyEnabled, true);
    } else {
        SS_LOG_WARN(kLogCategory,
            L"ZeroTrustGuard: ConfigManager unavailable at Initialize(); "
            L"defaulting to enabled=true");
    }

    // Load initial config snapshot under exclusive lock.
    {
        std::unique_lock lock(m_impl->m_mutex);
        if (::ShadowStrike::Config::ConfigManager::HasInstance()) {
            m_impl->m_config = LoadConfigFromManager();
        }
        // else leave factory defaults
    }

    m_impl->m_enabled.store(moduleEnabled, std::memory_order_release);

    // Note on subsystem singletons:
    //  - AccessControlManager::Instance() (ShadowStrike::RealTime) — available;
    //    risk signals are passed in pre-computed via DecisionInputs.
    //  - ThreatIntelManager::Instance() (ShadowStrike::ThreatIntel) — available;
    //    scores are passed in pre-computed (caller normalizes 0-100 -> 0.0-1.0).
    //  - PhantomCortex::Instance() (ShadowStrike::AI) — available;
    //    benign confidence passed in pre-computed by caller.
    //  - WhitelistStore (ShadowStrike::Whitelist) — NO singleton. Caller must
    //    resolve whitelist membership before calling Decide().
    // Because Decide() accepts pre-resolved inputs, none of these are stored
    // here; this comment documents the design constraint.

    SS_LOG_INFO(kLogCategory,
        L"ZeroTrustGuard: Initialized (enabled=%hs threshold=%.3f ztMode=%hs)",
        moduleEnabled ? "true" : "false",
        m_impl->m_config.threshold,
        m_impl->m_config.zeroTrustMode ? "true" : "false");

    return true;
}

bool ZeroTrustGuard::Start() {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(kLogCategory, L"ZeroTrustGuard: Start() called before Initialize()");
        return false;
    }

    m_impl->m_running.store(true, std::memory_order_release);
    SS_LOG_INFO(kLogCategory, L"ZeroTrustGuard: Running");
    return true;
}

void ZeroTrustGuard::Shutdown() {
    if (!m_impl->m_running.exchange(false, std::memory_order_acq_rel)
        && !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return;
    }
    m_impl->m_initialized.store(false, std::memory_order_release);
    m_impl->m_enabled.store(false, std::memory_order_release);
    SS_LOG_INFO(kLogCategory, L"ZeroTrustGuard: Shut down");
}

// ============================================================================
// MODE APPLICATION
// ============================================================================

bool ZeroTrustGuard::ApplyMode(std::uint8_t modeOrdinal) {
    using ::ShadowStrike::Products::Home::ProtectionMode;
    using ::ShadowStrike::Products::Home::ApplyModeThresholds;

    const auto mode = static_cast<ProtectionMode>(modeOrdinal);

    SS_LOG_INFO(kLogCategory,
        L"ZeroTrustGuard: ApplyMode(%u)", static_cast<unsigned>(modeOrdinal));

    if (mode == ProtectionMode::Off) {
        m_impl->m_enabled.store(false, std::memory_order_release);
        SS_LOG_INFO(kLogCategory, L"ZeroTrustGuard: Mode=Off — module disabled");
        return true;
    }

    // Reject unknown / out-of-range mode ordinals before they silently fall
    // through the switch and leave the module in a stale-config state.
    if (mode != ProtectionMode::Passive
        && mode != ProtectionMode::Balanced
        && mode != ProtectionMode::Aggressive) {
        SS_LOG_WARN(kLogCategory,
            L"ZeroTrustGuard: ApplyMode rejected unknown ordinal %u",
            static_cast<unsigned>(modeOrdinal));
        return false;
    }

    // Write the canonical ModeThresholds keys so other subscribers see them.
    if (!ApplyModeThresholds("ZeroTrust", mode)) {
        SS_LOG_WARN(kLogCategory,
            L"ZeroTrustGuard: ApplyModeThresholds() failed for mode %u",
            static_cast<unsigned>(modeOrdinal));
        // Non-fatal: we still apply the in-memory snapshot.
    }

    std::unique_lock lock(m_impl->m_mutex);

    switch (mode) {
        case ProtectionMode::Passive:
            m_impl->m_config.threshold         = kThresholdPassive;
            m_impl->m_config.uncertainBehavior = UncertainBehavior::SilentAllow;
            break;
        case ProtectionMode::Balanced:
            m_impl->m_config.threshold         = kThresholdBalanced;
            m_impl->m_config.uncertainBehavior = UncertainBehavior::Prompt;
            break;
        case ProtectionMode::Aggressive:
            m_impl->m_config.threshold         = kThresholdAggressive;
            m_impl->m_config.uncertainBehavior = UncertainBehavior::Prompt;
            break;
        default:
            // Already filtered above; defensive no-op.
            break;
    }

    // Re-enable if we were Off previously.
    m_impl->m_enabled.store(true, std::memory_order_release);
    // ZeroTrustMode is user-opt-in; do not touch it on mode transitions.

    return true;
}

// ============================================================================
// CORE DECISION LOGIC
// ============================================================================

DecisionResult ZeroTrustGuard::Decide(const DecisionInputs& inputs) {
    // ------------------------------------------------------------------
    // 1. Module disabled → pass-through Allow.
    // ------------------------------------------------------------------
    if (!m_impl->m_enabled.load(std::memory_order_acquire)) {
        return DecisionResult{
            .verdict       = Verdict::Allow,
            .computedTrust = 1.0,
            .threshold     = 0.0,
            .reason        = "module disabled",
        };
    }

    // Read config snapshot under shared_lock (concurrent Decide() calls safe).
    ZeroTrustConfigSnapshot cfg;
    {
        std::shared_lock lock(m_impl->m_mutex);
        cfg = m_impl->m_config;
    }

    // ------------------------------------------------------------------
    // 2. Fast-path ALLOW: clean store or whitelisted publisher.
    // ------------------------------------------------------------------
    if (inputs.hashInCleanStore || inputs.publisherWhitelisted) {
        return DecisionResult{
            .verdict       = Verdict::Allow,
            .computedTrust = 1.0,
            .threshold     = cfg.threshold,
            .reason        = inputs.hashInCleanStore
                                 ? "hash in clean store"
                                 : "publisher whitelisted",
        };
    }

    // ------------------------------------------------------------------
    // 3. Fast-path BLOCK: known malware hash.
    // ------------------------------------------------------------------
    if (inputs.hashInMalwareStore) {
        const std::wstring  safePath = TruncateW(inputs.imagePath, 128);
        const std::string   safeSha  = SanitizeShaForLog(inputs.sha256);
        SS_LOG_WARN(kLogCategory,
            L"ZeroTrustGuard: BLOCK image='%.128ls' sha=%.16hs "
            L"trust=0.000 threshold=%.3f reason=malware store",
            safePath.c_str(),
            safeSha.c_str(),
            cfg.threshold);
        return DecisionResult{
            .verdict       = Verdict::Block,
            .computedTrust = 0.0,
            .threshold     = cfg.threshold,
            .reason        = "hash in malware store",
        };
    }

    // ------------------------------------------------------------------
    // 4. Compute blended trust score.
    // ------------------------------------------------------------------
    const double trust = ComputeBlendedTrust(inputs);

    // Effective threshold: ZeroTrustMode overrides to 0.999.
    const double effectiveThreshold = cfg.zeroTrustMode
                                          ? kZeroTrustModeThreshold
                                          : cfg.threshold;

    // Effective gate flags: ZeroTrustMode implicitly enables all hard gates.
    const bool effectiveRequirePub     = cfg.requirePublisherSigned || cfg.zeroTrustMode;
    const bool effectiveRequireWL      = cfg.requireWhitelist        || cfg.zeroTrustMode;
    const double effectiveMinRep       = cfg.zeroTrustMode ? kZeroTrustModeThreshold
                                                           : cfg.minReputation;
    const double effectiveMinStatic    = cfg.zeroTrustMode ? kZeroTrustModeThreshold
                                                           : cfg.minStaticBenign;

    // ------------------------------------------------------------------
    // 5. Hard gate checks (before threshold comparison).
    // ------------------------------------------------------------------
    auto makeBlockResult = [&](const char* reasonStr) -> DecisionResult {
        const std::wstring safePath = TruncateW(inputs.imagePath, 128);
        const std::string  safeSha  = SanitizeShaForLog(inputs.sha256);
        SS_LOG_WARN(kLogCategory,
            L"ZeroTrustGuard: BLOCK image='%.128ls' sha=%.16hs "
            L"trust=%.3f threshold=%.3f reason=%hs",
            safePath.c_str(),
            safeSha.c_str(),
            trust, effectiveThreshold, reasonStr);
        return DecisionResult{
            .verdict       = Verdict::Block,
            .computedTrust = trust,
            .threshold     = effectiveThreshold,
            .reason        = reasonStr,
        };
    };

    if (effectiveRequirePub && !inputs.publisherSigned) {
        return makeBlockResult("RequirePublisherSigned gate: unsigned binary");
    }

    if (effectiveRequireWL
        && !inputs.publisherWhitelisted
        && !inputs.hashInCleanStore) {
        return makeBlockResult("RequireWhitelist gate: not in whitelist or clean store");
    }

    if (effectiveMinRep > 0.0) {
        if (!inputs.reputationScore.has_value()
            || inputs.reputationScore.value() < effectiveMinRep) {
            return makeBlockResult("MinReputation gate: reputation score insufficient");
        }
    }

    if (effectiveMinStatic > 0.0) {
        if (!inputs.staticBenignConfidence.has_value()
            || inputs.staticBenignConfidence.value() < effectiveMinStatic) {
            return makeBlockResult("MinStaticBenign gate: static classifier score insufficient");
        }
    }

    // ------------------------------------------------------------------
    // 6. Threshold comparison.
    // ------------------------------------------------------------------
    constexpr double kBand = 0.05;
    const double upperEdge = effectiveThreshold + kBand;
    const double lowerEdge = effectiveThreshold - kBand;

    // Build a human-readable signal summary for the reason string. Use
    // locale-independent snprintf formatting; std::to_string for floating
    // point honours the global CRT locale, which can flip the decimal mark
    // to ',' on non-"C" systems and corrupt downstream telemetry parsers.
    std::string signals;
    signals.reserve(128);
    {
        if (inputs.publisherSigned && inputs.publisherTrusted) signals += "trusted-publisher ";
        else if (inputs.publisherSigned) signals += "signed ";
        if (inputs.reputationScore.has_value())
            signals += "rep=" + FormatTrust(inputs.reputationScore.value()) + " ";
        if (inputs.staticBenignConfidence.has_value())
            signals += "static=" + FormatTrust(inputs.staticBenignConfidence.value()) + " ";
        if (inputs.riskSignalsFromACM) {
            char buf[20]{};
            std::snprintf(buf, sizeof(buf), "acm-risk=0x%08X",
                          inputs.riskSignalsFromACM);
            signals += buf;
        }
        if (signals.empty()) signals = "no signals";
    }

    if (trust >= upperEdge) {
        const std::string reason = "allow: trust=" + FormatTrust(trust)
                                   + " >= threshold+band (" + signals + ")";
        return DecisionResult{
            .verdict       = Verdict::Allow,
            .computedTrust = trust,
            .threshold     = effectiveThreshold,
            .reason        = reason,
        };
    }

    if (trust < lowerEdge) {
        const std::string reason = "block: trust=" + FormatTrust(trust)
                                   + " < threshold-band (" + signals + ")";
        const std::wstring safePath = TruncateW(inputs.imagePath, 128);
        const std::string  safeSha  = SanitizeShaForLog(inputs.sha256);
        SS_LOG_WARN(kLogCategory,
            L"ZeroTrustGuard: BLOCK image='%.128ls' sha=%.16hs "
            L"trust=%.3f threshold=%.3f reason=%hs",
            safePath.c_str(),
            safeSha.c_str(),
            trust, effectiveThreshold, reason.c_str());
        return DecisionResult{
            .verdict       = Verdict::Block,
            .computedTrust = trust,
            .threshold     = effectiveThreshold,
            .reason        = reason,
        };
    }

    // ------------------------------------------------------------------
    // 7. Uncertain: apply UncertainBehavior policy.
    // ------------------------------------------------------------------
    const std::string uncertainReason = "uncertain: trust=" + FormatTrust(trust)
                                        + " in band [" + FormatTrust(lowerEdge)
                                        + "," + FormatTrust(upperEdge)
                                        + "] (" + signals + ")";

    switch (cfg.uncertainBehavior) {
        case UncertainBehavior::SilentAllow:
            return DecisionResult{
                .verdict       = Verdict::Allow,
                .computedTrust = trust,
                .threshold     = effectiveThreshold,
                .reason        = "uncertain, silent-allow policy",
            };

        case UncertainBehavior::SilentBlock: {
            const std::wstring safePath = TruncateW(inputs.imagePath, 128);
            const std::string  safeSha  = SanitizeShaForLog(inputs.sha256);
            SS_LOG_WARN(kLogCategory,
                L"ZeroTrustGuard: BLOCK (silent) image='%.128ls' sha=%.16hs "
                L"trust=%.3f threshold=%.3f reason=uncertain",
                safePath.c_str(),
                safeSha.c_str(),
                trust, effectiveThreshold);
            return DecisionResult{
                .verdict       = Verdict::Block,
                .computedTrust = trust,
                .threshold     = effectiveThreshold,
                .reason        = "uncertain, silent-block policy",
            };
        }

        case UncertainBehavior::Prompt: {
            PromptEntry entry;
            entry.createdAt    = std::chrono::system_clock::now();
            entry.imagePath    = inputs.imagePath;
            entry.sha256       = inputs.sha256;
            entry.publisher    = inputs.publisherSubject;
            entry.computedTrust = trust;
            entry.reason       = uncertainReason;

            const std::uint64_t promptId =
                ZeroTrustPromptQueue::Instance().Enqueue(std::move(entry));

            SS_LOG_INFO(kLogCategory,
                L"ZeroTrustGuard: Uncertain — prompt enqueued id=%llu "
                L"trust=%.3f threshold=%.3f",
                static_cast<unsigned long long>(promptId),
                trust, effectiveThreshold);

            return DecisionResult{
                .verdict        = Verdict::Uncertain,
                .computedTrust  = trust,
                .threshold      = effectiveThreshold,
                .reason         = uncertainReason,
                .promptEnqueued = true,
                .promptId       = promptId,
            };
        }

        default:
            // Defensive fail-safe: an out-of-range UncertainBehavior must
            // never produce a permissive verdict on a zero-trust path.
            SS_LOG_WARN(kLogCategory,
                L"ZeroTrustGuard: invalid UncertainBehavior=%u — failing safe (Block)",
                static_cast<unsigned>(cfg.uncertainBehavior));
            return DecisionResult{
                .verdict       = Verdict::Block,
                .computedTrust = trust,
                .threshold     = effectiveThreshold,
                .reason        = "uncertain, invalid policy → fail-safe block",
            };
    }
}

// ============================================================================
// CONFIG SURFACE
// ============================================================================

ZeroTrustConfigSnapshot ZeroTrustGuard::GetConfig() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config;
}

bool ZeroTrustGuard::SetConfig(const ZeroTrustConfigSnapshot& next) {
    // Validate every bounded field before locking. ZeroTrustGuard is a hard
    // security boundary — silently clamping invalid policy in-place would
    // mask configuration bugs and weaken the audit trail.
    auto inUnit = [](double v) noexcept {
        return std::isfinite(v) && v >= 0.0 && v <= 1.0;
    };

    if (!inUnit(next.threshold)) {
        SS_LOG_WARN(kLogCategory,
            L"ZeroTrustGuard: SetConfig() rejected — threshold %.3f out of [0,1]",
            next.threshold);
        return false;
    }
    if (!inUnit(next.minReputation)) {
        SS_LOG_WARN(kLogCategory,
            L"ZeroTrustGuard: SetConfig() rejected — minReputation %.3f out of [0,1]",
            next.minReputation);
        return false;
    }
    if (!inUnit(next.minStaticBenign)) {
        SS_LOG_WARN(kLogCategory,
            L"ZeroTrustGuard: SetConfig() rejected — minStaticBenign %.3f out of [0,1]",
            next.minStaticBenign);
        return false;
    }
    const auto behaviorInt = static_cast<std::uint8_t>(next.uncertainBehavior);
    if (behaviorInt > static_cast<std::uint8_t>(UncertainBehavior::Prompt)) {
        SS_LOG_WARN(kLogCategory,
            L"ZeroTrustGuard: SetConfig() rejected — UncertainBehavior=%u invalid",
            static_cast<unsigned>(behaviorInt));
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_config = next;
    lock.unlock();

    SS_LOG_INFO(kLogCategory,
        L"ZeroTrustGuard: Config updated threshold=%.3f ztMode=%hs behavior=%u",
        next.threshold,
        next.zeroTrustMode ? "true" : "false",
        static_cast<unsigned>(behaviorInt));

    if (::ShadowStrike::Config::ConfigManager::HasInstance()) {
        if (!PersistConfigToManager(next)) {
            SS_LOG_WARN(kLogCategory,
                L"ZeroTrustGuard: SetConfig() — one or more ConfigManager writes failed");
            // Non-fatal: in-memory snapshot was updated.
        }
    }

    return true;
}

// ============================================================================
// UNIT-TEST HELPERS
// ============================================================================
#ifdef SHADOWSTRIKE_UNIT_TEST
namespace ShadowStrike::PhantomCore::RealTime::ZeroTrust {

double ZeroTrustGuard_BlendedTrust_ForTest(const DecisionInputs& inputs) {
    return ComputeBlendedTrust(inputs);
}

double ZeroTrustGuard_RiskFromAcm_ForTest(std::uint32_t bitmask) {
    return RiskFromAcmBitmask(bitmask);
}

} // namespace
#endif

} // namespace ShadowStrike::PhantomCore::RealTime::ZeroTrust
