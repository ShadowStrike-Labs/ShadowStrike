/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file ZeroTrustGuard.cpp
 * @brief PhantomHome adapter implementation for the PhantomCore ZeroTrustGuard.
 *
 * See ZeroTrustGuard.hpp for the full design rationale.
 *
 * CONFIG KEYS  (under "Home/ZeroTrust/"):
 *   Enabled                bool    default true
 *   Threshold              double  default 0.70
 *   UncertainBand          double  default 0.05
 *   ZeroTrustMode          bool    default false
 *   UncertainBehavior      int32   default 2 (Prompt)
 *   RequirePublisherSigned bool    default false
 *   RequireWhitelist       bool    default false
 *   MinReputation          double  default 0.0
 *   MinStaticBenign        double  default 0.0
 */

#include "ZeroTrustGuard.hpp"
#include "ZeroTrustPromptQueue.hpp"

#include "../../../../PhantomCore/Config/ConfigManager.hpp"
#include "../../../../PhantomCore/Utils/Logger.hpp"
#include "../../../../PhantomCore/RealTime/ZeroTrust/ZeroTrustGuard.hpp"
#include "../../../../PhantomCore/RealTime/ZeroTrust/ZeroTrustPromptQueue.hpp"
#include "../ModeThresholds.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <mutex>
#include <shared_mutex>
#include <string>

namespace ShadowStrike::Products::Home::ZeroTrust {

namespace {

constexpr const wchar_t* kLogCategory = L"ZeroTrustGuard.Home";

// Config key constants (all under "Home/ZeroTrust/").
constexpr const char* kKeyEnabled                = "Home/ZeroTrust/Enabled";
constexpr const char* kKeyThreshold              = "Home/ZeroTrust/Threshold";
constexpr const char* kKeyUncertainBand          = "Home/ZeroTrust/UncertainBand";
constexpr const char* kKeyZeroTrustMode          = "Home/ZeroTrust/ZeroTrustMode";
constexpr const char* kKeyUncertainBehavior      = "Home/ZeroTrust/UncertainBehavior";
constexpr const char* kKeyRequirePublisherSigned = "Home/ZeroTrust/RequirePublisherSigned";
constexpr const char* kKeyRequireWhitelist       = "Home/ZeroTrust/RequireWhitelist";
constexpr const char* kKeyMinReputation          = "Home/ZeroTrust/MinReputation";
constexpr const char* kKeyMinStaticBenign        = "Home/ZeroTrust/MinStaticBenign";

// Threshold constants per ProtectionMode.
// Off → threshold 1.01 so scores can never reach it; uncertain → SilentAllow.
constexpr double kThresholdOff        = 1.01;
constexpr double kThresholdPassive    = 0.40;
constexpr double kThresholdBalanced   = 0.70;
constexpr double kThresholdAggressive = 0.85;
constexpr double kZeroTrustThreshold  = 0.999;

/// @brief Clamp a double to [0.0, 1.0].
[[nodiscard]] inline double Clamp01(double v) noexcept {
    return (v < 0.0) ? 0.0 : (v > 1.0) ? 1.0 : v;
}

// ============================================================================
// CONFIG PERSISTENCE HELPERS
// ============================================================================

[[nodiscard]] ZeroTrustConfig LoadConfigFromManager() {
    auto& cfg = ::ShadowStrike::Config::ConfigManager::Instance();

    ZeroTrustConfig snap;
    snap.threshold          = Clamp01(cfg.GetValue<double>(kKeyThreshold, 0.70));
    snap.uncertainBand      = Clamp01(cfg.GetValue<double>(kKeyUncertainBand, 0.05));
    snap.zeroTrustMode      = cfg.GetValue<bool>(kKeyZeroTrustMode, false);
    snap.requirePublisherSigned = cfg.GetValue<bool>(kKeyRequirePublisherSigned, false);
    snap.requireWhitelist       = cfg.GetValue<bool>(kKeyRequireWhitelist, false);
    snap.minReputation      = Clamp01(cfg.GetValue<double>(kKeyMinReputation, 0.0));
    snap.minStaticBenign    = Clamp01(cfg.GetValue<double>(kKeyMinStaticBenign, 0.0));

    const auto behaviorInt = cfg.GetValue<int32_t>(kKeyUncertainBehavior, 2);
    if (behaviorInt >= 0 && behaviorInt <= 2) {
        snap.uncertainBehavior = static_cast<ZeroTrustUncertainBehavior>(behaviorInt);
    } else {
        snap.uncertainBehavior = ZeroTrustUncertainBehavior::Prompt;
    }

    return snap;
}

[[nodiscard]] bool PersistConfigToManager(const ZeroTrustConfig& c) {
    auto& cfg = ::ShadowStrike::Config::ConfigManager::Instance();
    using Layer = ::ShadowStrike::Config::ConfigLayer;

    bool ok = true;
    ok &= cfg.SetValue<double> (kKeyThreshold,              c.threshold,              Layer::User);
    ok &= cfg.SetValue<double> (kKeyUncertainBand,          c.uncertainBand,          Layer::User);
    ok &= cfg.SetValue<bool>   (kKeyZeroTrustMode,          c.zeroTrustMode,          Layer::User);
    ok &= cfg.SetValue<int32_t>(kKeyUncertainBehavior,      static_cast<int32_t>(c.uncertainBehavior), Layer::User);
    ok &= cfg.SetValue<bool>   (kKeyRequirePublisherSigned, c.requirePublisherSigned, Layer::User);
    ok &= cfg.SetValue<bool>   (kKeyRequireWhitelist,       c.requireWhitelist,       Layer::User);
    ok &= cfg.SetValue<double> (kKeyMinReputation,          c.minReputation,          Layer::User);
    ok &= cfg.SetValue<double> (kKeyMinStaticBenign,        c.minStaticBenign,        Layer::User);
    return ok;
}

// ============================================================================
// CONVERSION HELPERS — PhantomHome ↔ PhantomCore types
// ============================================================================

/**
 * @brief Convert a narrow string publisher subject to wide string for the
 *        PhantomHome prompt item.
 */
[[nodiscard]] std::wstring NarrowToWide(std::string_view s) {
    if (s.empty()) return {};
    const int needed = ::MultiByteToWideChar(CP_UTF8, 0,
                                             s.data(), static_cast<int>(s.size()),
                                             nullptr, 0);
    if (needed <= 0) return {};
    std::wstring out(static_cast<std::size_t>(needed), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                          out.data(), needed);
    return out;
}

/**
 * @brief Convert a wide-string publisher subject to narrow UTF-8 for
 *        the PhantomCore DecisionInputs::publisherSubject field.
 */
[[nodiscard]] std::string WideToNarrow(std::wstring_view ws) {
    if (ws.empty()) return {};
    const int needed = ::WideCharToMultiByte(CP_UTF8, 0,
                                             ws.data(), static_cast<int>(ws.size()),
                                             nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(static_cast<std::size_t>(needed), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()),
                          out.data(), needed, nullptr, nullptr);
    return out;
}

/**
 * @brief Map PhantomHome UncertainBehavior to the PhantomCore equivalent.
 */
[[nodiscard]]
::ShadowStrike::PhantomCore::RealTime::ZeroTrust::UncertainBehavior
ToCoreUncertainBehavior(ZeroTrustUncertainBehavior b) noexcept {
    using Core = ::ShadowStrike::PhantomCore::RealTime::ZeroTrust::UncertainBehavior;
    switch (b) {
        case ZeroTrustUncertainBehavior::SilentAllow: return Core::SilentAllow;
        case ZeroTrustUncertainBehavior::SilentBlock: return Core::SilentBlock;
        case ZeroTrustUncertainBehavior::Prompt:      return Core::Prompt;
    }
    return Core::Prompt;
}

/**
 * @brief Map PhantomCore UncertainBehavior to the PhantomHome equivalent.
 */
[[nodiscard]] ZeroTrustUncertainBehavior
FromCoreUncertainBehavior(
    ::ShadowStrike::PhantomCore::RealTime::ZeroTrust::UncertainBehavior b) noexcept
{
    using Core = ::ShadowStrike::PhantomCore::RealTime::ZeroTrust::UncertainBehavior;
    switch (b) {
        case Core::SilentAllow: return ZeroTrustUncertainBehavior::SilentAllow;
        case Core::SilentBlock: return ZeroTrustUncertainBehavior::SilentBlock;
        case Core::Prompt:      return ZeroTrustUncertainBehavior::Prompt;
    }
    return ZeroTrustUncertainBehavior::Prompt;
}

/**
 * @brief Translate the ZeroTrustConfig into the PhantomCore snapshot and sync
 *        the core engine.
 */
void SyncCoreEngine(const ZeroTrustConfig& cfg) {
    using CoreSnap = ::ShadowStrike::PhantomCore::RealTime::ZeroTrust::ZeroTrustConfigSnapshot;
    using CoreGuard = ::ShadowStrike::PhantomCore::RealTime::ZeroTrust::ZeroTrustGuard;

    CoreSnap snap;
    snap.threshold             = cfg.zeroTrustMode ? kZeroTrustThreshold : cfg.threshold;
    snap.zeroTrustMode         = cfg.zeroTrustMode;
    snap.uncertainBehavior     = ToCoreUncertainBehavior(cfg.uncertainBehavior);
    snap.requirePublisherSigned = cfg.requirePublisherSigned || cfg.zeroTrustMode;
    snap.requireWhitelist      = cfg.requireWhitelist || cfg.zeroTrustMode;
    snap.minReputation         = cfg.zeroTrustMode ? kZeroTrustThreshold : cfg.minReputation;
    snap.minStaticBenign       = cfg.zeroTrustMode ? kZeroTrustThreshold : cfg.minStaticBenign;

    if (!CoreGuard::Instance().SetConfig(snap)) {
        SS_LOG_WARN(kLogCategory,
            L"ZeroTrustGuard.Home: SyncCoreEngine() — core SetConfig() rejected snapshot; "
            L"threshold=%.3f, ztMode=%hs",
            snap.threshold, snap.zeroTrustMode ? "true" : "false");
    }
}

} // anonymous namespace

// ============================================================================
// PIMPL
// ============================================================================

struct ZeroTrustGuard::Impl {
    mutable std::shared_mutex    m_mutex;
    ZeroTrustConfig              m_config;
    ::ShadowStrike::Products::Home::ProtectionMode m_mode{
        ::ShadowStrike::Products::Home::ProtectionMode::Off};
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
    Shutdown();
}

// ============================================================================
// LIFECYCLE
// ============================================================================

bool ZeroTrustGuard::Initialize() {
    if (m_impl->m_initialized.load(std::memory_order_acquire)) {
        return true;
    }

    SS_LOG_INFO(kLogCategory, L"ZeroTrustGuard.Home: Initializing");

    // Initialize the PhantomCore engine first.
    if (!::ShadowStrike::PhantomCore::RealTime::ZeroTrust::ZeroTrustGuard::Instance()
            .Initialize()) {
        SS_LOG_ERROR(kLogCategory,
            L"ZeroTrustGuard.Home: PhantomCore ZeroTrustGuard::Initialize() failed");
        return false;
    }

    // Load persisted config.
    {
        std::unique_lock lock(m_impl->m_mutex);
        if (::ShadowStrike::Config::ConfigManager::HasInstance()) {
            m_impl->m_config = LoadConfigFromManager();
        }
        // else keep safe defaults
    }

    // Sync the loaded config to the core engine.
    {
        std::shared_lock lock(m_impl->m_mutex);
        SyncCoreEngine(m_impl->m_config);
    }

    // Load persisted always-allow entries into the prompt queue.
    ZeroTrustPromptQueue::Instance().LoadPersistedAllowList();

    m_impl->m_initialized.store(true, std::memory_order_release);

    SS_LOG_INFO(kLogCategory,
        L"ZeroTrustGuard.Home: Initialized (threshold=%.3f, ztMode=%hs, "
        L"behavior=%hhu)",
        m_impl->m_config.threshold,
        m_impl->m_config.zeroTrustMode ? "true" : "false",
        static_cast<std::uint8_t>(m_impl->m_config.uncertainBehavior));

    return true;
}

bool ZeroTrustGuard::Start() {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(kLogCategory,
            L"ZeroTrustGuard.Home: Start() called before Initialize()");
        return false;
    }

    if (!::ShadowStrike::PhantomCore::RealTime::ZeroTrust::ZeroTrustGuard::Instance()
            .Start()) {
        SS_LOG_ERROR(kLogCategory,
            L"ZeroTrustGuard.Home: PhantomCore ZeroTrustGuard::Start() failed");
        return false;
    }

    m_impl->m_running.store(true, std::memory_order_release);
    SS_LOG_INFO(kLogCategory, L"ZeroTrustGuard.Home: Running");
    return true;
}

void ZeroTrustGuard::Shutdown() {
    if (!m_impl->m_running.exchange(false, std::memory_order_acq_rel)
        && !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    ZeroTrustPromptQueue::Instance().Stop();

    ::ShadowStrike::PhantomCore::RealTime::ZeroTrust::ZeroTrustGuard::Instance()
        .Shutdown();

    m_impl->m_initialized.store(false, std::memory_order_release);

    SS_LOG_INFO(kLogCategory, L"ZeroTrustGuard.Home: Shut down");
}

// ============================================================================
// CONFIGURATION
// ============================================================================

void ZeroTrustGuard::SetConfig(const ZeroTrustConfig& c) {
    // Validate before acquiring the lock.
    if (c.threshold < 0.0 || c.threshold > 1.0) {
        SS_LOG_WARN(kLogCategory,
            L"ZeroTrustGuard.Home: SetConfig() rejected — threshold %.3f out of [0,1]",
            c.threshold);
        return;
    }
    if (c.uncertainBand < 0.0 || c.uncertainBand > 0.5) {
        SS_LOG_WARN(kLogCategory,
            L"ZeroTrustGuard.Home: SetConfig() rejected — uncertainBand %.3f out of [0,0.5]",
            c.uncertainBand);
        return;
    }

    {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_config = c;
    }

    // Sync core engine without the lock held.
    SyncCoreEngine(c);

    if (::ShadowStrike::Config::ConfigManager::HasInstance()) {
        if (!PersistConfigToManager(c)) {
            SS_LOG_WARN(kLogCategory,
                L"ZeroTrustGuard.Home: SetConfig() — one or more ConfigManager writes failed");
        }
    }

    SS_LOG_INFO(kLogCategory,
        L"ZeroTrustGuard.Home: Config updated threshold=%.3f band=%.3f "
        L"ztMode=%hs behavior=%hhu",
        c.threshold, c.uncertainBand,
        c.zeroTrustMode ? "true" : "false",
        static_cast<std::uint8_t>(c.uncertainBehavior));
}

ZeroTrustConfig ZeroTrustGuard::GetConfig() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config;
}

// ============================================================================
// MODE INTEGRATION
// ============================================================================

void ZeroTrustGuard::SetMode(::ShadowStrike::Products::Home::ProtectionMode m) {
    using ::ShadowStrike::Products::Home::ProtectionMode;

    SS_LOG_INFO(kLogCategory,
        L"ZeroTrustGuard.Home: SetMode -> %hs",
        std::string(::ShadowStrike::Products::Home::HomeProductOrchestrator::ToString(m)).c_str());

    // Tell the PhantomCore engine; this also writes ModeThresholds to ConfigManager.
    if (!::ShadowStrike::PhantomCore::RealTime::ZeroTrust::ZeroTrustGuard::Instance()
            .ApplyMode(static_cast<std::uint8_t>(m))) {
        SS_LOG_WARN(kLogCategory,
            L"ZeroTrustGuard.Home: PhantomCore::ApplyMode(%hhu) failed; "
            L"in-memory snapshot will still be updated",
            static_cast<std::uint8_t>(m));
    }

    // Now update our own snapshot to stay in sync.
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_mode = m;

    switch (m) {
        case ProtectionMode::Off:
            m_impl->m_config.threshold         = kThresholdOff;
            m_impl->m_config.uncertainBehavior = ZeroTrustUncertainBehavior::SilentAllow;
            break;
        case ProtectionMode::Passive:
            m_impl->m_config.threshold         = kThresholdPassive;
            m_impl->m_config.uncertainBehavior = ZeroTrustUncertainBehavior::SilentAllow;
            break;
        case ProtectionMode::Balanced:
            m_impl->m_config.threshold         = kThresholdBalanced;
            m_impl->m_config.uncertainBehavior = ZeroTrustUncertainBehavior::Prompt;
            break;
        case ProtectionMode::Aggressive:
            m_impl->m_config.threshold         = kThresholdAggressive;
            m_impl->m_config.uncertainBehavior = ZeroTrustUncertainBehavior::SilentBlock;
            break;
    }
}

ProtectionMode ZeroTrustGuard::Mode() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_mode;
}

// ============================================================================
// HOT-PATH EVALUATE
// ============================================================================

ZeroTrustDecision ZeroTrustGuard::Evaluate(const ZeroTrustInputs& in,
                                            double* outScore) const
{
    using CoreGuard  = ::ShadowStrike::PhantomCore::RealTime::ZeroTrust::ZeroTrustGuard;
    using CoreInputs = ::ShadowStrike::PhantomCore::RealTime::ZeroTrust::DecisionInputs;
    using Verdict    = ::ShadowStrike::PhantomCore::RealTime::ZeroTrust::Verdict;

    // ------------------------------------------------------------------
    // 1. Always-allow / always-deny fast-path (no scoring required).
    //    These are populated via UI resolution (AlwaysAllow/AlwaysBlock).
    // ------------------------------------------------------------------
    auto& promptQueue = ZeroTrustPromptQueue::Instance();

    if (promptQueue.IsAlwaysAllowed(in.imagePath, in.publisherSubject)) {
        if (outScore) *outScore = 1.0;
        return ZeroTrustDecision::Allow;
    }
    if (promptQueue.IsAlwaysDenied(in.imagePath)) {
        if (outScore) *outScore = 0.0;
        return ZeroTrustDecision::Block;
    }

    // ------------------------------------------------------------------
    // 2. Build PhantomCore DecisionInputs from PhantomHome ZeroTrustInputs.
    //    wstring_view fields are converted by value; the core engine does
    //    not hold the view beyond the Decide() call so ownership is safe.
    // ------------------------------------------------------------------
    CoreInputs coreIn;
    coreIn.imagePath            = std::wstring(in.imagePath);
    coreIn.publisherSubject     = WideToNarrow(in.publisherSubject);
    coreIn.publisherSigned      = in.publisherSigned;
    coreIn.publisherTrusted     = in.publisherTrusted;
    coreIn.reputationScore      = in.reputation;
    coreIn.staticBenignConfidence = in.staticBenign;

    // ACM risk: the PhantomCore field is uint32_t; we widen the optional uint8_t.
    // Absent acmRisk → riskSignalsFromACM = 0 (zero risk, per task spec).
    coreIn.riskSignalsFromACM   = in.acmRisk.has_value()
                                    ? static_cast<std::uint32_t>(in.acmRisk.value())
                                    : 0u;

    // Fields not represented in ZeroTrustInputs default safely.
    coreIn.hashInCleanStore     = false;
    coreIn.hashInMalwareStore   = false;
    coreIn.publisherWhitelisted = false;
    coreIn.parentPid            = 0;

    // ------------------------------------------------------------------
    // 3. Delegate to the PhantomCore engine.
    // ------------------------------------------------------------------
    const auto result = CoreGuard::Instance().Decide(coreIn);

    if (outScore) {
        *outScore = result.computedTrust;
    }

    // ------------------------------------------------------------------
    // 4. Map Verdict back to ZeroTrustDecision.
    // ------------------------------------------------------------------
    switch (result.verdict) {
        case Verdict::Allow:
            return ZeroTrustDecision::Allow;

        case Verdict::Block:
            return ZeroTrustDecision::Block;

        case Verdict::Uncertain: {
            // The PhantomCore engine already applied UncertainBehavior
            // (SilentAllow / SilentBlock were collapsed to Allow/Block above).
            // If we reach here, the behavior is Prompt — enqueue to the
            // PhantomHome-facing UI queue.
            ZeroTrustPromptItem item;
            item.imagePath        = std::wstring(in.imagePath);
            item.publisherSubject = std::wstring(in.publisherSubject);
            item.processSessionId = in.processSessionId;
            item.score            = result.computedTrust;
            item.createdAt        = std::chrono::system_clock::now();

            const std::uint64_t promptId =
                promptQueue.Enqueue(std::move(item));

            if (promptId == 0) {
                // Queue is full even after eviction; treat as SilentBlock to
                // avoid allowing unknown execution without a prompt.
                SS_LOG_WARN(kLogCategory,
                    L"ZeroTrustGuard.Home: PromptQueue full — "
                    L"falling back to Block for '%.128ls'",
                    std::wstring(in.imagePath).c_str());
                return ZeroTrustDecision::Block;
            }

            return ZeroTrustDecision::Uncertain;
        }
    }

    // Unreachable with a valid Verdict enum.
    return ZeroTrustDecision::Block;
}

} // namespace ShadowStrike::Products::Home::ZeroTrust
