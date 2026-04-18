/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomHome - PRODUCT ORCHESTRATOR
 * ============================================================================
 *
 * @file HomeProductOrchestrator.hpp
 * @brief Single entry point that initializes, starts, and shuts down every
 *        PhantomHome subsystem (Email, Banking, Backup, CryptoMiners, GameMode,
 *        IoT, Privacy, USB, WebProtection) on top of the PhantomCore engine.
 *
 * Role in the architecture:
 *   PhantomCore is the shared detection engine (EDR, XDR, Home). It exposes a
 *   single extension point - ShadowStrike::Service::ProductExtensions - into
 *   which exactly one product orchestrator may register its lifecycle hooks.
 *   The HomeProductEntry translation unit performs that registration via a
 *   static initializer. When AntivirusService::Initialize() fires the hook,
 *   control reaches HomeProductOrchestrator::Initialize() + Start().
 *
 * Design requirements:
 *   - No #ifdef gating inside PhantomCore. All product logic lives here.
 *   - Each subsystem is independent: failure of one must not block the others.
 *   - Each subsystem is gated by a ConfigManager key (Home/<Feature>/Enabled).
 *     If the user disables a subsystem, we never call its Initialize().
 *   - Deterministic startup order: shared prerequisites (config defaults,
 *     profile presets, policy) first, background-thread modules last.
 *   - Shutdown in exact reverse order, RAII-safe, idempotent.
 *   - Thread-safe: Initialize / Start / Shutdown are mutually exclusive.
 *
 * Module registration is performed by small "wiring-home-<feature>" .cpp
 * files (one per folder) that call HomeProductOrchestrator::RegisterModule()
 * from a local static initializer. This keeps Phase B work trivially
 * parallelizable across folders without merge conflicts on this file.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike {
namespace Products {
namespace Home {

/// @brief Per-module lifecycle state.
enum class ModuleState : uint8_t {
    Unregistered = 0,  ///< Never registered.
    Registered   = 1,  ///< Registered but Initialize() not yet called.
    Disabled     = 2,  ///< Registered but config key evaluates false.
    Initialized  = 3,  ///< Initialize() succeeded; Start() not yet called.
    Running      = 4,  ///< Start() succeeded.
    Failed       = 5,  ///< Initialize() or Start() threw or returned false.
    Stopped      = 6,  ///< Shutdown() completed.
};

/// @brief Phase ordering controls the startup sequence within the orchestrator.
///        Phases are executed in numerical order; modules within a phase are
///        initialized in registration order. This is how we model dependencies
///        (e.g. Banking wants Web and USB alerts first).
enum class ModulePhase : uint8_t {
    Foundation      = 0,  ///< Config defaults, profile presets, policy.
    CoreProtections = 1,  ///< Real-time file/process/URL protections.
    OnDemand        = 2,  ///< Privacy cleaners, IoT scanners (scheduled).
    UserExperience  = 3,  ///< GameMode, performance optimizer, overlays.
    Background      = 4,  ///< BackupManager snapshot-on-threat.
};

/// @brief Descriptor supplied by each subsystem at registration time.
struct ModuleDescriptor {
    /// Human-readable module name, used in logs and status queries. E.g.
    /// "EmailProtection", "BankingTrojanDetector". Must be unique.
    std::string name;

    /// ConfigManager key (e.g. "Home/Email/Enabled"). Empty string means
    /// "always enabled" (used by Config/Policy bootstrap modules).
    std::string enabledConfigKey;

    /// Ordering bucket. See ModulePhase.
    ModulePhase phase{ModulePhase::CoreProtections};

    /// Must not throw. Returns true on success.
    /// Contract: bring the subsystem to an initialized-but-not-yet-running
    /// state; do not spawn long-running threads here.
    std::function<bool()> initialize;

    /// Must not throw. Returns true on success.
    /// Contract: spawn background threads, register RealTimeProtection
    /// callbacks, begin accepting events.
    std::function<bool()> start;

    /// Must not throw. Contract: quiesce threads, unregister callbacks,
    /// release OS handles. Called in reverse phase order during teardown.
    std::function<void()> shutdown;
};

/// @brief Runtime status snapshot for diagnostics / IPC /status endpoint.
struct ModuleStatus {
    std::string name;
    ModulePhase phase{ModulePhase::CoreProtections};
    ModuleState state{ModuleState::Unregistered};
    std::string lastError;  ///< Populated when state == Failed.
    std::chrono::steady_clock::time_point lastTransition{};
};

/**
 * @class HomeProductOrchestrator
 * @brief Meyers' singleton that owns the PhantomHome lifecycle.
 *
 * Typical call chain at service start:
 *
 *   AntivirusService::Initialize()
 *     -> ProductExtensions::InitializeProduct()
 *       -> HomeProductOrchestrator::Initialize()    // phase 0..N Initialize
 *       -> HomeProductOrchestrator::Start()         // phase 0..N Start
 */
class HomeProductOrchestrator final {
public:
    [[nodiscard]] static HomeProductOrchestrator& Instance() noexcept;

    /**
     * @brief Register a subsystem. Thread-safe. Safe to call from static init.
     *
     * Contract:
     *   - Module name must be unique; duplicates are rejected with a fatal log.
     *   - All three callbacks must be non-null.
     *   - May be called before OR after Initialize(); late registrations that
     *     arrive after Initialize() has already run are kept in Registered
     *     state and will be initialized if Initialize() is called again.
     *
     * @return true on success, false if rejected.
     */
    bool RegisterModule(ModuleDescriptor descriptor) noexcept;

    /**
     * @brief Initialize every registered module whose config gate is enabled.
     *
     * Ordering:
     *   1. Iterate modules in phase order; Foundation modules first.
     *   2. For each module:
     *        - read the enabled config key (default true if missing)
     *        - if enabled, invoke initialize() in try/catch
     *        - update state to Initialized or Failed
     *
     * Config defaults and profile presets are registered by the HomeConfig
     * Foundation-phase module (ConfigWiring.cpp), guaranteeing all keys
     * exist before any feature module reads them.
     *
     * Returns true iff every ENABLED module initialized successfully. A single
     * module failure does not abort the pass - we always attempt every
     * enabled module so one broken subsystem doesn't hide others' issues.
     *
     * Sets IsInitialized() to true only if at least one module succeeded.
     */
    [[nodiscard]] bool Initialize() noexcept;

    /**
     * @brief Start every module that is currently in Initialized state.
     *
     * Same iteration order and failure-isolation semantics as Initialize().
     */
    [[nodiscard]] bool Start() noexcept;

    /**
     * @brief Shutdown every module in reverse phase order.
     *
     * Idempotent. Safe to call from destructors and from Windows service
     * SCM callbacks.
     */
    void Shutdown() noexcept;

    /// @brief Whether Initialize() has been called and at least one module is Initialized/Running.
    [[nodiscard]] bool IsInitialized() const noexcept;

    /// @brief Whether Start() has been called and at least one module is Running.
    [[nodiscard]] bool IsRunning() const noexcept;

    /// @brief Snapshot of every registered module's status, for diagnostics.
    [[nodiscard]] std::vector<ModuleStatus> GetStatus() const;

    /// @brief Retrieve status for a single named module, or nullopt if unknown.
    [[nodiscard]] std::optional<ModuleStatus> GetModuleStatus(std::string_view name) const;

    HomeProductOrchestrator(const HomeProductOrchestrator&) = delete;
    HomeProductOrchestrator& operator=(const HomeProductOrchestrator&) = delete;
    HomeProductOrchestrator(HomeProductOrchestrator&&) = delete;
    HomeProductOrchestrator& operator=(HomeProductOrchestrator&&) = delete;

private:
    HomeProductOrchestrator();
    ~HomeProductOrchestrator();

    struct ModuleRecord {
        ModuleDescriptor descriptor;
        ModuleState state{ModuleState::Registered};
        std::string lastError;
        std::chrono::steady_clock::time_point lastTransition{};
    };

    // Lifecycle helpers - called under m_lifecycleMutex.
    [[nodiscard]] bool InitializeLocked() noexcept;
    [[nodiscard]] bool StartLocked() noexcept;
    void ShutdownLocked() noexcept;

    [[nodiscard]] bool IsModuleEnabled(const ModuleDescriptor& desc) const noexcept;
    void SetModuleState(ModuleRecord& rec, ModuleState state, std::string_view err = {}) noexcept;

    // m_registryMutex protects m_modules during registration.
    mutable std::shared_mutex m_registryMutex;
    std::vector<ModuleRecord> m_modules;

    // m_lifecycleMutex serializes Initialize/Start/Shutdown against each other.
    mutable std::mutex m_lifecycleMutex;

    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_running{false};
};

}  // namespace Home
}  // namespace Products
}  // namespace ShadowStrike
