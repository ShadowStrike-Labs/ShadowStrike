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

/// @brief Per-module protection intensity level.
///
/// Determines how aggressively a subsystem monitors and blocks threats.
/// Ordered from least to most aggressive; cast to uint8_t gives a stable
/// numeric representation suitable for ConfigManager persistence.
enum class ProtectionMode : std::uint8_t {
    Off        = 0,  ///< Module disabled; no detection activity.
    Passive    = 1,  ///< Detect-only; no blocking; lowest CPU overhead.
    Balanced   = 2,  ///< Block on suspicion at moderate sensitivity (default).
    Aggressive = 3,  ///< Maximum sensitivity; block at low confidence threshold.
};

/// @brief Returns the bitmask bit for a given ProtectionMode.
///
/// Bit i is set when mode i is in the mask. Combined masks declare which
/// modes a ModuleDescriptor supports.
/// @example ProtectionModeMask(ProtectionMode::Balanced) == 0b0100 == 4
[[nodiscard]] constexpr std::uint8_t ProtectionModeMask(ProtectionMode m) noexcept {
    return static_cast<std::uint8_t>(1u << static_cast<std::uint8_t>(m));
}

/// @brief Descriptor supplied by each subsystem at registration time.
struct ModuleDescriptor {
    /// Human-readable module name, used in logs and status queries. E.g.
    /// "EmailProtection", "BankingTrojanDetector". Must be unique.
    std::string name;

    /// Optional user-facing label (e.g. "Ransomware protection"). When left
    /// empty the UI/IPC layer will derive a presentable title from `name`
    /// via a CamelCase-to-spaces humanizer. Populate this whenever the
    /// internal code id is ambiguous or not properly title-cased.
    std::string displayName;

    /// Optional UI grouping tag (e.g. "Realtime", "Ransomware", "Web",
    /// "Network", "Privacy", "Exploit", "Script", "USB", "IoT", "Banking",
    /// "Email", "Identity"). When empty, the IPC layer derives a default
    /// bucket from `phase` so UI keeps working for legacy modules that have
    /// not yet been retagged.
    std::string group;

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

    /// Optional: transitions the module to a new active ProtectionMode.
    /// Called only when the module is already Running and mode != Off.
    /// If null, the orchestrator falls back to ApplyModeThresholds().
    /// Must not throw. Return true on success.
    std::function<bool(ProtectionMode)> setMode;

    /// Bitmask of ProtectionMode values this module supports.
    /// Bit i set means ProtectionMode(i) is accepted by SetModuleMode.
    /// Default: Off | Balanced (bits 0 and 2, mask = 0b0101 = 5).
    std::uint8_t supportedModesMask =
        ProtectionModeMask(ProtectionMode::Off) |
        ProtectionModeMask(ProtectionMode::Balanced);
};

/// @brief Runtime status snapshot for diagnostics / IPC /status endpoint.
struct ModuleStatus {
    std::string name;           ///< Stable internal id (e.g. "RansomwareProtection").
    std::string displayName;    ///< Presentable title; falls back to humanized name.
    std::string group;          ///< UI grouping tag; falls back to derived-from-phase.
    ModulePhase phase{ModulePhase::CoreProtections};
    ModuleState state{ModuleState::Unregistered};
    std::string lastError;      ///< Populated when state == Failed.
    std::chrono::steady_clock::time_point lastTransition{};
    ProtectionMode currentMode = ProtectionMode::Off;  ///< Active protection intensity.
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

    /**
     * @brief Enable or disable a named module at runtime.
     *
     * If disabling a Running module: calls its shutdown() callback.
     * If enabling a Disabled/Stopped module: calls initialize() then start().
     * The corresponding ConfigManager key is also updated so the change
     * persists across restarts.
     *
     * @return true if the module was found and the transition succeeded.
     */
    [[nodiscard]] bool SetModuleEnabled(std::string_view name, bool enabled) noexcept;

    /**
     * @brief Transition a named module to the given ProtectionMode.
     *
     * Behavior:
     *   - Mode::Off  → disabled via the existing SetModuleEnabled(false) path;
     *                  setMode() is NOT invoked.
     *   - Any other  → ensures the module is Running (enables if needed),
     *                  then calls descriptor.setMode(mode) if set, otherwise
     *                  falls back to ApplyModeThresholds(name, mode).
     * The new mode is persisted to ConfigManager key "Home/<Name>/Mode".
     * ModuleStatus::currentMode is updated on success.
     *
     * @param name  Stable internal module name (e.g. "BankingTrojanDetector").
     * @param mode  Target protection intensity.
     * @return true on success; false if the module was not found, the mode is
     *         not in its supportedModesMask, or the transition callback failed.
     */
    [[nodiscard]] bool SetModuleMode(std::string_view name, ProtectionMode mode) noexcept;

    /**
     * @brief Return the current ProtectionMode for a named module.
     * @return The active mode, or nullopt if the module does not exist.
     */
    [[nodiscard]] std::optional<ProtectionMode> GetModuleMode(std::string_view name) const;

    /**
     * @brief Convert a ProtectionMode enumerator to its string representation.
     * @return "Off" | "Passive" | "Balanced" | "Aggressive" | "Unknown"
     */
    [[nodiscard]] static constexpr std::string_view ToString(ProtectionMode mode) noexcept {
        switch (mode) {
            case ProtectionMode::Off:        return "Off";
            case ProtectionMode::Passive:    return "Passive";
            case ProtectionMode::Balanced:   return "Balanced";
            case ProtectionMode::Aggressive: return "Aggressive";
        }
        return "Unknown";
    }

    /**
     * @brief Pause all currently Running modules.
     *
     * Calls shutdown() on every Running module and records their names so
     * ResumeAllModules() can re-initialize and re-start them. IsPaused()
     * returns true until ResumeAllModules() is called.
     *
     * Does NOT change the config-gate keys — modules are not "disabled",
     * they are temporarily quiesced.
     */
    void PauseAllModules() noexcept;

    /**
     * @brief Resume modules that were quiesced by PauseAllModules().
     *
     * Re-initializes and re-starts every module that was Running before
     * the last pause. No-op if !IsPaused().
     */
    void ResumeAllModules() noexcept;

    /// @brief Whether protection is currently paused via PauseAllModules().
    [[nodiscard]] bool IsPaused() const noexcept;

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
        ProtectionMode currentMode{ProtectionMode::Off};  ///< Active protection intensity.
    };

    // Lifecycle helpers - called under m_lifecycleMutex.
    [[nodiscard]] bool InitializeLocked() noexcept;
    [[nodiscard]] bool StartLocked() noexcept;
    void ShutdownLocked() noexcept;

    /// @brief Recompute m_initialized / m_running atomics from current module
    ///        states. Caller must hold m_lifecycleMutex; acquires a shared
    ///        lock on m_registryMutex internally. Used after any code path
    ///        that flips one or more module states so the public IsRunning()
    ///        / IsInitialized() queries reflect reality (e.g. disabling the
    ///        last Running module via SetModuleEnabled, PauseAllModules,
    ///        ResumeAllModules, SetModuleMode(Off)).
    void RecomputeRunStateLocked() noexcept;

    /// @brief Reads "Home/<name>/Mode" from ConfigManager and applies it.
    ///        Must be called under m_lifecycleMutex with the module Running.
    ///        No-op if the key is absent or the mode equals the current one.
    void ApplyPersistedModeUnlocked(std::size_t moduleIdx) noexcept;

    [[nodiscard]] bool IsModuleEnabled(const ModuleDescriptor& desc) const noexcept;
    void SetModuleState(ModuleRecord& rec, ModuleState state, std::string_view err = {}) noexcept;

    // m_registryMutex protects m_modules during registration.
    mutable std::shared_mutex m_registryMutex;
    std::vector<ModuleRecord> m_modules;

    // m_lifecycleMutex serializes Initialize/Start/Shutdown against each other.
    mutable std::mutex m_lifecycleMutex;

    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_paused{false};
    std::vector<std::string> m_pausedModuleNames;  // guarded by m_lifecycleMutex
};

/// @brief Force-link every *Wiring.cpp TU. Call at the start of Initialize()
///        to prevent MSVC /OPT:REF + LTCG from stripping registrar globals.
void EnsureAllModulesWired() noexcept;

}  // namespace Home
}  // namespace Products
}  // namespace ShadowStrike
