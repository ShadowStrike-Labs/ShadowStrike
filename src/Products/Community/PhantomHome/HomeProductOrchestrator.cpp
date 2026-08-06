/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file HomeProductOrchestrator.cpp
 * @brief Implementation of the PhantomHome lifecycle orchestrator.
 */

#include "pch.h"

#include "HomeProductOrchestrator.hpp"
#include "ModeThresholds.hpp"

#include "../../../PhantomCore/Config/ConfigManager.hpp"
#include "../../../PhantomCore/Utils/Logger.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <future>
#include <thread>
#include "../../../PhantomCore/Diagnostics/DiagTrace.hpp"

namespace ShadowStrike {
namespace Products {
namespace Home {

namespace {

constexpr const wchar_t* kLogCategory = L"HomeOrchestrator";

constexpr std::array<ModulePhase, 5> kPhaseOrder = {
    ModulePhase::Foundation,
    ModulePhase::CoreProtections,
    ModulePhase::OnDemand,
    ModulePhase::UserExperience,
    ModulePhase::Background,
};

[[nodiscard]] const char* PhaseName(ModulePhase p) noexcept {
    switch (p) {
        case ModulePhase::Foundation:      return "Foundation";
        case ModulePhase::CoreProtections: return "CoreProtections";
        case ModulePhase::OnDemand:        return "OnDemand";
        case ModulePhase::UserExperience:  return "UserExperience";
        case ModulePhase::Background:      return "Background";
    }
    return "Unknown";
}

[[nodiscard]] const char* StateName(ModuleState s) noexcept {
    switch (s) {
        case ModuleState::Unregistered: return "Unregistered";
        case ModuleState::Registered:   return "Registered";
        case ModuleState::Disabled:     return "Disabled";
        case ModuleState::Initialized:  return "Initialized";
        case ModuleState::Running:      return "Running";
        case ModuleState::Failed:       return "Failed";
        case ModuleState::Stopped:      return "Stopped";
    }
    return "Unknown";
}

}  // namespace

HomeProductOrchestrator& HomeProductOrchestrator::Instance() noexcept {
    static HomeProductOrchestrator s_instance;
    return s_instance;
}

HomeProductOrchestrator::HomeProductOrchestrator() = default;

HomeProductOrchestrator::~HomeProductOrchestrator() {
    // Best-effort cleanup if the service crashed before Shutdown() was called.
    try {
        Shutdown();
    } catch (...) {
        // Destructor swallow - logger may be gone by now.
    }
}

bool HomeProductOrchestrator::RegisterModule(ModuleDescriptor descriptor) noexcept {
    if (descriptor.name.empty()) {
        SS_LOG_ERROR(kLogCategory, L"RegisterModule: empty name rejected");
        return false;
    }
    if (!descriptor.initialize || !descriptor.start || !descriptor.shutdown) {
        SS_LOG_ERROR(kLogCategory,
            L"RegisterModule '%hs': null lifecycle callback(s) rejected",
            descriptor.name.c_str());
        return false;
    }

    try {
        std::unique_lock lock(m_registryMutex);

        const auto dup = std::find_if(m_modules.begin(), m_modules.end(),
            [&](const ModuleRecord& r) { return r.descriptor.name == descriptor.name; });
        if (dup != m_modules.end()) {
            SS_LOG_ERROR(kLogCategory,
                L"RegisterModule '%hs': duplicate name rejected",
                descriptor.name.c_str());
            return false;
        }

        ModuleRecord rec;
        rec.descriptor = std::move(descriptor);
        rec.state = ModuleState::Registered;
        rec.lastTransition = std::chrono::steady_clock::now();
        m_modules.push_back(std::move(rec));
    } catch (const std::exception& e) {
        SS_LOG_ERROR(kLogCategory, L"RegisterModule exception: %hs", e.what());
        return false;
    } catch (...) {
        SS_LOG_ERROR(kLogCategory, L"RegisterModule unknown exception");
        return false;
    }

    return true;
}

bool HomeProductOrchestrator::Initialize() noexcept {
    std::lock_guard<std::mutex> lifecycleLock(m_lifecycleMutex);
    return InitializeLocked();
}

bool HomeProductOrchestrator::InitializeLocked() noexcept {
    // Pull every *Wiring.cpp TU into the reference graph before we iterate
    // modules. This is a no-op at runtime but defeats MSVC /OPT:REF + LTCG
    // elision of the internal-linkage registrar globals in Release builds.
    EnsureAllModulesWired();

    // Config defaults and profile presets are registered by the HomeConfig
    // Foundation-phase module (ConfigWiring.cpp). Because Foundation runs
    // first in phase order, all keys are available before any feature module
    // reads them. No duplicate bootstrap here — single source of truth.

    // Iterate modules in phase order, initializing each enabled one.
    // We take a snapshot of the registry under a shared lock so concurrent
    // RegisterModule calls (from late-arriving static initializers) don't
    // invalidate our iterators.
    std::vector<std::size_t> indicesByPhase;
    {
        std::shared_lock regLock(m_registryMutex);
        indicesByPhase.reserve(m_modules.size());
        for (ModulePhase phase : kPhaseOrder) {
            for (std::size_t i = 0; i < m_modules.size(); ++i) {
                if (m_modules[i].descriptor.phase == phase) {
                    indicesByPhase.push_back(i);
                }
            }
        }
    }

    bool allOk = true;
    for (std::size_t idx : indicesByPhase) {
        ModuleDescriptor desc;
        ModuleState priorState;
        {
            std::shared_lock regLock(m_registryMutex);
            if (idx >= m_modules.size()) continue;
            desc = m_modules[idx].descriptor;
            priorState = m_modules[idx].state;
        }

        if (priorState == ModuleState::Initialized ||
            priorState == ModuleState::Running) {
            continue;  // Already initialized - idempotent re-entry.
        }

        if (!IsModuleEnabled(desc)) {
            SS_LOG_INFO(kLogCategory,
                L"Module '%hs' [%hs] disabled by config (%hs); skipping",
                desc.name.c_str(), PhaseName(desc.phase),
                desc.enabledConfigKey.empty() ? "always" : desc.enabledConfigKey.c_str());
            std::unique_lock regLock(m_registryMutex);
            if (idx < m_modules.size()) {
                SetModuleState(m_modules[idx], ModuleState::Disabled);
            }
            continue;
        }

        SS_LOG_INFO(kLogCategory,
            L"Initializing '%hs' [%hs]",
            desc.name.c_str(), PhaseName(desc.phase));

        bool ok = false;
        bool timedOut = false;
        std::string errMsg;

        // Run each module's Initialize() on a worker thread with a hard
        // wall-clock budget. A single module that blocks on a slow syscall
        // (NDIS/WFP warm-up, DNS resolution, filesystem stall, RPC timeout)
        // must not be able to freeze the orchestrator's sequential phase
        // loop — that leaves every subsequent module un-registered and the
        // UI stuck on "Loading protection modules...". On timeout we mark
        // the module Failed, log forensically, and continue.
        //
        // We deliberately use std::packaged_task on a detached std::thread
        // rather than std::async(std::launch::async). The future returned
        // by async-launched policy blocks in its destructor until the worker
        // completes, which defeats the timeout. A packaged_task future has
        // no such waiting behaviour, and the detached thread carries no
        // handle that needs cleanup from our scope. This avoids any raw
        // new / heap leak.
        constexpr auto kInitBudget = std::chrono::seconds(15);
        try {
            std::packaged_task<bool()> task([fn = desc.initialize]() -> bool {
                try {
                    return fn ? fn() : false;
                } catch (...) {
                    return false;
                }
            });
            std::future<bool> fut = task.get_future();
            std::thread(std::move(task)).detach();

            if (fut.wait_for(kInitBudget) == std::future_status::ready) {
                ok = fut.get();
            } else {
                timedOut = true;
                ok = false;
                errMsg = "initialize() exceeded 15s budget";
                SS_LOG_ERROR(kLogCategory,
                    L"Module '%hs' Initialize() timed out after 15s; continuing without it",
                    desc.name.c_str());
                // fut goes out of scope here without blocking (packaged_task
                // future does not own the worker thread the way async does).
                // The detached worker may still finish later; its result is
                // silently discarded by the packaged_task shared state.
            }
        } catch (const std::exception& e) {
            ok = false;
            errMsg = e.what();
            SS_LOG_ERROR(kLogCategory,
                L"Module '%hs' Initialize() threw: %hs",
                desc.name.c_str(), errMsg.c_str());
        } catch (...) {
            ok = false;
            errMsg = "unknown exception";
            SS_LOG_ERROR(kLogCategory,
                L"Module '%hs' Initialize() threw unknown exception",
                desc.name.c_str());
        }

        {
            std::unique_lock regLock(m_registryMutex);
            if (idx >= m_modules.size()) continue;
            if (ok) {
                SetModuleState(m_modules[idx], ModuleState::Initialized);
                SS_LOG_INFO(kLogCategory, L"Module '%hs' initialized", desc.name.c_str());
            } else {
                SetModuleState(m_modules[idx], ModuleState::Failed,
                    timedOut ? std::string("init timeout") : errMsg);
                SS_LOG_ERROR(kLogCategory,
                    L"Module '%hs' Initialize() reported failure: %hs",
                    desc.name.c_str(),
                    errMsg.empty() ? "module returned false" : errMsg.c_str());
                allOk = false;
            }
        }
    }

    // Only report initialized if at least one module reached Initialized/Running.
    {
        std::shared_lock regLock(m_registryMutex);
        const bool anyInitialized = std::any_of(m_modules.begin(), m_modules.end(),
            [](const ModuleRecord& r) {
                return r.state == ModuleState::Initialized ||
                       r.state == ModuleState::Running;
            });
        m_initialized.store(anyInitialized, std::memory_order_release);
    }
    SS_LOG_INFO(kLogCategory,
        L"PhantomHome Initialize phase complete (allOk=%d, initialized=%d)",
        allOk ? 1 : 0, m_initialized.load(std::memory_order_relaxed) ? 1 : 0);
    return allOk;
}

bool HomeProductOrchestrator::Start() noexcept {
    std::lock_guard<std::mutex> lifecycleLock(m_lifecycleMutex);
    return StartLocked();
}

bool HomeProductOrchestrator::StartLocked() noexcept {
    std::vector<std::size_t> indicesByPhase;
    {
        std::shared_lock regLock(m_registryMutex);
        indicesByPhase.reserve(m_modules.size());
        for (ModulePhase phase : kPhaseOrder) {
            for (std::size_t i = 0; i < m_modules.size(); ++i) {
                if (m_modules[i].descriptor.phase == phase) {
                    indicesByPhase.push_back(i);
                }
            }
        }
    }

    bool allOk = true;
    for (std::size_t idx : indicesByPhase) {
        ModuleDescriptor desc;
        ModuleState priorState;
        {
            std::shared_lock regLock(m_registryMutex);
            if (idx >= m_modules.size()) continue;
            desc = m_modules[idx].descriptor;
            priorState = m_modules[idx].state;
        }

        if (priorState != ModuleState::Initialized) {
            // Disabled / Failed / already Running / Stopped: skip silently.
            continue;
        }

        SS_LOG_INFO(kLogCategory,
            L"Starting '%hs' [%hs]", desc.name.c_str(), PhaseName(desc.phase));

        bool ok = false;
        std::string errMsg;
        try {
            // Timed individually: start-up drives roughly 125 module
            // initialisations into a three-second window, and the machine
            // stalls during exactly that window, so the per-module cost is
            // the measurement that matters.
            SS_DIAG_SCOPE("Startup", desc.name.c_str());
            ok = desc.start();
        } catch (const std::exception& e) {
            ok = false;
            errMsg = e.what();
            SS_LOG_ERROR(kLogCategory,
                L"Module '%hs' Start() threw: %hs", desc.name.c_str(), errMsg.c_str());
        } catch (...) {
            ok = false;
            errMsg = "unknown exception";
            SS_LOG_ERROR(kLogCategory,
                L"Module '%hs' Start() threw unknown exception", desc.name.c_str());
        }

        {
            std::unique_lock regLock(m_registryMutex);
            if (idx >= m_modules.size()) continue;
            if (ok) {
                SetModuleState(m_modules[idx], ModuleState::Running);
                SS_LOG_INFO(kLogCategory, L"Module '%hs' running", desc.name.c_str());
            } else {
                SetModuleState(m_modules[idx], ModuleState::Failed, errMsg);
                SS_LOG_ERROR(kLogCategory,
                    L"Module '%hs' Start() failed: %hs",
                    desc.name.c_str(),
                    errMsg.empty() ? "module returned false" : errMsg.c_str());
                allOk = false;
            }
        }

        // Restore persisted protection mode for modules that just reached Running.
        if (ok) {
            ApplyPersistedModeUnlocked(idx);
        }
    }

    // Only report running if at least one module reached Running state.
    {
        std::shared_lock regLock(m_registryMutex);
        const bool anyRunning = std::any_of(m_modules.begin(), m_modules.end(),
            [](const ModuleRecord& r) {
                return r.state == ModuleState::Running;
            });
        m_running.store(anyRunning, std::memory_order_release);
    }
    SS_LOG_INFO(kLogCategory,
        L"PhantomHome Start phase complete (allOk=%d, running=%d)",
        allOk ? 1 : 0, m_running.load(std::memory_order_relaxed) ? 1 : 0);
    return allOk;
}

void HomeProductOrchestrator::Shutdown() noexcept {
    std::lock_guard<std::mutex> lifecycleLock(m_lifecycleMutex);
    ShutdownLocked();
}

void HomeProductOrchestrator::ShutdownLocked() noexcept {
    if (!m_initialized.load(std::memory_order_acquire) &&
        !m_running.load(std::memory_order_acquire)) {
        return;  // Never initialized or already shut down.
    }

    SS_LOG_INFO(kLogCategory, L"PhantomHome shutdown starting");

    // Reverse phase order so dependents stop before dependencies.
    std::vector<std::size_t> indices;
    {
        std::shared_lock regLock(m_registryMutex);
        indices.reserve(m_modules.size());
        for (auto it = kPhaseOrder.rbegin(); it != kPhaseOrder.rend(); ++it) {
            for (std::size_t i = m_modules.size(); i-- > 0;) {
                if (m_modules[i].descriptor.phase == *it) {
                    indices.push_back(i);
                }
            }
        }
    }

    for (std::size_t idx : indices) {
        ModuleDescriptor desc;
        ModuleState priorState;
        {
            std::shared_lock regLock(m_registryMutex);
            if (idx >= m_modules.size()) continue;
            desc = m_modules[idx].descriptor;
            priorState = m_modules[idx].state;
        }

        if (priorState != ModuleState::Running &&
            priorState != ModuleState::Initialized &&
            priorState != ModuleState::Failed) {
            continue;  // Nothing to tear down.
        }

        SS_LOG_INFO(kLogCategory,
            L"Shutting down '%hs' [%hs] from %hs",
            desc.name.c_str(), PhaseName(desc.phase), StateName(priorState));

        try {
            desc.shutdown();
        } catch (const std::exception& e) {
            SS_LOG_ERROR(kLogCategory,
                L"Module '%hs' Shutdown() threw: %hs", desc.name.c_str(), e.what());
        } catch (...) {
            SS_LOG_ERROR(kLogCategory,
                L"Module '%hs' Shutdown() threw unknown exception", desc.name.c_str());
        }

        {
            std::unique_lock regLock(m_registryMutex);
            if (idx < m_modules.size()) {
                SetModuleState(m_modules[idx], ModuleState::Stopped);
            }
        }
    }

    m_running.store(false, std::memory_order_release);
    m_initialized.store(false, std::memory_order_release);
    SS_LOG_INFO(kLogCategory, L"PhantomHome shutdown complete");
}

bool HomeProductOrchestrator::IsInitialized() const noexcept {
    return m_initialized.load(std::memory_order_acquire);
}

bool HomeProductOrchestrator::IsRunning() const noexcept {
    return m_running.load(std::memory_order_acquire);
}

std::vector<ModuleStatus> HomeProductOrchestrator::GetStatus() const {
    std::shared_lock regLock(m_registryMutex);
    std::vector<ModuleStatus> out;
    out.reserve(m_modules.size());
    for (const auto& rec : m_modules) {
        out.push_back({
            rec.descriptor.name,
            rec.descriptor.displayName,
            rec.descriptor.group,
            rec.descriptor.phase,
            rec.state,
            rec.lastError,
            rec.lastTransition,
            rec.currentMode,
        });
    }
    return out;
}

std::optional<ModuleStatus> HomeProductOrchestrator::GetModuleStatus(std::string_view name) const {
    std::shared_lock regLock(m_registryMutex);
    const auto it = std::find_if(m_modules.begin(), m_modules.end(),
        [&](const ModuleRecord& r) { return r.descriptor.name == name; });
    if (it == m_modules.end()) return std::nullopt;
    return ModuleStatus{
        it->descriptor.name,
        it->descriptor.displayName,
        it->descriptor.group,
        it->descriptor.phase,
        it->state,
        it->lastError,
        it->lastTransition,
        it->currentMode,
    };
}

bool HomeProductOrchestrator::IsModuleEnabled(const ModuleDescriptor& desc) const noexcept {
    if (desc.enabledConfigKey.empty()) {
        return true;  // Always-on module (e.g. Foundation phase bootstrap).
    }
    try {
        auto& cfg = ::ShadowStrike::Config::ConfigManager::Instance();
        return cfg.GetValue<bool>(desc.enabledConfigKey, /*default=*/true);
    } catch (...) {
        // If ConfigManager isn't available (extremely early startup or
        // engine-only test binary), default to enabled. PhantomCore already
        // initialized the ConfigManager before calling into us, so this
        // path is only reached on gross misconfiguration.
        SS_LOG_WARN(kLogCategory,
            L"ConfigManager unavailable while checking '%hs'; defaulting to enabled",
            desc.enabledConfigKey.c_str());
        return true;
    }
}

void HomeProductOrchestrator::SetModuleState(ModuleRecord& rec,
                                             ModuleState state,
                                             std::string_view err) noexcept {
    rec.state = state;
    rec.lastError.assign(err.data(), err.size());
    rec.lastTransition = std::chrono::steady_clock::now();
}

void HomeProductOrchestrator::RecomputeRunStateLocked() noexcept {
    // Caller holds m_lifecycleMutex. We only read the registry here.
    bool anyRunning = false;
    bool anyInitialized = false;
    try {
        std::shared_lock regLock(m_registryMutex);
        for (const auto& rec : m_modules) {
            if (rec.state == ModuleState::Running) {
                anyRunning = true;
                anyInitialized = true;
            } else if (rec.state == ModuleState::Initialized) {
                anyInitialized = true;
            }
        }
    } catch (...) {
        // shared_lock construction can theoretically throw system_error;
        // if it does, leave the atomics untouched rather than publish a
        // partially computed view. The next successful recompute will
        // converge them again.
        SS_LOG_ERROR(kLogCategory,
            L"RecomputeRunStateLocked: registry lock acquisition failed; "
            L"IsRunning()/IsInitialized() may be stale until next recompute");
        return;
    }
    m_running.store(anyRunning, std::memory_order_release);
    m_initialized.store(anyInitialized, std::memory_order_release);
}

bool HomeProductOrchestrator::SetModuleEnabled(std::string_view name, bool enabled) noexcept {
    std::lock_guard<std::mutex> lifecycleLock(m_lifecycleMutex);

    // Find the module by name.
    std::size_t idx = SIZE_MAX;
    ModuleDescriptor desc;
    ModuleState priorState;
    {
        std::shared_lock regLock(m_registryMutex);
        for (std::size_t i = 0; i < m_modules.size(); ++i) {
            if (m_modules[i].descriptor.name == name) {
                idx = i;
                desc = m_modules[i].descriptor;
                priorState = m_modules[i].state;
                break;
            }
        }
    }
    if (idx == SIZE_MAX) {
        SS_LOG_WARN(kLogCategory, L"SetModuleEnabled: unknown module '%hs'",
                    std::string(name).c_str());
        return false;
    }

    // Persist the change to ConfigManager so it survives restarts.
    if (!desc.enabledConfigKey.empty()) {
        try {
            auto& cfg = ::ShadowStrike::Config::ConfigManager::Instance();
            if (!cfg.SetValue(desc.enabledConfigKey, enabled)) {
                SS_LOG_WARN(kLogCategory,
                    L"SetModuleEnabled '%hs': ConfigManager::SetValue returned false",
                    desc.name.c_str());
            }
        } catch (...) {
            SS_LOG_ERROR(kLogCategory,
                L"SetModuleEnabled '%hs': ConfigManager::SetValue failed",
                desc.name.c_str());
        }
    }

    if (enabled) {
        // Enable: re-initialize + start if the module is Disabled/Stopped/Failed.
        if (priorState == ModuleState::Running ||
            priorState == ModuleState::Initialized) {
            return true;  // Already running/initialized — nothing to do.
        }

        bool ok = false;
        std::string errMsg;
        try {
            ok = desc.initialize();
        } catch (const std::exception& e) {
            errMsg = e.what();
        } catch (...) {
            errMsg = "unknown exception";
        }

        if (!ok) {
            std::unique_lock regLock(m_registryMutex);
            if (idx < m_modules.size()) {
                SetModuleState(m_modules[idx], ModuleState::Failed, errMsg);
            }
            SS_LOG_ERROR(kLogCategory,
                L"SetModuleEnabled '%hs': Initialize() failed: %hs",
                desc.name.c_str(),
                errMsg.empty() ? "returned false" : errMsg.c_str());
            return false;
        }

        {
            std::unique_lock regLock(m_registryMutex);
            if (idx < m_modules.size()) {
                SetModuleState(m_modules[idx], ModuleState::Initialized);
            }
        }

        ok = false;
        errMsg.clear();
        try {
            ok = desc.start();
        } catch (const std::exception& e) {
            errMsg = e.what();
        } catch (...) {
            errMsg = "unknown exception";
        }

        {
            std::unique_lock regLock(m_registryMutex);
            if (idx < m_modules.size()) {
                if (ok) {
                    SetModuleState(m_modules[idx], ModuleState::Running);
                    SS_LOG_INFO(kLogCategory,
                        L"Module '%hs' enabled and started", desc.name.c_str());
                } else {
                    SetModuleState(m_modules[idx], ModuleState::Failed, errMsg);
                    SS_LOG_ERROR(kLogCategory,
                        L"SetModuleEnabled '%hs': Start() failed: %hs",
                        desc.name.c_str(),
                        errMsg.empty() ? "returned false" : errMsg.c_str());
                }
            }
        }
        RecomputeRunStateLocked();
        return ok;
    } else {
        // Disable: shutdown if running.
        if (priorState != ModuleState::Running &&
            priorState != ModuleState::Initialized) {
            std::unique_lock regLock(m_registryMutex);
            if (idx < m_modules.size()) {
                SetModuleState(m_modules[idx], ModuleState::Disabled);
            }
            RecomputeRunStateLocked();
            return true;  // Already not running.
        }

        try {
            desc.shutdown();
        } catch (const std::exception& e) {
            SS_LOG_ERROR(kLogCategory,
                L"SetModuleEnabled '%hs': Shutdown() threw: %hs",
                desc.name.c_str(), e.what());
        } catch (...) {
            SS_LOG_ERROR(kLogCategory,
                L"SetModuleEnabled '%hs': Shutdown() threw unknown exception",
                desc.name.c_str());
        }

        {
            std::unique_lock regLock(m_registryMutex);
            if (idx < m_modules.size()) {
                SetModuleState(m_modules[idx], ModuleState::Disabled);
                SS_LOG_INFO(kLogCategory,
                    L"Module '%hs' disabled and stopped", desc.name.c_str());
            }
        }
        RecomputeRunStateLocked();
        return true;
    }
}

void HomeProductOrchestrator::PauseAllModules() noexcept {
    std::lock_guard<std::mutex> lifecycleLock(m_lifecycleMutex);

    if (m_paused.load(std::memory_order_acquire)) {
        SS_LOG_WARN(kLogCategory, L"PauseAllModules: already paused");
        return;
    }

    m_pausedModuleNames.clear();

    // Collect Running module names and shut them down in reverse phase order
    // (same shutdown ordering as Shutdown()).
    std::vector<std::size_t> indices;
    {
        std::shared_lock regLock(m_registryMutex);
        indices.reserve(m_modules.size());
        for (auto phaseIt = kPhaseOrder.rbegin(); phaseIt != kPhaseOrder.rend(); ++phaseIt) {
            for (std::size_t i = m_modules.size(); i-- > 0; ) {
                if (m_modules[i].descriptor.phase == *phaseIt &&
                    m_modules[i].state == ModuleState::Running) {
                    indices.push_back(i);
                }
            }
        }
    }

    for (std::size_t idx : indices) {
        ModuleDescriptor desc;
        {
            std::shared_lock regLock(m_registryMutex);
            if (idx >= m_modules.size()) continue;
            desc = m_modules[idx].descriptor;
        }

        m_pausedModuleNames.push_back(desc.name);

        try {
            desc.shutdown();
        } catch (const std::exception& e) {
            SS_LOG_ERROR(kLogCategory,
                L"PauseAllModules: '%hs' shutdown threw: %hs",
                desc.name.c_str(), e.what());
        } catch (...) {
            SS_LOG_ERROR(kLogCategory,
                L"PauseAllModules: '%hs' shutdown threw unknown exception",
                desc.name.c_str());
        }

        {
            std::unique_lock regLock(m_registryMutex);
            if (idx < m_modules.size()) {
                SetModuleState(m_modules[idx], ModuleState::Stopped);
            }
        }
        SS_LOG_INFO(kLogCategory, L"Paused module '%hs'", desc.name.c_str());
    }

    m_paused.store(true, std::memory_order_release);
    RecomputeRunStateLocked();
    SS_LOG_INFO(kLogCategory, L"PhantomHome protection paused (%zu modules quiesced)",
                m_pausedModuleNames.size());
}

void HomeProductOrchestrator::ResumeAllModules() noexcept {
    std::lock_guard<std::mutex> lifecycleLock(m_lifecycleMutex);

    if (!m_paused.load(std::memory_order_acquire)) {
        return;  // Not paused.
    }

    SS_LOG_INFO(kLogCategory, L"Resuming %zu paused modules",
                m_pausedModuleNames.size());

    for (const auto& name : m_pausedModuleNames) {
        // Find module by name.
        std::size_t idx = SIZE_MAX;
        ModuleDescriptor desc;
        {
            std::shared_lock regLock(m_registryMutex);
            for (std::size_t i = 0; i < m_modules.size(); ++i) {
                if (m_modules[i].descriptor.name == name) {
                    idx = i;
                    desc = m_modules[i].descriptor;
                    break;
                }
            }
        }
        if (idx == SIZE_MAX) continue;

        bool ok = false;
        std::string errMsg;
        try {
            ok = desc.initialize();
        } catch (const std::exception& e) {
            errMsg = e.what();
        } catch (...) {
            errMsg = "unknown exception";
        }

        if (!ok) {
            std::unique_lock regLock(m_registryMutex);
            if (idx < m_modules.size()) {
                SetModuleState(m_modules[idx], ModuleState::Failed, errMsg);
            }
            SS_LOG_ERROR(kLogCategory,
                L"Resume '%hs': Initialize() failed: %hs",
                name.c_str(), errMsg.empty() ? "returned false" : errMsg.c_str());
            continue;
        }

        {
            std::unique_lock regLock(m_registryMutex);
            if (idx < m_modules.size()) {
                SetModuleState(m_modules[idx], ModuleState::Initialized);
            }
        }

        ok = false;
        errMsg.clear();
        try {
            ok = desc.start();
        } catch (const std::exception& e) {
            errMsg = e.what();
        } catch (...) {
            errMsg = "unknown exception";
        }

        {
            std::unique_lock regLock(m_registryMutex);
            if (idx < m_modules.size()) {
                if (ok) {
                    SetModuleState(m_modules[idx], ModuleState::Running);
                    SS_LOG_INFO(kLogCategory, L"Resumed module '%hs'", name.c_str());
                } else {
                    SetModuleState(m_modules[idx], ModuleState::Failed, errMsg);
                    SS_LOG_ERROR(kLogCategory,
                        L"Resume '%hs': Start() failed: %hs",
                        name.c_str(),
                        errMsg.empty() ? "returned false" : errMsg.c_str());
                }
            }
        }
    }

    m_pausedModuleNames.clear();
    m_paused.store(false, std::memory_order_release);
    RecomputeRunStateLocked();
    SS_LOG_INFO(kLogCategory, L"PhantomHome protection resumed");
}

bool HomeProductOrchestrator::IsPaused() const noexcept {
    return m_paused.load(std::memory_order_acquire);
}

// ============================================================================
// Protection Mode Management
// ============================================================================

bool HomeProductOrchestrator::SetModuleMode(std::string_view name,
                                            ProtectionMode mode) noexcept {
    std::lock_guard<std::mutex> lifecycleLock(m_lifecycleMutex);

    // Find module under a shared registry lock; copy what we need.
    std::size_t idx = SIZE_MAX;
    ModuleDescriptor desc;
    ModuleState priorState = ModuleState::Unregistered;
    {
        std::shared_lock regLock(m_registryMutex);
        for (std::size_t i = 0; i < m_modules.size(); ++i) {
            if (m_modules[i].descriptor.name == name) {
                idx = i;
                desc = m_modules[i].descriptor;
                priorState = m_modules[i].state;
                break;
            }
        }
    }

    if (idx == SIZE_MAX) {
        SS_LOG_ERROR(kLogCategory, L"SetModuleMode: unknown module '%hs'",
                     std::string(name).c_str());
        return false;
    }

    // Validate the requested mode against the descriptor's supported mask.
    const std::uint8_t modeBit = ProtectionModeMask(mode);
    if ((desc.supportedModesMask & modeBit) == 0) {
        SS_LOG_ERROR(kLogCategory,
            L"SetModuleMode '%hs': mode '%hs' not in supported mask 0x%02X",
            desc.name.c_str(),
            std::string(ToString(mode)).c_str(),
            static_cast<unsigned>(desc.supportedModesMask));
        return false;
    }

    // -------------------------------------------------------------------------
    // Off — delegate to the disable path (no setMode call).
    // -------------------------------------------------------------------------
    if (mode == ProtectionMode::Off) {
        if (priorState == ModuleState::Running ||
            priorState == ModuleState::Initialized) {
            // Persist the enabled-state change.
            if (!desc.enabledConfigKey.empty()) {
                try {
                    if (!::ShadowStrike::Config::ConfigManager::Instance()
                            .SetValue<bool>(desc.enabledConfigKey, false)) {
                        SS_LOG_WARN(kLogCategory,
                            L"SetModuleMode '%hs' Off: ConfigManager SetValue(enabled=false) returned false",
                            desc.name.c_str());
                    }
                } catch (...) {
                    SS_LOG_ERROR(kLogCategory,
                        L"SetModuleMode '%hs' Off: failed to persist enabled=false",
                        desc.name.c_str());
                }
            }
            // Quiesce the module.
            try {
                desc.shutdown();
            } catch (const std::exception& e) {
                SS_LOG_ERROR(kLogCategory,
                    L"SetModuleMode '%hs' Off: shutdown() threw: %hs",
                    desc.name.c_str(), e.what());
            } catch (...) {
                SS_LOG_ERROR(kLogCategory,
                    L"SetModuleMode '%hs' Off: shutdown() threw unknown exception",
                    desc.name.c_str());
            }
            {
                std::unique_lock regLock(m_registryMutex);
                if (idx < m_modules.size()) {
                    SetModuleState(m_modules[idx], ModuleState::Disabled);
                    m_modules[idx].currentMode = ProtectionMode::Off;
                }
            }
        } else {
            // Already not running — just record the mode.
            std::unique_lock regLock(m_registryMutex);
            if (idx < m_modules.size()) {
                m_modules[idx].currentMode = ProtectionMode::Off;
            }
        }

        // Persist the mode.
        try {
            if (!::ShadowStrike::Config::ConfigManager::Instance()
                    .SetValue<int32_t>("Home/" + desc.name + "/Mode", 0)) {
                SS_LOG_WARN(kLogCategory,
                    L"SetModuleMode '%hs' Off: ConfigManager SetValue(Mode=0) returned false",
                    desc.name.c_str());
            }
        } catch (...) {
            SS_LOG_ERROR(kLogCategory,
                L"SetModuleMode '%hs' Off: failed to persist mode",
                desc.name.c_str());
        }

        SS_LOG_INFO(kLogCategory,
            L"Module '%hs' set to Off (disabled and quiesced)", desc.name.c_str());
        RecomputeRunStateLocked();
        return true;
    }

    // -------------------------------------------------------------------------
    // Non-Off mode — ensure the module is Running before applying thresholds.
    // -------------------------------------------------------------------------
    if (priorState == ModuleState::Disabled  ||
        priorState == ModuleState::Stopped   ||
        priorState == ModuleState::Failed    ||
        priorState == ModuleState::Registered) {

        // Enable: persist enabled key, then initialize + start.
        if (!desc.enabledConfigKey.empty()) {
            try {
                if (!::ShadowStrike::Config::ConfigManager::Instance()
                        .SetValue<bool>(desc.enabledConfigKey, true)) {
                    SS_LOG_WARN(kLogCategory,
                        L"SetModuleMode '%hs': ConfigManager SetValue(enabled=true) returned false",
                        desc.name.c_str());
                }
            } catch (...) {
                SS_LOG_ERROR(kLogCategory,
                    L"SetModuleMode '%hs': failed to persist enabled=true",
                    desc.name.c_str());
            }
        }

        bool ok = false;
        std::string errMsg;
        try {
            ok = desc.initialize();
        } catch (const std::exception& e) {
            errMsg = e.what();
        } catch (...) {
            errMsg = "unknown exception";
        }

        if (!ok) {
            std::unique_lock regLock(m_registryMutex);
            if (idx < m_modules.size()) {
                SetModuleState(m_modules[idx], ModuleState::Failed, errMsg);
            }
            SS_LOG_ERROR(kLogCategory,
                L"SetModuleMode '%hs': Initialize() failed while enabling for mode %hs: %hs",
                desc.name.c_str(),
                std::string(ToString(mode)).c_str(),
                errMsg.empty() ? "returned false" : errMsg.c_str());
            return false;
        }
        {
            std::unique_lock regLock(m_registryMutex);
            if (idx < m_modules.size()) {
                SetModuleState(m_modules[idx], ModuleState::Initialized);
            }
        }
        priorState = ModuleState::Initialized;  // Fall through to the Start block below.
    }

    // If the module is Initialized but not yet Running, start it now.
    // This covers two cases: the enable block above just initialized it,
    // and the rare case where the module arrived here already Initialized
    // (e.g. Initialize() ran but Start() was not yet called).
    if (priorState == ModuleState::Initialized) {
        bool ok = false;
        std::string errMsg;
        try {
            // Timed individually: start-up drives roughly 125 module
            // initialisations into a three-second window, and the machine
            // stalls during exactly that window, so the per-module cost is
            // the measurement that matters.
            SS_DIAG_SCOPE("Startup", desc.name.c_str());
            ok = desc.start();
        } catch (const std::exception& e) {
            errMsg = e.what();
        } catch (...) {
            errMsg = "unknown exception";
        }

        if (!ok) {
            std::unique_lock regLock(m_registryMutex);
            if (idx < m_modules.size()) {
                SetModuleState(m_modules[idx], ModuleState::Failed, errMsg);
            }
            SS_LOG_ERROR(kLogCategory,
                L"SetModuleMode '%hs': Start() failed while enabling for mode %hs: %hs",
                desc.name.c_str(),
                std::string(ToString(mode)).c_str(),
                errMsg.empty() ? "returned false" : errMsg.c_str());
            return false;
        }
        {
            std::unique_lock regLock(m_registryMutex);
            if (idx < m_modules.size()) {
                SetModuleState(m_modules[idx], ModuleState::Running);
            }
        }
        SS_LOG_INFO(kLogCategory,
            L"Module '%hs' started for mode transition to %hs",
            desc.name.c_str(), std::string(ToString(mode)).c_str());
    }

    // -------------------------------------------------------------------------
    // Apply the mode: prefer descriptor.setMode, fall back to ApplyModeThresholds.
    // -------------------------------------------------------------------------
    bool modeApplied = false;
    if (desc.setMode) {
        try {
            modeApplied = desc.setMode(mode);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(kLogCategory,
                L"SetModuleMode '%hs': setMode(%hs) threw: %hs",
                desc.name.c_str(), std::string(ToString(mode)).c_str(), e.what());
            return false;
        } catch (...) {
            SS_LOG_ERROR(kLogCategory,
                L"SetModuleMode '%hs': setMode(%hs) threw unknown exception",
                desc.name.c_str(), std::string(ToString(mode)).c_str());
            return false;
        }
        if (!modeApplied) {
            SS_LOG_ERROR(kLogCategory,
                L"SetModuleMode '%hs': setMode(%hs) returned false",
                desc.name.c_str(), std::string(ToString(mode)).c_str());
            return false;
        }
    } else {
        modeApplied = ApplyModeThresholds(desc.name, mode);
        if (!modeApplied) {
            SS_LOG_ERROR(kLogCategory,
                L"SetModuleMode '%hs': ApplyModeThresholds(%hs) failed",
                desc.name.c_str(), std::string(ToString(mode)).c_str());
            return false;
        }
    }

    // Persist the mode to ConfigManager.
    try {
        if (!::ShadowStrike::Config::ConfigManager::Instance()
                .SetValue<int32_t>("Home/" + desc.name + "/Mode",
                                   static_cast<int32_t>(mode))) {
            SS_LOG_WARN(kLogCategory,
                L"SetModuleMode '%hs': ConfigManager SetValue(Mode=%hs) returned false",
                desc.name.c_str(), std::string(ToString(mode)).c_str());
        }
    } catch (...) {
        // Non-fatal: mode already applied; log and continue.
        SS_LOG_ERROR(kLogCategory,
            L"SetModuleMode '%hs': failed to persist mode %hs (mode is active)",
            desc.name.c_str(), std::string(ToString(mode)).c_str());
    }

    // Update the live status record.
    {
        std::unique_lock regLock(m_registryMutex);
        if (idx < m_modules.size()) {
            m_modules[idx].currentMode = mode;
        }
    }

    SS_LOG_INFO(kLogCategory,
        L"Module '%hs' protection mode set to %hs",
        desc.name.c_str(), std::string(ToString(mode)).c_str());
    RecomputeRunStateLocked();
    return true;
}

std::optional<ProtectionMode>
HomeProductOrchestrator::GetModuleMode(std::string_view name) const {
    std::shared_lock regLock(m_registryMutex);
    const auto it = std::find_if(m_modules.begin(), m_modules.end(),
        [&](const ModuleRecord& r) { return r.descriptor.name == name; });
    if (it == m_modules.end()) return std::nullopt;
    return it->currentMode;
}

void HomeProductOrchestrator::ApplyPersistedModeUnlocked(
    std::size_t moduleIdx) noexcept {
    // Called under m_lifecycleMutex. The module at moduleIdx is Running.
    ModuleDescriptor desc;
    {
        std::shared_lock regLock(m_registryMutex);
        if (moduleIdx >= m_modules.size()) return;
        desc = m_modules[moduleIdx].descriptor;
    }

    const std::string modeKey = "Home/" + desc.name + "/Mode";
    int32_t storedRaw = -1;
    try {
        auto& cfg = ::ShadowStrike::Config::ConfigManager::Instance();
        if (!cfg.HasKey(modeKey)) return;  // No persisted mode — leave default.
        storedRaw = cfg.GetValue<int32_t>(modeKey, -1);
    } catch (...) {
        SS_LOG_WARN(kLogCategory,
            L"ApplyPersistedMode '%hs': ConfigManager read failed; using default mode",
            desc.name.c_str());
        return;
    }

    // Validate range (0..3 correspond to ProtectionMode enumerators).
    if (storedRaw < 0 || storedRaw > 3) {
        SS_LOG_WARN(kLogCategory,
            L"ApplyPersistedMode '%hs': stored mode value %d is out of range [0,3]; ignoring",
            desc.name.c_str(), storedRaw);
        return;
    }

    const auto mode = static_cast<ProtectionMode>(storedRaw);

    // Off means disabled — but the module just started, so this is inconsistent.
    // The enabled-key check in InitializeLocked already gates on Off. Skip.
    if (mode == ProtectionMode::Off) return;

    // Confirm the module supports this mode.
    {
        std::shared_lock regLock(m_registryMutex);
        if (moduleIdx >= m_modules.size()) return;
        const std::uint8_t mask = m_modules[moduleIdx].descriptor.supportedModesMask;
        if ((mask & ProtectionModeMask(mode)) == 0) {
            SS_LOG_WARN(kLogCategory,
                L"ApplyPersistedMode '%hs': persisted mode %hs not in supported mask 0x%02X; ignoring",
                desc.name.c_str(),
                std::string(ToString(mode)).c_str(),
                static_cast<unsigned>(mask));
            return;
        }
    }

    // Apply: prefer the module's own setMode, fall back to threshold helper.
    bool ok = false;
    if (desc.setMode) {
        try {
            ok = desc.setMode(mode);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(kLogCategory,
                L"ApplyPersistedMode '%hs': setMode(%hs) threw: %hs",
                desc.name.c_str(), std::string(ToString(mode)).c_str(), e.what());
        } catch (...) {
            SS_LOG_ERROR(kLogCategory,
                L"ApplyPersistedMode '%hs': setMode(%hs) threw unknown exception",
                desc.name.c_str(), std::string(ToString(mode)).c_str());
        }
    } else {
        ok = ApplyModeThresholds(desc.name, mode);
    }

    if (!ok) {
        SS_LOG_WARN(kLogCategory,
            L"ApplyPersistedMode '%hs': failed to restore mode %hs; module runs at default",
            desc.name.c_str(), std::string(ToString(mode)).c_str());
        return;
    }

    {
        std::unique_lock regLock(m_registryMutex);
        if (moduleIdx < m_modules.size()) {
            m_modules[moduleIdx].currentMode = mode;
        }
    }
    SS_LOG_INFO(kLogCategory,
        L"Module '%hs' restored to persisted protection mode %hs",
        desc.name.c_str(), std::string(ToString(mode)).c_str());
}

}  // namespace Home
}  // namespace Products
}  // namespace ShadowStrike
