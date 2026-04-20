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

#include "../../../PhantomCore/Config/ConfigManager.hpp"
#include "../../../PhantomCore/Utils/Logger.hpp"

#include <algorithm>
#include <array>

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
        std::string errMsg;
        try {
            ok = desc.initialize();
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
                SetModuleState(m_modules[idx], ModuleState::Failed, errMsg);
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
            rec.descriptor.phase,
            rec.state,
            rec.lastError,
            rec.lastTransition,
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
        it->descriptor.phase,
        it->state,
        it->lastError,
        it->lastTransition,
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

}  // namespace Home
}  // namespace Products
}  // namespace ShadowStrike
