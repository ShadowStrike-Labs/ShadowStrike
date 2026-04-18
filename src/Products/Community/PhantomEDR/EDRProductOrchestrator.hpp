/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */
#pragma once

#include <cstdint>
#include <memory>
#include <string_view>

namespace ShadowStrike::Products::PhantomEDR {

class EDRProductOrchestratorImpl;

/// @brief Product-level orchestrator for PhantomEDR.
///
/// Initializes every EDR subsystem in dependency order, provides a single
/// Shutdown() that tears everything down in reverse, and exposes health
/// status for the management console / heartbeat.
///
/// Meyers' singleton — thread-safe, lazy-initialized.
class EDRProductOrchestrator final {
public:
    [[nodiscard]] static EDRProductOrchestrator& Instance();

    /// @brief Boot the entire EDR product stack.
    /// @return true if every mandatory subsystem initialized successfully
    [[nodiscard]] bool Initialize();

    /// @brief Graceful shutdown — reverse dependency order.
    void Shutdown();

    /// @brief True once Initialize() has completed successfully.
    [[nodiscard]] bool IsInitialized() const noexcept;

    /// @brief Count of subsystems that started successfully.
    [[nodiscard]] uint32_t InitializedSubsystemCount() const noexcept;

    /// @brief Total subsystem count managed by this orchestrator.
    [[nodiscard]] uint32_t TotalSubsystemCount() const noexcept;

    /// @brief Quick health check — false if any critical subsystem failed.
    [[nodiscard]] bool IsHealthy() const noexcept;

    /// @brief Human-readable version string: "PhantomEDR 3.0.0"
    [[nodiscard]] static constexpr std::string_view ProductName() noexcept {
        return "PhantomEDR 3.0.0";
    }

    ~EDRProductOrchestrator();
    EDRProductOrchestrator(const EDRProductOrchestrator&) = delete;
    EDRProductOrchestrator& operator=(const EDRProductOrchestrator&) = delete;

private:
    EDRProductOrchestrator();
    std::unique_ptr<EDRProductOrchestratorImpl> m_impl;
};

/// @brief Called from the agent main() to register and boot EDR.
/// @return true if the EDR product started successfully.
[[nodiscard]] bool RegisterEDRModules();

} // namespace ShadowStrike::Products::PhantomEDR
