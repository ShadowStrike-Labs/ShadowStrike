/*
 * ShadowStrike - Enterprise NGAV/EDR/XDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */
#pragma once

#include <cstdint>
#include <memory>
#include <string_view>

namespace ShadowStrike::Products::PhantomXDR {

class XDRProductOrchestratorImpl;

/// @brief Product-level orchestrator for PhantomXDR.
///
/// Initializes every XDR subsystem in dependency order, provides a single
/// Shutdown() that tears everything down in reverse, and exposes health
/// status for the management console / heartbeat.
///
/// The XDR orchestrator assumes the EDR product stack is already running.
/// It adds cross-domain correlation, network detection, identity protection,
/// email threat analysis, SOAR automation, and AI-assisted hunting on top.
///
/// Meyers' singleton — thread-safe, lazy-initialized.
class XDRProductOrchestrator final {
public:
    [[nodiscard]] static XDRProductOrchestrator& Instance();

    /// @brief Boot the entire XDR product stack.
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

    /// @brief Human-readable version string.
    [[nodiscard]] static constexpr std::string_view ProductName() noexcept {
        return "PhantomXDR 3.0.0";
    }

    ~XDRProductOrchestrator();
    XDRProductOrchestrator(const XDRProductOrchestrator&)            = delete;
    XDRProductOrchestrator& operator=(const XDRProductOrchestrator&) = delete;

private:
    XDRProductOrchestrator();
    std::unique_ptr<XDRProductOrchestratorImpl> m_impl;
};

/// @brief Called from the agent main() to register and boot XDR.
/// @return true if the XDR product started successfully.
[[nodiscard]] bool RegisterXDRModules();

} // namespace ShadowStrike::Products::PhantomXDR
