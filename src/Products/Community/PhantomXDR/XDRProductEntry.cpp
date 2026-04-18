/*
 * ShadowStrike - Enterprise NGAV/EDR/XDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 *
 * XDR Product Entry — called from main() to boot the full XDR stack.
 * Initializes EDR first, then layers XDR on top.
 */

#include <format>

#include "PhantomCore/Utils/Logger.hpp"
#include "Products/Community/PhantomEDR/EDRProductOrchestrator.hpp"
#include "Products/Community/PhantomXDR/XDRProductOrchestrator.hpp"

namespace ShadowStrike::Products::PhantomXDR {

using ShadowStrike::Utils::Logger;

static constexpr std::string_view kLogPrefix = "[XDREntry]";

/// @brief Full XDR product boot: EDR foundation + XDR extensions.
///
/// The XDR product is a superset of EDR. This function ensures the EDR
/// stack is running before initializing XDR-specific subsystems.
///
/// @return true if both EDR and XDR stacks initialized successfully
[[nodiscard]] bool BootXDRProduct() {
    Logger::Info("{} Booting full XDR product stack...", kLogPrefix);

    // ── Step 1: Boot the EDR foundation ──
    if (!PhantomEDR::RegisterEDRModules()) {
        Logger::Error("{} EDR foundation boot failed — cannot start XDR", kLogPrefix);
        return false;
    }
    Logger::Info("{} EDR foundation ready — layering XDR...", kLogPrefix);

    // ── Step 2: Boot XDR extensions ──
    if (!RegisterXDRModules()) {
        Logger::Error("{} XDR extension boot failed", kLogPrefix);
        // EDR is still running; caller decides whether to keep it
        return false;
    }

    const auto& edr = PhantomEDR::EDRProductOrchestrator::Instance();
    const auto& xdr = XDRProductOrchestrator::Instance();

    Logger::Info("{} ============================================================", kLogPrefix);
    Logger::Info("{} XDR PRODUCT READY", kLogPrefix);
    Logger::Info("{}   EDR subsystems: {}/{}", kLogPrefix,
                 edr.InitializedSubsystemCount(), edr.TotalSubsystemCount());
    Logger::Info("{}   XDR subsystems: {}/{}", kLogPrefix,
                 xdr.InitializedSubsystemCount(), xdr.TotalSubsystemCount());
    Logger::Info("{}   Total: {}/{}", kLogPrefix,
                 edr.InitializedSubsystemCount() + xdr.InitializedSubsystemCount(),
                 edr.TotalSubsystemCount() + xdr.TotalSubsystemCount());
    Logger::Info("{} ============================================================", kLogPrefix);

    return true;
}

/// @brief Graceful shutdown of the full XDR stack (XDR first, then EDR).
void ShutdownXDRProduct() {
    Logger::Info("{} Shutting down full XDR product stack...", kLogPrefix);

    // XDR extensions first (reverse of boot order)
    if (XDRProductOrchestrator::Instance().IsInitialized()) {
        XDRProductOrchestrator::Instance().Shutdown();
    }

    // Then EDR foundation
    if (PhantomEDR::EDRProductOrchestrator::Instance().IsInitialized()) {
        PhantomEDR::EDRProductOrchestrator::Instance().Shutdown();
    }

    Logger::Info("{} Full XDR product stack shut down", kLogPrefix);
}

} // namespace ShadowStrike::Products::PhantomXDR
