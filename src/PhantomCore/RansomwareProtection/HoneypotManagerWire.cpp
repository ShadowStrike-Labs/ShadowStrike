/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Per-module wiring shim for HoneypotManager. Isolated in its own TU because the
 * RansomwareProtection module headers pair-wise redefine the same enums in
 * the ShadowStrike::Ransomware namespace, so only one may be included per TU.
 */
#include "pch.h"
#include "HoneypotManager.hpp"
#include "../Utils/Logger.hpp"

namespace ShadowStrike::Ransomware::Wiring::Internal {

bool HoneypotManager_Init() noexcept {
    try {
        if (HoneypotManager::Instance().Initialize()) {
            return true;
        }
        Utils::Logger::Warn("RansomwareWiring: HoneypotManager::Initialize returned false");
    } catch (const std::exception& e) {
        Utils::Logger::Error("RansomwareWiring: HoneypotManager init exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("RansomwareWiring: HoneypotManager init unknown exception");
    }
    return false;
}

void HoneypotManager_Shutdown() noexcept {
    try {
        HoneypotManager::Instance().Shutdown();
    } catch (const std::exception& e) {
        Utils::Logger::Error("RansomwareWiring: HoneypotManager shutdown exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("RansomwareWiring: HoneypotManager shutdown unknown exception");
    }
}

}  // namespace ShadowStrike::Ransomware::Wiring::Internal
