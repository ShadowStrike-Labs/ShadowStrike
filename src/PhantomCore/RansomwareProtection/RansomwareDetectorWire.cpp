/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Per-module wiring shim for RansomwareDetector. Isolated in its own TU because the
 * RansomwareProtection module headers pair-wise redefine the same enums in
 * the ShadowStrike::Ransomware namespace, so only one may be included per TU.
 */
#include "pch.h"
#include "RansomwareDetector.hpp"
#include "../Utils/Logger.hpp"

namespace ShadowStrike::Ransomware::Wiring::Internal {

bool RansomwareDetector_Init() noexcept {
    try {
        if (RansomwareDetector::Instance().Initialize()) {
            return true;
        }
        Utils::Logger::Warn("RansomwareWiring: RansomwareDetector::Initialize returned false");
    } catch (const std::exception& e) {
        Utils::Logger::Error("RansomwareWiring: RansomwareDetector init exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("RansomwareWiring: RansomwareDetector init unknown exception");
    }
    return false;
}

void RansomwareDetector_Shutdown() noexcept {
    try {
        RansomwareDetector::Instance().Shutdown();
    } catch (const std::exception& e) {
        Utils::Logger::Error("RansomwareWiring: RansomwareDetector shutdown exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("RansomwareWiring: RansomwareDetector shutdown unknown exception");
    }
}

}  // namespace ShadowStrike::Ransomware::Wiring::Internal
