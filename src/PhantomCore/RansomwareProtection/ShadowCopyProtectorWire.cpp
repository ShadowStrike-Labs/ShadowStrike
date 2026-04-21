/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Per-module wiring shim for ShadowCopyProtector. Isolated in its own TU because the
 * RansomwareProtection module headers pair-wise redefine the same enums in
 * the ShadowStrike::Ransomware namespace, so only one may be included per TU.
 */
#include "pch.h"
#include "ShadowCopyProtector.hpp"
#include "../Utils/Logger.hpp"

namespace ShadowStrike::Ransomware::Wiring::Internal {

bool ShadowCopyProtector_Init() noexcept {
    try {
        if (ShadowCopyProtector::Instance().Initialize()) {
            return true;
        }
        Utils::Logger::Warn("RansomwareWiring: ShadowCopyProtector::Initialize returned false");
    } catch (const std::exception& e) {
        Utils::Logger::Error("RansomwareWiring: ShadowCopyProtector init exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("RansomwareWiring: ShadowCopyProtector init unknown exception");
    }
    return false;
}

void ShadowCopyProtector_Shutdown() noexcept {
    try {
        ShadowCopyProtector::Instance().Shutdown();
    } catch (const std::exception& e) {
        Utils::Logger::Error("RansomwareWiring: ShadowCopyProtector shutdown exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("RansomwareWiring: ShadowCopyProtector shutdown unknown exception");
    }
}

}  // namespace ShadowStrike::Ransomware::Wiring::Internal
