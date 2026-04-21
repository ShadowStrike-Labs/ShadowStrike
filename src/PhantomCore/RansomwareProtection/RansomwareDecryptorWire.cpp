/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Per-module wiring shim for RansomwareDecryptor. Isolated in its own TU because the
 * RansomwareProtection module headers pair-wise redefine the same enums in
 * the ShadowStrike::Ransomware namespace, so only one may be included per TU.
 */
#include "pch.h"
#include "RansomwareDecryptor.hpp"
#include "../Utils/Logger.hpp"

namespace ShadowStrike::Ransomware::Wiring::Internal {

bool RansomwareDecryptor_Init() noexcept {
    try {
        if (RansomwareDecryptor::Instance().Initialize()) {
            return true;
        }
        Utils::Logger::Warn("RansomwareWiring: RansomwareDecryptor::Initialize returned false");
    } catch (const std::exception& e) {
        Utils::Logger::Error("RansomwareWiring: RansomwareDecryptor init exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("RansomwareWiring: RansomwareDecryptor init unknown exception");
    }
    return false;
}

void RansomwareDecryptor_Shutdown() noexcept {
    try {
        RansomwareDecryptor::Instance().Shutdown();
    } catch (const std::exception& e) {
        Utils::Logger::Error("RansomwareWiring: RansomwareDecryptor shutdown exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("RansomwareWiring: RansomwareDecryptor shutdown unknown exception");
    }
}

}  // namespace ShadowStrike::Ransomware::Wiring::Internal
