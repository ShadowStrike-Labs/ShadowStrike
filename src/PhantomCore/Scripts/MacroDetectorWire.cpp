/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Per-module wiring shim for MacroDetector. Isolated in its own TU to
 * match the Ransomware pattern and guard against future ODR collisions
 * across the Scripts module headers.
 */
#include "pch.h"
#include "MacroDetector.hpp"
#include "../Utils/Logger.hpp"

namespace ShadowStrike::Scripts::Wiring::Internal {

bool MacroDetector_Init() noexcept {
    try {
        if (MacroDetector::Instance().Initialize()) {
            return true;
        }
        Utils::Logger::Warn("ScriptsWiring: MacroDetector::Initialize returned false");
    } catch (const std::exception& e) {
        Utils::Logger::Error("ScriptsWiring: MacroDetector init exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("ScriptsWiring: MacroDetector init unknown exception");
    }
    return false;
}

void MacroDetector_Shutdown() noexcept {
    try {
        MacroDetector::Instance().Shutdown();
    } catch (const std::exception& e) {
        Utils::Logger::Error("ScriptsWiring: MacroDetector shutdown exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("ScriptsWiring: MacroDetector shutdown unknown exception");
    }
}

}  // namespace ShadowStrike::Scripts::Wiring::Internal
