/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Per-module wiring shim for VBScriptScanner. Isolated in its own TU to
 * match the Ransomware pattern and guard against future ODR collisions
 * across the Scripts module headers.
 */
#include "pch.h"
#include "VBScriptScanner.hpp"
#include "../Utils/Logger.hpp"

namespace ShadowStrike::Scripts::Wiring::Internal {

bool VBScriptScanner_Init() noexcept {
    try {
        if (VBScriptScanner::Instance().Initialize()) {
            return true;
        }
        Utils::Logger::Warn("ScriptsWiring: VBScriptScanner::Initialize returned false");
    } catch (const std::exception& e) {
        Utils::Logger::Error("ScriptsWiring: VBScriptScanner init exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("ScriptsWiring: VBScriptScanner init unknown exception");
    }
    return false;
}

void VBScriptScanner_Shutdown() noexcept {
    try {
        VBScriptScanner::Instance().Shutdown();
    } catch (const std::exception& e) {
        Utils::Logger::Error("ScriptsWiring: VBScriptScanner shutdown exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("ScriptsWiring: VBScriptScanner shutdown unknown exception");
    }
}

}  // namespace ShadowStrike::Scripts::Wiring::Internal
