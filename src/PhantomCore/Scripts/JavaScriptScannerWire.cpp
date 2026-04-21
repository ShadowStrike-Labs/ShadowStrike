/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Per-module wiring shim for JavaScriptScanner. Isolated in its own TU to
 * match the Ransomware pattern and guard against future ODR collisions
 * across the Scripts module headers.
 */
#include "pch.h"
#include "JavaScriptScanner.hpp"
#include "../Utils/Logger.hpp"

namespace ShadowStrike::Scripts::Wiring::Internal {

bool JavaScriptScanner_Init() noexcept {
    try {
        if (JavaScriptScanner::Instance().Initialize()) {
            return true;
        }
        Utils::Logger::Warn("ScriptsWiring: JavaScriptScanner::Initialize returned false");
    } catch (const std::exception& e) {
        Utils::Logger::Error("ScriptsWiring: JavaScriptScanner init exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("ScriptsWiring: JavaScriptScanner init unknown exception");
    }
    return false;
}

void JavaScriptScanner_Shutdown() noexcept {
    try {
        JavaScriptScanner::Instance().Shutdown();
    } catch (const std::exception& e) {
        Utils::Logger::Error("ScriptsWiring: JavaScriptScanner shutdown exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("ScriptsWiring: JavaScriptScanner shutdown unknown exception");
    }
}

}  // namespace ShadowStrike::Scripts::Wiring::Internal
