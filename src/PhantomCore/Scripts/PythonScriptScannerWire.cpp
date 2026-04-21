/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Per-module wiring shim for PythonScriptScanner. Isolated in its own TU to
 * match the Ransomware pattern and guard against future ODR collisions
 * across the Scripts module headers.
 */
#include "pch.h"
#include "PythonScriptScanner.hpp"
#include "../Utils/Logger.hpp"

namespace ShadowStrike::Scripts::Wiring::Internal {

bool PythonScriptScanner_Init() noexcept {
    try {
        if (PythonScriptScanner::Instance().Initialize()) {
            return true;
        }
        Utils::Logger::Warn("ScriptsWiring: PythonScriptScanner::Initialize returned false");
    } catch (const std::exception& e) {
        Utils::Logger::Error("ScriptsWiring: PythonScriptScanner init exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("ScriptsWiring: PythonScriptScanner init unknown exception");
    }
    return false;
}

void PythonScriptScanner_Shutdown() noexcept {
    try {
        PythonScriptScanner::Instance().Shutdown();
    } catch (const std::exception& e) {
        Utils::Logger::Error("ScriptsWiring: PythonScriptScanner shutdown exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("ScriptsWiring: PythonScriptScanner shutdown unknown exception");
    }
}

}  // namespace ShadowStrike::Scripts::Wiring::Internal
