/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "pch.h"
/**
 * @file  ScriptsWiring.cpp
 * @brief Aggregator TU for the script-scanner subsystem.
 *
 * Does NOT include any of the per-module headers directly, for the same
 * ODR-hygiene reason documented in RansomwareWiring.cpp. Individual module
 * calls are delegated to `<Module>Wire.cpp` free functions.
 */

#include "ScriptsWiring.hpp"
#include "../Utils/Logger.hpp"

namespace ShadowStrike::Scripts::Wiring::Internal {

bool JavaScriptScanner_Init() noexcept;
void JavaScriptScanner_Shutdown() noexcept;
bool MacroDetector_Init() noexcept;
void MacroDetector_Shutdown() noexcept;
bool PythonScriptScanner_Init() noexcept;
void PythonScriptScanner_Shutdown() noexcept;
bool VBScriptScanner_Init() noexcept;
void VBScriptScanner_Shutdown() noexcept;

}  // namespace ShadowStrike::Scripts::Wiring::Internal

namespace ShadowStrike::Scripts::Wiring {

bool InitializeScriptsSubsystem() noexcept {
    using namespace Internal;

    Utils::Logger::Info("ScriptsWiring: initializing subsystem");

    const bool js  = JavaScriptScanner_Init();
    const bool vbs = VBScriptScanner_Init();
    const bool py  = PythonScriptScanner_Init();
    const bool mac = MacroDetector_Init();

    const int ok = (js ? 1 : 0) + (vbs ? 1 : 0) + (py ? 1 : 0) + (mac ? 1 : 0);
    Utils::Logger::Info("ScriptsWiring: subsystem online ({}/4 scanners ready)",
                        ok);
    return ok > 0;
}

void ShutdownScriptsSubsystem() noexcept {
    using namespace Internal;

    Utils::Logger::Info("ScriptsWiring: shutting down subsystem");

    MacroDetector_Shutdown();
    PythonScriptScanner_Shutdown();
    VBScriptScanner_Shutdown();
    JavaScriptScanner_Shutdown();

    Utils::Logger::Info("ScriptsWiring: subsystem stopped");
}

}  // namespace ShadowStrike::Scripts::Wiring
