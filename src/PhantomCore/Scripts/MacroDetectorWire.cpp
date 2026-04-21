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
#include <filesystem>

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

bool MacroDetector_ScanDocument(const std::wstring& filePath) noexcept {
    try {
        const auto result = MacroDetector::Instance().ScanDocument(
            std::filesystem::path{filePath});
        return result.isMalicious;
    } catch (const std::exception& e) {
        Utils::Logger::Warn("ScriptsWiring: Macro ScanDocument exception: {}", e.what());
    } catch (...) {}
    return false;
}

}  // namespace ShadowStrike::Scripts::Wiring::Internal
