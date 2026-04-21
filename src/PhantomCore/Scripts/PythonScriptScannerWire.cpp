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
#include <filesystem>

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

bool PythonScriptScanner_ScanFile(const std::wstring& filePath,
                                  const std::wstring& lowerExt) noexcept {
    try {
        std::filesystem::path p{filePath};
        PythonScanResult result{};
        if (lowerExt == L".pyc" || lowerExt == L".pyo") {
            result = PythonScriptScanner::Instance().ScanBytecode(p);
        } else {
            result = PythonScriptScanner::Instance().ScanFile(p);
        }
        return result.isMalicious;
    } catch (const std::exception& e) {
        Utils::Logger::Warn("ScriptsWiring: Python ScanFile exception: {}", e.what());
    } catch (...) {}
    return false;
}

}  // namespace ShadowStrike::Scripts::Wiring::Internal
