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
#include <filesystem>
#include <algorithm>
#include <cwctype>

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

bool VBScriptScanner_ScanFile(const std::wstring& filePath,
                              const std::wstring& lowerExt) noexcept {
    try {
        std::filesystem::path p{filePath};
        VBSScanResult result{};
        if (lowerExt == L".vbe") {
            result = VBScriptScanner::Instance().ScanEncodedVBE(p);
        } else if (lowerExt == L".wsf" || lowerExt == L".wsh") {
            result = VBScriptScanner::Instance().ScanWSF(p);
        } else if (lowerExt == L".hta") {
            result = VBScriptScanner::Instance().ScanHTA(p);
        } else {
            result = VBScriptScanner::Instance().ScanFile(p);
        }
        return result.isMalicious;
    } catch (const std::exception& e) {
        Utils::Logger::Warn("ScriptsWiring: VBS ScanFile exception: {}", e.what());
    } catch (...) {}
    return false;
}

}  // namespace ShadowStrike::Scripts::Wiring::Internal
