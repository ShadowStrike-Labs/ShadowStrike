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
#include <string_view>

namespace ShadowStrike::Scripts::Wiring::Internal {
namespace {

constexpr std::size_t kMaxPythonWirePathChars = 32767;

[[nodiscard]] bool IsValidWirePath(std::wstring_view path) noexcept {
    if (path.empty() || path.size() > kMaxPythonWirePathChars) {
        return false;
    }
    for (const wchar_t ch : path) {
        if (ch == L'\0' || ch < 0x20) {
            return false;
        }
    }
    return true;
}

}  // namespace

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
        if (!IsValidWirePath(filePath)) {
            Utils::Logger::Warn("ScriptsWiring: rejected invalid Python scan path");
            return false;
        }
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
    } catch (...) {
        Utils::Logger::Warn("ScriptsWiring: Python ScanFile unknown exception");
    }
    return false;
}

}  // namespace ShadowStrike::Scripts::Wiring::Internal
