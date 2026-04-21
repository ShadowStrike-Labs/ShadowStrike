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

#include <algorithm>
#include <cwctype>
#include <string>

namespace ShadowStrike::Scripts::Wiring::Internal {

bool JavaScriptScanner_Init() noexcept;
void JavaScriptScanner_Shutdown() noexcept;
bool MacroDetector_Init() noexcept;
void MacroDetector_Shutdown() noexcept;
bool PythonScriptScanner_Init() noexcept;
void PythonScriptScanner_Shutdown() noexcept;
bool VBScriptScanner_Init() noexcept;
void VBScriptScanner_Shutdown() noexcept;

bool JavaScriptScanner_ScanFile(const std::wstring& filePath) noexcept;
bool VBScriptScanner_ScanFile(const std::wstring& filePath,
                              const std::wstring& lowerExt) noexcept;
bool PythonScriptScanner_ScanFile(const std::wstring& filePath,
                                  const std::wstring& lowerExt) noexcept;
bool MacroDetector_ScanDocument(const std::wstring& filePath) noexcept;

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

// ===========================================================================
// PUBLIC DISPATCH
// ===========================================================================

namespace {

std::wstring ExtractLowerExtension(const std::wstring& path) noexcept {
    const auto dot = path.find_last_of(L'.');
    if (dot == std::wstring::npos || dot + 1 >= path.size()) {
        return {};
    }
    std::wstring ext = path.substr(dot);
    std::transform(ext.begin(), ext.end(), ext.begin(),
                   [](wchar_t c) -> wchar_t {
                       return static_cast<wchar_t>(std::towlower(c));
                   });
    return ext;
}

constexpr std::size_t kMaxDispatchPathChars = 32768;

}  // namespace

bool DispatchFileScan(std::uint32_t /*pid*/,
                      const std::wstring& filePath) noexcept {
    if (filePath.empty() || filePath.size() > kMaxDispatchPathChars) {
        return false;
    }

    const std::wstring ext = ExtractLowerExtension(filePath);
    if (ext.empty()) return false;

    using namespace Internal;

    // JavaScript family.
    if (ext == L".js" || ext == L".jse" || ext == L".mjs" || ext == L".cjs") {
        return JavaScriptScanner_ScanFile(filePath);
    }

    // VBScript / Windows Script Host / HTA.
    if (ext == L".vbs" || ext == L".vbe" || ext == L".wsf" ||
        ext == L".wsh" || ext == L".hta") {
        return VBScriptScanner_ScanFile(filePath, ext);
    }

    // Python scripts / bytecode.
    if (ext == L".py" || ext == L".pyw" ||
        ext == L".pyc" || ext == L".pyo" || ext == L".pyz") {
        return PythonScriptScanner_ScanFile(filePath, ext);
    }

    // Microsoft Office macros (legacy + OpenXML + macro-enabled variants).
    if (ext == L".doc" || ext == L".docm" || ext == L".docx" ||
        ext == L".xls" || ext == L".xlsm" || ext == L".xlsx" || ext == L".xlsb" ||
        ext == L".ppt" || ext == L".pptm" || ext == L".pptx" ||
        ext == L".rtf" || ext == L".dotm" || ext == L".xltm") {
        return MacroDetector_ScanDocument(filePath);
    }

    return false;
}

}  // namespace ShadowStrike::Scripts::Wiring
