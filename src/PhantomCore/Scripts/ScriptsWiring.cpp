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
// Diagnostics only. Like RansomwareWiring.cpp, this is NOT one of the per-module
// Scripts headers the ODR note below forbids: it declares only ShadowStrike::Diag.
#include "../Diagnostics/DiagTrace.hpp"

#include <algorithm>
#include <cwctype>
#include <iterator>
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

bool JavaScriptScanner_ScanFile(const std::wstring& filePath,
                                std::uint32_t pid) noexcept;
bool VBScriptScanner_ScanFile(const std::wstring& filePath,
                              const std::wstring& lowerExt,
                              std::uint32_t pid) noexcept;
bool PythonScriptScanner_ScanFile(const std::wstring& filePath,
                                  const std::wstring& lowerExt) noexcept;
bool MacroDetector_ScanDocument(const std::wstring& filePath) noexcept;

// Task 177 kernel event fan-out, uniform signature per (module, event) so one
// table can hold every module. Each is implemented in the matching
// <Module>Wire.cpp and is noexcept (it shields its module there).
void PowerShellScanner_OnProcessNotify(std::uint32_t pid, std::uint32_t parentPid,
                                       const std::wstring& imagePath,
                                       const std::wstring& commandLine,
                                       bool isCreation) noexcept;
void PowerShellScanner_OnImageLoad(std::uint32_t pid, const std::wstring& imagePath,
                                   std::uintptr_t imageBase, std::size_t imageSize) noexcept;
void JavaScriptScanner_OnProcessNotify(std::uint32_t pid, std::uint32_t parentPid,
                                       const std::wstring& imagePath,
                                       const std::wstring& commandLine,
                                       bool isCreation) noexcept;
void JavaScriptScanner_OnImageLoad(std::uint32_t pid, const std::wstring& imagePath,
                                   std::uintptr_t imageBase, std::size_t imageSize) noexcept;
void MacroDetector_OnProcessNotify(std::uint32_t pid, std::uint32_t parentPid,
                                   const std::wstring& imagePath,
                                   const std::wstring& commandLine,
                                   bool isCreation) noexcept;
void MacroDetector_OnImageLoad(std::uint32_t pid, const std::wstring& imagePath,
                               std::uintptr_t imageBase, std::size_t imageSize) noexcept;
void AMSIIntegration_OnProcessNotify(std::uint32_t pid, std::uint32_t parentPid,
                                     const std::wstring& imagePath,
                                     const std::wstring& commandLine,
                                     bool isCreation) noexcept;
void AMSIIntegration_OnImageLoad(std::uint32_t pid, const std::wstring& imagePath,
                                 std::uintptr_t imageBase, std::size_t imageSize) noexcept;
void PythonScriptScanner_OnProcessNotify(std::uint32_t pid, std::uint32_t parentPid,
                                         const std::wstring& imagePath,
                                         const std::wstring& commandLine,
                                         bool isCreation) noexcept;
void PythonScriptScanner_OnImageLoad(std::uint32_t pid, const std::wstring& imagePath,
                                     std::uintptr_t imageBase, std::size_t imageSize) noexcept;
void VBScriptScanner_OnProcessNotify(std::uint32_t pid, std::uint32_t parentPid,
                                     const std::wstring& imagePath,
                                     const std::wstring& commandLine,
                                     bool isCreation) noexcept;
void VBScriptScanner_OnImageLoad(std::uint32_t pid, const std::wstring& imagePath,
                                 std::uintptr_t imageBase, std::size_t imageSize) noexcept;

}  // namespace ShadowStrike::Scripts::Wiring::Internal

namespace ShadowStrike::Scripts::Wiring {

bool InitializeScriptsSubsystem() noexcept {
    using namespace Internal;

    Utils::Logger::Info("ScriptsWiring: initializing subsystem");

    const bool js  = JavaScriptScanner_Init();
    const bool vbs = VBScriptScanner_Init();
    const bool py  = PythonScriptScanner_Init();
    const bool mac = MacroDetector_Init();

    // Surface which scanners failed so operators can act on a partial bring-up
    // instead of seeing only an "N/4 ready" count.
    if (!js)  Utils::Logger::Warn ("ScriptsWiring: JavaScriptScanner_Init failed");
    if (!vbs) Utils::Logger::Warn ("ScriptsWiring: VBScriptScanner_Init failed");
    if (!py)  Utils::Logger::Warn ("ScriptsWiring: PythonScriptScanner_Init failed");
    if (!mac) Utils::Logger::Warn ("ScriptsWiring: MacroDetector_Init failed");

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
    // Restrict the search to the final path component so that a directory
    // containing a dot (e.g. "C:\program files.evil\foo") cannot fool the
    // dispatcher into routing on an apparent extension that is really part
    // of a parent directory name.
    const auto sep = path.find_last_of(L"\\/");
    const std::size_t fileStart = (sep == std::wstring::npos) ? 0 : sep + 1;
    if (fileStart >= path.size()) return {};

    const auto dot = path.find_last_of(L'.');
    if (dot == std::wstring::npos || dot < fileStart || dot + 1 >= path.size()) {
        return {};
    }
    std::wstring ext = path.substr(dot);
    std::transform(ext.begin(), ext.end(), ext.begin(),
                   [](wchar_t c) -> wchar_t {
                       return static_cast<wchar_t>(std::towlower(c));
                   });
    return ext;
}

constexpr std::size_t kMaxDispatchPathChars = 32767;

[[nodiscard]] bool IsValidDispatchPath(const std::wstring& path) noexcept {
    if (path.empty() || path.size() > kMaxDispatchPathChars) {
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

bool DispatchFileScan(std::uint32_t pid,
                      const std::wstring& filePath) noexcept {
    if (!IsValidDispatchPath(filePath)) {
        return false;
    }

    const std::wstring ext = ExtractLowerExtension(filePath);
    if (ext.empty()) return false;

    using namespace Internal;

    // JavaScript family. The originating process is forwarded: the scanner stamps it on
    // the result, the alert and the telemetry. The VBScript, Python and macro scanners
    // below have no process-aware scan entry yet, so their reports carry no process
    // (task 180); RealTimeProtection still names it on the block it logs.
    if (ext == L".js" || ext == L".jse" || ext == L".mjs" || ext == L".cjs") {
        return JavaScriptScanner_ScanFile(filePath, pid);
    }

    // VBScript / Windows Script Host / HTA. The originating process is forwarded
    // (task 180) so a detection names the process that wrote the script.
    if (ext == L".vbs" || ext == L".vbe" || ext == L".wsf" ||
        ext == L".wsh" || ext == L".hta") {
        return VBScriptScanner_ScanFile(filePath, ext, pid);
    }

    // Python scripts / bytecode / wheels / eggs.
    // T3: Add .whl/.egg/.pyd routing as scanner handles them
    if (ext == L".py" || ext == L".pyw" ||
        ext == L".pyc" || ext == L".pyo" || ext == L".pyz" ||
        ext == L".whl" || ext == L".egg" || ext == L".pyd") {
        return PythonScriptScanner_ScanFile(filePath, ext);
    }

    // Microsoft Office macros (legacy + OpenXML + macro-enabled variants).
    // Also includes OpenDocument (.odt/.ods), Publisher (.pub), Visio (.vsd),
    // and XLL add-ins (.xll) which MacroDetector now handles.
    if (ext == L".doc" || ext == L".docm" || ext == L".docx" ||
        ext == L".xls" || ext == L".xlsm" || ext == L".xlsx" || ext == L".xlsb" ||
        ext == L".ppt" || ext == L".pptm" || ext == L".pptx" ||
        ext == L".rtf" || ext == L".dotm" || ext == L".xltm" ||
        ext == L".odt" || ext == L".ods" || ext == L".xll" ||
        ext == L".pub" || ext == L".vsd") {
        return MacroDetector_ScanDocument(filePath);
    }

    return false;
}

// ===========================================================================
// PROCESS-NOTIFY AND IMAGE-LOAD FAN-OUT (task 177)
// ===========================================================================
//
// One table per event. Each entry pairs a ScriptModule tag with the module's
// uniform-signature shim from <Module>Wire.cpp. Every shim is noexcept and
// shields its module, so one misbehaving module cannot stop the rest or take
// down the off-thread worker. See ScriptsWiring.hpp for why this restores
// detection and telemetry, NOT enforcement, and where each dispatch runs.
//
// THE PIN. The size static_assert catches a module added to the enum but not a
// table (or a table entry for a module not in the enum). It does NOT catch a
// table that duplicates one module and drops another, because the count stays
// right while coverage is wrong - so the FanOutCoverage accessors expose the
// real coverage and a unit test asserts it equals kScriptFanOutCoverageAll.

namespace {

using Detail::ScriptModule;

using ScriptProcessNotifyFn = void (*)(std::uint32_t, std::uint32_t,
                                       const std::wstring&, const std::wstring&,
                                       bool) noexcept;
using ScriptImageLoadFn = void (*)(std::uint32_t, const std::wstring&,
                                   std::uintptr_t, std::size_t) noexcept;

struct ProcessNotifyEntry { ScriptModule module; ScriptProcessNotifyFn fn; };
struct ImageLoadEntry     { ScriptModule module; ScriptImageLoadFn fn; };

constexpr ProcessNotifyEntry kProcessNotifyFanOut[] = {
    { ScriptModule::PowerShell, &Internal::PowerShellScanner_OnProcessNotify },
    { ScriptModule::JavaScript, &Internal::JavaScriptScanner_OnProcessNotify },
    { ScriptModule::Macro,      &Internal::MacroDetector_OnProcessNotify },
    { ScriptModule::Amsi,       &Internal::AMSIIntegration_OnProcessNotify },
    { ScriptModule::Python,     &Internal::PythonScriptScanner_OnProcessNotify },
    { ScriptModule::VBScript,   &Internal::VBScriptScanner_OnProcessNotify },
};
static_assert(std::size(kProcessNotifyFanOut) == Detail::kScriptFanOutModuleCount,
              "every script module must appear in the process-notify fan-out exactly once");

constexpr ImageLoadEntry kImageLoadFanOut[] = {
    { ScriptModule::PowerShell, &Internal::PowerShellScanner_OnImageLoad },
    { ScriptModule::JavaScript, &Internal::JavaScriptScanner_OnImageLoad },
    { ScriptModule::Macro,      &Internal::MacroDetector_OnImageLoad },
    { ScriptModule::Amsi,       &Internal::AMSIIntegration_OnImageLoad },
    { ScriptModule::Python,     &Internal::PythonScriptScanner_OnImageLoad },
    { ScriptModule::VBScript,   &Internal::VBScriptScanner_OnImageLoad },
};
static_assert(std::size(kImageLoadFanOut) == Detail::kScriptFanOutModuleCount,
              "every script module must appear in the image-load fan-out exactly once");

[[nodiscard]] std::uint32_t CoverageOf(const ProcessNotifyEntry (&table)[Detail::kScriptFanOutModuleCount]) noexcept {
    std::uint32_t mask = 0;
    for (const auto& e : table) mask |= (std::uint32_t{1} << static_cast<unsigned>(e.module));
    return mask;
}
[[nodiscard]] std::uint32_t CoverageOf(const ImageLoadEntry (&table)[Detail::kScriptFanOutModuleCount]) noexcept {
    std::uint32_t mask = 0;
    for (const auto& e : table) mask |= (std::uint32_t{1} << static_cast<unsigned>(e.module));
    return mask;
}

}  // namespace

void DispatchProcessNotify(std::uint32_t pid,
                           std::uint32_t parentPid,
                           const std::wstring& imagePath,
                           const std::wstring& commandLine,
                           bool isCreation) noexcept {
    SS_DIAG_SCOPE("ScriptFanOut", isCreation ? "procnotify-create" : "procnotify-exit");
    for (const auto& entry : kProcessNotifyFanOut) {
        entry.fn(pid, parentPid, imagePath, commandLine, isCreation);
    }
}

void DispatchImageLoad(std::uint32_t pid,
                       const std::wstring& imagePath,
                       std::uintptr_t imageBase,
                       std::size_t imageSize) noexcept {
    SS_DIAG_SCOPE("ScriptFanOut", "imageload");
    for (const auto& entry : kImageLoadFanOut) {
        entry.fn(pid, imagePath, imageBase, imageSize);
    }
}

std::uint32_t ProcessNotifyFanOutCoverage() noexcept {
    return CoverageOf(kProcessNotifyFanOut);
}

std::uint32_t ImageLoadFanOutCoverage() noexcept {
    return CoverageOf(kImageLoadFanOut);
}

}  // namespace ShadowStrike::Scripts::Wiring
