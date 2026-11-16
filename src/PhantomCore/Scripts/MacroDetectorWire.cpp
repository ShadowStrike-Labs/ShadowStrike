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

bool MacroDetector_ScanDocument(const std::wstring& filePath, std::uint32_t pid) noexcept {
    try {
        const auto result = MacroDetector::Instance().ScanDocument(
            std::filesystem::path{filePath}, pid);
        return result.isMalicious;
    } catch (const std::exception& e) {
        Utils::Logger::Warn("ScriptsWiring: Macro ScanDocument exception: {}", e.what());
    } catch (...) {}
    return false;
}

// Task 177 process-notify / image-load fan-out. MacroDetector flags Office hosts
// launched with macro-enabled document arguments, so it reads the command line;
// it ignores parentPid.
void MacroDetector_OnProcessNotify(std::uint32_t pid,
                                   std::uint32_t parentPid,
                                   const std::wstring& imagePath,
                                   const std::wstring& commandLine,
                                   bool isCreation) noexcept {
    (void)parentPid;
    try {
        MacroDetector::Instance().OnKernelProcessNotify(
            pid, imagePath, commandLine, isCreation);
    } catch (const std::exception& e) {
        Utils::Logger::Warn("ScriptsWiring: Macro OnKernelProcessNotify exception: {}", e.what());
    } catch (...) {}
}

void MacroDetector_OnImageLoad(std::uint32_t pid,
                               const std::wstring& imagePath,
                               std::uintptr_t imageBase,
                               std::size_t imageSize) noexcept {
    try {
        MacroDetector::Instance().OnKernelImageLoad(
            pid, imagePath, static_cast<std::uint64_t>(imageBase), imageSize);
    } catch (const std::exception& e) {
        Utils::Logger::Warn("ScriptsWiring: Macro OnKernelImageLoad exception: {}", e.what());
    } catch (...) {}
}

}  // namespace ShadowStrike::Scripts::Wiring::Internal
