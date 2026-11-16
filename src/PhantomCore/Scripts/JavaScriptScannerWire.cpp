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
#include <filesystem>

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

bool JavaScriptScanner_ScanFile(const std::wstring& filePath,
                                std::uint32_t pid) noexcept {
    try {
        const auto result = JavaScriptScanner::Instance().ScanFile(
            std::filesystem::path{filePath}, pid);
        return result.isMalicious;
    } catch (const std::exception& e) {
        Utils::Logger::Warn("ScriptsWiring: JS ScanFile exception: {}", e.what());
    } catch (...) {}
    return false;
}

// Task 177 process-notify / image-load fan-out. Uniform signature across all six
// modules so ScriptsWiring can hold them in one table; JavaScriptScanner keys on
// the command line and ignores parentPid.
void JavaScriptScanner_OnProcessNotify(std::uint32_t pid,
                                       std::uint32_t parentPid,
                                       const std::wstring& imagePath,
                                       const std::wstring& commandLine,
                                       bool isCreation) noexcept {
    (void)parentPid;
    try {
        JavaScriptScanner::Instance().OnKernelProcessNotify(
            pid, imagePath, commandLine, isCreation);
    } catch (const std::exception& e) {
        Utils::Logger::Warn("ScriptsWiring: JS OnKernelProcessNotify exception: {}", e.what());
    } catch (...) {}
}

void JavaScriptScanner_OnImageLoad(std::uint32_t pid,
                                   const std::wstring& imagePath,
                                   std::uintptr_t imageBase,
                                   std::size_t imageSize) noexcept {
    try {
        JavaScriptScanner::Instance().OnKernelImageLoad(
            pid, imagePath, static_cast<std::uint64_t>(imageBase), imageSize);
    } catch (const std::exception& e) {
        Utils::Logger::Warn("ScriptsWiring: JS OnKernelImageLoad exception: {}", e.what());
    } catch (...) {}
}

}  // namespace ShadowStrike::Scripts::Wiring::Internal
