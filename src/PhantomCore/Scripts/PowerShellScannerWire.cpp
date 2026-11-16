/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Per-module wiring shim for PowerShellScanner. Isolated in its own TU to match
 * the Ransomware pattern and guard against ODR collisions across the Scripts
 * module headers.
 *
 * Only the kernel process-notify / image-load fan-out lives here (task 177).
 * PowerShellScanner's Init/Shutdown are owned by AntivirusService, not the
 * ScriptsWiring subsystem, so they are deliberately absent - this file adds the
 * feed the module was missing, not a second lifecycle.
 */
#include "pch.h"
#include "PowerShellScanner.hpp"
#include "../Utils/Logger.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

namespace ShadowStrike::Scripts::Wiring::Internal {

// PowerShellScanner's highest-value detection is the encoded-command scan, so it
// reads the command line; it ignores parentPid. Detection and telemetry only:
// a conviction asks the kernel to block through the broken 158/175 transport,
// which the kernel discards.
void PowerShellScanner_OnProcessNotify(std::uint32_t pid,
                                       std::uint32_t parentPid,
                                       const std::wstring& imagePath,
                                       const std::wstring& commandLine,
                                       bool isCreation) noexcept {
    (void)parentPid;
    try {
        PowerShellScanner::getInstance().OnKernelProcessNotify(
            pid, imagePath, commandLine, isCreation);
    } catch (const std::exception& e) {
        Utils::Logger::Warn("ScriptsWiring: PowerShell OnKernelProcessNotify exception: {}", e.what());
    } catch (...) {}
}

void PowerShellScanner_OnImageLoad(std::uint32_t pid,
                                   const std::wstring& imagePath,
                                   std::uintptr_t imageBase,
                                   std::size_t imageSize) noexcept {
    try {
        PowerShellScanner::getInstance().OnKernelImageLoad(
            pid, imagePath, static_cast<std::uint64_t>(imageBase), imageSize);
    } catch (const std::exception& e) {
        Utils::Logger::Warn("ScriptsWiring: PowerShell OnKernelImageLoad exception: {}", e.what());
    } catch (...) {}
}

}  // namespace ShadowStrike::Scripts::Wiring::Internal
