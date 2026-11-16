/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Per-module wiring shim for AMSIIntegration. Isolated in its own TU to match
 * the Ransomware pattern and guard against ODR collisions across the Scripts
 * module headers.
 *
 * Only the kernel process-notify / image-load fan-out lives here (task 177).
 * AMSIIntegration's Init/Shutdown are owned by AntivirusService, not the
 * ScriptsWiring subsystem, so they are deliberately absent.
 *
 * The EXIT branch matters here beyond detection: AMSIIntegration is the only
 * eraser of its per-process bypass record, so its OnKernelProcessNotify must be
 * reached on termination too (isCreation == false) or that record leaks when the
 * pid is reused. The fan-out therefore never gates this module on the create
 * branch, and HasInstance() is checked so a teardown race is a quiet no-op.
 */
#include "pch.h"
#include "AMSIIntegration.hpp"
#include "../Utils/Logger.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

namespace ShadowStrike::Scripts::Wiring::Internal {

void AMSIIntegration_OnProcessNotify(std::uint32_t pid,
                                     std::uint32_t parentPid,
                                     const std::wstring& imagePath,
                                     const std::wstring& commandLine,
                                     bool isCreation) noexcept {
    (void)parentPid;
    try {
        if (!AMSIIntegration::HasInstance()) return;
        AMSIIntegration::Instance().OnKernelProcessNotify(
            pid, imagePath, commandLine, isCreation);
    } catch (const std::exception& e) {
        Utils::Logger::Warn("ScriptsWiring: AMSI OnKernelProcessNotify exception: {}", e.what());
    } catch (...) {}
}

void AMSIIntegration_OnImageLoad(std::uint32_t pid,
                                 const std::wstring& imagePath,
                                 std::uintptr_t imageBase,
                                 std::size_t imageSize) noexcept {
    try {
        if (!AMSIIntegration::HasInstance()) return;
        AMSIIntegration::Instance().OnKernelImageLoad(
            pid, imagePath, static_cast<std::uint64_t>(imageBase), imageSize);
    } catch (const std::exception& e) {
        Utils::Logger::Warn("ScriptsWiring: AMSI OnKernelImageLoad exception: {}", e.what());
    } catch (...) {}
}

}  // namespace ShadowStrike::Scripts::Wiring::Internal
