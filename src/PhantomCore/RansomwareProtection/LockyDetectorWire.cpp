/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Per-module wiring shim for LockyDetector. Isolated in its own TU because the
 * RansomwareProtection module headers pair-wise redefine the same enums in
 * the ShadowStrike::Ransomware namespace, so only one may be included per TU.
 */
#include "pch.h"
#include "LockyDetector.hpp"
#include "../Utils/Logger.hpp"

namespace ShadowStrike::Ransomware::Wiring::Internal {

bool LockyDetector_Init() noexcept {
    try {
        if (LockyDetector::Instance().Initialize()) {
            return true;
        }
        Utils::Logger::Warn("RansomwareWiring: LockyDetector::Initialize returned false");
    } catch (const std::exception& e) {
        Utils::Logger::Error("RansomwareWiring: LockyDetector init exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("RansomwareWiring: LockyDetector init unknown exception");
    }
    return false;
}

void LockyDetector_Shutdown() noexcept {
    try {
        LockyDetector::Instance().Shutdown();
    } catch (const std::exception& e) {
        Utils::Logger::Error("RansomwareWiring: LockyDetector shutdown exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("RansomwareWiring: LockyDetector shutdown unknown exception");
    }
}

// ---------------------------------------------------------------------------
// Kernel event dispatch for LockyDetector. Detection results are swallowed:
// LockyDetector feeds its own detection callback on an internal pool, and
// the RansomwareDetector composite score is updated separately through the
// detector chain — we do not need to surface the optional here.
// ---------------------------------------------------------------------------

void LockyDetector_OnFileWrite(std::uint32_t pid,
                               const std::wstring& filePath,
                               std::size_t dataSize) noexcept {
    try {
        // Entropy == 0.0 when the write payload is not available at the
        // user-mode message boundary. LockyDetector handles that by relying
        // on path/extension signals and the size burst tracker.
        (void)LockyDetector::Instance().OnFileWrite(
            pid, std::wstring_view{filePath}, dataSize, 0.0);
    } catch (const std::exception& e) {
        Utils::Logger::Warn("RansomwareWiring: Locky OnFileWrite exception: {}", e.what());
    } catch (...) {}
}

void LockyDetector_OnFileRename(std::uint32_t pid,
                                const std::wstring& oldPath,
                                const std::wstring& newPath) noexcept {
    try {
        (void)LockyDetector::Instance().OnFileRename(
            pid, std::wstring_view{oldPath}, std::wstring_view{newPath});
    } catch (const std::exception& e) {
        Utils::Logger::Warn("RansomwareWiring: Locky OnFileRename exception: {}", e.what());
    } catch (...) {}
}

void LockyDetector_OnProcessNotify(std::uint32_t pid,
                                   std::uint32_t parentPid,
                                   const std::wstring& imagePath,
                                   bool isCreation) noexcept {
    try {
        LockyDetector::Instance().OnKernelProcessNotify(
            pid, parentPid, std::wstring_view{imagePath}, isCreation);
    } catch (const std::exception& e) {
        Utils::Logger::Warn("RansomwareWiring: Locky OnKernelProcessNotify exception: {}", e.what());
    } catch (...) {}
}

void LockyDetector_OnImageLoad(std::uint32_t pid,
                               const std::wstring& imagePath,
                               std::uintptr_t imageBase) noexcept {
    try {
        LockyDetector::Instance().OnKernelImageLoad(
            pid, std::wstring_view{imagePath}, imageBase);
    } catch (const std::exception& e) {
        Utils::Logger::Warn("RansomwareWiring: Locky OnKernelImageLoad exception: {}", e.what());
    } catch (...) {}
}

}  // namespace ShadowStrike::Ransomware::Wiring::Internal
