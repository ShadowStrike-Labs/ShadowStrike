/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Per-module wiring shim for HoneypotManager. Isolated in its own TU because the
 * RansomwareProtection module headers pair-wise redefine the same enums in
 * the ShadowStrike::Ransomware namespace, so only one may be included per TU.
 */
#include "pch.h"
#include "HoneypotManager.hpp"
#include "../Utils/Logger.hpp"

namespace ShadowStrike::Ransomware::Wiring::Internal {

bool HoneypotManager_Init() noexcept {
    try {
        if (HoneypotManager::Instance().Initialize()) {
            return true;
        }
        Utils::Logger::Warn("RansomwareWiring: HoneypotManager::Initialize returned false");
    } catch (const std::exception& e) {
        Utils::Logger::Error("RansomwareWiring: HoneypotManager init exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("RansomwareWiring: HoneypotManager init unknown exception");
    }
    return false;
}

void HoneypotManager_Shutdown() noexcept {
    try {
        HoneypotManager::Instance().Shutdown();
    } catch (const std::exception& e) {
        Utils::Logger::Error("RansomwareWiring: HoneypotManager shutdown exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("RansomwareWiring: HoneypotManager shutdown unknown exception");
    }
}

// ---------------------------------------------------------------------------
// Kernel event dispatch for HoneypotManager.
//
// ProcessKernelNotification is the primary block-gate: if a process touches
// a registered honeypot path the manager returns `true` so the caller can
// translate that into a kernel Block verdict BEFORE the minifilter lets the
// I/O complete. The other two entry points feed process / image context
// that the manager uses for attribution and whitelisting.
// ---------------------------------------------------------------------------

bool HoneypotManager_OnKernelNotification(const std::wstring& filePath,
                                          std::uint32_t pid,
                                          std::uint32_t threadId,
                                          std::uint8_t accessTypeRaw) noexcept {
    try {
        const auto accessType = (accessTypeRaw <= static_cast<uint8_t>(HoneypotAccessType::SetInfo))
            ? static_cast<HoneypotAccessType>(accessTypeRaw)
            : HoneypotAccessType::Unknown;
        return HoneypotManager::Instance().ProcessKernelNotification(
            std::wstring_view{filePath}, pid, threadId, accessType);
    } catch (const std::exception& e) {
        Utils::Logger::Warn("RansomwareWiring: HoneypotManager kernel notify exception: {}",
                            e.what());
    } catch (...) {}
    return false;
}

void HoneypotManager_OnProcessNotify(std::uint32_t pid,
                                     std::uint32_t parentPid,
                                     const std::wstring& imagePath,
                                     bool isCreation) noexcept {
    try {
        HoneypotManager::Instance().OnKernelProcessNotify(
            pid, parentPid, std::wstring_view{imagePath}, isCreation);
    } catch (const std::exception& e) {
        Utils::Logger::Warn("RansomwareWiring: HoneypotManager OnKernelProcessNotify exception: {}",
                            e.what());
    } catch (...) {}
}

void HoneypotManager_OnImageLoad(std::uint32_t pid,
                                 const std::wstring& imagePath,
                                 std::uintptr_t imageBase) noexcept {
    try {
        HoneypotManager::Instance().OnKernelImageLoad(
            pid, std::wstring_view{imagePath}, imageBase);
    } catch (const std::exception& e) {
        Utils::Logger::Warn("RansomwareWiring: HoneypotManager OnKernelImageLoad exception: {}",
                            e.what());
    } catch (...) {}
}

}  // namespace ShadowStrike::Ransomware::Wiring::Internal
