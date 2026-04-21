/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Per-module wiring shim for WannaCryDetector. Isolated in its own TU because the
 * RansomwareProtection module headers pair-wise redefine the same enums in
 * the ShadowStrike::Ransomware namespace, so only one may be included per TU.
 */
#include "pch.h"
#include "WannaCryDetector.hpp"
#include "../Utils/Logger.hpp"

namespace ShadowStrike::Ransomware::Wiring::Internal {

bool WannaCryDetector_Init() noexcept {
    try {
        if (WannaCryDetector::Instance().Initialize()) {
            return true;
        }
        Utils::Logger::Warn("RansomwareWiring: WannaCryDetector::Initialize returned false");
    } catch (const std::exception& e) {
        Utils::Logger::Error("RansomwareWiring: WannaCryDetector init exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("RansomwareWiring: WannaCryDetector init unknown exception");
    }
    return false;
}

void WannaCryDetector_Shutdown() noexcept {
    try {
        WannaCryDetector::Instance().Shutdown();
    } catch (const std::exception& e) {
        Utils::Logger::Error("RansomwareWiring: WannaCryDetector shutdown exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("RansomwareWiring: WannaCryDetector shutdown unknown exception");
    }
}

// ---------------------------------------------------------------------------
// WannaCry has a narrow kernel-hot-path surface — only process create is
// relevant (SMB events go through a separate network handler that is not
// yet plumbed into user-mode). File write/rename signals are consumed
// indirectly through RansomwareDetector's sub-detector chain.
// ---------------------------------------------------------------------------

void WannaCryDetector_OnProcessCreated(std::uint32_t pid,
                                       const std::wstring& imagePath,
                                       const std::wstring& commandLine) noexcept {
    try {
        WannaCryDetector::Instance().OnProcessCreated(
            pid, std::wstring_view{imagePath}, std::wstring_view{commandLine});
    } catch (const std::exception& e) {
        Utils::Logger::Warn("RansomwareWiring: WannaCry OnProcessCreated exception: {}", e.what());
    } catch (...) {}
}

}  // namespace ShadowStrike::Ransomware::Wiring::Internal
