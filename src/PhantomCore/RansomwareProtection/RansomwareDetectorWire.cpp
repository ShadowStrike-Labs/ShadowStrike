/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Per-module wiring shim for RansomwareDetector. Isolated in its own TU because the
 * RansomwareProtection module headers pair-wise redefine the same enums in
 * the ShadowStrike::Ransomware namespace, so only one may be included per TU.
 */
#include "pch.h"
#include "RansomwareDetector.hpp"
#include "../Utils/Logger.hpp"

namespace ShadowStrike::Ransomware::Wiring::Internal {

bool RansomwareDetector_Init() noexcept {
    try {
        if (RansomwareDetector::Instance().Initialize()) {
            return true;
        }
        Utils::Logger::Warn("RansomwareWiring: RansomwareDetector::Initialize returned false");
    } catch (const std::exception& e) {
        Utils::Logger::Error("RansomwareWiring: RansomwareDetector init exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("RansomwareWiring: RansomwareDetector init unknown exception");
    }
    return false;
}

void RansomwareDetector_Shutdown() noexcept {
    try {
        RansomwareDetector::Instance().Shutdown();
    } catch (const std::exception& e) {
        Utils::Logger::Error("RansomwareWiring: RansomwareDetector shutdown exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("RansomwareWiring: RansomwareDetector shutdown unknown exception");
    }
}

// ---------------------------------------------------------------------------
// Kernel event dispatch — each function is the single authoritative bridge
// between the IPC layer and RansomwareDetector for that event. All paths
// wrap the real call in try/catch because kernel handlers must never throw.
// ---------------------------------------------------------------------------

bool RansomwareDetector_OnFileWrite(std::uint32_t pid,
                                    const std::wstring& filePath) noexcept {
    try {
        // Empty buffer: FILE_SCAN_REQUEST carries only path+pid. The detector
        // still runs path/pid heuristics, extension analysis, and burst-write
        // tracking without the contents.
        return RansomwareDetector::Instance().AnalyzeWrite(
            pid, std::span<const std::uint8_t>{}, std::wstring_view{filePath});
    } catch (const std::exception& e) {
        Utils::Logger::Warn("RansomwareWiring: AnalyzeWrite exception: {}", e.what());
    } catch (...) {}
    return false;
}

bool RansomwareDetector_OnFileRename(std::uint32_t pid,
                                     const std::wstring& oldPath,
                                     const std::wstring& newPath) noexcept {
    try {
        return RansomwareDetector::Instance().AnalyzeRename(pid, oldPath, newPath);
    } catch (const std::exception& e) {
        Utils::Logger::Warn("RansomwareWiring: AnalyzeRename exception: {}", e.what());
    } catch (...) {}
    return false;
}

bool RansomwareDetector_OnFileDelete(std::uint32_t pid,
                                     const std::wstring& filePath) noexcept {
    try {
        return RansomwareDetector::Instance().AnalyzeDelete(pid, std::wstring_view{filePath});
    } catch (const std::exception& e) {
        Utils::Logger::Warn("RansomwareWiring: AnalyzeDelete exception: {}", e.what());
    } catch (...) {}
    return false;
}

void RansomwareDetector_OnProcessNotify(std::uint32_t pid,
                                        const std::wstring& imagePath,
                                        const std::wstring& commandLine,
                                        bool isCreation) noexcept {
    try {
        RansomwareDetector::Instance().OnKernelProcessNotify(
            pid, std::wstring_view{imagePath}, std::wstring_view{commandLine}, isCreation);
    } catch (const std::exception& e) {
        Utils::Logger::Warn("RansomwareWiring: OnKernelProcessNotify exception: {}", e.what());
    } catch (...) {}
}

void RansomwareDetector_OnImageLoad(std::uint32_t pid,
                                    const std::wstring& imagePath,
                                    std::uintptr_t imageBase,
                                    std::size_t imageSize) noexcept {
    try {
        RansomwareDetector::Instance().OnKernelImageLoad(
            pid, std::wstring_view{imagePath},
            static_cast<std::uint64_t>(imageBase), imageSize);
    } catch (const std::exception& e) {
        Utils::Logger::Warn("RansomwareWiring: OnKernelImageLoad exception: {}", e.what());
    } catch (...) {}
}

bool RansomwareDetector_IsHoneypotPath(const std::wstring& filePath) noexcept {
    try {
        return RansomwareDetector::Instance().IsHoneypot(std::wstring_view{filePath});
    } catch (...) {}
    return false;
}

void RansomwareDetector_OnHoneypotTouched(std::uint32_t pid,
                                          const std::wstring& filePath) noexcept {
    try {
        RansomwareDetector::Instance().OnHoneypotTouched(pid, filePath);
    } catch (const std::exception& e) {
        Utils::Logger::Warn("RansomwareWiring: OnHoneypotTouched exception: {}", e.what());
    } catch (...) {}
}

}  // namespace ShadowStrike::Ransomware::Wiring::Internal
