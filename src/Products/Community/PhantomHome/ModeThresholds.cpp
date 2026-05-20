/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file ModeThresholds.cpp
 * @brief Implementation of ApplyModeThresholds — the canonical authority for
 *        per-mode sensitivity/AI/block-on-suspicion key values.
 */

#include "pch.h"

#include "ModeThresholds.hpp"

#include "../../../PhantomCore/Config/ConfigManager.hpp"
#include "../../../PhantomCore/Utils/Logger.hpp"

#include <string>

namespace ShadowStrike {
namespace Products {
namespace Home {

namespace {

constexpr const wchar_t* kLogCategory = L"ModeThresholds";

// Threshold constants per mode.
// These are the single source of truth referenced by documentation, IPC
// layer, and any future policy override validation logic.

struct ModeThresholdValues {
    int32_t sensitivity;          // 0-100
    double  aiConfidenceThreshold; // 0.0-1.0
    bool    blockOnSuspicion;
    bool    detectOnly;
};

[[nodiscard]] constexpr ModeThresholdValues ValuesFor(ProtectionMode mode) noexcept {
    switch (mode) {
        case ProtectionMode::Passive:
            return {25, 0.85, false, true};
        case ProtectionMode::Balanced:
            return {60, 0.70, true,  false};
        case ProtectionMode::Aggressive:
            return {90, 0.55, true,  false};
        case ProtectionMode::Off:
            // Caller must guard against Off before reaching here.
            return {0, 1.0, false, true};
    }
    // Unreachable with a valid enum; return safe defaults.
    return {0, 1.0, false, true};
}

}  // namespace

bool ApplyModeThresholds(std::string_view moduleName, ProtectionMode mode) {
    // Defense in depth: the orchestrator passes ModuleDescriptor::name which
    // is validated on RegisterModule (non-empty), but ApplyModeThresholds is
    // also reachable as the fall-back from descriptor.setMode == nullptr,
    // and may eventually be reached from IPC / policy layers. A malformed
    // module name (empty, containing '/', '\\', whitespace control chars,
    // or absurdly long) would produce a corrupted ConfigManager key path
    // such as "Home//Sensitivity" or "Home/a/b/Sensitivity", which would
    // either silently desync from the orchestrator's key convention or
    // collide with unrelated subtrees.
    constexpr std::size_t kMaxModuleNameLen = 128;
    if (moduleName.empty()) {
        SS_LOG_ERROR(kLogCategory,
            L"ApplyModeThresholds: empty moduleName rejected");
        return false;
    }
    if (moduleName.size() > kMaxModuleNameLen) {
        SS_LOG_ERROR(kLogCategory,
            L"ApplyModeThresholds: moduleName length %zu exceeds %zu; rejected",
            moduleName.size(), kMaxModuleNameLen);
        return false;
    }
    for (const char c : moduleName) {
        const unsigned char uc = static_cast<unsigned char>(c);
        if (uc < 0x20 || uc == 0x7F || c == '/' || c == '\\') {
            SS_LOG_ERROR(kLogCategory,
                L"ApplyModeThresholds: moduleName contains invalid character 0x%02X; rejected",
                static_cast<unsigned>(uc));
            return false;
        }
    }

    if (mode == ProtectionMode::Off) {
        SS_LOG_ERROR(kLogCategory,
            L"ApplyModeThresholds '%hs': called with ProtectionMode::Off — "
            L"Off must be handled by the orchestrator's disable path, not this helper",
            std::string(moduleName).c_str());
        return false;
    }

    auto& cfg = ::ShadowStrike::Config::ConfigManager::Instance();

    const std::string prefix = "Home/" + std::string(moduleName) + "/";
    const ModeThresholdValues v = ValuesFor(mode);

    bool allOk = true;

    // --- Sensitivity ---
    if (!cfg.SetValue<int32_t>(prefix + "Sensitivity", v.sensitivity)) {
        SS_LOG_ERROR(kLogCategory,
            L"ApplyModeThresholds '%hs' [%hs]: SetValue Sensitivity=%d failed",
            std::string(moduleName).c_str(),
            std::string(HomeProductOrchestrator::ToString(mode)).c_str(),
            v.sensitivity);
        allOk = false;
    }

    // --- AIConfidenceThreshold ---
    if (!cfg.SetValue<double>(prefix + "AIConfidenceThreshold",
                              v.aiConfidenceThreshold)) {
        SS_LOG_ERROR(kLogCategory,
            L"ApplyModeThresholds '%hs' [%hs]: SetValue AIConfidenceThreshold=%.2f failed",
            std::string(moduleName).c_str(),
            std::string(HomeProductOrchestrator::ToString(mode)).c_str(),
            v.aiConfidenceThreshold);
        allOk = false;
    }

    // --- BlockOnSuspicion ---
    if (!cfg.SetValue<bool>(prefix + "BlockOnSuspicion", v.blockOnSuspicion)) {
        SS_LOG_ERROR(kLogCategory,
            L"ApplyModeThresholds '%hs' [%hs]: SetValue BlockOnSuspicion=%d failed",
            std::string(moduleName).c_str(),
            std::string(HomeProductOrchestrator::ToString(mode)).c_str(),
            v.blockOnSuspicion ? 1 : 0);
        allOk = false;
    }

    // --- DetectOnly ---
    if (!cfg.SetValue<bool>(prefix + "DetectOnly", v.detectOnly)) {
        SS_LOG_ERROR(kLogCategory,
            L"ApplyModeThresholds '%hs' [%hs]: SetValue DetectOnly=%d failed",
            std::string(moduleName).c_str(),
            std::string(HomeProductOrchestrator::ToString(mode)).c_str(),
            v.detectOnly ? 1 : 0);
        allOk = false;
    }

    if (allOk) {
        SS_LOG_INFO(kLogCategory,
            L"ApplyModeThresholds '%hs' -> %hs applied: "
            L"Sensitivity=%d, AIThreshold=%.2f, BlockOnSuspicion=%d, DetectOnly=%d",
            std::string(moduleName).c_str(),
            std::string(HomeProductOrchestrator::ToString(mode)).c_str(),
            v.sensitivity,
            v.aiConfidenceThreshold,
            v.blockOnSuspicion ? 1 : 0,
            v.detectOnly ? 1 : 0);
    } else {
        SS_LOG_ERROR(kLogCategory,
            L"ApplyModeThresholds '%hs' -> %hs: one or more threshold writes failed; "
            L"module may run with partially updated configuration",
            std::string(moduleName).c_str(),
            std::string(HomeProductOrchestrator::ToString(mode)).c_str());
    }

    return allOk;
}

}  // namespace Home
}  // namespace Products
}  // namespace ShadowStrike
