/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */
#pragma once

/// @file ForensicsCommon.hpp
/// @brief Shared types for the Forensics subsystem.
///
/// All Forensics module headers include this instead of defining
/// ModuleStatus independently, preventing ODR violations when
/// multiple Forensics modules are used in the same translation unit.

#include <cstdint>

// This header is always included from within namespace ShadowStrike::Forensics.
// Do NOT add a namespace wrapper — the enclosing header provides it.

/// @brief Lifecycle state for any Forensics module.
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Degraded        = 3,  ///< General degraded state (most modules)
    Analyzing       = 3,  ///< Alias — active analysis phase (TimelineAnalyzer)
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};
