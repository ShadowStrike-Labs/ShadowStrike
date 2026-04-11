/**
 * @file SecurityEnums.hpp
 * @brief Canonical ownership point for shared self-protection enums.
 *
 * Security modules that need a common lifecycle state must include this header
 * instead of re-declaring ModuleStatus in their own public headers.
 *
 * @copyright Copyright (C) 2026 ShadowStrike Security
 * @license AGPL-3.0-or-later
 */
#pragma once
#include <cstdint>

namespace ShadowStrike {
namespace Security {

#ifndef SHADOWSTRIKE_SECURITY_MODULESTATUS_DEFINED
#define SHADOWSTRIKE_SECURITY_MODULESTATUS_DEFINED
/**
 * @brief Lifecycle status of a security module.
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Degraded        = 3,    ///< Running with reduced functionality
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};
#endif // SHADOWSTRIKE_SECURITY_MODULESTATUS_DEFINED

} // namespace Security
} // namespace ShadowStrike
