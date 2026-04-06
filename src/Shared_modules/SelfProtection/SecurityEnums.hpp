/**
 * @file SecurityEnums.hpp
 * @brief Common enum types shared across Security/ module headers.
 *
 * Multiple Security headers (TamperProtection, ProcessProtection, RegistryProtection,
 * CertificateValidator, etc.) each define their own identical copy of ModuleStatus.
 * This header and all defining headers use #ifndef SHADOWSTRIKE_SECURITY_MODULESTATUS_DEFINED
 * guards to ensure only the first inclusion defines the enum.
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
