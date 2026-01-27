/**
 * ============================================================================
 * ShadowStrike NGAV - SERVICE INSTALLATION MANAGER
 * ============================================================================
 *
 * @file ServiceInstaller.hpp
 * @brief Utilities for installing, uninstalling, and configuring the ShadowStrike
 *        Windows Service. Handles interaction with the Service Control Manager (SCM).
 *
 * FEATURES:
 * - Service registration/deletion
 * - Recovery configuration (restart on failure)
 * - Security descriptor configuration
 * - Dependency management
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <string>
#include <string_view>
#include <vector>
#include <optional>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#endif

namespace ShadowStrike {
namespace Service {

// ============================================================================
// CONFIGURATION STRUCTURES
// ============================================================================

/**
 * @brief Configuration parameters for service installation
 */
struct ServiceConfig {
    std::wstring name;              ///< Internal service name
    std::wstring displayName;       ///< Visible name in Services.msc
    std::wstring description;       ///< Description text
    std::wstring binaryPath;        ///< Path to the executable
    std::wstring account;           ///< Service account (empty for LocalSystem)
    std::wstring password;          ///< Account password
    std::vector<std::wstring> dependencies; ///< List of service dependencies

    DWORD startType = SERVICE_AUTO_START;
    DWORD errorControl = SERVICE_ERROR_NORMAL;
    bool delayedStart = false;      ///< Enable delayed auto-start
    bool interactive = false;       ///< Allow interaction with desktop (legacy)

    // Recovery options
    bool enableRecovery = true;
    uint32_t resetPeriodDays = 1;   ///< Reset failure count after N days
    uint32_t restartDelayMs = 60000;///< Wait 1 min before restart
};

// ============================================================================
// SERVICE INSTALLER CLASS
// ============================================================================

/**
 * @class ServiceInstaller
 * @brief Static utility class for managing Windows Service registration.
 */
class ServiceInstaller final {
public:
    // ========================================================================
    // PUBLIC API
    // ========================================================================

    /**
     * @brief Install the service with default configuration
     * @return true if successful
     */
    [[nodiscard]] static bool Install();

    /**
     * @brief Install the service with custom configuration
     * @param config Service configuration details
     * @return true if successful
     */
    [[nodiscard]] static bool Install(const ServiceConfig& config);

    /**
     * @brief Remove the service from the system
     * @return true if successful
     */
    [[nodiscard]] static bool Uninstall();

    /**
     * @brief Reinstall the service (Uninstall + Install)
     * @return true if successful
     */
    [[nodiscard]] static bool Reinstall();

    /**
     * @brief Check if the service is currently installed
     * @return true if service exists in SCM
     */
    [[nodiscard]] static bool IsInstalled();

    /**
     * @brief Start the service
     * @return true if started successfully
     */
    [[nodiscard]] static bool Start();

    /**
     * @brief Stop the service
     * @return true if stopped successfully
     */
    [[nodiscard]] static bool Stop();

    // Deleted constructor (static class)
    ServiceInstaller() = delete;
    ~ServiceInstaller() = delete;
    ServiceInstaller(const ServiceInstaller&) = delete;
    ServiceInstaller& operator=(const ServiceInstaller&) = delete;

private:
    // ========================================================================
    // INTERNAL HELPERS
    // ========================================================================

    [[nodiscard]] static bool ConfigureRecovery(SC_HANDLE hService, const ServiceConfig& config);
    [[nodiscard]] static bool ConfigureDescription(SC_HANDLE hService, const std::wstring& description);
    [[nodiscard]] static bool ConfigureDelayedAutoStart(SC_HANDLE hService, bool delayed);
    [[nodiscard]] static std::wstring FormatDependencies(const std::vector<std::wstring>& deps);
};

} // namespace Service
} // namespace ShadowStrike
