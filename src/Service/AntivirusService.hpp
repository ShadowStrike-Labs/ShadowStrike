/**
 * ============================================================================
 * ShadowStrike NGAV - MAIN SERVICE ENTRY POINT
 * ============================================================================
 *
 * @file AntivirusService.hpp
 * @brief Enterprise-grade Windows Service implementation for ShadowStrike NGAV.
 *        Orchestrates the lifecycle of all security modules, handles IPC,
 *        and manages service control events.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * COMPLIANCE: SOC2, ISO 27001, PCI-DSS
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <atomic>
#include <functional>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#endif

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
namespace ShadowStrike {
    namespace Service {
        class AntivirusServiceImpl;
    }
}

namespace ShadowStrike {
namespace Service {

// ============================================================================
// CONSTANTS
// ============================================================================
namespace ServiceConstants {
    constexpr const wchar_t* SERVICE_NAME = L"ShadowStrikeService";
    constexpr const wchar_t* DISPLAY_NAME = L"ShadowStrike Enterprise AV Service";
    constexpr const wchar_t* DESCRIPTION = L"Provides enterprise-grade advanced threat protection against malware, ransomware, and zero-day exploits.";
    constexpr const wchar_t* DEPENDENCIES = L"RpcSs\0Winmgmt\0\0"; // Multiple string
    constexpr uint32_t SHUTDOWN_TIMEOUT_MS = 10000;
}

/**
 * @class AntivirusService
 * @brief Main Windows Service wrapper for ShadowStrike NGAV.
 *        Implements the Service Control Manager (SCM) interface and orchestrates
 *        module lifecycle.
 *
 * Implements:
 * - Singleton Pattern (Meyers')
 * - PIMPL Pattern
 * - RAII Resource Management
 */
class AntivirusService final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    /**
     * @brief Get the singleton instance of the service
     * @return Reference to the service instance
     */
    [[nodiscard]] static AntivirusService& Instance() noexcept;

    // Delete copy/move
    AntivirusService(const AntivirusService&) = delete;
    AntivirusService& operator=(const AntivirusService&) = delete;
    AntivirusService(AntivirusService&&) = delete;
    AntivirusService& operator=(AntivirusService&&) = delete;

    // ========================================================================
    // SERVICE CONTROL MANAGER (SCM) ENTRY POINTS
    // ========================================================================

    /**
     * @brief Main entry point called by the SCM
     * @param argc Argument count
     * @param argv Argument vector
     */
    static void WINAPI ServiceMain(DWORD argc, LPTSTR* argv);

    /**
     * @brief Control handler callback for SCM
     * @param control Control code
     * @param eventType Event type
     * @param eventData Event specific data
     * @param context Context pointer
     * @return Status code
     */
    static DWORD WINAPI ServiceCtrlHandler(DWORD control, DWORD eventType, LPVOID eventData, LPVOID context);

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Run the service (blocks until shutdown)
     * @return true if service ran successfully
     */
    [[nodiscard]] bool Run();

    /**
     * @brief Install the service into Windows SCM
     * @return true on success
     */
    [[nodiscard]] bool Install();

    /**
     * @brief Uninstall the service from Windows SCM
     * @return true on success
     */
    [[nodiscard]] bool Uninstall();

    // ========================================================================
    // STATUS & DIAGNOSTICS
    // ========================================================================

    /**
     * @brief Get current service status
     * @return JSON string of status
     */
    [[nodiscard]] std::string GetStatusReport() const;

    /**
     * @brief Check if service is healthy
     * @return true if all subsystems are running
     */
    [[nodiscard]] bool IsHealthy() const noexcept;

private:
    // ========================================================================
    // INTERNAL IMPLEMENTATION
    // ========================================================================

    AntivirusService();
    ~AntivirusService();

    // Internal handlers called by static wrappers
    void OnStart(DWORD argc, LPTSTR* argv);
    void OnStop();
    void OnPause();
    void OnContinue();
    void OnShutdown();
    void OnSessionChange(DWORD eventType, WTSSESSION_NOTIFICATION* notification);
    void OnPowerEvent(DWORD eventType, POWERBROADCAST_SETTING* setting);

    // Helper to update SCM status
    void SetServiceStatus(DWORD currentState, DWORD win32ExitCode = NO_ERROR, DWORD waitHint = 0);

    // PIMPL
    std::unique_ptr<AntivirusServiceImpl> m_impl;

    // Status handles
    SERVICE_STATUS_HANDLE m_statusHandle{ nullptr };
    SERVICE_STATUS m_serviceStatus{ 0 };

    static std::atomic<bool> s_instanceCreated;
};

} // namespace Service
} // namespace ShadowStrike
