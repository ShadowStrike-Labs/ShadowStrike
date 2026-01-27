/**
 * ============================================================================
 * ShadowStrike NGAV - SERVICE CONTROLLER
 * ============================================================================
 *
 * @file ServiceController.hpp
 * @brief Manages the Windows Service lifecycle, SCM interactions, and IPC.
 *        Acts as the central nervous system for the ShadowStrike agent.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma once

// Windows SDK
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#endif

// Standard Library
#include <memory>
#include <string>
#include <vector>
#include <atomic>
#include <span>
#include <functional>

namespace ShadowStrike::Service {

    // Forward declaration for PIMPL
    class ServiceControllerImpl;

    /**
     * @class ServiceController
     * @brief Enterprise-grade Windows Service Controller.
     *        Handles Service Control Manager (SCM) requests, power events,
     *        session changes, and orchestrates protection modules.
     */
    class ServiceController final {
    public:
        // ========================================================================
        // SINGLETON PATTERN
        // ========================================================================

        /**
         * @brief Get the singleton instance
         * @return Reference to ServiceController
         */
        [[nodiscard]] static ServiceController& Instance();

        // Prevent copying/moving
        ServiceController(const ServiceController&) = delete;
        ServiceController& operator=(const ServiceController&) = delete;
        ServiceController(ServiceController&&) = delete;
        ServiceController& operator=(ServiceController&&) = delete;

        // ========================================================================
        // SCM ENTRY POINTS
        // ========================================================================

        /**
         * @brief Main entry point called by SCM (Service Control Manager)
         * @param argc Argument count
         * @param argv Argument vector
         */
        static void WINAPI ServiceMain(DWORD argc, LPTSTR* argv);

        /**
         * @brief Extended Service Control Handler
         * @param control Control code (STOP, PAUSE, CONTINUE, etc.)
         * @param eventType Type of event (Power, Session, etc.)
         * @param eventData Event-specific data
         * @param context User-defined context
         * @return Win32 error code
         */
        static DWORD WINAPI ServiceCtrlHandler(DWORD control, DWORD eventType, LPVOID eventData, LPVOID context);

        // ========================================================================
        // CONTROL API
        // ========================================================================

        /**
         * @brief Initialize the controller and its dependencies
         * @return true if initialization succeeded
         */
        [[nodiscard]] bool Initialize();

        /**
         * @brief Signal the service to stop (asynchronous)
         */
        void SignalStop();

        /**
         * @brief Check if service is in running state
         * @return true if running
         */
        [[nodiscard]] bool IsRunning() const;

        /**
         * @brief Generate a full status report (Enterprise requirement)
         * @return JSON string containing service health and stats
         */
        [[nodiscard]] std::string GetStatusReport() const;

        /**
         * @brief Request recovery of a failed component
         * @param componentId ID of the component to restart
         * @return true if recovery initiated
         */
        [[nodiscard]] bool RequestRecovery(const std::string& componentId);

    private:
        ServiceController();
        ~ServiceController();

        // PIMPL Pointer
        std::unique_ptr<ServiceControllerImpl> m_impl;

        // Instance tracking
        static std::atomic<bool> s_instanceCreated;
    };

} // namespace ShadowStrike::Service
