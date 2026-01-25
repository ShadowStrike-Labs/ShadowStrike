/**
 * ============================================================================
 * ShadowStrike Communication - SERVICE COMMUNICATION (The Pipeline)
 * ============================================================================
 *
 * @file ServiceCommunication.hpp
 * @brief Logic for communication between the background Service and User GUI.
 *
 * Capabilities:
 * 1. Named Pipes: Using secure Windows Named Pipes for local IPC.
 * 2. Commands: Start Scan, Stop Scan, Update, Quarantine.
 * 3. Events: Forwarding "Threat Detected" events to the UI in real-time.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>
#include <functional>

namespace ShadowStrike {
    namespace Communication {

        class ServiceCommunication {
        public:
            static ServiceCommunication& Instance();

            /**
             * @brief Start the listener (Service side) or Connector (GUI side).
             */
            bool Start(bool isService);

            /**
             * @brief Send a command string to the counterpart.
             */
            void SendCommand(const std::string& cmd);

            /**
             * @brief Register a callback for incoming messages.
             */
            void SetMessageCallback(std::function<void(const std::string&)> cb);

        private:
            ServiceCommunication() = default;
        };

    } // namespace Communication
} // namespace ShadowStrike
