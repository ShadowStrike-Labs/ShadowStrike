/**
 * ============================================================================
 * ShadowStrike Communication - TELEMETRY COLLECTOR (The Beacon)
 * ============================================================================
 *
 * @file TelemetryCollector.hpp
 * @brief Anonymous collection of threat data for global intelligence.
 *
 * Capabilities:
 * 1. Anonymization: Scrubbing PII (Usernames, IPs) before sending.
 * 2. Batching: Queueing events to send once per day.
 * 3. Health Checks: Reporting crash dumps and performance metrics.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>

namespace ShadowStrike {
    namespace Communication {

        struct TelemetryEvent {
            std::string eventType; // "Detection", "Crash", "Update"
            std::string payloadJson;
            uint64_t timestamp;
        };

        class TelemetryCollector {
        public:
            static TelemetryCollector& Instance();

            /**
             * @brief Queue an event for future submission.
             */
            void RecordEvent(const std::string& type, const std::string& data);

            /**
             * @brief Force submission of all queued events.
             */
            void Flush();

        private:
            TelemetryCollector() = default;
        };

    } // namespace Communication
} // namespace ShadowStrike
