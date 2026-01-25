/**
 * ============================================================================
 * ShadowStrike Forensics - INCIDENT RECORDER (The Black Box)
 * ============================================================================
 *
 * @file IncidentRecorder.hpp
 * @brief Persistent recording of security-relevant system changes.
 *
 * Capabilities:
 * 1. Event Journaling: Writing every block/detect event to a tamper-proof log.
 * 2. SQLite Integration: Storing structured incident data for fast query.
 * 3. Forensics Context: Linking PIDs to executable hashes and parent chains.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>

namespace ShadowStrike {
    namespace Forensics {

        struct Incident {
            uint64_t id;
            uint64_t timestamp;
            std::string category; // "Detection", "Exploit", "Policy"
            std::string details;
            std::string severity;
        };

        class IncidentRecorder {
        public:
            static IncidentRecorder& Instance();

            /**
             * @brief Commit a new security incident to the database.
             */
            void RecordIncident(const Incident& incident);

            /**
             * @brief Retrieve incidents for analysis.
             */
            std::vector<Incident> GetRecentIncidents(uint32_t limit = 100);

        private:
            IncidentRecorder() = default;
        };

    } // namespace Forensics
} // namespace ShadowStrike
