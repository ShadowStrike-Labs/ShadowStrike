/**
 * ============================================================================
 * ShadowStrike IoT Security - ROUTER CHECKER (The Gateway Auditor)
 * ============================================================================
 *
 * @file RouterSecurityChecker.hpp
 * @brief Vulnerability assessment for the Home/Office Router.
 *
 * Capabilities:
 * 1. Default Credential Check: Tries common logins (admin/admin) on the gateway.
 * 2. DNS Hijack Detection: Checks if the router's DNS is pointing to rogue IPs.
 * 3. UPnP Exposure: Identifies internal ports exposed to the public internet.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>

namespace ShadowStrike {
    namespace IoT {

        struct RouterRisk {
            bool hasDefaultCredentials;
            bool isDnsHijacked;
            std::vector<uint16_t> exposedPorts;
            std::string firmwareVersion;
        };

        class RouterSecurityChecker {
        public:
            static RouterSecurityChecker& Instance();

            /**
             * @brief Perform an audit of the default gateway.
             */
            RouterRisk AuditGateway();

        private:
            RouterSecurityChecker() = default;
        };

    } // namespace IoT
} // namespace ShadowStrike
