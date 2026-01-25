/**
 * ============================================================================
 * ShadowStrike Configuration - POLICY MANAGER (The Enforcer)
 * ============================================================================
 *
 * @file PolicyManager.hpp
 * @brief Management of enterprise-wide security policies.
 *
 * Policies are immutable by the end-user and are typically pushed from a
 * central management console (Cloud/Server).
 *
 * Examples:
 * - "Real-time scanning MUST be ON".
 * - "USB Storage is READ-ONLY".
 * - "Exclusions: C:\InternalApp\".
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>
#include <map>

namespace ShadowStrike {
    namespace Config {

        struct Policy {
            std::string id;
            std::string name;
            bool isMandatory;
            std::map<std::string, std::string> settings;
        };

        class PolicyManager {
        public:
            static PolicyManager& Instance();

            /**
             * @brief Apply a new policy received from the server.
             */
            void ApplyPolicy(const Policy& policy);

            /**
             * @brief Check if a specific setting is enforced by policy.
             */
            bool IsEnforced(const std::string& settingName);

            /**
             * @brief Get the enforced value for a setting.
             */
            std::string GetPolicyValue(const std::string& settingName);

        private:
            PolicyManager() = default;
            std::map<std::string, Policy> m_activePolicies;
        };

    } // namespace Config
} // namespace ShadowStrike
