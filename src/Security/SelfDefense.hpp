/**
 * ============================================================================
 * ShadowStrike Security - SELF DEFENSE (The Fortress)
 * ============================================================================
 *
 * @file SelfDefense.hpp
 * @brief Logic for preventing termination or removal of ShadowStrike.
 *
 * Capabilities:
 * 1. Process Guard: Prevents `TerminateProcess` or `SuspendThread` on our PIDs.
 * 2. Driver Guard: Prevents unloading the Minifilter driver.
 * 3. Registry Guard: Blocks modification of our service configuration.
 * 4. Persistence: Automatically restarts components if they crash.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <atomic>

namespace ShadowStrike {
    namespace Security {

        class SelfDefense {
        public:
            static SelfDefense& Instance();

            /**
             * @brief Initialize kernel-level self-defense.
             */
            bool Initialize();

            /**
             * @brief Check if a request to access our process should be allowed.
             * Called via Kernel callback (ObRegisterCallbacks).
             */
            bool IsAccessAllowed(uint32_t callerPid, uint32_t desiredAccess);

        private:
            SelfDefense() = default;
        };

    } // namespace Security
} // namespace ShadowStrike
