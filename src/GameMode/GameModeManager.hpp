/**
 * ============================================================================
 * ShadowStrike GameMode - MANAGER (The Player's Friend)
 * ============================================================================
 *
 * @file GameModeManager.hpp
 * @brief Orchestrator for AV performance tuning during gaming.
 *
 * Capabilities:
 * 1. Automatic Detection: Detects when a game is running or in Fullscreen.
 * 2. Silent Mode: Postpones non-critical notifications.
 * 3. Resource Reallocation: Reduces CPU/IO priority of background scans.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <atomic>
#include <mutex>

namespace ShadowStrike {
    namespace GameMode {

        class GameModeManager {
        public:
            static GameModeManager& Instance();

            /**
             * @brief Manual toggle for Game Mode.
             */
            void SetEnabled(bool enabled);

            /**
             * @brief Check if Game Mode is currently active (Auto or Manual).
             */
            bool IsActive() const;

            /**
             * @brief Called by GameProcessDetector when a game starts/stops.
             */
            void OnGameStateChanged(bool isGaming);

        private:
            GameModeManager() = default;
            std::atomic<bool> m_manualOverride{ false };
            std::atomic<bool> m_autoDetected{ false };
        };

    } // namespace GameMode
} // namespace ShadowStrike
