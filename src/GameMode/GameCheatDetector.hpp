/**
 * ============================================================================
 * ShadowStrike GameMode - CHEAT DETECTOR (The Anti-Cheat)
 * ============================================================================
 *
 * @file GameCheatDetector.hpp
 * @brief Detection of game-specific manipulation tools.
 *
 * NOTE: This is NOT a full Anti-Cheat (like EAC/BattlEye), but a security
 * feature to protect the user from malware *disguised* as cheats.
 *
 * Capabilities:
 * 1. Memory Modification: Detects unauthorized `WriteProcessMemory` into game processes.
 * 2. Signature Match: Detects Cheat Engine, ArtMoney, and known trainers.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <cstdint>

namespace ShadowStrike {
    namespace GameMode {

        class GameCheatDetector {
        public:
            static GameCheatDetector& Instance();

            /**
             * @brief Scan for known cheating artifacts in memory.
             */
            bool ScanForCheats(uint32_t gamePid);

        private:
            GameCheatDetector() = default;
        };

    } // namespace GameMode
} // namespace ShadowStrike
