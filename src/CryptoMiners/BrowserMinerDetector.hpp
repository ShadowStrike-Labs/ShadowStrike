/**
 * ============================================================================
 * ShadowStrike CryptoMiners - BROWSER MINER DETECTOR (The Script Block)
 * ============================================================================
 *
 * @file BrowserMinerDetector.hpp
 * @brief Detection of WebAssembly (WASM) miners like Coinhive.
 *
 * Detects:
 * 1. Long-running Worker Threads in browser processes.
 * 2. High CPU usage by specific browser tabs.
 * 3. Network connections to known WebSocket mining pools.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <cstdint>
#include <string>

namespace ShadowStrike {
    namespace CryptoMiners {

        class BrowserMinerDetector {
        public:
            static BrowserMinerDetector& Instance();

            /**
             * @brief Monitor browser processes for mining heuristics.
             * @param browserPid PID of chrome.exe / firefox.exe.
             */
            bool AnalyzeBrowser(uint32_t browserPid);

        private:
            BrowserMinerDetector() = default;
        };

    } // namespace CryptoMiners
} // namespace ShadowStrike
