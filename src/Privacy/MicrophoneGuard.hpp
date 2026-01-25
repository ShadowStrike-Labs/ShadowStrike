/**
 * ============================================================================
 * ShadowStrike Privacy - MICROPHONE GUARD (The Earplug)
 * ============================================================================
 *
 * @file MicrophoneGuard.hpp
 * @brief Prevention of audio eavesdropping.
 *
 * Capabilities:
 * 1. Audio Stream Monitoring: Detects when a process is recording audio.
 * 2. Mute Enforcement: Forcefully mutes the input stream for unauthorized apps.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <cstdint>

namespace ShadowStrike {
    namespace Privacy {

        class MicrophoneGuard {
        public:
            static MicrophoneGuard& Instance();

            /**
             * @brief Monitor for new WASAPI or WaveIn streams.
             */
            void MonitorAudioStreams();

            /**
             * @brief Block a specific process from accessing audio input.
             */
            bool BlockAudioForProcess(uint32_t pid);

        private:
            MicrophoneGuard() = default;
        };

    } // namespace Privacy
} // namespace ShadowStrike
