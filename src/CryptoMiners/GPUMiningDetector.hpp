/**
 * ============================================================================
 * ShadowStrike CryptoMiners - GPU DETECTOR (The Renderer)
 * ============================================================================
 *
 * @file GPUMiningDetector.hpp
 * @brief Detection of GPU-based mining activity.
 *
 * Uses NVML (NVIDIA) and ADL (AMD) libraries to monitor:
 * 1. GPU Utilization (Compute vs Graphics).
 * 2. VRAM Allocation (Miners allocate large DAG files).
 * 3. Fan Speed / Temperature.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <cstdint>

namespace ShadowStrike {
    namespace CryptoMiners {

        class GPUMiningDetector {
        public:
            static GPUMiningDetector& Instance();

            /**
             * @brief Check if any GPU is under mining load.
             */
            bool IsMiningDetected();

            /**
             * @brief Identify which process is using the GPU.
             */
            uint32_t GetMiningProcessId();

        private:
            GPUMiningDetector() = default;
        };

    } // namespace CryptoMiners
} // namespace ShadowStrike
