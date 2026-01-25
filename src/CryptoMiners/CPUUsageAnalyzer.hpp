/**
 * ============================================================================
 * ShadowStrike CryptoMiners - CPU ANALYZER (The Load Balancer)
 * ============================================================================
 *
 * @file CPUUsageAnalyzer.hpp
 * @brief Detection of anomalous CPU usage patterns.
 *
 * Miners typically consume 100% of available cores. This module tracks:
 * 1. Sustained High Usage: >80% for >1 minute.
 * 2. Thread Affinity: Locking threads to specific cores.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../Utils/ProcessUtils.hpp"
#include <map>
#include <mutex>

namespace ShadowStrike {
    namespace CryptoMiners {

        struct CpuStats {
            double usagePercent;
            uint64_t durationMs;
        };

        class CPUUsageAnalyzer {
        public:
            static CPUUsageAnalyzer& Instance();

            /**
             * @brief Check if a process is abusing the CPU.
             */
            bool IsHighUsage(uint32_t pid);

        private:
            CPUUsageAnalyzer() = default;
            
            std::mutex m_mutex;
            std::map<uint32_t, CpuStats> m_stats;
        };

    } // namespace CryptoMiners
} // namespace ShadowStrike
