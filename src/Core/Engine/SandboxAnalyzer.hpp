/**
 * ============================================================================
 * ShadowStrike Core Engine - SANDBOX ANALYZER (The Isolation Tank)
 * ============================================================================
 *
 * @file SandboxAnalyzer.hpp
 * @brief Logic for full system-level sandbox analysis.
 *
 * While EmulationEngine emulates the CPU, SandboxAnalyzer manages a dedicated
 * isolated OS environment (VM or Container) to detonate malware and capture
 * its full impact on the system.
 *
 * Capabilities:
 * 1. VM Lifecycle: Reverting to snapshots, starting/stopping guest OS.
 * 2. Agent Communication: Talking to the internal agent inside the sandbox.
 * 3. Artifact Extraction: Pulling logs, dropped files, and memory dumps from guest.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>

namespace ShadowStrike {
    namespace Core {
        namespace Engine {

            struct SandboxVerdict {
                bool isMalicious;
                int threatScore;
                std::vector<std::string> behaviorSummary;
            };

            class SandboxAnalyzer {
            public:
                static SandboxAnalyzer& Instance();

                /**
                 * @brief Run a file in the sandbox for a set duration.
                 */
                SandboxVerdict Analyze(const std::wstring& filePath, uint32_t timeoutSeconds = 120);

            private:
                SandboxAnalyzer() = default;
            };

        } // namespace Engine
    } // namespace Core
} // namespace ShadowStrike
