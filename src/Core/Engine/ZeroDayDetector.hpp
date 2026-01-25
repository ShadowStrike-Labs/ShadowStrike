/**
 * ============================================================================
 * ShadowStrike Core Engine - ZERO DAY DETECTOR (The Oracle)
 * ============================================================================
 *
 * @file ZeroDayDetector.hpp
 * @brief Detection of exploits and previously unknown vulnerabilities.
 *
 * This module looks for "Weird Machines" and exploit primitives rather than
 * malware payloads. It is heavily used by the EmulationEngine.
 *
 * Capabilities:
 * 1. Shellcode Detection: Finds NOP sleds, GetPC tricks, and Stack Pivots.
 * 2. Heap Spray Detection: Identifies massive allocations of uniform patterns.
 * 3. ROP Chain Detection: Finds sequences of "Return" instructions in stack.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <vector>
#include <cstdint>
#include <optional>

namespace ShadowStrike {
    namespace Core {
        namespace Engine {

            enum class ExploitType {
                StackOverflow,
                HeapSpray,
                UseAfterFree,
                ROPChain,
                Shellcode
            };

            struct ZeroDayResult {
                bool detected;
                ExploitType type;
                uint64_t offset;
                std::string description;
            };

            class ZeroDayDetector {
            public:
                static ZeroDayDetector& Instance();

                /**
                 * @brief Analyze a memory buffer (or emulated memory) for exploit patterns.
                 */
                ZeroDayResult AnalyzeBuffer(const std::vector<uint8_t>& buffer);

                /**
                 * @brief Analyze the stack for ROP gadgets.
                 */
                ZeroDayResult AnalyzeStack(const std::vector<uintptr_t>& stackDump);

            private:
                ZeroDayDetector() = default;
                
                bool IsNopSled(const std::vector<uint8_t>& buffer);
                bool HasGetPC(const std::vector<uint8_t>& buffer);
            };

        } // namespace Engine
    } // namespace Core
} // namespace ShadowStrike
