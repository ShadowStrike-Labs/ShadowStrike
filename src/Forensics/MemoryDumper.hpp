/**
 * ============================================================================
 * ShadowStrike Forensics - MEMORY DUMPER (The Photographer)
 * ============================================================================
 *
 * @file MemoryDumper.hpp
 * @brief Logic for creating process and kernel memory dumps.
 *
 * Capabilities:
 * 1. Process Dump: Using `MiniDumpWriteDump` for a specific PID.
 * 2. Full RAM Dump: (Optional) Interface with WinPMEM/Custom driver for full memory.
 * 3. Strings Extraction: Extracting ASCII/UTF-16 strings from a dump for quick analysis.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <cstdint>

namespace ShadowStrike {
    namespace Forensics {

        class MemoryDumper {
        public:
            static MemoryDumper& Instance();

            /**
             * @brief Create a full memory dump of a running process.
             */
            bool DumpProcess(uint32_t pid, const std::wstring& outputPath);

            /**
             * @brief Create a lightweight minidump.
             */
            bool CreateMiniDump(uint32_t pid, const std::wstring& outputPath);

        private:
            MemoryDumper() = default;
        };

    } // namespace Forensics
} // namespace ShadowStrike
