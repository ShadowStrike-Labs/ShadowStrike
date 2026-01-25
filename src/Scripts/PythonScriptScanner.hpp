/**
 * ============================================================================
 * ShadowStrike Script Security - PYTHON SCANNER (The Backdoor Hunter)
 * ============================================================================
 *
 * @file PythonScriptScanner.hpp
 * @brief Analysis of Python scripts (.py, .pyc).
 *
 * Capabilities:
 * 1. Bytecode Decompilation: Automatically decompiles .pyc files for analysis.
 * 2. Library Check: Detecting malicious libraries (e.g. `pynput` for keylogging).
 * 3. PyInstaller Detection: Detecting compiled Python executables.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>

namespace ShadowStrike {
    namespace Scripts {

        class PythonScriptScanner {
        public:
            static PythonScriptScanner& Instance();

            /**
             * @brief Scan a .py source file.
             */
            bool ScanPython(const std::string& source);

            /**
             * @brief Scan a compiled .pyc or .pyo file.
             */
            bool ScanBytecode(const std::vector<uint8_t>& bytecode);

        private:
            PythonScriptScanner() = default;
        };

    } // namespace Scripts
} // namespace ShadowStrike
