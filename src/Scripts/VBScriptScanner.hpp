/**
 * ============================================================================
 * ShadowStrike Script Security - VBSCRIPT SCANNER (The Macro Hunter)
 * ============================================================================
 *
 * @file VBScriptScanner.hpp
 * @brief Analysis of VBScript and WSH (Windows Script Host) scripts.
 *
 * Capabilities:
 * 1. Object Model Analysis: Detecting use of `GetObject("winmgmts:...")`.
 * 2. Downloader Detection: Detecting use of `Microsoft.XMLHTTP` or `Adodb.Stream`.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>

namespace ShadowStrike {
    namespace Scripts {

        class VBScriptScanner {
        public:
            static VBScriptScanner& Instance();

            /**
             * @brief Scan a .vbs or .vbe file.
             */
            bool ScanVBS(const std::wstring& code);

        private:
            VBScriptScanner() = default;
        };

    } // namespace Scripts
} // namespace ShadowStrike
