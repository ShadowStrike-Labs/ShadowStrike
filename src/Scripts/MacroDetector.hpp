/**
 * ============================================================================
 * ShadowStrike Script Security - MACRO DETECTOR (The Office Guard)
 * ============================================================================
 *
 * @file MacroDetector.hpp
 * @brief Analysis of VBA Macros in Office documents (DOCM, XLSM).
 *
 * Capabilities:
 * 1. OLE Object Extraction: Uses `pugixml` and custom parsers to find macros.
 * 2. VBA Source Analysis: Looks for `AutoOpen`, `Shell`, `Execute` keywords.
 * 3. De-obfuscation: Resolves character code manipulation in VBA strings.
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

        struct MacroInfo {
            std::string moduleName;
            std::string sourceCode;
            bool isMalicious;
            std::vector<std::string> suspiciousApis;
        };

        class MacroDetector {
        public:
            static MacroDetector& Instance();

            /**
             * @brief Extract and analyze macros from an Office document.
             */
            std::vector<MacroInfo> AnalyzeDocument(const std::wstring& filePath);

        private:
            MacroDetector() = default;
        };

    } // namespace Scripts
} // namespace ShadowStrike
