/**
 * ============================================================================
 * ShadowStrike Script Security - JAVASCRIPT SCANNER (The Web Guard)
 * ============================================================================
 *
 * @file JavaScriptScanner.hpp
 * @brief Analysis of standalone and embedded JavaScript.
 *
 * Capabilities:
 * 1. String De-obfuscation: Resolves `eval()`, `String.fromCharCode`, and Obfuscator.io patterns.
 * 2. Suspicious API detection: `activexobject`, `filesystemobject`, `WScript.Shell`.
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

        class JavaScriptScanner {
        public:
            static JavaScriptScanner& Instance();

            /**
             * @brief Analyze a .js file or embedded script block.
             */
            bool ScanJS(const std::string& code);

        private:
            JavaScriptScanner() = default;
        };

    } // namespace Scripts
} // namespace ShadowStrike
