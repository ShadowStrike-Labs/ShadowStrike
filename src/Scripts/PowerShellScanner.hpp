/**
 * ============================================================================
 * ShadowStrike Script Security - POWERSHELL SCANNER (The De-Obfuscator)
 * ============================================================================
 *
 * @file PowerShellScanner.hpp
 * @brief Analysis of PowerShell scripts and command lines.
 *
 * Capabilities:
 * 1. Base64 Decoding: Automatically decodes `-EncodedCommand` payloads.
 * 2. Layered De-obfuscation: Resolves backticks, string joins, and hex encoding.
 * 3. Execution Policy Hardening: Enforcing `AllSigned` mode via Registry.
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

        class PowerShellScanner {
        public:
            static PowerShellScanner& Instance();

            /**
             * @brief Scan a raw script block.
             */
            bool ScanScript(const std::wstring& script);

            /**
             * @brief Analyze a PowerShell process command line.
             */
            bool AnalyzeCommandLine(const std::wstring& cmdLine);

        private:
            PowerShellScanner() = default;
            
            // Resolve recursive obfuscation (e.g. Base64(IEX(Base64(...))))
            std::wstring Deobfuscate(const std::wstring& input);
        };

    } // namespace Scripts
} // namespace ShadowStrike
