/**
 * ============================================================================
 * ShadowStrike Core Engine - PACKER UNPACKER (The Revealer)
 * ============================================================================
 *
 * @file PackerUnpacker.hpp
 * @brief Automated unpacking of protected and compressed executables.
 *
 * This module coordinates with the `EmulationEngine` to identify the "Original
 * Entry Point" (OEP) of a packed file and dump its de-obfuscated code.
 *
 * Capabilities:
 * 1. Static Unpacking: For simple packers like UPX.
 * 2. Dynamic Unpacking: Running the stub in the emulator until the OEP is hit.
 * 3. Import Reconstruction: Rebuilding the IAT (Import Address Table) of the dumped file.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <vector>
#include <cstdint>
#include <string>

namespace ShadowStrike {
    namespace Core {
        namespace Engine {

            class PackerUnpacker {
            public:
                static PackerUnpacker& Instance();

                /**
                 * @brief Attempt to unpack a buffer.
                 * @return True if OEP was found and code was dumped.
                 */
                bool Unpack(const std::vector<uint8_t>& input, std::vector<uint8_t>& output);

            private:
                PackerUnpacker() = default;
            };

        } // namespace Engine
    } // namespace Core
} // namespace ShadowStrike
