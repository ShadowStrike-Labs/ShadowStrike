/**
 * @file CpuFeatures.hpp
 * @brief Runtime CPU feature detection for instructions that are not architecturally
 *        guaranteed on x64, plus safe substitutes for them.
 *
 * WHY THIS EXISTS
 * ---------------
 * The hand-written anti-evasion assembly layer and its C++ fallbacks both use RDTSCP.
 * RDTSCP is NOT baseline x64: it was introduced with Intel Nehalem and AMD Barcelona and
 * is reported by CPUID.80000001h:EDX[27]. Executing it on a processor that does not
 * implement it raises #UD (invalid opcode), which surfaces as a hard crash rather than a
 * degraded measurement.
 *
 * Before this header existed there were ZERO queries of CPUID leaf 0x80000000 or
 * 0x80000001 anywhere in the tree, so nothing established RDTSCP availability before
 * using it. Every RDTSCP site therefore assumed a capability it never verified. That was
 * latent rather than live only because the routines concerned had no reachable caller;
 * wiring them - which is the point of the anti-evasion assembly work - is precisely what
 * would have made it reachable.
 *
 * DESIGN NOTES
 * ------------
 * - The probe runs ONCE. CPUID is a serializing instruction and traps to the hypervisor
 *   on a virtualised host, so it must not sit on a hot path. A function-local static
 *   gives thread-safe one-time initialisation with only a guard load per subsequent call.
 * - The extended-leaf maximum is checked FIRST. If leaf 0x80000001 is unsupported, CPUID
 *   does not return zeroes: it returns the data of the highest supported leaf instead, so
 *   reading the feature bit without this check samples an unrelated register.
 * - This header is intentionally free of Windows dependencies so it can be included from
 *   any translation unit without ordering constraints.
 */

#pragma once

#include <cstdint>
#include <intrin.h>

namespace ShadowStrike {
namespace Utils {
namespace CpuFeatures {

/**
 * @brief Whether RDTSCP is implemented by this processor.
 * @return true when CPUID.80000001h:EDX[27] is set.
 * @note Evaluated once per process; subsequent calls only test an initialisation guard.
 */
[[nodiscard]] inline bool HasRDTSCP() noexcept {
    static const bool supported = []() noexcept -> bool {
        int regs[4] = { 0, 0, 0, 0 };

        // Leaf 0x80000000 reports the highest extended leaf the CPU implements. Querying
        // 0x80000001 without this guard would read whatever the highest supported leaf
        // returns, so the feature bit could be sampled from unrelated register content.
        __cpuid(regs, static_cast<int>(0x80000000));
        if (static_cast<std::uint32_t>(regs[0]) < 0x80000001u) {
            return false;
        }

        __cpuid(regs, static_cast<int>(0x80000001));
        constexpr std::uint32_t kRdtscpBit = 1u << 27;   // EDX bit 27
        return (static_cast<std::uint32_t>(regs[3]) & kRdtscpBit) != 0u;
    }();
    return supported;
}

/**
 * @brief Read the timestamp counter with a serializing guarantee on any x64 processor.
 *
 * RDTSC alone may be reordered against surrounding instructions, which is why the timing
 * probes want RDTSCP. Where RDTSCP is unavailable this issues CPUID - an unconditionally
 * serializing instruction - immediately before RDTSC, which provides the same ordering
 * property. The measured quantity therefore keeps its meaning on both paths, so a
 * detector's thresholds do not shift with the host processor.
 *
 * @param auxOut Optional out-parameter receiving a processor identifier. On the RDTSCP
 *               path this is IA32_TSC_AUX, which Windows programs with the processor
 *               number. On the substitute path it is the initial APIC ID from
 *               CPUID.01h:EBX[31:24], which identifies the logical processor but is not
 *               guaranteed to equal the value Windows would report.
 * @return The timestamp counter value.
 */
[[nodiscard]] inline std::uint64_t ReadSerializedTsc(std::uint32_t* auxOut) noexcept {
    if (HasRDTSCP()) {
        unsigned int aux = 0;
        const std::uint64_t tsc = __rdtscp(&aux);
        if (auxOut != nullptr) {
            *auxOut = static_cast<std::uint32_t>(aux);
        }
        return tsc;
    }

    int regs[4] = { 0, 0, 0, 0 };
    __cpuid(regs, 0);                       // serialize before sampling
    const std::uint64_t tsc = __rdtsc();

    if (auxOut != nullptr) {
        __cpuid(regs, 1);
        *auxOut = (static_cast<std::uint32_t>(regs[1]) >> 24) & 0xFFu;
    }
    return tsc;
}

} // namespace CpuFeatures
} // namespace Utils
} // namespace ShadowStrike
