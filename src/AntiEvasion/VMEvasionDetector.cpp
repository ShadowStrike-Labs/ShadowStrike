/**
 * @file VMEvasionDetector.cpp
 * @brief Enterprise-grade VM/Hypervisor detection implementation
 *
 * ShadowStrike AntiEvasion - VM Evasion Detection Module
 * Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 *
 * PRODUCTION-LEVEL IMPLEMENTATION
 * - Thread-safe with std::shared_mutex for concurrent access
 * - PIMPL pattern for ABI stability
 * - Comprehensive error handling with try-catch blocks
 * - Statistics tracking with std::atomic counters
 * - Caching with TTL for performance
 * - Integration with ThreatIntel and SignatureStore
 * - Assembly integration for low-level CPU checks
 *
 * Detection Capabilities:
 * - 100+ distinct VM indicators across 12 detection categories
 * - Support for VMware, VirtualBox, Hyper-V, KVM, Xen, Parallels, and more
 * - Process analysis for anti-VM behavior detection
 * - Performance: <1ms quick check, <50ms standard, <200ms deep analysis
 */
#include"pch.h"
#include "VMEvasionDetector.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/MemoryUtils.hpp"
#include "../ThreatIntel/ThreatIntelStore.hpp"
#include "../SignatureStore/SignatureStore.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/RegistryUtils.hpp"
#include "../PEParser/PEParser.hpp"

// Zydis Disassembler Integration
#include <Zydis/Zydis.h>

#include <algorithm>
#include <numeric>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <wbemidl.h>
#include <comdef.h>
#include <SetupAPI.h>
#include <devguid.h>
#include <cfgmgr32.h>
#include <psapi.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "SetupAPI.lib")
#pragma comment(lib, "cfgmgr32.lib")
#pragma comment(lib, "Zydis.lib")

// External assembly functions (implemented in VMEvasionDetector_x64.asm)
extern "C" {
    /// @brief Checks CPUID hypervisor bit (ECX bit 31 of leaf 0x1)
    bool CheckCPUIDHypervisorBit() noexcept;

    /// @brief Retrieves CPUID vendor string from leaf 0x40000000
    void GetCPUIDVendorString(char* buffer, size_t bufferSize) noexcept;

    /// @brief Measures RDTSC timing delta for VM detection
    uint64_t MeasureRDTSCTimingDelta(uint32_t iterations) noexcept;

    /// @brief Retrieves SIDT (Interrupt Descriptor Table) base address
    uint64_t GetIDTBase() noexcept;

    /// @brief Retrieves SGDT (Global Descriptor Table) base address
    uint64_t GetGDTBase() noexcept;

    /// @brief Retrieves SLDT (Local Descriptor Table) selector
    uint16_t GetLDTSelector() noexcept;

    /// @brief Checks VMware backdoor port 0x5658 (implemented in ASM)
    void CheckVMwareBackdoor(uint32_t* rax, uint32_t* rbx, uint32_t* rcx, uint32_t* rdx) noexcept;

    // ========================================================================
    // Enterprise Enhancement Assembly Functions
    // ========================================================================

    /// @brief Retrieves Task Register selector via STR instruction (SWIZZ test)
    uint16_t GetTRSelector() noexcept;

    /// @brief Measures CPUID instruction timing for VM exit detection
    uint64_t MeasureCPUIDTiming(uint32_t iterations) noexcept;

    /// @brief Checks for Hyper-V specific interface signature
    uint32_t CheckHyperVBackdoor() noexcept;

    /// @brief Extended CPUID query with all output registers
    bool GetExtendedCPUIDInfo(uint32_t leaf, uint32_t subleaf,
                               uint32_t* eax, uint32_t* ebx,
                               uint32_t* ecx, uint32_t* edx) noexcept;

    /// @brief Checks segment descriptor limits for VM detection
    bool CheckSegmentLimits(uint32_t* csLimit, uint32_t* dsLimit, uint32_t* ssLimit) noexcept;

    /// @brief Generic instruction timing measurement
    uint64_t MeasureInstructionTiming(uint32_t iterations, uint32_t instructionType) noexcept;

    /// @brief Intel VT-x hypercall detection (causes #UD on non-VM)
    bool DetectVMCALL() noexcept;

    /// @brief AMD-V hypercall detection (causes #UD on non-VM)
    bool DetectVMMCALL() noexcept;

    /// @brief Validates hypervisor CPUID leaf range
    uint32_t CheckCPUIDLeafRange() noexcept;

    /// @brief Retrieves both IDT and GDT information in single call
    bool GetIDTAndGDTInfo(uint64_t* idtBase, uint16_t* idtLimit,
                          uint64_t* gdtBase, uint16_t* gdtLimit) noexcept;

    /// @brief Measures RDTSCP timing (serializing version)
    uint64_t MeasureRDTSCPTiming(uint32_t iterations) noexcept;
}

// ============================================================================
// C++ FALLBACK IMPLEMENTATIONS FOR ASSEMBLY FUNCTIONS
// ============================================================================
// These fallback functions provide functionality when:
// - Assembly module is not linked
// - Running on platforms where assembly isn't supported
// - Testing/debugging without assembly
//
// The fallbacks use MSVC intrinsics where possible, providing near-native
// performance while maintaining portability.
// ============================================================================

namespace {
    /// @brief Configuration flag to prefer fallbacks (for testing/debugging)
    constexpr bool USE_ASM_FUNCTIONS = true;

    // ------------------------------------------------------------------------
    // CPUID Fallbacks (using MSVC __cpuid intrinsic)
    // ------------------------------------------------------------------------

    /// @brief Fallback: Check CPUID hypervisor bit using intrinsics
    [[nodiscard]] bool Fallback_CheckCPUIDHypervisorBit() noexcept {
        int cpuInfo[4] = { 0 };
        __cpuid(cpuInfo, 1);  // Leaf 1 contains feature flags
        // ECX bit 31 indicates hypervisor present
        return (cpuInfo[2] & (1 << 31)) != 0;
    }

    /// @brief Fallback: Get CPUID vendor string using intrinsics
    void Fallback_GetCPUIDVendorString(char* buffer, size_t bufferSize) noexcept {
        if (!buffer || bufferSize < 13) return;

        int cpuInfo[4] = { 0 };
        __cpuid(cpuInfo, 0x40000000);  // Hypervisor vendor leaf

        // Check if hypervisor is present first
        int featureInfo[4] = { 0 };
        __cpuid(featureInfo, 1);
        if ((featureInfo[2] & (1 << 31)) == 0) {
            buffer[0] = '\0';
            return;
        }

        // Vendor string is in EBX, ECX, EDX (12 chars total)
        memcpy(buffer, &cpuInfo[1], 4);      // EBX
        memcpy(buffer + 4, &cpuInfo[2], 4);  // ECX
        memcpy(buffer + 8, &cpuInfo[3], 4);  // EDX
        buffer[12] = '\0';
    }

    /// @brief Fallback: Measure RDTSC timing delta using intrinsics
    [[nodiscard]] uint64_t Fallback_MeasureRDTSCTimingDelta(uint32_t iterations) noexcept {
        if (iterations == 0) return 0;

        uint64_t totalDelta = 0;
        unsigned int aux = 0;

        for (uint32_t i = 0; i < iterations; ++i) {
            // Serialize with CPUID, then measure RDTSC
            int cpuInfo[4] = { 0 };
            __cpuid(cpuInfo, 0);  // Serializing instruction

            uint64_t start = __rdtsc();

            // Execute a simple operation that may trigger VM exit
            __cpuid(cpuInfo, 1);

            uint64_t end = __rdtsc();

            totalDelta += (end - start);
        }

        return totalDelta / iterations;
    }

    // ------------------------------------------------------------------------
    // Descriptor Table Fallbacks (using inline assembly via intrinsics)
    // ------------------------------------------------------------------------

    /// @brief Fallback: Get IDT base address
    /// @note On x64 Windows, user-mode cannot directly execute SIDT
    /// Returns 0 as a fallback - assembly version handles this properly
    [[nodiscard]] uint64_t Fallback_GetIDTBase() noexcept {
        // SIDT requires special handling on x64
        // Use the SGDT/SIDT intrinsics if available, otherwise return sentinel
        uint8_t idtr[10] = { 0 };
        
        // MSVC doesn't have __sidt intrinsic for x64, use assembly or return 0
        // The ASM version handles this - fallback indicates "not available"
        #if defined(_M_X64)
            // On x64, we can't reliably get IDT from user mode without ASM
            // Return a sentinel value that won't trigger false positives
            return 0xFFFFFFFF'FFFFFFFF;
        #else
            return 0;
        #endif
    }

    /// @brief Fallback: Get GDT base address
    [[nodiscard]] uint64_t Fallback_GetGDTBase() noexcept {
        #if defined(_M_X64)
            // Same limitation as IDT
            return 0xFFFFFFFF'FFFFFFFF;
        #else
            return 0;
        #endif
    }

    /// @brief Fallback: Get LDT selector
    [[nodiscard]] uint16_t Fallback_GetLDTSelector() noexcept {
        // SLDT not available via intrinsics
        // Return 0 (typical value, won't trigger false positives)
        return 0;
    }

    /// @brief Fallback: Get TR selector
    [[nodiscard]] uint16_t Fallback_GetTRSelector() noexcept {
        // STR instruction not available via intrinsics
        // Return typical Windows value to avoid false positives
        return 0x40;  // Typical TR selector on Windows
    }

    // ------------------------------------------------------------------------
    // VMware Backdoor Fallback
    // ------------------------------------------------------------------------

    /// @brief Fallback: Check VMware backdoor
    /// @note This is a no-op fallback - real detection requires ASM
    void Fallback_CheckVMwareBackdoor(uint32_t* rax, uint32_t* rbx, 
                                       uint32_t* rcx, uint32_t* rdx) noexcept {
        // VMware backdoor requires privileged I/O port access
        // Cannot be done reliably without assembly
        if (rax) *rax = 0;
        if (rbx) *rbx = 0;
        if (rcx) *rcx = 0;
        if (rdx) *rdx = 0;
    }

    // ------------------------------------------------------------------------
    // CPUID Timing Fallback
    // ------------------------------------------------------------------------

    /// @brief Fallback: Measure CPUID timing
    [[nodiscard]] uint64_t Fallback_MeasureCPUIDTiming(uint32_t iterations) noexcept {
        if (iterations == 0) return 0;

        uint64_t totalCycles = 0;

        for (uint32_t i = 0; i < iterations; ++i) {
            int cpuInfo[4] = { 0 };
            
            // Serialize
            __cpuid(cpuInfo, 0);
            
            uint64_t start = __rdtsc();
            
            // Measure CPUID leaf 0 (causes VM exit on hypervisors)
            __cpuid(cpuInfo, 0);
            
            uint64_t end = __rdtsc();
            
            totalCycles += (end - start);
        }

        return totalCycles / iterations;
    }

    // ------------------------------------------------------------------------
    // Hyper-V Detection Fallback
    // ------------------------------------------------------------------------

    /// @brief Fallback: Check Hyper-V backdoor
    [[nodiscard]] uint32_t Fallback_CheckHyperVBackdoor() noexcept {
        // Check for Hyper-V signature via CPUID
        int cpuInfo[4] = { 0 };
        __cpuid(cpuInfo, 0x40000000);

        // Check max leaf value (Hyper-V returns at least 0x40000005)
        if (cpuInfo[0] >= 0x40000005) {
            // Verify "Microsoft Hv" signature
            char vendor[13] = { 0 };
            memcpy(vendor, &cpuInfo[1], 4);
            memcpy(vendor + 4, &cpuInfo[2], 4);
            memcpy(vendor + 8, &cpuInfo[3], 4);
            
            if (strncmp(vendor, "Microsoft Hv", 12) == 0) {
                return cpuInfo[0];  // Return max leaf as indicator
            }
        }
        return 0;
    }

    // ------------------------------------------------------------------------
    // Extended CPUID Fallback
    // ------------------------------------------------------------------------

    /// @brief Fallback: Get extended CPUID info
    [[nodiscard]] bool Fallback_GetExtendedCPUIDInfo(uint32_t leaf, uint32_t subleaf,
                                                      uint32_t* eax, uint32_t* ebx,
                                                      uint32_t* ecx, uint32_t* edx) noexcept {
        int cpuInfo[4] = { 0 };
        __cpuidex(cpuInfo, static_cast<int>(leaf), static_cast<int>(subleaf));

        if (eax) *eax = static_cast<uint32_t>(cpuInfo[0]);
        if (ebx) *ebx = static_cast<uint32_t>(cpuInfo[1]);
        if (ecx) *ecx = static_cast<uint32_t>(cpuInfo[2]);
        if (edx) *edx = static_cast<uint32_t>(cpuInfo[3]);

        return true;
    }

    // ------------------------------------------------------------------------
    // Segment Limits Fallback
    // ------------------------------------------------------------------------

    /// @brief Fallback: Check segment limits
    /// @note Cannot get actual segment limits without assembly
    [[nodiscard]] bool Fallback_CheckSegmentLimits(uint32_t* csLimit, uint32_t* dsLimit, 
                                                    uint32_t* ssLimit) noexcept {
        // On x64 flat model, segment limits are 0xFFFFFFFF
        // Return typical values to avoid false positives
        if (csLimit) *csLimit = 0xFFFFFFFF;
        if (dsLimit) *dsLimit = 0xFFFFFFFF;
        if (ssLimit) *ssLimit = 0xFFFFFFFF;
        return true;
    }

    // ------------------------------------------------------------------------
    // Instruction Timing Fallback
    // ------------------------------------------------------------------------

    /// @brief Fallback: Measure generic instruction timing
    [[nodiscard]] uint64_t Fallback_MeasureInstructionTiming(uint32_t iterations, 
                                                              uint32_t instructionType) noexcept {
        if (iterations == 0) return 0;

        uint64_t totalCycles = 0;
        int cpuInfo[4] = { 0 };

        for (uint32_t i = 0; i < iterations; ++i) {
            // Serialize
            __cpuid(cpuInfo, 0);
            uint64_t start = __rdtsc();

            // Execute instruction based on type
            switch (instructionType) {
                case 0:  // CPUID
                    __cpuid(cpuInfo, 0);
                    break;
                case 1:  // RDTSC (already doing it)
                    (void)__rdtsc();
                    break;
                case 2:  // Memory fence
                    _mm_mfence();
                    break;
                default:
                    __cpuid(cpuInfo, 0);
                    break;
            }

            uint64_t end = __rdtsc();
            totalCycles += (end - start);
        }

        return totalCycles / iterations;
    }

    // ------------------------------------------------------------------------
    // VMCALL/VMMCALL Fallbacks
    // ------------------------------------------------------------------------

    /// @brief Fallback: Detect VMCALL (Intel VT-x)
    /// @note Cannot safely execute VMCALL without ASM/SEH
    [[nodiscard]] bool Fallback_DetectVMCALL() noexcept {
        // VMCALL would cause #UD on bare metal
        // Fallback cannot safely test this - return false
        return false;
    }

    /// @brief Fallback: Detect VMMCALL (AMD-V)
    [[nodiscard]] bool Fallback_DetectVMMCALL() noexcept {
        // VMMCALL would cause #UD on bare metal
        // Fallback cannot safely test this - return false
        return false;
    }

    // ------------------------------------------------------------------------
    // CPUID Leaf Range Fallback
    // ------------------------------------------------------------------------

    /// @brief Fallback: Check CPUID leaf range
    [[nodiscard]] uint32_t Fallback_CheckCPUIDLeafRange() noexcept {
        int cpuInfo[4] = { 0 };
        
        // Check if hypervisor is present
        __cpuid(cpuInfo, 1);
        if ((cpuInfo[2] & (1 << 31)) == 0) {
            return 0;  // No hypervisor
        }

        // Get hypervisor leaf range
        __cpuid(cpuInfo, 0x40000000);
        return static_cast<uint32_t>(cpuInfo[0]);  // Max leaf value
    }

    // ------------------------------------------------------------------------
    // IDT/GDT Combined Fallback
    // ------------------------------------------------------------------------

    /// @brief Fallback: Get IDT and GDT info
    [[nodiscard]] bool Fallback_GetIDTAndGDTInfo(uint64_t* idtBase, uint16_t* idtLimit,
                                                  uint64_t* gdtBase, uint16_t* gdtLimit) noexcept {
        // Cannot get this info without ASM
        // Return sentinel values that won't trigger false positives
        if (idtBase) *idtBase = 0xFFFFFFFF'FFFFFFFF;
        if (idtLimit) *idtLimit = 0xFFF;  // Typical limit
        if (gdtBase) *gdtBase = 0xFFFFFFFF'FFFFFFFF;
        if (gdtLimit) *gdtLimit = 0x7F;   // Typical limit
        return true;
    }

    // ------------------------------------------------------------------------
    // RDTSCP Timing Fallback
    // ------------------------------------------------------------------------

    /// @brief Fallback: Measure RDTSCP timing
    [[nodiscard]] uint64_t Fallback_MeasureRDTSCPTiming(uint32_t iterations) noexcept {
        if (iterations == 0) return 0;

        uint64_t totalCycles = 0;
        unsigned int aux = 0;

        for (uint32_t i = 0; i < iterations; ++i) {
            // RDTSCP is serializing, no need for CPUID fence
            uint64_t start = __rdtscp(&aux);
            
            // Execute something that causes VM exit
            int cpuInfo[4] = { 0 };
            __cpuid(cpuInfo, 0);
            
            uint64_t end = __rdtscp(&aux);
            
            totalCycles += (end - start);
        }

        return totalCycles / iterations;
    }

} // anonymous namespace

// ============================================================================
// WRAPPER FUNCTIONS - Select ASM or Fallback
// ============================================================================
// These inline wrappers allow easy switching between ASM and fallback
// implementations. In production, USE_ASM_FUNCTIONS should be true.
// For testing/debugging, set to false to use intrinsic-based fallbacks.
// ============================================================================

namespace {
    /// @brief Wrapper for CPUID hypervisor bit check
    [[nodiscard]] inline bool Safe_CheckCPUIDHypervisorBit() noexcept {
        if constexpr (USE_ASM_FUNCTIONS) {
            return CheckCPUIDHypervisorBit();
        } else {
            return Fallback_CheckCPUIDHypervisorBit();
        }
    }

    /// @brief Wrapper for CPUID vendor string
    inline void Safe_GetCPUIDVendorString(char* buffer, size_t bufferSize) noexcept {
        if constexpr (USE_ASM_FUNCTIONS) {
            GetCPUIDVendorString(buffer, bufferSize);
        } else {
            Fallback_GetCPUIDVendorString(buffer, bufferSize);
        }
    }

    /// @brief Wrapper for RDTSC timing
    [[nodiscard]] inline uint64_t Safe_MeasureRDTSCTimingDelta(uint32_t iterations) noexcept {
        if constexpr (USE_ASM_FUNCTIONS) {
            return MeasureRDTSCTimingDelta(iterations);
        } else {
            return Fallback_MeasureRDTSCTimingDelta(iterations);
        }
    }

    /// @brief Wrapper for IDT base
    [[nodiscard]] inline uint64_t Safe_GetIDTBase() noexcept {
        if constexpr (USE_ASM_FUNCTIONS) {
            return GetIDTBase();
        } else {
            return Fallback_GetIDTBase();
        }
    }

    /// @brief Wrapper for GDT base
    [[nodiscard]] inline uint64_t Safe_GetGDTBase() noexcept {
        if constexpr (USE_ASM_FUNCTIONS) {
            return GetGDTBase();
        } else {
            return Fallback_GetGDTBase();
        }
    }

    /// @brief Wrapper for LDT selector
    [[nodiscard]] inline uint16_t Safe_GetLDTSelector() noexcept {
        if constexpr (USE_ASM_FUNCTIONS) {
            return GetLDTSelector();
        } else {
            return Fallback_GetLDTSelector();
        }
    }

    /// @brief Wrapper for TR selector
    [[nodiscard]] inline uint16_t Safe_GetTRSelector() noexcept {
        if constexpr (USE_ASM_FUNCTIONS) {
            return GetTRSelector();
        } else {
            return Fallback_GetTRSelector();
        }
    }

    /// @brief Wrapper for VMware backdoor
    inline void Safe_CheckVMwareBackdoor(uint32_t* rax, uint32_t* rbx, 
                                          uint32_t* rcx, uint32_t* rdx) noexcept {
        if constexpr (USE_ASM_FUNCTIONS) {
            CheckVMwareBackdoor(rax, rbx, rcx, rdx);
        } else {
            Fallback_CheckVMwareBackdoor(rax, rbx, rcx, rdx);
        }
    }

    /// @brief Wrapper for CPUID timing
    [[nodiscard]] inline uint64_t Safe_MeasureCPUIDTiming(uint32_t iterations) noexcept {
        if constexpr (USE_ASM_FUNCTIONS) {
            return MeasureCPUIDTiming(iterations);
        } else {
            return Fallback_MeasureCPUIDTiming(iterations);
        }
    }

    /// @brief Wrapper for Hyper-V backdoor
    [[nodiscard]] inline uint32_t Safe_CheckHyperVBackdoor() noexcept {
        if constexpr (USE_ASM_FUNCTIONS) {
            return CheckHyperVBackdoor();
        } else {
            return Fallback_CheckHyperVBackdoor();
        }
    }

    /// @brief Wrapper for extended CPUID
    [[nodiscard]] inline bool Safe_GetExtendedCPUIDInfo(uint32_t leaf, uint32_t subleaf,
                                                         uint32_t* eax, uint32_t* ebx,
                                                         uint32_t* ecx, uint32_t* edx) noexcept {
        if constexpr (USE_ASM_FUNCTIONS) {
            return GetExtendedCPUIDInfo(leaf, subleaf, eax, ebx, ecx, edx);
        } else {
            return Fallback_GetExtendedCPUIDInfo(leaf, subleaf, eax, ebx, ecx, edx);
        }
    }

    /// @brief Wrapper for segment limits
    [[nodiscard]] inline bool Safe_CheckSegmentLimits(uint32_t* csLimit, uint32_t* dsLimit, 
                                                       uint32_t* ssLimit) noexcept {
        if constexpr (USE_ASM_FUNCTIONS) {
            return CheckSegmentLimits(csLimit, dsLimit, ssLimit);
        } else {
            return Fallback_CheckSegmentLimits(csLimit, dsLimit, ssLimit);
        }
    }

    /// @brief Wrapper for instruction timing
    [[nodiscard]] inline uint64_t Safe_MeasureInstructionTiming(uint32_t iterations, 
                                                                 uint32_t instructionType) noexcept {
        if constexpr (USE_ASM_FUNCTIONS) {
            return MeasureInstructionTiming(iterations, instructionType);
        } else {
            return Fallback_MeasureInstructionTiming(iterations, instructionType);
        }
    }

    /// @brief Wrapper for VMCALL detection
    [[nodiscard]] inline bool Safe_DetectVMCALL() noexcept {
        if constexpr (USE_ASM_FUNCTIONS) {
            return DetectVMCALL();
        } else {
            return Fallback_DetectVMCALL();
        }
    }

    /// @brief Wrapper for VMMCALL detection
    [[nodiscard]] inline bool Safe_DetectVMMCALL() noexcept {
        if constexpr (USE_ASM_FUNCTIONS) {
            return DetectVMMCALL();
        } else {
            return Fallback_DetectVMMCALL();
        }
    }

    /// @brief Wrapper for CPUID leaf range
    [[nodiscard]] inline uint32_t Safe_CheckCPUIDLeafRange() noexcept {
        if constexpr (USE_ASM_FUNCTIONS) {
            return CheckCPUIDLeafRange();
        } else {
            return Fallback_CheckCPUIDLeafRange();
        }
    }

    /// @brief Wrapper for IDT/GDT info
    [[nodiscard]] inline bool Safe_GetIDTAndGDTInfo(uint64_t* idtBase, uint16_t* idtLimit,
                                                     uint64_t* gdtBase, uint16_t* gdtLimit) noexcept {
        if constexpr (USE_ASM_FUNCTIONS) {
            return GetIDTAndGDTInfo(idtBase, idtLimit, gdtBase, gdtLimit);
        } else {
            return Fallback_GetIDTAndGDTInfo(idtBase, idtLimit, gdtBase, gdtLimit);
        }
    }

    /// @brief Wrapper for RDTSCP timing
    [[nodiscard]] inline uint64_t Safe_MeasureRDTSCPTiming(uint32_t iterations) noexcept {
        if constexpr (USE_ASM_FUNCTIONS) {
            return MeasureRDTSCPTiming(iterations);
        } else {
            return Fallback_MeasureRDTSCPTiming(iterations);
        }
    }

} // anonymous namespace

namespace ShadowStrike {
namespace AntiEvasion {

// ============================================================================
// Internal Helpers
// ============================================================================

namespace {
    struct WindowSearchContext {
        std::vector<std::pair<std::wstring, std::wstring>> matches;
    };

    BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
        WindowSearchContext* context = reinterpret_cast<WindowSearchContext*>(lParam);

        // Get class name
        wchar_t className[256] = { 0 };
        if (GetClassNameW(hwnd, className, ARRAYSIZE(className)) == 0) {
            return TRUE;
        }

        std::wstring classStr(className);

        // Check against known VM window classes
        for (const auto& knownClass : VMConstants::KNOWN_VM_WINDOW_CLASSES) {
            if (classStr == knownClass) {
                // Get window title for context (optional but useful)
                wchar_t windowTitle[256] = { 0 };
                GetWindowTextW(hwnd, windowTitle, ARRAYSIZE(windowTitle));

                context->matches.emplace_back(classStr, std::wstring(windowTitle));
                break; // Found a match, stop checking other classes for this window
            }
        }

        return TRUE;
    }

    // =========================================================================
    // ENTERPRISE FALSE POSITIVE REDUCTION - Cloud Environment Detection
    // =========================================================================
    // Detect legitimate cloud environments (AWS EC2, Azure, GCP) to avoid
    // flagging enterprise production workloads as "malware evasion".
    //
    // Cloud VMs are LEGITIMATE - only flag as suspicious if combined with
    // actual malware evasion indicators (sandbox tools, analysis artifacts).
    // =========================================================================

    struct CloudEnvironmentInfo {
        bool isCloud = false;
        std::wstring provider;
        std::wstring instanceId;
        std::wstring region;
    };

    /// @brief Detect AWS EC2 environment via SMBIOS/DMI data
    [[nodiscard]] bool DetectAWSEC2(CloudEnvironmentInfo& info) {
        // AWS EC2 instances have specific SMBIOS entries
        // Check system manufacturer and product name in registry
        HKEY key;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"HARDWARE\\DESCRIPTION\\System\\BIOS",
            0, KEY_READ, &key) == ERROR_SUCCESS) {
            
            wchar_t manufacturer[256] = {};
            wchar_t product[256] = {};
            DWORD size = sizeof(manufacturer);
            
            RegQueryValueExW(key, L"SystemManufacturer", nullptr, nullptr,
                            reinterpret_cast<LPBYTE>(manufacturer), &size);
            
            size = sizeof(product);
            RegQueryValueExW(key, L"SystemProductName", nullptr, nullptr,
                            reinterpret_cast<LPBYTE>(product), &size);
            
            RegCloseKey(key);
            
            std::wstring mfr(manufacturer);
            std::wstring prod(product);
            
            // AWS EC2 instances report "Amazon EC2" or "Xen" as manufacturer
            if (mfr.find(L"Amazon") != std::wstring::npos ||
                prod.find(L"EC2") != std::wstring::npos ||
                (mfr.find(L"Xen") != std::wstring::npos && prod.find(L"HVM") != std::wstring::npos)) {
                info.isCloud = true;
                info.provider = L"Amazon Web Services (EC2)";
                return true;
            }
        }
        return false;
    }

    /// @brief Detect Microsoft Azure environment
    [[nodiscard]] bool DetectAzure(CloudEnvironmentInfo& info) {
        // Azure VMs have specific SMBIOS entries and Hyper-V indicators
        HKEY key;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"HARDWARE\\DESCRIPTION\\System\\BIOS",
            0, KEY_READ, &key) == ERROR_SUCCESS) {
            
            wchar_t manufacturer[256] = {};
            wchar_t product[256] = {};
            DWORD size = sizeof(manufacturer);
            
            RegQueryValueExW(key, L"SystemManufacturer", nullptr, nullptr,
                            reinterpret_cast<LPBYTE>(manufacturer), &size);
            
            size = sizeof(product);
            RegQueryValueExW(key, L"SystemProductName", nullptr, nullptr,
                            reinterpret_cast<LPBYTE>(product), &size);
            
            RegCloseKey(key);
            
            std::wstring mfr(manufacturer);
            std::wstring prod(product);
            
            // Azure VMs report "Microsoft Corporation" and "Virtual Machine"
            if (mfr.find(L"Microsoft") != std::wstring::npos &&
                prod.find(L"Virtual Machine") != std::wstring::npos) {
                info.isCloud = true;
                info.provider = L"Microsoft Azure";
                return true;
            }
        }
        
        // Also check for Azure-specific registry key
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows Azure",
            0, KEY_READ, &key) == ERROR_SUCCESS) {
            RegCloseKey(key);
            info.isCloud = true;
            info.provider = L"Microsoft Azure";
            return true;
        }
        
        return false;
    }

    /// @brief Detect Google Cloud Platform environment
    [[nodiscard]] bool DetectGCP(CloudEnvironmentInfo& info) {
        HKEY key;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"HARDWARE\\DESCRIPTION\\System\\BIOS",
            0, KEY_READ, &key) == ERROR_SUCCESS) {
            
            wchar_t manufacturer[256] = {};
            wchar_t product[256] = {};
            DWORD size = sizeof(manufacturer);
            
            RegQueryValueExW(key, L"SystemManufacturer", nullptr, nullptr,
                            reinterpret_cast<LPBYTE>(manufacturer), &size);
            
            size = sizeof(product);
            RegQueryValueExW(key, L"SystemProductName", nullptr, nullptr,
                            reinterpret_cast<LPBYTE>(product), &size);
            
            RegCloseKey(key);
            
            std::wstring mfr(manufacturer);
            std::wstring prod(product);
            
            // GCP VMs report "Google" as manufacturer
            if (mfr.find(L"Google") != std::wstring::npos) {
                info.isCloud = true;
                info.provider = L"Google Cloud Platform";
                return true;
            }
        }
        return false;
    }

    /// @brief Detect enterprise VMware vSphere environment
    [[nodiscard]] bool DetectEnterpriseVMware(CloudEnvironmentInfo& info) {
        // Check if this is enterprise VMware (vSphere/ESXi) vs desktop VMware
        // Enterprise deployments typically have:
        // - Domain membership
        // - VMware Tools with enterprise features
        // - Corporate network indicators
        
        // Check for VMware Tools with enterprise configuration
        HKEY key;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\VMware, Inc.\\VMware Tools",
            0, KEY_READ, &key) == ERROR_SUCCESS) {
            
            // Check if machine is domain-joined (indicates enterprise)
            wchar_t domain[256] = {};
            DWORD size = sizeof(domain);
            
            if (GetComputerNameExW(ComputerNameDnsDomain, domain, &size) && wcslen(domain) > 0) {
                // Domain-joined VMware = likely enterprise vSphere
                RegCloseKey(key);
                info.isCloud = true;  // Treat enterprise VMware as "legitimate cloud"
                info.provider = L"VMware vSphere (Enterprise)";
                return true;
            }
            
            RegCloseKey(key);
        }
        return false;
    }

    /// @brief Master cloud/enterprise environment detection
    [[nodiscard]] CloudEnvironmentInfo DetectCloudEnvironment() {
        CloudEnvironmentInfo info;
        
        // Check in order of likelihood for enterprise deployments
        if (DetectAWSEC2(info)) return info;
        if (DetectAzure(info)) return info;
        if (DetectGCP(info)) return info;
        if (DetectEnterpriseVMware(info)) return info;
        
        return info;
    }

    /// @brief Check if VM type is a known legitimate cloud provider
    [[nodiscard]] bool IsLegitimateCloudVMType(VMType type) {
        switch (type) {
            case VMType::AmazonEC2:
            case VMType::AzureVM:
            case VMType::GoogleCloud:
            case VMType::HyperV:  // Could be Azure or enterprise Hyper-V
                return true;
            default:
                return false;
        }
    }

    // =========================================================================
    // SEH ISOLATION HELPERS
    // =========================================================================
    // C2712 Error: "__try cannot be used in functions that require object unwinding"
    // 
    // SEH (__try/__except) cannot coexist with C++ objects that have destructors
    // in the same function. These helper functions isolate the SEH code so that
    // the main functions can safely use std::wstring, std::vector, etc.
    // =========================================================================

    /// @brief Structure to hold I/O port probe results (POD type - no destructors)
    struct IOPortProbeResult {
        bool vmwareDetected;
        uint32_t vmwareResponse;
        bool vboxDetected;
        uint16_t vboxResponse;
    };

    /// @brief Isolated SEH function for VMware backdoor probe
    /// @note This function has NO C++ objects - only POD types for SEH compatibility
    [[nodiscard]] bool ProbeVMwareBackdoor_SEH(uint32_t* outResponse) noexcept {
        __try {
            // TryVMwareBackdoor is declared noexcept and uses only POD
            uint32_t response = 0;
            
            // VMware backdoor uses port 0x5658 with magic value 0x564D5868 ('VMXh')
            // We need to call the external function that does the actual probe
            uint32_t rax = 0, rbx = 0, rcx = 0, rdx = 0;
            CheckVMwareBackdoor(&rax, &rbx, &rcx, &rdx);
            
            // VMware returns magic value in EBX if backdoor is present
            if (rbx == 0x564D5868) {  // 'VMXh' magic
                if (outResponse) *outResponse = rbx;
                return true;
            }
            return false;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // Exception means we're not in VMware (normal on bare metal)
            return false;
        }
    }

    /// @brief Isolated SEH function for VirtualBox I/O port probe
    /// @note This function has NO C++ objects - only POD types for SEH compatibility
    [[nodiscard]] bool ProbeVirtualBoxPort_SEH(uint16_t* outValue) noexcept {
        __try {
            // Attempt to read VirtualBox I/O port
            // This will cause #GP exception on non-VirtualBox systems
            uint16_t val = __inword(0x4042);  // VirtualBox port
            if (outValue) *outValue = val;
            return true;  // If we reach here, we're in VirtualBox
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // Exception means we're not in VirtualBox (normal on bare metal)
            return false;
        }
    }

    /// @brief Combined I/O port probing with SEH isolation
    [[nodiscard]] IOPortProbeResult ProbeAllIOPorts_SEH() noexcept {
        IOPortProbeResult result = {};
        result.vmwareDetected = ProbeVMwareBackdoor_SEH(&result.vmwareResponse);
        result.vboxDetected = ProbeVirtualBoxPort_SEH(&result.vboxResponse);
        return result;
    }
}

// ============================================================================
// VMEvasionResult Implementation
// ============================================================================

std::wstring VMEvasionResult::GetSummary() const {
    std::wstringstream ss;

    if (isVM) {
        ss << L"VM Detected: " << VMEvasionDetector::VMTypeToString(detectedType);
        if (secondaryType != VMType::None) {
            ss << L" (Nested: " << VMEvasionDetector::VMTypeToString(secondaryType) << L")";
        }
        ss << L" - Confidence: " << std::fixed << std::setprecision(1) << confidenceScore << L"%";
        ss << L" - Artifacts: " << artifacts.size();
        ss << L" - Categories: " << GetCategoryCount();
    } else {
        ss << L"No VM Detected (Bare Metal) - Confidence: "
           << std::fixed << std::setprecision(1) << (100.0f - confidenceScore) << L"%";
    }

    if (timedOut) {
        ss << L" [TIMED OUT]";
    }

    return ss.str();
}

std::vector<VMArtifact> VMEvasionResult::GetArtifactsByCategory(VMDetectionCategory category) const {
    std::vector<VMArtifact> filtered;
    filtered.reserve(artifacts.size());

    for (const auto& artifact : artifacts) {
        if (artifact.category == category) {
            filtered.push_back(artifact);
        }
    }

    return filtered;
}

std::vector<VMArtifact> VMEvasionResult::GetArtifactsByVMType(VMType type) const {
    std::vector<VMArtifact> filtered;
    filtered.reserve(artifacts.size());

    for (const auto& artifact : artifacts) {
        if (artifact.associatedVMType == type) {
            filtered.push_back(artifact);
        }
    }

    return filtered;
}

size_t VMEvasionResult::GetCategoryCount() const noexcept {
    size_t count = 0;
    uint16_t flags = static_cast<uint16_t>(triggeredCategories);

    // Count set bits
    while (flags) {
        count += (flags & 1);
        flags >>= 1;
    }

    return count;
}

void VMEvasionResult::Clear() noexcept {
    isVM = false;
    detectedType = VMType::None;
    secondaryType = VMType::None;
    confidenceScore = 0.0f;
    confidenceLevel = VMConfidenceLevel::None;
    triggeredCategories = VMDetectionCategory::None;

    cpuidInfo.Clear();
    firmwareInfo.Clear();
    timingInfo = {};
    networkIndicators.clear();
    artifacts.clear();
    categoryScores.clear();

    detectionTime = {};
    detectionDuration = {};
    completed = false;
    timedOut = false;
    errorMessage.clear();
}

// ============================================================================
// VMEvasionDetector::Impl - PIMPL Implementation
// ============================================================================

struct VMEvasionDetector::Impl {
    // Thread synchronization
    mutable std::shared_mutex m_mutex;

    // Configuration
    VMDetectionConfig m_config;

    // External integrations
    std::shared_ptr<ThreatIntel::ThreatIntelStore> m_threatIntel;
    std::shared_ptr<SignatureStore::SignatureStore> m_signatureStore;

    // Cache management
    std::optional<VMEvasionResult> m_cachedResult;
    std::chrono::system_clock::time_point m_cacheTimestamp;
    mutable std::mutex m_cacheMutex;

    // Statistics
    VMDetectionStatistics m_statistics;

    // Callbacks
    ArtifactCallback m_artifactCallback;
    ProgressCallback m_progressCallback;

    // Known VM artifacts (pre-populated for fast lookup)
    std::unordered_set<std::wstring> m_knownVMProcesses;
    std::unordered_set<std::wstring> m_knownVMServices;
    std::vector<std::wstring> m_knownVMRegKeys;
    std::vector<std::wstring> m_knownVMFiles;
    std::vector<std::wstring> m_knownVMDeviceIDs;

    // Initialization flag
    std::atomic<bool> m_initialized{false};

    // Constructor
    Impl(std::shared_ptr<ThreatIntel::ThreatIntelStore> threatIntel,
         std::shared_ptr<SignatureStore::SignatureStore> signatureStore,
         const VMDetectionConfig& config)
        : m_config(config)
        , m_threatIntel(std::move(threatIntel))
        , m_signatureStore(std::move(signatureStore))
    {
        InitializeKnownArtifacts();
    }

    void InitializeKnownArtifacts() {
        // Populate known VM processes
        for (const auto& proc : VMConstants::KNOWN_VM_PROCESSES) {
            m_knownVMProcesses.insert(std::wstring(proc));
        }

        // Populate known VM services
        for (const auto& svc : VMConstants::KNOWN_VM_SERVICES) {
            m_knownVMServices.insert(std::wstring(svc));
        }

        // Populate known VM registry keys
        for (const auto& key : VMConstants::KNOWN_VM_REGISTRY_KEYS) {
            m_knownVMRegKeys.push_back(std::wstring(key));
        }

        // Populate known VM files
        for (const auto& file : VMConstants::KNOWN_VM_FILES) {
            m_knownVMFiles.push_back(std::wstring(file));
        }

        // Populate known VM device IDs
        for (const auto& dev : VMConstants::KNOWN_VM_DEVICE_IDS) {
            m_knownVMDeviceIDs.push_back(std::wstring(dev));
        }

        m_initialized.store(true, std::memory_order_release);
    }

    [[nodiscard]] bool IsCacheValid() const {
        if (!m_cachedResult.has_value()) {
            return false;
        }

        const auto now = std::chrono::system_clock::now();
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - m_cacheTimestamp
        ).count();

        return elapsed < VMConstants::RESULT_CACHE_TTL_SECONDS;
    }

    void InvalidateCache() {
        std::lock_guard<std::mutex> lock(m_cacheMutex);
        m_cachedResult.reset();
    }

    [[nodiscard]] std::optional<VMEvasionResult> GetCachedResult() const {
        std::lock_guard<std::mutex> lock(m_cacheMutex);

        if (!IsCacheValid()) {
            return std::nullopt;
        }

        return m_cachedResult;
    }

    void UpdateCache(const VMEvasionResult& result) {
        if (!m_config.enableCaching) {
            return;
        }

        std::lock_guard<std::mutex> lock(m_cacheMutex);
        m_cachedResult = result;
        m_cacheTimestamp = std::chrono::system_clock::now();
    }
};

// ============================================================================
// VMEvasionDetector - Public API Implementation
// ============================================================================

VMEvasionDetector::VMEvasionDetector(
    std::shared_ptr<ThreatIntel::ThreatIntelStore> threatStore,
    const VMDetectionConfig& config
)
    : m_impl(std::make_unique<Impl>(std::move(threatStore), nullptr, config))
{
    Initialize();
    SS_LOG_INFO(L"AntiEvasion", L"VMEvasionDetector initialized with default configuration");
}

VMEvasionDetector::VMEvasionDetector(
    std::shared_ptr<ThreatIntel::ThreatIntelStore> threatStore,
    std::shared_ptr<SignatureStore::SignatureStore> signatureStore,
    const VMDetectionConfig& config
)
    : m_impl(std::make_unique<Impl>(std::move(threatStore), std::move(signatureStore), config))
{
    Initialize();
    SS_LOG_INFO(L"AntiEvasion", L"VMEvasionDetector initialized with ThreatIntel and SignatureStore");
}

VMEvasionDetector::~VMEvasionDetector() {
    SS_LOG_INFO(L"AntiEvasion", L"VMEvasionDetector shutting down");
}

VMEvasionDetector::VMEvasionDetector(VMEvasionDetector&&) noexcept = default;
VMEvasionDetector& VMEvasionDetector::operator=(VMEvasionDetector&&) noexcept = default;

void VMEvasionDetector::Initialize() {
    // Initialization already done in Impl constructor
    SS_LOG_INFO(L"AntiEvasion", L"VMEvasionDetector: Artifact database loaded - %zu processes, %zu services, %zu registry keys",
                        m_impl->m_knownVMProcesses.size(),
                        m_impl->m_knownVMServices.size(),
                        m_impl->m_knownVMRegKeys.size());
}

// ============================================================================
// Primary Detection API
// ============================================================================

VMEvasionResult VMEvasionDetector::DetectEnvironment() {
    const auto startTime = std::chrono::high_resolution_clock::now();

    m_impl->m_statistics.totalDetections.fetch_add(1, std::memory_order_relaxed);

    // Check cache first
    if (m_impl->m_config.enableCaching) {
        if (auto cached = m_impl->GetCachedResult()) {
            m_impl->m_statistics.cacheHits.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_INFO(L"AntiEvasion", L"VMEvasionDetector: Returning cached result (VM: %d)", cached->isVM);
            return *cached;
        }
        m_impl->m_statistics.cacheMisses.fetch_add(1, std::memory_order_relaxed);
    }

    VMEvasionResult result;
    result.detectionTime = std::chrono::system_clock::now();

    try {
        std::shared_lock<std::shared_mutex> lock(m_impl->m_mutex);

        // Execute detection checks based on enabled categories
        const auto& config = m_impl->m_config;

        if (config.IsCategoryEnabled(VMDetectionCategory::CPUID)) {
            CheckCPUID(result);
        }

        if (config.IsCategoryEnabled(VMDetectionCategory::Registry)) {
            CheckRegistryArtifacts(result);
        }

        if (config.IsCategoryEnabled(VMDetectionCategory::FileSystem)) {
            CheckFileArtifacts(result);
        }

        if (config.IsCategoryEnabled(VMDetectionCategory::Network)) {
            CheckNetworkAdapters(result);
        }

        if (config.IsCategoryEnabled(VMDetectionCategory::Firmware)) {
            CheckFirmwareTables(result);
        }

        if (config.IsCategoryEnabled(VMDetectionCategory::Process) && config.enableProcessEnumeration) {
            CheckRunningProcesses(result);
        }

        if (config.IsCategoryEnabled(VMDetectionCategory::Timing) && config.enableTimingChecks) {
            CheckTiming(result);
        }

        if (config.IsCategoryEnabled(VMDetectionCategory::IOPort) && config.enableIOPortProbing) {
            CheckIOPorts(result);
        }

        if (config.IsCategoryEnabled(VMDetectionCategory::Memory) && config.enableMemoryScanning) {
            CheckMemoryArtifacts(result);
        }

        if (config.IsCategoryEnabled(VMDetectionCategory::Device)) {
            CheckDevices(result);
        }

        if (config.IsCategoryEnabled(VMDetectionCategory::WMI) && config.enableWMIQueries) {
            CheckWMI(result);
        }

        if (config.IsCategoryEnabled(VMDetectionCategory::Window)) {
            CheckWindows(result);
        }

        // Calculate final scores and determine VM type
        CalculateFinalScore(result);
        DetermineVMType(result);

        result.completed = true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"AntiEvasion", L"VMEvasionDetector: Detection failed - %hs", e.what());
        result.completed = false;
        result.errorMessage = Utils::StringUtils::ToWide(e.what());
    }

    const auto endTime = std::chrono::high_resolution_clock::now();
    result.detectionDuration = std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime);

    // Update statistics
    UpdateStatistics(result, result.detectionDuration);

    // Update cache
    m_impl->UpdateCache(result);

    if (result.isVM) {
        m_impl->m_statistics.vmDetectedCount.fetch_add(1, std::memory_order_relaxed);
        SS_LOG_WARN(L"AntiEvasion", L"VMEvasionDetector: VM DETECTED - %ls (confidence: %.1f%%, duration: %lldms)",
                           VMTypeToString(result.detectedType).c_str(),
                           result.confidenceScore,
                           result.detectionDuration.count() / 1000000);
    } else {
        SS_LOG_INFO(L"AntiEvasion", L"VMEvasionDetector: No VM detected (duration: %lldms)",
                          result.detectionDuration.count() / 1000000);
    }

    return result;
}

VMEvasionResult VMEvasionDetector::DetectEnvironment(const VMDetectionConfig& config) {
    // Temporarily use custom config (don't cache these results)
    const auto originalConfig = m_impl->m_config;
    m_impl->m_config = config;
    m_impl->m_config.enableCaching = false;  // Force no caching for custom config

    auto result = DetectEnvironment();

    m_impl->m_config = originalConfig;

    return result;
}

VMEvasionResult VMEvasionDetector::DetectEnvironmentWithProgress(ProgressCallback callback) {
    m_impl->m_progressCallback = std::move(callback);
    auto result = DetectEnvironment();
    m_impl->m_progressCallback = nullptr;
    return result;
}

CPUIDInfo VMEvasionDetector::QuickDetectCPUID() {
    CPUIDInfo info;

    try {
        // Check hypervisor bit using assembly function (with fallback)
        info.hypervisorPresent = Safe_CheckCPUIDHypervisorBit();

        if (info.hypervisorPresent) {
            // Get vendor string from CPUID leaf 0x40000000
            char vendorBuffer[13] = {0};
            Safe_GetCPUIDVendorString(vendorBuffer, sizeof(vendorBuffer));
            info.vendorString = std::string(vendorBuffer, 12);

            // Parse vendor string to determine VM type
            info.detectedType = ParseHypervisorVendor(info.vendorString);
            info.isReliable = (info.detectedType != VMType::Unknown && info.detectedType != VMType::None);

            SS_LOG_INFO(L"AntiEvasion", L"QuickDetectCPUID: Hypervisor detected - Vendor: %ls, Type: %ls",
                              Utils::StringUtils::ToWide(info.vendorString).c_str(),
                              VMTypeToString(info.detectedType).c_str());
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"AntiEvasion", L"QuickDetectCPUID failed: %hs", e.what());
        info.Clear();
    }

    return info;
}

bool VMEvasionDetector::IsRunningInVM() {
    // Check cache first
    if (auto cached = m_impl->GetCachedResult()) {
        return cached->isVM;
    }

    // Quick CPUID check
    auto cpuidInfo = QuickDetectCPUID();
    return cpuidInfo.hypervisorPresent;
}

// ============================================================================
// Individual Detection Methods
// ============================================================================

void VMEvasionDetector::CheckCPUID(VMEvasionResult& result) {
    try {
        result.cpuidInfo = QuickDetectCPUID();

        if (result.cpuidInfo.hypervisorPresent) {
            AddArtifact(
                result,
                VMDetectionCategory::CPUID,
                result.cpuidInfo.detectedType,
                95.0f,  // Very high confidence
                L"CPUID hypervisor bit set (leaf 0x1, ECX bit 31)",
                Utils::StringUtils::ToWide(result.cpuidInfo.vendorString),
                L"CPUID.0x1.ECX[31]"
            );

            result.triggeredCategories = result.triggeredCategories | VMDetectionCategory::CPUID;
            result.categoryScores[VMDetectionCategory::CPUID] = 95.0f;

            m_impl->m_statistics.categoryTriggerCounts[0].fetch_add(1, std::memory_order_relaxed);
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"AntiEvasion", L"CheckCPUID failed: %hs", e.what());
    }
}

void VMEvasionDetector::CheckRegistryArtifacts(VMEvasionResult& result) {
    try {
        float categoryScore = 0.0f;
        size_t foundCount = 0;

        for (const auto& keyPath : m_impl->m_knownVMRegKeys) {
            try {
                // Try both HKLM and HKCU
                if (Utils::RegistryUtils::KeyExists(HKEY_LOCAL_MACHINE, keyPath)) {
                    foundCount++;

                    // Determine VM type from registry key
                    VMType vmType = VMType::Unknown;
                    float confidence = 80.0f;

                    if (keyPath.find(L"VMware") != std::wstring::npos) {
                        vmType = VMType::VMware;
                        confidence = 90.0f;
                    } else if (keyPath.find(L"VirtualBox") != std::wstring::npos || keyPath.find(L"VBox") != std::wstring::npos) {
                        vmType = VMType::VirtualBox;
                        confidence = 90.0f;
                    } else if (keyPath.find(L"Virtual Machine") != std::wstring::npos) {
                        vmType = VMType::HyperV;
                        confidence = 85.0f;
                    } else if (keyPath.find(L"Parallels") != std::wstring::npos) {
                        vmType = VMType::Parallels;
                        confidence = 90.0f;
                    }

                    AddArtifact(
                        result,
                        VMDetectionCategory::Registry,
                        vmType,
                        confidence,
                        L"VM-specific registry key found",
                        keyPath,
                        L"HKEY_LOCAL_MACHINE\\" + keyPath
                    );

                    categoryScore = std::max(categoryScore, confidence);
                }
            } catch (...) {
                // Key doesn't exist or access denied - continue
            }
        }

        if (foundCount > 0) {
            result.triggeredCategories = result.triggeredCategories | VMDetectionCategory::Registry;
            result.categoryScores[VMDetectionCategory::Registry] = categoryScore;
            m_impl->m_statistics.categoryTriggerCounts[1].fetch_add(1, std::memory_order_relaxed);

            SS_LOG_INFO(L"AntiEvasion", L"CheckRegistryArtifacts: Found %zu VM registry keys", foundCount);
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"AntiEvasion", L"CheckRegistryArtifacts failed: %hs", e.what());
    }
}

void VMEvasionDetector::CheckFileArtifacts(VMEvasionResult& result) {
    try {
        float categoryScore = 0.0f;
        size_t foundCount = 0;

        for (const auto& filePath : m_impl->m_knownVMFiles) {
            if (Utils::FileUtils::Exists(filePath)) {
                foundCount++;

                // Determine VM type from file path
                VMType vmType = VMType::Unknown;
                float confidence = 75.0f;

                if (filePath.find(L"vmware") != std::wstring::npos || filePath.find(L"VMware") != std::wstring::npos) {
                    vmType = VMType::VMware;
                    confidence = 85.0f;
                } else if (filePath.find(L"VBox") != std::wstring::npos) {
                    vmType = VMType::VirtualBox;
                    confidence = 85.0f;
                } else if (filePath.find(L"prl") != std::wstring::npos || filePath.find(L"Parallels") != std::wstring::npos) {
                    vmType = VMType::Parallels;
                    confidence = 85.0f;
                } else if (filePath.find(L"xen") != std::wstring::npos) {
                    vmType = VMType::Xen;
                    confidence = 85.0f;
                }

                AddArtifact(
                    result,
                    VMDetectionCategory::FileSystem,
                    vmType,
                    confidence,
                    L"VM-specific driver or tool file found",
                    filePath,
                    filePath
                );

                categoryScore = std::max(categoryScore, confidence);
            }
        }

        if (foundCount > 0) {
            result.triggeredCategories = result.triggeredCategories | VMDetectionCategory::FileSystem;
            result.categoryScores[VMDetectionCategory::FileSystem] = categoryScore;
            m_impl->m_statistics.categoryTriggerCounts[2].fetch_add(1, std::memory_order_relaxed);

            SS_LOG_INFO(L"AntiEvasion", L"CheckFileArtifacts: Found %zu VM files", foundCount);
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"AntiEvasion", L"CheckFileArtifacts failed: %hs", e.what());
    }
}

void VMEvasionDetector::CheckNetworkAdapters(VMEvasionResult& result) {
    try {
        std::vector<Utils::NetworkUtils::NetworkAdapterInfo> adapters;
        Utils::NetworkUtils::GetNetworkAdapters(adapters);
        float categoryScore = 0.0f;

        for (const auto& adapter : adapters) {
            auto mac = adapter.macAddress;
            VMType vmType = CheckMACAddress(mac);

            if (vmType != VMType::None) {
                VMNetworkInfo netInfo;
                netInfo.macAddress = mac;
                netInfo.adapterName = adapter.friendlyName;
                netInfo.associatedVMType = vmType;
                
                // =========================================================
                // FALSE POSITIVE FIX: Reduce confidence for cloud VMs
                // =========================================================
                // Cloud providers use VM MAC addresses legitimately.
                // Lower confidence for known cloud VM types to prevent
                // flagging AWS EC2, Azure, and GCP instances as suspicious.
                // =========================================================
                float confidence = 80.0f;
                if (IsLegitimateCloudVMType(vmType)) {
                    confidence = 30.0f;  // Lower confidence for cloud VMs
                    netInfo.confidence = confidence;
                } else if (vmType == VMType::VMware) {
                    // VMware could be desktop or enterprise vSphere
                    // Use moderate confidence until other checks confirm
                    confidence = 50.0f;
                    netInfo.confidence = confidence;
                } else {
                    netInfo.confidence = confidence;
                }
                
                netInfo.isVirtualAdapter = true;

                result.networkIndicators.push_back(netInfo);

                std::wstringstream macStr;
                macStr << std::hex << std::setfill(L'0') << std::uppercase;
                for (size_t i = 0; i < mac.bytes.size(); ++i) {
                    if (i > 0) macStr << L":";
                    macStr << std::setw(2) << static_cast<int>(mac.bytes[i]);
                }

                AddArtifact(
                    result,
                    VMDetectionCategory::Network,
                    vmType,
                    confidence,
                    L"VM-specific MAC OUI detected",
                    macStr.str(),
                    adapter.friendlyName
                );

                categoryScore = std::max(categoryScore, 80.0f);
            }
        }

        if (!result.networkIndicators.empty()) {
            result.triggeredCategories = result.triggeredCategories | VMDetectionCategory::Network;
            result.categoryScores[VMDetectionCategory::Network] = categoryScore;
            m_impl->m_statistics.categoryTriggerCounts[3].fetch_add(1, std::memory_order_relaxed);

            SS_LOG_INFO(L"AntiEvasion", L"CheckNetworkAdapters: Found %zu VM network adapters", result.networkIndicators.size());
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"AntiEvasion", L"CheckNetworkAdapters failed: %hs", e.what());
    }
}

void VMEvasionDetector::CheckFirmwareTables(VMEvasionResult& result) {
    try {
        // Query BIOS info from Registry as a fallback since SystemUtils doesn't provide direct SMBIOS access
        std::wstring biosVendor, biosVersion, systemManufacturer, systemModel;

        (void)Utils::RegistryUtils::QuickReadString(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVendor", biosVendor);
        (void)Utils::RegistryUtils::QuickReadString(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVersion", biosVersion);
        (void)Utils::RegistryUtils::QuickReadString(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemManufacturer", systemManufacturer);
        (void)Utils::RegistryUtils::QuickReadString(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemProductName", systemModel);

        result.firmwareInfo.biosVendor = biosVendor;
        result.firmwareInfo.biosVersion = biosVersion;
        result.firmwareInfo.systemManufacturer = systemManufacturer;
        result.firmwareInfo.systemProductName = systemModel;

        float categoryScore = 0.0f;
        VMType detectedType = VMType::None;

        // Check for known firmware strings
        for (const auto& vmString : VMConstants::KNOWN_FIRMWARE_STRINGS) {
            bool found = false;

            if (biosVendor.find(vmString) != std::wstring::npos ||
                biosVersion.find(vmString) != std::wstring::npos ||
                systemManufacturer.find(vmString) != std::wstring::npos ||
                systemModel.find(vmString) != std::wstring::npos) {
                found = true;
            }

            if (found) {
                // Determine VM type
                if (vmString.find(L"VMware") != std::wstring::npos || vmString.find(L"VMWARE") != std::wstring::npos) {
                    detectedType = VMType::VMware;
                    categoryScore = 95.0f;
                } else if (vmString.find(L"VirtualBox") != std::wstring::npos || vmString.find(L"VBOX") != std::wstring::npos || vmString.find(L"innotek") != std::wstring::npos) {
                    detectedType = VMType::VirtualBox;
                    categoryScore = 95.0f;
                } else if (vmString.find(L"Hyper-V") != std::wstring::npos || vmString.find(L"Microsoft Corporation") != std::wstring::npos) {
                    detectedType = VMType::HyperV;
                    categoryScore = 90.0f;
                } else if (vmString.find(L"QEMU") != std::wstring::npos || vmString.find(L"Bochs") != std::wstring::npos || vmString.find(L"SeaBIOS") != std::wstring::npos) {
                    detectedType = VMType::QEMU;
                    categoryScore = 90.0f;
                } else if (vmString.find(L"Xen") != std::wstring::npos || vmString.find(L"XEN") != std::wstring::npos) {
                    detectedType = VMType::Xen;
                    categoryScore = 90.0f;
                } else if (vmString.find(L"Parallels") != std::wstring::npos) {
                    detectedType = VMType::Parallels;
                    categoryScore = 90.0f;
                } else if (vmString.find(L"KVM") != std::wstring::npos) {
                    detectedType = VMType::KVM;
                    categoryScore = 85.0f;
                } else if (vmString.find(L"Amazon") != std::wstring::npos) {
                    detectedType = VMType::AmazonEC2;
                    categoryScore = 85.0f;
                } else if (vmString.find(L"Google") != std::wstring::npos) {
                    detectedType = VMType::GoogleCloud;
                    categoryScore = 85.0f;
                } else {
                    detectedType = VMType::GenericHypervisor;
                    categoryScore = 70.0f;
                }

                AddArtifact(
                    result,
                    VMDetectionCategory::Firmware,
                    detectedType,
                    categoryScore,
                    L"VM signature in firmware/SMBIOS tables",
                    vmString,
                    L"SMBIOS"
                );
            }
        }

        if (categoryScore > 0.0f) {
            result.firmwareInfo.detectedType = detectedType;
            result.firmwareInfo.confidence = categoryScore;
            result.triggeredCategories = result.triggeredCategories | VMDetectionCategory::Firmware;
            result.categoryScores[VMDetectionCategory::Firmware] = categoryScore;
            m_impl->m_statistics.categoryTriggerCounts[4].fetch_add(1, std::memory_order_relaxed);

            SS_LOG_INFO(L"AntiEvasion", L"CheckFirmwareTables: VM firmware detected - %ls", VMTypeToString(detectedType).c_str());
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"AntiEvasion", L"CheckFirmwareTables failed: %hs", e.what());
    }
}

void VMEvasionDetector::CheckRunningProcesses(VMEvasionResult& result) {
    try {
        std::vector<Utils::ProcessUtils::ProcessBasicInfo> processes;
        Utils::ProcessUtils::EnumerateProcesses(processes);
        float categoryScore = 0.0f;
        size_t foundCount = 0;

        for (const auto& proc : processes) {
            std::wstring procNameLower = Utils::StringUtils::ToLowerCopy(proc.name);

            if (m_impl->m_knownVMProcesses.count(procNameLower) > 0) {
                foundCount++;

                // Determine VM type from process name
                VMType vmType = VMType::Unknown;
                float confidence = 70.0f;

                if (procNameLower.find(L"vmware") != std::wstring::npos || procNameLower.find(L"vmtoolsd") != std::wstring::npos) {
                    vmType = VMType::VMware;
                    confidence = 85.0f;
                } else if (procNameLower.find(L"vbox") != std::wstring::npos) {
                    vmType = VMType::VirtualBox;
                    confidence = 85.0f;
                } else if (procNameLower.find(L"vmms") != std::wstring::npos || procNameLower.find(L"vmwp") != std::wstring::npos) {
                    vmType = VMType::HyperV;
                    confidence = 85.0f;
                } else if (procNameLower.find(L"qemu") != std::wstring::npos) {
                    vmType = VMType::QEMU;
                    confidence = 85.0f;
                } else if (procNameLower.find(L"xen") != std::wstring::npos) {
                    vmType = VMType::Xen;
                    confidence = 85.0f;
                } else if (procNameLower.find(L"prl_") != std::wstring::npos) {
                    vmType = VMType::Parallels;
                    confidence = 85.0f;
                } else if (procNameLower.find(L"sbie") != std::wstring::npos) {
                    vmType = VMType::Sandboxie;
                    confidence = 80.0f;
                } else if (procNameLower.find(L"wine") != std::wstring::npos) {
                    vmType = VMType::Wine;
                    confidence = 75.0f;
                }

                AddArtifact(
                    result,
                    VMDetectionCategory::Process,
                    vmType,
                    confidence,
                    L"VM-specific process detected",
                    proc.name,
                    L"PID: " + std::to_wstring(proc.pid)
                );

                categoryScore = std::max(categoryScore, confidence);
            }
        }

        if (foundCount > 0) {
            result.triggeredCategories = result.triggeredCategories | VMDetectionCategory::Process;
            result.categoryScores[VMDetectionCategory::Process] = categoryScore;
            m_impl->m_statistics.categoryTriggerCounts[5].fetch_add(1, std::memory_order_relaxed);

            SS_LOG_INFO(L"AntiEvasion", L"CheckRunningProcesses: Found %zu VM processes", foundCount);
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"AntiEvasion", L"CheckRunningProcesses failed: %hs", e.what());
    }
}

void VMEvasionDetector::CheckTiming(VMEvasionResult& result) {
    try {
        // Use assembly function to measure RDTSC timing (with fallback)
        const uint32_t iterations = 1000;
        uint64_t delta = Safe_MeasureRDTSCTimingDelta(iterations);

        result.timingInfo.rdtscDelta = delta;
        result.timingInfo.sampleCount = iterations;
        result.timingInfo.averageDelta = delta / iterations;

        // Threshold for VM detection (VMs typically have higher RDTSC variance)
        constexpr uint64_t VM_THRESHOLD = 1000;  // Cycles

        if (result.timingInfo.averageDelta > VM_THRESHOLD) {
            result.timingInfo.timingAnomalyDetected = true;
            result.timingInfo.confidence = 60.0f;  // Medium confidence (can be noisy)

            AddArtifact(
                result,
                VMDetectionCategory::Timing,
                VMType::GenericHypervisor,
                60.0f,
                L"RDTSC timing anomaly detected (VM overhead)",
                std::to_wstring(result.timingInfo.averageDelta) + L" cycles",
                L"RDTSC"
            );

            result.triggeredCategories = result.triggeredCategories | VMDetectionCategory::Timing;
            result.categoryScores[VMDetectionCategory::Timing] = 60.0f;
            m_impl->m_statistics.categoryTriggerCounts[6].fetch_add(1, std::memory_order_relaxed);

            SS_LOG_INFO(L"AntiEvasion", L"CheckTiming: Timing anomaly detected - avg %llu cycles", result.timingInfo.averageDelta);
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"AntiEvasion", L"CheckTiming failed: %hs", e.what());
    }
}

void VMEvasionDetector::CheckIOPorts(VMEvasionResult& result) {
    // =========================================================================
    // I/O PORT VM DETECTION
    // =========================================================================
    // Uses SEH-isolated helper functions to avoid C2712 error.
    // SEH (__try/__except) cannot be used in functions with C++ objects
    // that have destructors (std::wstring, etc.), so we isolate the
    // privileged I/O operations in separate POD-only functions.
    // =========================================================================

    // Probe all I/O ports using SEH-isolated helper
    IOPortProbeResult probeResult = ProbeAllIOPorts_SEH();

    // -------------------------------------------------------------------------
    // 1. VMware Backdoor Detection
    // -------------------------------------------------------------------------
    if (probeResult.vmwareDetected) {
        AddArtifact(result, VMDetectionCategory::IOPort, VMType::VMware, 95.0f,
                   L"VMware Backdoor port communication successful",
                   L"Magic: 0x" + std::to_wstring(probeResult.vmwareResponse), 
                   L"I/O Port Probe");
        
        result.triggeredCategories = result.triggeredCategories | VMDetectionCategory::IOPort;
        result.categoryScores[VMDetectionCategory::IOPort] = 95.0f;
        m_impl->m_statistics.categoryTriggerCounts[7].fetch_add(1, std::memory_order_relaxed);
        
        SS_LOG_INFO(L"AntiEvasion", L"CheckIOPorts: VMware backdoor detected");
    }

    // -------------------------------------------------------------------------
    // 2. VirtualBox I/O Port Detection
    // -------------------------------------------------------------------------
    if (probeResult.vboxDetected) {
        AddArtifact(result, VMDetectionCategory::IOPort, VMType::VirtualBox, 90.0f,
                   L"VirtualBox I/O Port (0x4042) accessed without exception",
                   L"Value: 0x" + std::to_wstring(probeResult.vboxResponse), 
                   L"I/O Port Probe");

        result.triggeredCategories = result.triggeredCategories | VMDetectionCategory::IOPort;
        result.categoryScores[VMDetectionCategory::IOPort] = 
            std::max(result.categoryScores[VMDetectionCategory::IOPort], 90.0f);
        m_impl->m_statistics.categoryTriggerCounts[7].fetch_add(1, std::memory_order_relaxed);
        
        SS_LOG_INFO(L"AntiEvasion", L"CheckIOPorts: VirtualBox I/O port detected");
    }
}

void VMEvasionDetector::CheckMemoryArtifacts(VMEvasionResult& result) {
    try {
        // Check descriptor tables (IDT, GDT, LDT) using assembly functions (with fallback)
        uint64_t idtBase = Safe_GetIDTBase();

        // On bare metal, IDT/GDT are typically in low memory
        // In VMs, they're often relocated to higher addresses
        // Note: Fallback returns 0xFFFFFFFF'FFFFFFFF as sentinel (skip check)
        constexpr uint64_t TYPICAL_IDT_THRESHOLD = 0xFFFFFF;  // ~16MB
        constexpr uint64_t SENTINEL_VALUE = 0xFFFFFFFF'FFFFFFFF;

        if (idtBase != SENTINEL_VALUE && idtBase > TYPICAL_IDT_THRESHOLD) {
            AddArtifact(
                result,
                VMDetectionCategory::Memory,
                VMType::GenericHypervisor,
                55.0f,
                L"IDT base address anomaly (typical of VM)",
                L"0x" + Utils::StringUtils::Format(L"%llX", idtBase),
                L"SIDT"
            );

            result.triggeredCategories = result.triggeredCategories | VMDetectionCategory::Memory;
            result.categoryScores[VMDetectionCategory::Memory] = 55.0f;
            m_impl->m_statistics.categoryTriggerCounts[8].fetch_add(1, std::memory_order_relaxed);
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"AntiEvasion", L"CheckMemoryArtifacts failed: %hs", e.what());
    }
}

void VMEvasionDetector::CheckDevices(VMEvasionResult& result) {
    SS_LOG_INFO(L"AntiEvasion", L"CheckDevices: Starting device enumeration");

    HDEVINFO hDevInfo = SetupDiGetClassDevsW(
        nullptr,                    // No specific enumerator
        nullptr,                    // No specific device instance ID
        nullptr,                    // No specific window
        DIGCF_ALLCLASSES | DIGCF_PRESENT // All classes, present devices only
    );

    if (hDevInfo == INVALID_HANDLE_VALUE) {
        SS_LOG_ERROR(L"AntiEvasion", L"CheckDevices: SetupDiGetClassDevsW failed with error %lu", GetLastError());
        return;
    }

    try {
        SP_DEVINFO_DATA devInfoData = { 0 };
        devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

        float categoryScore = 0.0f;
        size_t foundCount = 0;
        std::vector<wchar_t> buffer;
        const DWORD INITIAL_BUFFER_SIZE = 1024;
        buffer.resize(INITIAL_BUFFER_SIZE);

        for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
            DWORD dataType = 0;
            DWORD requiredSize = 0;

            // Get Hardware ID property
            BOOL success = SetupDiGetDeviceRegistryPropertyW(
                hDevInfo,
                &devInfoData,
                SPDRP_HARDWAREID,
                &dataType,
                reinterpret_cast<PBYTE>(buffer.data()),
                static_cast<DWORD>(buffer.size() * sizeof(wchar_t)),
                &requiredSize
            );

            if (!success && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                // Resize buffer and try again
                buffer.resize((requiredSize / sizeof(wchar_t)) + 2); // +2 for safety
                success = SetupDiGetDeviceRegistryPropertyW(
                    hDevInfo,
                    &devInfoData,
                    SPDRP_HARDWAREID,
                    &dataType,
                    reinterpret_cast<PBYTE>(buffer.data()),
                    static_cast<DWORD>(buffer.size() * sizeof(wchar_t)),
                    &requiredSize
                );
            }

            if (success) {
                // Hardware IDs are REG_MULTI_SZ (list of null-terminated strings, double-null terminated)
                wchar_t* currentId = buffer.data();
                bool deviceMatch = false;

                while (*currentId && !deviceMatch) {
                    std::wstring idStr(currentId);
                    // Normalize to lower case for comparison (ToUpper not available, checking against ToUpper constants requires adjustment)
                    // Note: We'll compare lower-to-lower since ToUpper isn't in Utils
                    std::wstring idStrLower = Utils::StringUtils::ToLowerCopy(idStr);

                    // Check against known VM device IDs
                    for (const auto& knownId : m_impl->m_knownVMDeviceIDs) {
                        std::wstring knownIdLower = Utils::StringUtils::ToLowerCopy(knownId);

                        if (idStrLower.find(knownIdLower) != std::wstring::npos) {
                            foundCount++;
                            deviceMatch = true;

                            // Determine VM type based on vendor IDs - checking against lower case
                            VMType vmType = VMType::Unknown;
                            if (idStrLower.find(L"ven_15ad") != std::wstring::npos) vmType = VMType::VMware;
                            else if (idStrLower.find(L"ven_80ee") != std::wstring::npos) vmType = VMType::VirtualBox;
                            else if (idStrLower.find(L"ven_1414") != std::wstring::npos || idStrLower.find(L"vmbus") != std::wstring::npos) vmType = VMType::HyperV;
                            else if (idStrLower.find(L"ven_1af4") != std::wstring::npos) vmType = VMType::KVM; // Red Hat VirtIO
                            else if (idStrLower.find(L"ven_1234") != std::wstring::npos) vmType = VMType::QEMU;
                            else vmType = VMType::GenericHypervisor;

                            AddArtifact(
                                result,
                                VMDetectionCategory::Device,
                                vmType,
                                85.0f, // High confidence for hardware ID match
                                L"VM-specific hardware device detected",
                                idStr,
                                L"SetupAPI: " + idStr
                            );

                            categoryScore = std::max(categoryScore, 85.0f);
                            break;
                        }
                    }

                    // Move to next string in MULTI_SZ
                    currentId += wcslen(currentId) + 1;
                }
            }
        }

        if (foundCount > 0) {
            result.triggeredCategories = result.triggeredCategories | VMDetectionCategory::Device;
            result.categoryScores[VMDetectionCategory::Device] = categoryScore;
            m_impl->m_statistics.categoryTriggerCounts[9].fetch_add(1, std::memory_order_relaxed); // Index 9 is Device

            SS_LOG_INFO(L"AntiEvasion", L"CheckDevices: Found %zu VM devices", foundCount);
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"AntiEvasion", L"CheckDevices failed with exception: %hs", e.what());
    }

    SetupDiDestroyDeviceInfoList(hDevInfo);
}

void VMEvasionDetector::CheckWMI(VMEvasionResult& result) {
    HRESULT hres;

    // Initialize COM
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    bool coInitialized = SUCCEEDED(hres);

    if (FAILED(hres) && hres != RPC_E_CHANGED_MODE) {
        SS_LOG_ERROR(L"AntiEvasion", L"CheckWMI: Failed to initialize COM library. Error code = 0x%X", static_cast<uint32_t>(hres));
        return;
    }

    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;

    try {
        // Obtain the initial locator to WMI
        hres = CoCreateInstance(
            CLSID_WbemLocator,
            0,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator, (LPVOID*)&pLoc);

        if (FAILED(hres)) {
            throw std::runtime_error("Failed to create IWbemLocator object");
        }

        // Connect to WMI through the IWbemLocator::ConnectServer method
        hres = pLoc->ConnectServer(
             _bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
             NULL,                    // User name. NULL = current user
             NULL,                    // User password. NULL = current
             0,                       // Locale. NULL indicates current
             NULL,                    // Security flags.
             0,                       // Authority (for example, Kerberos)
             0,                       // Context object
             &pSvc                    // pointer to IWbemServices proxy
        );

        if (FAILED(hres)) {
            throw std::runtime_error("Could not connect to WMI server");
        }

        // Set security levels on the proxy
        hres = CoSetProxyBlanket(
           pSvc,                        // Indicates the proxy to set
           RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
           RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
           NULL,                        // Server principal name
           RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx
           RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
           NULL,                        // client identity
           EOAC_NONE                    // proxy capabilities
        );

        if (FAILED(hres)) {
            throw std::runtime_error("Could not set proxy blanket");
        }

        // Helper lambda to query and check properties
        auto CheckWMIClass = [&](const wchar_t* query, const wchar_t* className) {
             IEnumWbemClassObject* pEnum = nullptr;
             hres = pSvc->ExecQuery(
                bstr_t("WQL"),
                bstr_t(query),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                NULL,
                &pEnum);

             if (FAILED(hres)) return;

             IWbemClassObject* pclsObj = nullptr;
             ULONG uReturn = 0;

             while (pEnum) {
                HRESULT hr = pEnum->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                if (0 == uReturn) break;

                VARIANT vtProp;

                // Check Manufacturer
                if (SUCCEEDED(pclsObj->Get(L"Manufacturer", 0, &vtProp, 0, 0))) {
                    if (vtProp.vt == VT_BSTR) {
                         std::wstring manufacturer(vtProp.bstrVal, SysStringLen(vtProp.bstrVal));

                         for (const auto& known : VMConstants::KNOWN_FIRMWARE_STRINGS) {
                             // Case insensitive check
                             std::wstring mfgLower = Utils::StringUtils::ToLowerCopy(manufacturer);
                             std::wstring knownLower = Utils::StringUtils::ToLowerCopy(std::wstring(known));

                             if (mfgLower.find(knownLower) != std::wstring::npos) {
                                  VMType type = VMType::GenericHypervisor;
                                  if (mfgLower.find(L"vmware") != std::wstring::npos) type = VMType::VMware;
                                  else if (mfgLower.find(L"virtualbox") != std::wstring::npos || mfgLower.find(L"vbox") != std::wstring::npos) type = VMType::VirtualBox;
                                  else if (mfgLower.find(L"hyper-v") != std::wstring::npos) type = VMType::HyperV;
                                  else if (mfgLower.find(L"xen") != std::wstring::npos) type = VMType::Xen;
                                  else if (mfgLower.find(L"qemu") != std::wstring::npos) type = VMType::QEMU;

                                  AddArtifact(result, VMDetectionCategory::WMI, type, 85.0f,
                                      L"WMI Manufacturer string indicates VM", manufacturer, className);

                                  result.triggeredCategories = result.triggeredCategories | VMDetectionCategory::WMI;
                                  result.categoryScores[VMDetectionCategory::WMI] = std::max(result.categoryScores[VMDetectionCategory::WMI], 85.0f);
                                  m_impl->m_statistics.categoryTriggerCounts[10].fetch_add(1, std::memory_order_relaxed);
                             }
                         }
                    }
                    VariantClear(&vtProp);
                }

                // Check Model
                if (SUCCEEDED(pclsObj->Get(L"Model", 0, &vtProp, 0, 0))) {
                     if (vtProp.vt == VT_BSTR) {
                         std::wstring model(vtProp.bstrVal, SysStringLen(vtProp.bstrVal));

                         for (const auto& known : VMConstants::KNOWN_FIRMWARE_STRINGS) {
                             std::wstring modelLower = Utils::StringUtils::ToLowerCopy(model);
                             std::wstring knownLower = Utils::StringUtils::ToLowerCopy(std::wstring(known));

                             if (modelLower.find(knownLower) != std::wstring::npos) {
                                  AddArtifact(result, VMDetectionCategory::WMI, VMType::GenericHypervisor, 85.0f,
                                      L"WMI Model string indicates VM", model, className);
                                  result.triggeredCategories = result.triggeredCategories | VMDetectionCategory::WMI;
                                  result.categoryScores[VMDetectionCategory::WMI] = std::max(result.categoryScores[VMDetectionCategory::WMI], 85.0f);
                                  m_impl->m_statistics.categoryTriggerCounts[10].fetch_add(1, std::memory_order_relaxed);
                             }
                         }
                     }
                     VariantClear(&vtProp);
                }

                pclsObj->Release();
             }
             if (pEnum) pEnum->Release();
        };

        CheckWMIClass(L"SELECT * FROM Win32_ComputerSystem", L"Win32_ComputerSystem");
        CheckWMIClass(L"SELECT * FROM Win32_BaseBoard", L"Win32_BaseBoard");

    } catch (const std::exception& e) {
         SS_LOG_ERROR(L"AntiEvasion", L"CheckWMI failed: %hs", e.what());
    }

    if (pSvc) pSvc->Release();
    if (pLoc) pLoc->Release();
    if (coInitialized) CoUninitialize();
}

void VMEvasionDetector::CheckWindows(VMEvasionResult& result) {
    try {
        WindowSearchContext context;

        // Enumerate all top-level windows
        if (!EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&context))) {
            SS_LOG_WARN(L"AntiEvasion", L"CheckWindows: EnumWindows returned false (last error: %lu)", GetLastError());
            // Continue processing any found windows anyway
        }

        if (!context.matches.empty()) {
            float categoryScore = 0.0f;

            for (const auto& match : context.matches) {
                const std::wstring& className = match.first;
                const std::wstring& windowTitle = match.second;

                // Determine VM type based on class name
                VMType vmType = VMType::Unknown;
                if (className.find(L"VMware") != std::wstring::npos || className == L"VMSwitchUserControlClass") vmType = VMType::VMware;
                else if (className.find(L"VBox") != std::wstring::npos) vmType = VMType::VirtualBox;
                else if (className.find(L"Parallels") != std::wstring::npos || className.find(L"Prl") != std::wstring::npos) vmType = VMType::Parallels;
                else if (className.find(L"Hyper-V") != std::wstring::npos || className == L"VMBusHidWindow") vmType = VMType::HyperV;
                else if (className.find(L"Sandboxie") != std::wstring::npos) vmType = VMType::Sandboxie;

                AddArtifact(
                    result,
                    VMDetectionCategory::Window,
                    vmType,
                    75.0f, // Good confidence but windows can be spoofed
                    L"VM-specific window class detected",
                    className,
                    windowTitle.empty() ? className : (className + L" (" + windowTitle + L")")
                );

                categoryScore = std::max(categoryScore, 75.0f);
            }

            result.triggeredCategories = result.triggeredCategories | VMDetectionCategory::Window;
            result.categoryScores[VMDetectionCategory::Window] = categoryScore;
            m_impl->m_statistics.categoryTriggerCounts[12].fetch_add(1, std::memory_order_relaxed); // Index 12 is Window

            SS_LOG_INFO(L"AntiEvasion", L"CheckWindows: Found %zu VM windows", context.matches.size());
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"AntiEvasion", L"CheckWindows failed: %hs", e.what());
    }
}

// ============================================================================
// Process Analysis API
// ============================================================================

bool VMEvasionDetector::AnalyzeProcessAntiVMBehavior(
    Utils::ProcessUtils::ProcessId processId,
    ProcessVMEvasionResult& result,
    const ProcessAnalysisConfig& config
) {
    const auto startTime = std::chrono::high_resolution_clock::now();
    result.processId = processId;
    result.completed = false;
    result.hasAntiVMBehavior = false;
    result.evasionScore = 0.0f;
    result.detectedTechniques = AntiVMTechnique::None;

    try {
        // 1. Get process info
        Utils::ProcessUtils::ProcessInfo procInfo;
        if (Utils::ProcessUtils::GetProcessInfo(processId, procInfo)) {
            result.processName = procInfo.basic.name;
            result.executablePath = procInfo.basic.executablePath;
        }

        // Increment stats
        if (m_impl) {
            m_impl->m_statistics.totalProcessesAnalyzed.fetch_add(1, std::memory_order_relaxed);
        }

        // 2. Open Process with VM_READ permissions
        HANDLE rawHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
        if (!rawHandle) {
            result.errorMessage = L"Access Denied: Cannot open process for scanning";
            return false;
        }

        // RAII closer
        std::shared_ptr<void> hProcess(rawHandle, [](void* h) { CloseHandle((HANDLE)h); });

        // 3. Scan Memory Regions
        // Focus on MEM_COMMIT, PAGE_EXECUTE_*, MEM_IMAGE (likely .text sections)

        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);

        uint8_t* pAddr = (uint8_t*)sysInfo.lpMinimumApplicationAddress;
        uint8_t* pMax = (uint8_t*)sysInfo.lpMaximumApplicationAddress;

        const size_t MAX_SCAN_SIZE = config.maxMemoryToScan > 0 ? config.maxMemoryToScan : 64 * 1024 * 1024;
        size_t totalScanned = 0;

        MEMORY_BASIC_INFORMATION mbi = { 0 };

        while (pAddr < pMax && totalScanned < MAX_SCAN_SIZE) {
            if (VirtualQueryEx((HANDLE)hProcess.get(), pAddr, &mbi, sizeof(mbi)) == 0) {
                pAddr += sysInfo.dwPageSize; // Skip if query fails
                continue;
            }

            // Check for executable code
            bool isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));

            // Only scan committed, executable image pages (code sections)
            if (mbi.State == MEM_COMMIT && isExecutable && mbi.Type == MEM_IMAGE) {

                std::vector<uint8_t> buffer;
                buffer.resize(mbi.RegionSize);
                SIZE_T bytesRead = 0;

                if (ReadProcessMemory((HANDLE)hProcess.get(), mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead)) {
                    // Scan buffer for Anti-VM patterns

                    for (size_t i = 0; i < bytesRead - 4; ++i) {
                        // Pattern 1: SIDT (Red Pill)
                        // x86: 0F 01 0D
                        // x64: 0F 01 4C 24 (SIDT [RSP+...]) or just 0F 01 (SIDT/SGDT)

                        bool redPillFound = false;

                        // Check for SIDT (0F 01 0D...)
                        if (buffer[i] == 0x0F && buffer[i+1] == 0x01 && buffer[i+2] == 0x0D) {
                            redPillFound = true;
                        }
                        // Check for x64 SIDT (0F 01 4C 24)
                        else if (buffer[i] == 0x0F && buffer[i+1] == 0x01 && buffer[i+2] == 0x4C && buffer[i+3] == 0x24) {
                            redPillFound = true;
                        }

                        if (redPillFound) {
                            DetectedAntiVMTechnique tech;
                            tech.technique = AntiVMTechnique::RedPillTest;
                            tech.category = VMDetectionCategory::BehaviorAnalysis;
                            tech.description = L"Red Pill (SIDT) instruction sequence detected";
                            tech.address = (uint64_t)mbi.BaseAddress + i;
                            tech.severity = 90.0f;
                            tech.isActive = true;

                            // Check for duplicates
                            bool isDuplicate = false;
                            for(const auto& existing : result.techniqueDetails) {
                                if (existing.technique == tech.technique && existing.address == tech.address) {
                                    isDuplicate = true; break;
                                }
                            }
                            if(!isDuplicate) {
                                result.techniqueDetails.push_back(tech);
                                result.detectedTechniques = result.detectedTechniques | AntiVMTechnique::RedPillTest;
                            }
                        }

                        // Pattern 2: SLDT (No Pill) - 0F 00 00
                        if (buffer[i] == 0x0F && buffer[i+1] == 0x00 && buffer[i+2] == 0x00) {
                            DetectedAntiVMTechnique tech;
                            tech.technique = AntiVMTechnique::NoPillTest;
                            tech.category = VMDetectionCategory::BehaviorAnalysis;
                            tech.description = L"No Pill (SLDT) instruction sequence detected";
                            tech.address = (uint64_t)mbi.BaseAddress + i;
                            tech.severity = 80.0f;
                            tech.isActive = true;

                            bool isDuplicate = false;
                            for(const auto& existing : result.techniqueDetails) {
                                if (existing.technique == tech.technique && existing.address == tech.address) {
                                    isDuplicate = true; break;
                                }
                            }
                            if(!isDuplicate) {
                                result.techniqueDetails.push_back(tech);
                                result.detectedTechniques = result.detectedTechniques | AntiVMTechnique::NoPillTest;
                            }
                        }

                        // Pattern 3: CPUID Loops (0F A2)
                        if (buffer[i] == 0x0F && buffer[i+1] == 0xA2) {
                            // Check for another CPUID within small window
                            bool loopDetected = false;
                            for (size_t k = 1; k < 32 && (i + k + 1) < bytesRead; ++k) {
                                if (buffer[i+k] == 0x0F && buffer[i+k+1] == 0xA2) {
                                    loopDetected = true;
                                    break;
                                }
                            }

                            if (loopDetected) {
                                DetectedAntiVMTechnique tech;
                                tech.technique = AntiVMTechnique::CPUIDHypervisorCheck;
                                tech.category = VMDetectionCategory::BehaviorAnalysis;
                                tech.description = L"CPUID instruction loop detected (Timing/Fuzzing)";
                                tech.address = (uint64_t)mbi.BaseAddress + i;
                                tech.severity = 70.0f;
                                tech.isActive = true;

                                bool isDuplicate = false;
                                for(const auto& existing : result.techniqueDetails) {
                                    if (existing.technique == tech.technique &&
                                       (existing.address > tech.address - 64 && existing.address < tech.address + 64)) {
                                        isDuplicate = true; break;
                                    }
                                }
                                if(!isDuplicate) {
                                    result.techniqueDetails.push_back(tech);
                                    result.detectedTechniques = result.detectedTechniques | AntiVMTechnique::CPUIDHypervisorCheck;
                                }

                                i += 32; // Skip to avoid flood
                            }
                        }
                    }
                }

                totalScanned += bytesRead;
            }

            pAddr += mbi.RegionSize;
        }

        if (!result.techniqueDetails.empty()) {
            result.hasAntiVMBehavior = true;
            result.evasionScore = 100.0f;
            if (m_impl) {
                m_impl->m_statistics.antiVMBehaviorDetected.fetch_add(1, std::memory_order_relaxed);
            }
        }

        result.completed = true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeProcessAntiVMBehavior failed for PID %u: %hs",
                            processId, e.what());
        result.errorMessage = Utils::StringUtils::ToWide(e.what());
        return false;
    }

    const auto endTime = std::chrono::high_resolution_clock::now();
    result.analysisTime = std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime);

    return result.completed;
}

size_t VMEvasionDetector::AnalyzeProcessesBatch(
    std::span<const Utils::ProcessUtils::ProcessId> processIds,
    std::unordered_map<Utils::ProcessUtils::ProcessId, ProcessVMEvasionResult>& results,
    const ProcessAnalysisConfig& config
) {
    size_t successCount = 0;

    for (auto pid : processIds) {
        ProcessVMEvasionResult result;
        if (AnalyzeProcessAntiVMBehavior(pid, result, config)) {
            results[pid] = std::move(result);
            successCount++;
        }
    }

    return successCount;
}

size_t VMEvasionDetector::ScanAllProcesses(
    std::unordered_map<Utils::ProcessUtils::ProcessId, ProcessVMEvasionResult>& results,
    const ProcessAnalysisConfig& config
) {
    std::vector<Utils::ProcessUtils::ProcessBasicInfo> processes;
    Utils::ProcessUtils::EnumerateProcesses(processes);
    std::vector<Utils::ProcessUtils::ProcessId> pids;
    pids.reserve(processes.size());

    for (const auto& proc : processes) {
        pids.push_back(proc.pid);
    }

    return AnalyzeProcessesBatch(pids, results, config);
}

// ============================================================================
// Configuration API
// ============================================================================

VMDetectionConfig VMEvasionDetector::GetConfig() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_mutex);
    return m_impl->m_config;
}

void VMEvasionDetector::SetConfig(const VMDetectionConfig& config) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);
    m_impl->m_config = config;
    m_impl->InvalidateCache();

    SS_LOG_INFO(L"AntiEvasion", L"VMEvasionDetector: Configuration updated");
}

void VMEvasionDetector::SetCategoryWeight(VMDetectionCategory category, float weight) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);
    m_impl->m_config.categoryWeights[category] = weight;
    m_impl->InvalidateCache();
}

void VMEvasionDetector::SetCategoryEnabled(VMDetectionCategory category, bool enabled) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);

    if (enabled) {
        m_impl->m_config.enabledCategories = m_impl->m_config.enabledCategories | category;
    } else {
        auto inverted = static_cast<VMDetectionCategory>(~static_cast<uint16_t>(category));
        m_impl->m_config.enabledCategories = m_impl->m_config.enabledCategories & inverted;
    }

    m_impl->InvalidateCache();
}

// ============================================================================
// Cache Management
// ============================================================================

void VMEvasionDetector::InvalidateCache() {
    m_impl->InvalidateCache();
    SS_LOG_INFO(L"AntiEvasion", L"VMEvasionDetector: Cache invalidated");
}

std::optional<VMEvasionResult> VMEvasionDetector::GetCachedResult() const {
    return m_impl->GetCachedResult();
}

bool VMEvasionDetector::IsCacheValid() const {
    return m_impl->IsCacheValid();
}

// ============================================================================
// Statistics API
// ============================================================================

const VMDetectionStatistics& VMEvasionDetector::GetStatistics() const {
    return m_impl->m_statistics;
}

void VMEvasionDetector::ResetStatistics() {
    m_impl->m_statistics.Reset();
    SS_LOG_INFO(L"AntiEvasion", L"VMEvasionDetector: Statistics reset");
}

// ============================================================================
// Utility Methods
// ============================================================================

std::wstring VMEvasionDetector::VMTypeToString(VMType type) {
    switch (type) {
        case VMType::None: return L"None (Bare Metal)";
        case VMType::VMware: return L"VMware";
        case VMType::VirtualBox: return L"VirtualBox";
        case VMType::HyperV: return L"Microsoft Hyper-V";
        case VMType::QEMU: return L"QEMU";
        case VMType::KVM: return L"KVM";
        case VMType::Xen: return L"Xen";
        case VMType::Parallels: return L"Parallels";
        case VMType::Bochs: return L"Bochs";
        case VMType::Wine: return L"Wine";
        case VMType::Sandboxie: return L"Sandboxie";
        case VMType::DockerContainer: return L"Docker Container";
        case VMType::WSL: return L"Windows Subsystem for Linux";
        case VMType::AmazonEC2: return L"Amazon EC2";
        case VMType::GoogleCloud: return L"Google Cloud Platform";
        case VMType::AzureVM: return L"Microsoft Azure";
        case VMType::Bhyve: return L"FreeBSD bhyve";
        case VMType::ACRN: return L"ACRN Hypervisor";
        case VMType::AppleVirt: return L"Apple Virtualization Framework";
        case VMType::GenericHypervisor: return L"Generic Hypervisor";
        case VMType::Unknown: return L"Unknown";
        default: return L"Invalid";
    }
}

std::wstring VMEvasionDetector::CategoryToString(VMDetectionCategory category) {
    switch (category) {
        case VMDetectionCategory::None: return L"None";
        case VMDetectionCategory::CPUID: return L"CPUID";
        case VMDetectionCategory::Registry: return L"Registry";
        case VMDetectionCategory::FileSystem: return L"File System";
        case VMDetectionCategory::Network: return L"Network";
        case VMDetectionCategory::Firmware: return L"Firmware/SMBIOS";
        case VMDetectionCategory::Process: return L"Process";
        case VMDetectionCategory::Timing: return L"Timing";
        case VMDetectionCategory::IOPort: return L"I/O Port";
        case VMDetectionCategory::Memory: return L"Memory";
        case VMDetectionCategory::Device: return L"Device";
        case VMDetectionCategory::WMI: return L"WMI";
        case VMDetectionCategory::Window: return L"Window";
        case VMDetectionCategory::BehaviorAnalysis: return L"Behavior Analysis";
        case VMDetectionCategory::All: return L"All Categories";
        default: return L"Unknown Category";
    }
}

std::wstring VMEvasionDetector::TechniqueToString(AntiVMTechnique technique) {
    // Return description based on technique enum
    uint32_t value = static_cast<uint32_t>(technique);

    if (value == 0) return L"None";

    // CPUID-based
    if ((value & 0xFF000000) == 0x01000000) return L"CPUID-based Detection";
    if ((value & 0xFF000000) == 0x02000000) return L"Registry-based Detection";
    if ((value & 0xFF000000) == 0x03000000) return L"File System Detection";
    if ((value & 0xFF000000) == 0x04000000) return L"Network Detection";
    if ((value & 0xFF000000) == 0x05000000) return L"Firmware Detection";
    if ((value & 0xFF000000) == 0x06000000) return L"Process/Service Detection";
    if ((value & 0xFF000000) == 0x07000000) return L"Timing-based Detection";
    if ((value & 0xFF000000) == 0x08000000) return L"I/O Port Detection";
    if ((value & 0xFF000000) == 0x09000000) return L"Memory Artifact Detection";
    if ((value & 0xFF000000) == 0x0A000000) return L"Device Detection";
    if ((value & 0xFF000000) == 0x0B000000) return L"WMI Detection";
    if ((value & 0xFF000000) == 0x0C000000) return L"Advanced Detection";

    return L"Multiple Techniques";
}

std::wstring VMEvasionDetector::ConfidenceLevelToString(VMConfidenceLevel level) {
    switch (level) {
        case VMConfidenceLevel::None: return L"None";
        case VMConfidenceLevel::VeryLow: return L"Very Low";
        case VMConfidenceLevel::Low: return L"Low";
        case VMConfidenceLevel::Medium: return L"Medium";
        case VMConfidenceLevel::High: return L"High";
        case VMConfidenceLevel::VeryHigh: return L"Very High";
        case VMConfidenceLevel::Definitive: return L"Definitive";
        default: return L"Unknown";
    }
}

VMType VMEvasionDetector::ParseHypervisorVendor(std::string_view vendorString) {
    if (vendorString == VMConstants::VENDOR_VMWARE) return VMType::VMware;
    if (vendorString == VMConstants::VENDOR_HYPERV) return VMType::HyperV;
    if (vendorString == VMConstants::VENDOR_VBOX) return VMType::VirtualBox;
    if (vendorString == VMConstants::VENDOR_XEN) return VMType::Xen;
    if (vendorString == VMConstants::VENDOR_KVM) return VMType::KVM;
    if (vendorString == VMConstants::VENDOR_QEMU) return VMType::QEMU;
    if (vendorString == VMConstants::VENDOR_PARALLELS) return VMType::Parallels;
    if (vendorString == VMConstants::VENDOR_BHYVE) return VMType::Bhyve;
    if (vendorString == VMConstants::VENDOR_ACRN) return VMType::ACRN;
    if (vendorString == VMConstants::VENDOR_QNX) return VMType::GenericHypervisor;

    return VMType::Unknown;
}

VMType VMEvasionDetector::CheckMACAddress(const Utils::NetworkUtils::MacAddress& mac) {
    // Check VMware OUIs
    for (const auto& oui : VMConstants::VMWARE_MAC_OUIS) {
        if (std::equal(oui.begin(), oui.end(), mac.bytes.begin())) {
            return VMType::VMware;
        }
    }

    // Check VirtualBox OUI
    if (std::equal(VMConstants::VBOX_MAC_OUI.begin(), VMConstants::VBOX_MAC_OUI.end(), mac.bytes.begin())) {
        return VMType::VirtualBox;
    }

    // Check Hyper-V OUI
    if (std::equal(VMConstants::HYPERV_MAC_OUI.begin(), VMConstants::HYPERV_MAC_OUI.end(), mac.bytes.begin())) {
        return VMType::HyperV;
    }

    // Check Parallels OUI
    if (std::equal(VMConstants::PARALLELS_MAC_OUI.begin(), VMConstants::PARALLELS_MAC_OUI.end(), mac.bytes.begin())) {
        return VMType::Parallels;
    }

    // Check Xen OUI
    if (std::equal(VMConstants::XEN_MAC_OUI.begin(), VMConstants::XEN_MAC_OUI.end(), mac.bytes.begin())) {
        return VMType::Xen;
    }

    // Check QEMU/KVM OUI
    if (std::equal(VMConstants::QEMU_MAC_OUI.begin(), VMConstants::QEMU_MAC_OUI.end(), mac.bytes.begin())) {
        return VMType::QEMU;
    }

    return VMType::None;
}

std::span<const std::wstring_view> VMEvasionDetector::GetKnownVMProcesses() {
    return VMConstants::KNOWN_VM_PROCESSES;
}

std::span<const std::wstring_view> VMEvasionDetector::GetKnownVMRegistryKeys() {
    return VMConstants::KNOWN_VM_REGISTRY_KEYS;
}

std::span<const std::wstring_view> VMEvasionDetector::GetKnownVMFiles() {
    return VMConstants::KNOWN_VM_FILES;
}

// ============================================================================
// Internal Helper Methods
// ============================================================================

void VMEvasionDetector::AddArtifact(
    VMEvasionResult& result,
    VMDetectionCategory category,
    VMType vmType,
    float confidence,
    std::wstring_view description,
    std::wstring_view rawValue,
    std::wstring_view location
) {
    VMArtifact artifact;
    artifact.category = category;
    artifact.associatedVMType = vmType;
    artifact.confidence = confidence;
    artifact.description = std::wstring(description);
    artifact.rawValue = std::wstring(rawValue);
    artifact.location = std::wstring(location);
    artifact.detectionTime = std::chrono::system_clock::now();

    result.artifacts.push_back(std::move(artifact));
    m_impl->m_statistics.totalArtifactsFound.fetch_add(1, std::memory_order_relaxed);
}

void VMEvasionDetector::CalculateFinalScore(VMEvasionResult& result) {
    if (result.categoryScores.empty()) {
        result.confidenceScore = 0.0f;
        result.isVM = false;
        return;
    }

    float weightedSum = 0.0f;
    float totalWeight = 0.0f;

    for (const auto& [category, score] : result.categoryScores) {
        auto it = m_impl->m_config.categoryWeights.find(category);
        float weight = (it != m_impl->m_config.categoryWeights.end()) ? it->second : 1.0f;

        weightedSum += score * weight;
        totalWeight += weight;
    }

    result.confidenceScore = (totalWeight > 0.0f) ? (weightedSum / totalWeight) : 0.0f;
    
    // =========================================================================
    // ENTERPRISE FALSE POSITIVE REDUCTION: Context-Aware Scoring
    // =========================================================================
    // Check if we're in a legitimate cloud environment BEFORE marking as VM.
    // Cloud VMs (AWS EC2, Azure, GCP) are LEGITIMATE enterprise infrastructure,
    // not malware evasion. We should:
    // 1. Detect and flag VM presence (informational)
    // 2. NOT flag as "suspicious evasion" unless combined with sandbox indicators
    // =========================================================================
    
    CloudEnvironmentInfo cloudInfo = DetectCloudEnvironment();
    
    if (cloudInfo.isCloud) {
        result.isLegitimateCloudEnvironment = true;
        result.cloudProvider = cloudInfo.provider;
        result.cloudInstanceId = cloudInfo.instanceId;
        result.cloudRegion = cloudInfo.region;
        
        // For legitimate cloud environments, we still detect VM but don't flag as evasion
        // unless there are specific malware evasion indicators (sandbox tools, analysis artifacts)
        result.isVM = true;  // It IS a VM
        result.isSuspiciousEvasion = false;  // But NOT suspicious evasion
        
        SS_LOG_INFO(L"AntiEvasion", 
            L"CalculateFinalScore: Legitimate cloud environment detected (%ls) - not flagging as evasion",
            cloudInfo.provider.c_str());
    } else {
        // Not a cloud environment - use standard threshold
        result.isVM = (result.confidenceScore >= m_impl->m_config.minimumConfidenceThreshold);
        
        // For non-cloud VMs, check if this looks like malware evasion
        // Suspicious evasion requires BOTH:
        // 1. VM presence indicators
        // 2. Additional suspicious indicators (sandbox artifacts, analysis tools, etc.)
        if (result.isVM) {
            // Count suspicious (non-cloud) indicators
            size_t suspiciousIndicators = 0;
            for (const auto& artifact : result.artifacts) {
                // VirtualBox, QEMU, Sandboxie, Wine are more likely to be analysis environments
                if (artifact.associatedVMType == VMType::VirtualBox ||
                    artifact.associatedVMType == VMType::QEMU ||
                    artifact.associatedVMType == VMType::Sandboxie ||
                    artifact.associatedVMType == VMType::Wine ||
                    artifact.associatedVMType == VMType::Bochs) {
                    suspiciousIndicators++;
                }
                
                // Process/service artifacts indicating analysis environment
                if (artifact.category == VMDetectionCategory::Process &&
                    artifact.confidence >= 70.0f) {
                    suspiciousIndicators++;
                }
            }
            
            // Require multiple suspicious indicators to flag as evasion
            result.isSuspiciousEvasion = (suspiciousIndicators >= 3);
            
            // Check for enterprise VMware (domain-joined) - not suspicious
            if (result.detectedType == VMType::VMware || result.detectedType == VMType::HyperV) {
                wchar_t domain[256] = {};
                DWORD size = sizeof(domain);
                if (GetComputerNameExW(ComputerNameDnsDomain, domain, &size) && wcslen(domain) > 0) {
                    result.isEnterpriseVirtualization = true;
                    result.isSuspiciousEvasion = false;  // Domain-joined = enterprise
                    SS_LOG_INFO(L"AntiEvasion",
                        L"CalculateFinalScore: Domain-joined VM detected - enterprise environment");
                }
            }
        }
    }

    // Set confidence level
    if (result.confidenceScore >= 95.0f) result.confidenceLevel = VMConfidenceLevel::Definitive;
    else if (result.confidenceScore >= 80.0f) result.confidenceLevel = VMConfidenceLevel::VeryHigh;
    else if (result.confidenceScore >= 60.0f) result.confidenceLevel = VMConfidenceLevel::High;
    else if (result.confidenceScore >= 40.0f) result.confidenceLevel = VMConfidenceLevel::Medium;
    else if (result.confidenceScore >= 20.0f) result.confidenceLevel = VMConfidenceLevel::Low;
    else if (result.confidenceScore > 0.0f) result.confidenceLevel = VMConfidenceLevel::VeryLow;
    else result.confidenceLevel = VMConfidenceLevel::None;
}

void VMEvasionDetector::DetermineVMType(VMEvasionResult& result) {
    if (!result.isVM) {
        result.detectedType = VMType::None;
        return;
    }

    // Count votes for each VM type from artifacts
    std::unordered_map<VMType, size_t> votes;
    std::unordered_map<VMType, float> confidenceSum;

    for (const auto& artifact : result.artifacts) {
        if (artifact.associatedVMType != VMType::None && artifact.associatedVMType != VMType::Unknown) {
            votes[artifact.associatedVMType]++;
            confidenceSum[artifact.associatedVMType] += artifact.confidence;
        }
    }

    // Find VM type with highest votes and confidence
    VMType primaryType = VMType::Unknown;
    size_t maxVotes = 0;
    float maxConfidence = 0.0f;

    for (const auto& [type, voteCount] : votes) {
        float avgConfidence = confidenceSum[type] / static_cast<float>(voteCount);

        if (voteCount > maxVotes || (voteCount == maxVotes && avgConfidence > maxConfidence)) {
            maxVotes = voteCount;
            maxConfidence = avgConfidence;
            primaryType = type;
        }
    }

    result.detectedType = primaryType;

    // Check for secondary type (nested virtualization)
    votes.erase(primaryType);
    if (!votes.empty()) {
        auto secondBest = std::max_element(votes.begin(), votes.end(),
            [](const auto& a, const auto& b) { return a.second < b.second; });

        if (secondBest->second >= 2) {  // At least 2 artifacts
            result.secondaryType = secondBest->first;
        }
    }
}

void VMEvasionDetector::UpdateStatistics(const VMEvasionResult& result, std::chrono::nanoseconds duration) {
    auto durationNs = static_cast<uint64_t>(duration.count());

    m_impl->m_statistics.totalDetectionTimeNs.fetch_add(durationNs, std::memory_order_relaxed);

    // Update min time
    uint64_t currentMin = m_impl->m_statistics.minDetectionTimeNs.load(std::memory_order_relaxed);
    while (durationNs < currentMin) {
        if (m_impl->m_statistics.minDetectionTimeNs.compare_exchange_weak(currentMin, durationNs, std::memory_order_relaxed)) {
            break;
        }
    }

    // Update max time
    uint64_t currentMax = m_impl->m_statistics.maxDetectionTimeNs.load(std::memory_order_relaxed);
    while (durationNs > currentMax) {
        if (m_impl->m_statistics.maxDetectionTimeNs.compare_exchange_weak(currentMax, durationNs, std::memory_order_relaxed)) {
            break;
        }
    }
}

// ============================================================================
// Private Helper Implementations
// ============================================================================

bool VMEvasionDetector::IsKnownVMArtifact(const std::wstring& name, const std::wstring& type) {
    if (m_impl && m_impl->m_threatIntel) {
        // Convert to narrow string for ThreatIntel API
        std::string nameUtf8 = Utils::StringUtils::ToNarrow(name);

        // Map string type to IOCType
        ThreatIntel::IOCType iocType = ThreatIntel::IOCType::ProcessName; // Default
        bool typeSupported = false;

        if (type == L"Process") {
            iocType = ThreatIntel::IOCType::ProcessName;
            typeSupported = true;
        }
        else if (type == L"Registry") {
            iocType = ThreatIntel::IOCType::RegistryKey;
            typeSupported = true;
        }
        else if (type == L"Mutex") {
            iocType = ThreatIntel::IOCType::MutexName;
            typeSupported = true;
        }
        else if (type == L"NamedPipe") {
            iocType = ThreatIntel::IOCType::NamedPipe;
            typeSupported = true;
        }

        if (typeSupported) {
            auto result = m_impl->m_threatIntel->LookupIOC(iocType, nameUtf8);
            return result.IsMalicious();
        }
    }
    return false;
}

bool VMEvasionDetector::SafeCPUID(uint32_t leaf, uint32_t subleaf, int32_t* regs) {
    if (!regs) return false;

    // Initialize regs to 0
    memset(regs, 0, 4 * sizeof(int32_t));

    bool success = false;
    __try {
        __cpuidex(regs, leaf, subleaf);
        success = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Catch Illegal Instruction or Privileged Instruction if restricted
        SS_LOG_WARN(L"AntiEvasion", L"SafeCPUID: Exception executing CPUID(0x%08X, 0x%08X)", leaf, subleaf);
        success = false;
    }
    return success;
}

bool VMEvasionDetector::TryVMwareBackdoor(uint32_t& response) {
    // VMware Backdoor Check
    // I/O Port: 0x5658 ("VX")
    // Magic: 0x564D5868 ("VMXh")

    bool detected = false;
    response = 0;

    __try {
        uint32_t rax = VMConstants::VMWARE_MAGIC; // Magic
        uint32_t rbx = 0;                         // Output buffer
        uint32_t rcx = 0x0A;                      // Command: Get Version
        uint32_t rdx = VMConstants::VMWARE_IO_PORT; // Port

        // Execute the I/O instruction via external ASM helper
        CheckVMwareBackdoor(&rax, &rbx, &rcx, &rdx);

        // Check if magic matches in RBX (successful backdoor communication)
        // or if we got a valid version response
        if (rbx == VMConstants::VMWARE_MAGIC) {
            response = rax; // Version usually in RAX or related
            detected = true;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Exception expected on non-VMware systems (Privileged Instruction)
        // This is safe to ignore
        detected = false;
    }

    return detected;
}

uint64_t VMEvasionDetector::MeasureRDTSCDelta(uint32_t iterations) {
    // Call the optimized assembly implementation (with fallback)
    return Safe_MeasureRDTSCTimingDelta(iterations);
}

// ============================================================================
// Free Functions
// ============================================================================

bool IsVirtualMachine() {
    VMEvasionDetector detector;
    return detector.IsRunningInVM();
}

VMEvasionResult QuickVMDetection() {
    VMEvasionDetector detector(nullptr, VMDetectionConfig::CreateQuickScan());
    return detector.DetectEnvironment();
}

VMEvasionResult FullVMDetection() {
    VMEvasionDetector detector(nullptr, VMDetectionConfig::CreateDeepAnalysis());
    return detector.DetectEnvironment();
}

}  // namespace AntiEvasion
}  // namespace ShadowStrike
