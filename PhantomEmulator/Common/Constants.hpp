/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#pragma once

#include <cstdint>

namespace Phantom {

// ============================================================================
// x86/x64 Instruction Encoding Constants
// ============================================================================

namespace Encoding {

    // Maximum instruction length
    static constexpr uint32_t kMaxInstructionLength = 15;

    // Legacy prefix groups
    static constexpr uint8_t kPrefixLOCK    = 0xF0;
    static constexpr uint8_t kPrefixREPNE   = 0xF2;
    static constexpr uint8_t kPrefixREP     = 0xF3;

    static constexpr uint8_t kPrefixCS      = 0x2E;
    static constexpr uint8_t kPrefixSS      = 0x36;
    static constexpr uint8_t kPrefixDS      = 0x3E;
    static constexpr uint8_t kPrefixES      = 0x26;
    static constexpr uint8_t kPrefixFS      = 0x64;
    static constexpr uint8_t kPrefixGS      = 0x65;

    static constexpr uint8_t kPrefixOpSize  = 0x66;
    static constexpr uint8_t kPrefixAddrSize = 0x67;

    // REX prefix range (0x40-0x4F in 64-bit mode)
    static constexpr uint8_t kREXBase       = 0x40;
    static constexpr uint8_t kREXMax        = 0x4F;
    static constexpr uint8_t kREX_W         = 0x08;   // 64-bit operand size
    static constexpr uint8_t kREX_R         = 0x04;   // ModRM.reg extension
    static constexpr uint8_t kREX_X         = 0x02;   // SIB.index extension
    static constexpr uint8_t kREX_B         = 0x01;   // ModRM.rm / SIB.base extension

    // VEX prefix bytes
    static constexpr uint8_t kVEX2Byte      = 0xC5;
    static constexpr uint8_t kVEX3Byte      = 0xC4;

    // 2-byte opcode escape
    static constexpr uint8_t kTwoByteEscape = 0x0F;

    // 3-byte opcode escapes (after 0x0F)
    static constexpr uint8_t kThreeByteEscape38 = 0x38;
    static constexpr uint8_t kThreeByteEscape3A = 0x3A;

    // ModR/M byte field extraction
    [[nodiscard]] constexpr uint8_t ModRM_Mod(uint8_t modrm) noexcept { return (modrm >> 6) & 0x03; }
    [[nodiscard]] constexpr uint8_t ModRM_Reg(uint8_t modrm) noexcept { return (modrm >> 3) & 0x07; }
    [[nodiscard]] constexpr uint8_t ModRM_RM(uint8_t modrm) noexcept  { return modrm & 0x07; }

    // SIB byte field extraction
    [[nodiscard]] constexpr uint8_t SIB_Scale(uint8_t sib) noexcept { return (sib >> 6) & 0x03; }
    [[nodiscard]] constexpr uint8_t SIB_Index(uint8_t sib) noexcept { return (sib >> 3) & 0x07; }
    [[nodiscard]] constexpr uint8_t SIB_Base(uint8_t sib) noexcept  { return sib & 0x07; }

    // Scale factor lookup
    static constexpr uint8_t kScaleFactors[4] = { 1, 2, 4, 8 };

    // ModRM mod values
    static constexpr uint8_t kMod_Indirect   = 0;
    static constexpr uint8_t kMod_Disp8      = 1;
    static constexpr uint8_t kMod_Disp32     = 2;
    static constexpr uint8_t kMod_Register   = 3;

    // Special ModRM.rm for SIB / RIP-relative
    static constexpr uint8_t kRM_SIB         = 4;    // mod!=3, rm=4 → SIB byte follows
    static constexpr uint8_t kRM_Disp32      = 5;    // mod=0, rm=5 → disp32 (or RIP-relative in 64-bit)

    // SIB special: no index register
    static constexpr uint8_t kSIB_NoIndex    = 4;
    // SIB special: disp32 base (when mod=0, base=5)
    static constexpr uint8_t kSIB_Disp32Base = 5;

} // namespace Encoding

// ============================================================================
// x86/x64 EFLAGS Bit Positions
// ============================================================================

namespace Flags {

    static constexpr uint64_t CF   = 1ULL << 0;   // Carry
    static constexpr uint64_t PF   = 1ULL << 2;   // Parity
    static constexpr uint64_t AF   = 1ULL << 4;   // Auxiliary Carry
    static constexpr uint64_t ZF   = 1ULL << 6;   // Zero
    static constexpr uint64_t SF   = 1ULL << 7;   // Sign
    static constexpr uint64_t TF   = 1ULL << 8;   // Trap
    static constexpr uint64_t IF   = 1ULL << 9;   // Interrupt
    static constexpr uint64_t DF   = 1ULL << 10;  // Direction
    static constexpr uint64_t OF   = 1ULL << 11;  // Overflow
    static constexpr uint64_t IOPL = 3ULL << 12;  // I/O Privilege Level
    static constexpr uint64_t NT   = 1ULL << 14;  // Nested Task
    static constexpr uint64_t RF   = 1ULL << 16;  // Resume
    static constexpr uint64_t VM   = 1ULL << 17;  // Virtual 8086 Mode
    static constexpr uint64_t AC   = 1ULL << 18;  // Alignment Check
    static constexpr uint64_t VIF  = 1ULL << 19;  // Virtual Interrupt
    static constexpr uint64_t VIP  = 1ULL << 20;  // Virtual Interrupt Pending
    static constexpr uint64_t ID   = 1ULL << 21;  // ID (CPUID support)

    // Arithmetic flag mask (flags affected by most ALU ops)
    static constexpr uint64_t kArithFlags = CF | PF | AF | ZF | SF | OF;

    // Status flags (the commonly tested ones)
    static constexpr uint64_t kStatusFlags = CF | PF | AF | ZF | SF | OF;

    // Parity lookup table (precomputed for bytes 0-255)
    // PF is set if the low 8 bits of the result have an even number of 1 bits
    constexpr bool ComputeParity(uint8_t value) noexcept {
        value ^= value >> 4;
        value ^= value >> 2;
        value ^= value >> 1;
        return (~value) & 1;
    }

} // namespace Flags

// ============================================================================
// CPUID Constants (for anti-evasion)
// ============================================================================

namespace CPUID {
    // Leaf 0: Vendor string
    static constexpr uint32_t kVendorEBX = 0x756E6547; // "Genu"
    static constexpr uint32_t kVendorEDX = 0x49656E69; // "ineI"
    static constexpr uint32_t kVendorECX = 0x6C65746E; // "ntel"
    static constexpr uint32_t kMaxBasicLeaf = 0x16;

    // Leaf 1: Version info (Core i7-10700K, Comet Lake-S)
    // Family=6, ExtModel=0xA, Model=0x5, Stepping=5 → DisplayModel=0xA5
    static constexpr uint32_t kVersionInfo = 0x000A0655;
    // Feature flags (leaf 1 ECX) — match real Comet Lake hardware
    static constexpr uint32_t kFeatureECX =
        (1 << 0)  | // SSE3
        (1 << 1)  | // PCLMULQDQ
        (1 << 2)  | // DTES64
        (1 << 3)  | // MONITOR
        (1 << 4)  | // DS-CPL
        (1 << 9)  | // SSSE3
        (1 << 12) | // FMA
        (1 << 13) | // CMPXCHG16B
        (1 << 14) | // xTPR Update Control
        (1 << 15) | // PDCM
        (1 << 17) | // PCID
        (1 << 19) | // SSE4.1
        (1 << 20) | // SSE4.2
        (1 << 21) | // x2APIC
        (1 << 22) | // MOVBE
        (1 << 23) | // POPCNT
        (1 << 25) | // AES-NI
        (1 << 26) | // XSAVE
        (1 << 27) | // OSXSAVE
        (1 << 28) | // AVX
        (1 << 29) | // F16C
        (1 << 30);  // RDRAND
    // NOTE: Bit 31 (hypervisor) is intentionally NOT set — anti-evasion

    // Feature flags (leaf 1 EDX) — match real Comet Lake hardware
    static constexpr uint32_t kFeatureEDX =
        (1 << 0)  | // FPU
        (1 << 1)  | // VME
        (1 << 2)  | // DE (Debugging Extensions)
        (1 << 3)  | // PSE (Page Size Extension)
        (1 << 4)  | // TSC
        (1 << 5)  | // MSR
        (1 << 6)  | // PAE
        (1 << 7)  | // MCE
        (1 << 8)  | // CMPXCHG8B
        (1 << 9)  | // APIC
        (1 << 11) | // SEP (SYSENTER/SYSEXIT)
        (1 << 12) | // MTRR
        (1 << 13) | // PGE
        (1 << 14) | // MCA
        (1 << 15) | // CMOV
        (1 << 16) | // PAT
        (1 << 17) | // PSE-36
        (1 << 19) | // CLFLUSH
        (1 << 21) | // DS (Debug Store)
        (1 << 22) | // ACPI
        (1 << 23) | // MMX
        (1 << 24) | // FXSR
        (1 << 25) | // SSE
        (1 << 26) | // SSE2
        (1 << 27) | // SS (Self Snoop)
        (1 << 28) | // HTT (Hyper-Threading)
        (1 << 29);  // TM (Thermal Monitor)

    // Leaf 0x80000000: Extended CPUID max leaf
    static constexpr uint32_t kMaxExtLeaf = 0x80000008;

    // Leaf 0x80000002-0x80000004: Brand string (48 bytes)
    // "Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz"
    static constexpr uint32_t kBrand[12] = {
        0x65746E49, 0x2952286C, 0x726F4320, 0x4D542865, // "Inte" "l(R)" " Cor" "e(TM"
        0x37692029, 0x3030372D, 0x4320304B, 0x40205550, // ") i7" "-107" "00K " "CPU "
        0x382E3320, 0x7A484730, 0x00000000, 0x00000000, // "@ 3." "80GH" "z\0\0\0" "\0\0\0\0"
    };

} // namespace CPUID

// ============================================================================
// Windows Constants (for API emulation)
// ============================================================================

namespace WinConst {
    // Common NTSTATUS values
    static constexpr uint32_t STATUS_SUCCESS           = 0x00000000;
    static constexpr uint32_t STATUS_INVALID_PARAMETER = 0xC000000D;
    static constexpr uint32_t STATUS_ACCESS_DENIED     = 0xC0000022;
    static constexpr uint32_t STATUS_NO_MEMORY         = 0xC0000017;
    static constexpr uint32_t STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034;

    // Common Win32 error codes
    static constexpr uint32_t ERROR_SUCCESS            = 0;
    static constexpr uint32_t ERROR_FILE_NOT_FOUND     = 2;
    static constexpr uint32_t ERROR_ACCESS_DENIED      = 5;
    static constexpr uint32_t ERROR_INVALID_HANDLE     = 6;
    static constexpr uint32_t ERROR_NOT_ENOUGH_MEMORY  = 8;
    static constexpr uint32_t ERROR_INVALID_PARAMETER  = 87;

    // Handle constants
    static constexpr uint64_t INVALID_HANDLE_VALUE     = 0xFFFFFFFFFFFFFFFFULL;
    static constexpr uint64_t NULL_HANDLE              = 0;

    // Memory allocation types
    static constexpr uint32_t MEM_COMMIT               = 0x1000;
    static constexpr uint32_t MEM_RESERVE              = 0x2000;
    static constexpr uint32_t MEM_RELEASE              = 0x8000;
    static constexpr uint32_t MEM_DECOMMIT             = 0x4000;

    // Page protection
    static constexpr uint32_t PAGE_NOACCESS            = 0x01;
    static constexpr uint32_t PAGE_READONLY            = 0x02;
    static constexpr uint32_t PAGE_READWRITE           = 0x04;
    static constexpr uint32_t PAGE_WRITECOPY           = 0x08;
    static constexpr uint32_t PAGE_EXECUTE             = 0x10;
    static constexpr uint32_t PAGE_EXECUTE_READ        = 0x20;
    static constexpr uint32_t PAGE_EXECUTE_READWRITE   = 0x40;
    static constexpr uint32_t PAGE_EXECUTE_WRITECOPY   = 0x80;
    static constexpr uint32_t PAGE_GUARD               = 0x100;

    // PE image base defaults
    static constexpr uint64_t kDefaultImageBase32      = 0x00400000;
    static constexpr uint64_t kDefaultImageBase64      = 0x0000000140000000ULL;
    static constexpr uint64_t kDefaultDllBase32        = 0x10000000;
    static constexpr uint64_t kDefaultDllBase64        = 0x00007FFF00000000ULL;

    // Virtual DLL bases (where we map our fake DLLs)
    static constexpr uint64_t kNtdllBase64             = 0x00007FFE00000000ULL;
    static constexpr uint64_t kKernel32Base64          = 0x00007FFE01000000ULL;
    static constexpr uint64_t kKernelBaseBase64        = 0x00007FFE02000000ULL;
    static constexpr uint64_t kAdvapi32Base64          = 0x00007FFE03000000ULL;
    static constexpr uint64_t kWs2_32Base64            = 0x00007FFE04000000ULL;
    static constexpr uint64_t kUser32Base64            = 0x00007FFE05000000ULL;
    static constexpr uint64_t kShell32Base64           = 0x00007FFE06000000ULL;

    // PEB/TEB addresses
    static constexpr uint64_t kPEBAddress64            = 0x000000007FFE0000ULL;
    static constexpr uint64_t kTEBAddress64            = 0x000000007FFE1000ULL;

    // Stack addresses
    static constexpr uint64_t kStackBase64             = 0x0000000080000000ULL;
    static constexpr uint64_t kStackTop64              = kStackBase64 + (1024 * 1024); // 1MB

    // Heap addresses
    static constexpr uint64_t kProcessHeapBase64       = 0x0000000000100000ULL;

} // namespace WinConst

// ============================================================================
// PE Constants
// ============================================================================

namespace PEConst {
    static constexpr uint16_t kDOSSignature    = 0x5A4D;       // "MZ"
    static constexpr uint32_t kNTSignature     = 0x00004550;   // "PE\0\0"
    static constexpr uint16_t kMachineI386     = 0x014C;
    static constexpr uint16_t kMachineAMD64    = 0x8664;
    static constexpr uint16_t kOptionalHdr32   = 0x010B;
    static constexpr uint16_t kOptionalHdr64   = 0x020B;
    static constexpr uint32_t kMaxSections     = 96;
    static constexpr uint32_t kMaxImports      = 4096;
    static constexpr uint32_t kSectionAlignment = 0x1000;

    // Section characteristics
    static constexpr uint32_t IMAGE_SCN_CNT_CODE             = 0x00000020;
    static constexpr uint32_t IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
    static constexpr uint32_t IMAGE_SCN_MEM_EXECUTE          = 0x20000000;
    static constexpr uint32_t IMAGE_SCN_MEM_READ             = 0x40000000;
    static constexpr uint32_t IMAGE_SCN_MEM_WRITE            = 0x80000000;

    // Data directory indices
    static constexpr uint32_t DIR_EXPORT    = 0;
    static constexpr uint32_t DIR_IMPORT    = 1;
    static constexpr uint32_t DIR_RESOURCE  = 2;
    static constexpr uint32_t DIR_EXCEPTION = 3;
    static constexpr uint32_t DIR_SECURITY  = 4;
    static constexpr uint32_t DIR_BASERELOC = 5;
    static constexpr uint32_t DIR_DEBUG     = 6;
    static constexpr uint32_t DIR_TLS       = 9;
    static constexpr uint32_t DIR_IAT       = 12;
    static constexpr uint32_t DIR_DELAYIMPORT = 13;
    static constexpr uint32_t DIR_CLR       = 14;
    static constexpr uint32_t kMaxDirEntries = 16;

    // Relocation types
    static constexpr uint16_t IMAGE_REL_BASED_ABSOLUTE = 0;
    static constexpr uint16_t IMAGE_REL_BASED_HIGHLOW  = 3;
    static constexpr uint16_t IMAGE_REL_BASED_DIR64    = 10;

} // namespace PEConst

} // namespace Phantom
