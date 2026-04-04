/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <array>
#include <span>
#include <optional>
#include <string>
#include <string_view>
#include <compare>

namespace Phantom {

// ============================================================================
// Guest Address Space Types
// ============================================================================

using GuestAddress   = uint64_t;
using GuestSize      = uint64_t;
using GuestOffset    = int64_t;
using HostAddress    = uint8_t*;
using ConstHostAddr  = const uint8_t*;

static constexpr GuestAddress kGuestNull       = 0;
static constexpr GuestAddress kGuestInvalid    = 0xDEADDEADDEADDEADULL;
static constexpr GuestSize    kPageSize        = 4096;
static constexpr GuestSize    kPageMask        = kPageSize - 1;
static constexpr GuestSize    kPageShift       = 12;
static constexpr GuestSize    kMaxGuestMemory  = 512ULL * 1024 * 1024;   // 512 MB
static constexpr uint32_t     kMaxPages        = static_cast<uint32_t>(kMaxGuestMemory / kPageSize);
static constexpr GuestSize    kStackSize       = 1024 * 1024;            // 1 MB default stack
static constexpr GuestSize    kHeapInitial     = 4 * 1024 * 1024;       // 4 MB initial heap

[[nodiscard]] constexpr GuestAddress AlignDown(GuestAddress addr, GuestSize alignment) noexcept {
    return addr & ~(alignment - 1);
}

[[nodiscard]] constexpr GuestAddress AlignUp(GuestAddress addr, GuestSize alignment) noexcept {
    return (addr + alignment - 1) & ~(alignment - 1);
}

[[nodiscard]] constexpr GuestAddress PageBase(GuestAddress addr) noexcept {
    return addr & ~kPageMask;
}

[[nodiscard]] constexpr uint32_t PageIndex(GuestAddress addr) noexcept {
    return static_cast<uint32_t>(addr >> kPageShift);
}

[[nodiscard]] constexpr uint32_t PageOffset(GuestAddress addr) noexcept {
    return static_cast<uint32_t>(addr & kPageMask);
}

[[nodiscard]] constexpr uint32_t PagesNeeded(GuestSize size) noexcept {
    return static_cast<uint32_t>((size + kPageMask) >> kPageShift);
}

// ============================================================================
// Register Indices
// ============================================================================

enum class GPR : uint8_t {
    RAX = 0, RCX = 1, RDX = 2, RBX = 3,
    RSP = 4, RBP = 5, RSI = 6, RDI = 7,
    R8  = 8, R9  = 9, R10 = 10, R11 = 11,
    R12 = 12, R13 = 13, R14 = 14, R15 = 15,
    Count = 16
};

enum class SegReg : uint8_t {
    ES = 0, CS = 1, SS = 2, DS = 3, FS = 4, GS = 5,
    Count = 6
};

// ============================================================================
// Memory Protection
// ============================================================================

enum class MemProt : uint8_t {
    None      = 0,
    Read      = 1 << 0,
    Write     = 1 << 1,
    Execute   = 1 << 2,
    Guard     = 1 << 3,
    NoCache   = 1 << 4,

    RW        = Read | Write,
    RX        = Read | Execute,
    RWX       = Read | Write | Execute,
};

[[nodiscard]] constexpr MemProt operator|(MemProt a, MemProt b) noexcept {
    return static_cast<MemProt>(static_cast<uint8_t>(a) | static_cast<uint8_t>(b));
}

[[nodiscard]] constexpr MemProt operator&(MemProt a, MemProt b) noexcept {
    return static_cast<MemProt>(static_cast<uint8_t>(a) & static_cast<uint8_t>(b));
}

[[nodiscard]] constexpr bool HasProt(MemProt prot, MemProt flag) noexcept {
    return (static_cast<uint8_t>(prot) & static_cast<uint8_t>(flag)) != 0;
}

// ============================================================================
// Operand Size Mode
// ============================================================================

enum class OperandSize : uint8_t {
    Size8  = 1,
    Size16 = 2,
    Size32 = 4,
    Size64 = 8,
};

enum class AddressSize : uint8_t {
    Addr16 = 2,
    Addr32 = 4,
    Addr64 = 8,
};

enum class CPUMode : uint8_t {
    Real16,           // 16-bit real mode (DOS malware, boot sector)
    Protected32,      // 32-bit protected mode (Win32 PE)
    Long64,           // 64-bit long mode (Win64 PE)
};

// ============================================================================
// Emulation Session Types
// ============================================================================

enum class EmulationTarget : uint8_t {
    PE32,                // 32-bit Windows PE executable
    PE64,                // 64-bit Windows PE executable
    Shellcode32,         // 32-bit raw shellcode buffer
    Shellcode64,         // 64-bit raw shellcode buffer
    DLL32,               // 32-bit DLL (DllMain execution)
    DLL64,               // 64-bit DLL (DllMain execution)
};

enum class StopReason : uint8_t {
    None,
    InstructionLimit,    // Hit max instruction count
    TimeLimit,           // Hit max wall-clock time
    MemoryLimit,         // Hit max guest memory
    InvalidInstruction,  // Decoded an invalid/unsupported opcode
    AccessViolation,     // Memory access violation (DEP, guard page, unmapped)
    DivideByZero,        // DIV/IDIV with zero divisor
    StackOverflow,       // Stack pointer below stack limit
    Breakpoint,          // Hit breakpoint (INT3, DR0-DR3)
    Syscall,             // SYSCALL/SYSENTER/INT 0x2E instruction
    APICallTrap,         // Hit API hook magic address
    ExitProcess,         // Emulated ExitProcess() called
    UnpackComplete,      // OEP reached during unpacking
    Crashed,             // Unrecoverable emulation error
    UserAborted,         // External abort request
};

enum class ThreatLevel : uint8_t {
    Clean       = 0,
    Suspicious  = 1,
    Likely      = 2,
    Malicious   = 3,
    Critical    = 4,
};

// ============================================================================
// API Call Record
// ============================================================================

struct APICallRecord {
    uint32_t    ordinal;             // Internal API ordinal
    GuestAddress returnAddress;      // Caller return address
    GuestAddress stackPointer;       // RSP at call time
    uint64_t    args[8];             // First 8 arguments (register + stack)
    uint64_t    returnValue;         // Return value after emulation
    uint32_t    instructionCount;    // Instruction count when called
    uint16_t    threadId;            // Emulated thread ID
    uint8_t     argCount;            // Actual argument count
    bool        wasBlocked;          // True if API call was blocked/faked
};

// ============================================================================
// Memory Region Descriptor
// ============================================================================

struct MemoryRegion {
    GuestAddress base;
    GuestSize    size;
    MemProt      protection;
    bool         isStack;
    bool         isHeap;
    bool         isMapped;           // PE section mapping
    bool         wasWritten;         // Track W→X transitions
    bool         wasExecuted;        // Track W→X transitions

    [[nodiscard]] bool Contains(GuestAddress addr) const noexcept {
        return addr >= base && addr < (base + size);
    }

    [[nodiscard]] bool Overlaps(GuestAddress otherBase, GuestSize otherSize) const noexcept {
        return base < (otherBase + otherSize) && otherBase < (base + size);
    }
};

// ============================================================================
// Hash Types
// ============================================================================

struct SHA256Hash {
    std::array<uint8_t, 32> bytes{};

    [[nodiscard]] bool operator==(const SHA256Hash& other) const noexcept = default;
    [[nodiscard]] auto operator<=>(const SHA256Hash& other) const noexcept = default;

    [[nodiscard]] bool IsZero() const noexcept {
        for (auto b : bytes) { if (b != 0) return false; }
        return true;
    }
};

struct MD5Hash {
    std::array<uint8_t, 16> bytes{};
    [[nodiscard]] bool operator==(const MD5Hash& other) const noexcept = default;
};

// ============================================================================
// Byte Span Helpers
// ============================================================================

using ByteSpan      = std::span<const uint8_t>;
using MutableBytes  = std::span<uint8_t>;

} // namespace Phantom
