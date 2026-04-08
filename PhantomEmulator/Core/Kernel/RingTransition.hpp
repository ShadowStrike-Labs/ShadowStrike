/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * RingTransition — CPU privilege level tracking and transition handling
 *
 * Tracks CPL (Current Privilege Level) and handles SYSCALL/SYSRET,
 * SYSENTER/SYSEXIT, INT 0x2E, and IRETQ transitions. Every ring
 * transition is logged for behavioral analysis, and anomaly detection
 * identifies exploitation attempts such as user-mode code executing
 * at Ring 0 or SYSRET to non-canonical addresses.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../../Common/Types.hpp"
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace Phantom {

// Forward declarations
class CPUState;
class VirtualMemory;
class MSREmulation;

// ============================================================================
// Transition Type
// ============================================================================

enum class TransitionType : uint8_t {
    Syscall,         // SYSCALL instruction
    Sysret,          // SYSRET instruction
    Sysenter,        // SYSENTER instruction
    Sysexit,         // SYSEXIT instruction
    Int2E,           // INT 0x2E (legacy Windows syscall)
    Iret,            // IRETQ (return from interrupt)
    Exception,       // CPU exception (page fault → kernel)
    Callback         // User-mode callback dispatch
};

// ============================================================================
// Ring Transition Event Record
// ============================================================================

struct RingTransitionEvent {
    TransitionType type;
    uint8_t        fromRing;
    uint8_t        toRing;
    GuestAddress   fromRIP;
    GuestAddress   toRIP;
    uint64_t       rflags;
    uint64_t       rsp;
    uint32_t       syscallNumber;   // RAX at SYSCALL time
    uint64_t       timestamp;       // Instruction count
};

// ============================================================================
// Transition Anomaly
// ============================================================================

struct TransitionAnomaly {
    enum class Type : uint8_t {
        UserCodeAtRing0,          // User-space RIP executing at CPL=0
        KernelCodeAtRing3,        // Kernel RIP at CPL=3
        SyscallFromKernel,        // SYSCALL when already in Ring 0
        SysretToKernel,           // SYSRET to Ring 0 address
        InvalidSyscallNumber,     // RAX > max syscall number
        StackPivot,               // RSP changed dramatically during transition
        NonCanonicalReturn        // SYSRET to non-canonical address
    };

    Type                  type;
    std::string           description;
    RingTransitionEvent   event;
};

// ============================================================================
// Ring Transition Engine
// ============================================================================

class RingTransition {
public:
    static RingTransition& Instance();
    void Reset();

    // Initialize with references to CPU state and MSR emulation
    void Initialize(CPUState& cpu, MSREmulation& msr);

    // Transition handlers — return false if transition fails
    [[nodiscard]] bool HandleSyscall(CPUState& cpu);
    [[nodiscard]] bool HandleSysret(CPUState& cpu);
    [[nodiscard]] bool HandleSysenter(CPUState& cpu);
    [[nodiscard]] bool HandleSysexit(CPUState& cpu);
    [[nodiscard]] bool HandleInt2E(CPUState& cpu);
    [[nodiscard]] bool HandleIret(CPUState& cpu, VirtualMemory& memory);

    // Current privilege level
    [[nodiscard]] uint8_t GetCPL() const;
    void SetCPL(uint8_t cpl);
    [[nodiscard]] bool IsKernelMode() const;
    [[nodiscard]] bool IsUserMode() const;

    // Transition history
    [[nodiscard]] const std::vector<RingTransitionEvent>& GetHistory() const;
    [[nodiscard]] uint32_t GetSyscallCount() const;
    [[nodiscard]] uint32_t GetTransitionCount() const;

    // Anomaly detection
    [[nodiscard]] std::vector<TransitionAnomaly> DetectAnomalies() const;

    // Most called syscalls (for behavioral analysis)
    [[nodiscard]] std::vector<std::pair<uint32_t, uint32_t>> GetSyscallHistogram() const;

private:
    RingTransition();
    ~RingTransition();

    RingTransition(const RingTransition&) = delete;
    RingTransition& operator=(const RingTransition&) = delete;
    RingTransition(RingTransition&&) = delete;
    RingTransition& operator=(RingTransition&&) = delete;

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
