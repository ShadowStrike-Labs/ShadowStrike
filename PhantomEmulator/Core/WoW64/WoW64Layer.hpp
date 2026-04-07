/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#pragma once

#include "../../Common/Types.hpp"
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace Phantom {

// Forward declarations
class CPUState;
class VirtualMemory;

// ============================================================================
// WoW64 Transition Classification
// ============================================================================
// Identifies the type of 32↔64 bit transition occurring in a WoW64 process.
// This is critical for detecting Heaven's Gate evasion — malware that switches
// from 32-bit to 64-bit code to bypass analysis tools that only instrument
// one execution mode.

enum class WoW64Transition : uint8_t {
    None,
    Wow64SystemService,     // Normal wow64 syscall thunking via wow64cpu.dll
    HeavensGate32to64,      // 32→64 bit switch (far call/jmp to 64-bit CS)
    HeavensGate64to32,      // 64→32 bit switch (far ret/jmp back to 32-bit CS)
    TurboThunk,             // Fast-path thunking for common APIs
};

// ============================================================================
// Heaven's Gate Detection Event
// ============================================================================
// Records a single cross-mode transition for post-emulation analysis.
// Security analysts use these events to identify evasion techniques.

struct HeavensGateEvent {
    GuestAddress sourceRIP = 0;         // RIP before the transition
    GuestAddress targetRIP = 0;         // RIP after the transition
    WoW64Transition direction = WoW64Transition::None;
    uint64_t instructionCount = 0;      // When it happened
    bool isEvasionAttempt = false;      // True if transition bypasses wow64cpu.dll
};

// ============================================================================
// WoW64 Process Layout
// ============================================================================
// Tracks the guest addresses of the 32-bit and 64-bit PEB/TEB structures
// and the WoW64 system DLL base addresses. These must match real Windows
// memory layout so that malware's PEB/TEB walks succeed.

struct WoW64ProcessInfo {
    // 64-bit structures (native)
    GuestAddress peb64 = 0;
    GuestAddress teb64 = 0;

    // 32-bit structures (WoW64 shadows)
    GuestAddress peb32 = 0;             // PEB32 in low 4GB
    GuestAddress teb32 = 0;             // TEB32 in low 4GB

    // WoW64 system DLLs
    GuestAddress wow64DllBase = 0;      // wow64.dll
    GuestAddress wow64CpuDllBase = 0;   // wow64cpu.dll
    GuestAddress wow64WinDllBase = 0;   // wow64win.dll
    GuestAddress ntdll32Base = 0;       // ntdll.dll (32-bit copy)
    GuestAddress ntdll64Base = 0;       // ntdll.dll (64-bit native)

    // Key internal addresses
    GuestAddress wow64TransitionStub = 0; // wow64cpu!X86SwitchTo64BitMode
    GuestAddress wow64SystemService = 0;  // wow64!Wow64SystemServiceEx
};

// ============================================================================
// Syscall Translation Entry
// ============================================================================
// Maps a 32-bit WoW64 syscall number to its 64-bit NT equivalent.
// Pointer parameters require widening (4→8 bytes), handles need
// zero-extension, and structure layouts differ between 32/64 bit.

struct SyscallTranslation {
    uint32_t wow64Number = 0;           // 32-bit syscall number
    uint32_t nativeNumber = 0;          // Corresponding 64-bit syscall number
    uint8_t  paramCount32 = 0;          // Number of 32-bit stack params
    uint8_t  paramCount64 = 0;          // Number of 64-bit params
    bool     needsPointerThunk = false; // True if any param is a pointer
};

// ============================================================================
// WoW64 Emulation Layer
// ============================================================================
// Enables correct emulation of 32-bit PE files inside a 64-bit emulation
// environment. Over 40% of malware in the wild is 32-bit, running under
// the WoW64 subsystem on modern 64-bit Windows.
//
// Responsibilities:
// - Segment descriptor setup (CS32=0x23, CS64=0x33, FS/GS bases)
// - PEB32/TEB32 allocation and initialization in low 4GB
// - Syscall thunking: 32-bit cdecl stack params → 64-bit fastcall registers
// - Heaven's Gate detection: 32↔64 mode switches not through wow64cpu.dll
// - File system redirection: System32 → SysWOW64
// - Registry redirection: Software → Software\WOW6432Node
//
// Thread safety: This class is NOT thread-safe by itself. It is designed
// to be owned by a single emulation session thread. The emulator core
// serializes access to CPU state and memory.

class WoW64Layer {
public:
    WoW64Layer() noexcept;
    ~WoW64Layer() noexcept;

    WoW64Layer(const WoW64Layer&) = delete;
    WoW64Layer& operator=(const WoW64Layer&) = delete;

    // ========================================================================
    // Initialization
    // ========================================================================

    [[nodiscard]] bool Initialize(VirtualMemory& memory,
                                   CPUState& cpu) noexcept;

    [[nodiscard]] bool SetupFor32BitPE(VirtualMemory& memory,
                                        CPUState& cpu,
                                        GuestAddress imageBase,
                                        GuestAddress entryPoint) noexcept;

    [[nodiscard]] bool IsInitialized() const noexcept;

    // ========================================================================
    // Segment Descriptor Management
    // ========================================================================

    [[nodiscard]] bool SetupSegmentDescriptors(VirtualMemory& memory,
                                                CPUState& cpu) noexcept;

    [[nodiscard]] uint16_t GetCS32Selector() const noexcept;
    [[nodiscard]] uint16_t GetCS64Selector() const noexcept;

    // ========================================================================
    // CPU Mode Switching
    // ========================================================================

    void SwitchTo32Bit(CPUState& cpu) noexcept;
    void SwitchTo64Bit(CPUState& cpu) noexcept;

    // ========================================================================
    // Heaven's Gate Detection
    // ========================================================================

    [[nodiscard]] bool DetectHeavensGate(
        const CPUState& cpu,
        uint16_t targetSelector,
        GuestAddress targetOffset,
        WoW64Transition& outTransition) noexcept;

    void ProcessTransition(CPUState& cpu,
                           WoW64Transition transition,
                           GuestAddress targetRIP) noexcept;

    [[nodiscard]] const std::vector<HeavensGateEvent>& GetHeavensGateEvents() const noexcept;

    // ========================================================================
    // Syscall Thunking (32-bit → 64-bit)
    // ========================================================================

    [[nodiscard]] bool ThunkSyscall(CPUState& cpu,
                                     VirtualMemory& memory) noexcept;

    void RegisterSyscallTranslation(const SyscallTranslation& entry) noexcept;

    // ========================================================================
    // Address Translation
    // ========================================================================

    [[nodiscard]] GuestAddress Widen32To64(uint32_t addr32) const noexcept;
    [[nodiscard]] uint32_t Narrow64To32(GuestAddress addr64) const noexcept;
    [[nodiscard]] bool IsWoW64Address(GuestAddress addr) const noexcept;

    // ========================================================================
    // TEB/PEB Access
    // ========================================================================

    [[nodiscard]] const WoW64ProcessInfo& GetProcessInfo() const noexcept;
    [[nodiscard]] GuestAddress GetTEB32() const noexcept;
    [[nodiscard]] GuestAddress GetTEB64() const noexcept;

    // ========================================================================
    // File System Redirection
    // ========================================================================

    [[nodiscard]] std::wstring RedirectPath(std::wstring_view path) const noexcept;
    [[nodiscard]] bool IsFsRedirectionDisabled() const noexcept;
    void SetFsRedirection(bool enabled) noexcept;

    // ========================================================================
    // Registry Redirection
    // ========================================================================

    [[nodiscard]] std::wstring RedirectRegistryKey(std::wstring_view keyPath) const noexcept;

    // ========================================================================
    // Statistics
    // ========================================================================

    [[nodiscard]] uint32_t GetTransitionCount() const noexcept;
    [[nodiscard]] uint32_t GetSyscallThunkCount() const noexcept;
    [[nodiscard]] uint32_t GetHeavensGateCount() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
