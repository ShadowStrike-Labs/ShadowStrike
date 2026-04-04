/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * DebuggerAntiEvasion.cpp — Anti-debug response centralizer
 *
 * Every anti-debugging technique known to the malware analysis community
 * is handled here with a "clean system" response, while simultaneously
 * recording each attempt as a behavioral indicator of compromise (IOC).
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "DebuggerAntiEvasion.hpp"
#include <algorithm>

namespace Phantom::VirtualOS::AntiEvasion {

// ============================================================================
// NT status codes used in anti-debug responses (no windows.h dependency)
// ============================================================================

namespace {

constexpr int32_t kStatusPortNotSet        = static_cast<int32_t>(0xC0000353);
constexpr int32_t kStatusDebuggerInactive  = static_cast<int32_t>(0xC0000354);

// OutputDebugString sets last error to this when no debugger is attached
constexpr uint32_t kNoDebuggerLastError    = 0x00000057; // ERROR_INVALID_PARAMETER

// Simulated parent process (explorer.exe)
constexpr uint32_t kExplorerPID            = 3000;

// Heap flags for a non-debug heap
constexpr uint32_t kHeapGrowable           = 0x00000002;

// Debug register reset-state values (Intel SDM Vol. 3B)
constexpr uint64_t kDR6ResetState          = 0xFFFF0FF0ULL;
constexpr uint64_t kDR7ResetState          = 0x00000400ULL;

} // anonymous namespace

// ============================================================================
// Singleton
// ============================================================================

DebuggerAntiEvasion& DebuggerAntiEvasion::Instance() noexcept {
    static DebuggerAntiEvasion instance;
    return instance;
}

// ============================================================================
// Initialize
// ============================================================================

void DebuggerAntiEvasion::Initialize(const EmulationConfig& /*config*/) noexcept {
    if (m_initialized) return;

    {
        std::unique_lock lock(m_mutex);
        m_detectedTechniques.clear();
        m_detectedTechniques.reserve(64);
    }
    m_checkCount.store(0, std::memory_order_relaxed);
    m_initialized = true;
}

// ============================================================================
// Reset
// ============================================================================

void DebuggerAntiEvasion::Reset() noexcept {
    {
        std::unique_lock lock(m_mutex);
        m_detectedTechniques.clear();
    }
    m_checkCount.store(0, std::memory_order_relaxed);
    m_initialized = false;
}

// ============================================================================
// Evasion attempt tracking
// ============================================================================

void DebuggerAntiEvasion::RecordAntiDebugAttempt(std::string_view technique) noexcept {
    m_checkCount.fetch_add(1, std::memory_order_relaxed);

    std::unique_lock lock(m_mutex);
    if (m_detectedTechniques.size() < kMaxTrackedTechniques) {
        m_detectedTechniques.emplace_back(technique);
    }
}

uint32_t DebuggerAntiEvasion::GetAntiDebugCheckCount() const noexcept {
    return m_checkCount.load(std::memory_order_relaxed);
}

std::vector<std::string> DebuggerAntiEvasion::GetDetectedTechniques() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_detectedTechniques;
}

// ============================================================================
// PEB-based checks
// ============================================================================

bool DebuggerAntiEvasion::GetPEBBeingDebugged() const noexcept {
    // PEB.BeingDebugged — 0 = not debugged
    const_cast<DebuggerAntiEvasion*>(this)->RecordAntiDebugAttempt(
        "PEB.BeingDebugged");
    return false;
}

uint32_t DebuggerAntiEvasion::GetPEBNtGlobalFlag() const noexcept {
    // A debugged process has FLG_HEAP_ENABLE_TAIL_CHECK (0x10),
    // FLG_HEAP_ENABLE_FREE_CHECK (0x20), FLG_HEAP_VALIDATE_PARAMETERS (0x40).
    // Clean system = 0.
    const_cast<DebuggerAntiEvasion*>(this)->RecordAntiDebugAttempt(
        "PEB.NtGlobalFlag");
    return 0;
}

uint64_t DebuggerAntiEvasion::GetProcessDebugPort() const noexcept {
    // NtQueryInformationProcess(ProcessDebugPort) — 0 = no debugger
    const_cast<DebuggerAntiEvasion*>(this)->RecordAntiDebugAttempt(
        "NtQIP.ProcessDebugPort");
    return 0;
}

uint32_t DebuggerAntiEvasion::GetProcessDebugFlags() const noexcept {
    // NtQueryInformationProcess(ProcessDebugFlags) — 1 = NOT being debugged
    // (counter-intuitive: 1 means NoDebugInherit flag IS set)
    const_cast<DebuggerAntiEvasion*>(this)->RecordAntiDebugAttempt(
        "NtQIP.ProcessDebugFlags");
    return 1;
}

int32_t DebuggerAntiEvasion::GetDebugObjectHandle() const noexcept {
    // NtQueryInformationProcess(ProcessDebugObjectHandle)
    // STATUS_PORT_NOT_SET when no debugger is attached
    const_cast<DebuggerAntiEvasion*>(this)->RecordAntiDebugAttempt(
        "NtQIP.ProcessDebugObjectHandle");
    return kStatusPortNotSet;
}

// ============================================================================
// Heap-based checks
// ============================================================================

uint32_t DebuggerAntiEvasion::GetHeapFlags() const noexcept {
    // In a debug heap: HEAP_GROWABLE | HEAP_TAIL_CHECKING_ENABLED |
    //                  HEAP_FREE_CHECKING_ENABLED | HEAP_VALIDATE_PARAMETERS_ENABLED
    // Clean: only HEAP_GROWABLE (0x02)
    const_cast<DebuggerAntiEvasion*>(this)->RecordAntiDebugAttempt(
        "Heap.Flags");
    return kHeapGrowable;
}

uint32_t DebuggerAntiEvasion::GetHeapForceFlags() const noexcept {
    // Clean system: 0 (no forced debug flags on heap)
    const_cast<DebuggerAntiEvasion*>(this)->RecordAntiDebugAttempt(
        "Heap.ForceFlags");
    return 0;
}

// ============================================================================
// INT-based checks
// ============================================================================

bool DebuggerAntiEvasion::HandleInt2D() const noexcept {
    // INT 2D: kernel debugger interface. Without a debugger, the byte
    // after INT 2D is skipped. We return true to indicate "handled as
    // no-debugger" (caller should skip one byte and continue).
    const_cast<DebuggerAntiEvasion*>(this)->RecordAntiDebugAttempt(
        "INT2D");
    return true;
}

bool DebuggerAntiEvasion::HandleInt3() const noexcept {
    // INT 3: software breakpoint. Without a debugger, this raises
    // EXCEPTION_BREAKPOINT. Return true to indicate the exception
    // should be dispatched to the guest SEH chain, not swallowed.
    const_cast<DebuggerAntiEvasion*>(this)->RecordAntiDebugAttempt(
        "INT3");
    return true;
}

// ============================================================================
// API-based checks
// ============================================================================

bool DebuggerAntiEvasion::IsDebuggerPresent() const noexcept {
    const_cast<DebuggerAntiEvasion*>(this)->RecordAntiDebugAttempt(
        "IsDebuggerPresent");
    return false;
}

bool DebuggerAntiEvasion::CheckRemoteDebuggerPresent() const noexcept {
    const_cast<DebuggerAntiEvasion*>(this)->RecordAntiDebugAttempt(
        "CheckRemoteDebuggerPresent");
    return false;
}

// ============================================================================
// NtSetInformationThread(ThreadHideFromDebugger)
// ============================================================================

bool DebuggerAntiEvasion::HandleThreadHideFromDebugger() const noexcept {
    // Malware calls this to hide from a debugger. We succeed silently
    // (STATUS_SUCCESS) — the call appears to work but there's no
    // debugger to hide from. Return true = success.
    const_cast<DebuggerAntiEvasion*>(this)->RecordAntiDebugAttempt(
        "NtSetInformationThread.HideFromDebugger");
    return true;
}

// ============================================================================
// Hardware debug registers
// ============================================================================
// When no hardware breakpoints are set, DR0-DR3 are 0.
// DR6 status register is 0xFFFF0FF0 (reset state per Intel SDM).
// DR7 control register is 0x400 (reset state, bit 10 always set).

uint64_t DebuggerAntiEvasion::GetDR0() const noexcept {
    const_cast<DebuggerAntiEvasion*>(this)->RecordAntiDebugAttempt(
        "HW.DR0");
    return 0;
}

uint64_t DebuggerAntiEvasion::GetDR1() const noexcept {
    const_cast<DebuggerAntiEvasion*>(this)->RecordAntiDebugAttempt(
        "HW.DR1");
    return 0;
}

uint64_t DebuggerAntiEvasion::GetDR2() const noexcept {
    const_cast<DebuggerAntiEvasion*>(this)->RecordAntiDebugAttempt(
        "HW.DR2");
    return 0;
}

uint64_t DebuggerAntiEvasion::GetDR3() const noexcept {
    const_cast<DebuggerAntiEvasion*>(this)->RecordAntiDebugAttempt(
        "HW.DR3");
    return 0;
}

uint64_t DebuggerAntiEvasion::GetDR6() const noexcept {
    const_cast<DebuggerAntiEvasion*>(this)->RecordAntiDebugAttempt(
        "HW.DR6");
    return kDR6ResetState;
}

uint64_t DebuggerAntiEvasion::GetDR7() const noexcept {
    const_cast<DebuggerAntiEvasion*>(this)->RecordAntiDebugAttempt(
        "HW.DR7");
    return kDR7ResetState;
}

// ============================================================================
// Kernel debugger
// ============================================================================

bool DebuggerAntiEvasion::IsKernelDebuggerPresent() const noexcept {
    // NtQuerySystemInformation(SystemKernelDebuggerInformation)
    // KdDebuggerEnabled = FALSE
    const_cast<DebuggerAntiEvasion*>(this)->RecordAntiDebugAttempt(
        "NtQSI.KernelDebuggerPresent");
    return false;
}

bool DebuggerAntiEvasion::IsKernelDebuggerEnabled() const noexcept {
    // KdDebuggerNotPresent = TRUE (double negative: debugger NOT present)
    const_cast<DebuggerAntiEvasion*>(this)->RecordAntiDebugAttempt(
        "NtQSI.KernelDebuggerEnabled");
    return false;
}

// ============================================================================
// NtSystemDebugControl
// ============================================================================

int32_t DebuggerAntiEvasion::HandleSystemDebugControl() const noexcept {
    // Without a kernel debugger, returns STATUS_DEBUGGER_INACTIVE
    const_cast<DebuggerAntiEvasion*>(this)->RecordAntiDebugAttempt(
        "NtSystemDebugControl");
    return kStatusDebuggerInactive;
}

// ============================================================================
// OutputDebugString trick
// ============================================================================

uint32_t DebuggerAntiEvasion::GetOutputDebugStringError() const noexcept {
    // Technique: SetLastError(0), OutputDebugString("..."), GetLastError().
    // With debugger: error stays 0 (debugger consumed the string).
    // Without debugger: error is set to ERROR_INVALID_PARAMETER (87).
    const_cast<DebuggerAntiEvasion*>(this)->RecordAntiDebugAttempt(
        "OutputDebugString.ErrorCheck");
    return kNoDebuggerLastError;
}

// ============================================================================
// Parent process check
// ============================================================================

uint32_t DebuggerAntiEvasion::GetParentProcessId() const noexcept {
    // Malware checks if parent is explorer.exe (normal) vs. debugger.
    const_cast<DebuggerAntiEvasion*>(this)->RecordAntiDebugAttempt(
        "ParentProcess.PID");
    return kExplorerPID;
}

std::wstring DebuggerAntiEvasion::GetParentProcessName() const noexcept {
    const_cast<DebuggerAntiEvasion*>(this)->RecordAntiDebugAttempt(
        "ParentProcess.Name");
    return L"explorer.exe";
}

// ============================================================================
// Window checks
// ============================================================================

bool DebuggerAntiEvasion::HasDebuggerWindow() const noexcept {
    // FindWindow("OLLYDBG"), FindWindow("x64dbg"), etc. — all return NULL
    const_cast<DebuggerAntiEvasion*>(this)->RecordAntiDebugAttempt(
        "FindWindow.DebuggerClass");
    return false;
}

} // namespace Phantom::VirtualOS::AntiEvasion
