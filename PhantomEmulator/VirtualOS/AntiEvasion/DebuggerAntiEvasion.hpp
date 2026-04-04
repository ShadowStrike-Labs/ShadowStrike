/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * DebuggerAntiEvasion.hpp — Anti-debug response centralizer
 *
 * Malware checks for debuggers through dozens of different methods.
 * This module centralizes ALL anti-debugging responses, ensuring
 * consistent "no debugger present" answers and tracking every
 * evasion attempt as a behavioral IOC.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <atomic>
#include <shared_mutex>

namespace Phantom::VirtualOS::AntiEvasion {

// ============================================================================
// DebuggerAntiEvasion — Centralized anti-debug bypass and tracking
// ============================================================================

class DebuggerAntiEvasion {
public:
    [[nodiscard]] static DebuggerAntiEvasion& Instance() noexcept;

    void Initialize(const EmulationConfig& config) noexcept;
    void Reset() noexcept;

    // === PEB-based checks ===
    [[nodiscard]] bool     GetPEBBeingDebugged() const noexcept;
    [[nodiscard]] uint32_t GetPEBNtGlobalFlag() const noexcept;
    [[nodiscard]] uint64_t GetProcessDebugPort() const noexcept;
    [[nodiscard]] uint32_t GetProcessDebugFlags() const noexcept;
    [[nodiscard]] int32_t  GetDebugObjectHandle() const noexcept;

    // === Heap-based checks ===
    [[nodiscard]] uint32_t GetHeapFlags() const noexcept;
    [[nodiscard]] uint32_t GetHeapForceFlags() const noexcept;

    // === INT-based checks ===
    [[nodiscard]] bool HandleInt2D() const noexcept;
    [[nodiscard]] bool HandleInt3() const noexcept;

    // === API-based checks ===
    [[nodiscard]] bool IsDebuggerPresent() const noexcept;
    [[nodiscard]] bool CheckRemoteDebuggerPresent() const noexcept;

    // === NtSetInformationThread ===
    [[nodiscard]] bool HandleThreadHideFromDebugger() const noexcept;

    // === Hardware debug registers ===
    [[nodiscard]] uint64_t GetDR0() const noexcept;
    [[nodiscard]] uint64_t GetDR1() const noexcept;
    [[nodiscard]] uint64_t GetDR2() const noexcept;
    [[nodiscard]] uint64_t GetDR3() const noexcept;
    [[nodiscard]] uint64_t GetDR6() const noexcept;
    [[nodiscard]] uint64_t GetDR7() const noexcept;

    // === Kernel debugger ===
    [[nodiscard]] bool IsKernelDebuggerPresent() const noexcept;
    [[nodiscard]] bool IsKernelDebuggerEnabled() const noexcept;

    // === NtSystemDebugControl ===
    [[nodiscard]] int32_t HandleSystemDebugControl() const noexcept;

    // === OutputDebugString trick ===
    [[nodiscard]] uint32_t GetOutputDebugStringError() const noexcept;

    // === Parent process check ===
    [[nodiscard]] uint32_t     GetParentProcessId() const noexcept;
    [[nodiscard]] std::wstring GetParentProcessName() const noexcept;

    // === Window checks ===
    [[nodiscard]] bool HasDebuggerWindow() const noexcept;

    // === Evasion attempt tracking ===
    [[nodiscard]] uint32_t GetAntiDebugCheckCount() const noexcept;
    void RecordAntiDebugAttempt(std::string_view technique) noexcept;
    [[nodiscard]] std::vector<std::string> GetDetectedTechniques() const noexcept;

private:
    DebuggerAntiEvasion() noexcept = default;
    ~DebuggerAntiEvasion() noexcept = default;
    DebuggerAntiEvasion(const DebuggerAntiEvasion&) = delete;
    DebuggerAntiEvasion& operator=(const DebuggerAntiEvasion&) = delete;

    mutable std::shared_mutex m_mutex;
    std::vector<std::string>  m_detectedTechniques;
    mutable std::atomic<uint32_t> m_checkCount{0};

    bool m_initialized = false;

    static constexpr uint32_t kMaxTrackedTechniques = 4096;
};

} // namespace Phantom::VirtualOS::AntiEvasion
