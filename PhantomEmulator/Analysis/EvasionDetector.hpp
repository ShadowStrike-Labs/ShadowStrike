/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#pragma once

#include "../Common/Types.hpp"
#include "../Common/Config.hpp"
#include "../WinAPI/APITypes.hpp"
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace Phantom {

// ============================================================================
// Evasion Technique Taxonomy
// ============================================================================

enum class EvasionTechnique : uint8_t {
    // Anti-Debug
    IsDebuggerPresent,
    CheckRemoteDebuggerPresent,
    NtQueryInfoProcessDebugPort,
    NtQueryInfoProcessDebugFlags,
    NtQueryInfoProcessDebugObject,
    NtSetInfoThreadHideFromDebugger,
    CloseHandleWithInvalidHandle,
    OutputDebugString,
    INT2D,
    RDTSC_Timing,
    QueryPerformanceCounter_Timing,
    GetTickCount_Timing,
    NtQuerySystemTime_Timing,
    UnhandledExceptionFilter,
    SetLastError_Check,
    NtYieldExecution,
    FindWindow_OllyDbg,

    // Anti-VM
    CPUID_Hypervisor,
    CPUID_Vendor,
    RegQuery_VMware,
    RegQuery_VBox,
    RegQuery_HyperV,
    DeviceQuery_VMware,
    DeviceQuery_VBox,
    ProcessCheck_VMTools,
    ProcessCheck_VBoxTray,
    FileCheck_VMware,
    FileCheck_VBox,
    MACAddress_VMware,
    MACAddress_VBox,
    DiskSize_Check,
    MemorySize_Check,
    ProcessorCount_Check,
    SMBIOS_Check,
    ACPI_Check,
    FirmwareTable_Check,

    // Anti-Sandbox
    SleepAcceleration,
    UserInteraction_Check,
    ScreenResolution_Check,
    DomainJoined_Check,
    RunningProcessCount_Check,
    RecentFiles_Check,
    SystemUptime_Check,
    MouseMovement_Check,
    USBHistory_Check,
    InstalledSoftware_Check,
    Filename_Check,

    // Anti-Analysis
    ProcessCheck_Wireshark,
    ProcessCheck_IDA,
    ProcessCheck_x64dbg,
    ProcessCheck_Procmon,
    ProcessCheck_ProcExp,
    ModuleCheck_SbieDll,
    ModuleCheck_DbgHelp,
    WindowCheck_Filemon,
    ParentProcess_Check,
};

// ============================================================================
// Evasion Attempt Record
// ============================================================================

struct EvasionAttempt {
    EvasionTechnique technique;
    std::string      description;
    GuestAddress     rip              = 0; // Instruction pointer at time of attempt
    uint64_t         instructionCount = 0;
    float            severity         = 0.0f; // 0.0 – 1.0
    bool             wasDefeated      = false; // Did anti-evasion module handle it?
};

// ============================================================================
// Aggregate Evasion Summary
// ============================================================================

struct EvasionSummary {
    uint32_t    totalAttempts          = 0;
    uint32_t    uniqueTechniques       = 0;
    uint32_t    antiDebugCount         = 0;
    uint32_t    antiVMCount            = 0;
    uint32_t    antiSandboxCount       = 0;
    uint32_t    antiAnalysisCount      = 0;
    float       evasionScore           = 0.0f; // 0.0 – 1.0
    bool        isHighlyEvasive        = false; // Score > 0.7
    std::string sophisticationLevel;            // "Basic", …, "Nation-State"
};

// ============================================================================
// Evasion Detector
// ============================================================================
// Aggregates and analyses all evasion techniques attempted by the sample.
// Tracks anti-debug, anti-VM, anti-sandbox, and anti-analysis-tool attempts.
//
// Thread-safe: designed for single-threaded event-driven analysis.

class EvasionDetector {
public:
    explicit EvasionDetector(const EmulationConfig& config) noexcept;
    ~EvasionDetector() noexcept;

    EvasionDetector(const EvasionDetector&) = delete;
    EvasionDetector& operator=(const EvasionDetector&) = delete;
    EvasionDetector(EvasionDetector&&) noexcept;
    EvasionDetector& operator=(EvasionDetector&&) noexcept;

    // --- Feed events ---

    void OnAPICall(const APICallDetail& call) noexcept;
    void OnTimingCheck(GuestAddress rip, uint64_t instrCount) noexcept;
    void OnEnvironmentQuery(const std::string& queryType,
                            const std::string& detail) noexcept;
    void OnProcessEnumeration(const std::string& processName) noexcept;

    // --- Results ---

    [[nodiscard]] const std::vector<EvasionAttempt>& GetAttempts() const noexcept;
    [[nodiscard]] EvasionSummary GetSummary() const noexcept;
    [[nodiscard]] uint32_t GetAttemptCount() const noexcept;
    [[nodiscard]] std::vector<const EvasionAttempt*> GetByTechnique(EvasionTechnique tech) const noexcept;
    [[nodiscard]] bool HasTechnique(EvasionTechnique tech) const noexcept;
    [[nodiscard]] float GetEvasionScore() const noexcept;

    void Reset() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
