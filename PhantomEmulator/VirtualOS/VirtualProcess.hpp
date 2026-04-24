/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * VirtualProcess.hpp — Centralized fake process/thread table
 *
 * Provides the backing store for NtQuerySystemInformation
 * (SystemProcessInformation), NtQueryInformationProcess, and all
 * process / thread handle operations.  Manages:
 *   - A realistic fake process list (~60 Win10 Pro entries)
 *   - Thread lifecycle for the emulated process
 *   - Per-process module list (DLL base addresses)
 *   - IOC tracking for child-process creation
 *
 * ANTI-EVASION: The process list never contains analysis tools.
 * Any lookup for debugger / sandbox process names returns empty.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../Common/Types.hpp"
#include "../Common/Config.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <shared_mutex>
#include <unordered_map>

namespace Phantom::VirtualOS {

// ============================================================================
// Data Structures
// ============================================================================

struct ProcessInfo {
    uint32_t     pid;
    uint32_t     parentPid;
    std::wstring name;
    std::wstring imagePath;
    uint32_t     threadCount;
    uint32_t     handleCount;
    uint64_t     workingSetSize;     // bytes
    uint64_t     virtualSize;        // bytes
    uint64_t     createTime;         // FILETIME (100-ns since 1601-01-01)
    int32_t      basePriority;
    uint32_t     sessionId;
    bool         isSystem;           // System process (PID < 100)
};

struct ThreadInfo {
    uint32_t     tid;
    uint32_t     ownerPid;
    GuestAddress startAddress;
    int32_t      priority;
    uint32_t     state;              // KTHREAD_STATE
    uint64_t     createTime;
    uint64_t     kernelTime;         // 100-ns units
    uint64_t     userTime;           // 100-ns units
    uint32_t     waitReason;
    bool         isSuspended;
};

struct ModuleInfo {
    std::wstring name;
    std::wstring fullPath;
    GuestAddress baseAddress;
    uint32_t     imageSize;
    uint32_t     flags;
    uint16_t     loadOrderIndex;
    uint16_t     initOrderIndex;
};

// IOC: Process creation event recorded when the emulated sample spawns
// a child process.  CREATE_SUSPENDED is a strong indicator of process
// hollowing; CREATE_NO_WINDOW often indicates hidden payload execution.
struct ProcessCreateIOC {
    std::wstring commandLine;
    std::wstring imagePath;
    uint32_t     creationFlags;
    bool         isSuspended;        // CREATE_SUSPENDED → hollowing indicator
    bool         isHidden;           // CREATE_NO_WINDOW
};

// ============================================================================
// VirtualProcess — Singleton
// ============================================================================

class VirtualProcess {
public:
    [[nodiscard]] static VirtualProcess& Instance() noexcept;

    void Initialize(const EmulationConfig& config) noexcept;
    void Reset() noexcept;

    // === Process Table ===
    /// Returns a locked snapshot of the virtual process table. On allocation
    /// failure the snapshot is empty and internal state remains unchanged.
    [[nodiscard]] std::vector<ProcessInfo> GetProcessList() const noexcept;
    [[nodiscard]] std::optional<ProcessInfo> GetProcessByPID(uint32_t pid) const noexcept;
    [[nodiscard]] std::optional<ProcessInfo> GetProcessByName(std::wstring_view name) const noexcept;

    // Current emulated process info
    /// Returns a locked snapshot of the emulated process descriptor.
    [[nodiscard]] ProcessInfo GetCurrentProcess() const noexcept;
    [[nodiscard]] uint32_t GetCurrentPID() const noexcept;
    [[nodiscard]] uint32_t GetParentPID() const noexcept;

    // === Thread Management ===
    [[nodiscard]] uint32_t CreateThread(GuestAddress startAddress, int32_t priority = 0) noexcept;
    [[nodiscard]] std::vector<ThreadInfo> GetThreadList(uint32_t pid) const noexcept;
    [[nodiscard]] std::optional<ThreadInfo> GetThreadByTID(uint32_t tid) const noexcept;
    [[nodiscard]] uint32_t GetCurrentTID() const noexcept;
    bool SuspendThread(uint32_t tid) noexcept;
    bool ResumeThread(uint32_t tid) noexcept;
    bool TerminateThread(uint32_t tid) noexcept;

    // === Module List ===
    /// Returns a locked snapshot of modules mapped into the emulated process.
    [[nodiscard]] std::vector<ModuleInfo> GetModuleList() const noexcept;
    [[nodiscard]] std::optional<ModuleInfo> GetModuleByName(std::wstring_view name) const noexcept;
    [[nodiscard]] std::optional<ModuleInfo> GetModuleByAddress(GuestAddress addr) const noexcept;

    // === Anti-Evasion Checks ===
    [[nodiscard]] bool IsAnalysisTool(std::wstring_view processName) const noexcept;
    [[nodiscard]] bool IsDebuggerProcess(std::wstring_view processName) const noexcept;

    // === IOC Tracking ===
    void RecordProcessCreation(const ProcessCreateIOC& ioc) noexcept;
    [[nodiscard]] std::vector<ProcessCreateIOC> GetProcessCreationIOCs() const noexcept;

    // === PEB/TEB Info ===
    [[nodiscard]] GuestAddress GetPEBAddress() const noexcept;
    [[nodiscard]] GuestAddress GetTEBAddress() const noexcept;
    [[nodiscard]] GuestAddress GetProcessHeapAddress() const noexcept;

private:
    VirtualProcess() noexcept = default;
    ~VirtualProcess() noexcept = default;
    VirtualProcess(const VirtualProcess&) = delete;
    VirtualProcess& operator=(const VirtualProcess&) = delete;

    void PopulateProcessList(const EmulationConfig& config);
    void PopulateModuleList();

    mutable std::shared_mutex m_mutex;
    std::vector<ProcessInfo>      m_processList;
    std::vector<ThreadInfo>       m_threads;
    std::vector<ModuleInfo>       m_modules;
    std::vector<ProcessCreateIOC> m_createIOCs;

    ProcessInfo m_currentProcess{};
    uint32_t    m_nextTID     = 0;
    bool        m_initialized = false;

    static constexpr uint32_t kEmulatedPID       = 4444;
    static constexpr uint32_t kEmulatedParentPID = 3000; // explorer.exe
    static constexpr uint32_t kMaxThreads        = 256;
    static constexpr uint32_t kMaxIOCs           = 10000;
};

} // namespace Phantom::VirtualOS
