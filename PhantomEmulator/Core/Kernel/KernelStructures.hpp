/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * KernelStructures — Emulated Windows kernel objects for DKOM detection
 *
 * Provides faithful representations of EPROCESS, KTHREAD, DRIVER_OBJECT,
 * SSDT, and IDT structures that kernel-mode malware (rootkits, bootkits)
 * manipulates via Direct Kernel Object Manipulation. The KernelObjectManager
 * maintains linked-list integrity invariants and scans for hook/unlink attacks.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../../Common/Types.hpp"
#include "../../Common/WinMacroUndef.hpp"
#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace Phantom {

class VirtualMemory;

// ============================================================================
// Capacity Limits
// ============================================================================

static constexpr uint32_t kMaxEmulatedProcesses = 256;
static constexpr uint32_t kMaxEmulatedThreads   = 4096;
static constexpr uint32_t kMaxEmulatedDrivers   = 512;
static constexpr uint32_t kSSDTEntryCount       = 512;
static constexpr uint32_t kIDTEntryCount        = 256;
static constexpr uint32_t kIRPMajorCount        = 28;

// ============================================================================
// EPROCESS (simplified but accurate field layout)
// ============================================================================

struct EmulatedEPROCESS {
    GuestAddress selfPtr                    = 0;
    GuestAddress activeProcessLinks_Flink   = 0;
    GuestAddress activeProcessLinks_Blink   = 0;
    uint32_t     uniqueProcessId            = 0;
    uint32_t     parentProcessId            = 0;
    GuestAddress imageFileName              = 0;
    char         imageFileNameStr[16]       = {};
    GuestAddress peb                        = 0;
    GuestAddress objectTable                = 0;
    uint8_t      protection                 = 0;
    bool         isWow64                    = false;
    uint64_t     createTime                 = 0;
    uint64_t     exitTime                   = 0;
    int32_t      exitStatus                 = 0;
    GuestAddress token                      = 0;
    GuestAddress sectionObject              = 0;
    uint32_t     flags                      = 0;
    uint32_t     flags2                     = 0;
    GuestAddress vadRoot                    = 0;
    GuestAddress threadListHead_Flink       = 0;
    GuestAddress threadListHead_Blink       = 0;
};

// ============================================================================
// KTHREAD (simplified)
// ============================================================================

struct EmulatedKTHREAD {
    GuestAddress selfPtr                    = 0;
    GuestAddress process                    = 0;
    uint32_t     threadId                   = 0;
    GuestAddress startAddress               = 0;
    GuestAddress win32StartAddress          = 0;
    GuestAddress stackBase                  = 0;
    GuestAddress stackLimit                 = 0;
    GuestAddress kernelStack                = 0;
    uint8_t      state                      = 0;   // 0=Init, 2=Running, 5=Waiting
    int8_t       priority                   = 0;
    int8_t       basePriority               = 0;
    bool         alertable                  = false;
    GuestAddress teb                        = 0;
    GuestAddress threadListEntry_Flink      = 0;
    GuestAddress threadListEntry_Blink      = 0;
    uint64_t     createTime                 = 0;
    uint8_t      previousMode               = 0;   // KernelMode=0, UserMode=1
};

// ============================================================================
// DRIVER_OBJECT
// ============================================================================

struct EmulatedDriverObject {
    GuestAddress selfPtr                    = 0;
    GuestAddress deviceObject               = 0;
    GuestAddress driverStart                = 0;
    uint32_t     driverSize                 = 0;
    GuestAddress driverInit                 = 0;
    GuestAddress driverUnload               = 0;
    std::array<GuestAddress, kIRPMajorCount> majorFunction{};
    char         driverName[64]             = {};
    GuestAddress driverExtension            = 0;
};

// ============================================================================
// SSDT (System Service Descriptor Table)
// ============================================================================

struct SSDTEntry {
    GuestAddress functionAddress             = 0;
    uint32_t     serviceNumber               = 0;
    std::string  serviceName;
    bool         hooked                      = false;
    GuestAddress originalAddress             = 0;
};

struct SSDT {
    GuestAddress              baseAddress    = 0;
    uint32_t                  serviceCount   = 0;
    std::vector<SSDTEntry>    entries;
};

// ============================================================================
// IDT (Interrupt Descriptor Table)
// ============================================================================

struct IDTEntry {
    uint8_t      vector                      = 0;
    GuestAddress handler                     = 0;
    uint8_t      ist                         = 0;
    uint8_t      dpl                         = 0;
    bool         present                     = false;
    bool         hooked                      = false;
    GuestAddress originalHandler             = 0;
};

// ============================================================================
// DKOM Detection Result
// ============================================================================

struct DKOMDetection {
    enum class Type : uint8_t {
        ProcessUnlinked,
        ThreadUnlinked,
        DriverUnlinked,
        SSDTHooked,
        IDTHooked,
        TokenSwapped,
        CallbackRemoved
    };

    Type         type;
    std::string  description;
    uint32_t     targetPid  = 0;
    GuestAddress targetAddr = 0;
};

// ============================================================================
// Kernel Object Manager
// ============================================================================
// Manages emulated kernel objects (processes, threads, drivers) and
// system tables (SSDT, IDT).  Linked-list integrity invariants are
// maintained so that DKOM attacks (unlinking, hooking, token swaps)
// can be detected by cross-checking forward/backward traversals and
// snapshot comparisons.
//
// Thread-safe: shared_mutex protects all mutable state.
// Singleton: Meyers' singleton — one manager per emulation session.

class KernelObjectManager {
public:
    static KernelObjectManager& Instance();

    void Reset();
    bool Initialize(VirtualMemory& memory);

    // === Process management ===

    GuestAddress CreateProcess(uint32_t pid, uint32_t parentPid, const char* imageName);
    bool TerminateProcess(uint32_t pid);
    [[nodiscard]] std::optional<EmulatedEPROCESS> FindProcess(uint32_t pid) const;
    [[nodiscard]] std::vector<EmulatedEPROCESS> GetProcessList() const;
    [[nodiscard]] bool ValidateProcessList() const;

    // === Thread management ===

    GuestAddress CreateThread(uint32_t pid, uint32_t tid, GuestAddress startAddr);
    [[nodiscard]] std::optional<EmulatedKTHREAD> FindThread(uint32_t tid) const;

    // === Driver management ===

    GuestAddress LoadDriver(const char* name, GuestAddress base, uint32_t size);
    [[nodiscard]] std::optional<EmulatedDriverObject> FindDriver(const char* name) const;
    [[nodiscard]] std::vector<EmulatedDriverObject> GetDriverList() const;

    // === SSDT management ===

    void InitializeSSDT();
    [[nodiscard]] SSDT GetSSDT() const;
    bool HookSSDTEntry(uint32_t serviceNumber, GuestAddress newAddress);
    [[nodiscard]] std::vector<uint32_t> DetectSSDTHooks() const;

    // === IDT management ===

    void InitializeIDT();
    [[nodiscard]] std::vector<uint8_t> DetectIDTHooks() const;

    // === DKOM detection ===

    [[nodiscard]] std::vector<DKOMDetection> ScanForDKOM() const;

    // === Integrity verification ===

    [[nodiscard]] bool ValidateDriverIntegrity() const;
    [[nodiscard]] bool ValidateSSDTIntegrity() const;
    [[nodiscard]] uint32_t GetProcessCount() const;
    [[nodiscard]] uint32_t GetThreadCount() const;
    [[nodiscard]] uint32_t GetDriverCount() const;

private:
    KernelObjectManager();
    ~KernelObjectManager();

    KernelObjectManager(const KernelObjectManager&) = delete;
    KernelObjectManager& operator=(const KernelObjectManager&) = delete;
    KernelObjectManager(KernelObjectManager&&) = delete;
    KernelObjectManager& operator=(KernelObjectManager&&) = delete;

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
