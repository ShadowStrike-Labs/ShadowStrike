/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * KernelAPI.cpp — Kernel API emulation handlers for rootkit/driver analysis
 *
 * Each handler:
 *   1. Extracts arguments via APIContext (Win x64 ABI)
 *   2. Performs the emulated operation using KernelAddressSpace / KernelObjectManager
 *   3. Records the call in KernelAPITracker with suspicious-activity tagging
 *   4. Sets the return value in RAX (typically STATUS_SUCCESS = 0)
 *   5. Returns true (continue emulation)
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "KernelAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../HandleTable.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Core/Kernel/KernelStructures.hpp"
#include "../../Core/Kernel/KernelAddressSpace.hpp"
#include "../../Core/Kernel/DriverLoader.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <vector>

namespace Phantom::WinAPI::Kernel {

// ============================================================================
// Constants
// ============================================================================

static constexpr uint64_t kMaxKernelPoolAlloc       = 64ULL * 1024 * 1024; // 64 MB cap
static constexpr uint64_t kMaxContiguousAlloc       = 16ULL * 1024 * 1024; // 16 MB cap
static constexpr uint32_t kMaxCallRecords           = 256 * 1024;          // 256K ring
static constexpr uint32_t kFakeNextThreadId         = 0x1000;
static constexpr uint32_t kFakeCurrentPid           = 4;  // System process PID
static constexpr uint32_t kFakeCurrentTid           = 8;
static constexpr GuestAddress kFakeSSDTBase         = 0xFFFFF80010000000ULL;
static constexpr GuestAddress kFakeDeviceBase       = 0xFFFFF80500000000ULL;

// Emulated pool tag for internal bookkeeping
static constexpr uint32_t kDefaultPoolTag           = 0x74536453; // 'SdSt'

// ============================================================================
// KernelAPITracker::Impl
// ============================================================================

struct KernelAPITracker::Impl {
    mutable std::shared_mutex mutex;
    std::vector<KernelAPICallRecord> calls;
    uint32_t totalCalls             = 0;
    uint32_t suspiciousCalls        = 0;

    // Category counters
    uint32_t memoryAllocations      = 0;
    uint32_t processManipulations   = 0;
    uint32_t registryOperations     = 0;
    uint32_t fileOperations         = 0;
    uint32_t callbackRegistrations  = 0;
    uint32_t hookingAttempts        = 0;

    // Flags
    bool usesDirectSSDTAccess           = false;
    bool usesProcessAttach              = false;
    bool usesMmMapIoSpace               = false;
    bool usesDynamicImportResolution    = false;
    bool usesAPCInjection               = false;
    bool registersSecurityCallbacks     = false;

    std::vector<std::string> mitreTechniques;

    void AddMitreTechnique(const std::string& technique) {
        for (const auto& t : mitreTechniques) {
            if (t == technique) return;
        }
        mitreTechniques.push_back(technique);
    }
};

KernelAPITracker::KernelAPITracker()  : m_impl(std::make_unique<Impl>()) {}
KernelAPITracker::~KernelAPITracker() = default;

KernelAPITracker& KernelAPITracker::Instance() {
    static KernelAPITracker instance;
    return instance;
}

void KernelAPITracker::Reset() {
    std::unique_lock lock(m_impl->mutex);
    m_impl->calls.clear();
    m_impl->totalCalls             = 0;
    m_impl->suspiciousCalls        = 0;
    m_impl->memoryAllocations      = 0;
    m_impl->processManipulations   = 0;
    m_impl->registryOperations     = 0;
    m_impl->fileOperations         = 0;
    m_impl->callbackRegistrations  = 0;
    m_impl->hookingAttempts        = 0;
    m_impl->usesDirectSSDTAccess           = false;
    m_impl->usesProcessAttach              = false;
    m_impl->usesMmMapIoSpace               = false;
    m_impl->usesDynamicImportResolution    = false;
    m_impl->usesAPCInjection               = false;
    m_impl->registersSecurityCallbacks     = false;
    m_impl->mitreTechniques.clear();
}

void KernelAPITracker::RecordCall(const KernelAPICallRecord& record) {
    std::unique_lock lock(m_impl->mutex);
    if (m_impl->calls.size() < kMaxCallRecords) {
        m_impl->calls.push_back(record);
    }
    ++m_impl->totalCalls;
    if (record.isSuspicious) {
        ++m_impl->suspiciousCalls;
    }
}

void KernelAPITracker::IncrementMemoryAllocations() {
    std::unique_lock lock(m_impl->mutex);
    ++m_impl->memoryAllocations;
}
void KernelAPITracker::IncrementProcessManipulations() {
    std::unique_lock lock(m_impl->mutex);
    ++m_impl->processManipulations;
}
void KernelAPITracker::IncrementRegistryOperations() {
    std::unique_lock lock(m_impl->mutex);
    ++m_impl->registryOperations;
}
void KernelAPITracker::IncrementFileOperations() {
    std::unique_lock lock(m_impl->mutex);
    ++m_impl->fileOperations;
}
void KernelAPITracker::IncrementCallbackRegistrations() {
    std::unique_lock lock(m_impl->mutex);
    ++m_impl->callbackRegistrations;
}
void KernelAPITracker::IncrementHookingAttempts() {
    std::unique_lock lock(m_impl->mutex);
    ++m_impl->hookingAttempts;
}
void KernelAPITracker::FlagDirectSSDTAccess() {
    std::unique_lock lock(m_impl->mutex);
    m_impl->usesDirectSSDTAccess = true;
}
void KernelAPITracker::FlagProcessAttach() {
    std::unique_lock lock(m_impl->mutex);
    m_impl->usesProcessAttach = true;
}
void KernelAPITracker::FlagMmMapIoSpace() {
    std::unique_lock lock(m_impl->mutex);
    m_impl->usesMmMapIoSpace = true;
}
void KernelAPITracker::FlagDynamicImportResolution() {
    std::unique_lock lock(m_impl->mutex);
    m_impl->usesDynamicImportResolution = true;
}
void KernelAPITracker::FlagAPCInjection() {
    std::unique_lock lock(m_impl->mutex);
    m_impl->usesAPCInjection = true;
}
void KernelAPITracker::FlagSecurityCallbacks() {
    std::unique_lock lock(m_impl->mutex);
    m_impl->registersSecurityCallbacks = true;
}
void KernelAPITracker::AddMitreTechnique(const std::string& technique) {
    std::unique_lock lock(m_impl->mutex);
    m_impl->AddMitreTechnique(technique);
}

KernelAPIReport KernelAPITracker::GenerateReport() const {
    std::shared_lock lock(m_impl->mutex);
    KernelAPIReport report;
    report.calls                        = m_impl->calls;
    report.totalCalls                   = m_impl->totalCalls;
    report.suspiciousCalls              = m_impl->suspiciousCalls;
    report.memoryAllocations            = m_impl->memoryAllocations;
    report.processManipulations         = m_impl->processManipulations;
    report.registryOperations           = m_impl->registryOperations;
    report.fileOperations               = m_impl->fileOperations;
    report.callbackRegistrations        = m_impl->callbackRegistrations;
    report.hookingAttempts              = m_impl->hookingAttempts;
    report.usesDirectSSDTAccess         = m_impl->usesDirectSSDTAccess;
    report.usesProcessAttach            = m_impl->usesProcessAttach;
    report.usesMmMapIoSpace             = m_impl->usesMmMapIoSpace;
    report.usesDynamicImportResolution  = m_impl->usesDynamicImportResolution;
    report.usesAPCInjection             = m_impl->usesAPCInjection;
    report.registersSecurityCallbacks   = m_impl->registersSecurityCallbacks;
    report.mitreTechniques              = m_impl->mitreTechniques;
    return report;
}

uint32_t KernelAPITracker::GetCallCount() const {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->totalCalls;
}

bool KernelAPITracker::HasSuspiciousActivity() const {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->suspiciousCalls > 0;
}

// ============================================================================
// Tracker helpers (file-local)
// ============================================================================

static void RecordSimpleCall(const char* api, const char* module,
                             uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                             uint64_t retVal,
                             bool suspicious = false,
                             const char* reason = nullptr) {
    KernelAPICallRecord rec;
    rec.apiName     = api;
    rec.moduleName  = module;
    rec.arg1        = a1;
    rec.arg2        = a2;
    rec.arg3        = a3;
    rec.arg4        = a4;
    rec.returnValue = retVal;
    rec.timestamp   = 0; // filled by caller if needed
    rec.isSuspicious    = suspicious;
    if (reason) rec.suspiciousReason = reason;
    KernelAPITracker::Instance().RecordCall(rec);
}

static KernelAPITracker& Tracker() {
    return KernelAPITracker::Instance();
}

// Monotonic device address allocator for IoCreateDevice
static std::atomic<uint64_t> s_nextDeviceAddr{ kFakeDeviceBase };
static std::atomic<uint32_t> s_nextKernelThreadId{ kFakeNextThreadId };

// ============================================================================
// Memory Management Handlers
// ============================================================================

// ExAllocatePoolWithTag(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag)
static bool HandleExAllocatePoolWithTag(APIContext& ctx) {
    const auto poolType     = ctx.GetArg32(0);
    const auto numBytes     = ctx.GetArg(1);
    const auto tag          = ctx.GetArg32(2);

    Tracker().IncrementMemoryAllocations();

    if (numBytes == 0 || numBytes > kMaxKernelPoolAlloc) {
        ctx.SetReturn(0); // NULL = allocation failure
        RecordSimpleCall("ExAllocatePoolWithTag", "ntoskrnl.exe",
                         poolType, numBytes, tag, 0, 0);
        return true;
    }

    PoolType pt = (poolType & 1) ? PoolType::PagedPool : PoolType::NonPagedPool;
    auto result = KernelAddressSpace::Instance().AllocatePool(pt, numBytes, tag);

    uint64_t retAddr = result.has_value() ? result.value() : 0;
    ctx.SetReturn(retAddr);
    RecordSimpleCall("ExAllocatePoolWithTag", "ntoskrnl.exe",
                     poolType, numBytes, tag, 0, retAddr);
    return true;
}

// ExAllocatePool(POOL_TYPE PoolType, SIZE_T NumberOfBytes)
static bool HandleExAllocatePool(APIContext& ctx) {
    const auto poolType = ctx.GetArg32(0);
    const auto numBytes = ctx.GetArg(1);

    Tracker().IncrementMemoryAllocations();

    if (numBytes == 0 || numBytes > kMaxKernelPoolAlloc) {
        ctx.SetReturn(0);
        RecordSimpleCall("ExAllocatePool", "ntoskrnl.exe",
                         poolType, numBytes, 0, 0, 0);
        return true;
    }

    PoolType pt = (poolType & 1) ? PoolType::PagedPool : PoolType::NonPagedPool;
    auto result = KernelAddressSpace::Instance().AllocatePool(pt, numBytes, kDefaultPoolTag);

    uint64_t retAddr = result.has_value() ? result.value() : 0;
    ctx.SetReturn(retAddr);
    RecordSimpleCall("ExAllocatePool", "ntoskrnl.exe",
                     poolType, numBytes, 0, 0, retAddr);
    return true;
}

// ExFreePoolWithTag(PVOID P, ULONG Tag)
static bool HandleExFreePoolWithTag(APIContext& ctx) {
    const auto ptr = ctx.GetArgPtr(0);
    const auto tag = ctx.GetArg32(1);

    if (ptr != 0) {
        KernelAddressSpace::Instance().FreePool(ptr);
    }

    ctx.SetReturn(0); // void return
    RecordSimpleCall("ExFreePoolWithTag", "ntoskrnl.exe", ptr, tag, 0, 0, 0);
    return true;
}

// ExFreePool(PVOID P)
static bool HandleExFreePool(APIContext& ctx) {
    const auto ptr = ctx.GetArgPtr(0);

    if (ptr != 0) {
        KernelAddressSpace::Instance().FreePool(ptr);
    }

    ctx.SetReturn(0);
    RecordSimpleCall("ExFreePool", "ntoskrnl.exe", ptr, 0, 0, 0, 0);
    return true;
}

// MmAllocateContiguousMemory(SIZE_T NumberOfBytes, PHYSICAL_ADDRESS HighestAcceptable)
static bool HandleMmAllocateContiguousMemory(APIContext& ctx) {
    const auto numBytes = ctx.GetArg(0);

    Tracker().IncrementMemoryAllocations();

    bool suspicious = true;
    RecordSimpleCall("MmAllocateContiguousMemory", "ntoskrnl.exe",
                     numBytes, 0, 0, 0, 0, suspicious,
                     "Contiguous physical memory allocation — potential DMA attack vector");
    Tracker().AddMitreTechnique("T1014");  // Rootkit

    if (numBytes == 0 || numBytes > kMaxContiguousAlloc) {
        ctx.SetReturn(0);
        return true;
    }

    auto result = KernelAddressSpace::Instance().AllocatePool(
        PoolType::NonPagedPool, numBytes, kDefaultPoolTag);
    uint64_t retAddr = result.has_value() ? result.value() : 0;
    ctx.SetReturn(retAddr);
    return true;
}

// MmMapIoSpace(PHYSICAL_ADDRESS PhysAddr, SIZE_T NumberOfBytes, MEMORY_CACHING_TYPE CacheType)
static bool HandleMmMapIoSpace(APIContext& ctx) {
    const auto physAddr = ctx.GetArg(0);
    const auto numBytes = ctx.GetArg(1);

    Tracker().IncrementMemoryAllocations();
    Tracker().FlagMmMapIoSpace();

    RecordSimpleCall("MmMapIoSpace", "ntoskrnl.exe",
                     physAddr, numBytes, 0, 0, 0, true,
                     "Physical memory mapping — MMIO rootkit indicator");
    Tracker().AddMitreTechnique("T1014");  // Rootkit
    Tracker().AddMitreTechnique("T1542");  // Pre-OS Boot

    if (numBytes == 0 || numBytes > kMaxContiguousAlloc) {
        ctx.SetReturn(0);
        return true;
    }

    auto result = KernelAddressSpace::Instance().AllocatePool(
        PoolType::NonPagedPool, numBytes, kDefaultPoolTag);
    uint64_t retAddr = result.has_value() ? result.value() : 0;
    ctx.SetReturn(retAddr);
    return true;
}

// MmGetSystemRoutineAddress(PUNICODE_STRING SystemRoutineName)
static bool HandleMmGetSystemRoutineAddress(APIContext& ctx) {
    const auto namePtr = ctx.GetArgPtr(0);

    Tracker().FlagDynamicImportResolution();
    Tracker().IncrementHookingAttempts();

    std::wstring routineName;
    if (namePtr != 0) {
        routineName = ctx.ReadUnicodeString(namePtr);
    }

    RecordSimpleCall("MmGetSystemRoutineAddress", "ntoskrnl.exe",
                     namePtr, 0, 0, 0, 0, true,
                     "Dynamic kernel API resolution — evasion/hooking indicator");
    Tracker().AddMitreTechnique("T1014");  // Rootkit
    Tracker().AddMitreTechnique("T1562");  // Impair Defenses

    // Return a non-zero fake address so the driver proceeds
    GuestAddress fakeAddr = kFakeSSDTBase + 0x100000;
    ctx.SetReturn(fakeAddr);
    return true;
}

// ============================================================================
// Process / Thread Manipulation Handlers
// ============================================================================

// PsCreateSystemThread(PHANDLE ThreadHandle, ULONG DesiredAccess,
//   POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
//   PCLIENT_ID ClientId, PKSTART_ROUTINE StartRoutine, PVOID StartContext)
static bool HandlePsCreateSystemThread(APIContext& ctx) {
    const auto threadHandlePtr = ctx.GetArgPtr(0);
    const auto startRoutine    = ctx.GetArgPtr(5);

    Tracker().IncrementProcessManipulations();

    uint32_t newTid = s_nextKernelThreadId.fetch_add(1);
    (void)KernelObjectManager::Instance().CreateThread(
        kFakeCurrentPid, newTid, startRoutine);

    GuestHandle gh = ctx.Handles().Create(HandleType::Thread,
        ThreadHandleData{ newTid, kFakeCurrentPid, NT::THREAD_ALL_ACCESS, false });

    if (threadHandlePtr != 0) {
        (void)ctx.Memory().WriteU64(threadHandlePtr, gh);
    }

    RecordSimpleCall("PsCreateSystemThread", "ntoskrnl.exe",
                     threadHandlePtr, startRoutine, 0, 0,
                     static_cast<uint64_t>(NT::STATUS_SUCCESS));

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// PsTerminateSystemThread(NTSTATUS ExitStatus)
static bool HandlePsTerminateSystemThread(APIContext& ctx) {
    const auto exitStatus = ctx.GetArg32(0);

    Tracker().IncrementProcessManipulations();
    RecordSimpleCall("PsTerminateSystemThread", "ntoskrnl.exe",
                     exitStatus, 0, 0, 0,
                     static_cast<uint64_t>(NT::STATUS_SUCCESS));

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// PsGetCurrentProcessId() → HANDLE (PID)
static bool HandlePsGetCurrentProcessId(APIContext& ctx) {
    ctx.SetReturn(kFakeCurrentPid);
    RecordSimpleCall("PsGetCurrentProcessId", "ntoskrnl.exe",
                     0, 0, 0, 0, kFakeCurrentPid);
    return true;
}

// PsGetCurrentThreadId() → HANDLE (TID)
static bool HandlePsGetCurrentThreadId(APIContext& ctx) {
    ctx.SetReturn(kFakeCurrentTid);
    RecordSimpleCall("PsGetCurrentThreadId", "ntoskrnl.exe",
                     0, 0, 0, 0, kFakeCurrentTid);
    return true;
}

// PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *Process)
static bool HandlePsLookupProcessByProcessId(APIContext& ctx) {
    const auto pid       = ctx.GetArg32(0);
    const auto outPtr    = ctx.GetArgPtr(1);

    Tracker().IncrementProcessManipulations();

    const auto eproc = KernelObjectManager::Instance().FindProcess(pid);
    if (eproc && outPtr != 0) {
        (void)ctx.Memory().WriteU64(outPtr, eproc->selfPtr);
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    } else if (outPtr != 0) {
        (void)ctx.Memory().WriteU64(outPtr, 0);
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
    } else {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
    }

    RecordSimpleCall("PsLookupProcessByProcessId", "ntoskrnl.exe",
                     pid, outPtr, 0, 0,
                     static_cast<uint64_t>(ctx.CPU().RAX()));
    return true;
}

// PsLookupThreadByThreadId(HANDLE ThreadId, PKTHREAD *Thread)
static bool HandlePsLookupThreadByThreadId(APIContext& ctx) {
    const auto tid    = ctx.GetArg32(0);
    const auto outPtr = ctx.GetArgPtr(1);

    Tracker().IncrementProcessManipulations();

    const auto kthread = KernelObjectManager::Instance().FindThread(tid);
    if (kthread && outPtr != 0) {
        (void)ctx.Memory().WriteU64(outPtr, kthread->selfPtr);
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    } else if (outPtr != 0) {
        (void)ctx.Memory().WriteU64(outPtr, 0);
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
    } else {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
    }

    RecordSimpleCall("PsLookupThreadByThreadId", "ntoskrnl.exe",
                     tid, outPtr, 0, 0,
                     static_cast<uint64_t>(ctx.CPU().RAX()));
    return true;
}

// KeAttachProcess(PRKPROCESS Process)
static bool HandleKeAttachProcess(APIContext& ctx) {
    const auto processPtr = ctx.GetArgPtr(0);

    Tracker().IncrementProcessManipulations();
    Tracker().FlagProcessAttach();

    RecordSimpleCall("KeAttachProcess", "ntoskrnl.exe",
                     processPtr, 0, 0, 0, 0, true,
                     "Process address-space attach — injection/manipulation indicator");
    Tracker().AddMitreTechnique("T1055");  // Process Injection

    ctx.SetReturn(0); // void
    return true;
}

// KeDetachProcess()
static bool HandleKeDetachProcess(APIContext& ctx) {
    RecordSimpleCall("KeDetachProcess", "ntoskrnl.exe", 0, 0, 0, 0, 0);
    ctx.SetReturn(0);
    return true;
}

// KeStackAttachProcess(PRKPROCESS Process, PRKAPC_STATE ApcState)
static bool HandleKeStackAttachProcess(APIContext& ctx) {
    const auto processPtr = ctx.GetArgPtr(0);
    const auto apcState   = ctx.GetArgPtr(1);

    Tracker().IncrementProcessManipulations();
    Tracker().FlagProcessAttach();

    RecordSimpleCall("KeStackAttachProcess", "ntoskrnl.exe",
                     processPtr, apcState, 0, 0, 0, true,
                     "Stack-based process attach — injection indicator");
    Tracker().AddMitreTechnique("T1055");  // Process Injection

    ctx.SetReturn(0); // void
    return true;
}

// KeUnstackDetachProcess(PRKAPC_STATE ApcState)
static bool HandleKeUnstackDetachProcess(APIContext& ctx) {
    const auto apcState = ctx.GetArgPtr(0);
    RecordSimpleCall("KeUnstackDetachProcess", "ntoskrnl.exe",
                     apcState, 0, 0, 0, 0);
    ctx.SetReturn(0);
    return true;
}

// ============================================================================
// Object Manager Handlers
// ============================================================================

// ObReferenceObjectByHandle(HANDLE Handle, ACCESS_MASK DesiredAccess,
//   POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode,
//   PVOID *Object, POBJECT_HANDLE_INFORMATION HandleInformation)
static bool HandleObReferenceObjectByHandle(APIContext& ctx) {
    const auto handle = ctx.GetArg(0);
    const auto outPtr = ctx.GetArgPtr(4);

    // Return a fake kernel object pointer
    if (outPtr != 0) {
        (void)ctx.Memory().WriteU64(outPtr, kFakeSSDTBase + 0x200000 + (handle & 0xFFFF) * 0x100);
    }
    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);

    RecordSimpleCall("ObReferenceObjectByHandle", "ntoskrnl.exe",
                     handle, 0, 0, 0,
                     static_cast<uint64_t>(NT::STATUS_SUCCESS));
    return true;
}

// ObDereferenceObject(PVOID Object) — void
static bool HandleObDereferenceObject(APIContext& ctx) {
    const auto objPtr = ctx.GetArgPtr(0);
    RecordSimpleCall("ObDereferenceObject", "ntoskrnl.exe", objPtr, 0, 0, 0, 0);
    ctx.SetReturn(0);
    return true;
}

// ObOpenObjectByPointer(PVOID Object, ULONG HandleAttributes,
//   PACCESS_STATE PassedAccessState, ACCESS_MASK DesiredAccess,
//   POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PHANDLE Handle)
static bool HandleObOpenObjectByPointer(APIContext& ctx) {
    const auto objPtr    = ctx.GetArgPtr(0);
    const auto handlePtr = ctx.GetArgPtr(6);

    RecordSimpleCall("ObOpenObjectByPointer", "ntoskrnl.exe",
                     objPtr, 0, 0, 0,
                     static_cast<uint64_t>(NT::STATUS_SUCCESS), true,
                     "Object-to-handle conversion — privilege escalation vector");
    Tracker().AddMitreTechnique("T1068");  // Exploitation for Privilege Escalation

    if (handlePtr != 0) {
        GuestHandle gh = ctx.Handles().Create(HandleType::Process,
            ProcessHandleData{ kFakeCurrentPid, NT::PROCESS_ALL_ACCESS, false, 0 });
        (void)ctx.Memory().WriteU64(handlePtr, gh);
    }

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// Registry Handlers (Zw*)
// ============================================================================

// ZwCreateKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
//   POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex,
//   PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition)
static bool HandleZwCreateKey(APIContext& ctx) {
    const auto keyHandlePtr = ctx.GetArgPtr(0);
    const auto objAttrPtr   = ctx.GetArgPtr(2);

    Tracker().IncrementRegistryOperations();

    GuestHandle gh = ctx.Handles().Create(HandleType::RegistryKey,
        RegistryKeyHandleData{ L"\\Registry\\Machine\\SYSTEM", 0, false });

    if (keyHandlePtr != 0) {
        (void)ctx.Memory().WriteU64(keyHandlePtr, gh);
    }

    RecordSimpleCall("ZwCreateKey", "ntoskrnl.exe",
                     keyHandlePtr, objAttrPtr, 0, 0,
                     static_cast<uint64_t>(NT::STATUS_SUCCESS));
    Tracker().AddMitreTechnique("T1547");  // Boot or Logon Autostart Execution (persistence)

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ZwOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
static bool HandleZwOpenKey(APIContext& ctx) {
    const auto keyHandlePtr = ctx.GetArgPtr(0);
    const auto objAttrPtr   = ctx.GetArgPtr(2);

    Tracker().IncrementRegistryOperations();

    GuestHandle gh = ctx.Handles().Create(HandleType::RegistryKey,
        RegistryKeyHandleData{ L"\\Registry\\Machine\\SYSTEM", 0, false });

    if (keyHandlePtr != 0) {
        (void)ctx.Memory().WriteU64(keyHandlePtr, gh);
    }

    RecordSimpleCall("ZwOpenKey", "ntoskrnl.exe",
                     keyHandlePtr, objAttrPtr, 0, 0,
                     static_cast<uint64_t>(NT::STATUS_SUCCESS));

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ZwSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex,
//               ULONG Type, PVOID Data, ULONG DataSize)
static bool HandleZwSetValueKey(APIContext& ctx) {
    const auto keyHandle = ctx.GetArg(0);
    const auto valueType = ctx.GetArg32(3);

    Tracker().IncrementRegistryOperations();

    RecordSimpleCall("ZwSetValueKey", "ntoskrnl.exe",
                     keyHandle, 0, 0, valueType,
                     static_cast<uint64_t>(NT::STATUS_SUCCESS), true,
                     "Kernel-mode registry write — persistence indicator");
    Tracker().AddMitreTechnique("T1547");  // Boot or Logon Autostart Execution
    Tracker().AddMitreTechnique("T1112");  // Modify Registry

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ZwQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName,
//   KEY_VALUE_INFORMATION_CLASS KeyValueInfoClass, PVOID KeyValueInfo,
//   ULONG Length, PULONG ResultLength)
static bool HandleZwQueryValueKey(APIContext& ctx) {
    const auto keyHandle    = ctx.GetArg(0);
    const auto resultLenPtr = ctx.GetArgPtr(5);

    Tracker().IncrementRegistryOperations();

    if (resultLenPtr != 0) {
        (void)ctx.Memory().WriteU32(resultLenPtr, 0);
    }

    RecordSimpleCall("ZwQueryValueKey", "ntoskrnl.exe",
                     keyHandle, 0, 0, 0,
                     static_cast<uint64_t>(NT::STATUS_OBJECT_NAME_NOT_FOUND));

    ctx.SetReturnNtStatus(NT::STATUS_OBJECT_NAME_NOT_FOUND);
    return true;
}

// ZwDeleteKey(HANDLE KeyHandle)
static bool HandleZwDeleteKey(APIContext& ctx) {
    const auto keyHandle = ctx.GetArg(0);

    Tracker().IncrementRegistryOperations();

    RecordSimpleCall("ZwDeleteKey", "ntoskrnl.exe",
                     keyHandle, 0, 0, 0,
                     static_cast<uint64_t>(NT::STATUS_SUCCESS), true,
                     "Kernel-mode registry deletion — anti-forensics indicator");
    Tracker().AddMitreTechnique("T1070");  // Indicator Removal

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// File System Handlers (Zw*)
// ============================================================================

// ZwCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
//   POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
//   PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
//   ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
//   PVOID EaBuffer, ULONG EaLength)
static bool HandleZwCreateFile(APIContext& ctx) {
    const auto fileHandlePtr = ctx.GetArgPtr(0);
    const auto accessMask    = ctx.GetArg32(1);

    Tracker().IncrementFileOperations();

    GuestHandle gh = ctx.Handles().Create(HandleType::File,
        FileHandleData{ L"\\Device\\HarddiskVolume1\\", accessMask, 0, 0, 0, false, false });

    if (fileHandlePtr != 0) {
        (void)ctx.Memory().WriteU64(fileHandlePtr, gh);
    }

    RecordSimpleCall("ZwCreateFile", "ntoskrnl.exe",
                     fileHandlePtr, accessMask, 0, 0,
                     static_cast<uint64_t>(NT::STATUS_SUCCESS));

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ZwReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
//   PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
//   ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
static bool HandleZwReadFile(APIContext& ctx) {
    const auto fileHandle = ctx.GetArg(0);
    const auto length     = ctx.GetArg32(6);

    Tracker().IncrementFileOperations();

    RecordSimpleCall("ZwReadFile", "ntoskrnl.exe",
                     fileHandle, length, 0, 0,
                     static_cast<uint64_t>(NT::STATUS_END_OF_FILE));

    ctx.SetReturnNtStatus(NT::STATUS_END_OF_FILE);
    return true;
}

// ZwWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
//   PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
//   ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
static bool HandleZwWriteFile(APIContext& ctx) {
    const auto fileHandle = ctx.GetArg(0);
    const auto length     = ctx.GetArg32(6);

    Tracker().IncrementFileOperations();

    RecordSimpleCall("ZwWriteFile", "ntoskrnl.exe",
                     fileHandle, length, 0, 0,
                     static_cast<uint64_t>(NT::STATUS_SUCCESS));

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ZwClose(HANDLE Handle)
static bool HandleZwClose(APIContext& ctx) {
    const auto handle = ctx.GetArg(0);

    (void)ctx.Handles().Close(handle);

    RecordSimpleCall("ZwClose", "ntoskrnl.exe",
                     handle, 0, 0, 0,
                     static_cast<uint64_t>(NT::STATUS_SUCCESS));

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ZwQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock,
//   PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInfoClass)
static bool HandleZwQueryInformationFile(APIContext& ctx) {
    const auto fileHandle = ctx.GetArg(0);

    Tracker().IncrementFileOperations();

    RecordSimpleCall("ZwQueryInformationFile", "ntoskrnl.exe",
                     fileHandle, 0, 0, 0,
                     static_cast<uint64_t>(NT::STATUS_SUCCESS));

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// System Info / Hooking / Device Handlers
// ============================================================================

// KeServiceDescriptorTable — global SSDT pointer access
static bool HandleKeServiceDescriptorTable(APIContext& ctx) {
    Tracker().FlagDirectSSDTAccess();
    Tracker().IncrementHookingAttempts();

    const auto& ssdt = KernelObjectManager::Instance().GetSSDT();
    GuestAddress ssdtAddr = ssdt.baseAddress;
    if (ssdtAddr == 0) ssdtAddr = kFakeSSDTBase;

    ctx.SetReturn(ssdtAddr);

    RecordSimpleCall("KeServiceDescriptorTable", "ntoskrnl.exe",
                     0, 0, 0, 0, ssdtAddr, true,
                     "Direct SSDT access — rootkit hooking technique");
    Tracker().AddMitreTechnique("T1014");  // Rootkit
    Tracker().AddMitreTechnique("T1562");  // Impair Defenses

    return true;
}

// IoCreateDevice(PDRIVER_OBJECT DriverObject, ULONG DeviceExtensionSize,
//   PUNICODE_STRING DeviceName, DEVICE_TYPE DeviceType,
//   ULONG DeviceCharacteristics, BOOLEAN Exclusive, PDEVICE_OBJECT *DeviceObject)
static bool HandleIoCreateDevice(APIContext& ctx) {
    const auto driverObjPtr  = ctx.GetArgPtr(0);
    const auto extSize       = ctx.GetArg32(1);
    const auto deviceObjPtr  = ctx.GetArgPtr(6);

    GuestAddress devAddr = s_nextDeviceAddr.fetch_add(kPageSize);
    if (deviceObjPtr != 0) {
        (void)ctx.Memory().WriteU64(deviceObjPtr, devAddr);
    }

    RecordSimpleCall("IoCreateDevice", "ntoskrnl.exe",
                     driverObjPtr, extSize, 0, 0,
                     static_cast<uint64_t>(NT::STATUS_SUCCESS));

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// IoDeleteDevice(PDEVICE_OBJECT DeviceObject)
static bool HandleIoDeleteDevice(APIContext& ctx) {
    const auto devObjPtr = ctx.GetArgPtr(0);

    RecordSimpleCall("IoDeleteDevice", "ntoskrnl.exe",
                     devObjPtr, 0, 0, 0, 0);

    ctx.SetReturn(0); // void
    return true;
}

// IoCreateSymbolicLink(PUNICODE_STRING SymbolicLinkName, PUNICODE_STRING DeviceName)
static bool HandleIoCreateSymbolicLink(APIContext& ctx) {
    const auto symlinkName = ctx.GetArgPtr(0);
    const auto deviceName  = ctx.GetArgPtr(1);

    RecordSimpleCall("IoCreateSymbolicLink", "ntoskrnl.exe",
                     symlinkName, deviceName, 0, 0,
                     static_cast<uint64_t>(NT::STATUS_SUCCESS));

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString)
static bool HandleRtlInitUnicodeString(APIContext& ctx) {
    const auto destPtr = ctx.GetArgPtr(0);
    const auto srcPtr  = ctx.GetArgPtr(1);

    // UNICODE_STRING layout: { USHORT Length; USHORT MaxLength; PWSTR Buffer; }
    if (destPtr != 0 && srcPtr != 0) {
        auto& mem = ctx.Memory();
        std::wstring str = ctx.ReadWideString(srcPtr);
        uint16_t byteLen = static_cast<uint16_t>(
            std::min<size_t>(str.size() * 2, 0xFFFE));
        uint16_t maxLen  = byteLen + 2;

        (void)mem.WriteU16(destPtr, byteLen);
        (void)mem.WriteU16(destPtr + 2, maxLen);
        // Padding at +4..+7 for alignment on x64
        (void)mem.WriteU64(destPtr + 8, srcPtr); // Buffer points to original string
    } else if (destPtr != 0) {
        auto& mem = ctx.Memory();
        (void)mem.WriteU16(destPtr, 0);
        (void)mem.WriteU16(destPtr + 2, 0);
        (void)mem.WriteU64(destPtr + 8, 0);
    }

    RecordSimpleCall("RtlInitUnicodeString", "ntoskrnl.exe",
                     destPtr, srcPtr, 0, 0, 0);
    ctx.SetReturn(0); // void
    return true;
}

// DbgPrint(PCSTR Format, ...) — debug output (informational)
static bool HandleDbgPrint(APIContext& ctx) {
    const auto fmtPtr = ctx.GetArgPtr(0);

    RecordSimpleCall("DbgPrint", "ntoskrnl.exe",
                     fmtPtr, 0, 0, 0,
                     static_cast<uint64_t>(NT::STATUS_SUCCESS));

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// Callback Registration Handlers
// ============================================================================

// PsSetCreateProcessNotifyRoutineEx(PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine, BOOLEAN Remove)
static bool HandlePsSetCreateProcessNotifyRoutineEx(APIContext& ctx) {
    const auto notifyRoutine = ctx.GetArgPtr(0);
    const auto remove        = ctx.GetArg32(1);

    Tracker().IncrementCallbackRegistrations();
    Tracker().FlagSecurityCallbacks();

    RecordSimpleCall("PsSetCreateProcessNotifyRoutineEx", "ntoskrnl.exe",
                     notifyRoutine, remove, 0, 0,
                     static_cast<uint64_t>(NT::STATUS_SUCCESS));
    Tracker().AddMitreTechnique("T1543");  // Create or Modify System Process

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// PsSetCreateThreadNotifyRoutine(PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine)
static bool HandlePsSetCreateThreadNotifyRoutine(APIContext& ctx) {
    const auto notifyRoutine = ctx.GetArgPtr(0);

    Tracker().IncrementCallbackRegistrations();
    Tracker().FlagSecurityCallbacks();

    RecordSimpleCall("PsSetCreateThreadNotifyRoutine", "ntoskrnl.exe",
                     notifyRoutine, 0, 0, 0,
                     static_cast<uint64_t>(NT::STATUS_SUCCESS));

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// PsSetLoadImageNotifyRoutine(PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine)
static bool HandlePsSetLoadImageNotifyRoutine(APIContext& ctx) {
    const auto notifyRoutine = ctx.GetArgPtr(0);

    Tracker().IncrementCallbackRegistrations();
    Tracker().FlagSecurityCallbacks();

    RecordSimpleCall("PsSetLoadImageNotifyRoutine", "ntoskrnl.exe",
                     notifyRoutine, 0, 0, 0,
                     static_cast<uint64_t>(NT::STATUS_SUCCESS));

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// CmRegisterCallbackEx(PEX_CALLBACK_FUNCTION Function, PUNICODE_STRING Altitude,
//   PVOID Driver, PVOID Context, PLARGE_INTEGER Cookie, PVOID Reserved)
static bool HandleCmRegisterCallbackEx(APIContext& ctx) {
    const auto callbackFn = ctx.GetArgPtr(0);

    Tracker().IncrementCallbackRegistrations();
    Tracker().FlagSecurityCallbacks();

    RecordSimpleCall("CmRegisterCallbackEx", "ntoskrnl.exe",
                     callbackFn, 0, 0, 0,
                     static_cast<uint64_t>(NT::STATUS_SUCCESS));
    Tracker().AddMitreTechnique("T1112");  // Modify Registry

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ObRegisterCallbacks(POB_CALLBACK_REGISTRATION CallbackRegistration, PVOID *RegistrationHandle)
static bool HandleObRegisterCallbacks(APIContext& ctx) {
    const auto regPtr    = ctx.GetArgPtr(0);
    const auto handlePtr = ctx.GetArgPtr(1);

    Tracker().IncrementCallbackRegistrations();
    Tracker().FlagSecurityCallbacks();

    if (handlePtr != 0) {
        (void)ctx.Memory().WriteU64(handlePtr, kFakeSSDTBase + 0x300000);
    }

    RecordSimpleCall("ObRegisterCallbacks", "ntoskrnl.exe",
                     regPtr, handlePtr, 0, 0,
                     static_cast<uint64_t>(NT::STATUS_SUCCESS));
    Tracker().AddMitreTechnique("T1562");  // Impair Defenses

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// Suspicious / Rootkit-Specific Handlers
// ============================================================================

// KeInsertQueueApc(PRKAPC Apc, PVOID SystemArgument1, PVOID SystemArgument2)
static bool HandleKeInsertQueueApc(APIContext& ctx) {
    const auto apcPtr  = ctx.GetArgPtr(0);
    const auto sysArg1 = ctx.GetArgPtr(1);
    const auto sysArg2 = ctx.GetArgPtr(2);

    Tracker().IncrementProcessManipulations();
    Tracker().FlagAPCInjection();

    RecordSimpleCall("KeInsertQueueApc", "ntoskrnl.exe",
                     apcPtr, sysArg1, sysArg2, 0, 1, true,
                     "APC injection — code injection technique");
    Tracker().AddMitreTechnique("T1055.004");  // Asynchronous Procedure Call

    ctx.SetReturn(1); // TRUE = success
    return true;
}

// MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress,
//   PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize,
//   KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize)
static bool HandleMmCopyVirtualMemory(APIContext& ctx) {
    const auto srcProcess = ctx.GetArgPtr(0);
    const auto srcAddr    = ctx.GetArgPtr(1);
    const auto dstProcess = ctx.GetArgPtr(2);
    const auto dstAddr    = ctx.GetArgPtr(3);

    Tracker().IncrementProcessManipulations();

    RecordSimpleCall("MmCopyVirtualMemory", "ntoskrnl.exe",
                     srcProcess, srcAddr, dstProcess, dstAddr,
                     static_cast<uint64_t>(NT::STATUS_SUCCESS), true,
                     "Cross-process memory copy — process injection vector");
    Tracker().AddMitreTechnique("T1055");  // Process Injection

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
//   PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect)
static bool HandleZwProtectVirtualMemory(APIContext& ctx) {
    const auto processHandle = ctx.GetArg(0);
    const auto newProtect    = ctx.GetArg32(3);

    Tracker().IncrementProcessManipulations();

    bool suspicious = (newProtect == NT::PAGE_EXECUTE_READWRITE);

    RecordSimpleCall("ZwProtectVirtualMemory", "ntoskrnl.exe",
                     processHandle, 0, 0, newProtect,
                     static_cast<uint64_t>(NT::STATUS_SUCCESS), suspicious,
                     suspicious ? "RWX memory protection from kernel — code injection indicator"
                                : nullptr);
    if (suspicious) {
        Tracker().AddMitreTechnique("T1055");  // Process Injection
    }

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ZwAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
//   ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
static bool HandleZwAllocateVirtualMemory(APIContext& ctx) {
    const auto processHandle = ctx.GetArg(0);
    const auto baseAddrPtr   = ctx.GetArgPtr(1);
    const auto regionSizePtr = ctx.GetArgPtr(3);
    const auto protect       = ctx.GetArg32(5);

    Tracker().IncrementProcessManipulations();

    bool suspicious = (protect == NT::PAGE_EXECUTE_READWRITE);

    RecordSimpleCall("ZwAllocateVirtualMemory", "ntoskrnl.exe",
                     processHandle, baseAddrPtr, regionSizePtr, protect,
                     static_cast<uint64_t>(NT::STATUS_SUCCESS), suspicious,
                     suspicious ? "Kernel-mode RWX user-space allocation — injection vector"
                                : nullptr);
    if (suspicious) {
        Tracker().AddMitreTechnique("T1055");  // Process Injection
    }

    // Allocate a small region in pool space as a stand-in
    if (regionSizePtr != 0) {
        uint64_t reqSize = 0;
        (void)ctx.Memory().ReadU64(regionSizePtr, reqSize);
        if (reqSize == 0) reqSize = kPageSize;
        reqSize = std::min<uint64_t>(reqSize, kMaxKernelPoolAlloc);

        auto result = KernelAddressSpace::Instance().AllocatePool(
            PoolType::NonPagedPool, reqSize, kDefaultPoolTag);
        if (result.has_value() && baseAddrPtr != 0) {
            (void)ctx.Memory().WriteU64(baseAddrPtr, result.value());
        }
    }

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
//   PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten)
static bool HandleNtWriteVirtualMemory(APIContext& ctx) {
    const auto processHandle = ctx.GetArg(0);
    const auto baseAddr      = ctx.GetArgPtr(1);
    const auto bufferAddr    = ctx.GetArgPtr(2);
    const auto numBytes      = ctx.GetArg(3);

    Tracker().IncrementProcessManipulations();

    RecordSimpleCall("NtWriteVirtualMemory", "ntoskrnl.exe",
                     processHandle, baseAddr, bufferAddr, numBytes,
                     static_cast<uint64_t>(NT::STATUS_SUCCESS), true,
                     "Kernel-mode cross-process memory write — injection vector");
    Tracker().AddMitreTechnique("T1055");  // Process Injection

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// Registration Table
// ============================================================================

static constexpr APIRegistration kKernelRegs[] = {
    // Memory Management
    { "ntoskrnl.exe", "ExAllocatePoolWithTag",
      HandleExAllocatePoolWithTag, 3, false },
    { "ntoskrnl.exe", "ExAllocatePool",
      HandleExAllocatePool, 2, false },
    { "ntoskrnl.exe", "ExFreePoolWithTag",
      HandleExFreePoolWithTag, 2, false },
    { "ntoskrnl.exe", "ExFreePool",
      HandleExFreePool, 1, false },
    { "ntoskrnl.exe", "MmAllocateContiguousMemory",
      HandleMmAllocateContiguousMemory, 2, false },
    { "ntoskrnl.exe", "MmMapIoSpace",
      HandleMmMapIoSpace, 3, false },
    { "ntoskrnl.exe", "MmGetSystemRoutineAddress",
      HandleMmGetSystemRoutineAddress, 1, false },

    // Process / Thread
    { "ntoskrnl.exe", "PsCreateSystemThread",
      HandlePsCreateSystemThread, 7, false },
    { "ntoskrnl.exe", "PsTerminateSystemThread",
      HandlePsTerminateSystemThread, 1, false },
    { "ntoskrnl.exe", "PsGetCurrentProcessId",
      HandlePsGetCurrentProcessId, 0, false },
    { "ntoskrnl.exe", "PsGetCurrentThreadId",
      HandlePsGetCurrentThreadId, 0, false },
    { "ntoskrnl.exe", "PsLookupProcessByProcessId",
      HandlePsLookupProcessByProcessId, 2, false },
    { "ntoskrnl.exe", "PsLookupThreadByThreadId",
      HandlePsLookupThreadByThreadId, 2, false },
    { "ntoskrnl.exe", "KeAttachProcess",
      HandleKeAttachProcess, 1, false },
    { "ntoskrnl.exe", "KeDetachProcess",
      HandleKeDetachProcess, 0, false },
    { "ntoskrnl.exe", "KeStackAttachProcess",
      HandleKeStackAttachProcess, 2, false },
    { "ntoskrnl.exe", "KeUnstackDetachProcess",
      HandleKeUnstackDetachProcess, 1, false },

    // Object Manager
    { "ntoskrnl.exe", "ObReferenceObjectByHandle",
      HandleObReferenceObjectByHandle, 6, false },
    { "ntoskrnl.exe", "ObDereferenceObject",
      HandleObDereferenceObject, 1, false },
    { "ntoskrnl.exe", "ObOpenObjectByPointer",
      HandleObOpenObjectByPointer, 7, false },

    // Registry (Zw*)
    { "ntoskrnl.exe", "ZwCreateKey",
      HandleZwCreateKey, 7, false },
    { "ntoskrnl.exe", "ZwOpenKey",
      HandleZwOpenKey, 3, false },
    { "ntoskrnl.exe", "ZwSetValueKey",
      HandleZwSetValueKey, 6, false },
    { "ntoskrnl.exe", "ZwQueryValueKey",
      HandleZwQueryValueKey, 6, false },
    { "ntoskrnl.exe", "ZwDeleteKey",
      HandleZwDeleteKey, 1, false },

    // File System (Zw*)
    { "ntoskrnl.exe", "ZwCreateFile",
      HandleZwCreateFile, 11, false },
    { "ntoskrnl.exe", "ZwReadFile",
      HandleZwReadFile, 9, false },
    { "ntoskrnl.exe", "ZwWriteFile",
      HandleZwWriteFile, 9, false },
    { "ntoskrnl.exe", "ZwClose",
      HandleZwClose, 1, false },
    { "ntoskrnl.exe", "ZwQueryInformationFile",
      HandleZwQueryInformationFile, 5, false },

    // System Info / Hooking / Device
    { "ntoskrnl.exe", "KeServiceDescriptorTable",
      HandleKeServiceDescriptorTable, 0, false },
    { "ntoskrnl.exe", "IoCreateDevice",
      HandleIoCreateDevice, 7, false },
    { "ntoskrnl.exe", "IoDeleteDevice",
      HandleIoDeleteDevice, 1, false },
    { "ntoskrnl.exe", "IoCreateSymbolicLink",
      HandleIoCreateSymbolicLink, 2, false },
    { "ntoskrnl.exe", "RtlInitUnicodeString",
      HandleRtlInitUnicodeString, 2, false },
    { "ntoskrnl.exe", "DbgPrint",
      HandleDbgPrint, 1, false },

    // Callback Registration
    { "ntoskrnl.exe", "PsSetCreateProcessNotifyRoutineEx",
      HandlePsSetCreateProcessNotifyRoutineEx, 2, false },
    { "ntoskrnl.exe", "PsSetCreateThreadNotifyRoutine",
      HandlePsSetCreateThreadNotifyRoutine, 1, false },
    { "ntoskrnl.exe", "PsSetLoadImageNotifyRoutine",
      HandlePsSetLoadImageNotifyRoutine, 1, false },
    { "ntoskrnl.exe", "CmRegisterCallbackEx",
      HandleCmRegisterCallbackEx, 6, false },
    { "ntoskrnl.exe", "ObRegisterCallbacks",
      HandleObRegisterCallbacks, 2, false },

    // Suspicious / Rootkit-Specific
    { "ntoskrnl.exe", "KeInsertQueueApc",
      HandleKeInsertQueueApc, 3, false },
    { "ntoskrnl.exe", "MmCopyVirtualMemory",
      HandleMmCopyVirtualMemory, 7, false },
    { "ntoskrnl.exe", "ZwProtectVirtualMemory",
      HandleZwProtectVirtualMemory, 5, false },
    { "ntoskrnl.exe", "ZwAllocateVirtualMemory",
      HandleZwAllocateVirtualMemory, 6, false },
    { "ntoskrnl.exe", "NtWriteVirtualMemory",
      HandleNtWriteVirtualMemory, 5, false },
};

// ============================================================================
// Registration entry point
// ============================================================================

void RegisterKernelAPIs(APIDispatcher& dispatcher) noexcept {
    dispatcher.RegisterBatch(kKernelRegs, static_cast<uint32_t>(std::size(kKernelRegs)));
}

} // namespace Phantom::WinAPI::Kernel
