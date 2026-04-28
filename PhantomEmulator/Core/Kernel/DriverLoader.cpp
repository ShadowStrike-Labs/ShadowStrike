/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * DriverLoader.cpp — Kernel-mode driver (.sys) loader implementation
 *
 * Full PE/COFF loading pipeline for x64 kernel drivers: parse headers,
 * map sections, apply IMAGE_REL_BASED_DIR64 relocations, resolve kernel
 * imports from pre-registered stub tables, create DRIVER_OBJECT, and
 * perform security analysis with MITRE ATT&CK mapping.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "DriverLoader.hpp"
#include "KernelAddressSpace.hpp"
#include "../Memory/VirtualMemory.hpp"
#include "../Loader/PEStructures.hpp"
#include "../../Common/Errors.hpp"
#include "../../Common/Platform.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <mutex>
#include <new>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

namespace Phantom {

// ============================================================================
// Limits
// ============================================================================

static constexpr uint32_t kMaxLoadedDrivers       = 128;
static constexpr uint32_t kMaxDriverImageSize      = 64 * 1024 * 1024;   // 64 MB
static constexpr uint32_t kMaxRelocsPerDriver      = 16384;
static constexpr uint32_t kMaxImportsPerDriver     = 4096;

// Stub region: first 64 KB of driver address range reserved for RET stubs
static constexpr GuestAddress kStubRegionBase      = kDriverBase;
static constexpr GuestSize    kStubRegionSize      = 0x10000;            // 64 KB
static constexpr uint32_t     kStubSlotSize        = 16;
static constexpr uint32_t     kMaxStubSlots        = static_cast<uint32_t>(
                                                         kStubRegionSize / kStubSlotSize);

// DRIVER_OBJECT allocation area: 512 KB offset from driver base
static constexpr GuestAddress kDriverObjRegionBase = kDriverBase + 0x80000;
static constexpr GuestSize    kDriverObjSlotSize   = kPageSize;          // 1 page each

// Actual driver images start at 1 MB offset
static constexpr GuestAddress kDriverImageStart    = kDriverBase + 0x100000;

// DRIVER_OBJECT field offsets (Windows 10 x64 layout)
static constexpr uint32_t kDrvObjOfs_Type          = 0x00;
static constexpr uint32_t kDrvObjOfs_Size          = 0x02;
static constexpr uint32_t kDrvObjOfs_DeviceObject  = 0x08;
static constexpr uint32_t kDrvObjOfs_Flags         = 0x10;
static constexpr uint32_t kDrvObjOfs_DriverStart   = 0x18;
static constexpr uint32_t kDrvObjOfs_DriverSize    = 0x20;
static constexpr uint32_t kDrvObjOfs_DriverInit    = 0x58;
static constexpr uint32_t kDrvObjOfs_DriverUnload  = 0x68;
static constexpr uint32_t kDrvObjOfs_MajorFunction = 0x70;
static constexpr uint32_t kIRPMajorFunctionCount   = 28;
static constexpr uint16_t kIOTypeDriver            = 4;

// ============================================================================
// Internal Helpers (anonymous namespace)
// ============================================================================

namespace {

[[nodiscard]] std::string ToLower(std::string_view sv) {
    std::string result(sv);
    for (char& c : result) {
        if (c >= 'A' && c <= 'Z') c += 32;
    }
    return result;
}

[[nodiscard]] float CalculateEntropy(const uint8_t* data, size_t size) {
    if (data == nullptr || size == 0) return 0.0f;
    uint32_t freq[256] = {};
    for (size_t i = 0; i < size; ++i) {
        freq[data[i]]++;
    }
    double entropy = 0.0;
    const double total = static_cast<double>(size);
    for (uint32_t i = 0; i < 256; ++i) {
        if (freq[i] == 0) continue;
        const double p = static_cast<double>(freq[i]) / total;
        entropy -= p * std::log2(p);
    }
    return static_cast<float>(entropy);
}

[[nodiscard]] bool AddU32(uint32_t a, uint32_t b, uint32_t& result) noexcept {
    if ((std::numeric_limits<uint32_t>::max)() - a < b) {
        return false;
    }
    result = a + b;
    return true;
}

[[nodiscard]] bool AddGuest(GuestAddress a, GuestSize b, GuestAddress& result) noexcept {
    if ((std::numeric_limits<GuestAddress>::max)() - a < b) {
        return false;
    }
    result = a + b;
    return true;
}

[[nodiscard]] bool AlignUpGuest(GuestAddress value, GuestSize alignment, GuestAddress& result) noexcept {
    if (alignment == 0 || (alignment & (alignment - 1)) != 0) {
        return false;
    }
    if ((std::numeric_limits<GuestAddress>::max)() - value < alignment - 1) {
        return false;
    }
    result = AlignUp(value, alignment);
    return true;
}

[[nodiscard]] uint32_t SectionMappedSize(const PE::SectionHeader& sec) noexcept {
    return std::max(sec.VirtualSize, sec.SizeOfRawData);
}

// Convert an RVA to a file offset using the section table
[[nodiscard]] std::optional<uint32_t> RVAToFileOffset(
    uint32_t rva,
    const PE::SectionHeader* sections,
    uint32_t sectionCount)
{
    for (uint32_t i = 0; i < sectionCount; ++i) {
        const uint32_t secStart = sections[i].VirtualAddress;
        const uint32_t secSize  = SectionMappedSize(sections[i]);
        uint32_t secEnd = 0;
        if (secSize == 0 || !AddU32(secStart, secSize, secEnd)) {
            continue;
        }
        if (rva >= secStart && rva < secEnd) {
            const uint32_t offset = rva - secStart;
            if (offset < sections[i].SizeOfRawData) {
                uint32_t fileOffset = 0;
                if (AddU32(sections[i].PointerToRawData, offset, fileOffset)) {
                    return fileOffset;
                }
                return std::nullopt;
            }
            return std::nullopt; // In zero-fill region
        }
    }
    return std::nullopt;
}

// Read a null-terminated ASCII string from a byte span
[[nodiscard]] std::string ReadStringFromImage(
    std::span<const uint8_t> image,
    size_t offset,
    size_t maxLen = PE::kMaxDLLNameLen)
{
    if (offset >= image.size()) return {};
    const size_t limit = offset + std::min(maxLen, image.size() - offset);
    size_t end = offset;
    while (end < limit && image[end] != 0) ++end;
    return std::string(reinterpret_cast<const char*>(image.data() + offset),
                       end - offset);
}

// Convert PE section characteristics to MemProt
[[nodiscard]] MemProt SectionCharacteristicsToMemProt(uint32_t chars) noexcept {
    auto raw = static_cast<MemProt>(PE::SectionToMemProt(chars));
    return raw;
}

} // anonymous namespace

// ============================================================================
// PIMPL Implementation
// ============================================================================

struct DriverLoader::Impl {
    VirtualMemory*  memory      = nullptr;
    bool            initialized = false;

    // Loaded driver registry
    std::vector<LoadedDriver> drivers;

    // Kernel export table: module(lower) -> function(lower) -> stub address
    std::vector<KernelExport> exports;
    std::unordered_map<std::string,
                       std::unordered_map<std::string, GuestAddress>> exportMap;

    // Address cursors
    uint32_t     nextStubIndex    = 0;
    GuestAddress nextDriverObjBase = kDriverObjRegionBase;
    GuestAddress nextDriverImageBase = kDriverImageStart;

    // Aggregate statistics
    GuestSize totalMappedSize  = 0;
    uint32_t  totalImportCount = 0;

    mutable std::shared_mutex mutex;

    // ------------------------------------------------------------------
    // Stub allocation — write a single RET (0xC3) into the stub slot
    // ------------------------------------------------------------------
    [[nodiscard]] GuestAddress AllocateStub() {
        if (nextStubIndex >= kMaxStubSlots) return 0;
        const GuestAddress addr = kStubRegionBase +
                                  static_cast<GuestAddress>(nextStubIndex) * kStubSlotSize;

        const uint8_t retInst = 0xC3;
        if (memory == nullptr ||
            memory->Write(addr, &retInst, sizeof(retInst)) != ErrorCode::Success) {
            return 0;
        }
        ++nextStubIndex;
        return addr;
    }

    // ------------------------------------------------------------------
    // Register an export in the lookup table (no lock — caller holds it)
    // ------------------------------------------------------------------
    [[nodiscard]] bool RegisterExportNoLock(const std::string& module,
                              const std::string& function,
                              GuestAddress addr) {
        if (module.empty() || function.empty() || addr == 0 || exports.size() >= kMaxStubSlots) {
            return false;
        }

        const std::string moduleKey = ToLower(module);
        const std::string functionKey = ToLower(function);
        auto& functions = exportMap[moduleKey];
        if (auto it = functions.find(functionKey); it != functions.end()) {
            it->second = addr;
            for (auto& existing : exports) {
                if (ToLower(existing.moduleName) == moduleKey &&
                    ToLower(existing.functionName) == functionKey) {
                    existing.stubAddress = addr;
                    return true;
                }
            }
        }
        functions[functionKey] = addr;

        KernelExport ke;
        ke.moduleName   = module;
        ke.functionName = function;
        ke.stubAddress  = addr;
        ke.isHooked     = false;
        exports.push_back(std::move(ke));
        return true;
    }

    // ------------------------------------------------------------------
    // Allocate a stub + register it
    // ------------------------------------------------------------------
    GuestAddress AllocateAndRegister(const std::string& module,
                                     const std::string& function) {
        GuestAddress addr = AllocateStub();
        if (addr != 0 && !RegisterExportNoLock(module, function, addr)) {
            return 0;
        }
        return addr;
    }

    // ------------------------------------------------------------------
    // Resolve an export (no lock — caller holds it)
    // ------------------------------------------------------------------
    [[nodiscard]] std::optional<GuestAddress> ResolveExportNoLock(
        const std::string& module,
        const std::string& function) const
    {
        auto modIt = exportMap.find(ToLower(module));
        if (modIt == exportMap.end()) return std::nullopt;
        auto funcIt = modIt->second.find(ToLower(function));
        if (funcIt == modIt->second.end()) return std::nullopt;
        return funcIt->second;
    }

    // ------------------------------------------------------------------
    // Create a DRIVER_OBJECT in guest kernel memory
    // ------------------------------------------------------------------
    [[nodiscard]] GuestAddress CreateDriverObject(
        GuestAddress imageBase,
        uint32_t imageSize,
        GuestAddress entryPoint)
    {
        if (memory == nullptr) return 0;
        GuestAddress nextObjBase = 0;
        if (!AddGuest(nextDriverObjBase, kDriverObjSlotSize, nextObjBase)) {
            return 0;
        }
        auto allocated = memory->Allocate(nextDriverObjBase,
                                          kDriverObjSlotSize,
                                          MemProt::RW);
        if (!allocated) return 0;

        const GuestAddress objBase = *allocated;

        // Type = IO_TYPE_DRIVER (4)
        bool ok = memory->WriteU16(objBase + kDrvObjOfs_Type, kIOTypeDriver) == ErrorCode::Success;
        // Size field
        ok = ok && memory->WriteU16(objBase + kDrvObjOfs_Size,
                                    static_cast<uint16_t>(kDrvObjOfs_MajorFunction +
                                                          kIRPMajorFunctionCount * 8)) == ErrorCode::Success;
        // DeviceObject = 0 (none yet)
        ok = ok && memory->WriteU64(objBase + kDrvObjOfs_DeviceObject, 0) == ErrorCode::Success;
        // Flags
        ok = ok && memory->WriteU32(objBase + kDrvObjOfs_Flags, 0) == ErrorCode::Success;
        // DriverStart
        ok = ok && memory->WriteU64(objBase + kDrvObjOfs_DriverStart, imageBase) == ErrorCode::Success;
        // DriverSize
        ok = ok && memory->WriteU32(objBase + kDrvObjOfs_DriverSize, imageSize) == ErrorCode::Success;
        // DriverInit (DriverEntry)
        ok = ok && memory->WriteU64(objBase + kDrvObjOfs_DriverInit, entryPoint) == ErrorCode::Success;
        // DriverUnload = 0
        ok = ok && memory->WriteU64(objBase + kDrvObjOfs_DriverUnload, 0) == ErrorCode::Success;
        // MajorFunction[0..27] = 0
        for (uint32_t i = 0; i < kIRPMajorFunctionCount; ++i) {
            ok = ok && memory->WriteU64(objBase + kDrvObjOfs_MajorFunction + i * 8, 0) == ErrorCode::Success;
        }

        if (!ok) {
            (void)memory->Free(objBase, kDriverObjSlotSize);
            return 0;
        }

        nextDriverObjBase = nextObjBase;
        return objBase;
    }

    // ------------------------------------------------------------------
    // Populate default kernel export stubs
    // ------------------------------------------------------------------
    void RegisterDefaultExports();

    // ------------------------------------------------------------------
    // Detect suspicious imports and set LoadedDriver flags
    // ------------------------------------------------------------------
    void AnalyzeImportBehavior(const std::vector<DriverImport>& imports,
                               LoadedDriver& driver) const;
};

// ============================================================================
// Impl::RegisterDefaultExports — pre-register ~180 kernel function stubs
// ============================================================================

void DriverLoader::Impl::RegisterDefaultExports() {
    auto r = [this](const char* mod, const char* func) {
        AllocateAndRegister(mod, func);
    };

    // ---- ntoskrnl.exe : Memory ----
    r("ntoskrnl.exe", "ExAllocatePoolWithTag");
    r("ntoskrnl.exe", "ExAllocatePool");
    r("ntoskrnl.exe", "ExFreePoolWithTag");
    r("ntoskrnl.exe", "ExFreePool");
    r("ntoskrnl.exe", "ExAllocatePoolWithQuotaTag");
    r("ntoskrnl.exe", "MmAllocateContiguousMemory");
    r("ntoskrnl.exe", "MmFreeContiguousMemory");
    r("ntoskrnl.exe", "MmAllocateNonCachedMemory");
    r("ntoskrnl.exe", "MmFreeNonCachedMemory");
    r("ntoskrnl.exe", "MmMapIoSpace");
    r("ntoskrnl.exe", "MmUnmapIoSpace");
    r("ntoskrnl.exe", "MmMapLockedPagesSpecifyCache");
    r("ntoskrnl.exe", "MmUnlockPages");
    r("ntoskrnl.exe", "MmProbeAndLockPages");
    r("ntoskrnl.exe", "MmBuildMdlForNonPagedPool");
    r("ntoskrnl.exe", "MmGetSystemRoutineAddress");
    r("ntoskrnl.exe", "MmGetPhysicalAddress");
    r("ntoskrnl.exe", "MmIsAddressValid");
    r("ntoskrnl.exe", "ProbeForRead");
    r("ntoskrnl.exe", "ProbeForWrite");

    // ---- ntoskrnl.exe : IO ----
    r("ntoskrnl.exe", "IoCreateDevice");
    r("ntoskrnl.exe", "IoDeleteDevice");
    r("ntoskrnl.exe", "IoCreateSymbolicLink");
    r("ntoskrnl.exe", "IoDeleteSymbolicLink");
    r("ntoskrnl.exe", "IoCompleteRequest");
    r("ntoskrnl.exe", "IofCompleteRequest");
    r("ntoskrnl.exe", "IoGetCurrentIrpStackLocation");
    r("ntoskrnl.exe", "IoAllocateIrp");
    r("ntoskrnl.exe", "IoFreeIrp");
    r("ntoskrnl.exe", "IoCallDriver");
    r("ntoskrnl.exe", "IofCallDriver");
    r("ntoskrnl.exe", "IoAllocateMdl");
    r("ntoskrnl.exe", "IoFreeMdl");
    r("ntoskrnl.exe", "IoGetDeviceProperty");
    r("ntoskrnl.exe", "IoGetDeviceObjectPointer");
    r("ntoskrnl.exe", "IoRegisterDeviceInterface");
    r("ntoskrnl.exe", "IoSetDeviceInterfaceState");
    r("ntoskrnl.exe", "IoRegisterShutdownNotification");
    r("ntoskrnl.exe", "IoUnregisterShutdownNotification");
    r("ntoskrnl.exe", "IoWMIRegistrationControl");
    r("ntoskrnl.exe", "IoRegisterPlugPlayNotification");
    r("ntoskrnl.exe", "IoUnregisterPlugPlayNotification");
    r("ntoskrnl.exe", "IoAttachDeviceToDeviceStack");
    r("ntoskrnl.exe", "IoDetachDevice");

    // ---- ntoskrnl.exe : Synchronisation ----
    r("ntoskrnl.exe", "KeInitializeSpinLock");
    r("ntoskrnl.exe", "KeAcquireSpinLockRaiseToDpc");
    r("ntoskrnl.exe", "KeReleaseSpinLock");
    r("ntoskrnl.exe", "KeAcquireSpinLockAtDpcLevel");
    r("ntoskrnl.exe", "KeReleaseSpinLockFromDpcLevel");
    r("ntoskrnl.exe", "KeWaitForSingleObject");
    r("ntoskrnl.exe", "KeWaitForMultipleObjects");
    r("ntoskrnl.exe", "KeSetEvent");
    r("ntoskrnl.exe", "KeInitializeEvent");
    r("ntoskrnl.exe", "KeResetEvent");
    r("ntoskrnl.exe", "KeClearEvent");
    r("ntoskrnl.exe", "KeInitializeMutex");
    r("ntoskrnl.exe", "KeReleaseMutex");
    r("ntoskrnl.exe", "KeInitializeSemaphore");
    r("ntoskrnl.exe", "KeReleaseSemaphore");
    r("ntoskrnl.exe", "ExInitializeFastMutex");
    r("ntoskrnl.exe", "ExAcquireFastMutex");
    r("ntoskrnl.exe", "ExReleaseFastMutex");
    r("ntoskrnl.exe", "ExInitializeResourceLite");
    r("ntoskrnl.exe", "ExAcquireResourceSharedLite");
    r("ntoskrnl.exe", "ExAcquireResourceExclusiveLite");
    r("ntoskrnl.exe", "ExReleaseResourceLite");

    // ---- ntoskrnl.exe : Timers / DPC ----
    r("ntoskrnl.exe", "KeInitializeTimer");
    r("ntoskrnl.exe", "KeInitializeTimerEx");
    r("ntoskrnl.exe", "KeSetTimer");
    r("ntoskrnl.exe", "KeSetTimerEx");
    r("ntoskrnl.exe", "KeCancelTimer");
    r("ntoskrnl.exe", "KeInitializeDpc");
    r("ntoskrnl.exe", "KeInsertQueueDpc");
    r("ntoskrnl.exe", "KeRemoveQueueDpc");
    r("ntoskrnl.exe", "KeDelayExecutionThread");
    r("ntoskrnl.exe", "KeQuerySystemTime");
    r("ntoskrnl.exe", "KeQueryTickCount");
    r("ntoskrnl.exe", "KeQueryPerformanceCounter");
    r("ntoskrnl.exe", "KeQueryInterruptTime");

    // ---- ntoskrnl.exe : IRQL ----
    r("ntoskrnl.exe", "KeGetCurrentIrql");
    r("ntoskrnl.exe", "KeLowerIrql");
    r("ntoskrnl.exe", "KeRaiseIrqlToDpcLevel");
    r("ntoskrnl.exe", "KfRaiseIrql");
    r("ntoskrnl.exe", "KfLowerIrql");

    // ---- ntoskrnl.exe : Process / Thread ----
    r("ntoskrnl.exe", "PsCreateSystemThread");
    r("ntoskrnl.exe", "PsTerminateSystemThread");
    r("ntoskrnl.exe", "PsGetCurrentProcess");
    r("ntoskrnl.exe", "PsGetCurrentProcessId");
    r("ntoskrnl.exe", "PsGetCurrentThread");
    r("ntoskrnl.exe", "PsGetCurrentThreadId");
    r("ntoskrnl.exe", "PsGetProcessPeb");
    r("ntoskrnl.exe", "PsGetProcessId");
    r("ntoskrnl.exe", "PsGetProcessImageFileName");
    r("ntoskrnl.exe", "PsLookupProcessByProcessId");
    r("ntoskrnl.exe", "PsLookupThreadByThreadId");
    r("ntoskrnl.exe", "KeAttachProcess");
    r("ntoskrnl.exe", "KeDetachProcess");
    r("ntoskrnl.exe", "KeStackAttachProcess");
    r("ntoskrnl.exe", "KeUnstackDetachProcess");
    r("ntoskrnl.exe", "PsSetCreateProcessNotifyRoutine");
    r("ntoskrnl.exe", "PsSetCreateProcessNotifyRoutineEx");
    r("ntoskrnl.exe", "PsSetCreateThreadNotifyRoutine");
    r("ntoskrnl.exe", "PsRemoveCreateThreadNotifyRoutine");
    r("ntoskrnl.exe", "PsSetLoadImageNotifyRoutine");
    r("ntoskrnl.exe", "PsRemoveLoadImageNotifyRoutine");

    // ---- ntoskrnl.exe : Object Manager ----
    r("ntoskrnl.exe", "ObReferenceObjectByHandle");
    r("ntoskrnl.exe", "ObDereferenceObject");
    r("ntoskrnl.exe", "ObfDereferenceObject");
    r("ntoskrnl.exe", "ObReferenceObjectByPointer");
    r("ntoskrnl.exe", "ObRegisterCallbacks");
    r("ntoskrnl.exe", "ObUnRegisterCallbacks");
    r("ntoskrnl.exe", "ObOpenObjectByPointer");

    // ---- ntoskrnl.exe : Zw / Nt ----
    r("ntoskrnl.exe", "ZwCreateFile");
    r("ntoskrnl.exe", "ZwClose");
    r("ntoskrnl.exe", "ZwReadFile");
    r("ntoskrnl.exe", "ZwWriteFile");
    r("ntoskrnl.exe", "ZwQueryInformationFile");
    r("ntoskrnl.exe", "ZwSetInformationFile");
    r("ntoskrnl.exe", "ZwCreateKey");
    r("ntoskrnl.exe", "ZwOpenKey");
    r("ntoskrnl.exe", "ZwDeleteKey");
    r("ntoskrnl.exe", "ZwQueryValueKey");
    r("ntoskrnl.exe", "ZwSetValueKey");
    r("ntoskrnl.exe", "ZwEnumerateKey");
    r("ntoskrnl.exe", "ZwEnumerateValueKey");
    r("ntoskrnl.exe", "ZwQuerySystemInformation");
    r("ntoskrnl.exe", "ZwAllocateVirtualMemory");
    r("ntoskrnl.exe", "ZwFreeVirtualMemory");
    r("ntoskrnl.exe", "ZwWriteVirtualMemory");

    // ---- ntoskrnl.exe : Rtl ----
    r("ntoskrnl.exe", "RtlInitUnicodeString");
    r("ntoskrnl.exe", "RtlCopyUnicodeString");
    r("ntoskrnl.exe", "RtlCompareUnicodeString");
    r("ntoskrnl.exe", "RtlFreeUnicodeString");
    r("ntoskrnl.exe", "RtlInitAnsiString");
    r("ntoskrnl.exe", "RtlAnsiStringToUnicodeString");
    r("ntoskrnl.exe", "RtlUnicodeStringToAnsiString");
    r("ntoskrnl.exe", "RtlCopyMemory");
    r("ntoskrnl.exe", "RtlZeroMemory");
    r("ntoskrnl.exe", "RtlMoveMemory");
    r("ntoskrnl.exe", "RtlFillMemory");
    r("ntoskrnl.exe", "RtlCompareMemory");
    r("ntoskrnl.exe", "RtlStringCbPrintfW");
    r("ntoskrnl.exe", "RtlStringCbCopyW");
    r("ntoskrnl.exe", "RtlStringCchPrintfW");
    r("ntoskrnl.exe", "RtlGetVersion");

    // ---- ntoskrnl.exe : Miscellaneous ----
    r("ntoskrnl.exe", "DbgPrint");
    r("ntoskrnl.exe", "DbgPrintEx");
    r("ntoskrnl.exe", "KeBugCheckEx");
    r("ntoskrnl.exe", "KeBugCheck");
    r("ntoskrnl.exe", "IoCreateNotificationEvent");
    r("ntoskrnl.exe", "IoCreateSynchronizationEvent");
    r("ntoskrnl.exe", "SeAccessCheck");
    r("ntoskrnl.exe", "SeSinglePrivilegeCheck");
    r("ntoskrnl.exe", "ExInterlockedInsertHeadList");
    r("ntoskrnl.exe", "ExInterlockedInsertTailList");
    r("ntoskrnl.exe", "ExInterlockedRemoveHeadList");
    r("ntoskrnl.exe", "ExSystemTimeToLocalTime");
    r("ntoskrnl.exe", "KeServiceDescriptorTable");
    r("ntoskrnl.exe", "CmRegisterCallback");
    r("ntoskrnl.exe", "CmRegisterCallbackEx");
    r("ntoskrnl.exe", "CmUnRegisterCallback");

    // ---- ntoskrnl.exe : WDF / Minifilter bridging ----
    r("ntoskrnl.exe", "FltRegisterFilter");
    r("ntoskrnl.exe", "FltStartFiltering");
    r("ntoskrnl.exe", "FltUnregisterFilter");
    r("ntoskrnl.exe", "WdfVersionBind");
    r("ntoskrnl.exe", "WdfVersionUnbind");

    // ---- HAL.dll ----
    r("HAL.dll", "HalGetBusData");
    r("HAL.dll", "HalGetBusDataByOffset");
    r("HAL.dll", "HalSetBusData");
    r("HAL.dll", "HalSetBusDataByOffset");
    r("HAL.dll", "HalTranslateBusAddress");
    r("HAL.dll", "HalGetInterruptVector");
    r("HAL.dll", "KeQueryPerformanceCounter");
    r("HAL.dll", "KeStallExecutionProcessor");
    r("HAL.dll", "ExAcquireFastMutex");
    r("HAL.dll", "ExReleaseFastMutex");
    r("HAL.dll", "ExTryToAcquireFastMutex");
    r("HAL.dll", "KfAcquireSpinLock");
    r("HAL.dll", "KfReleaseSpinLock");
    r("HAL.dll", "KfRaiseIrql");
    r("HAL.dll", "KfLowerIrql");

    // ---- ndis.sys ----
    r("ndis.sys", "NdisRegisterProtocolDriver");
    r("ndis.sys", "NdisDeregisterProtocolDriver");
    r("ndis.sys", "NdisSendNetBufferLists");
    r("ndis.sys", "NdisReturnNetBufferLists");
    r("ndis.sys", "NdisOpenAdapterEx");
    r("ndis.sys", "NdisCloseAdapterEx");
    r("ndis.sys", "NdisAllocateMemoryWithTag");
    r("ndis.sys", "NdisFreeMemory");
    r("ndis.sys", "NdisAllocateNetBufferListPool");
    r("ndis.sys", "NdisFreeNetBufferListPool");
    r("ndis.sys", "NdisAllocateNetBufferAndNetBufferList");
    r("ndis.sys", "NdisFreeNetBufferList");
    r("ndis.sys", "NdisMIndicateReceiveNetBufferLists");
    r("ndis.sys", "NdisMSendNetBufferListsComplete");
    r("ndis.sys", "NdisMRegisterMiniportDriver");
    r("ndis.sys", "NdisMDeregisterMiniportDriver");
    r("ndis.sys", "NdisMSetMiniportAttributes");
}

// ============================================================================
// Impl::AnalyzeImportBehavior — flag suspicious imports
// ============================================================================

void DriverLoader::Impl::AnalyzeImportBehavior(
    const std::vector<DriverImport>& imports,
    LoadedDriver& driver) const
{
    for (const auto& imp : imports) {
        const std::string funcLower = ToLower(imp.functionName);

        if (funcLower == "keservicedescriptortable")
            driver.accessesSSDT = true;

        if (funcLower == "keattachprocess" ||
            funcLower == "kestackattachprocess")
            driver.callsKeAttachProcess = true;

        if (funcLower == "psgetprocesspeb")
            driver.manipulatesPEB = true;

        if (funcLower == "mmmapiospace" ||
            funcLower == "mmmaplockedpagesspecifycache")
            driver.usesMMAPIO = true;

        // IDT manipulation heuristics
        if (funcLower.find("idt") != std::string::npos ||
            funcLower == "keregisterbugcheckreasoncallback")
            driver.accessesIDT = true;
    }
}

// ============================================================================
// DriverLoader — Constructor / Destructor / Singleton
// ============================================================================

DriverLoader::DriverLoader()
    : m_impl(std::make_unique<Impl>()) {}

DriverLoader::~DriverLoader() = default;

DriverLoader& DriverLoader::Instance() {
    static DriverLoader instance;
    return instance;
}

void DriverLoader::Reset() {
    std::unique_lock lock(m_impl->mutex);
    m_impl->drivers.clear();
    m_impl->exports.clear();
    m_impl->exportMap.clear();
    m_impl->nextStubIndex       = 0;
    m_impl->nextDriverObjBase   = kDriverObjRegionBase;
    m_impl->nextDriverImageBase = kDriverImageStart;
    m_impl->totalMappedSize     = 0;
    m_impl->totalImportCount    = 0;
    m_impl->initialized         = false;
    m_impl->memory              = nullptr;
}

// ============================================================================
// Initialize — set up stub region and register default kernel exports
// ============================================================================

bool DriverLoader::Initialize(VirtualMemory& memory) {
    std::unique_lock lock(m_impl->mutex);
    if (m_impl->initialized) return true;

    m_impl->memory = &memory;

    // Map the stub region writable only during emission; make it RX afterwards
    // so emulated kernel imports do not leave writable executable memory.
    auto stubAlloc = memory.Allocate(kStubRegionBase, kStubRegionSize,
                                     MemProt::RW);
    if (!stubAlloc) return false;

    m_impl->RegisterDefaultExports();
    if (m_impl->exports.empty() ||
        !memory.Protect(kStubRegionBase, kStubRegionSize, MemProt::RX)) {
        (void)memory.Free(kStubRegionBase, kStubRegionSize);
        m_impl->exports.clear();
        m_impl->exportMap.clear();
        m_impl->nextStubIndex = 0;
        m_impl->memory = nullptr;
        return false;
    }
    m_impl->initialized = true;
    return true;
}

// ============================================================================
// IsValidKernelDriver — static PE validation
// ============================================================================

bool DriverLoader::IsValidKernelDriver(std::span<const uint8_t> image) {
    if (image.size() < sizeof(PE::DOSHeader)) return false;

    const auto* dos = reinterpret_cast<const PE::DOSHeader*>(image.data());
    if (dos->e_magic != PE::kDOSMagic) return false;
    if (dos->e_lfanew < static_cast<int32_t>(sizeof(PE::DOSHeader))) return false;

    const auto lfanew = static_cast<size_t>(dos->e_lfanew);
    if (lfanew > image.size() || image.size() - lfanew < sizeof(PE::NTHeaders64)) return false;

    const auto* nt = reinterpret_cast<const PE::NTHeaders64*>(
                          image.data() + lfanew);
    if (nt->Signature != PE::kNTSignature) return false;
    if (nt->FileHdr.Machine != PE::kMachineAMD64) return false;
    if (nt->FileHdr.SizeOfOptionalHeader < sizeof(PE::OptionalHeader64)) return false;
    if (nt->OptionalHdr.Magic != PE::kPE64Magic) return false;

    // Kernel drivers use NATIVE subsystem
    if (nt->OptionalHdr.Subsystem != PE::kSubsystemNative) return false;

    // Sanity limits
    if (nt->OptionalHdr.SizeOfImage == 0) return false;
    if (nt->OptionalHdr.SizeOfImage > kMaxDriverImageSize) return false;
    if (nt->OptionalHdr.AddressOfEntryPoint >= nt->OptionalHdr.SizeOfImage) return false;
    if (nt->FileHdr.NumberOfSections == 0) return false;
    if (nt->FileHdr.NumberOfSections > PE::kMaxSections) return false;

    const size_t sectionTableOffset = lfanew + sizeof(uint32_t) + sizeof(PE::FileHeader) +
                                      nt->FileHdr.SizeOfOptionalHeader;
    const size_t sectionBytes = static_cast<size_t>(nt->FileHdr.NumberOfSections) *
                                sizeof(PE::SectionHeader);
    if (sectionTableOffset > image.size() || image.size() - sectionTableOffset < sectionBytes) {
        return false;
    }

    return true;
}

// ============================================================================
// LoadDriver — full PE loading pipeline
// ============================================================================

std::optional<LoadedDriver> DriverLoader::LoadDriver(
    std::span<const uint8_t> driverImage,
    const std::string& driverName,
    GuestAddress preferredBase)
{
    std::unique_lock lock(m_impl->mutex);

    if (!m_impl->initialized || !m_impl->memory) return std::nullopt;
    if (m_impl->drivers.size() >= kMaxLoadedDrivers) return std::nullopt;
    if (driverImage.size() < sizeof(PE::DOSHeader)) return std::nullopt;
    if (driverImage.size() > kMaxDriverImageSize) return std::nullopt;
    if (driverName.empty() || driverName.size() > PE::kMaxDLLNameLen) return std::nullopt;

    // ------------------------------------------------------------------
    // 1. Parse and validate PE headers
    // ------------------------------------------------------------------

    const auto* dos = reinterpret_cast<const PE::DOSHeader*>(driverImage.data());
    if (dos->e_magic != PE::kDOSMagic) return std::nullopt;
    if (dos->e_lfanew < static_cast<int32_t>(sizeof(PE::DOSHeader))) return std::nullopt;

    const auto lfanew = static_cast<size_t>(dos->e_lfanew);
    if (lfanew > driverImage.size() ||
        driverImage.size() - lfanew < sizeof(PE::NTHeaders64)) {
        return std::nullopt;
    }

    const auto* nt = reinterpret_cast<const PE::NTHeaders64*>(
                          driverImage.data() + lfanew);
    if (nt->Signature != PE::kNTSignature) return std::nullopt;
    if (nt->FileHdr.Machine != PE::kMachineAMD64) return std::nullopt;
    if (nt->FileHdr.SizeOfOptionalHeader < sizeof(PE::OptionalHeader64)) return std::nullopt;
    if (nt->OptionalHdr.Magic != PE::kPE64Magic) return std::nullopt;
    if (nt->OptionalHdr.Subsystem != PE::kSubsystemNative) return std::nullopt;

    const uint32_t sectionCount = nt->FileHdr.NumberOfSections;
    if (sectionCount == 0 || sectionCount > PE::kMaxSections) return std::nullopt;

    const uint32_t sizeOfImage  = nt->OptionalHdr.SizeOfImage;
    const uint32_t sizeOfHeaders = nt->OptionalHdr.SizeOfHeaders;
    const uint64_t peImageBase  = nt->OptionalHdr.ImageBase;
    const uint32_t entryRVA     = nt->OptionalHdr.AddressOfEntryPoint;

    if (sizeOfImage == 0 || sizeOfImage > kMaxDriverImageSize) return std::nullopt;
    if (sizeOfHeaders > sizeOfImage) return std::nullopt;
    if (sizeOfHeaders > driverImage.size()) return std::nullopt;
    if (entryRVA >= sizeOfImage) return std::nullopt;

    // Locate section headers
    const size_t sectionTableOffset = lfanew + sizeof(uint32_t) +
                                      sizeof(PE::FileHeader) +
                                      nt->FileHdr.SizeOfOptionalHeader;
    const size_t sectionBytes = static_cast<size_t>(sectionCount) * sizeof(PE::SectionHeader);
    if (sectionTableOffset > driverImage.size() ||
        driverImage.size() - sectionTableOffset < sectionBytes) {
        return std::nullopt;
    }

    const auto* sections = reinterpret_cast<const PE::SectionHeader*>(
                               driverImage.data() + sectionTableOffset);

    // ------------------------------------------------------------------
    // 2. Determine load address
    // ------------------------------------------------------------------

    GuestAddress loadBase = 0;
    if (preferredBase != 0) {
        auto alloc = m_impl->memory->Allocate(preferredBase,
                                              static_cast<GuestSize>(sizeOfImage),
                                              MemProt::RW);
        if (alloc) loadBase = *alloc;
    }
    if (loadBase == 0) {
        const GuestAddress candidate = m_impl->nextDriverImageBase;
        auto alloc = m_impl->memory->Allocate(candidate,
                                              static_cast<GuestSize>(sizeOfImage),
                                              MemProt::RW);
        if (!alloc) return std::nullopt;
        loadBase = *alloc;
        GuestAddress imageEnd = 0;
        GuestAddress nextImageBase = 0;
        if (!AddGuest(loadBase, sizeOfImage, imageEnd) ||
            !AlignUpGuest(imageEnd, 0x10000, nextImageBase)) {
            (void)m_impl->memory->Free(loadBase, sizeOfImage);
            return std::nullopt;
        }
        m_impl->nextDriverImageBase = nextImageBase;
    }

    // ------------------------------------------------------------------
    // 3. Map PE headers
    // ------------------------------------------------------------------

    if (m_impl->memory->Write(loadBase, driverImage.data(),
                              sizeOfHeaders) != ErrorCode::Success) {
        (void)m_impl->memory->Free(loadBase, sizeOfImage);
        return std::nullopt;
    }

    // ------------------------------------------------------------------
    // 4. Map each section
    // ------------------------------------------------------------------

    LoadedDriver driver;
    driver.name          = driverName;
    driver.fullPath      = driverName;
    driver.imageBase     = loadBase;
    driver.imageSize     = sizeOfImage;
    if (!AddGuest(loadBase, entryRVA, driver.entryPoint)) {
        (void)m_impl->memory->Free(loadBase, sizeOfImage);
        return std::nullopt;
    }
    driver.loadTimestamp  = Platform::GetHighResolutionTicks();
    try {
        driver.sections.reserve(sectionCount);
        driver.imports.reserve(kMaxImportsPerDriver);
    } catch (const std::bad_alloc&) {
        (void)m_impl->memory->Free(loadBase, sizeOfImage);
        return std::nullopt;
    }

    for (uint32_t i = 0; i < sectionCount; ++i) {
        const auto& sec = sections[i];

        // Bounds-check raw data in file
        if (sec.SizeOfRawData > 0) {
            if (sec.PointerToRawData >= driverImage.size()) {
                (void)m_impl->memory->Free(loadBase, sizeOfImage);
                return std::nullopt;
            }
            const uint64_t rawEnd = static_cast<uint64_t>(sec.PointerToRawData) +
                                    sec.SizeOfRawData;
            if (rawEnd > driverImage.size()) {
                (void)m_impl->memory->Free(loadBase, sizeOfImage);
                return std::nullopt;
            }
        }

        // Bounds-check virtual range within image
        const uint32_t mappedSize = SectionMappedSize(sec);
        uint32_t sectionEnd = 0;
        if (mappedSize == 0 ||
            !AddU32(sec.VirtualAddress, mappedSize, sectionEnd) ||
            sectionEnd > sizeOfImage) {
            (void)m_impl->memory->Free(loadBase, sizeOfImage);
            return std::nullopt;
        }

        // Copy raw data into guest memory
        const uint32_t copySize = std::min(sec.SizeOfRawData, mappedSize);
        if (copySize > 0) {
            GuestAddress sectionBase = 0;
            if (!AddGuest(loadBase, sec.VirtualAddress, sectionBase)) {
                (void)m_impl->memory->Free(loadBase, sizeOfImage);
                return std::nullopt;
            }
            if (m_impl->memory->Write(
                    sectionBase,
                    driverImage.data() + sec.PointerToRawData,
                    copySize) != ErrorCode::Success) {
                (void)m_impl->memory->Free(loadBase, sizeOfImage);
                return std::nullopt;
            }
        }

        // Build DriverSection descriptor
        DriverSection ds;
        char nameBuf[PE::kMaxSectionNameLen + 1] = {};
        std::memcpy(nameBuf, sec.Name, PE::kMaxSectionNameLen);
        ds.name             = nameBuf;
        if (!AddGuest(loadBase, sec.VirtualAddress, ds.virtualAddress)) {
            (void)m_impl->memory->Free(loadBase, sizeOfImage);
            return std::nullopt;
        }
        ds.virtualSize      = mappedSize;
        ds.rawDataSize      = sec.SizeOfRawData;
        ds.characteristics  = sec.Characteristics;
        ds.isExecutable     = (sec.Characteristics & PE::kSecMemExecute) != 0;
        ds.isWritable       = (sec.Characteristics & PE::kSecMemWrite) != 0;
        ds.isDiscardable    = (sec.Characteristics & PE::kSecMemDiscardable) != 0;
        driver.sections.push_back(std::move(ds));
    }

    // ------------------------------------------------------------------
    // 5. Apply relocations (IMAGE_REL_BASED_DIR64)
    // ------------------------------------------------------------------

    const uint64_t relocationDelta = loadBase - peImageBase;

    if (relocationDelta != 0) {
        if (nt->FileHdr.Characteristics & PE::kCharRelocsStripped) {
            (void)m_impl->memory->Free(loadBase, sizeOfImage);
            return std::nullopt;
        }

        const uint32_t relocDirIdx = PE::kDirBaseReloc;
        const uint32_t numDirs = nt->OptionalHdr.NumberOfRvaAndSizes;
        if (relocDirIdx < numDirs) {
            const uint32_t relocRVA  = nt->OptionalHdr.DataDirectories[relocDirIdx].VirtualAddress;
            const uint32_t relocSize = nt->OptionalHdr.DataDirectories[relocDirIdx].Size;

            if (relocRVA != 0 && relocSize >= sizeof(PE::BaseRelocation)) {
                auto relocFileOfs = RVAToFileOffset(relocRVA, sections, sectionCount);
                if (!relocFileOfs) {
                    (void)m_impl->memory->Free(loadBase, sizeOfImage);
                    return std::nullopt;
                }

                uint32_t totalRelocs = 0;
                uint32_t processed   = 0;

                while (relocSize - processed >= sizeof(PE::BaseRelocation)) {
                    const size_t blockOfs = static_cast<size_t>(*relocFileOfs) + processed;
                    if (blockOfs + sizeof(PE::BaseRelocation) > driverImage.size()) break;

                    const auto* block = reinterpret_cast<const PE::BaseRelocation*>(
                                             driverImage.data() + blockOfs);
                    if (block->SizeOfBlock == 0) break;
                    if (block->SizeOfBlock < sizeof(PE::BaseRelocation)) break;
                    if (block->SizeOfBlock > relocSize - processed) break;
                    if (block->VirtualAddress >= sizeOfImage) {
                        (void)m_impl->memory->Free(loadBase, sizeOfImage);
                        return std::nullopt;
                    }

                    const uint32_t entryCount =
                        (block->SizeOfBlock - static_cast<uint32_t>(sizeof(PE::BaseRelocation))) / 2;
                    const auto* entries = reinterpret_cast<const uint16_t*>(
                                              driverImage.data() + blockOfs +
                                              sizeof(PE::BaseRelocation));

                    // Validate entries fit in image
                    if (blockOfs + sizeof(PE::BaseRelocation) +
                        static_cast<size_t>(entryCount) * 2 > driverImage.size()) break;

                    for (uint32_t e = 0; e < entryCount; ++e) {
                        if (totalRelocs >= kMaxRelocsPerDriver) break;

                        const uint16_t entry  = entries[e];
                        const uint16_t type   = entry >> 12;
                        const uint16_t offset = entry & 0x0FFF;

                        if (type == PE::kRelocAbsolute) continue; // Padding

                        if (type == PE::kRelocDir64) {
                            GuestAddress relocAddr = 0;
                            GuestAddress relocEnd = 0;
                            if (!AddGuest(loadBase,
                                          static_cast<GuestSize>(block->VirtualAddress) + offset,
                                          relocAddr) ||
                                !AddGuest(relocAddr, sizeof(uint64_t) - 1, relocEnd) ||
                                (relocEnd - loadBase) >= sizeOfImage) {
                                (void)m_impl->memory->Free(loadBase, sizeOfImage);
                                return std::nullopt;
                            }
                            uint64_t value = 0;
                            if (m_impl->memory->ReadU64(relocAddr, value) !=
                                ErrorCode::Success) {
                                (void)m_impl->memory->Free(loadBase, sizeOfImage);
                                return std::nullopt;
                            }
                            value += relocationDelta;
                            if (m_impl->memory->WriteU64(relocAddr, value) !=
                                ErrorCode::Success) {
                                (void)m_impl->memory->Free(loadBase, sizeOfImage);
                                return std::nullopt;
                            }
                            ++totalRelocs;
                        } else if (type == PE::kRelocHighLow) {
                            // 32-bit relocation (unusual in x64 drivers but legal)
                            GuestAddress relocAddr = 0;
                            GuestAddress relocEnd = 0;
                            if (!AddGuest(loadBase,
                                          static_cast<GuestSize>(block->VirtualAddress) + offset,
                                          relocAddr) ||
                                !AddGuest(relocAddr, sizeof(uint32_t) - 1, relocEnd) ||
                                (relocEnd - loadBase) >= sizeOfImage) {
                                (void)m_impl->memory->Free(loadBase, sizeOfImage);
                                return std::nullopt;
                            }
                            uint32_t value32 = 0;
                            if (m_impl->memory->ReadU32(relocAddr, value32) !=
                                ErrorCode::Success) {
                                (void)m_impl->memory->Free(loadBase, sizeOfImage);
                                return std::nullopt;
                            }
                            value32 += static_cast<uint32_t>(relocationDelta);
                            if (m_impl->memory->WriteU32(relocAddr, value32) !=
                                ErrorCode::Success) {
                                (void)m_impl->memory->Free(loadBase, sizeOfImage);
                                return std::nullopt;
                            }
                            ++totalRelocs;
                        }
                        // Other relocation types silently ignored for kernel drivers
                    }

                    if (totalRelocs >= kMaxRelocsPerDriver) break;
                    processed += block->SizeOfBlock;
                }

                driver.relocCount = totalRelocs;
            }
        }
    }

    // ------------------------------------------------------------------
    // 6. Resolve imports
    // ------------------------------------------------------------------

    const uint32_t importDirIdx = PE::kDirImport;
    if (importDirIdx < nt->OptionalHdr.NumberOfRvaAndSizes) {
        const uint32_t importRVA  = nt->OptionalHdr.DataDirectories[importDirIdx].VirtualAddress;
        const uint32_t importSize = nt->OptionalHdr.DataDirectories[importDirIdx].Size;

        if (importRVA != 0 && importSize >= sizeof(PE::ImportDescriptor)) {
            auto importFileOfs = RVAToFileOffset(importRVA, sections, sectionCount);
            if (importFileOfs) {
                uint32_t totalImports = 0;

                for (uint32_t descIdx = 0; ; ++descIdx) {
                    const uint64_t descDirOffset =
                        static_cast<uint64_t>(descIdx) * sizeof(PE::ImportDescriptor);
                    if (descDirOffset + sizeof(PE::ImportDescriptor) > importSize) {
                        break;
                    }
                    const size_t descOfs =
                        static_cast<size_t>(*importFileOfs) +
                        static_cast<size_t>(descDirOffset);
                    if (descOfs + sizeof(PE::ImportDescriptor) > driverImage.size())
                        break;

                    const auto* desc = reinterpret_cast<const PE::ImportDescriptor*>(
                                           driverImage.data() + descOfs);

                    // Terminal descriptor: all zero
                    if (desc->Name == 0 && desc->FirstThunk == 0) break;
                    if (desc->Name == 0) continue;

                    // Read DLL name
                    auto nameOfs = RVAToFileOffset(desc->Name, sections, sectionCount);
                    if (!nameOfs) continue;
                    std::string dllName = ReadStringFromImage(driverImage, *nameOfs);
                    if (dllName.empty()) continue;

                    // ILT and IAT RVAs
                    const uint32_t iltRVA = (desc->OriginalFirstThunk != 0)
                                                ? desc->OriginalFirstThunk
                                                : desc->FirstThunk;
                    const uint32_t iatRVA = desc->FirstThunk;
                    if (iltRVA == 0 || iatRVA == 0) continue;

                    auto iltOfs = RVAToFileOffset(iltRVA, sections, sectionCount);
                    if (!iltOfs) continue;
                    if (iatRVA >= sizeOfImage) continue;

                    for (uint32_t funcIdx = 0; ; ++funcIdx) {
                        if (totalImports >= kMaxImportsPerDriver) break;
                        if (funcIdx >= PE::kMaxImportsPerDLL) break;

                        const size_t entryOfs =
                            static_cast<size_t>(*iltOfs) + funcIdx * 8;
                        if (entryOfs + 8 > driverImage.size()) break;

                        uint64_t iltEntry = 0;
                        std::memcpy(&iltEntry,
                                    driverImage.data() + entryOfs, 8);
                        if (iltEntry == 0) break;

                        DriverImport imp;
                        imp.moduleName = dllName;
                        const GuestSize thunkOffset = static_cast<GuestSize>(funcIdx) * 8;
                        GuestAddress iatRvaWithIndex = 0;
                        if (!AddGuest(iatRVA, thunkOffset, iatRvaWithIndex) ||
                            iatRvaWithIndex > sizeOfImage ||
                            sizeOfImage - iatRvaWithIndex < sizeof(uint64_t) ||
                            !AddGuest(loadBase, iatRvaWithIndex, imp.iatEntry)) {
                            (void)m_impl->memory->Free(loadBase, sizeOfImage);
                            return std::nullopt;
                        }

                        if (iltEntry & PE::kImportByOrdinal64) {
                            imp.ordinal      = static_cast<uint16_t>(
                                                   iltEntry & PE::kOrdinalMask16);
                            imp.functionName = "Ordinal#" +
                                               std::to_string(imp.ordinal);
                        } else {
                            const auto hintRVA = static_cast<uint32_t>(iltEntry);
                            auto hintOfs = RVAToFileOffset(
                                hintRVA, sections, sectionCount);
                            if (hintOfs &&
                                static_cast<size_t>(*hintOfs) + 3 <= driverImage.size()) {
                                // Skip 2-byte Hint field
                                imp.functionName = ReadStringFromImage(
                                    driverImage,
                                    static_cast<size_t>(*hintOfs) + 2);
                            }
                            imp.ordinal = 0;
                        }

                        // Resolve from registered exports
                        auto resolved = m_impl->ResolveExportNoLock(
                            imp.moduleName, imp.functionName);
                        if (resolved) {
                            imp.resolvedAddress = *resolved;
                            imp.resolved        = true;
                        } else {
                            imp.resolvedAddress = 0;
                            imp.resolved        = false;
                        }

                        // Patch the IAT in guest memory
                        if (m_impl->memory->WriteU64(imp.iatEntry,
                                                     imp.resolvedAddress) != ErrorCode::Success) {
                            (void)m_impl->memory->Free(loadBase, sizeOfImage);
                            return std::nullopt;
                        }

                        driver.imports.push_back(std::move(imp));
                        ++totalImports;
                    }

                    if (totalImports >= kMaxImportsPerDriver) break;
                }

                driver.importCount = totalImports;
            }
        }
    }

    // ------------------------------------------------------------------
    // 7. Analyze import behavior for suspicious indicators
    // ------------------------------------------------------------------

    m_impl->AnalyzeImportBehavior(driver.imports, driver);

    // ------------------------------------------------------------------
    // 8. Apply per-section protections
    // ------------------------------------------------------------------

    for (const auto& ds : driver.sections) {
        const MemProt prot = SectionCharacteristicsToMemProt(ds.characteristics);
        if (!m_impl->memory->Protect(ds.virtualAddress,
                                     static_cast<GuestSize>(ds.virtualSize),
                                     prot)) {
            (void)m_impl->memory->Free(loadBase, sizeOfImage);
            return std::nullopt;
        }
    }

    // ------------------------------------------------------------------
    // 9. Create DRIVER_OBJECT in kernel memory
    // ------------------------------------------------------------------

    driver.driverObject = m_impl->CreateDriverObject(
        loadBase, sizeOfImage, driver.entryPoint);
    if (driver.driverObject == 0) {
        (void)m_impl->memory->Free(loadBase, sizeOfImage);
        return std::nullopt;
    }

    // ------------------------------------------------------------------
    // 10. Finalize and register
    // ------------------------------------------------------------------

    if ((std::numeric_limits<GuestSize>::max)() - m_impl->totalMappedSize < sizeOfImage) {
        (void)m_impl->memory->Free(driver.driverObject, kDriverObjSlotSize);
        (void)m_impl->memory->Free(loadBase, sizeOfImage);
        return std::nullopt;
    }
    if ((std::numeric_limits<uint32_t>::max)() - m_impl->totalImportCount < driver.importCount) {
        (void)m_impl->memory->Free(driver.driverObject, kDriverObjSlotSize);
        (void)m_impl->memory->Free(loadBase, sizeOfImage);
        return std::nullopt;
    }
    const GuestAddress driverObjectBase = driver.driverObject;
    try {
        m_impl->drivers.push_back(std::move(driver));
    } catch (const std::bad_alloc&) {
        (void)m_impl->memory->Free(driverObjectBase, kDriverObjSlotSize);
        (void)m_impl->memory->Free(loadBase, sizeOfImage);
        return std::nullopt;
    }

    m_impl->totalMappedSize += sizeOfImage;
    m_impl->totalImportCount += m_impl->drivers.back().importCount;

    return m_impl->drivers.back();
}

// ============================================================================
// UnloadDriver
// ============================================================================

bool DriverLoader::UnloadDriver(const std::string& driverName) {
    std::unique_lock lock(m_impl->mutex);
    if (!m_impl->memory) return false;

    auto it = std::find_if(
        m_impl->drivers.begin(), m_impl->drivers.end(),
        [&](const LoadedDriver& d) { return d.name == driverName; });

    if (it == m_impl->drivers.end()) return false;

    (void)m_impl->memory->Free(it->imageBase,
                          static_cast<GuestSize>(it->imageSize));
    if (it->driverObject != 0) {
        (void)m_impl->memory->Free(it->driverObject, kDriverObjSlotSize);
    }

    m_impl->totalMappedSize = (m_impl->totalMappedSize >= it->imageSize)
                                  ? m_impl->totalMappedSize - it->imageSize
                                  : 0;
    m_impl->totalImportCount = (m_impl->totalImportCount >= it->importCount)
                                   ? m_impl->totalImportCount - it->importCount
                                   : 0;
    m_impl->drivers.erase(it);
    return true;
}

// ============================================================================
// Query methods
// ============================================================================

std::optional<LoadedDriver> DriverLoader::FindDriver(const std::string& name) const {
    std::shared_lock lock(m_impl->mutex);
    for (const auto& d : m_impl->drivers) {
        if (d.name == name) return d;
    }
    return std::nullopt;
}

std::optional<LoadedDriver> DriverLoader::FindDriverByAddress(GuestAddress addr) const {
    std::shared_lock lock(m_impl->mutex);
    for (const auto& d : m_impl->drivers) {
        if (addr >= d.imageBase && (addr - d.imageBase) < d.imageSize)
            return d;
    }
    return std::nullopt;
}

std::vector<LoadedDriver> DriverLoader::GetLoadedDrivers() const {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->drivers;
}

uint32_t DriverLoader::GetDriverCount() const {
    std::shared_lock lock(m_impl->mutex);
    return static_cast<uint32_t>(m_impl->drivers.size());
}

// ============================================================================
// Kernel export resolution
// ============================================================================

std::optional<GuestAddress> DriverLoader::ResolveKernelExport(
    const std::string& moduleName,
    const std::string& functionName) const
{
    std::shared_lock lock(m_impl->mutex);
    return m_impl->ResolveExportNoLock(moduleName, functionName);
}

std::vector<KernelExport> DriverLoader::GetRegisteredExports() const {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->exports;
}

void DriverLoader::RegisterKernelExport(
    const std::string& module,
    const std::string& function,
    GuestAddress addr)
{
    std::unique_lock lock(m_impl->mutex);
    (void)m_impl->RegisterExportNoLock(module, function, addr);
}

// ============================================================================
// Statistics
// ============================================================================

GuestSize DriverLoader::GetTotalMappedSize() const {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->totalMappedSize;
}

uint32_t DriverLoader::GetTotalImportCount() const {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->totalImportCount;
}

// ============================================================================
// AnalyzeDriverSecurity — produce a security report for a loaded driver
// ============================================================================

DriverLoader::DriverSecurityReport DriverLoader::AnalyzeDriverSecurity(
    const LoadedDriver& driver) const
{
    std::shared_lock lock(m_impl->mutex);

    DriverSecurityReport report;
    report.driverName         = driver.name;
    report.unresolvedImports  = 0;
    report.hasSuspiciousImports = false;
    report.isPackedOrEncrypted  = false;
    report.entropy            = 0.0f;

    // --- Count unresolved imports ---
    for (const auto& imp : driver.imports) {
        if (!imp.resolved) ++report.unresolvedImports;
    }

    // --- Compute entropy of first executable section ---
    for (const auto& sec : driver.sections) {
        if (!sec.isExecutable) continue;
        // Cap read to 1 MB to bound allocation
        const uint32_t readSize = std::min<uint32_t>(sec.rawDataSize,
                                                     1024 * 1024);
        if (readSize == 0) continue;
        std::vector<uint8_t> buf(readSize);
        auto err = m_impl->memory->Read(sec.virtualAddress,
                                        buf.data(), readSize);
        if (err == ErrorCode::Success) {
            report.entropy = CalculateEntropy(buf.data(), buf.size());
            if (report.entropy > 7.0f) {
                report.isPackedOrEncrypted = true;
            }
        }
        break; // Only first executable section
    }

    // --- Suspicious API detection ---
    static const char* const kSuspiciousAPIs[] = {
        "KeServiceDescriptorTable",
        "KeAttachProcess",
        "KeStackAttachProcess",
        "PsGetProcessPeb",
        "MmMapIoSpace",
        "MmMapLockedPagesSpecifyCache",
        "ZwWriteVirtualMemory",
        "MmGetSystemRoutineAddress",
        "KeBugCheckEx",
        "KeBugCheck",
        "ZwQuerySystemInformation",
    };

    for (const auto& imp : driver.imports) {
        const std::string funcLower = ToLower(imp.functionName);
        for (const char* suspect : kSuspiciousAPIs) {
            if (funcLower == ToLower(suspect)) {
                report.suspiciousAPIs.push_back(imp.functionName);
                report.hasSuspiciousImports = true;
                break;
            }
        }
    }

    // --- Check for dangerous combinations ---
    bool hasAttach = driver.callsKeAttachProcess;
    bool hasMemWrite = false;
    for (const auto& imp : driver.imports) {
        const std::string fl = ToLower(imp.functionName);
        if (fl == "zwwritevirtualmemory" || fl == "ntwritevirtualmemory" ||
            fl == "zwallocatevirtualmemory") {
            hasMemWrite = true;
            break;
        }
    }

    // --- MITRE ATT&CK mapping ---
    // T1543.003 — every kernel driver is a Windows service
    report.mitreTechniques.push_back("T1543.003");

    if (driver.accessesSSDT || driver.accessesIDT) {
        report.mitreTechniques.push_back("T1014"); // Rootkit
    }
    if (driver.modifiesCR0 || driver.disablesWP) {
        report.mitreTechniques.push_back("T1068"); // Privilege Escalation
    }
    if (hasAttach && hasMemWrite) {
        report.mitreTechniques.push_back("T1055"); // Process Injection
    }
    if (driver.manipulatesPEB) {
        report.mitreTechniques.push_back("T1055.012"); // Process Hollowing
    }
    if (driver.usesMMAPIO) {
        report.mitreTechniques.push_back("T1006"); // Direct Volume Access
    }

    // Deduplicate technique IDs
    std::sort(report.mitreTechniques.begin(), report.mitreTechniques.end());
    report.mitreTechniques.erase(
        std::unique(report.mitreTechniques.begin(),
                    report.mitreTechniques.end()),
        report.mitreTechniques.end());

    return report;
}

} // namespace Phantom
