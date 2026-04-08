/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * KernelStructures — Emulated Windows kernel objects for DKOM detection
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "KernelStructures.hpp"
#include "../Memory/VirtualMemory.hpp"

#include <algorithm>
#include <cstring>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

namespace Phantom {

// ============================================================================
// Guest-address layout for emulated kernel objects
// ============================================================================

static constexpr GuestAddress kEprocessPoolBase  = 0xFFFF800010000000ULL;
static constexpr GuestAddress kEprocessStride    = 0x1000;
static constexpr GuestAddress kThreadPoolBase    = 0xFFFF800020000000ULL;
static constexpr GuestAddress kThreadStride      = 0x800;
static constexpr GuestAddress kDriverPoolBase    = 0xFFFF800030000000ULL;
static constexpr GuestAddress kDriverStride      = 0x1000;
static constexpr GuestAddress kSsdtBaseAddress   = 0xFFFFF80001000000ULL;
static constexpr GuestAddress kIdtBaseAddress    = 0xFFFFF80002000000ULL;
static constexpr GuestAddress kSsdtFuncBase      = 0xFFFFF80003000000ULL;
static constexpr GuestAddress kIdtHandlerBase    = 0xFFFFF80004000000ULL;
static constexpr GuestAddress kTokenPoolBase     = 0xFFFF800040000000ULL;

// ============================================================================
// Windows 10/11 SSDT syscall table (top 50 most-abused + many more)
// ============================================================================

struct SyscallDef {
    uint32_t    number;
    const char* name;
};

// Service numbers sourced from Windows 10 21H2/22H2 x64 ntoskrnl
static constexpr SyscallDef kSyscallTable[] = {
    {0x0000, "NtAccessCheck"},
    {0x0001, "NtWorkerFactoryWorkerReady"},
    {0x0002, "NtAcceptConnectPort"},
    {0x0003, "NtMapUserPhysicalPagesScatter"},
    {0x0004, "NtWaitForSingleObject"},
    {0x0005, "NtCallbackReturn"},
    {0x0006, "NtReadFile"},
    {0x0007, "NtDeviceIoControlFile"},
    {0x0008, "NtWriteFile"},
    {0x0009, "NtRemoveIoCompletion"},
    {0x000A, "NtReleaseSemaphore"},
    {0x000B, "NtReplyWaitReceivePort"},
    {0x000C, "NtReplyPort"},
    {0x000D, "NtSetInformationThread"},
    {0x000E, "NtSetEvent"},
    {0x000F, "NtClose"},
    {0x0010, "NtQueryObject"},
    {0x0011, "NtQueryInformationFile"},
    {0x0012, "NtOpenKey"},
    {0x0013, "NtEnumerateValueKey"},
    {0x0014, "NtFindAtom"},
    {0x0015, "NtQueryDefaultLocale"},
    {0x0016, "NtQueryKey"},
    {0x0017, "NtQueryValueKey"},
    {0x0018, "NtAllocateVirtualMemory"},
    {0x0019, "NtQueryInformationProcess"},
    {0x001A, "NtWaitForMultipleObjects32"},
    {0x001B, "NtWriteFileGather"},
    {0x001C, "NtSetInformationProcess"},
    {0x001D, "NtCreateKey"},
    {0x001E, "NtFreeVirtualMemory"},
    {0x001F, "NtImpersonateClientOfPort"},
    {0x0020, "NtReleaseMutant"},
    {0x0021, "NtQueryInformationToken"},
    {0x0022, "NtRequestWaitReplyPort"},
    {0x0023, "NtQueryVirtualMemory"},
    {0x0024, "NtOpenThreadToken"},
    {0x0025, "NtQueryInformationThread"},
    {0x0026, "NtOpenProcess"},
    {0x0027, "NtSetInformationFile"},
    {0x0028, "NtMapViewOfSection"},
    {0x0029, "NtAccessCheckAndAuditAlarm"},
    {0x002A, "NtUnmapViewOfSection"},
    {0x002B, "NtReplyWaitReceivePortEx"},
    {0x002C, "NtTerminateProcess"},
    {0x002D, "NtSetEventBoostPriority"},
    {0x002E, "NtReadFileScatter"},
    {0x002F, "NtOpenThreadTokenEx"},
    {0x0030, "NtOpenProcessTokenEx"},
    {0x0031, "NtQueryDirectoryFile"},
    {0x0032, "NtQuerySystemInformation"},
    {0x0033, "NtOpenToken"},
    {0x0034, "NtYieldExecution"},
    {0x0035, "NtResumeThread"},
    {0x0036, "NtRemoveIoCompletionEx"},
    {0x0037, "NtAlpcSendWaitReceivePort"},
    {0x0038, "NtWaitForWorkViaWorkerFactory"},
    {0x0039, "NtQuerySystemEnvironmentValueEx"},
    {0x003A, "NtDelayExecution"},
    {0x003B, "NtWaitForAlertByThreadId"},
    {0x003C, "NtAlertThreadByThreadId"},
    {0x003D, "NtCancelIoFileEx"},
    {0x003E, "NtCancelSynchronousIoFile"},
    {0x003F, "NtQueryEaFile"},
    {0x0040, "NtQueryDirectoryFileEx"},
    {0x0041, "NtCancelIoFile"},
    {0x0042, "NtClearEvent"},
    {0x0043, "NtReadVirtualMemory"},
    {0x0044, "NtOpenEvent"},
    {0x0045, "NtAdjustPrivilegesToken"},
    {0x0046, "NtDuplicateToken"},
    {0x0047, "NtContinue"},
    {0x0048, "NtQueryDefaultUILanguage"},
    {0x0049, "NtQueueApcThread"},
    {0x004A, "NtYieldExecution2"},
    {0x004B, "NtAddAtom"},
    {0x004C, "NtCreateEvent"},
    {0x004D, "NtQueryVolumeInformationFile"},
    {0x004E, "NtCreateSection"},
    {0x004F, "NtFlushBuffersFile"},
    {0x0050, "NtProtectVirtualMemory"},
    {0x0051, "NtOpenSection"},
    {0x0052, "NtFlushBuffersFileEx"},
    {0x0053, "NtConnectPort"},
    {0x0054, "NtOpenDirectoryObject"},
    {0x0055, "NtCreateFile"},
    {0x0056, "NtQueryAttributesFile"},
    {0x0057, "NtDuplicateObject"},
    {0x0058, "NtOpenThread"},
    {0x0059, "NtQueryPerformanceCounter"},
    {0x005A, "NtCompareTokens"},
    {0x005B, "NtLockFile"},
    {0x005C, "NtSignalAndWaitForSingleObject"},
    {0x005D, "NtOpenKeyEx"},
    {0x005E, "NtCreateKeyTransacted"},
    {0x005F, "NtQueryFullAttributesFile"},
    {0x0060, "NtOpenKeyTransacted"},
    {0x0061, "NtFlushKey"},
    {0x0062, "NtOpenProcessToken"},
    {0x0063, "NtQuerySecurityObject"},
    {0x0064, "NtQuerySystemTime"},
    {0x0065, "NtEnumerateKey"},
    {0x0066, "NtTerminateThread"},
    {0x0067, "NtSetValueKey"},
    {0x0068, "NtDeleteKey"},
    {0x0069, "NtCreateNamedPipeFile"},
    {0x006A, "NtDeleteValueKey"},
    {0x006B, "NtFsControlFile"},
    {0x006C, "NtSuspendThread"},
    {0x006D, "NtWriteVirtualMemory"},
    {0x006E, "NtNotifyChangeKey"},
    {0x006F, "NtQueryMultipleValueKey"},
    {0x0070, "NtSetInformationKey"},
    {0x0071, "NtCreateThread"},
    {0x0072, "NtWaitForMultipleObjects"},
    {0x0073, "NtSetTimer2"},
    {0x0074, "NtCreateTimer2"},
    {0x0075, "NtSuspendProcess"},
    {0x0076, "NtResumeProcess"},
    {0x0077, "NtGetCurrentProcessorNumber"},
    {0x0078, "NtSetContextThread"},
    {0x0079, "NtGetContextThread"},
    {0x007A, "NtRaiseException"},
    {0x007B, "NtCreateMutant"},
    {0x007C, "NtOpenMutant"},
    {0x007D, "NtQueryMutant"},
    {0x007E, "NtReleaseSemaphoreEx"},
    {0x007F, "NtUserGetMessage"},
    {0x0080, "NtCreateSemaphore"},
    {0x0081, "NtOpenSemaphore"},
    {0x0082, "NtSecureConnectPort"},
    {0x0083, "NtCreateSymbolicLinkObject"},
    {0x0084, "NtOpenSymbolicLinkObject"},
    {0x0085, "NtQuerySymbolicLinkObject"},
    {0x0086, "NtQuerySystemEnvironmentValue"},
    {0x0087, "NtSetSystemEnvironmentValue"},
    {0x0088, "NtOpenFile"},
    {0x0089, "NtCreateMailslotFile"},
    {0x008A, "NtSetEaFile"},
    {0x008B, "NtCreateIoCompletion"},
    {0x008C, "NtOpenIoCompletion"},
    {0x008D, "NtSetIoCompletion"},
    {0x008E, "NtSetSystemInformation"},
    {0x008F, "NtOpenTimer"},
    {0x0090, "NtSetTimerEx"},
    {0x0091, "NtCancelTimer"},
    {0x0092, "NtQueryTimer"},
    {0x0093, "NtSetIntervalProfile"},
    {0x0094, "NtQueryIntervalProfile"},
    {0x0095, "NtRegisterThreadTerminatePort"},
    {0x0096, "NtSetSecurityObject"},
    {0x0097, "NtQuerySection"},
    {0x0098, "NtCreateTimer"},
    {0x0099, "NtLoadDriver"},
    {0x009A, "NtUnloadDriver"},
    {0x009B, "NtRaiseHardError"},
    {0x009C, "NtCreateThreadEx"},
    {0x009D, "NtOpenJobObject"},
    {0x009E, "NtCreateJobObject"},
    {0x009F, "NtAssignProcessToJobObject"},
    {0x00A0, "NtTerminateJobObject"},
    {0x00A1, "NtIsProcessInJob"},
    {0x00A2, "NtSetInformationJobObject"},
    {0x00A3, "NtQueryInformationJobObject"},
    {0x00A4, "NtCreateDirectoryObject"},
    {0x00A5, "NtOpenDirectoryObjectEx"},
    {0x00A6, "NtCreateUserProcess"},
    {0x00A7, "NtCreateProfile"},
    {0x00A8, "NtStartProfile"},
    {0x00A9, "NtStopProfile"},
    {0x00AA, "NtSetInformationToken"},
    {0x00AB, "NtFilterToken"},
    {0x00AC, "NtCompareObjects"},
    {0x00AD, "NtAlpcCreatePort"},
    {0x00AE, "NtAlpcConnectPort"},
    {0x00AF, "NtAlpcAcceptConnectPort"},
    {0x00B0, "NtAlpcSendWaitReceive"},
    {0x00B1, "NtAlpcCancelMessage"},
    {0x00B2, "NtAlpcDisconnectPort"},
    {0x00B3, "NtAlpcCreatePortSection"},
    {0x00B4, "NtAlpcDeletePortSection"},
    {0x00B5, "NtAlpcCreateResourceReserve"},
    {0x00B6, "NtAlpcDeleteResourceReserve"},
    {0x00B7, "NtAlpcCreateSectionView"},
    {0x00B8, "NtAlpcDeleteSectionView"},
    {0x00B9, "NtAlpcCreateSecurityContext"},
    {0x00BA, "NtAlpcDeleteSecurityContext"},
    {0x00BB, "NtAlpcRevokeSecurityContext"},
    {0x00BC, "NtAlpcQueryInformation"},
    {0x00BD, "NtAlpcSetInformation"},
    {0x00BE, "NtAlpcQueryInformationMessage"},
    {0x00BF, "NtAlpcConnectPortEx"},
    {0x00C0, "NtTraceEvent"},
    {0x00C1, "NtTraceControl"},
    {0x00C2, "NtCreateWnfStateName"},
    {0x00C3, "NtDeleteWnfStateName"},
    {0x00C4, "NtUpdateWnfStateData"},
    {0x00C5, "NtQueryWnfStateData"},
    {0x00C6, "NtSubscribeWnfStateChange"},
    {0x00C7, "NtUnsubscribeWnfStateChange"},
    {0x00C8, "NtCreateWnfSubscription"},
    {0x00C9, "NtDeleteWnfSubscription"},
    {0x00CA, "NtSetInformationWorkerFactory"},
    {0x00CB, "NtQueryInformationWorkerFactory"},
    {0x00CC, "NtCreateWorkerFactory"},
    {0x00CD, "NtShutdownWorkerFactory"},
    {0x00CE, "NtReleaseWorkerFactoryWorker"},
    {0x00CF, "NtWaitForWorkViaWorkerFactory2"},
    {0x00D0, "NtWorkerFactoryWorkerReady2"},
    {0x00D1, "NtPowerInformation"},
    {0x00D2, "NtInitiatePowerAction"},
    {0x00D3, "NtSetSystemPowerState"},
    {0x00D4, "NtGetPlugPlayEvent"},
    {0x00D5, "NtPlugPlayControl"},
    {0x00D6, "NtCreateTransaction"},
    {0x00D7, "NtOpenTransaction"},
    {0x00D8, "NtCommitTransaction"},
    {0x00D9, "NtRollbackTransaction"},
    {0x00DA, "NtCreateResourceManager"},
    {0x00DB, "NtOpenResourceManager"},
    {0x00DC, "NtCreateEnlistment"},
    {0x00DD, "NtOpenEnlistment"},
    {0x00DE, "NtPrepareEnlistment"},
    {0x00DF, "NtPrePrepareEnlistment"},
    {0x00E0, "NtCommitEnlistment"},
    {0x00E1, "NtRollbackEnlistment"},
    {0x00E2, "NtCommitComplete"},
    {0x00E3, "NtRollbackComplete"},
    {0x00E4, "NtPrepareComplete"},
    {0x00E5, "NtPrePrepareComplete"},
    {0x00E6, "NtSinglePhaseReject"},
    {0x00E7, "NtCreateTransactionManager"},
    {0x00E8, "NtOpenTransactionManager"},
    {0x00E9, "NtGetNotificationResourceManager"},
    {0x00EA, "NtRecoverTransactionManager"},
    {0x00EB, "NtRecoverResourceManager"},
    {0x00EC, "NtRecoverEnlistment"},
    {0x00ED, "NtFreezeTransactions"},
    {0x00EE, "NtThawTransactions"},
    {0x00EF, "NtPropagationComplete"},
    {0x00F0, "NtPropagationFailed"},
    {0x00F1, "NtSetCachedSigningLevel"},
    {0x00F2, "NtGetCachedSigningLevel"},
    {0x00F3, "NtCompareSigningLevels"},
    {0x00F4, "NtCreateRegistryTransaction"},
    {0x00F5, "NtOpenRegistryTransaction"},
    {0x00F6, "NtCommitRegistryTransaction"},
    {0x00F7, "NtRollbackRegistryTransaction"},
    {0x00F8, "NtNotifyChangeDirectoryFile"},
    {0x00F9, "NtNotifyChangeDirectoryFileEx"},
    {0x00FA, "NtMapViewOfSectionEx"},
    {0x00FB, "NtUnmapViewOfSectionEx"},
    {0x00FC, "NtCreatePartition"},
    {0x00FD, "NtOpenPartition"},
    {0x00FE, "NtManagePartition"},
    {0x00FF, "NtSetSystemEnvironmentValueEx"},
    {0x0100, "NtFlushInstallUILanguage"},
    {0x0101, "NtQueryInstallUILanguage"},
    {0x0102, "NtSetDefaultUILanguage"},
    {0x0103, "NtQueryDefaultUILanguageEx"},
    {0x0104, "NtGetNlsSectionPtr"},
    {0x0105, "NtMapCMFModule"},
    {0x0106, "NtUnloadKey2"},
    {0x0107, "NtLoadKeyEx"},
    {0x0108, "NtUnloadKeyEx"},
    {0x0109, "NtSaveMergedKeys"},
    {0x010A, "NtSetBootOptions"},
    {0x010B, "NtQueryBootOptions"},
    {0x010C, "NtQueryBootEntryOrder"},
    {0x010D, "NtSetBootEntryOrder"},
    {0x010E, "NtAddBootEntry"},
    {0x010F, "NtDeleteBootEntry"},
    {0x0110, "NtModifyBootEntry"},
    {0x0111, "NtEnumerateBootEntries"},
    {0x0112, "NtAddDriverEntry"},
    {0x0113, "NtDeleteDriverEntry"},
    {0x0114, "NtModifyDriverEntry"},
    {0x0115, "NtEnumerateDriverEntries"},
    {0x0116, "NtQueryDriverEntryOrder"},
    {0x0117, "NtSetDriverEntryOrder"},
    {0x0118, "NtSetLdtEntries"},
    {0x0119, "NtQueryOpenSubKeysEx"},
    {0x011A, "NtCompressKey"},
    {0x011B, "NtLockRegistryKey"},
    {0x011C, "NtThawRegistry"},
    {0x011D, "NtFreezeRegistry"},
    {0x011E, "NtQueryLicenseValue"},
    {0x011F, "NtCompactKeys"},
    {0x0120, "NtLockProductActivationKeys"},
    {0x0121, "NtSaveKeyEx"},
    {0x0122, "NtRestoreKey"},
    {0x0123, "NtSaveKey"},
    {0x0124, "NtReplaceKey"},
    {0x0125, "NtRenameKey"},
    {0x0126, "NtLoadKey"},
    {0x0127, "NtUnloadKey"},
    {0x0128, "NtQueryOpenSubKeys"},
    {0x0129, "NtEnumerateSystemEnvironmentValuesEx"},
    {0x012A, "NtSetSystemTime"},
    {0x012B, "NtAssignProcessToJobObjectEx"},
    {0x012C, "NtWaitForDebugEvent"},
    {0x012D, "NtDebugActiveProcess"},
    {0x012E, "NtDebugContinue"},
    {0x012F, "NtRemoveProcessDebug"},
    {0x0130, "NtCreateDebugObject"},
    {0x0131, "NtSetInformationDebugObject"},
    {0x0132, "NtPrivilegeCheck"},
    {0x0133, "NtPrivilegedServiceAuditAlarm"},
    {0x0134, "NtPrivilegeObjectAuditAlarm"},
    {0x0135, "NtAccessCheckByType"},
    {0x0136, "NtAccessCheckByTypeAndAuditAlarm"},
    {0x0137, "NtAccessCheckByTypeResultList"},
    {0x0138, "NtAccessCheckByTypeResultListAndAuditAlarm"},
    {0x0139, "NtAccessCheckByTypeResultListAndAuditAlarmByHandle"},
    {0x013A, "NtObjectManagerSetInformation"},
    {0x013B, "NtCreateCrossVmMutant"},
    {0x013C, "NtCreateCrossVmEvent"},
    {0x013D, "NtOpenKeyedEvent"},
    {0x013E, "NtCreateKeyedEvent"},
    {0x013F, "NtReleaseKeyedEvent"},
    {0x0140, "NtWaitForKeyedEvent"},
    {0x0141, "NtCreatePort"},
    {0x0142, "NtCreateWaitablePort"},
    {0x0143, "NtListenPort"},
    {0x0144, "NtRequestPort"},
    {0x0145, "NtCompleteConnectPort"},
    {0x0146, "NtImpersonateAnonymousToken"},
    {0x0147, "NtMakeTemporaryObject"},
    {0x0148, "NtMakePermanentObject"},
    {0x0149, "NtWaitHighEventPair"},
    {0x014A, "NtWaitLowEventPair"},
    {0x014B, "NtSetHighWaitLowEventPair"},
    {0x014C, "NtSetLowWaitHighEventPair"},
    {0x014D, "NtSetHighEventPair"},
    {0x014E, "NtSetLowEventPair"},
    {0x014F, "NtOpenEventPair"},
    {0x0150, "NtCreateEventPair"},
    {0x0151, "NtDisableLastKnownGood"},
    {0x0152, "NtEnableLastKnownGood"},
    {0x0153, "NtTestAlert"},
    {0x0154, "NtAlertResumeThread"},
    {0x0155, "NtAlertThread"},
    {0x0156, "NtQueryDebugFilterState"},
    {0x0157, "NtSetDebugFilterState"},
    {0x0158, "NtApphelpCacheControl"},
    {0x0159, "NtFlushProcessWriteBuffers"},
    {0x015A, "NtQueryProcessInformation"},
    {0x015B, "NtInitializeNlsFiles"},
    {0x015C, "NtMapUserPhysicalPages"},
    {0x015D, "NtAllocateUserPhysicalPages"},
    {0x015E, "NtFreeUserPhysicalPages"},
    {0x015F, "NtAreMappedFilesTheSame"},
    {0x0160, "NtCreatePagingFile"},
    {0x0161, "NtExtendSection"},
    {0x0162, "NtLockVirtualMemory"},
    {0x0163, "NtUnlockVirtualMemory"},
    {0x0164, "NtQueryVirtualMemoryEx"},
    {0x0165, "NtAllocateVirtualMemoryEx"},
    {0x0166, "NtFlushVirtualMemory"},
    {0x0167, "NtGetWriteWatch"},
    {0x0168, "NtResetWriteWatch"},
    {0x0169, "NtCreateProcessEx"},
    {0x016A, "NtCreateProcess"},
    {0x016B, "NtOpenProcess2"},
    {0x016C, "NtQueueApcThreadEx"},
    {0x016D, "NtQueueApcThreadEx2"},
    {0x016E, "NtSetInformationVirtualMemory"},
    {0x016F, "NtSetIoCompletionEx"},
    {0x0170, "NtRemoveIoCompletionEx2"},
    {0x0171, "NtWaitForMultipleObjects2"},
    {0x0172, "NtCreateEnclave"},
    {0x0173, "NtInitializeEnclave"},
    {0x0174, "NtLoadEnclaveData"},
    {0x0175, "NtCallEnclave"},
    {0x0176, "NtTerminateEnclave"},
    {0x0177, "NtDeleteEnclave"},
    {0x0178, "NtIsUILanguageComitted"},
    {0x0179, "NtQueryInformationByName"},
    {0x017A, "NtCreatePrivateNamespace"},
    {0x017B, "NtOpenPrivateNamespace"},
    {0x017C, "NtDeletePrivateNamespace"},
    {0x017D, "NtSetInformationSymbolicLink"},
    {0x017E, "NtQueryInformationPort"},
    {0x017F, "NtSetPortInformation"},
};

static constexpr size_t kSyscallTableSize = sizeof(kSyscallTable) / sizeof(kSyscallTable[0]);

// ============================================================================
// IDT vector names (CPU exceptions, 0-31)
// ============================================================================

struct IDTVectorDef {
    uint8_t     vector;
    const char* name;
    uint8_t     dpl;        // Privilege level
    uint8_t     ist;        // IST index (0 = legacy stack)
};

static constexpr IDTVectorDef kIDTVectors[] = {
    { 0,  "DivideError",                0, 0},
    { 1,  "Debug",                      0, 0},
    { 2,  "NMI",                        0, 1},
    { 3,  "Breakpoint",                 3, 0},
    { 4,  "Overflow",                   3, 0},
    { 5,  "BoundRange",                 0, 0},
    { 6,  "InvalidOpcode",              0, 0},
    { 7,  "DeviceNotAvailable",         0, 0},
    { 8,  "DoubleFault",                0, 2},
    { 9,  "CoprocessorSegOverrun",      0, 0},
    {10,  "InvalidTSS",                 0, 0},
    {11,  "SegmentNotPresent",          0, 0},
    {12,  "StackSegmentFault",          0, 0},
    {13,  "GeneralProtection",          0, 0},
    {14,  "PageFault",                  0, 0},
    {15,  "Reserved15",                 0, 0},
    {16,  "x87FloatingPoint",           0, 0},
    {17,  "AlignmentCheck",             0, 0},
    {18,  "MachineCheck",               0, 3},
    {19,  "SIMDFloatingPoint",          0, 0},
    {20,  "VirtualizationException",    0, 0},
    {21,  "ControlProtection",          0, 0},
    {22,  "Reserved22",                 0, 0},
    {23,  "Reserved23",                 0, 0},
    {24,  "Reserved24",                 0, 0},
    {25,  "Reserved25",                 0, 0},
    {26,  "Reserved26",                 0, 0},
    {27,  "Reserved27",                 0, 0},
    {28,  "HypervisorInjection",        0, 0},
    {29,  "VMMCommunication",           0, 0},
    {30,  "SecurityException",          0, 0},
    {31,  "Reserved31",                 0, 0},
};

static constexpr size_t kIDTVectorCount = sizeof(kIDTVectors) / sizeof(kIDTVectors[0]);

// ============================================================================
// PIMPL Implementation
// ============================================================================

struct KernelObjectManager::Impl {
    mutable std::shared_mutex mutex;

    VirtualMemory* memory = nullptr;
    bool initialized      = false;

    // Process tracking — ordered for deterministic iteration
    std::vector<EmulatedEPROCESS> processes;
    std::unordered_map<uint32_t, size_t> pidIndex;

    // Thread tracking
    std::vector<EmulatedKTHREAD> threads;
    std::unordered_map<uint32_t, size_t> tidIndex;

    // Driver tracking
    std::vector<EmulatedDriverObject> drivers;

    // System tables
    SSDT ssdt;
    std::vector<IDTEntry> idt;

    // Token snapshot: maps pid → original token address
    std::unordered_map<uint32_t, GuestAddress> originalTokens;

    // Counters for guest address allocation
    uint32_t nextProcessSlot = 0;
    uint32_t nextThreadSlot  = 0;
    uint32_t nextDriverSlot  = 0;
    uint32_t nextTokenSlot   = 0;

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    [[nodiscard]] GuestAddress AllocProcessAddress() {
        if (nextProcessSlot >= kMaxEmulatedProcesses) return 0;
        return kEprocessPoolBase + static_cast<GuestAddress>(nextProcessSlot++) * kEprocessStride;
    }

    [[nodiscard]] GuestAddress AllocThreadAddress() {
        if (nextThreadSlot >= kMaxEmulatedThreads) return 0;
        return kThreadPoolBase + static_cast<GuestAddress>(nextThreadSlot++) * kThreadStride;
    }

    [[nodiscard]] GuestAddress AllocDriverAddress() {
        if (nextDriverSlot >= kMaxEmulatedDrivers) return 0;
        return kDriverPoolBase + static_cast<GuestAddress>(nextDriverSlot++) * kDriverStride;
    }

    [[nodiscard]] GuestAddress AllocTokenAddress() {
        return kTokenPoolBase + static_cast<GuestAddress>(nextTokenSlot++) * 0x100;
    }

    // Link a new EPROCESS into the circular doubly-linked list
    void LinkProcess(EmulatedEPROCESS& proc) {
        if (processes.size() <= 1) {
            proc.activeProcessLinks_Flink = proc.selfPtr;
            proc.activeProcessLinks_Blink = proc.selfPtr;
            return;
        }
        // Insert at tail: last existing node's Flink → new, new's Flink → head
        auto& head = processes[0];
        auto& tail = processes[processes.size() - 2]; // previous last entry

        proc.activeProcessLinks_Flink = head.selfPtr;
        proc.activeProcessLinks_Blink = tail.selfPtr;
        tail.activeProcessLinks_Flink = proc.selfPtr;
        head.activeProcessLinks_Blink = proc.selfPtr;
    }

    // Unlink an EPROCESS from the circular doubly-linked list
    void UnlinkProcess(size_t index) {
        if (processes.empty()) return;
        auto& dying = processes[index];

        // Find the prev and next by selfPtr
        EmulatedEPROCESS* prev = nullptr;
        EmulatedEPROCESS* next = nullptr;
        for (auto& p : processes) {
            if (p.selfPtr == dying.activeProcessLinks_Blink) prev = &p;
            if (p.selfPtr == dying.activeProcessLinks_Flink) next = &p;
        }
        if (prev) prev->activeProcessLinks_Flink = dying.activeProcessLinks_Flink;
        if (next) next->activeProcessLinks_Blink = dying.activeProcessLinks_Blink;
    }

    // Rebuild index maps after vector mutations
    void RebuildProcessIndex() {
        pidIndex.clear();
        pidIndex.reserve(processes.size());
        for (size_t i = 0; i < processes.size(); ++i) {
            pidIndex[processes[i].uniqueProcessId] = i;
        }
    }

    void RebuildThreadIndex() {
        tidIndex.clear();
        tidIndex.reserve(threads.size());
        for (size_t i = 0; i < threads.size(); ++i) {
            tidIndex[threads[i].threadId] = i;
        }
    }

    // Walk linked list forward from head; returns count of unique nodes visited
    [[nodiscard]] uint32_t WalkForward() const {
        if (processes.empty()) return 0;
        uint32_t count = 0;
        GuestAddress cur = processes[0].selfPtr;
        GuestAddress start = cur;
        uint32_t limit = static_cast<uint32_t>(processes.size()) + 1;
        do {
            const EmulatedEPROCESS* found = nullptr;
            for (const auto& p : processes) {
                if (p.selfPtr == cur) { found = &p; break; }
            }
            if (!found) break;
            ++count;
            cur = found->activeProcessLinks_Flink;
            if (count > limit) break; // cycle detection
        } while (cur != start);
        return count;
    }

    // Walk linked list backward from head
    [[nodiscard]] uint32_t WalkBackward() const {
        if (processes.empty()) return 0;
        uint32_t count = 0;
        GuestAddress cur = processes[0].selfPtr;
        GuestAddress start = cur;
        uint32_t limit = static_cast<uint32_t>(processes.size()) + 1;
        do {
            const EmulatedEPROCESS* found = nullptr;
            for (const auto& p : processes) {
                if (p.selfPtr == cur) { found = &p; break; }
            }
            if (!found) break;
            ++count;
            cur = found->activeProcessLinks_Blink;
            if (count > limit) break;
        } while (cur != start);
        return count;
    }
};

// ============================================================================
// Singleton
// ============================================================================

KernelObjectManager& KernelObjectManager::Instance() {
    static KernelObjectManager instance;
    return instance;
}

KernelObjectManager::KernelObjectManager()
    : m_impl(std::make_unique<Impl>()) {}

KernelObjectManager::~KernelObjectManager() = default;

// ============================================================================
// Initialization / Reset
// ============================================================================

void KernelObjectManager::Reset() {
    std::unique_lock lock(m_impl->mutex);

    m_impl->memory = nullptr;
    m_impl->initialized = false;
    m_impl->processes.clear();
    m_impl->pidIndex.clear();
    m_impl->threads.clear();
    m_impl->tidIndex.clear();
    m_impl->drivers.clear();
    m_impl->ssdt = SSDT{};
    m_impl->idt.clear();
    m_impl->originalTokens.clear();
    m_impl->nextProcessSlot = 0;
    m_impl->nextThreadSlot  = 0;
    m_impl->nextDriverSlot  = 0;
    m_impl->nextTokenSlot   = 0;
}

bool KernelObjectManager::Initialize(VirtualMemory& memory) {
    std::unique_lock lock(m_impl->mutex);

    m_impl->memory = &memory;
    m_impl->initialized = true;

    m_impl->processes.reserve(64);
    m_impl->threads.reserve(256);
    m_impl->drivers.reserve(64);

    return true;
}

// ============================================================================
// Process Management
// ============================================================================

GuestAddress KernelObjectManager::CreateProcess(uint32_t pid, uint32_t parentPid, const char* imageName) {
    std::unique_lock lock(m_impl->mutex);

    if (!m_impl->initialized) return 0;
    if (m_impl->processes.size() >= kMaxEmulatedProcesses) return 0;
    if (m_impl->pidIndex.count(pid)) return 0; // duplicate PID
    if (!imageName) return 0;

    GuestAddress addr = m_impl->AllocProcessAddress();
    if (addr == 0) return 0;

    EmulatedEPROCESS proc{};
    proc.selfPtr         = addr;
    proc.uniqueProcessId = pid;
    proc.parentProcessId = parentPid;

    // Safe copy of image name (15 chars max + NUL, matching real EPROCESS)
    std::memset(proc.imageFileNameStr, 0, sizeof(proc.imageFileNameStr));
    const size_t nameLen = std::strlen(imageName);
    const size_t copyLen = (nameLen < 15) ? nameLen : 15;
    std::memcpy(proc.imageFileNameStr, imageName, copyLen);

    proc.imageFileName = addr + 0x100; // offset within virtual EPROCESS
    proc.peb           = addr + 0x200;
    proc.objectTable   = addr + 0x300;

    GuestAddress tokenAddr = m_impl->AllocTokenAddress();
    proc.token = tokenAddr;

    proc.createTime = static_cast<uint64_t>(m_impl->processes.size()) + 1;
    proc.exitStatus = 259; // STILL_ACTIVE

    // Thread list initially self-referential
    proc.threadListHead_Flink = addr + offsetof(EmulatedEPROCESS, threadListHead_Flink);
    proc.threadListHead_Blink = addr + offsetof(EmulatedEPROCESS, threadListHead_Blink);

    m_impl->processes.push_back(proc);
    m_impl->LinkProcess(m_impl->processes.back());
    m_impl->RebuildProcessIndex();

    m_impl->originalTokens[pid] = tokenAddr;

    return addr;
}

bool KernelObjectManager::TerminateProcess(uint32_t pid) {
    std::unique_lock lock(m_impl->mutex);

    auto it = m_impl->pidIndex.find(pid);
    if (it == m_impl->pidIndex.end()) return false;

    size_t idx = it->second;
    m_impl->processes[idx].exitTime = m_impl->processes[idx].createTime + 1;
    m_impl->processes[idx].exitStatus = 0;

    m_impl->UnlinkProcess(idx);

    // Remove associated threads
    auto& threads = m_impl->threads;
    GuestAddress procAddr = m_impl->processes[idx].selfPtr;
    threads.erase(
        std::remove_if(threads.begin(), threads.end(),
            [procAddr](const EmulatedKTHREAD& t) { return t.process == procAddr; }),
        threads.end());
    m_impl->RebuildThreadIndex();

    // Erase the process and rebuild index
    m_impl->processes.erase(m_impl->processes.begin() + static_cast<ptrdiff_t>(idx));
    m_impl->RebuildProcessIndex();

    return true;
}

const EmulatedEPROCESS* KernelObjectManager::FindProcess(uint32_t pid) const {
    std::shared_lock lock(m_impl->mutex);

    auto it = m_impl->pidIndex.find(pid);
    if (it == m_impl->pidIndex.end()) return nullptr;
    return &m_impl->processes[it->second];
}

std::vector<const EmulatedEPROCESS*> KernelObjectManager::GetProcessList() const {
    std::shared_lock lock(m_impl->mutex);

    std::vector<const EmulatedEPROCESS*> result;
    result.reserve(m_impl->processes.size());
    for (const auto& p : m_impl->processes) {
        result.push_back(&p);
    }
    return result;
}

bool KernelObjectManager::ValidateProcessList() const {
    std::shared_lock lock(m_impl->mutex);

    if (m_impl->processes.empty()) return true;

    const uint32_t expected = static_cast<uint32_t>(m_impl->processes.size());
    const uint32_t fwd = m_impl->WalkForward();
    const uint32_t bwd = m_impl->WalkBackward();

    // All three counts must agree; a DKOM unlink causes mismatch
    return (fwd == expected) && (bwd == expected);
}

// ============================================================================
// Thread Management
// ============================================================================

GuestAddress KernelObjectManager::CreateThread(uint32_t pid, uint32_t tid, GuestAddress startAddr) {
    std::unique_lock lock(m_impl->mutex);

    if (!m_impl->initialized) return 0;
    if (m_impl->threads.size() >= kMaxEmulatedThreads) return 0;
    if (m_impl->tidIndex.count(tid)) return 0;

    auto procIt = m_impl->pidIndex.find(pid);
    if (procIt == m_impl->pidIndex.end()) return 0;

    GuestAddress addr = m_impl->AllocThreadAddress();
    if (addr == 0) return 0;

    EmulatedEPROCESS& owner = m_impl->processes[procIt->second];

    EmulatedKTHREAD thread{};
    thread.selfPtr          = addr;
    thread.process          = owner.selfPtr;
    thread.threadId         = tid;
    thread.startAddress     = startAddr;
    thread.win32StartAddress = startAddr;
    thread.stackBase        = addr + 0x10000;
    thread.stackLimit       = thread.stackBase - kStackSize;
    thread.kernelStack      = addr + 0x20000;
    thread.state            = 2; // Running
    thread.priority         = 8;
    thread.basePriority     = 8;
    thread.alertable        = false;
    thread.teb              = addr + 0x30000;
    thread.createTime       = static_cast<uint64_t>(m_impl->threads.size()) + 1;
    thread.previousMode     = 1; // UserMode

    // Link into owning process thread list
    thread.threadListEntry_Flink = owner.threadListHead_Flink;
    thread.threadListEntry_Blink = owner.selfPtr + offsetof(EmulatedEPROCESS, threadListHead_Flink);
    owner.threadListHead_Flink   = addr;

    m_impl->threads.push_back(thread);
    m_impl->RebuildThreadIndex();

    return addr;
}

const EmulatedKTHREAD* KernelObjectManager::FindThread(uint32_t tid) const {
    std::shared_lock lock(m_impl->mutex);

    auto it = m_impl->tidIndex.find(tid);
    if (it == m_impl->tidIndex.end()) return nullptr;
    return &m_impl->threads[it->second];
}

// ============================================================================
// Driver Management
// ============================================================================

GuestAddress KernelObjectManager::LoadDriver(const char* name, GuestAddress base, uint32_t size) {
    std::unique_lock lock(m_impl->mutex);

    if (!m_impl->initialized) return 0;
    if (!name) return 0;
    if (m_impl->drivers.size() >= kMaxEmulatedDrivers) return 0;

    // Reject duplicate driver names
    for (const auto& d : m_impl->drivers) {
        if (std::strncmp(d.driverName, name, sizeof(d.driverName) - 1) == 0) return 0;
    }

    GuestAddress addr = m_impl->AllocDriverAddress();
    if (addr == 0) return 0;

    EmulatedDriverObject drv{};
    drv.selfPtr       = addr;
    drv.driverStart   = base;
    drv.driverSize    = size;
    drv.driverInit    = base; // DriverEntry at module base by default
    drv.driverUnload  = 0;
    drv.deviceObject  = 0;
    drv.driverExtension = addr + 0x800;

    std::memset(drv.driverName, 0, sizeof(drv.driverName));
    const size_t nameLen = std::strlen(name);
    const size_t copyLen = (nameLen < sizeof(drv.driverName) - 1) ? nameLen : sizeof(drv.driverName) - 1;
    std::memcpy(drv.driverName, name, copyLen);

    // Default dispatch table: point all IRP_MJ_* handlers to a sentinel address
    GuestAddress defaultDispatch = base + 0x100;
    for (auto& mf : drv.majorFunction) {
        mf = defaultDispatch;
    }

    m_impl->drivers.push_back(drv);

    return addr;
}

const EmulatedDriverObject* KernelObjectManager::FindDriver(const char* name) const {
    std::shared_lock lock(m_impl->mutex);

    if (!name) return nullptr;
    for (const auto& d : m_impl->drivers) {
        if (std::strncmp(d.driverName, name, sizeof(d.driverName) - 1) == 0) {
            return &d;
        }
    }
    return nullptr;
}

std::vector<const EmulatedDriverObject*> KernelObjectManager::GetDriverList() const {
    std::shared_lock lock(m_impl->mutex);

    std::vector<const EmulatedDriverObject*> result;
    result.reserve(m_impl->drivers.size());
    for (const auto& d : m_impl->drivers) {
        result.push_back(&d);
    }
    return result;
}

// ============================================================================
// SSDT Management
// ============================================================================

void KernelObjectManager::InitializeSSDT() {
    std::unique_lock lock(m_impl->mutex);

    auto& ssdt = m_impl->ssdt;
    ssdt.baseAddress  = kSsdtBaseAddress;
    ssdt.entries.clear();
    ssdt.entries.reserve(kSSDTEntryCount);

    // Populate from the built-in syscall table
    for (size_t i = 0; i < kSyscallTableSize && i < kSSDTEntryCount; ++i) {
        SSDTEntry e{};
        e.serviceNumber  = kSyscallTable[i].number;
        e.serviceName    = kSyscallTable[i].name;
        e.functionAddress = kSsdtFuncBase + static_cast<GuestAddress>(kSyscallTable[i].number) * 0x10;
        e.originalAddress = e.functionAddress;
        e.hooked          = false;
        ssdt.entries.push_back(std::move(e));
    }

    // Fill remaining entries with placeholder unassigned syscalls
    for (uint32_t svc = static_cast<uint32_t>(kSyscallTableSize); svc < kSSDTEntryCount; ++svc) {
        SSDTEntry e{};
        e.serviceNumber   = svc;
        e.serviceName     = "NtUnassigned_" + std::to_string(svc);
        e.functionAddress = kSsdtFuncBase + static_cast<GuestAddress>(svc) * 0x10;
        e.originalAddress = e.functionAddress;
        e.hooked          = false;
        ssdt.entries.push_back(std::move(e));
    }

    ssdt.serviceCount = static_cast<uint32_t>(ssdt.entries.size());
}

const SSDT& KernelObjectManager::GetSSDT() const {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->ssdt;
}

bool KernelObjectManager::HookSSDTEntry(uint32_t serviceNumber, GuestAddress newAddress) {
    std::unique_lock lock(m_impl->mutex);

    for (auto& e : m_impl->ssdt.entries) {
        if (e.serviceNumber == serviceNumber) {
            if (!e.hooked) {
                e.originalAddress = e.functionAddress;
            }
            e.functionAddress = newAddress;
            e.hooked = true;
            return true;
        }
    }
    return false;
}

std::vector<uint32_t> KernelObjectManager::DetectSSDTHooks() const {
    std::shared_lock lock(m_impl->mutex);

    std::vector<uint32_t> hooked;
    for (const auto& e : m_impl->ssdt.entries) {
        if (e.hooked || e.functionAddress != e.originalAddress) {
            hooked.push_back(e.serviceNumber);
        }
    }
    return hooked;
}

// ============================================================================
// IDT Management
// ============================================================================

void KernelObjectManager::InitializeIDT() {
    std::unique_lock lock(m_impl->mutex);

    auto& idt = m_impl->idt;
    idt.clear();
    idt.resize(kIDTEntryCount);

    // Initialize all entries with defaults
    for (uint32_t v = 0; v < kIDTEntryCount; ++v) {
        idt[v].vector          = static_cast<uint8_t>(v);
        idt[v].handler         = kIdtHandlerBase + static_cast<GuestAddress>(v) * 0x10;
        idt[v].originalHandler = idt[v].handler;
        idt[v].ist             = 0;
        idt[v].dpl             = 0;
        idt[v].present         = false;
        idt[v].hooked          = false;
    }

    // Populate CPU exception vectors (0-31) with accurate attributes
    for (size_t i = 0; i < kIDTVectorCount; ++i) {
        auto& entry = idt[kIDTVectors[i].vector];
        entry.dpl     = kIDTVectors[i].dpl;
        entry.ist     = kIDTVectors[i].ist;
        entry.present = true;
    }

    // Common hardware interrupt vectors
    // PIC: IRQ 0-15 mapped to vectors 0x30-0x3F (typical APIC remap)
    for (uint8_t irq = 0; irq < 16; ++irq) {
        const uint8_t vec = 0x30 + irq;
        idt[vec].present = true;
    }

    // APIC timer, spurious, error, IPI vectors
    constexpr uint8_t kApicTimerVec   = 0xD1;
    constexpr uint8_t kApicSpurious   = 0xDF;
    constexpr uint8_t kApicError      = 0xE1;
    constexpr uint8_t kApicIPI        = 0xE2;
    idt[kApicTimerVec].present = true;
    idt[kApicSpurious].present = true;
    idt[kApicError].present    = true;
    idt[kApicIPI].present      = true;

    // System call vector (traditional int 0x2E)
    idt[0x2E].present = true;
    idt[0x2E].dpl     = 3; // Callable from user mode
}

std::vector<uint8_t> KernelObjectManager::DetectIDTHooks() const {
    std::shared_lock lock(m_impl->mutex);

    std::vector<uint8_t> hooked;
    for (const auto& e : m_impl->idt) {
        if (e.present && (e.hooked || e.handler != e.originalHandler)) {
            hooked.push_back(e.vector);
        }
    }
    return hooked;
}

// ============================================================================
// DKOM Detection
// ============================================================================

std::vector<DKOMDetection> KernelObjectManager::ScanForDKOM() const {
    std::shared_lock lock(m_impl->mutex);

    std::vector<DKOMDetection> detections;

    // --- 1. Process list integrity (unlink detection) ---
    if (!m_impl->processes.empty()) {
        const uint32_t expected = static_cast<uint32_t>(m_impl->processes.size());
        const uint32_t fwd = m_impl->WalkForward();
        const uint32_t bwd = m_impl->WalkBackward();

        if (fwd != expected) {
            DKOMDetection d{};
            d.type = DKOMDetection::Type::ProcessUnlinked;
            d.description = "Forward process list walk count (" + std::to_string(fwd) +
                            ") does not match expected (" + std::to_string(expected) + ")";
            detections.push_back(std::move(d));
        }
        if (bwd != expected) {
            DKOMDetection d{};
            d.type = DKOMDetection::Type::ProcessUnlinked;
            d.description = "Backward process list walk count (" + std::to_string(bwd) +
                            ") does not match expected (" + std::to_string(expected) + ")";
            detections.push_back(std::move(d));
        }

        // Check each link points to a valid EPROCESS
        for (const auto& proc : m_impl->processes) {
            bool flinkValid = false;
            bool blinkValid = false;
            for (const auto& other : m_impl->processes) {
                if (other.selfPtr == proc.activeProcessLinks_Flink) flinkValid = true;
                if (other.selfPtr == proc.activeProcessLinks_Blink) blinkValid = true;
            }
            if (!flinkValid || !blinkValid) {
                DKOMDetection d{};
                d.type = DKOMDetection::Type::ProcessUnlinked;
                d.targetPid  = proc.uniqueProcessId;
                d.targetAddr = proc.selfPtr;
                d.description = "Process PID " + std::to_string(proc.uniqueProcessId) +
                                " has invalid ActiveProcessLinks";
                detections.push_back(std::move(d));
            }
        }
    }

    // --- 2. Thread list integrity ---
    for (const auto& thread : m_impl->threads) {
        bool ownerExists = false;
        for (const auto& proc : m_impl->processes) {
            if (proc.selfPtr == thread.process) { ownerExists = true; break; }
        }
        if (!ownerExists) {
            DKOMDetection d{};
            d.type = DKOMDetection::Type::ThreadUnlinked;
            d.targetAddr = thread.selfPtr;
            d.description = "Thread TID " + std::to_string(thread.threadId) +
                            " references non-existent process at 0x" +
                            std::to_string(thread.process);
            detections.push_back(std::move(d));
        }
    }

    // --- 3. Driver list integrity ---
    for (const auto& drv : m_impl->drivers) {
        if (drv.selfPtr == 0 || drv.driverStart == 0) {
            DKOMDetection d{};
            d.type = DKOMDetection::Type::DriverUnlinked;
            d.targetAddr = drv.selfPtr;
            d.description = std::string("Driver '") + drv.driverName +
                            "' has zeroed self/base pointer (possible unlink)";
            detections.push_back(std::move(d));
        }
    }

    // --- 4. SSDT hooks ---
    for (const auto& e : m_impl->ssdt.entries) {
        if (e.hooked || e.functionAddress != e.originalAddress) {
            DKOMDetection d{};
            d.type = DKOMDetection::Type::SSDTHooked;
            d.targetAddr = e.functionAddress;
            d.description = "SSDT entry " + std::to_string(e.serviceNumber) +
                            " (" + e.serviceName + ") hooked: original=0x" +
                            std::to_string(e.originalAddress) +
                            " current=0x" + std::to_string(e.functionAddress);
            detections.push_back(std::move(d));
        }
    }

    // --- 5. IDT hooks ---
    for (const auto& e : m_impl->idt) {
        if (e.present && (e.hooked || e.handler != e.originalHandler)) {
            DKOMDetection d{};
            d.type = DKOMDetection::Type::IDTHooked;
            d.targetAddr = e.handler;
            d.description = "IDT vector " + std::to_string(e.vector) +
                            " hooked: original=0x" + std::to_string(e.originalHandler) +
                            " current=0x" + std::to_string(e.handler);
            detections.push_back(std::move(d));
        }
    }

    // --- 6. Token swap detection ---
    for (const auto& proc : m_impl->processes) {
        auto tokenIt = m_impl->originalTokens.find(proc.uniqueProcessId);
        if (tokenIt != m_impl->originalTokens.end()) {
            if (proc.token != tokenIt->second) {
                DKOMDetection d{};
                d.type = DKOMDetection::Type::TokenSwapped;
                d.targetPid  = proc.uniqueProcessId;
                d.targetAddr = proc.token;
                d.description = "Process PID " + std::to_string(proc.uniqueProcessId) +
                                " token changed from 0x" + std::to_string(tokenIt->second) +
                                " to 0x" + std::to_string(proc.token);
                detections.push_back(std::move(d));
            }
        }
    }

    return detections;
}

// ============================================================================
// Integrity Verification
// ============================================================================

bool KernelObjectManager::ValidateDriverIntegrity() const {
    std::shared_lock lock(m_impl->mutex);

    for (const auto& drv : m_impl->drivers) {
        if (drv.selfPtr == 0) return false;
        if (drv.driverStart == 0) return false;
        if (drv.driverSize == 0) return false;

        // Verify all dispatch pointers are within kernel address range
        for (const auto& mf : drv.majorFunction) {
            if (mf != 0 && mf < 0xFFFF800000000000ULL) {
                return false; // Dispatch handler outside kernel range
            }
        }
    }
    return true;
}

bool KernelObjectManager::ValidateSSDTIntegrity() const {
    std::shared_lock lock(m_impl->mutex);

    for (const auto& e : m_impl->ssdt.entries) {
        if (e.functionAddress != e.originalAddress) return false;
    }
    return true;
}

uint32_t KernelObjectManager::GetProcessCount() const {
    std::shared_lock lock(m_impl->mutex);
    return static_cast<uint32_t>(m_impl->processes.size());
}

uint32_t KernelObjectManager::GetThreadCount() const {
    std::shared_lock lock(m_impl->mutex);
    return static_cast<uint32_t>(m_impl->threads.size());
}

uint32_t KernelObjectManager::GetDriverCount() const {
    std::shared_lock lock(m_impl->mutex);
    return static_cast<uint32_t>(m_impl->drivers.size());
}

} // namespace Phantom
