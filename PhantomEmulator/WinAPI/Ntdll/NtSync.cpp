/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * NtSync.cpp — Nt* synchronization and object syscall implementations
 *
 * Synchronization primitives are emulated in accelerated mode: waits
 * never block the emulation thread. Signaled objects return immediately;
 * non-signaled objects return STATUS_TIMEOUT. This is intentional —
 * we observe behavior, not replicate real-time scheduling.
 *
 * Named mutexes are the #1 malware infection marker. Every name is
 * captured and checked against known patterns. Named events and
 * sections are similarly recorded for behavioral analysis.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "NtSync.hpp"
#include "NtRegistry.hpp"
#include "../APIDispatcher.hpp"
#include "../HandleTable.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <algorithm>
#include <cstring>
#include <string>
#include <string_view>
#include <cctype>

namespace Phantom::WinAPI::Ntdll {

// ============================================================================
// Internal constants
// ============================================================================

static constexpr uint32_t kMaxWaitObjects       = 64;
static constexpr uint32_t kMaxObjectNameChars    = 1024;

// WAIT_TYPE for NtWaitForMultipleObjects
static constexpr uint32_t kWaitAll = 0;
static constexpr uint32_t kWaitAny = 1;

// NT wait return base values
static constexpr uint32_t kWaitObject0 = 0x00000000;

// EVENT_TYPE for NtCreateEvent
static constexpr uint32_t kNotificationEvent    = 0; // Manual-reset
static constexpr uint32_t kSynchronizationEvent = 1; // Auto-reset

// ============================================================================
// OBJECT_ATTRIBUTES parsing helper
// ============================================================================
// Extracts the object name from an OBJECT_ATTRIBUTES structure in guest memory.
//
// OBJECT_ATTRIBUTES x64 layout:
//   +0x00 ULONG  Length (sizeof = 0x30)
//   +0x08 HANDLE RootDirectory
//   +0x10 PUNICODE_STRING ObjectName
//   +0x18 ULONG  Attributes
//   +0x20 PVOID  SecurityDescriptor
//   +0x28 PVOID  SecurityQualityOfService
//
// UNICODE_STRING x64 layout:
//   +0x00 USHORT Length (byte count, not including NUL)
//   +0x02 USHORT MaximumLength
//   +0x08 PWSTR  Buffer

static std::wstring ReadObjectName(APIContext& ctx,
                                   GuestAddress oaAddr) noexcept {
    if (oaAddr == 0) return {};

    auto& mem = ctx.Memory();

    uint64_t unicodeStringAddr = 0;
    if (mem.ReadU64(oaAddr + 0x10, unicodeStringAddr) != ErrorCode::Success) {
        return {};
    }
    if (unicodeStringAddr == 0) return {};

    uint16_t byteLength = 0;
    uint64_t bufferAddr = 0;
    if (mem.ReadU16(unicodeStringAddr, byteLength) != ErrorCode::Success) {
        return {};
    }
    if (mem.ReadU64(unicodeStringAddr + 0x08, bufferAddr) != ErrorCode::Success) {
        return {};
    }
    if (bufferAddr == 0 || byteLength == 0) return {};

    const uint32_t charCount = byteLength / 2;
    if (charCount > kMaxObjectNameChars) return {};

    std::wstring result;
    result.resize(charCount);
    if (mem.Read(bufferAddr, result.data(),
                 static_cast<uint32_t>(charCount * sizeof(wchar_t))) != ErrorCode::Success) {
        return {};
    }

    return result;
}

// ============================================================================
// Malware mutex pattern detection
// ============================================================================
// Named mutexes are the primary infection marker for malware. Patterns include:
// - Global\ prefix (cross-session synchronization)
// - Short hex/GUID-like names (automated naming)
// - Known malware mutex families

static std::wstring ToUpperW(std::wstring_view sv) noexcept {
    std::wstring result(sv);
    std::transform(result.begin(), result.end(), result.begin(),
                   [](wchar_t c) -> wchar_t {
                       return (c >= L'a' && c <= L'z') ? (c - L'a' + L'A') : c;
                   });
    return result;
}

[[nodiscard]] static bool IsSuspiciousMutexName(const std::wstring& name) noexcept {
    if (name.empty()) return false;

    std::wstring upper = ToUpperW(name);

    // Strip BaseNamedObjects prefix for pattern matching
    static constexpr std::wstring_view kBNO = L"\\BASENAMEDOBJECTS\\";
    std::wstring_view check = upper;
    if (check.size() > kBNO.size() && check.substr(0, kBNO.size()) == kBNO) {
        check = check.substr(kBNO.size());
    }

    // Global\ prefix — cross-session mutexes are suspicious
    static constexpr std::wstring_view kGlobalPrefix = L"GLOBAL\\";
    if (check.size() > kGlobalPrefix.size() &&
        check.substr(0, kGlobalPrefix.size()) == kGlobalPrefix) {
        return true;
    }

    // Known malware mutex pattern fragments
    static constexpr std::wstring_view kPatterns[] = {
        L"SINGLEINSTANCE",
        L"UNIQUEINSTANCE",
        L"NOREPEAT",
        L"ALREADY_RUNNING",
        L"MYMUTEX",
        L"SHELLMUTEX",
        L"INSTALLMUTEX",
        L"TROJAN",
        L"BACKDOOR",
        L"RAT_",
        L"BOTNET",
        L"C2MUTEX",
        L"CRYPTOLOCKER",
        L"RANSOMWARE",
    };

    for (const auto& pattern : kPatterns) {
        if (upper.find(pattern) != std::wstring::npos) {
            return true;
        }
    }

    // Pure hex/GUID strings (8+ hex chars, often auto-generated identifiers)
    // Pattern: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX} or just hex chars
    if (check.size() >= 8) {
        bool allHexOrDash = true;
        uint32_t hexCount = 0;
        for (wchar_t c : check) {
            if ((c >= L'0' && c <= L'9') ||
                (c >= L'A' && c <= L'F')) {
                ++hexCount;
            } else if (c != L'-' && c != L'{' && c != L'}') {
                allHexOrDash = false;
                break;
            }
        }
        if (allHexOrDash && hexCount >= 8) {
            return true;
        }
    }

    return false;
}

// ============================================================================
// Handle type classification for wait operations
// ============================================================================

[[nodiscard]] static bool IsWaitableType(HandleType type) noexcept {
    switch (type) {
        case HandleType::Mutex:
        case HandleType::Event:
        case HandleType::Semaphore:
        case HandleType::Process:
        case HandleType::Thread:
            return true;
        default:
            return false;
    }
}

// Check if a waitable handle is currently signaled and optionally auto-reset.
// Returns true if the object was signaled at the time of check.
[[nodiscard]] static bool CheckAndConsumeSignal(
    HandleTable& handles,
    GuestHandle handle,
    HandleType type) noexcept
{
    if (type == HandleType::Process || type == HandleType::Thread) {
        // Emulated processes/threads are always considered "not terminated"
        // unless explicitly marked, so they are not signaled.
        return false;
    }

    auto entry = handles.Lookup(handle);
    if (!entry.has_value()) return false;

    auto* sync = std::get_if<SyncObjectData>(&entry->data);
    if (!sync) return false;

    if (!sync->signaled) return false;

    // Auto-reset for SynchronizationEvent (auto-reset event) and Mutex:
    // Consuming the signal clears it.
    if (type == HandleType::Event) {
        // Auto-reset events (count == 1) reset on successful wait.
        // Manual-reset events (count == 0) stay signaled.
        if (sync->count == 1) {
            (void)handles.Modify<SyncObjectData>(handle, [](SyncObjectData& sd) {
                sd.signaled = false;
            });
        }
    } else if (type == HandleType::Mutex) {
        // Acquiring a mutex clears signaled state
        (void)handles.Modify<SyncObjectData>(handle, [](SyncObjectData& sd) {
            sd.signaled = false;
            sd.count++;
        });
    } else if (type == HandleType::Semaphore) {
        // Decrement semaphore count
        (void)handles.Modify<SyncObjectData>(handle, [](SyncObjectData& sd) {
            sd.count--;
            if (sd.count <= 0) {
                sd.signaled = false;
            }
        });
    }

    return true;
}

// ============================================================================
// HandleNtWaitForSingleObject
// ============================================================================
// NTSTATUS NtWaitForSingleObject(
//     HANDLE Handle,          // arg0
//     BOOLEAN Alertable,      // arg1
//     PLARGE_INTEGER Timeout  // arg2
// );
//
// Emulation strategy: instantaneous. If signaled → STATUS_SUCCESS.
// If not signaled → STATUS_TIMEOUT (unless timeout is NULL/infinite,
// in which we still return STATUS_SUCCESS to prevent deadlocking the
// emulation).

bool HandleNtWaitForSingleObject(APIContext& ctx) {
    const auto handle       = static_cast<GuestHandle>(ctx.GetArg(0));
    // arg1: Alertable (not used in emulation)
    const auto timeoutPtr   = ctx.GetArgPtr(2);

    // Validate handle
    auto entry = ctx.Handles().Lookup(handle);
    if (!entry.has_value()) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    const HandleType type = entry->type;
    if (!IsWaitableType(type)) {
        // Waiting on non-waitable types succeeds immediately on Windows
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    // Determine timeout behavior
    int64_t timeout = 0;
    bool hasTimeout = false;
    if (timeoutPtr != 0) {
        uint64_t rawTimeout = 0;
        if (ctx.Memory().ReadU64(timeoutPtr, rawTimeout) == ErrorCode::Success) {
            timeout = static_cast<int64_t>(rawTimeout);
            hasTimeout = true;
        }
    }
    const bool isZeroTimeout = hasTimeout && (timeout == 0);
    const bool isInfinite    = !hasTimeout; // NULL timeout = infinite wait

    // Check signaled state
    if (CheckAndConsumeSignal(ctx.Handles(), handle, type)) {
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    // Not signaled
    if (isZeroTimeout) {
        ctx.SetReturnNtStatus(NT::STATUS_TIMEOUT);
        return true;
    }

    // Non-zero or infinite timeout: in emulation we accelerate waits.
    // For infinite waits, return SUCCESS to prevent deadlock in the emulator.
    // For finite waits, return TIMEOUT to let the sample proceed.
    if (isInfinite) {
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    } else {
        ctx.SetReturnNtStatus(NT::STATUS_TIMEOUT);
    }

    return true;
}

// ============================================================================
// HandleNtWaitForMultipleObjects
// ============================================================================
// NTSTATUS NtWaitForMultipleObjects(
//     ULONG Count,            // arg0
//     HANDLE* Handles,        // arg1
//     WAIT_TYPE WaitType,     // arg2 (0=WaitAll, 1=WaitAny)
//     BOOLEAN Alertable,      // arg3
//     PLARGE_INTEGER Timeout  // arg4
// );

bool HandleNtWaitForMultipleObjects(APIContext& ctx) {
    const auto count       = ctx.GetArg32(0);
    const auto handlesPtr  = ctx.GetArgPtr(1);
    const auto waitType    = ctx.GetArg32(2);
    // arg3: Alertable (not used)
    const auto timeoutPtr  = ctx.GetArgPtr(4);

    if (count == 0 || count > kMaxWaitObjects) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    if (handlesPtr == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    if (waitType != kWaitAll && waitType != kWaitAny) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    // Read handle array from guest memory
    GuestHandle handleArray[kMaxWaitObjects] = {};
    auto& mem = ctx.Memory();
    for (uint32_t i = 0; i < count; ++i) {
        uint64_t val = 0;
        if (mem.ReadU64(handlesPtr + i * 8, val) != ErrorCode::Success) {
            ctx.SetReturnNtStatus(NT::STATUS_ACCESS_VIOLATION);
            return true;
        }
        handleArray[i] = static_cast<GuestHandle>(val);
    }

    // Validate all handles exist
    for (uint32_t i = 0; i < count; ++i) {
        if (!ctx.Handles().IsValid(handleArray[i])) {
            ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
            return true;
        }
    }

    // Determine timeout
    int64_t timeout = 0;
    bool hasTimeout = false;
    if (timeoutPtr != 0) {
        uint64_t rawTimeout = 0;
        if (mem.ReadU64(timeoutPtr, rawTimeout) == ErrorCode::Success) {
            timeout = static_cast<int64_t>(rawTimeout);
            hasTimeout = true;
        }
    }
    const bool isZeroTimeout = hasTimeout && (timeout == 0);
    const bool isInfinite    = !hasTimeout;

    // Check signaled states
    if (waitType == kWaitAny) {
        // WaitAny: return as soon as one is signaled
        for (uint32_t i = 0; i < count; ++i) {
            auto entry = ctx.Handles().Lookup(handleArray[i]);
            if (!entry.has_value()) continue;

            if (IsWaitableType(entry->type) &&
                CheckAndConsumeSignal(ctx.Handles(), handleArray[i], entry->type)) {
                // WAIT_OBJECT_0 + index is the NTSTATUS for WaitAny
                ctx.SetReturnNtStatus(static_cast<GuestNtStatus>(kWaitObject0 + i));
                return true;
            }
        }

        // None signaled
        if (isZeroTimeout) {
            ctx.SetReturnNtStatus(NT::STATUS_TIMEOUT);
        } else if (isInfinite) {
            // Return first object to prevent deadlock
            ctx.SetReturnNtStatus(static_cast<GuestNtStatus>(kWaitObject0));
        } else {
            ctx.SetReturnNtStatus(NT::STATUS_TIMEOUT);
        }
    } else {
        // WaitAll: all must be signaled
        bool allSignaled = true;
        for (uint32_t i = 0; i < count; ++i) {
            auto entry = ctx.Handles().Lookup(handleArray[i]);
            if (!entry.has_value()) continue;

            if (IsWaitableType(entry->type)) {
                auto* sync = std::get_if<SyncObjectData>(&entry->data);
                if (!sync || !sync->signaled) {
                    allSignaled = false;
                    break;
                }
            }
        }

        if (allSignaled) {
            // Consume all signals
            for (uint32_t i = 0; i < count; ++i) {
                auto entry = ctx.Handles().Lookup(handleArray[i]);
                if (entry.has_value() && IsWaitableType(entry->type)) {
                    (void)CheckAndConsumeSignal(ctx.Handles(), handleArray[i], entry->type);
                }
            }
            ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        } else if (isZeroTimeout) {
            ctx.SetReturnNtStatus(NT::STATUS_TIMEOUT);
        } else if (isInfinite) {
            ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        } else {
            ctx.SetReturnNtStatus(NT::STATUS_TIMEOUT);
        }
    }

    return true;
}

// ============================================================================
// HandleNtCreateEvent
// ============================================================================
// NTSTATUS NtCreateEvent(
//     PHANDLE EventHandle,                // arg0 (OUT)
//     ACCESS_MASK DesiredAccess,           // arg1
//     POBJECT_ATTRIBUTES ObjectAttributes, // arg2
//     EVENT_TYPE EventType,                // arg3 (0=Notification, 1=Synchronization)
//     BOOLEAN InitialState                 // arg4
// );

bool HandleNtCreateEvent(APIContext& ctx) {
    const auto eventHandlePtr = ctx.GetArgPtr(0);
    // arg1: DesiredAccess (not enforced in emulation)
    const auto objAttrPtr     = ctx.GetArgPtr(2);
    const auto eventType      = ctx.GetArg32(3);
    const auto initialState   = ctx.GetArg32(4);

    if (eventHandlePtr == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    // Extract optional name from ObjectAttributes
    std::wstring name = ReadObjectName(ctx, objAttrPtr);

    // Build sync object data
    SyncObjectData sd;
    sd.name     = std::move(name);
    sd.signaled = (initialState != 0);
    // Encode event type in count field: 0 = manual-reset, 1 = auto-reset
    sd.count    = (eventType == kSynchronizationEvent) ? 1 : 0;

    GuestHandle handle = ctx.Handles().Create(HandleType::Event, std::move(sd));
    if (handle == kNullHandle) {
        ctx.SetReturnNtStatus(NT::STATUS_INSUFFICIENT_RESOURCES);
        return true;
    }

    (void)ctx.Memory().WriteU64(eventHandlePtr, handle);
    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// HandleNtSetEvent
// ============================================================================
// NTSTATUS NtSetEvent(
//     HANDLE EventHandle,  // arg0
//     PLONG PreviousState  // arg1 (optional OUT)
// );

bool HandleNtSetEvent(APIContext& ctx) {
    const auto handle         = static_cast<GuestHandle>(ctx.GetArg(0));
    const auto prevStatePtr   = ctx.GetArgPtr(1);

    // Validate handle and type
    auto entry = ctx.Handles().Lookup(handle, HandleType::Event);
    if (!entry.has_value()) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    // Read previous state before modification
    int32_t previousState = 0;
    auto* sync = std::get_if<SyncObjectData>(&entry->data);
    if (sync) {
        previousState = sync->signaled ? 1 : 0;
    }

    // Set the event to signaled
    (void)ctx.Handles().Modify<SyncObjectData>(handle, [](SyncObjectData& sd) {
        sd.signaled = true;
    });

    // Write previous state if caller requested it
    if (prevStatePtr != 0) {
        (void)ctx.Memory().WriteU32(prevStatePtr, static_cast<uint32_t>(previousState));
    }

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// HandleNtCreateMutant
// ============================================================================
// NTSTATUS NtCreateMutant(
//     PHANDLE MutantHandle,                // arg0 (OUT)
//     ACCESS_MASK DesiredAccess,            // arg1
//     POBJECT_ATTRIBUTES ObjectAttributes,  // arg2
//     BOOLEAN InitialOwner                  // arg3
// );
//
// Named mutexes are the #1 malware infection marker. Every creation is
// logged for behavioral analysis.

bool HandleNtCreateMutant(APIContext& ctx) {
    const auto mutantHandlePtr = ctx.GetArgPtr(0);
    // arg1: DesiredAccess (not enforced)
    const auto objAttrPtr      = ctx.GetArgPtr(2);
    const auto initialOwner    = ctx.GetArg32(3);

    if (mutantHandlePtr == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    std::wstring name = ReadObjectName(ctx, objAttrPtr);

    // Malware analysis: named mutexes are infection markers
    if (!name.empty()) {
        if (IsSuspiciousMutexName(name)) {
            ctx.AddBehaviorFlag(BehaviorFlag::AntiAnalysis);
        }
        // All named mutexes are noteworthy for behavioral analysis
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
    }

    // A mutex is signaled when NOT owned (available for acquisition).
    // If InitialOwner is TRUE, the creating thread owns it → not signaled.
    SyncObjectData sd;
    sd.name     = std::move(name);
    sd.signaled = (initialOwner == 0);
    sd.count    = (initialOwner != 0) ? 1 : 0; // Recursion depth

    GuestHandle handle = ctx.Handles().Create(HandleType::Mutex, std::move(sd));
    if (handle == kNullHandle) {
        ctx.SetReturnNtStatus(NT::STATUS_INSUFFICIENT_RESOURCES);
        return true;
    }

    (void)ctx.Memory().WriteU64(mutantHandlePtr, handle);
    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// HandleNtOpenMutant
// ============================================================================
// NTSTATUS NtOpenMutant(
//     PHANDLE MutantHandle,                // arg0 (OUT)
//     ACCESS_MASK DesiredAccess,            // arg1
//     POBJECT_ATTRIBUTES ObjectAttributes   // arg2
// );
//
// Opens an existing named mutex. Malware uses this to check if another
// instance is already running (single-instance check).

bool HandleNtOpenMutant(APIContext& ctx) {
    const auto mutantHandlePtr = ctx.GetArgPtr(0);
    // arg1: DesiredAccess (not enforced)
    const auto objAttrPtr      = ctx.GetArgPtr(2);

    if (mutantHandlePtr == 0 || objAttrPtr == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    std::wstring name = ReadObjectName(ctx, objAttrPtr);
    if (name.empty()) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    // Named mutex opens are interesting for behavioral analysis
    ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
    if (IsSuspiciousMutexName(name)) {
        ctx.AddBehaviorFlag(BehaviorFlag::AntiAnalysis);
    }

    // Search existing Mutex handles for a matching name
    auto& handles = ctx.Handles();
    auto mutexHandles = handles.GetHandlesByType(HandleType::Mutex);

    for (GuestHandle existingHandle : mutexHandles) {
        auto entry = handles.Lookup(existingHandle, HandleType::Mutex);
        if (!entry.has_value()) continue;

        auto* sync = std::get_if<SyncObjectData>(&entry->data);
        if (!sync) continue;

        if (sync->name == name) {
            // Found matching named mutex — duplicate the handle
            auto dupResult = handles.Duplicate(existingHandle);
            if (dupResult.has_value()) {
                (void)ctx.Memory().WriteU64(mutantHandlePtr, *dupResult);
                ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
                return true;
            }
        }
    }

    // No matching mutex found
    ctx.SetReturnNtStatus(NT::STATUS_OBJECT_NAME_NOT_FOUND);
    return true;
}

// ============================================================================
// HandleNtOpenSection
// ============================================================================
// NTSTATUS NtOpenSection(
//     PHANDLE SectionHandle,               // arg0 (OUT)
//     ACCESS_MASK DesiredAccess,            // arg1
//     POBJECT_ATTRIBUTES ObjectAttributes   // arg2
// );
//
// Malware commonly opens known DLL sections (\KnownDlls\ntdll.dll) to
// map clean copies of system DLLs, bypassing inline hooks.

bool HandleNtOpenSection(APIContext& ctx) {
    const auto sectionHandlePtr = ctx.GetArgPtr(0);
    // arg1: DesiredAccess (not enforced)
    const auto objAttrPtr       = ctx.GetArgPtr(2);

    if (sectionHandlePtr == 0 || objAttrPtr == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    std::wstring name = ReadObjectName(ctx, objAttrPtr);
    if (name.empty()) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    // Detect evasion: opening \KnownDlls sections to bypass API hooks
    std::wstring upper = ToUpperW(name);
    static constexpr std::wstring_view kKnownDlls = L"\\KNOWNDLLS\\";
    if (upper.size() > kKnownDlls.size() &&
        std::wstring_view(upper).substr(0, kKnownDlls.size()) == kKnownDlls) {
        ctx.AddBehaviorFlag(BehaviorFlag::DefenseEvasion);
    }

    // Search existing Section handles for a matching name
    auto& handles = ctx.Handles();
    auto sectionHandles = handles.GetHandlesByType(HandleType::Section);

    for (GuestHandle existingHandle : sectionHandles) {
        auto entry = handles.Lookup(existingHandle, HandleType::Section);
        if (!entry.has_value()) continue;

        auto* section = std::get_if<SectionData>(&entry->data);
        if (!section) continue;

        if (ToUpperW(section->name) == upper) {
            auto dupResult = handles.Duplicate(existingHandle);
            if (dupResult.has_value()) {
                (void)ctx.Memory().WriteU64(sectionHandlePtr, *dupResult);
                ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
                return true;
            }
        }
    }

    // Section not found — create a placeholder for known system sections
    // so the sample can proceed with its logic (we observe, not block).
    SectionData sd;
    sd.name       = name;
    sd.maxSize    = 0;
    sd.protection = 0;
    sd.mappedBase = 0;
    sd.mappedSize = 0;

    GuestHandle handle = handles.Create(HandleType::Section, std::move(sd));
    if (handle == kNullHandle) {
        ctx.SetReturnNtStatus(NT::STATUS_INSUFFICIENT_RESOURCES);
        return true;
    }

    (void)ctx.Memory().WriteU64(sectionHandlePtr, handle);
    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// HandleNtOpenKeyEx
// ============================================================================
// NTSTATUS NtOpenKeyEx(
//     PHANDLE KeyHandle,                   // arg0 (OUT)
//     ACCESS_MASK DesiredAccess,            // arg1
//     POBJECT_ATTRIBUTES ObjectAttributes,  // arg2
//     ULONG OpenOptions                     // arg3
// );
//
// Functionally identical to NtOpenKey with an additional OpenOptions
// parameter (REG_OPTION_OPEN_LINK, etc.). We delegate to the existing
// NtOpenKey handler — the options parameter does not affect emulation
// behavior since we don't support symbolic registry links.

bool HandleNtOpenKeyEx(APIContext& ctx) {
    // NtOpenKeyEx has the same first 3 args as NtOpenKey (arg0-arg2).
    // arg3 (OpenOptions) is informational and does not change emulation.
    // Delegate directly to HandleNtOpenKey which reads arg0, arg1, arg2.
    return HandleNtOpenKey(ctx);
}

// ============================================================================
// Registration
// ============================================================================

void RegisterNtSync(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "ntdll.dll", "NtWaitForSingleObject",
          HandleNtWaitForSingleObject, 3, true },
        { "ntdll.dll", "NtWaitForMultipleObjects",
          HandleNtWaitForMultipleObjects, 5, false },
        { "ntdll.dll", "NtCreateEvent",
          HandleNtCreateEvent, 5, false },
        { "ntdll.dll", "NtSetEvent",
          HandleNtSetEvent, 2, false },
        { "ntdll.dll", "NtCreateMutant",
          HandleNtCreateMutant, 4, false },
        { "ntdll.dll", "NtOpenMutant",
          HandleNtOpenMutant, 3, false },
        { "ntdll.dll", "NtOpenSection",
          HandleNtOpenSection, 3, false },
        { "ntdll.dll", "NtOpenKeyEx",
          HandleNtOpenKeyEx, 4, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Ntdll
