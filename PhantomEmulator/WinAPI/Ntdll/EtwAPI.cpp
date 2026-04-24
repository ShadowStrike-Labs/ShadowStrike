/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * EtwAPI.cpp — ETW event tracing API handler implementations
 *
 * This module emulates the ntdll.dll ETW surface targeted by advanced
 * adversaries for defense evasion. Modern malware (Cobalt Strike loaders,
 * Brute Ratel, Nighthawk, APT29 tooling) routinely:
 *
 *   - Patches EtwEventWrite with 0xC3 (RET) to suppress EDR telemetry
 *   - Changes page protection on ETW functions via NtProtectVirtualMemory
 *   - Unregisters security-critical ETW providers (TI, AMSI, .NET CLR)
 *   - Probes provider registration to detect sandbox environments
 *
 * Design decisions:
 *   - All providers are reported as "enabled" to prevent sandbox fingerprinting
 *   - Registration of sensitive GUIDs (TI, AMSI, Kernel-Audit, .NET) is flagged
 *   - Event write calls are counted; unusual volume from malware is suspicious
 *   - Blinding events are captured with full context for the analysis report
 *   - Fake but plausible trace handles, flags, and levels are returned
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "EtwAPI.hpp"
#include "../APIDispatcher.hpp"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <iterator>

// DESIGN: WriteU32/Write on guest memory is [[nodiscard]] so the caller can
// detect guest-side AVs. In ETW handlers the caller-supplied out-pointer is
// always null-checked before use; a guest AV on write is a guest-side fault
// that the emulated application must cope with, so discarding the outcome
// is semantically correct here.
#pragma warning(push)
#pragma warning(disable : 4834 6031)

namespace Phantom::WinAPI::Ntdll {

// ============================================================================
// ETW-specific constants (no windows.h dependency)
// ============================================================================

// Resource caps
static constexpr uint32_t kMaxProviderRegistrations = 256;
static constexpr uint32_t kMaxEventWritesTracked    = 10000;
static constexpr uint32_t kMaxBlindingEvents        = 64;

// Fake trace session values returned to the guest
static constexpr uint64_t kFakeLoggerHandle  = 0x0000'0000'FEED'E700ULL;
static constexpr uint32_t kFakeEnableFlags   = 0xFFFFFFFF; // All flags enabled
static constexpr uint8_t  kTraceVerboseLevel = 5;          // TRACE_LEVEL_VERBOSE

// REGHANDLE base — monotonically increasing pseudo-handles
static constexpr uint64_t kRegHandleBase = 0xE7B0'0001'0000'0000ULL;

// ============================================================================
// Sensitive ETW provider GUIDs
// ============================================================================
// Malware targeting any of these is performing defense evasion.

struct SensitiveGuid {
    EtwGuid     guid;
    const char* name;
};

static constexpr EtwGuid MakeGuid(uint32_t d1, uint16_t d2, uint16_t d3,
                                  uint8_t a, uint8_t b, uint8_t c, uint8_t d,
                                  uint8_t e, uint8_t f, uint8_t g, uint8_t h) noexcept {
    EtwGuid g2{};
    g2.data1 = d1;
    g2.data2 = d2;
    g2.data3 = d3;
    g2.data4[0] = a; g2.data4[1] = b; g2.data4[2] = c; g2.data4[3] = d;
    g2.data4[4] = e; g2.data4[5] = f; g2.data4[6] = g; g2.data4[7] = h;
    return g2;
}

// {F4E1897A-BB5D-5668-F1D8-040F4D8DD344}
static const EtwGuid kGuidThreatIntel =
    MakeGuid(0xF4E1897A, 0xBB5D, 0x5668,
             0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44);

// {E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23}
static const EtwGuid kGuidKernelAudit =
    MakeGuid(0xE02A841C, 0x75A3, 0x4FA7,
             0xAF, 0xC8, 0xAE, 0x09, 0xCF, 0x9B, 0x7F, 0x23);

// {E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}
static const EtwGuid kGuidDotNetRuntime =
    MakeGuid(0xE13C0D23, 0xCCBC, 0x4E12,
             0x93, 0x1B, 0xD9, 0xCC, 0x2E, 0xEE, 0x27, 0xE4);

// {2A576B87-09A7-520E-C21A-4942F0271D67}
static const EtwGuid kGuidAmsi =
    MakeGuid(0x2A576B87, 0x09A7, 0x520E,
             0xC2, 0x1A, 0x49, 0x42, 0xF0, 0x27, 0x1D, 0x67);

static const SensitiveGuid kSensitiveGuids[] = {
    { kGuidThreatIntel,    "Microsoft-Windows-Threat-Intelligence" },
    { kGuidKernelAudit,    "Microsoft-Windows-Kernel-Audit-API-Calls" },
    { kGuidDotNetRuntime,  "Microsoft-Windows-DotNETRuntime" },
    { kGuidAmsi,           "Microsoft-Antimalware-Scan-Interface" },
};

// ============================================================================
// EtwGuid implementation
// ============================================================================

bool EtwGuid::operator==(const EtwGuid& o) const noexcept {
    return data1 == o.data1 && data2 == o.data2 && data3 == o.data3 &&
           std::memcmp(data4, o.data4, 8) == 0;
}

std::string EtwGuid::ToString() const noexcept {
    char buf[40];
    std::snprintf(buf, sizeof(buf),
                  "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                  data1, data2, data3,
                  data4[0], data4[1], data4[2], data4[3],
                  data4[4], data4[5], data4[6], data4[7]);
    return std::string(buf);
}

// ============================================================================
// Internal state — file-static singleton implementation
// ============================================================================

struct EtwProviderEntry {
    uint64_t    regHandle       = 0;
    EtwGuid     guid;
    std::string guidString;
    bool        isSensitive     = false;
    uint32_t    eventWriteCount = 0;
};

struct EtwStateImpl {
    mutable std::mutex                                   mutex;
    std::unordered_map<uint64_t, EtwProviderEntry>       providers;
    std::vector<EtwBlindingEvent>                        blindingEvents;
    std::atomic<uint64_t>                                nextRegHandle{ kRegHandleBase };
    std::atomic<uint32_t>                                totalEventWrites{ 0 };

    [[nodiscard]] uint64_t AllocRegHandle() noexcept {
        return nextRegHandle.fetch_add(1, std::memory_order_relaxed);
    }
};

static EtwStateImpl& GetState() noexcept {
    static EtwStateImpl s_state;
    return s_state;
}

// ============================================================================
// EtwState public interface (Meyers' singleton)
// ============================================================================

EtwState& EtwState::Instance() noexcept {
    static EtwState s_instance;
    return s_instance;
}

std::vector<EtwProviderInfo> EtwState::GetRegisteredProviders() const noexcept {
    auto& st = GetState();
    std::lock_guard lock(st.mutex);
    std::vector<EtwProviderInfo> result;
    result.reserve(st.providers.size());
    for (const auto& [handle, entry] : st.providers) {
        EtwProviderInfo info;
        info.regHandle       = entry.regHandle;
        info.providerId      = entry.guid;
        info.guidString      = entry.guidString;
        info.isSensitive     = entry.isSensitive;
        info.eventWriteCount = entry.eventWriteCount;
        result.push_back(std::move(info));
    }
    return result;
}

std::vector<EtwBlindingEvent> EtwState::GetBlindingEvents() const noexcept {
    auto& st = GetState();
    std::lock_guard lock(st.mutex);
    return st.blindingEvents;
}

uint32_t EtwState::GetEventWriteCount() const noexcept {
    return GetState().totalEventWrites.load(std::memory_order_relaxed);
}

bool EtwState::WasEtwPatched() const noexcept {
    auto& st = GetState();
    std::lock_guard lock(st.mutex);
    return !st.blindingEvents.empty();
}

void EtwState::RegisterProvider(uint64_t regHandle, const EtwGuid& guid,
                                bool sensitive) noexcept {
    auto& st = GetState();
    std::lock_guard lock(st.mutex);
    if (st.providers.size() >= kMaxProviderRegistrations) return;

    EtwProviderEntry entry;
    entry.regHandle   = regHandle;
    entry.guid        = guid;
    entry.guidString  = guid.ToString();
    entry.isSensitive = sensitive;
    st.providers[regHandle] = std::move(entry);
}

void EtwState::UnregisterProvider(uint64_t regHandle) noexcept {
    auto& st = GetState();
    std::lock_guard lock(st.mutex);
    st.providers.erase(regHandle);
}

void EtwState::IncrementEventWriteCount(uint64_t regHandle) noexcept {
    auto& st = GetState();
    uint32_t total = st.totalEventWrites.fetch_add(1, std::memory_order_relaxed);
    if (total < kMaxEventWritesTracked) {
        std::lock_guard lock(st.mutex);
        auto it = st.providers.find(regHandle);
        if (it != st.providers.end()) {
            it->second.eventWriteCount++;
        }
    }
}

void EtwState::RecordBlindingEvent(EtwBlindingEvent evt) noexcept {
    auto& st = GetState();
    std::lock_guard lock(st.mutex);
    if (st.blindingEvents.size() < kMaxBlindingEvents) {
        st.blindingEvents.push_back(std::move(evt));
    }
}

bool EtwState::IsHandleSensitive(uint64_t regHandle) const noexcept {
    auto& st = GetState();
    std::lock_guard lock(st.mutex);
    auto it = st.providers.find(regHandle);
    if (it == st.providers.end()) return false;
    return it->second.isSensitive;
}

void EtwState::Reset() noexcept {
    auto& st = GetState();
    std::lock_guard lock(st.mutex);
    st.providers.clear();
    st.blindingEvents.clear();
    st.totalEventWrites.store(0, std::memory_order_relaxed);
    st.nextRegHandle.store(kRegHandleBase, std::memory_order_relaxed);
}

// ============================================================================
// Helpers
// ============================================================================

/// Read a GUID structure (16 bytes) from guest memory into an EtwGuid.
static bool ReadGuidFromGuest(VirtualMemory& mem, GuestAddress addr,
                              EtwGuid& out) noexcept {
    if (addr == 0) return false;

    uint32_t d1 = 0;
    uint16_t d2 = 0, d3 = 0;
    uint8_t  d4[8] = {};

    if (mem.ReadU32(addr,      d1) != ErrorCode::Success) return false;
    if (mem.ReadU16(addr + 4,  d2) != ErrorCode::Success) return false;
    if (mem.ReadU16(addr + 6,  d3) != ErrorCode::Success) return false;
    if (mem.Read(addr + 8, d4, 8)  != ErrorCode::Success) return false;

    out.data1 = d1;
    out.data2 = d2;
    out.data3 = d3;
    std::memcpy(out.data4, d4, 8);
    return true;
}

/// Check if a GUID matches any known sensitive provider.
static bool IsSensitiveProvider(const EtwGuid& guid) noexcept {
    for (const auto& sg : kSensitiveGuids) {
        if (sg.guid == guid) return true;
    }
    return false;
}

/// Return the human-readable name of a sensitive GUID, or empty string.
static const char* SensitiveProviderName(const EtwGuid& guid) noexcept {
    for (const auto& sg : kSensitiveGuids) {
        if (sg.guid == guid) return sg.name;
    }
    return "";
}

/// Write a 64-bit value to guest memory (pointer-width aware).
static ErrorCode WriteGuestU64(VirtualMemory& mem, GuestAddress addr,
                               uint64_t value) noexcept {
    return mem.Write(addr, &value, sizeof(value));
}

// ============================================================================
// EtwEventRegister
// ============================================================================
// NTSTATUS EtwEventRegister(
//     LPCGUID         ProviderId,       // [in]  Provider GUID
//     PENABLECALLBACK EnableCallback,    // [in]  Optional callback (ignored)
//     PVOID           CallbackContext,   // [in]  Optional context  (ignored)
//     PREGHANDLE      RegHandle          // [out] Registration handle
// )

bool HandleEtwEventRegister(APIContext& ctx) {
    GuestAddress pGuid      = ctx.GetArgPtr(0);
    // arg1 (EnableCallback) — ignored in emulation
    // arg2 (CallbackContext) — ignored in emulation
    GuestAddress pRegHandle = ctx.GetArgPtr(3);

    if (pGuid == 0 || pRegHandle == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    EtwGuid guid{};
    if (!ReadGuidFromGuest(ctx.Memory(), pGuid, guid)) {
        ctx.SetReturnNtStatus(NT::STATUS_ACCESS_VIOLATION);
        return true;
    }

    bool sensitive = IsSensitiveProvider(guid);

    auto& st = GetState();
    uint64_t regHandle = st.AllocRegHandle();

    EtwState::Instance().RegisterProvider(regHandle, guid, sensitive);

    // Flag registration of security-sensitive providers
    if (sensitive) {
        ctx.AddBehaviorFlag(BehaviorFlag::DefenseEvasion);

        EtwBlindingEvent evt;
        evt.kind       = EtwBlindingEvent::Kind::ProviderTampering;
        evt.patchAddr  = pGuid;
        evt.targetFunc = "EtwEventRegister";
        evt.detail     = std::string("Registered sensitive provider: ") +
                         SensitiveProviderName(guid) + " " + guid.ToString();
        EtwState::Instance().RecordBlindingEvent(std::move(evt));
    }

    // Write the REGHANDLE back to the caller
    auto err = WriteGuestU64(ctx.Memory(), pRegHandle, regHandle);
    if (err != ErrorCode::Success) {
        EtwState::Instance().UnregisterProvider(regHandle);
        ctx.SetReturnNtStatus(NT::STATUS_ACCESS_VIOLATION);
        return true;
    }

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// EtwEventUnregister
// ============================================================================
// NTSTATUS EtwEventUnregister(REGHANDLE RegHandle)

bool HandleEtwEventUnregister(APIContext& ctx) {
    uint64_t regHandle = ctx.GetArg(0);

    auto& state = EtwState::Instance();

    // Unregistering a sensitive provider is a defense evasion indicator
    if (state.IsHandleSensitive(regHandle)) {
        ctx.AddBehaviorFlag(BehaviorFlag::DefenseEvasion | BehaviorFlag::AntiAnalysis);

        EtwBlindingEvent evt;
        evt.kind       = EtwBlindingEvent::Kind::ProviderTampering;
        evt.patchAddr  = 0;
        evt.targetFunc = "EtwEventUnregister";
        evt.detail     = "Unregistered sensitive ETW provider (handle=" +
                         std::to_string(regHandle) + ")";
        state.RecordBlindingEvent(std::move(evt));
    }

    state.UnregisterProvider(regHandle);
    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// EtwEventWrite — THE critical function malware patches
// ============================================================================
// NTSTATUS EtwEventWrite(
//     REGHANDLE              RegHandle,
//     PCEVENT_DESCRIPTOR     EventDescriptor,
//     ULONG                  UserDataCount,
//     PEVENT_DATA_DESCRIPTOR UserData
// )

bool HandleEtwEventWrite(APIContext& ctx) {
    uint64_t     regHandle = ctx.GetArg(0);
    GuestAddress pEvtDesc  = ctx.GetArgPtr(1);
    uint32_t     dataCount = ctx.GetArg32(2);
    // arg3 = user data array (not deeply parsed in emulation)
    (void)dataCount;  // DESIGN: reserved for future rate-limit heuristic

    // Malware emitting ETW events is unusual — log it
    EtwState::Instance().IncrementEventWriteCount(regHandle);

    // If a sensitive provider is writing events, flag for analysis
    if (EtwState::Instance().IsHandleSensitive(regHandle)) {
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
    }

    // Validate event descriptor pointer (basic sanity)
    if (pEvtDesc == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// EtwEventWriteFull — Extended event write
// ============================================================================
// NTSTATUS EtwEventWriteFull(
//     REGHANDLE              RegHandle,
//     PCEVENT_DESCRIPTOR     EventDescriptor,
//     USHORT                 EventProperty,
//     LPCGUID                ActivityId,
//     LPCGUID                RelatedActivityId,
//     ULONG                  UserDataCount,
//     PEVENT_DATA_DESCRIPTOR UserData            (ignored — 7th arg, index 6)
// )
// Note: Per the task spec this has 6 args for registration but the real
// Windows API has 7. We register with 6 to match the spec.

bool HandleEtwEventWriteFull(APIContext& ctx) {
    uint64_t     regHandle = ctx.GetArg(0);
    GuestAddress pEvtDesc  = ctx.GetArgPtr(1);
    // Remaining args not deeply parsed

    EtwState::Instance().IncrementEventWriteCount(regHandle);

    if (EtwState::Instance().IsHandleSensitive(regHandle)) {
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
    }

    if (pEvtDesc == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// NtTraceEvent — Low-level syscall underlying ETW
// ============================================================================
// NTSTATUS NtTraceEvent(
//     HANDLE  TraceHandle,
//     ULONG   Flags,
//     ULONG   FieldSize,
//     PVOID   Fields
// )

bool HandleNtTraceEvent(APIContext& ctx) {
    uint64_t traceHandle = ctx.GetArg(0);
    uint32_t flags       = ctx.GetArg32(1);
    (void)flags;  // DESIGN: reserved for future NT flag-bit correlation

    // Direct syscall usage of NtTraceEvent is suspicious — most legitimate
    // code goes through EtwEventWrite. Direct syscalls suggest evasion.
    ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);

    // Count as an event write for tracking purposes
    EtwState::Instance().IncrementEventWriteCount(traceHandle);

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// NtTraceControl — ETW session management syscall
// ============================================================================
// NTSTATUS NtTraceControl(
//     ULONG  FunctionCode,
//     PVOID  InBuffer,
//     ULONG  InBufferLen,
//     PVOID  OutBuffer,
//     ULONG  OutBufferLen,
//     PULONG ReturnLength
// )

bool HandleNtTraceControl(APIContext& ctx) {
    uint32_t functionCode = ctx.GetArg32(0);
    GuestAddress retLenPtr = ctx.GetArgPtr(5);

    // Trace control operations from malware indicate ETW tampering
    ctx.AddBehaviorFlag(BehaviorFlag::DefenseEvasion);

    EtwBlindingEvent evt;
    evt.kind       = EtwBlindingEvent::Kind::ProtectionChange;
    evt.patchAddr  = 0;
    evt.targetFunc = "NtTraceControl";
    evt.detail     = "ETW session control invoked (FunctionCode=" +
                     std::to_string(functionCode) + ")";
    EtwState::Instance().RecordBlindingEvent(std::move(evt));

    // Write zero to ReturnLength if provided
    if (retLenPtr != 0) {
        uint32_t zero = 0;
        ctx.Memory().WriteU32(retLenPtr, zero);
    }

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// EtwEventEnabled — Provider/event query
// ============================================================================
// BOOLEAN EtwEventEnabled(
//     REGHANDLE              RegHandle,
//     PCEVENT_DESCRIPTOR     EventDescriptor
// )
// Returns TRUE (BOOLEAN=1) to prevent sandbox detection via "no ETW" heuristic.

bool HandleEtwEventEnabled(APIContext& ctx) {
    // Always report events as enabled — prevents malware from detecting
    // that it's in an emulation sandbox by checking ETW provider state.
    ctx.SetReturn(1); // TRUE — provider is enabled
    return true;
}

// ============================================================================
// EtwGetTraceLoggerHandle — Returns the trace session logger handle
// ============================================================================
// TRACEHANDLE EtwGetTraceLoggerHandle(PVOID Buffer)
// Returns a fake but plausible 64-bit logger handle.

bool HandleEtwGetTraceLoggerHandle(APIContext& ctx) {
    GuestAddress buffer = ctx.GetArgPtr(0);

    if (buffer == 0) {
        ctx.SetLastError(Win32::ERROR_INVALID_PARAMETER);
        ctx.SetReturn(0);
        return true;
    }

    // Return a fake logger handle that looks legitimate
    ctx.SetReturn(kFakeLoggerHandle);
    return true;
}

// ============================================================================
// EtwGetTraceEnableFlags — Returns the enable flags for a trace session
// ============================================================================
// ULONG EtwGetTraceEnableFlags(TRACEHANDLE TraceHandle)

bool HandleEtwGetTraceEnableFlags(APIContext& ctx) {
    // Return all flags enabled — prevents fingerprinting
    ctx.SetReturn32(kFakeEnableFlags);
    return true;
}

// ============================================================================
// EtwGetTraceEnableLevel — Returns the enable level for a trace session
// ============================================================================
// UCHAR EtwGetTraceEnableLevel(TRACEHANDLE TraceHandle)

bool HandleEtwGetTraceEnableLevel(APIContext& ctx) {
    // Return TRACE_LEVEL_VERBOSE (5) — maximum verbosity
    ctx.SetReturn32(static_cast<uint32_t>(kTraceVerboseLevel));
    return true;
}

// ============================================================================
// Registration — Wire all ETW handlers into the dispatcher
// ============================================================================

void RegisterEtwAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "ntdll.dll", "EtwEventRegister",         HandleEtwEventRegister,         4, false },
        { "ntdll.dll", "EtwEventUnregister",       HandleEtwEventUnregister,       1, false },
        { "ntdll.dll", "EtwEventWrite",            HandleEtwEventWrite,            4, false },
        { "ntdll.dll", "EtwEventWriteFull",        HandleEtwEventWriteFull,        6, false },
        { "ntdll.dll", "NtTraceEvent",             HandleNtTraceEvent,             4, false },
        { "ntdll.dll", "NtTraceControl",           HandleNtTraceControl,           6, false },
        { "ntdll.dll", "EtwEventEnabled",          HandleEtwEventEnabled,          2, false },
        { "ntdll.dll", "EtwGetTraceLoggerHandle",  HandleEtwGetTraceLoggerHandle,  1, false },
        { "ntdll.dll", "EtwGetTraceEnableFlags",   HandleEtwGetTraceEnableFlags,   1, false },
        { "ntdll.dll", "EtwGetTraceEnableLevel",   HandleEtwGetTraceEnableLevel,   1, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Ntdll

#pragma warning(pop)
