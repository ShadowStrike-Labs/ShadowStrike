/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * APIDispatcher.cpp — Central API routing, argument extraction, and call recording
 *
 * This is the backbone of Windows API emulation. When the CPU hits an API hook
 * address, the dispatcher:
 *   1. Identifies which API was called
 *   2. Extracts arguments per the calling convention (x64/x86)
 *   3. Dispatches to the registered handler
 *   4. Records the call for behavioral analysis
 *   5. Sets the return value and cleans up the stack
 *
 * Author: ShadowStrike-Labs contact@ShadowStrike.dev
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "APIDispatcher.hpp"
#include "APIDatabase.hpp"
#include "Ntdll\Ldr.hpp"
#include "Ntdll\NtFile.hpp"
#include "Ntdll\NtMemory.hpp"
#include "Ntdll\NtProcess.hpp"
#include "Ntdll\NtRegistry.hpp"
#include "Ntdll\NtSystem.hpp"
#include "Ntdll\NtThread.hpp"
#include "Ntdll\NtToken.hpp"
#include "../Core/CPU/State/CPUState.hpp"
#include "../Core/Memory/VirtualMemory.hpp"
#include "../Core/Loader/ImportResolver.hpp"

#include <algorithm>
#include <cstring>

namespace Phantom {

// ============================================================================
// Constants
// ============================================================================

// Each hook address is 8 bytes apart (pointer-width stride for x64 compatibility).
static constexpr GuestAddress kHookStride = 8;

// Maximum arguments we capture per API call.
static constexpr uint32_t kMaxCaptureArgs = 8;

// TEB offset for LastErrorValue on x64 (offset 0x68 in TEB).
static constexpr uint32_t kTEB64_LastErrorOffset = 0x68;
// TEB offset for LastErrorValue on x86 (offset 0x34 in TEB).
static constexpr uint32_t kTEB32_LastErrorOffset = 0x34;

// Win10 22H2 ThreadHideFromDebugger info class value.
static constexpr uint32_t kThreadHideFromDebugger = 0x11;

// CREATE_SUSPENDED flag for CreateProcess.
static constexpr uint32_t kCreateSuspended = 0x00000004;

// NTSTATUS returned for unimplemented syscalls.
static constexpr GuestNtStatus kStatusNotImplemented = NT::STATUS_NOT_IMPLEMENTED;

// ============================================================================
// ASCII-only lowercase helper (no locale dependency, no allocation)
// ============================================================================

static char ToLowerASCII(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
}

// ============================================================================
// Constructor
// ============================================================================

APIDispatcher::APIDispatcher(VirtualMemory& memory,
                             const EmulationConfig& config) noexcept
    : m_memory(memory)
    , m_config(config)
    , m_handleTable()
{
    m_callLog.reserve(std::min<uint32_t>(kMaxAPICallLog, 16384));
    m_hookMap.reserve(1024);
    m_nameMap.reserve(1024);

    // Initialize thread 0 (main emulated thread).
    auto& mainThread = m_threadStates[0];
    mainThread.threadId   = 0;
    mainThread.lastError  = 0;
    mainThread.tebAddress = 0;

    m_syscallTable.fill(nullptr);
}

// ============================================================================
// Register — Add a single API handler
// ============================================================================

void APIDispatcher::Register(const APIRegistration& reg) noexcept {
    if (!reg.handler || !reg.dllName || !reg.funcName) {
        return;
    }

    std::string key = MakeKey(reg.dllName, reg.funcName);

    // Reject duplicate registrations.
    if (m_nameMap.find(key) != m_nameMap.end()) {
        return;
    }

    // Allocate a hook address from the hook region.
    GuestAddress hookAddr = m_nextHookAddr;
    m_nextHookAddr += kHookStride;

    // Safety: if we've exhausted the hook region, silently stop registering.
    if (m_hookSize > 0 && (hookAddr - m_hookBase) >= m_hookSize) {
        return;
    }

    HandlerEntry entry{};
    entry.handler     = reg.handler;
    entry.dllName     = reg.dllName;
    entry.funcName    = reg.funcName;
    entry.argCount    = reg.argCount;
    entry.isCritical  = reg.isCritical;
    entry.isBlocked   = false;
    entry.hookAddress = hookAddr;
    entry.category    = ClassifyAPI(reg.dllName, reg.funcName);

    auto [it, inserted] = m_hookMap.emplace(hookAddr, entry);
    if (inserted) {
        m_nameMap.emplace(std::move(key), &it->second);

        // If this is a known syscall, wire it into the syscall table.
        const KnownAPIEntry* known = FindKnownAPI(reg.dllName, reg.funcName);
        if (known && known->syscallNumber != 0 &&
            known->syscallNumber < kMaxSyscallNumber) {
            m_syscallTable[known->syscallNumber] = &it->second;
        }
    }
}

// ============================================================================
// RegisterBatch — Register an array of API handlers
// ============================================================================

void APIDispatcher::RegisterBatch(const APIRegistration* regs,
                                  uint32_t count) noexcept {
    if (!regs) return;

    for (uint32_t i = 0; i < count; ++i) {
        Register(regs[i]);
    }
}

// ============================================================================
// RegisterAll — Call all DLL registration stubs
// ============================================================================
// Each individual RegisterXxx() is a stub that will be populated when
// the corresponding DLL handler module is implemented. The DLL modules
// themselves call Register()/RegisterBatch() to insert their entries.

void APIDispatcher::RegisterAll() noexcept {
    RegisterNtdll();
    RegisterKernel32();
    RegisterAdvapi32();
    RegisterWs2_32();
    RegisterWininet();
    RegisterWinhttp();
    RegisterUser32();
    RegisterShell32();
    RegisterOle32();
    RegisterUrlmon();
}

// DLL registration stubs — will be filled by DLL handler modules.
void APIDispatcher::RegisterNtdll() noexcept {
    WinAPI::Ntdll::RegisterNtMemory(*this);
    WinAPI::Ntdll::RegisterNtFile(*this);
    WinAPI::Ntdll::RegisterNtProcess(*this);
    WinAPI::Ntdll::RegisterNtThread(*this);
    WinAPI::Ntdll::RegisterNtRegistry(*this);
    WinAPI::Ntdll::RegisterNtSystem(*this);
    WinAPI::Ntdll::RegisterNtToken(*this);
    WinAPI::Ntdll::RegisterLdrHandlers(*this);
}
void APIDispatcher::RegisterKernel32() noexcept {}
void APIDispatcher::RegisterAdvapi32() noexcept {}
void APIDispatcher::RegisterWs2_32()   noexcept {}
void APIDispatcher::RegisterWininet()  noexcept {}
void APIDispatcher::RegisterWinhttp()  noexcept {}
void APIDispatcher::RegisterUser32()   noexcept {}
void APIDispatcher::RegisterShell32()  noexcept {}
void APIDispatcher::RegisterOle32()    noexcept {}
void APIDispatcher::RegisterUrlmon()   noexcept {}

// ============================================================================
// WireImports — Bind all registered hooks into the ImportResolver
// ============================================================================

void APIDispatcher::WireImports(ImportResolver& imports,
                                GuestAddress hookBase,
                                GuestSize hookRegionSize) noexcept {
    m_hookBase     = hookBase;
    m_hookSize     = hookRegionSize;
    m_nextHookAddr = hookBase;

    // Re-assign hook addresses sequentially from the new base.
    // This must be done before wiring because the previous hook addresses
    // were assigned with the old (possibly zero) base.
    for (auto& [addr, entry] : m_hookMap) {
        // We'll rebuild from scratch below, so break the loop.
        static_cast<void>(addr);
        static_cast<void>(entry);
    }

    // Rebuild hookMap with fresh addresses from the provided base.
    std::unordered_map<GuestAddress, HandlerEntry> newHookMap;
    newHookMap.reserve(m_hookMap.size());
    m_nameMap.clear();
    m_syscallTable.fill(nullptr);

    GuestAddress nextAddr = hookBase;

    for (auto& [oldAddr, entry] : m_hookMap) {
        if ((nextAddr - hookBase) >= hookRegionSize) {
            break;
        }
        entry.hookAddress = nextAddr;

        auto [it, inserted] = newHookMap.emplace(nextAddr, std::move(entry));
        if (inserted) {
            std::string key = MakeKey(it->second.dllName, it->second.funcName);
            m_nameMap.emplace(std::move(key), &it->second);

            // Re-register syscall entries.
            const KnownAPIEntry* known =
                FindKnownAPI(it->second.dllName, it->second.funcName);
            if (known && known->syscallNumber != 0 &&
                known->syscallNumber < kMaxSyscallNumber) {
                m_syscallTable[known->syscallNumber] = &it->second;
            }

            // Wire into ImportResolver.
            imports.RegisterAPIHook(
                it->second.dllName, it->second.funcName, nextAddr);
        }

        nextAddr += kHookStride;
    }

    m_hookMap     = std::move(newHookMap);
    m_nextHookAddr = nextAddr;
}

// ============================================================================
// Dispatch — Main entry point for API hook interception
// ============================================================================

bool APIDispatcher::Dispatch(CPUState& cpu, VirtualMemory& mem,
                             GuestAddress hookAddress) noexcept {
    auto it = m_hookMap.find(hookAddress);
    if (it == m_hookMap.end()) {
        return false;
    }

    HandlerEntry& entry = it->second;
    const bool is64 = cpu.Is64Bit();

    // If the API is blocked, fake a failure return and skip the handler.
    if (entry.isBlocked) {
        if (is64) {
            cpu.SetReg64(GPR::RAX, 0);
        } else {
            cpu.SetReg32(GPR::RAX, 0);
        }

        // Simulate stdcall return: pop return address from stack, set RIP.
        GuestAddress returnAddr = 0;
        if (is64) {
            mem.ReadU64(cpu.RSP(), returnAddr);
            cpu.SetReg64(GPR::RSP, cpu.RSP() + 8);
        } else {
            uint32_t retAddr32 = 0;
            mem.ReadU32(static_cast<GuestAddress>(cpu.GetReg32(GPR::RSP)), retAddr32);
            cpu.SetReg32(GPR::RSP, cpu.GetReg32(GPR::RSP) + 4);
            // x86 stdcall: also pop argCount * 4 bytes.
            cpu.SetReg32(GPR::RSP,
                         cpu.GetReg32(GPR::RSP) + entry.argCount * 4);
            returnAddr = retAddr32;
        }

        cpu.SetRIP(returnAddr);
        RecordCall(entry, cpu, 0, false, true);
        return true;
    }

    // Capture arguments for logging before the handler modifies them.
    uint64_t capturedArgs[kMaxCaptureArgs] = {};
    uint32_t captureCount = std::min<uint32_t>(entry.argCount, kMaxCaptureArgs);
    CaptureArgs(cpu, is64, captureCount, capturedArgs);

    // Read return address from top of stack (before handler runs).
    GuestAddress returnAddr = 0;
    if (is64) {
        mem.ReadU64(cpu.RSP(), returnAddr);
    } else {
        uint32_t retAddr32 = 0;
        mem.ReadU32(static_cast<GuestAddress>(cpu.GetReg32(GPR::RSP)), retAddr32);
        returnAddr = retAddr32;
    }

    // Build the API context.
    ThreadLocalState& tls = GetThreadState(0);
    APIContext ctx(cpu, mem, m_handleTable, m_config, tls, this);

    // Call the handler.
    bool continueExec = entry.handler(ctx);

    // Read return value from RAX/EAX.
    uint64_t returnValue = is64 ? cpu.RAX()
                                : static_cast<uint64_t>(cpu.GetReg32(GPR::RAX));

    // Simulate STDCALL return: pop return address from stack, set RIP.
    if (is64) {
        GuestAddress retFromStack = 0;
        mem.ReadU64(cpu.RSP(), retFromStack);
        cpu.SetReg64(GPR::RSP, cpu.RSP() + 8);
        cpu.SetRIP(retFromStack);
    } else {
        uint32_t retFromStack = 0;
        mem.ReadU32(static_cast<GuestAddress>(cpu.GetReg32(GPR::RSP)), retFromStack);
        cpu.SetReg32(GPR::RSP, cpu.GetReg32(GPR::RSP) + 4);
        // x86 stdcall: callee cleans arguments.
        cpu.SetReg32(GPR::RSP,
                     cpu.GetReg32(GPR::RSP) + entry.argCount * 4);
        cpu.SetRIP(static_cast<GuestAddress>(retFromStack));
    }

    // Determine success heuristic: non-zero return or NT_SUCCESS for Nt* APIs.
    bool succeeded = (returnValue != 0);
    if (entry.funcName) {
        std::string_view name(entry.funcName);
        if (name.size() > 2 && name[0] == 'N' && name[1] == 't') {
            succeeded = NT::NT_SUCCESS(static_cast<GuestNtStatus>(
                static_cast<int32_t>(returnValue)));
        }
    }

    // Record the call and update args for the log.
    RecordCall(entry, cpu, returnValue, succeeded, false);

    // Overwrite captured args into the last log entry.
    if (!m_callLog.empty()) {
        APICallDetail& last = m_callLog.back();
        last.returnAddress = returnAddr;
        last.argCount      = captureCount;
        for (uint32_t i = 0; i < captureCount; ++i) {
            last.args[i] = capturedArgs[i];
        }
        last.behaviorFlags = ctx.GetBehaviorFlags();
        DetectBehaviors(entry, last);
    }

    return continueExec;
}

// ============================================================================
// DispatchSyscall — Handle SYSCALL/SYSENTER/INT 0x2E
// ============================================================================

bool APIDispatcher::DispatchSyscall(CPUState& cpu, VirtualMemory& mem) noexcept {
    // Syscall number is in EAX/RAX.
    uint32_t syscallNum = cpu.GetReg32(GPR::RAX);

    if (syscallNum >= kMaxSyscallNumber || !m_syscallTable[syscallNum]) {
        // Unknown syscall: return STATUS_NOT_IMPLEMENTED in EAX.
        cpu.SetReg32(GPR::RAX, static_cast<uint32_t>(kStatusNotImplemented));
        return true;
    }

    HandlerEntry* entry = m_syscallTable[syscallNum];

    const bool is64 = cpu.Is64Bit();

    // Capture args for logging.
    uint64_t capturedArgs[kMaxCaptureArgs] = {};
    uint32_t captureCount = std::min<uint32_t>(entry->argCount, kMaxCaptureArgs);
    CaptureArgs(cpu, is64, captureCount, capturedArgs);

    // Build the context.
    ThreadLocalState& tls = GetThreadState(0);
    APIContext ctx(cpu, mem, m_handleTable, m_config, tls, this);

    if (entry->isBlocked) {
        cpu.SetReg32(GPR::RAX, static_cast<uint32_t>(kStatusNotImplemented));
        RecordCall(*entry, cpu, static_cast<uint64_t>(kStatusNotImplemented),
                   false, true);
        return true;
    }

    // Call the handler.
    bool continueExec = entry->handler(ctx);

    uint64_t returnValue = is64 ? cpu.RAX()
                                : static_cast<uint64_t>(cpu.GetReg32(GPR::RAX));

    bool succeeded = NT::NT_SUCCESS(
        static_cast<GuestNtStatus>(static_cast<int32_t>(returnValue)));

    RecordCall(*entry, cpu, returnValue, succeeded, false);

    if (!m_callLog.empty()) {
        APICallDetail& last = m_callLog.back();
        last.argCount = captureCount;
        for (uint32_t i = 0; i < captureCount; ++i) {
            last.args[i] = capturedArgs[i];
        }
        last.behaviorFlags = ctx.GetBehaviorFlags();
        DetectBehaviors(*entry, last);
    }

    return continueExec;
}

// ============================================================================
// RecordCall — Append a call entry to the ring-buffer log
// ============================================================================

void APIDispatcher::RecordCall(const HandlerEntry& entry, CPUState& cpu,
                               uint64_t returnValue, bool succeeded,
                               bool blocked) noexcept {
    APICallDetail detail{};
    detail.ordinal        = m_callCount;
    detail.dllName        = entry.dllName;
    detail.funcName       = entry.funcName;
    detail.category       = entry.category;
    detail.behaviorFlags  = BehaviorFlag::None;
    detail.returnAddress  = 0;
    detail.returnValue    = returnValue;
    detail.argCount       = entry.argCount;
    detail.instructionNum = static_cast<uint32_t>(cpu.instructionCount);
    detail.threadId       = 0;
    detail.wasBlocked     = blocked;
    detail.succeeded      = succeeded;

    if (m_callLog.size() < kMaxAPICallLog) {
        m_callLog.push_back(detail);
    } else {
        // Ring buffer: overwrite oldest entry.
        m_callLog[m_callCount % kMaxAPICallLog] = detail;
    }

    ++m_callCount;
}

// ============================================================================
// CaptureArgs — Read first N args from CPU state per calling convention
// ============================================================================

void APIDispatcher::CaptureArgs(const CPUState& cpu, bool is64,
                                uint32_t argCount,
                                uint64_t* outArgs) const noexcept {
    if (!outArgs || argCount == 0) return;

    if (is64) {
        // x64 Windows: RCX, RDX, R8, R9, then stack at RSP+0x28 + (index-4)*8.
        static constexpr GPR kArgRegs[4] = {
            GPR::RCX, GPR::RDX, GPR::R8, GPR::R9
        };

        for (uint32_t i = 0; i < argCount; ++i) {
            if (i < 4) {
                outArgs[i] = cpu.GetReg64(kArgRegs[i]);
            } else {
                // Stack args: RSP + 0x28 + (i - 4) * 8
                // 0x28 = return addr (8) + shadow space (4*8=32) = 40 = 0x28
                GuestAddress stackAddr = cpu.RSP() + 0x28 +
                    static_cast<uint64_t>(i - 4) * 8;
                uint64_t val = 0;
                m_memory.ReadU64(stackAddr, val);
                outArgs[i] = val;
            }
        }
    } else {
        // x86 stdcall: all args on stack at ESP+4, ESP+8, ...
        GuestAddress esp = static_cast<GuestAddress>(cpu.GetReg32(GPR::RSP));
        for (uint32_t i = 0; i < argCount; ++i) {
            GuestAddress stackAddr = esp + 4 + static_cast<uint64_t>(i) * 4;
            uint32_t val32 = 0;
            m_memory.ReadU32(stackAddr, val32);
            outArgs[i] = val32;
        }
    }
}

// ============================================================================
// DetectBehaviors — Post-call behavioral flag detection
// ============================================================================

void APIDispatcher::DetectBehaviors(const HandlerEntry& entry,
                                    APICallDetail& detail) noexcept {
    if (!detail.succeeded && !detail.wasBlocked) {
        return;
    }

    BehaviorFlag flags = detail.behaviorFlags;

    // Apply the static flag from the KnownAPI database entry.
    const KnownAPIEntry* known =
        FindKnownAPI(entry.dllName, entry.funcName);
    if (known) {
        flags = flags | known->suspiciousFlag;
    }

    std::string_view funcName(entry.funcName ? entry.funcName : "");

    // WriteProcessMemory / NtWriteVirtualMemory to a remote process.
    if (funcName == "WriteProcessMemory" || funcName == "NtWriteVirtualMemory") {
        GuestHandle hProcess = detail.args[0];
        if (hProcess != kCurrentProcess && hProcess != kNullHandle) {
            flags = flags | BehaviorFlag::ProcessInjection;
            flags = flags | BehaviorFlag::CodeInjection;
        }
    }

    // VirtualAllocEx to a remote process.
    if (funcName == "VirtualAllocEx") {
        GuestHandle hProcess = detail.args[0];
        if (hProcess != kCurrentProcess && hProcess != kNullHandle) {
            flags = flags | BehaviorFlag::CodeInjection;
        }
    }

    // VirtualProtectEx to a remote process.
    if (funcName == "VirtualProtectEx") {
        GuestHandle hProcess = detail.args[0];
        if (hProcess != kCurrentProcess && hProcess != kNullHandle) {
            flags = flags | BehaviorFlag::CodeInjection;
        }
    }

    // CreateRemoteThread / CreateRemoteThreadEx.
    if (funcName == "CreateRemoteThread" || funcName == "CreateRemoteThreadEx" ||
        funcName == "NtCreateThreadEx") {
        flags = flags | BehaviorFlag::RemoteThreadCreation;
    }

    // CreateProcess with CREATE_SUSPENDED → process hollowing indicator.
    if (funcName == "CreateProcessA" || funcName == "CreateProcessW") {
        // dwCreationFlags is arg index 5 for CreateProcess.
        uint32_t creationFlags = static_cast<uint32_t>(detail.args[5]);
        if (creationFlags & kCreateSuspended) {
            flags = flags | BehaviorFlag::ProcessHollowing;
        }
    }

    // NtSetInformationThread with ThreadHideFromDebugger.
    if (funcName == "NtSetInformationThread") {
        uint32_t infoClass = static_cast<uint32_t>(detail.args[1]);
        if (infoClass == kThreadHideFromDebugger) {
            flags = flags | BehaviorFlag::AntiAnalysis;
        }
    }

    // SetThreadContext → code injection (change RIP/EIP of another thread).
    if (funcName == "SetThreadContext") {
        flags = flags | BehaviorFlag::CodeInjection;
    }

    // URLDownloadToFile → network + file drop.
    if (funcName == "URLDownloadToFileA" || funcName == "URLDownloadToFileW") {
        flags = flags | BehaviorFlag::NetworkC2;
        flags = flags | BehaviorFlag::FileDropped;
    }

    // Service creation/start.
    if (funcName == "CreateServiceA" || funcName == "CreateServiceW" ||
        funcName == "StartServiceA" || funcName == "StartServiceW") {
        flags = flags | BehaviorFlag::ServiceManipulation;
    }

    // Registry run-key persistence patterns.
    if (funcName == "RegSetValueExA" || funcName == "RegSetValueExW" ||
        funcName == "NtSetValueKey") {
        flags = flags | BehaviorFlag::RegistryPersistence;
    }

    // DLL injection via LoadLibrary into remote context (heuristic: combined
    // with prior VirtualAllocEx + WriteProcessMemory this is already flagged).
    if (funcName == "LdrLoadDll") {
        flags = flags | BehaviorFlag::DLLInjection;
    }

    // AdjustTokenPrivileges → privilege escalation.
    if (funcName == "AdjustTokenPrivileges" ||
        funcName == "NtAdjustPrivilegesToken") {
        flags = flags | BehaviorFlag::PrivilegeEscalation;
    }

    // Keyboard hooking.
    if (funcName == "SetWindowsHookExA" || funcName == "SetWindowsHookExW") {
        flags = flags | BehaviorFlag::Keylogging;
    }

    // Accumulate into session-wide flags and update the current call detail.
    m_behaviorFlags = m_behaviorFlags | flags;
    detail.behaviorFlags = flags;
}

// ============================================================================
// MakeKey — Build "dllname!funcname" lookup key (dll portion lowercase)
// ============================================================================

std::string APIDispatcher::MakeKey(std::string_view dll,
                                   std::string_view func) noexcept {
    std::string key;
    key.reserve(dll.size() + 1 + func.size());
    for (char c : dll) {
        key += ToLowerASCII(c);
    }
    key += '!';
    key.append(func.data(), func.size());
    return key;
}

// ============================================================================
// NormalizeDLL — Lowercase a DLL name, strip trailing ".dll" if present
// ============================================================================

std::string APIDispatcher::NormalizeDLL(std::string_view name) noexcept {
    std::string result;
    result.reserve(name.size());
    for (char c : name) {
        result += ToLowerASCII(c);
    }
    // Strip trailing ".dll" for uniform lookup.
    constexpr std::string_view suffix = ".dll";
    if (result.size() > suffix.size()) {
        bool hasSuffix = true;
        for (size_t i = 0; i < suffix.size(); ++i) {
            if (result[result.size() - suffix.size() + i] != suffix[i]) {
                hasSuffix = false;
                break;
            }
        }
        if (hasSuffix) {
            result.resize(result.size() - suffix.size());
        }
    }
    return result;
}

// ============================================================================
// ClassifyAPI — Determine APICategory from dll + function name
// ============================================================================

APICategory APIDispatcher::ClassifyAPI(std::string_view dllName,
                                       std::string_view funcName) noexcept {
    // First try the static database.
    const KnownAPIEntry* known = FindKnownAPI(dllName, funcName);
    if (known) {
        return known->category;
    }

    // Heuristic classification by DLL name.
    std::string dllLower;
    dllLower.reserve(dllName.size());
    for (char c : dllName) {
        dllLower += ToLowerASCII(c);
    }

    if (dllLower.find("ws2_32")  != std::string::npos ||
        dllLower.find("wininet") != std::string::npos ||
        dllLower.find("winhttp") != std::string::npos ||
        dllLower.find("urlmon")  != std::string::npos) {
        return APICategory::Network;
    }
    if (dllLower.find("advapi32") != std::string::npos) {
        // Could be registry, security, service — default to Unknown.
        return APICategory::Unknown;
    }
    if (dllLower.find("ole32") != std::string::npos ||
        dllLower.find("oleaut32") != std::string::npos) {
        return APICategory::COM;
    }
    if (dllLower.find("user32") != std::string::npos) {
        return APICategory::Unknown;
    }
    if (dllLower.find("shell32") != std::string::npos) {
        return APICategory::Process;
    }

    // Heuristic by function name prefix.
    if (funcName.size() >= 2) {
        if (funcName.substr(0, 2) == "Nt" || funcName.substr(0, 2) == "Zw") {
            return APICategory::Unknown;
        }
        if (funcName.substr(0, 3) == "Reg") {
            return APICategory::Registry;
        }
        if (funcName.substr(0, 7) == "Virtual") {
            return APICategory::Memory;
        }
        if (funcName.substr(0, 4) == "Heap") {
            return APICategory::Memory;
        }
    }

    return APICategory::Unknown;
}

// ============================================================================
// GetCallLog / GetCallCount / GetBehaviorFlags
// ============================================================================

const std::vector<APICallDetail>& APIDispatcher::GetCallLog() const noexcept {
    return m_callLog;
}

uint32_t APIDispatcher::GetCallCount() const noexcept {
    return m_callCount;
}

BehaviorFlag APIDispatcher::GetBehaviorFlags() const noexcept {
    return m_behaviorFlags;
}

// ============================================================================
// GetCallsByCategory
// ============================================================================

std::vector<const APICallDetail*> APIDispatcher::GetCallsByCategory(
    APICategory category) const noexcept
{
    std::vector<const APICallDetail*> result;
    result.reserve(256);

    for (const auto& entry : m_callLog) {
        if (entry.category == category) {
            result.push_back(&entry);
        }
    }
    return result;
}

// ============================================================================
// GetThreadState
// ============================================================================

ThreadLocalState& APIDispatcher::GetThreadState(uint32_t threadId) noexcept {
    auto it = m_threadStates.find(threadId);
    if (it != m_threadStates.end()) {
        return it->second;
    }

    auto& state = m_threadStates[threadId];
    state.threadId   = threadId;
    state.lastError  = 0;
    state.tebAddress = 0;
    return state;
}

// ============================================================================
// IsRegistered
// ============================================================================

bool APIDispatcher::IsRegistered(std::string_view dllName,
                                 std::string_view funcName) const noexcept {
    std::string key = MakeKey(dllName, funcName);
    return m_nameMap.find(key) != m_nameMap.end();
}

// ============================================================================
// GetRegisteredCount
// ============================================================================

uint32_t APIDispatcher::GetRegisteredCount() const noexcept {
    return static_cast<uint32_t>(m_hookMap.size());
}

// ============================================================================
// GetHookAddress
// ============================================================================

std::optional<GuestAddress> APIDispatcher::GetHookAddress(
    std::string_view dllName, std::string_view funcName) const noexcept
{
    std::string key = MakeKey(dllName, funcName);
    auto it = m_nameMap.find(key);
    if (it == m_nameMap.end()) {
        return std::nullopt;
    }
    return it->second->hookAddress;
}

// ============================================================================
// BlockAPI
// ============================================================================

void APIDispatcher::BlockAPI(std::string_view dllName,
                             std::string_view funcName) noexcept {
    std::string key = MakeKey(dllName, funcName);
    auto it = m_nameMap.find(key);
    if (it != m_nameMap.end()) {
        it->second->isBlocked = true;
    }
}

// ============================================================================
// Reset
// ============================================================================

void APIDispatcher::Reset() noexcept {
    m_callLog.clear();
    m_callCount      = 0;
    m_behaviorFlags  = BehaviorFlag::None;
    m_handleTable.Reset();

    m_threadStates.clear();
    auto& mainThread = m_threadStates[0];
    mainThread.threadId   = 0;
    mainThread.lastError  = 0;
    mainThread.tebAddress = 0;
}

// ============================================================================
// ============================================================================
//
//  APIContext Method Implementations
//
// ============================================================================
// ============================================================================

// ============================================================================
// GetArg — Calling-convention-aware argument extraction
// ============================================================================

uint64_t APIContext::GetArg(uint32_t index) const noexcept {
    if (Is64Bit()) {
        // x64 Windows calling convention:
        //   0 → RCX, 1 → RDX, 2 → R8, 3 → R9
        //   4+ → stack at RSP + 0x28 + (index - 4) * 8
        switch (index) {
            case 0: return m_cpu.RCX();
            case 1: return m_cpu.RDX();
            case 2: return m_cpu.GetReg64(GPR::R8);
            case 3: return m_cpu.GetReg64(GPR::R9);
            default: {
                GuestAddress stackAddr =
                    m_cpu.RSP() + 0x28 + static_cast<uint64_t>(index - 4) * 8;
                uint64_t val = 0;
                m_mem.ReadU64(stackAddr, val);
                return val;
            }
        }
    } else {
        // x86 stdcall: all args on stack at ESP + 4 + index * 4.
        GuestAddress esp = static_cast<GuestAddress>(m_cpu.GetReg32(GPR::RSP));
        GuestAddress stackAddr = esp + 4 + static_cast<uint64_t>(index) * 4;
        uint32_t val32 = 0;
        m_mem.ReadU32(stackAddr, val32);
        return static_cast<uint64_t>(val32);
    }
}

// ============================================================================
// GetArg32
// ============================================================================

uint32_t APIContext::GetArg32(uint32_t index) const noexcept {
    return static_cast<uint32_t>(GetArg(index));
}

// ============================================================================
// GetArgPtr — Pointer-sized argument
// ============================================================================

GuestAddress APIContext::GetArgPtr(uint32_t index) const noexcept {
    return GetArg(index);
}

// ============================================================================
// ReadAnsiString — Read null-terminated ANSI string from guest memory
// ============================================================================

std::string APIContext::ReadAnsiString(GuestAddress addr,
                                       uint32_t maxLen) const noexcept {
    if (addr == 0) return {};

    std::string result;
    result.reserve(std::min<uint32_t>(maxLen, 256));

    for (uint32_t i = 0; i < maxLen; ++i) {
        uint8_t ch = 0;
        if (m_mem.ReadU8(addr + i, ch) != ErrorCode::Success) {
            break;
        }
        if (ch == 0) break;
        result += static_cast<char>(ch);
    }

    return result;
}

// ============================================================================
// ReadWideString — Read null-terminated UTF-16LE string from guest memory
// ============================================================================

std::wstring APIContext::ReadWideString(GuestAddress addr,
                                        uint32_t maxChars) const noexcept {
    if (addr == 0) return {};

    std::wstring result;
    result.reserve(std::min<uint32_t>(maxChars, 256));

    for (uint32_t i = 0; i < maxChars; ++i) {
        uint16_t wch = 0;
        if (m_mem.ReadU16(addr + static_cast<uint64_t>(i) * 2, wch) !=
            ErrorCode::Success) {
            break;
        }
        if (wch == 0) break;
        result += static_cast<wchar_t>(wch);
    }

    return result;
}

// ============================================================================
// ReadUnicodeString — Read a UNICODE_STRING structure
// ============================================================================
// Layout (x64):
//   offset 0: Length        (uint16_t) — byte count of string (not including null)
//   offset 2: MaximumLength (uint16_t)
//   offset 4: padding       (4 bytes on x64 for alignment)
//   offset 8: Buffer        (uint64_t pointer)
// Layout (x86):
//   offset 0: Length        (uint16_t)
//   offset 2: MaximumLength (uint16_t)
//   offset 4: Buffer        (uint32_t pointer)

std::wstring APIContext::ReadUnicodeString(GuestAddress addr) const noexcept {
    if (addr == 0) return {};

    uint16_t length = 0;
    uint16_t maxLength = 0;
    if (m_mem.ReadU16(addr, length) != ErrorCode::Success) return {};
    if (m_mem.ReadU16(addr + 2, maxLength) != ErrorCode::Success) return {};

    // Validate: length should not exceed reasonable bounds.
    if (length == 0 || length > 32768) return {};

    GuestAddress bufferPtr = 0;
    if (Is64Bit()) {
        uint64_t ptr64 = 0;
        if (m_mem.ReadU64(addr + 8, ptr64) != ErrorCode::Success) return {};
        bufferPtr = ptr64;
    } else {
        uint32_t ptr32 = 0;
        if (m_mem.ReadU32(addr + 4, ptr32) != ErrorCode::Success) return {};
        bufferPtr = static_cast<GuestAddress>(ptr32);
    }

    if (bufferPtr == 0) return {};

    // Length is in bytes; each wchar is 2 bytes.
    uint32_t charCount = length / 2;
    return ReadWideString(bufferPtr, charCount);
}

// ============================================================================
// WriteAnsiString
// ============================================================================

ErrorCode APIContext::WriteAnsiString(GuestAddress addr,
                                      std::string_view str,
                                      uint32_t maxLen) noexcept {
    if (addr == 0) return ErrorCode::InvalidAddress;

    uint32_t writeLen = static_cast<uint32_t>(
        std::min<size_t>(str.size(), maxLen > 0 ? maxLen - 1 : 0));

    ErrorCode ec = m_mem.Write(addr, str.data(), writeLen);
    if (ec != ErrorCode::Success) return ec;

    // Write null terminator.
    uint8_t null = 0;
    return m_mem.WriteU8(addr + writeLen, null);
}

// ============================================================================
// WriteWideString
// ============================================================================

ErrorCode APIContext::WriteWideString(GuestAddress addr,
                                      std::wstring_view str,
                                      uint32_t maxChars) noexcept {
    if (addr == 0) return ErrorCode::InvalidAddress;

    uint32_t writeChars = static_cast<uint32_t>(
        std::min<size_t>(str.size(), maxChars > 0 ? maxChars - 1 : 0));

    for (uint32_t i = 0; i < writeChars; ++i) {
        uint16_t wch = static_cast<uint16_t>(str[i]);
        ErrorCode ec = m_mem.WriteU16(
            addr + static_cast<uint64_t>(i) * 2, wch);
        if (ec != ErrorCode::Success) return ec;
    }

    // Write null terminator.
    uint16_t null = 0;
    return m_mem.WriteU16(addr + static_cast<uint64_t>(writeChars) * 2, null);
}

// ============================================================================
// SetReturn — Write to RAX (x64) or EAX (x86)
// ============================================================================

void APIContext::SetReturn(uint64_t value) noexcept {
    if (Is64Bit()) {
        m_cpu.SetReg64(GPR::RAX, value);
    } else {
        m_cpu.SetReg32(GPR::RAX, static_cast<uint32_t>(value));
    }
}

// ============================================================================
// SetReturn32 — Write to EAX (zero-extend on x64)
// ============================================================================

void APIContext::SetReturn32(uint32_t value) noexcept {
    m_cpu.SetReg32(GPR::RAX, value);
}

// ============================================================================
// SetReturnBool — Win32 BOOL: TRUE=1, FALSE=0
// ============================================================================

void APIContext::SetReturnBool(bool value) noexcept {
    SetReturn(value ? 1ULL : 0ULL);
}

// ============================================================================
// SetReturnHandle
// ============================================================================

void APIContext::SetReturnHandle(GuestHandle h) noexcept {
    SetReturn(h);
}

// ============================================================================
// SetReturnNtStatus
// ============================================================================

void APIContext::SetReturnNtStatus(GuestNtStatus status) noexcept {
    SetReturn32(static_cast<uint32_t>(status));
}

// ============================================================================
// SetLastError — Update TLS and optionally write to TEB
// ============================================================================

void APIContext::SetLastError(GuestDword err) noexcept {
    m_tls.lastError = err;

    // If TEB address is known, also write to the TEB structure so
    // malware reading the TEB directly sees the correct value.
    if (m_tls.tebAddress != 0) {
        uint32_t offset = Is64Bit() ? kTEB64_LastErrorOffset
                                    : kTEB32_LastErrorOffset;
        m_mem.WriteU32(m_tls.tebAddress + offset, err);
    }
}

// ============================================================================
// GetLastError
// ============================================================================

GuestDword APIContext::GetLastError() const noexcept {
    return m_tls.lastError;
}

// ============================================================================
// FailWithError — SetLastError + return FALSE
// ============================================================================

void APIContext::FailWithError(GuestDword err) noexcept {
    SetLastError(err);
    SetReturnBool(false);
}

// ============================================================================
// FailWithInvalidHandle
// ============================================================================

void APIContext::FailWithInvalidHandle(GuestDword err) noexcept {
    SetLastError(err);
    SetReturnHandle(kInvalidHandleValue);
}

// ============================================================================
// CleanupStack — x86 only: add bytes to ESP (stdcall callee cleanup)
// ============================================================================

void APIContext::CleanupStack(uint32_t bytes) noexcept {
    if (Is64Bit()) return; // x64 is caller-cleanup.

    uint32_t esp = m_cpu.GetReg32(GPR::RSP);
    m_cpu.SetReg32(GPR::RSP, esp + bytes);
}

// ============================================================================
// Is64Bit
// ============================================================================

bool APIContext::Is64Bit() const noexcept {
    return m_cpu.Is64Bit();
}

} // namespace Phantom
