/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * APIDispatcher.hpp — Central API routing, argument extraction, and call recording
 *
 * This is the backbone of Windows API emulation. When the CPU hits an API hook
 * address, the dispatcher:
 *   1. Identifies which API was called
 *   2. Extracts arguments per the calling convention (x64/x86)
 *   3. Dispatches to the registered handler
 *   4. Records the call for behavioral analysis
 *   5. Sets the return value and cleans up the stack
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "APITypes.hpp"
#include "HandleTable.hpp"
#include "../Common/Types.hpp"
#include "../Common/Config.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <functional>
#include <optional>
#include <array>
#include <atomic>

namespace Phantom {

// Forward declarations
class CPU;
class VirtualMemory;
class ImportResolver;
class ExportResolver;

// ============================================================================
// APIDispatcher — Central routing engine for Windows API emulation
// ============================================================================
//
// Lifecycle:
//   1. Construct with references to CPU, memory, config
//   2. Call RegisterAll() to register all DLL handler modules
//   3. Call WireImports() to register hook addresses with ImportResolver
//   4. Set as the CPU's APICallCallback
//   5. CPU calls Dispatch() whenever it hits a hook address
//
// Not thread-safe internally — designed for single-threaded emulation.
// (Multi-threading is handled at the EmulatedThread level above.)

class APIDispatcher {
public:
    APIDispatcher(VirtualMemory& memory, const EmulationConfig& config) noexcept;
    ~APIDispatcher() noexcept = default;

    APIDispatcher(const APIDispatcher&) = delete;
    APIDispatcher& operator=(const APIDispatcher&) = delete;

    // === Registration ===

    // Register a single API handler.
    void Register(const APIRegistration& reg) noexcept;

    // Register a batch of handlers (used by DLL modules).
    void RegisterBatch(const APIRegistration* regs, uint32_t count) noexcept;

    // Register all built-in DLL modules (Ntdll, Kernel32, Advapi32, etc.)
    void RegisterAll() noexcept;

    // Wire all registered APIs into the ImportResolver as hook addresses.
    // This must be called AFTER RegisterAll() and BEFORE emulation starts.
    void WireImports(ImportResolver& imports, GuestAddress hookBase,
                     GuestSize hookRegionSize) noexcept;

    // === Dispatch (called by CPU on API hook hit) ===

    // Main dispatch entry point. Returns true if handled (continue), false to stop.
    [[nodiscard]] bool Dispatch(CPUState& cpu, VirtualMemory& mem,
                                GuestAddress hookAddress) noexcept;

    // Syscall dispatch entry point (for SYSCALL/SYSENTER/INT 0x2E).
    [[nodiscard]] bool DispatchSyscall(CPUState& cpu, VirtualMemory& mem) noexcept;

    // === API Call Logging ===

    // Get the complete API call log (ring buffer).
    [[nodiscard]] const std::vector<APICallDetail>& GetCallLog() const noexcept;

    // Get the number of API calls made.
    [[nodiscard]] uint32_t GetCallCount() const noexcept;

    // Get accumulated behavior flags.
    [[nodiscard]] BehaviorFlag GetBehaviorFlags() const noexcept;

    // Get calls filtered by category.
    [[nodiscard]] std::vector<const APICallDetail*> GetCallsByCategory(
        APICategory category) const noexcept;

    // === State ===

    // Get the handle table.
    [[nodiscard]] HandleTable& GetHandleTable() noexcept { return m_handleTable; }
    [[nodiscard]] const HandleTable& GetHandleTable() const noexcept { return m_handleTable; }

    // Get thread-local state for current thread.
    [[nodiscard]] ThreadLocalState& GetThreadState(uint32_t threadId) noexcept;

    // Check if an API is registered.
    [[nodiscard]] bool IsRegistered(std::string_view dllName,
                                    std::string_view funcName) const noexcept;

    // Get total registered API count.
    [[nodiscard]] uint32_t GetRegisteredCount() const noexcept;

    // Get the hook address for a specific API (for manual hook setup).
    [[nodiscard]] std::optional<GuestAddress> GetHookAddress(
        std::string_view dllName, std::string_view funcName) const noexcept;

    // === Control ===

    // Block a specific API (handler won't execute, returns failure).
    void BlockAPI(std::string_view dllName, std::string_view funcName) noexcept;

    // Reset state (for new emulation session).
    void Reset() noexcept;

    // Maximum syscall number we handle
    static constexpr uint32_t kMaxSyscallNumber = 512;

private:
    VirtualMemory&         m_memory;
    const EmulationConfig& m_config;
    HandleTable            m_handleTable;

    // === Handler Registry ===

    struct HandlerEntry {
        APIHandlerFn    handler     = nullptr;
        const char*     dllName     = nullptr;
        const char*     funcName    = nullptr;
        APICategory     category    = APICategory::Unknown;
        uint8_t         argCount    = 0;
        bool            isCritical  = false;
        bool            isBlocked   = false;
        GuestAddress    hookAddress = 0;
    };

    // Hook address → handler entry
    std::unordered_map<GuestAddress, HandlerEntry> m_hookMap;

    // "dllname!funcname" → handler entry (for lookup by name)
    std::unordered_map<std::string, HandlerEntry*> m_nameMap;

    // Syscall number → handler entry (for SYSCALL dispatch)
    std::array<HandlerEntry*, kMaxSyscallNumber> m_syscallTable{};

    // Hook address allocation
    GuestAddress m_nextHookAddr = 0;
    GuestAddress m_hookBase     = 0;
    GuestSize    m_hookSize     = 0;

    // === API Call Log ===
    std::vector<APICallDetail> m_callLog;
    uint32_t m_callCount = 0;
    BehaviorFlag m_behaviorFlags = BehaviorFlag::None;

    // === Thread State (per emulated thread) ===
    std::unordered_map<uint32_t, ThreadLocalState> m_threadStates;

    // === Internal helpers ===

    [[nodiscard]] static std::string MakeKey(std::string_view dll,
                                             std::string_view func) noexcept;
    [[nodiscard]] static std::string NormalizeDLL(std::string_view name) noexcept;
    [[nodiscard]] static APICategory ClassifyAPI(std::string_view dllName,
                                                 std::string_view funcName) noexcept;

    // Record a call in the log
    void RecordCall(const HandlerEntry& entry, CPUState& cpu,
                    uint64_t returnValue, bool succeeded, bool blocked) noexcept;

    // Extract arguments for logging (reads from CPU state)
    void CaptureArgs(const CPUState& cpu, bool is64, uint32_t argCount,
                     uint64_t* outArgs) const noexcept;

    // Post-call behavioral flag detection
    void DetectBehaviors(const HandlerEntry& entry, APICallDetail& detail) noexcept;

    // === DLL Registration Helpers (called by RegisterAll) ===
    void RegisterNtdll() noexcept;
    void RegisterKernel32() noexcept;
    void RegisterAdvapi32() noexcept;
    void RegisterWs2_32() noexcept;
    void RegisterWininet() noexcept;
    void RegisterWinhttp() noexcept;
    void RegisterUser32() noexcept;
    void RegisterShell32() noexcept;
    void RegisterOle32() noexcept;
    void RegisterBcrypt() noexcept;
    void RegisterUrlmon() noexcept;
    void RegisterAmsi() noexcept;
};

} // namespace Phantom
