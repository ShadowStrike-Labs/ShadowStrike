/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ImportResolver.hpp — PE import table resolver with API hook integration
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../../Common/Types.hpp"
#include "../../Common/Errors.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <unordered_map>

namespace Phantom {

// Forward declarations (full definitions only required in .cpp)
class ExportResolver;
class VirtualMemory;

// ============================================================================
// ImportResolution — Result of resolving all imports for a loaded PE
// ============================================================================

struct ImportResolution {
    struct ResolvedEntry {
        GuestAddress iatSlotAddress  = 0; // Guest address of the IAT slot
        GuestAddress resolvedAddress = 0; // Address written into IAT slot
        std::string  dllName;
        std::string  funcName;
        uint16_t     ordinal   = 0;
        bool         byOrdinal = false;
        bool         isHooked  = false;   // Resolved to API hook, not real export
    };

    std::vector<ResolvedEntry> resolved;
    std::vector<std::string>   failedImports; // Names that couldn't be resolved
    uint32_t totalResolved = 0;
    uint32_t totalFailed   = 0;
};

// ============================================================================
// ImportResolver — Wires PE imports to exports or API hook addresses
// ============================================================================
//
// Resolves PE import tables by matching each imported function to either:
//   (a) A real export address from a loaded module (via ExportResolver), or
//   (b) An API hook address for hooked/emulated APIs (APIDispatcher integration).
//
// When an import cannot be found in either registered hooks or loaded exports,
// the resolver auto-allocates a hook address from a configurable range so the
// API dispatcher can still intercept the call.
//
// Not thread-safe: expected to run single-threaded during PE loading.

class ImportResolver {
public:
    explicit ImportResolver(const ExportResolver& exports) noexcept;

    // Set the API hook address range for auto-allocated hooks.
    void SetAPIHookRange(GuestAddress base, GuestSize size) noexcept;

    // Register an API hook: when DLL.func is imported, use this hook address instead
    void RegisterAPIHook(std::string_view dllName, std::string_view funcName,
                         GuestAddress hookAddress) noexcept;
    void RegisterAPIHookByOrdinal(std::string_view dllName, uint16_t ordinal,
                                   GuestAddress hookAddress) noexcept;

    // Resolve all imports for a loaded PE.
    // imageBase: where PE was loaded in guest memory
    // memory: guest virtual memory (to write resolved IAT entries)
    // peData: raw PE file bytes (for parsing import directory)
    // is64Bit: PE32 vs PE64
    [[nodiscard]] ImportResolution ResolveAll(
        GuestAddress imageBase,
        VirtualMemory& memory,
        ByteSpan peData,
        bool is64Bit) noexcept;

    // Get the hook address for a specific API (or nullopt if not hooked)
    [[nodiscard]] std::optional<GuestAddress> GetHookAddress(
        std::string_view dllName, std::string_view funcName) const noexcept;

private:
    const ExportResolver& m_exports;
    GuestAddress m_hookBase     = 0;
    GuestSize    m_hookSize     = 0;
    GuestAddress m_nextHookAddr = 0;

    struct HookKey {
        std::string dll;
        std::string func;
    };

    // Keyed by "dllname!funcname" (dll portion lowercase-normalized)
    std::unordered_map<std::string, GuestAddress> m_hooksByName;
    // Keyed by "dllname!#ordinal"
    std::unordered_map<std::string, GuestAddress> m_hooksByOrdinal;

    [[nodiscard]] static std::string MakeHookKey(
        std::string_view dll, std::string_view func) noexcept;
    [[nodiscard]] static std::string MakeOrdinalKey(
        std::string_view dll, uint16_t ordinal) noexcept;
    [[nodiscard]] static std::string NormalizeDLLName(
        std::string_view name) noexcept;
};

} // namespace Phantom
