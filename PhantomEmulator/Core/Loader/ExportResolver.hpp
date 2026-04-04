/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ExportResolver.hpp — PE export directory parser and multi-module export database
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "PEStructures.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Errors.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <unordered_map>

namespace Phantom {

// ============================================================================
// ExportResolver — Multi-module PE export database with forwarder resolution
// ============================================================================
//
// Maintains a lookup database of all exports from loaded PE modules
// (ntdll.dll, kernel32.dll, etc.) within the guest address space.
// Supports name-based and ordinal-based resolution, including
// chained forwarded exports (e.g., kernel32!HeapAlloc → NTDLL.RtlAllocateHeap).
//
// Not thread-safe: expected to be fully populated before concurrent resolution
// queries begin. Callers must synchronize externally if interleaving registration
// and resolution across threads.

class ExportResolver {
public:
    ExportResolver() noexcept = default;

    // Register exports from a loaded module. Called once per DLL loaded into guest memory.
    // imageBase: guest address where module was loaded
    // moduleName: canonical name (e.g., "ntdll.dll")
    // data: raw PE file bytes (for parsing export table)
    [[nodiscard]] ErrorCode RegisterModule(
        GuestAddress imageBase,
        std::string_view moduleName,
        ByteSpan data) noexcept;

    // Resolve an import by DLL name + function name.
    // Returns the guest address of the export, or nullopt.
    [[nodiscard]] std::optional<GuestAddress> ResolveByName(
        std::string_view dllName,
        std::string_view funcName) const noexcept;

    // Resolve an import by DLL name + ordinal.
    [[nodiscard]] std::optional<GuestAddress> ResolveByOrdinal(
        std::string_view dllName,
        uint16_t ordinal) const noexcept;

    // Resolve a forwarded export (e.g., "NTDLL.RtlAllocateHeap")
    [[nodiscard]] std::optional<GuestAddress> ResolveForwarder(
        std::string_view forwarderString) const noexcept;

    // Get the module's image base by name
    [[nodiscard]] std::optional<GuestAddress> GetModuleBase(
        std::string_view dllName) const noexcept;

    // Check if a module is registered
    [[nodiscard]] bool HasModule(std::string_view dllName) const noexcept;

    // Get all registered module names
    [[nodiscard]] std::vector<std::string> GetModuleNames() const;

private:
    struct ExportEntry {
        GuestAddress address = 0;  // Guest address (imageBase + RVA)
        std::string forwarder;     // Non-empty if forwarded
    };

    struct ModuleExports {
        GuestAddress imageBase = 0;
        std::string canonicalName;
        std::unordered_map<std::string, ExportEntry> byName;
        std::unordered_map<uint16_t, ExportEntry> byOrdinal;
        uint32_t ordinalBase = 0;
    };

    // Key: lowercase DLL name (normalized)
    std::unordered_map<std::string, ModuleExports> m_modules;

    [[nodiscard]] static std::string NormalizeDLLName(std::string_view name) noexcept;

    // Recursive forwarder resolution with depth cap to prevent infinite chains
    [[nodiscard]] std::optional<GuestAddress> ResolveForwarderInternal(
        std::string_view forwarderString,
        uint32_t depth) const noexcept;
};

} // namespace Phantom
