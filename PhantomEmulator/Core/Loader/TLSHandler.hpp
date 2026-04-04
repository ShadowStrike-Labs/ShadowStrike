/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * TLSHandler.hpp — PE Thread Local Storage directory handler
 *
 * Parses the TLS directory, initializes per-thread TLS data regions, and
 * orchestrates execution of TLS callbacks through the CPU emulator. TLS
 * callbacks execute before the entry point and are a well-known malware
 * technique for anti-analysis, early payload decryption, and anti-debug.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "PEStructures.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Errors.hpp"
#include "../../Common/Config.hpp"
#include "../Memory/VirtualMemory.hpp"
#include "../CPU/CPU.hpp"

#include <cstdint>
#include <vector>

namespace Phantom {

// ============================================================================
// TLS Information Descriptor
// ============================================================================

struct TLSInfo {
    GuestAddress rawDataStart     = 0;   // VA of TLS template data start
    GuestAddress rawDataEnd       = 0;   // VA of TLS template data end
    GuestAddress indexAddress     = 0;   // VA of TLS index variable
    GuestAddress callbacksAddress = 0;   // VA of callback pointer array
    uint32_t     zeroFillSize     = 0;   // Bytes to zero after template data
    std::vector<GuestAddress> callbacks; // Resolved callback VAs
    bool         present          = false;
};

// ============================================================================
// TLSHandler — TLS directory parsing, data initialization, callback execution
// ============================================================================

class TLSHandler {
public:
    /// Parse the TLS directory from a loaded PE image in guest memory.
    /// @param imageBase  Guest address where the PE was loaded.
    /// @param tlsDirRVA  RVA of the TLS directory (from data directory[9]).
    /// @param tlsDirSize Size of the TLS directory entry.
    /// @param memory     Guest virtual memory containing the mapped image.
    /// @param is64Bit    true for PE64, false for PE32.
    /// @return TLSInfo with parsed data; check .present for validity.
    [[nodiscard]] static TLSInfo Parse(
        GuestAddress   imageBase,
        uint32_t       tlsDirRVA,
        uint32_t       tlsDirSize,
        VirtualMemory& memory,
        bool           is64Bit) noexcept;

    /// Initialize TLS data for a thread.
    /// Copies template data to the destination, zeros the fill area, writes
    /// the TLS index to the index variable.
    /// @param info         Parsed TLS information.
    /// @param memory       Guest virtual memory.
    /// @param tlsDataDest  Destination address for the TLS data copy.
    /// @param tlsIndex     TLS index value to write.
    [[nodiscard]] static ErrorCode InitializeTLSData(
        const TLSInfo& info,
        VirtualMemory& memory,
        GuestAddress   tlsDataDest,
        uint32_t       tlsIndex) noexcept;

    /// Execute TLS callbacks via CPU emulation.
    /// @param info       Parsed TLS information (must have callbacks).
    /// @param cpu        CPU emulator instance.
    /// @param memory     Guest virtual memory.
    /// @param imageBase  Guest address of the PE image.
    /// @param reason     DLL notification reason (1=PROCESS_ATTACH, etc.).
    /// @param config     Emulation configuration (instruction limits, etc.).
    [[nodiscard]] static ErrorCode ExecuteCallbacks(
        const TLSInfo&       info,
        CPU&                 cpu,
        VirtualMemory&       memory,
        GuestAddress         imageBase,
        uint32_t             reason,
        const EmulationConfig& config) noexcept;

private:
    [[nodiscard]] static TLSInfo Parse32(
        GuestAddress   imageBase,
        GuestAddress   tlsDirAddr,
        VirtualMemory& memory) noexcept;

    [[nodiscard]] static TLSInfo Parse64(
        GuestAddress   imageBase,
        GuestAddress   tlsDirAddr,
        VirtualMemory& memory) noexcept;

    [[nodiscard]] static ErrorCode ReadCallbackArray32(
        VirtualMemory&             memory,
        GuestAddress               callbacksVA,
        std::vector<GuestAddress>& out) noexcept;

    [[nodiscard]] static ErrorCode ReadCallbackArray64(
        VirtualMemory&             memory,
        GuestAddress               callbacksVA,
        std::vector<GuestAddress>& out) noexcept;
};

} // namespace Phantom
