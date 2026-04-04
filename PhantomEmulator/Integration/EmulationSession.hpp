/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * EmulationSession.hpp — Master orchestrator for a single emulation session
 *
 * Wires together CPU, Memory, MemoryTracker, APIDispatcher, EnvironmentBuilder,
 * PELoader, ShellcodeLoader, and all 11 analysis modules into a cohesive pipeline:
 *   1. Setup: allocate memory, build virtual Windows environment, load payload
 *   2. Execute: run the CPU with live analysis callbacks on every API call
 *   3. Post-analysis: memory forensics, string/crypto scanning, threat scoring
 *   4. Collect results into PhantomEmulationResult
 *
 * Thread safety: a single EmulationSession is NOT internally thread-safe.
 * One thread owns and drives the session. The only thread-safe operation is
 * RequestAbort(), which can be called from any thread to stop a running session.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "EmulationResult.hpp"
#include "../Common/Types.hpp"
#include "../Common/Config.hpp"

#include <cstdint>
#include <memory>
#include <span>

namespace Phantom {

// ============================================================================
// EmulationSession — orchestrates a complete emulation run
// ============================================================================
//
// Usage:
//   EmulationConfig config;                   // configure limits, features, etc.
//   EmulationSession session(config);
//   auto result = session.EmulatePE(peBytes); // or EmulateShellcode / EmulateBuffer
//   if (result.IsMalicious()) { /* quarantine */ }
//
// Lifecycle:
//   - Construct once per sample.
//   - Call exactly ONE of the Emulate* methods.
//   - The session is consumed after the call — do not reuse.
//
// The session owns all subsystem instances via PIMPL. Destruction is
// automatic (RAII); no manual cleanup is needed.

class EmulationSession {
public:
    explicit EmulationSession(const EmulationConfig& config) noexcept;
    ~EmulationSession() noexcept;

    EmulationSession(const EmulationSession&) = delete;
    EmulationSession& operator=(const EmulationSession&) = delete;
    EmulationSession(EmulationSession&&) noexcept;
    EmulationSession& operator=(EmulationSession&&) noexcept;

    // === Main Entry Points ===================================================
    //
    // Each method performs the full pipeline: setup → execute → analyse → collect.
    // Returns a complete PhantomEmulationResult.

    /// Emulate a PE executable (32-bit or 64-bit, auto-detected from headers).
    [[nodiscard]] PhantomEmulationResult EmulatePE(std::span<const uint8_t> peData) noexcept;

    /// Emulate raw shellcode.
    [[nodiscard]] PhantomEmulationResult EmulateShellcode(
        std::span<const uint8_t> code, bool is64Bit) noexcept;

    /// Emulate an arbitrary buffer already loaded at a known base/entry point.
    [[nodiscard]] PhantomEmulationResult EmulateBuffer(
        std::span<const uint8_t> buffer,
        GuestAddress base,
        GuestAddress entry,
        bool is64Bit) noexcept;

    // === Abort (thread-safe) =================================================

    /// Request early termination from any thread. The CPU loop will stop at
    /// the next instruction boundary and the result will have
    /// stopReason == UserAborted.
    void RequestAbort() noexcept;

    // === Configuration =======================================================

    [[nodiscard]] const EmulationConfig& GetConfig() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
