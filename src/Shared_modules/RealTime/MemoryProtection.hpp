/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#pragma once

#include <vector>
#include <string>
#include <memory>
#include <optional>
#include <cstdint>
#include <chrono>
#include <atomic>
#include <functional>

#include "../Utils/ProcessUtils.hpp"

namespace ShadowStrike {
namespace RealTime {

    // =========================================================================
    // Enumerations
    // =========================================================================

    /**
     * @brief Type of memory violation detected.
     * Extended for nation-state APT detection including kernel-reported events.
     */
    enum class MemoryViolationType : uint16_t {
        None                    = 0,

        // Core detections
        RWX_Page                = 1,    ///< Read-Write-Execute page
        Shellcode_Pattern       = 2,    ///< Shellcode pattern (NOP sled, encoder, PIC)
        Module_Stomping         = 3,    ///< Module .text section mismatch vs disk
        ROP_Gadget              = 4,    ///< ROP chain / gadget sequence on stack
        Heap_Spray              = 5,    ///< Heap spray pattern
        Thread_Injection        = 6,    ///< Thread start address in non-module memory

        // Advanced APT detections
        W_to_X_Transition       = 10,   ///< Write -> Execute protection change (W^X violation)
        Unbacked_Executable     = 11,   ///< Private executable memory with no file backing
        API_Hash_Resolution     = 12,   ///< API hashing loop (ror13, crc32, djb2)
        Syscall_Stub            = 13,   ///< Direct syscall / Hell's Gate / Halo's Gate
        CFG_Bypass              = 14,   ///< Control Flow Guard bypass
        Stack_Pivot             = 15,   ///< RSP outside thread stack limits
        Process_Hollowing       = 16,   ///< Hollowed process image
        Reflective_DLL          = 17,   ///< Reflective DLL loading
        Early_Bird_APC          = 18,   ///< Early bird APC injection
        Phantom_DLL             = 19,   ///< Memory-only DLL (no file backing)
        AtomBombing             = 20,   ///< AtomBombing injection
        Process_Doppelganging   = 21,   ///< NTFS transacted section injection
        Trampolining            = 22,   ///< Function hook / trampoline
        Entropy_Anomaly         = 23,   ///< High entropy in executable region
        IAT_Tampering           = 24,   ///< Import Address Table modification
        Callback_Overwrite      = 25,   ///< System callback pointer overwrite

        // Kernel-sourced detections (from PhantomSensor driver)
        Kernel_Shellcode        = 100,  ///< Driver-detected shellcode
        Kernel_Injection        = 101,  ///< Driver-detected injection technique
        Kernel_Hollowing        = 102,  ///< Driver-detected process hollowing
        Kernel_MemoryProtect    = 103,  ///< Driver-detected suspicious VirtualProtect
        Kernel_CrossProcess     = 104,  ///< Driver-detected cross-process memory access
        Kernel_SuspiciousAlloc  = 105   ///< Driver-detected suspicious VirtualAlloc
    };

    /**
     * @brief Scan intensity mode.
     */
    enum class ScanMode : uint8_t {
        Fast        = 0,    ///< Permissions + headers only (~1ms)
        Deep        = 1,    ///< Full pattern scan + module comparison (~50ms)
        Heuristic   = 2,    ///< Behavioral + stack analysis (~100ms)
        Targeted    = 3,    ///< Single region deep scan
        APT_Hunt    = 4     ///< Full nation-state APT sweep (~500ms)
    };

    /**
     * @brief Threat severity aligned with AlertSystem severity levels.
     */
    enum class MemoryThreatSeverity : uint8_t {
        None        = 0,
        Low         = 1,    ///< Informational / possible benign
        Medium      = 2,    ///< Suspicious, investigation required
        High        = 3,    ///< Likely malicious
        Critical    = 4,    ///< Active exploitation
        Emergency   = 5     ///< Zero-day / nation-state pattern
    };

    /**
     * @brief MITRE ATT&CK technique mapping for forensic correlation.
     */
    enum class MitreTechnique : uint16_t {
        None        = 0,
        T1055_001   = 1,    ///< Process Injection: DLL Injection
        T1055_002   = 2,    ///< Process Injection: PE Injection
        T1055_003   = 3,    ///< Process Injection: Thread Execution Hijacking
        T1055_004   = 4,    ///< Process Injection: APC Injection
        T1055_005   = 5,    ///< Process Injection: Thread Local Storage
        T1055_009   = 6,    ///< Process Injection: Proc Memory
        T1055_012   = 8,    ///< Process Injection: Process Hollowing
        T1055_013   = 9,    ///< Process Injection: Process Doppelganging
        T1620       = 12,   ///< Reflective Code Loading
        T1574       = 13,   ///< Hijack Execution Flow
        T1106       = 14,   ///< Native API (direct syscalls)
        T1027       = 15    ///< Obfuscated Files or Information
    };

    // =========================================================================
    // Data Structures
    // =========================================================================

    /**
     * @brief Full details of a detected memory violation.
     */
    struct MemoryViolation {
        MemoryViolationType type            = MemoryViolationType::None;
        uint64_t            address         = 0;
        size_t              size            = 0;
        std::vector<uint8_t> dump;                  ///< First bytes of violation region
        float               confidence      = 0.0f; ///< 0.0 - 1.0
        std::string         details;

        // APT-grade enrichment
        MemoryThreatSeverity severity       = MemoryThreatSeverity::None;
        MitreTechnique       mitreTechnique = MitreTechnique::None;
        uint32_t            targetPid       = 0;    ///< Target process (cross-process ops)
        uint32_t            sourcePid       = 0;    ///< Source/actor process
        uint64_t            threadId        = 0;    ///< Associated thread
        double              entropy         = 0.0;  ///< Shannon entropy of region
        bool                fromKernel      = false; ///< Kernel-driver sourced detection
        std::chrono::system_clock::time_point detectedAt;

        [[nodiscard]] std::string ToJson() const;
    };

    /**
     * @brief Aggregated result of a memory scan operation.
     */
    struct MemoryScanResult {
        Utils::ProcessUtils::ProcessId pid  = 0;
        bool                compromised     = false;
        size_t              pagesScanned    = 0;
        std::vector<MemoryViolation> violations;
        std::chrono::microseconds scanDuration{ 0 };
        MemoryThreatSeverity highestSeverity = MemoryThreatSeverity::None;
        float               overallThreatScore = 0.0f; ///< 0.0 - 100.0

        [[nodiscard]] std::string ToJson() const;
    };

    /**
     * @brief Runtime configuration for the memory protection engine.
     */
    struct MemoryProtectionConfig {
        bool enableKernelIntegration    = true;
        bool enableContinuousMonitoring = true;
        bool enableAPTHunting           = true;
        bool enableAlertSystem          = true;
        bool enableTelemetry            = true;
        bool enableBehaviorFeedback     = true;
        bool scanOnProcessCreate        = true;

        ScanMode processCreateScanMode  = ScanMode::Fast;
        float    alertThreshold         = 0.6f;    ///< Min confidence to alert
        float    blockThreshold         = 0.85f;   ///< Min confidence to block
        uint32_t maxRegionsPerScan      = 50000;
        std::chrono::milliseconds scanTimeout{ 30000 };
        double   highEntropyThreshold   = 7.2;
    };

    /// Callback for external consumers of memory threat events.
    using MemoryThreatCallback = std::function<void(const MemoryViolation&, uint32_t /*pid*/)>;

    // =========================================================================
    // Exploit Protection Flags (for EnableExploitProtection)
    // =========================================================================

    /// Apply Data Execution Prevention to the target process.
    constexpr uint32_t EXPLOIT_PROTECT_DEP            = 0x00000001;
    /// Force bottom-up ASLR randomization on all mappings.
    constexpr uint32_t EXPLOIT_PROTECT_ASLR_FORCE     = 0x00000002;
    /// Enable Control Flow Guard enforcement.
    constexpr uint32_t EXPLOIT_PROTECT_CFG             = 0x00000004;
    /// Terminate process on heap corruption detection.
    constexpr uint32_t EXPLOIT_PROTECT_HEAP_TERMINATE  = 0x00000008;
    /// Enable Structured Exception Handler Overwrite Protection.
    constexpr uint32_t EXPLOIT_PROTECT_SEHOP           = 0x00000010;
    /// Block dynamic code generation (unsigned code execution).
    constexpr uint32_t EXPLOIT_PROTECT_NO_DYNAMIC_CODE = 0x00000020;
    /// Enforce strict handle checks (raise on bad handle access).
    constexpr uint32_t EXPLOIT_PROTECT_STRICT_HANDLES  = 0x00000040;
    /// Apply all available mitigations (use with caution on 3rd-party processes).
    constexpr uint32_t EXPLOIT_PROTECT_ALL             = 0x0000007F;
    /// Enhanced monitoring only — no active mitigation applied.
    constexpr uint32_t EXPLOIT_PROTECT_MONITOR_ONLY    = 0x00001000;

    // =========================================================================
    // Memory Protection Engine
    // =========================================================================

    /**
     * @brief Enterprise memory threat detection engine.
     *
     * Detects memory-resident threats including nation-state APT techniques:
     *  - Shellcode injection (NOP sled, API hashing, direct syscall, encoders)
     *  - Process hollowing / module stomping / doppelganging
     *  - ROP chains and stack pivots
     *  - Reflective DLL loading
     *  - Thread injection and APC abuse
     *  - W^X policy violation monitoring
     *
     * Integrates with:
     *  - PhantomSensor kernel driver (real-time memory events via IPC)
     *  - AlertSystem (severity-based alerting)
     *  - TelemetryCollector (anonymous event telemetry)
     *  - BehaviorAnalyzer (behavioral scoring feed)
     *  - ProcessCreationMonitor (auto-scan on process creation)
     */
    class MemoryProtection final {
    public:
        [[nodiscard]] static MemoryProtection& Instance() noexcept;

        MemoryProtection(const MemoryProtection&) = delete;
        MemoryProtection& operator=(const MemoryProtection&) = delete;
        MemoryProtection(MemoryProtection&&) = delete;
        MemoryProtection& operator=(MemoryProtection&&) = delete;

        // ----- Lifecycle -----
        void Start();
        void Stop();
        [[nodiscard]] bool IsRunning() const noexcept;

        // ----- Configuration -----
        void Configure(const MemoryProtectionConfig& config);
        [[nodiscard]] MemoryProtectionConfig GetConfig() const;

        // ----- Core Scanning -----
        [[nodiscard]] MemoryScanResult ScanProcess(
            Utils::ProcessUtils::ProcessId pid,
            ScanMode mode = ScanMode::Fast);

        [[nodiscard]] MemoryScanResult ScanRegion(
            Utils::ProcessUtils::ProcessId pid,
            uint64_t address, size_t size);

        // ----- Process Monitoring -----
        [[nodiscard]] bool MonitorProcess(Utils::ProcessUtils::ProcessId pid);
        [[nodiscard]] bool UnmonitorProcess(Utils::ProcessUtils::ProcessId pid);
        [[nodiscard]] bool IsProcessCompromised(Utils::ProcessUtils::ProcessId pid);

        // ----- APT Hunting -----
        [[nodiscard]] MemoryScanResult HuntAPT(Utils::ProcessUtils::ProcessId pid);
        [[nodiscard]] std::vector<MemoryScanResult> HuntAllProcesses();

        // ----- Kernel Event Ingestion (IPC dispatcher) -----
        void ProcessKernelMemoryAlert(
            uint32_t messageType,
            const void* payload,
            size_t payloadSize);

        // ----- Consumer Callbacks -----
        [[nodiscard]] uint64_t RegisterThreatCallback(MemoryThreatCallback callback);
        bool UnregisterThreatCallback(uint64_t callbackId);

        // ----- Exploit Protection -----
        [[nodiscard]] bool EnableExploitProtection(
            Utils::ProcessUtils::ProcessId pid,
            uint32_t flags);

        // ----- Diagnostics -----
        [[nodiscard]] bool SelfTest();
        [[nodiscard]] std::string GetStatistics() const;

    private:
        MemoryProtection();
        ~MemoryProtection();

        class MemoryProtectionImpl;
        std::unique_ptr<MemoryProtectionImpl> m_impl;
    };

} // namespace RealTime
} // namespace ShadowStrike
