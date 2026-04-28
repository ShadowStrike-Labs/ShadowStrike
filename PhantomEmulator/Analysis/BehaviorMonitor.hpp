/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * BehaviorMonitor.hpp — Central behavioral analysis engine
 *
 * Sits between the API dispatcher and threat scorer, implementing 50+
 * behavioral detection rules as state machines with time-windowed tracking,
 * cross-thread correlation, and real-time alert generation.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../Common/Types.hpp"
#include "../Common/Config.hpp"
#include "../WinAPI/APITypes.hpp"
#include "../Core/Memory/MemoryTracker.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <memory>

namespace Phantom {

// ============================================================================
// Behavioral Alert Severity
// ============================================================================

enum class AlertSeverity : uint8_t {
    Info     = 0,
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4,
};

// ============================================================================
// Behavioral Alert Categories (MITRE ATT&CK aligned)
// ============================================================================

enum class BehaviorCategory : uint8_t {
    ProcessInjection     = 0,   // T1055 — Code injection into remote process
    ProcessHollowing     = 1,   // T1055.012 — Create suspended, unmap, remap, resume
    DLLInjection         = 2,   // T1055.001 — LoadLibrary-based or manual map
    ReflectiveDLLLoad    = 3,   // T1620.001 — In-memory DLL without LoadLibrary
    ShellcodeExecution   = 4,   // W-X transitions, decoded shellcode
    Persistence          = 5,   // T1547/T1053 — Registry Run, schtasks, services
    PrivilegeEscalation  = 6,   // T1134 — Token manipulation, impersonation
    CredentialAccess     = 7,   // T1003 — LSASS/SAM access
    DefenseEvasion       = 8,   // T1562/T1497 — Anti-debug, anti-VM, timestomping
    LateralMovement      = 9,   // T1021 — WMI, PsExec, remote services
    DataExfiltration     = 10,  // T1041 — Large outbound data, DNS tunneling
    Ransomware           = 11,  // T1486 — File enum + crypto + rename/delete
    Downloader           = 12,  // T1105 — Download + execute pattern
    Keylogger            = 13,  // T1056.001 — Keyboard hooks
    ScreenCapture        = 14,  // T1113 — Screen capture via GDI
    Discovery            = 15,  // T1057/T1082 — System/process/network enumeration
    CommandAndControl    = 16,  // T1071 — Beaconing, C2 protocols
    Execution            = 17,  // T1059 — Process/script execution
    FileManipulation     = 18,  // T1490 — Shadow copy delete, MBR access
    AntiForensics        = 19,  // T1070 — Log deletion, timestamp modification
};

// ============================================================================
// Behavioral Alert
// ============================================================================

struct BehaviorAlert {
    BehaviorCategory             category = BehaviorCategory::Discovery;
    AlertSeverity                severity = AlertSeverity::Info;
    float                        confidence = 0.0f;     // 0.0-1.0
    std::string                  description;
    std::string                  mitreId;               // e.g., "T1055.001"
    std::vector<uint32_t>        evidenceCallIndices;   // Indices into API call log
    uint64_t                     instructionCount = 0;  // When detected
    uint16_t                     threadId = 0;
};

// Callback for real-time alert notification during emulation
using BehaviorAlertCallback = std::function<void(const BehaviorAlert&)>;

// ============================================================================
// BehaviorMonitor — Central behavioral analysis hub
// ============================================================================
//
// Implements:
//   - 50+ behavioral detection rules (real state machines)
//   - Time-windowed behavior tracking (instruction count windows)
//   - Cross-thread correlation (thread A allocates, thread B executes)
//   - Real-time callback for immediate threat response
//
// Thread safety: NOT thread-safe. Single-threaded emulation loop feeds events.
// Multi-threading is serialized at the EmulatedThread scheduler level.
//
// Lifetime: Owned by the emulation session. Fed events by the dispatcher,
//           memory tracker, and CPU execution loop.

class BehaviorMonitor {
public:
    explicit BehaviorMonitor(const EmulationConfig& config) noexcept;
    ~BehaviorMonitor() noexcept;

    BehaviorMonitor(const BehaviorMonitor&) = delete;
    BehaviorMonitor& operator=(const BehaviorMonitor&) = delete;
    BehaviorMonitor(BehaviorMonitor&&) noexcept;
    BehaviorMonitor& operator=(BehaviorMonitor&&) noexcept;

    // === Feed Events (called by dispatcher / memory tracker / CPU) ===

    void OnAPICall(const APICallDetail& call, uint32_t callIndex) noexcept;
    void OnMemoryEvent(const MemoryAccessRecord& record) noexcept;
    void OnWXTransition(GuestAddress page, uint64_t instrCount) noexcept;
    void OnProtectionChange(GuestAddress base, GuestSize size,
                            MemProt oldProt, MemProt newProt) noexcept;

    // === Alert Management ===

    void SetAlertCallback(BehaviorAlertCallback cb) noexcept;

    [[nodiscard]] const std::vector<BehaviorAlert>& GetAlerts() const noexcept;
    [[nodiscard]] uint32_t GetAlertCount() const noexcept;
    [[nodiscard]] AlertSeverity GetMaxSeverity() const noexcept;
    [[nodiscard]] std::vector<const BehaviorAlert*>
        GetAlertsByCategory(BehaviorCategory cat) const noexcept;

    // === Behavior Flags (fast bitfield for hot-path checks) ===

    [[nodiscard]] BehaviorFlag GetAccumulatedFlags() const noexcept;

    // === State Machine Status ===

    [[nodiscard]] uint32_t GetActiveStateMachineCount() const noexcept;

    // === Reset (for new emulation session) ===

    void Reset() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
