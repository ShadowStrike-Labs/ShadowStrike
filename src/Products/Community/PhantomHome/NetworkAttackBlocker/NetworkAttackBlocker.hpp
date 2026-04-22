/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file NetworkAttackBlocker.hpp
 * @brief PhantomHome Network Attack Blocker — aggregates sub-detectors from
 *        NetworkMonitor into a single UI-facing protection card.
 *
 * Threat kinds aggregated:
 *   PortScan          – port reconnaissance (NetworkMonitor::PORT_SCANNING)
 *   BruteForce        – sustained auth failures (LATERAL_MOVEMENT)
 *   Flood             – DDoS / traffic storm (DATA_EXFILTRATION rate spike)
 *   ArpSpoof          – ARP cache poisoning  (future: ARP sensor callback)
 *   DnsSpoof          – DNS response forgery  (DNS_TUNNELING indicator)
 *   ExploitBeacon     – known exploit traffic  (EXPLOIT_TRAFFIC)
 *   C2Beacon          – periodic C2 beaconing  (BEACONING)
 *   SuspiciousOutbound– high-volume outbound    (DATA_EXFILTRATION)
 *
 * Blocking action delegates to NetworkMonitor::BlockIP() which uses the
 * existing WFP filter chain — no WFP code lives here.
 *
 * Mode semantics:
 *   Off        – unsubscribe; drop all events.
 *   Passive    – log + counter only; never call BlockIP.
 *   Balanced   – block if severity >= 0.75 OR kind ∈ {ArpSpoof, DnsSpoof, C2Beacon}.
 *   Aggressive – block if severity >= 0.50.
 *
 * Ring buffer of last 64 events is kept for UI queries.
 */

#pragma once

// ── Standard library ──────────────────────────────────────────────────────────
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

// ── PhantomHome infrastructure ────────────────────────────────────────────────
#include "Products/Community/PhantomHome/HomeProductOrchestrator.hpp"

namespace ShadowStrike {
namespace Products {
namespace Home {

// ─────────────────────────────────────────────────────────────────────────────
// NabThreatKind
// ─────────────────────────────────────────────────────────────────────────────

enum class NabThreatKind : std::uint32_t {
    PortScan          = 0,
    BruteForce        = 1,
    Flood             = 2,
    ArpSpoof          = 3,
    DnsSpoof          = 4,
    ExploitBeacon     = 5,
    C2Beacon          = 6,
    SuspiciousOutbound= 7,
    Count             = 8,
};

// ─────────────────────────────────────────────────────────────────────────────
// NabEvent — a single network-attack event
// ─────────────────────────────────────────────────────────────────────────────

struct NabEvent {
    NabThreatKind                           kind;
    std::wstring                            remoteAddr;
    std::uint16_t                           remotePort;
    std::wstring                            localProcess;
    double                                  severity;     ///< 0.0 – 1.0
    std::chrono::system_clock::time_point   at;
};

// ─────────────────────────────────────────────────────────────────────────────
// NetworkAttackBlocker — Meyers' singleton
// ─────────────────────────────────────────────────────────────────────────────

class NetworkAttackBlocker final {
public:
    [[nodiscard]] static NetworkAttackBlocker& Instance() noexcept;

    NetworkAttackBlocker(const NetworkAttackBlocker&)            = delete;
    NetworkAttackBlocker& operator=(const NetworkAttackBlocker&) = delete;

    // ── Module lifecycle ─────────────────────────────────────────────────────

    [[nodiscard]] bool Initialize() noexcept;

    /// Subscribe to NetworkMonitor callbacks.
    [[nodiscard]] bool Start() noexcept;

    /// Unsubscribe from NetworkMonitor; clear ring buffer.
    void Stop() noexcept;

    void Shutdown() noexcept;

    // ── Mode ─────────────────────────────────────────────────────────────────

    void                 SetMode(ProtectionMode m) noexcept;
    [[nodiscard]] ProtectionMode Mode() const noexcept;

    // ── Per-detector overlay ─────────────────────────────────────────────────

    void SetDetectorEnabled(NabThreatKind kind, bool enabled) noexcept;
    [[nodiscard]] bool IsDetectorEnabled(NabThreatKind kind) const noexcept;

    // ── Status snapshot for UI / IPC ─────────────────────────────────────────

    struct AggregateStatus {
        bool                    healthy;
        std::uint64_t           eventsTotal;
        std::uint64_t           eventsBlocked24h;
        std::uint64_t           eventsLogged24h;
        std::vector<NabEvent>   recent;   ///< ring-buffered last 64
    };
    [[nodiscard]] AggregateStatus GetStatus() const;

private:
    NetworkAttackBlocker();
    ~NetworkAttackBlocker();

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

}  // namespace Home
}  // namespace Products
}  // namespace ShadowStrike
