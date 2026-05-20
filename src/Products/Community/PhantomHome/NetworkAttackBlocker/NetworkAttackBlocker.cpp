/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

// ── Windows prerequisites (no PCH) ───────────────────────────────────────────
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

// ── Standard library before Logger.hpp (which uses std::format) ───────────────
#include <array>
#include <atomic>
#include <chrono>
#include <deque>
#include <cstdint>
#include <format>
#include <memory>
#include <shared_mutex>
#include <string>
#include <variant>
#include <vector>

// ── Own header ────────────────────────────────────────────────────────────────
#include "NetworkAttackBlocker.hpp"

// ── PhantomCore infrastructure ────────────────────────────────────────────────
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Core/Network/NetworkMonitor.hpp"

namespace ShadowStrike {
namespace Products {
namespace Home {

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

namespace {

constexpr const wchar_t*  kLogCategory  = L"NetworkAttackBlocker";
constexpr std::size_t     kRingCapacity = 64;

constexpr double kBalancedThreshold   = 0.75;
constexpr double kAggressiveThreshold = 0.50;

}  // namespace

// ─────────────────────────────────────────────────────────────────────────────
// Import NetworkMonitor types
// ─────────────────────────────────────────────────────────────────────────────

using Core::Network::BeaconingAnalysis;
using Core::Network::DataExfiltrationAnalysis;
using Core::Network::IPAddress;
using Core::Network::NetworkMonitor;
using Core::Network::PortScanAnalysis;
using Core::Network::ThreatIndicator;
using Core::Network::BlockReason;

// ─────────────────────────────────────────────────────────────────────────────
// PIMPL
// ─────────────────────────────────────────────────────────────────────────────

struct NetworkAttackBlocker::Impl {
    std::atomic<ProtectionMode> mode{ProtectionMode::Balanced};

    // Per-detector enable bitmask (bit i = NabThreatKind(i) enabled)
    std::atomic<std::uint32_t>  detectorMask{0xFFFFFFFFu};

    std::atomic<std::uint64_t>  eventsTotal{0};
    std::atomic<std::uint64_t>  eventsBlocked24h{0};
    std::atomic<std::uint64_t>  eventsLogged24h{0};

    mutable std::shared_mutex   ringMutex;
    std::deque<NabEvent>        ring;

    std::atomic<std::uint64_t>  threatCallbackId{0};
    std::atomic<bool>           running{false};

    // ─────────────────────────────────────────────────────────────────────────
    // Safe bit-position for a NabThreatKind enumerator (clamps to Count-1 to
    // guarantee the shift in `1u << pos` is well-defined regardless of the
    // caller-supplied enum value).
    // ─────────────────────────────────────────────────────────────────────────
    [[nodiscard]] static constexpr std::uint32_t SafeBitIndex(NabThreatKind k) noexcept {
        const auto v = static_cast<std::uint32_t>(k);
        constexpr std::uint32_t maxIdx =
            static_cast<std::uint32_t>(NabThreatKind::Count) - 1u;
        return (v <= maxIdx) ? v : maxIdx;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Map ThreatIndicator → NabThreatKind
    // ─────────────────────────────────────────────────────────────────────────
    static NabThreatKind MapIndicator(ThreatIndicator ind) noexcept {
        switch (ind) {
        case ThreatIndicator::BEACONING:         return NabThreatKind::C2Beacon;
        case ThreatIndicator::PORT_SCANNING:     return NabThreatKind::PortScan;
        case ThreatIndicator::DATA_EXFILTRATION: return NabThreatKind::SuspiciousOutbound;
        case ThreatIndicator::LATERAL_MOVEMENT:  return NabThreatKind::BruteForce;
        case ThreatIndicator::DNS_TUNNELING:     return NabThreatKind::DnsSpoof;
        case ThreatIndicator::ICMP_TUNNELING:    return NabThreatKind::Flood;
        case ThreatIndicator::DOMAIN_GENERATION: return NabThreatKind::DnsSpoof;
        case ThreatIndicator::TOR_USAGE:         return NabThreatKind::SuspiciousOutbound;
        case ThreatIndicator::CRYPTO_MINING:     return NabThreatKind::SuspiciousOutbound;
        case ThreatIndicator::BOTNET_ACTIVITY:   return NabThreatKind::C2Beacon;
        case ThreatIndicator::EXPLOIT_TRAFFIC:   return NabThreatKind::ExploitBeacon;
        case ThreatIndicator::NONE:              return NabThreatKind::SuspiciousOutbound;
        }
        return NabThreatKind::SuspiciousOutbound;
    }

    static double ExtractSeverity(
        const std::variant<BeaconingAnalysis,
                           DataExfiltrationAnalysis,
                           PortScanAnalysis>& analysis) noexcept {
        if (const auto* b = std::get_if<BeaconingAnalysis>(&analysis))
            return b->beaconingScore;
        if (const auto* d = std::get_if<DataExfiltrationAnalysis>(&analysis))
            return d->exfiltrationScore;
        if (const auto* p = std::get_if<PortScanAnalysis>(&analysis))
            return p->scanScore;
        return 0.5;
    }

    static std::wstring ExtractRemoteAddr(
        const std::variant<BeaconingAnalysis,
                           DataExfiltrationAnalysis,
                           PortScanAnalysis>& analysis) {
        if (const auto* b = std::get_if<BeaconingAnalysis>(&analysis))
            return b->destination.ip.ToWString();
        if (const auto* d = std::get_if<DataExfiltrationAnalysis>(&analysis))
            return d->destination.ip.ToWString();
        if (const auto* p = std::get_if<PortScanAnalysis>(&analysis))
            return p->sourceIp.ToWString();
        return {};
    }

    static std::uint16_t ExtractRemotePort(
        const std::variant<BeaconingAnalysis,
                           DataExfiltrationAnalysis,
                           PortScanAnalysis>& analysis) noexcept {
        if (const auto* b = std::get_if<BeaconingAnalysis>(&analysis))
            return b->destination.port;
        if (const auto* d = std::get_if<DataExfiltrationAnalysis>(&analysis))
            return d->destination.port;
        return 0;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Core event handler — called from NetworkMonitor's thread pool
    // ─────────────────────────────────────────────────────────────────────────
    void OnThreatDetected(
        uint64_t        connId,
        ThreatIndicator ind,
        const std::variant<BeaconingAnalysis,
                           DataExfiltrationAnalysis,
                           PortScanAnalysis>& analysis) {

        const ProtectionMode curMode =
            mode.load(std::memory_order_acquire);
        if (curMode == ProtectionMode::Off) return;

        const NabThreatKind kind     = MapIndicator(ind);
        const double        severity = ExtractSeverity(analysis);

        // Per-detector overlay check
        {
            const std::uint32_t bit = 1u << SafeBitIndex(kind);
            if (!(detectorMask.load(std::memory_order_relaxed) & bit)) return;
        }

        std::wstring   remoteAddr = ExtractRemoteAddr(analysis);
        const uint16_t remotePort = ExtractRemotePort(analysis);

        eventsTotal.fetch_add(1u, std::memory_order_relaxed);

        NabEvent ev;
        ev.kind       = kind;
        ev.remoteAddr = remoteAddr;
        ev.remotePort = remotePort;
        ev.severity   = severity;
        ev.at         = std::chrono::system_clock::now();

        bool shouldBlock = false;

        switch (curMode) {
        case ProtectionMode::Passive:
            SS_LOG_INFO(kLogCategory,
                L"[Passive] threat kind=%u severity=%.2f remote=%ls connId=%llu",
                static_cast<unsigned>(kind), severity,
                remoteAddr.c_str(),
                static_cast<unsigned long long>(connId));
            eventsLogged24h.fetch_add(1u, std::memory_order_relaxed);
            break;

        case ProtectionMode::Balanced:
            if (severity >= kBalancedThreshold      ||
                kind == NabThreatKind::ArpSpoof     ||
                kind == NabThreatKind::DnsSpoof     ||
                kind == NabThreatKind::C2Beacon) {
                shouldBlock = true;
            } else {
                SS_LOG_INFO(kLogCategory,
                    L"[Balanced] logged threat kind=%u severity=%.2f remote=%ls",
                    static_cast<unsigned>(kind), severity, remoteAddr.c_str());
                eventsLogged24h.fetch_add(1u, std::memory_order_relaxed);
            }
            break;

        case ProtectionMode::Aggressive:
            if (severity >= kAggressiveThreshold) {
                shouldBlock = true;
            } else {
                SS_LOG_INFO(kLogCategory,
                    L"[Aggressive] logged threat kind=%u severity=%.2f remote=%ls",
                    static_cast<unsigned>(kind), severity, remoteAddr.c_str());
                eventsLogged24h.fetch_add(1u, std::memory_order_relaxed);
            }
            break;

        default:
            break;
        }

        if (shouldBlock && !remoteAddr.empty()) {
            // Delegate to NetworkMonitor's WFP chain; no WFP code lives here.
            // Use brace-init to avoid the most-vexing-parse with explicit ctor.
            const IPAddress ip{std::wstring_view{remoteAddr}};
            if (ip.IsValid()) {
                if (NetworkMonitor::Instance().BlockIP(
                        ip, BlockReason::MALICIOUS_IP, 0u)) {
                    SS_LOG_WARN(kLogCategory,
                        L"Blocked remote=%ls kind=%u severity=%.2f connId=%llu",
                        remoteAddr.c_str(),
                        static_cast<unsigned>(kind),
                        severity,
                        static_cast<unsigned long long>(connId));
                    eventsBlocked24h.fetch_add(1u, std::memory_order_relaxed);
                } else {
                    SS_LOG_ERROR(kLogCategory,
                        L"BlockIP failed for %ls (kind=%u severity=%.2f); "
                        L"WFP filter may require elevation",
                        remoteAddr.c_str(),
                        static_cast<unsigned>(kind),
                        severity);
                    eventsLogged24h.fetch_add(1u, std::memory_order_relaxed);
                }
            } else {
                SS_LOG_WARN(kLogCategory,
                    L"OnThreatDetected: invalid IP address '%ls'; skip block",
                    remoteAddr.c_str());
                eventsLogged24h.fetch_add(1u, std::memory_order_relaxed);
            }
        }

        // Append to ring buffer (exclusive write, bounded at kRingCapacity)
        {
            std::unique_lock lock(ringMutex);
            ring.push_back(std::move(ev));
            if (ring.size() > kRingCapacity)
                ring.pop_front();
        }
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Singleton (Meyers')
// ─────────────────────────────────────────────────────────────────────────────

NetworkAttackBlocker& NetworkAttackBlocker::Instance() noexcept {
    static NetworkAttackBlocker instance;
    return instance;
}

NetworkAttackBlocker::NetworkAttackBlocker()
    : m_impl(std::make_unique<Impl>()) {}

NetworkAttackBlocker::~NetworkAttackBlocker() {
    Shutdown();
}

// ─────────────────────────────────────────────────────────────────────────────
// Lifecycle
// ─────────────────────────────────────────────────────────────────────────────

bool NetworkAttackBlocker::Initialize() noexcept {
    SS_LOG_INFO(kLogCategory,
        L"NetworkAttackBlocker initialising");
    return true;
}

bool NetworkAttackBlocker::Start() noexcept {
    // Idempotent + concurrency-safe: only one thread proceeds past the CAS.
    bool expected = false;
    if (!m_impl->running.compare_exchange_strong(
            expected, true,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        return true;  // Already running.
    }

    if (!NetworkMonitor::HasInstance()) {
        SS_LOG_ERROR(kLogCategory,
            L"Start: NetworkMonitor singleton not available; cannot subscribe "
            L"to threat callbacks. NetworkAttackBlocker requires PhantomCore "
            L"NetworkMonitor to be initialised before PhantomHome modules start");
        m_impl->running.store(false, std::memory_order_release);
        return false;
    }

    uint64_t cbId = 0;
    try {
        cbId = NetworkMonitor::Instance().RegisterThreatDetectionCallback(
            [this](uint64_t connId,
                   ThreatIndicator ind,
                   const std::variant<BeaconingAnalysis,
                                      DataExfiltrationAnalysis,
                                      PortScanAnalysis>& analysis) {
                m_impl->OnThreatDetected(connId, ind, analysis);
            });
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(kLogCategory,
            L"Start: RegisterThreatDetectionCallback threw: %hs", ex.what());
        m_impl->running.store(false, std::memory_order_release);
        return false;
    } catch (...) {
        SS_LOG_ERROR(kLogCategory,
            L"Start: RegisterThreatDetectionCallback threw unknown exception");
        m_impl->running.store(false, std::memory_order_release);
        return false;
    }

    if (cbId == 0) {
        SS_LOG_ERROR(kLogCategory,
            L"Start: RegisterThreatDetectionCallback returned 0; "
            L"threat detection unavailable for this session");
        m_impl->running.store(false, std::memory_order_release);
        return false;
    }

    m_impl->threatCallbackId.store(cbId, std::memory_order_release);
    SS_LOG_INFO(kLogCategory,
        L"Start: subscribed to NetworkMonitor (threatCbId=%llu)",
        static_cast<unsigned long long>(cbId));
    return true;
}

void NetworkAttackBlocker::Stop() noexcept {
    // Atomically claim the stop transition; second concurrent Stop() is a no-op.
    bool expected = true;
    if (!m_impl->running.compare_exchange_strong(
            expected, false,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        return;
    }

    const std::uint64_t cbId =
        m_impl->threatCallbackId.exchange(0, std::memory_order_acq_rel);

    if (cbId != 0 && NetworkMonitor::HasInstance()) {
        try {
            NetworkMonitor::Instance().UnregisterCallback(cbId);
        } catch (const std::exception& ex) {
            SS_LOG_ERROR(kLogCategory,
                L"Stop: UnregisterCallback threw: %hs", ex.what());
        } catch (...) {
            SS_LOG_ERROR(kLogCategory,
                L"Stop: UnregisterCallback threw unknown exception");
        }
    }

    {
        std::unique_lock lock(m_impl->ringMutex);
        m_impl->ring.clear();
    }

    SS_LOG_INFO(kLogCategory,
        L"Stop: unsubscribed from NetworkMonitor (cbId=%llu)",
        static_cast<unsigned long long>(cbId));
}

void NetworkAttackBlocker::Shutdown() noexcept {
    Stop();
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode
// ─────────────────────────────────────────────────────────────────────────────

void NetworkAttackBlocker::SetMode(ProtectionMode m) noexcept {
    m_impl->mode.store(m, std::memory_order_release);
    const std::string_view name = HomeProductOrchestrator::ToString(m);
    // Use width-bounded %.*hs because std::string_view is not guaranteed
    // null-terminated; ToString() returns literal-backed views but we stay
    // strictly correct regardless of source.
    SS_LOG_INFO(kLogCategory, L"SetMode → %.*hs",
        static_cast<int>(name.size()), name.data());
}

ProtectionMode NetworkAttackBlocker::Mode() const noexcept {
    return m_impl->mode.load(std::memory_order_acquire);
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-detector overlay
// ─────────────────────────────────────────────────────────────────────────────

void NetworkAttackBlocker::SetDetectorEnabled(NabThreatKind kind,
                                               bool enabled) noexcept {
    if (static_cast<std::uint32_t>(kind) >=
        static_cast<std::uint32_t>(NabThreatKind::Count)) {
        SS_LOG_WARN(kLogCategory,
            L"SetDetectorEnabled: kind=%u out of range [0,%u); request ignored",
            static_cast<unsigned>(kind),
            static_cast<unsigned>(NabThreatKind::Count));
        return;
    }
    const std::uint32_t bit = 1u << static_cast<std::uint32_t>(kind);
    if (enabled)
        m_impl->detectorMask.fetch_or(bit, std::memory_order_release);
    else
        m_impl->detectorMask.fetch_and(~bit, std::memory_order_release);
}

bool NetworkAttackBlocker::IsDetectorEnabled(NabThreatKind kind) const noexcept {
    if (static_cast<std::uint32_t>(kind) >=
        static_cast<std::uint32_t>(NabThreatKind::Count)) {
        return false;
    }
    const std::uint32_t bit = 1u << static_cast<std::uint32_t>(kind);
    return (m_impl->detectorMask.load(std::memory_order_acquire) & bit) != 0u;
}

// ─────────────────────────────────────────────────────────────────────────────
// Status
// ─────────────────────────────────────────────────────────────────────────────

NetworkAttackBlocker::AggregateStatus
NetworkAttackBlocker::GetStatus() const {
    AggregateStatus s;
    s.healthy          = m_impl->running.load(std::memory_order_acquire);
    s.eventsTotal      =
        m_impl->eventsTotal.load(std::memory_order_relaxed);
    s.eventsBlocked24h =
        m_impl->eventsBlocked24h.load(std::memory_order_relaxed);
    s.eventsLogged24h  =
        m_impl->eventsLogged24h.load(std::memory_order_relaxed);

    {
        std::shared_lock lock(m_impl->ringMutex);
        s.recent.assign(m_impl->ring.begin(), m_impl->ring.end());
    }
    return s;
}

}  // namespace Home
}  // namespace Products
}  // namespace ShadowStrike
