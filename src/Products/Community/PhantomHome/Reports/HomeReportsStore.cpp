// ShadowStrike Phantom Home — In-memory Reports journal (implementation).

#include "HomeReportsStore.hpp"

#include "../../../../PhantomCore/Communication/AlertSystem.hpp"

#include <algorithm>
#include <chrono>

namespace ShadowStrike::PhantomHome::Reports {

namespace {

constexpr std::size_t kMaxStringLen = 2048;
constexpr std::size_t kMaxTargetLen = 4096;

inline void ClampString(std::string& s, std::size_t max) noexcept {
    try {
        if (s.size() > max) {
            s.resize(max);
        }
    } catch (...) {
        // std::string::resize on already-valid string with smaller size never
        // throws in practice, but we honour the noexcept guarantee of callers.
    }
}

inline std::int64_t NowUnixMs() noexcept {
    using namespace std::chrono;
    return duration_cast<milliseconds>(
               system_clock::now().time_since_epoch()).count();
}

inline void Sanitize(ReportEntry& e) noexcept {
    ClampString(e.module,      kMaxStringLen);
    ClampString(e.title,       kMaxStringLen);
    ClampString(e.description, kMaxStringLen);
    ClampString(e.target,      kMaxTargetLen);
    ClampString(e.action,      kMaxStringLen);
    ClampString(e.scan_id,     kMaxStringLen);
}

}  // namespace

HomeReportsStore& HomeReportsStore::Instance() noexcept {
    static HomeReportsStore s;
    return s;
}

void HomeReportsStore::Record(ReportEntry entry) noexcept {
    try {
        if (entry.id == 0) {
            entry.id = next_id_.fetch_add(1, std::memory_order_relaxed);
        }
        if (entry.timestamp_unix_ms == 0) {
            entry.timestamp_unix_ms = NowUnixMs();
        }
        Sanitize(entry);

        std::unique_lock lock(mtx_);
        entries_.push_back(std::move(entry));
        while (entries_.size() > kMaxEntries) {
            entries_.pop_front();
        }
    } catch (...) {
        // Journal must never throw into caller paths.
    }
}

void HomeReportsStore::RecordScanCompleted(std::string_view scan_id,
                                           std::uint64_t files_scanned,
                                           std::uint64_t threats_found,
                                           std::int64_t duration_ms) noexcept {
    try {
        ReportEntry e;
        e.kind            = ReportKind::ScanCompleted;
        e.severity        = (threats_found > 0) ? ReportSeverity::Medium
                                                : ReportSeverity::Info;
        e.module          = "ScanEngine";
        e.title           = (threats_found > 0)
                              ? "Scan completed — threats detected"
                              : "Scan completed — clean";
        e.description     = "Scanned " + std::to_string(files_scanned)
                           + " file(s); "
                           + std::to_string(threats_found)
                           + " threat(s) found.";
        e.scan_id         = std::string(scan_id);
        e.files_scanned   = files_scanned;
        e.threats_found   = threats_found;
        e.duration_ms     = duration_ms;
        Record(std::move(e));
    } catch (...) {
    }
}

void HomeReportsStore::RecordThreatDetected(std::string_view target,
                                            std::string_view description,
                                            std::string_view action,
                                            ReportSeverity severity) noexcept {
    try {
        ReportEntry e;
        e.kind        = ReportKind::ThreatDetected;
        e.severity    = severity;
        e.module      = "RealTimeProtection";
        e.title       = "Threat detected";
        e.description = std::string(description);
        e.target      = std::string(target);
        e.action      = std::string(action);
        Record(std::move(e));
    } catch (...) {
    }
}

std::vector<ReportEntry> HomeReportsStore::Query(const ReportQuery& q) const {
    std::vector<ReportEntry> out;
    try {
        const std::size_t cap =
            (q.max_entries == 0 || q.max_entries > kMaxEntries)
                ? kMaxEntries : q.max_entries;
        out.reserve(cap);

        std::shared_lock lock(mtx_);
        // Walk newest → oldest so the freshest entries populate the cap first.
        for (auto it = entries_.rbegin(); it != entries_.rend(); ++it) {
            if (q.kind         && *q.kind         != it->kind)     continue;
            if (q.min_severity &&
                static_cast<std::uint32_t>(it->severity) <
                static_cast<std::uint32_t>(*q.min_severity))        continue;
            if (q.since_id     && it->id <= *q.since_id)            continue;

            // Inclusive on both ends - see the field declaration for why.
            if (q.since_unix_ms &&
                it->timestamp_unix_ms < *q.since_unix_ms)            continue;
            if (q.until_unix_ms &&
                it->timestamp_unix_ms > *q.until_unix_ms)            continue;

            out.push_back(*it);
            if (out.size() >= cap) break;
        }
    } catch (...) {
        out.clear();
    }
    return out;
}

std::vector<ReportEntry> HomeReportsStore::GetRecent(std::size_t max_entries) const {
    ReportQuery q;
    q.max_entries = max_entries == 0 ? 64 : max_entries;
    return Query(q);
}

std::size_t HomeReportsStore::Size() const noexcept {
    try {
        std::shared_lock lock(mtx_);
        return entries_.size();
    } catch (...) {
        return 0;
    }
}

void HomeReportsStore::Clear() noexcept {
    try {
        std::unique_lock lock(mtx_);
        entries_.clear();
    } catch (...) {
    }
}

// ===========================================================================
// THE ALERTSYSTEM BRIDGE
//
// AlertSystem::RaiseAlert has 101 call sites across 33 files and was the
// only chokepoint wide enough to give this store a general producer. See the
// header for why this is a registered callback rather than a call placed
// inside RaiseAlert itself.
// ===========================================================================
namespace {

std::atomic<std::uint64_t> g_bridged{0};
std::atomic<std::uint64_t> g_skippedInfo{0};
std::atomic<bool>          g_installed{false};

ReportSeverity MapSeverity(Communication::AlertSeverity s) noexcept {
    using AS = Communication::AlertSeverity;
    switch (s) {
        case AS::Info:      return ReportSeverity::Info;
        case AS::Low:       return ReportSeverity::Low;
        case AS::Medium:    return ReportSeverity::Medium;
        case AS::High:      return ReportSeverity::High;
        case AS::Critical:  return ReportSeverity::Critical;
        case AS::Emergency: return ReportSeverity::Critical;
        // Emergency FOLDS to Critical rather than being truncated: Critical
        // is the top of ReportSeverity, so an Emergency alert still lands in
        // the highest bucket the page can render and nothing is understated.
        // Adding a sixth ReportSeverity would change a type the UI maps to
        // colours, which is not a change to make as a side effect of this one.
    }
    return ReportSeverity::Info;
}

ReportKind MapKind(Communication::AlertType t) noexcept {
    using AT = Communication::AlertType;
    switch (t) {
        case AT::ThreatDetection: return ReportKind::ThreatDetected;
        case AT::Security:        return ReportKind::ThreatDetected;
        case AT::PolicyViolation: return ReportKind::PolicyChanged;
        case AT::SystemHealth:
        case AT::Operational:
        case AT::Performance:     return ReportKind::ModuleStateChange;
        case AT::ComplianceAlert:
        case AT::AuditEvent:
        case AT::Custom:          break;
        // These three fall through to Unknown DELIBERATELY. ReportKind has no
        // bucket for them, and filing an audit event as a ModuleStateChange
        // would state that a module changed state when none did. An honest
        // Unknown alongside a real title and description is worth more than a
        // confident wrong label - the same reasoning that keeps a stopped scan
        // out of RecordScanCompleted.
    }
    return ReportKind::Unknown;
}

}  // namespace

void InstallAlertSystemBridge() noexcept {
    bool expected = false;
    if (!g_installed.compare_exchange_strong(expected, true,
                                             std::memory_order_acq_rel)) {
        return;  // Already installed; registering twice would replace it.
    }
    try {
        Communication::AlertSystem::Instance().RegisterAlertCallback(
            [](const Communication::Alert& alert) {
                const ReportSeverity sev = MapSeverity(alert.severity);

                // INFO IS DROPPED, AND THE ARITHMETIC IS THE REASON.
                //
                // entries_ holds kMaxEntries = 1024 rows and evicts the
                // oldest, so the ring is a scarce resource shared with scan
                // rows and threat rows. The 1.0.104 field run recorded 46,185
                // kernel threat alerts in 329 seconds - about 140 a second -
                // and at that rate an unfiltered bridge would churn the whole
                // page in roughly seven seconds, leaving a user looking at the
                // last few moments of chatter instead of their security
                // history. Adding a producer that destroys the surface it
                // feeds is not an improvement.
                //
                // Info is the one class that is pure chatter. Scan completions
                // are Info-flavoured but genuinely user-meaningful, and they
                // come from the dedicated scan producer, not from here.
                //
                // BOTH SIDES ARE COUNTED. The right threshold is a field
                // question and the counters are how the next run answers it,
                // rather than this comment being the last word on it.
                if (sev == ReportSeverity::Info) {
                    g_skippedInfo.fetch_add(1, std::memory_order_relaxed);
                    return;
                }

                ReportEntry e;
                e.kind        = MapKind(alert.type);
                e.severity    = sev;
                e.module      = alert.source.empty() ? std::string("AlertSystem")
                                                     : alert.source;
                e.title       = alert.subject;
                e.description = alert.details;

                // target AND action ARE LEFT EMPTY ON PURPOSE. Alert carries no
                // subject path - correlationId is a dedup key and metadata is
                // opaque JSON - and an alert states that something was OBSERVED,
                // not what was done about it. Putting a dedup key in a field the
                // header documents as "subject path / URL / indicator", or
                // writing an action nothing performed, would be inventing
                // evidence. A blank column is the honest rendering, and it is
                // also the measurement that says a quarantine-side producer is
                // still owed.

                HomeReportsStore::Instance().Record(std::move(e));
                g_bridged.fetch_add(1, std::memory_order_relaxed);
            });
    } catch (...) {
        // Leave the flag clear so a later attempt can retry rather than the
        // bridge being permanently believed installed.
        g_installed.store(false, std::memory_order_release);
    }
}

AlertBridgeStats GetAlertBridgeStats() noexcept {
    AlertBridgeStats s;
    s.bridged      = g_bridged.load(std::memory_order_relaxed);
    s.skipped_info = g_skippedInfo.load(std::memory_order_relaxed);
    return s;
}

}  // namespace ShadowStrike::PhantomHome::Reports
