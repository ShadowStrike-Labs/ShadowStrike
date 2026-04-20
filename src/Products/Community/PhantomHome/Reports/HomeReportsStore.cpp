// ShadowStrike Phantom Home — In-memory Reports journal (implementation).

#include "HomeReportsStore.hpp"

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

}  // namespace ShadowStrike::PhantomHome::Reports
