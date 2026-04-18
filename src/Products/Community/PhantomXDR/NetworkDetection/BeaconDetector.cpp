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

#include "pch.h"
#include "BeaconDetector.hpp"

#include <format>
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

#include <windows.h>

#include <algorithm>
#include <cmath>
#include <deque>
#include <numbers>
#include <numeric>
#include <unordered_map>

namespace ShadowStrike::Products::PhantomXDR::NetworkDetection {

namespace SU = ShadowStrike::Utils::StringUtils;
using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;

namespace {

constexpr std::wstring_view kLogCategory = L"PhantomXDR.Network.Beacon";
constexpr size_t kMaxSamplesPerDestination = 512;
constexpr size_t kMaxStoredPatterns = 2048;

struct ConnectionSample {
    SystemTimePoint timestamp;
    uint32_t processId = 0;
    std::wstring processName;
};

[[nodiscard]] std::string Narrow(std::wstring_view value) {
    return SU::ToNarrow(value);
}

void LogDatabaseError(std::string_view context, const DatabaseError& err) {
    if (!err.HasError()) {
        return;
    }

    const std::wstring message = SU::ToWide(std::format("{}: {}", context, Narrow(err.message)));
    ShadowStrike::Utils::Logger::Instance().LogMessage(
        ShadowStrike::Utils::LogLevel::Error,
        kLogCategory.data(),
        message);
}

[[nodiscard]] std::string ToIso8601(SystemTimePoint timestamp) {
    if (timestamp.time_since_epoch().count() == 0) {
        timestamp = std::chrono::system_clock::now();
    }

    const auto tt = std::chrono::system_clock::to_time_t(timestamp);
    std::tm tmUtc{};
    gmtime_s(&tmUtc, &tt);

    char buffer[32]{};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tmUtc);
    return std::string(buffer);
}

[[nodiscard]] double Mean(const std::vector<double>& values) {
    if (values.empty()) {
        return 0.0;
    }
    return std::accumulate(values.begin(), values.end(), 0.0) / static_cast<double>(values.size());
}

[[nodiscard]] double StandardDeviation(const std::vector<double>& values, double mean) {
    if (values.size() < 2) {
        return 0.0;
    }

    double variance = 0.0;
    for (const double value : values) {
        const double delta = value - mean;
        variance += delta * delta;
    }
    variance /= static_cast<double>(values.size() - 1);
    return std::sqrt(std::max(variance, 0.0));
}

[[nodiscard]] double DominantFrequencyScore(const std::vector<double>& samples) {
    if (samples.size() < 4) {
        return 0.0;
    }

    double totalPower = 0.0;
    double dominantPower = 0.0;
    const size_t n = samples.size();

    for (size_t k = 1; k <= n / 2; ++k) {
        double real = 0.0;
        double imag = 0.0;

        for (size_t i = 0; i < n; ++i) {
            const double angle = 2.0 * std::numbers::pi_v<double> * static_cast<double>(k * i) / static_cast<double>(n);
            real += samples[i] * std::cos(angle);
            imag -= samples[i] * std::sin(angle);
        }

        const double power = (real * real) + (imag * imag);
        totalPower += power;
        dominantPower = std::max(dominantPower, power);
    }

    if (totalPower <= 0.0) {
        return 0.0;
    }

    return dominantPower / totalPower;
}

template <typename T>
void PushBounded(std::vector<T>& values, const T& item) {
    values.push_back(item);
    if (values.size() > kMaxStoredPatterns) {
        values.erase(values.begin(), values.begin() + static_cast<ptrdiff_t>(values.size() - kMaxStoredPatterns));
    }
}

} // namespace

class BeaconDetectorImpl final {
public:
    [[nodiscard]] bool Initialize(const BeaconDetectorSettings& settings) {
        std::unique_lock lock(m_mutex);
        if (m_initialized) {
            return true;
        }

        m_settings = settings;
        if (!EnsureSchemaLocked()) {
            ++m_stats.errors;
            return false;
        }

        m_initialized = true;
        return true;
    }

    void Shutdown() {
        std::unique_lock lock(m_mutex);
        m_samples.clear();
        m_patterns.clear();
        m_initialized = false;
    }

    void RecordConnection(const NetworkConnection& connection) {
        if (connection.direction != ConnectionDirection::Outbound || connection.destinationIp.empty()) {
            return;
        }

        std::unique_lock lock(m_mutex);
        if (!m_initialized) {
            ++m_stats.errors;
            return;
        }

        ++m_stats.recordedConnections;

        auto& destinationSamples = m_samples[connection.destinationIp];
        destinationSamples.push_back(ConnectionSample{
            connection.timestamp.time_since_epoch().count() == 0 ? std::chrono::system_clock::now() : connection.timestamp,
            connection.processId,
            connection.processName
        });

        while (destinationSamples.size() > kMaxSamplesPerDestination) {
            destinationSamples.pop_front();
        }

        const auto cutoff = std::chrono::system_clock::now() - m_settings.analysisWindow;
        while (!destinationSamples.empty() && destinationSamples.front().timestamp < cutoff) {
            destinationSamples.pop_front();
        }

        lock.unlock();
        const auto pattern = AnalyzeDestination(connection.destinationIp);
        if (pattern.has_value() && pattern->confidence >= m_settings.suspicionThreshold) {
            std::unique_lock relock(m_mutex);
            ++m_stats.detectedPatterns;
            ++m_stats.suspiciousDestinations;
            PushBounded(m_patterns, *pattern);
            PersistPatternLocked(*pattern);
        }
    }

    [[nodiscard]] std::optional<BeaconPattern> AnalyzeDestination(std::string_view destination) const {
        std::shared_lock lock(m_mutex);
        if (!m_initialized) {
            return std::nullopt;
        }

        const auto it = m_samples.find(std::string(destination));
        if (it == m_samples.end() || it->second.size() < m_settings.minimumSampleCount) {
            return std::nullopt;
        }

        ++m_stats.analyzedDestinations;
        std::vector<double> intervals;
        intervals.reserve(it->second.size() - 1);

        for (size_t i = 1; i < it->second.size(); ++i) {
            const auto delta = std::chrono::duration<double>(it->second[i].timestamp - it->second[i - 1].timestamp).count();
            if (delta > 0.0) {
                intervals.push_back(delta);
            }
        }

        if (intervals.size() + 1 < m_settings.minimumSampleCount) {
            return std::nullopt;
        }

        const double mean = Mean(intervals);
        const double stddev = StandardDeviation(intervals, mean);
        const double jitter = mean > 0.0 ? stddev / mean : 1.0;
        const double fftScore = DominantFrequencyScore(intervals);
        const double regularityScore = std::clamp(1.0 - jitter, 0.0, 1.0);
        const double confidence = std::clamp(
            (regularityScore * 0.55) +
            (fftScore * 0.30) +
            (std::min(intervals.size(), static_cast<size_t>(20)) / 20.0 * 0.15),
            0.0,
            1.0);

        if (jitter > m_settings.maxJitterRatio || confidence < m_settings.suspicionThreshold) {
            return std::nullopt;
        }

        BeaconPattern pattern;
        pattern.destination = std::string(destination);
        pattern.intervalMeanSeconds = mean;
        pattern.intervalStdDevSeconds = stddev;
        pattern.jitterRatio = jitter;
        pattern.sampleCount = it->second.size();
        pattern.confidence = confidence;
        pattern.intervals = std::move(intervals);
        pattern.lastSeen = it->second.back().timestamp;
        pattern.processId = it->second.back().processId;
        pattern.processName = it->second.back().processName;
        return pattern;
    }

    [[nodiscard]] std::vector<BeaconPattern> GetBeaconPatterns(size_t limit) const {
        std::shared_lock lock(m_mutex);
        if (limit >= m_patterns.size()) {
            return m_patterns;
        }
        return std::vector<BeaconPattern>(m_patterns.end() - static_cast<ptrdiff_t>(limit), m_patterns.end());
    }

    [[nodiscard]] std::vector<std::string> GetSuspiciousDestinations(size_t limit) const {
        std::shared_lock lock(m_mutex);
        std::vector<std::string> destinations;
        destinations.reserve(std::min(limit, m_patterns.size()));
        for (auto it = m_patterns.rbegin(); it != m_patterns.rend() && destinations.size() < limit; ++it) {
            destinations.push_back(it->destination);
        }
        return destinations;
    }

    [[nodiscard]] BeaconDetectorStatistics GetStatistics() const {
        std::shared_lock lock(m_mutex);
        return m_stats;
    }

private:
    [[nodiscard]] bool EnsureSchemaLocked() {
        DatabaseError err;
        const char* sql = R"SQL(
            CREATE TABLE IF NOT EXISTS xdr_beacon_patterns(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                destination TEXT NOT NULL,
                interval_mean REAL NOT NULL,
                interval_stddev REAL NOT NULL,
                jitter_ratio REAL NOT NULL,
                sample_count INTEGER NOT NULL,
                confidence REAL NOT NULL,
                process_id INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                observed_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_xdr_beacon_patterns_destination ON xdr_beacon_patterns(destination);
        )SQL";

        const bool ok = DatabaseManager::Instance().Execute(sql, &err);
        if (!ok) {
            LogDatabaseError("EnsureSchema", err);
        }
        return ok;
    }

    void PersistPatternLocked(const BeaconPattern& pattern) {
        DatabaseError err;
        const bool ok = DatabaseManager::Instance().ExecuteWithParams(
            "INSERT INTO xdr_beacon_patterns("
            "destination, interval_mean, interval_stddev, jitter_ratio, sample_count, confidence, process_id, process_name, observed_at"
            ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
            &err,
            pattern.destination,
            pattern.intervalMeanSeconds,
            pattern.intervalStdDevSeconds,
            pattern.jitterRatio,
            static_cast<int>(pattern.sampleCount),
            pattern.confidence,
            static_cast<int>(pattern.processId),
            Narrow(pattern.processName),
            ToIso8601(pattern.lastSeen));
        if (!ok) {
            LogDatabaseError("PersistPattern", err);
        }
    }

    mutable std::shared_mutex m_mutex;
    bool m_initialized = false;
    BeaconDetectorSettings m_settings{};
    mutable BeaconDetectorStatistics m_stats{};
    std::unordered_map<std::string, std::deque<ConnectionSample>> m_samples;
    std::vector<BeaconPattern> m_patterns;
};

BeaconDetector::BeaconDetector() : m_impl(std::make_unique<BeaconDetectorImpl>()) {}
BeaconDetector::~BeaconDetector() = default;

bool BeaconDetector::Initialize(const BeaconDetectorSettings& settings) { return m_impl->Initialize(settings); }
void BeaconDetector::Shutdown() { m_impl->Shutdown(); }
void BeaconDetector::RecordConnection(const NetworkConnection& connection) { m_impl->RecordConnection(connection); }
std::optional<BeaconPattern> BeaconDetector::AnalyzeDestination(std::string_view destination) const { return m_impl->AnalyzeDestination(destination); }
std::vector<BeaconPattern> BeaconDetector::GetBeaconPatterns(size_t limit) const { return m_impl->GetBeaconPatterns(limit); }
std::vector<std::string> BeaconDetector::GetSuspiciousDestinations(size_t limit) const { return m_impl->GetSuspiciousDestinations(limit); }
BeaconDetectorStatistics BeaconDetector::GetStatistics() const { return m_impl->GetStatistics(); }

} // namespace ShadowStrike::Products::PhantomXDR::NetworkDetection
