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

/**
 * @file ScanDetections.hpp
 * @brief What an on-demand scan found, kept so the user can act on it.
 *
 * An on-demand scan used to report a COUNT of threats and nothing else. The
 * DirectoryScanResult carrying the files themselves was read for its statistics
 * and destroyed, so the UI could say "3 threats found" and could not say which
 * three, and no command existed to quarantine them. A scanner that reports a
 * threat and offers no action is a report, not a product.
 *
 * This header holds the decisions that do not need the service around them, so
 * they can be tested directly:
 *
 *   - WHICH results become actionable detections, and how many are kept;
 *   - HOW a request names one, so the quarantine verb acts only on a file the
 *     scan actually reported rather than on any path a client supplies;
 *   - WHICH completed scan records may be discarded, so the registry is bounded.
 */

#include <Windows.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "../Core/Engine/ScanEngine.hpp"
#include "../Core/Engine/QuarantineManager.hpp"

namespace ShadowStrike::Service::ScanDetections {

/// @brief One file a completed scan convicted.
struct Detection {
    std::wstring path;             ///< Exactly as EngineResult::filePath carried it.
    std::string  sha256;           ///< Lowercase hex, as the scan computed it.
    std::string  threatName;
    std::string  detectionSource;
    bool         quarantined = false;

    /// @brief Set while a quarantine request for this entry is being carried out.
    ///
    /// Claimed and released under the scan record's lock, so two requests for the
    /// same file - a double click, or two UI windows - cannot both reach
    /// QuarantineManager. The second is refused rather than queued.
    bool         inProgress = false;

    /// @brief Whether the quarantine verb can act on this entry at all.
    ///
    /// The verb re-hashes the file and refuses unless the content is the content
    /// that was convicted. With no recorded fingerprint there is nothing to compare,
    /// so the entry is shown but cannot be acted on - an honest "we cannot confirm
    /// this is still the same file" rather than a button that acts blind.
    [[nodiscard]] bool Actionable() const noexcept {
        // An archive member is reported as "archive|entry". '|' cannot occur in a
        // Windows file name, so such a path names nothing that could be opened,
        // hashed or moved; quarantining it would have to mean quarantining the
        // whole archive, which is a different decision from the one shown.
        return !path.empty() && !sha256.empty() &&
               path.find(L'|') == std::wstring::npos;
    }
};

/// @brief Upper bound on detections retained per scan.
///
/// A full scan of a heavily infected machine can convict thousands of files, and
/// every detection is serialised into each progress reply. The count is never
/// truncated - threatsFound still reports the real figure - only the list is, and
/// the reply says how many were omitted rather than implying the list is complete.
inline constexpr std::size_t kMaxRetainedDetections = 1000;

struct Collected {
    std::vector<Detection> items;
    std::size_t            omitted = 0;   ///< Convictions beyond the cap.
};

/// @brief Selects the results a user can act on.
///
/// ONLY Infected. Suspicious, PUA, Adware and Riskware are deliberately excluded,
/// matching threatsFound, which counts confirmed detections only: a heuristic hit
/// presented beside a Quarantine button is presented as malware, and that is a
/// decision this surface must not make on the user's behalf.
///
/// A result with no path is skipped - memory, process, boot and UEFI scans have no
/// file to act on - but a convicted FILE with no fingerprint is kept and marked
/// not actionable, because hiding a conviction is worse than showing one that
/// cannot be acted on.
[[nodiscard]] inline Collected Collect(
    const std::vector<Core::Engine::EngineResult>& results,
    std::size_t cap = kMaxRetainedDetections) {
    Collected out;
    for (const auto& r : results) {
        if (r.verdict != Core::Engine::ScanVerdict::Infected) {
            continue;
        }
        if (r.filePath.empty()) {
            continue;
        }
        if (out.items.size() >= cap) {
            ++out.omitted;
            continue;
        }
        Detection d;
        d.path            = r.filePath;
        d.sha256          = r.sha256;
        d.threatName      = r.threatName;
        d.detectionSource = r.detectionSource;
        out.items.push_back(std::move(d));
    }
    return out;
}

/// @brief Case-insensitive path equality, by the same ordinal rule NTFS uses.
///
/// Locale-sensitive comparison is wrong for paths: under a Turkish locale "I" and
/// "i" are not a case pair, so a locale-aware compare would refuse a path that
/// differs from the recorded one only by case.
[[nodiscard]] inline bool SamePath(std::wstring_view a, std::wstring_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    if (a.empty()) {
        return true;
    }
    return ::CompareStringOrdinal(a.data(), static_cast<int>(a.size()),
                                  b.data(), static_cast<int>(b.size()),
                                  TRUE) == CSTR_EQUAL;
}

/// @brief The detection a request names, or nullptr.
///
/// THIS IS WHAT STOPS THE VERB BEING A "QUARANTINE ANY PATH" COMMAND. A client may
/// only name a file the scan it cites actually reported; any other path is refused
/// before QuarantineManager is reached.
[[nodiscard]] inline Detection* Find(std::vector<Detection>& items,
                                     std::wstring_view path) noexcept {
    if (path.empty()) {
        return nullptr;
    }
    for (auto& d : items) {
        if (SamePath(d.path, path)) {
            return &d;
        }
    }
    return nullptr;
}

/// @brief A stable wire code for a quarantine outcome.
///
/// QuarantineStatusToString yields enumerator names; the IPC protocol's error codes
/// are snake_case ("missing_field", "not_found"), and a client must be able to
/// branch on the outcome without parsing a message meant for people.
[[nodiscard]] inline const char* QuarantineOutcomeCode(
    Core::Engine::QuarantineStatus s) noexcept {
    using S = Core::Engine::QuarantineStatus;
    switch (s) {
        case S::Success:             return "ok";
        case S::FileNotFound:        return "file_not_found";
        case S::AccessDenied:        return "access_denied";
        case S::FileInUse:           return "file_in_use";
        case S::FileTooLarge:        return "file_too_large";
        case S::SystemFileProtected: return "system_file_protected";
        case S::WhitelistMatch:      return "whitelisted";
        case S::AlreadyQuarantined:  return "already_quarantined";
        case S::StorageFull:         return "storage_full";
        case S::RebootRequired:      return "reboot_required";
        case S::DatabaseError:       return "quarantine_unavailable";
        default:                     return "quarantine_failed";
    }
}

/// @brief One entry in the scan registry, as far as retention is concerned.
struct RetentionEntry {
    std::uint64_t sequence = 0;   ///< Monotonic start order.
    bool          terminal = false;
};

/// @brief Upper bound on scan records the service keeps.
///
/// Records were never removed, so the registry grew by one per scan for the life of
/// the service. That was small while a record held counters; with a detection list
/// attached it is not.
inline constexpr std::size_t kMaxRetainedScans = 32;

/// @brief Which records to discard so that at most @p maxRetained remain.
///
/// OLDEST FIRST, BY START ORDER, and ONLY TERMINAL ones. A running scan is never
/// discarded, even if that leaves more than the bound: its watcher still owns the
/// result, and evicting it would make its own progress poll answer "not found"
/// mid-scan. Start order comes from a sequence number, not from the id string,
/// because "scan-10" sorts before "scan-2".
[[nodiscard]] inline std::vector<std::uint64_t> SelectEvictions(
    std::vector<RetentionEntry> entries, std::size_t maxRetained = kMaxRetainedScans) {
    std::vector<std::uint64_t> evict;
    if (entries.size() <= maxRetained) {
        return evict;
    }
    std::size_t excess = entries.size() - maxRetained;
    std::sort(entries.begin(), entries.end(),
              [](const RetentionEntry& a, const RetentionEntry& b) {
                  return a.sequence < b.sequence;
              });
    for (const auto& e : entries) {
        if (excess == 0) {
            break;
        }
        if (e.terminal) {
            evict.push_back(e.sequence);
            --excess;
        }
    }
    return evict;
}

}  // namespace ShadowStrike::Service::ScanDetections
