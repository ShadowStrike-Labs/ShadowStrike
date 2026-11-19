/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "pch.h"
#include "ScriptThreatResponse.hpp"

#include <chrono>
#include <iterator>
#include <mutex>
#include <unordered_map>

#include "KernelBlockTarget.hpp"                 // IsKernelBlockTarget
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"              // ToNarrow
#include "../Core/Process/ProcessKiller.hpp"     // TerminateTree, KillResult

namespace ShadowStrike::Scripts {

namespace {

// Short-window dedup. Repeated scanner events for the same malicious host (a
// process-notify plus a file-scan, several detectors over the same command) must
// not re-terminate or spam telemetry. The window is bounded in TIME so a reused
// pid (Windows recycles pids) is responded to again once the window lapses, and
// bounded in SIZE so the map cannot grow without limit under a storm.
class RecentResponses {
public:
    bool ShouldRespond(std::uint32_t pid) noexcept {
        using namespace std::chrono;
        const auto now = steady_clock::now();
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_map.size() > kMaxEntries) {
            for (auto it = m_map.begin(); it != m_map.end();) {
                it = (now - it->second > kWindow) ? m_map.erase(it) : std::next(it);
            }
        }
        const auto it = m_map.find(pid);
        if (it != m_map.end() && (now - it->second) <= kWindow) {
            return false;  // already responded to this pid within the window
        }
        m_map[pid] = now;
        return true;
    }

private:
    static constexpr std::chrono::seconds kWindow{5};
    static constexpr std::size_t kMaxEntries = 1024;
    std::mutex m_mutex;
    std::unordered_map<std::uint32_t, std::chrono::steady_clock::time_point> m_map;
};

RecentResponses g_recent;

[[nodiscard]] const char* ModuleName(Wiring::Detail::ScriptModule m) noexcept {
    using M = Wiring::Detail::ScriptModule;
    switch (m) {
        case M::PowerShell: return "PowerShell";
        case M::JavaScript: return "JavaScript";
        case M::Macro:      return "Macro";
        case M::Amsi:       return "AMSI";
        case M::Python:     return "Python";
        case M::VBScript:   return "VBScript";
        default:            return "Script";
    }
}

[[nodiscard]] const char* KillResultName(Core::Process::KillResult r) noexcept {
    using KR = Core::Process::KillResult;
    switch (r) {
        case KR::Success:          return "Success";
        case KR::AlreadyDead:      return "AlreadyDead";
        case KR::AccessDenied:     return "AccessDenied";
        case KR::Protected:        return "Protected";
        case KR::Critical:         return "Critical";
        case KR::NotFound:         return "NotFound";
        case KR::Timeout:          return "Timeout";
        case KR::PartialSuccess:   return "PartialSuccess";
        case KR::Failed:           return "Failed";
        case KR::Blocked:          return "Blocked";
        case KR::Resurrected:      return "Resurrected";
        case KR::InsufficientPriv: return "InsufficientPriv";
        default:                   return "Unknown";
    }
}

}  // namespace

const char* ToString(ScriptResponseAction action) noexcept {
    switch (action) {
        case ScriptResponseAction::Allow:     return "Allow";
        case ScriptResponseAction::Alert:     return "Alert";
        case ScriptResponseAction::Terminate: return "Terminate";
        default:                              return "Unknown";
    }
}

ScriptResponseAction RespondToScriptThreat(const ScriptConviction& c) noexcept {
    const bool blockable = IsKernelBlockTarget(c.pid);
    const ScriptResponseAction action =
        DecideScriptResponse(c.blockWorthy, c.suspicious, blockable);

    try {
        const std::string mod    = ModuleName(c.module);
        const std::string image  = Utils::StringUtils::ToNarrow(c.processImage);
        const std::string reason = Utils::StringUtils::ToNarrow(c.reason);

        switch (action) {
        case ScriptResponseAction::Terminate: {
            if (!g_recent.ShouldRespond(c.pid)) {
                return action;  // same host handled within the dedup window
            }
            const auto result = Core::Process::ProcessKiller::TerminateTree(c.pid);
            using KR = Core::Process::KillResult;

            if (result == KR::Success || result == KR::AlreadyDead ||
                result == KR::PartialSuccess) {
                Utils::Logger::Warn(
                    "ScriptThreatResponse: TERMINATED {} script host PID {} ({}) - "
                    "risk={} result={} reason='{}'",
                    mod, c.pid, image, c.riskScore, KillResultName(result), reason);
                return ScriptResponseAction::Terminate;
            }

            if (result == KR::Critical || result == KR::Protected ||
                result == KR::Blocked) {
                // The policy chose to terminate, but ProcessKiller refused a
                // critical / PPL / policy-protected target. Honest outcome: the
                // conviction stands and is reported, the process is NOT killed -
                // never bugcheck the machine over a script verdict.
                Utils::Logger::Warn(
                    "ScriptThreatResponse: {} convicted PID {} ({}) risk={} but did "
                    "NOT terminate - target is critical/protected ({}); reported only",
                    mod, c.pid, image, c.riskScore, KillResultName(result));
                return ScriptResponseAction::Alert;
            }

            // Access denied, timeout, resurrected, failed: the block was attempted
            // and did not complete. Reported honestly, not claimed as a success.
            Utils::Logger::Error(
                "ScriptThreatResponse: {} convicted PID {} ({}) risk={} but "
                "termination failed ({}); reported only",
                mod, c.pid, image, c.riskScore, KillResultName(result));
            return ScriptResponseAction::Alert;
        }

        case ScriptResponseAction::Alert:
            Utils::Logger::Warn(
                "ScriptThreatResponse: {} conviction on PID {} ({}) risk={} reported, "
                "not terminated ({})",
                mod, c.pid, image, c.riskScore,
                (c.blockWorthy ? "target is not terminable (System/self/no-pid)"
                               : "below the block threshold - suspicious, watched"));
            break;

        case ScriptResponseAction::Allow:
            break;
        }
    } catch (...) {
        // A response must never throw back into a scanner's detection flow.
    }

    return action;
}

}  // namespace ShadowStrike::Scripts
