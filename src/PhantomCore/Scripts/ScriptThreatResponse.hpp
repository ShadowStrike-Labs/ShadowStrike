/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomCore - SCRIPT THREAT RESPONSE (fileless defense)
 * ============================================================================
 *
 * @file  ScriptThreatResponse.hpp
 * @brief Confidence-gated response that turns a script-scanner conviction into a
 *        real, false-positive-safe action. The six script scanners (PowerShell,
 *        JavaScript, VBScript, Python, Office macros, AMSI) each compute a tuned
 *        verdict and riskScore over obfuscation, download cradles, reflection /
 *        injection, AMSI-bypass attempts and behavioural context - the content a
 *        fileless attack exposes at run time. Until now a conviction asked the
 *        kernel to "block the PID" through a headerless wire struct the driver
 *        refused (tasks 158/361), so malicious scripts were DETECTED but never
 *        STOPPED. This component is the missing enforcement.
 *
 * THE POLICY is tiered so a legitimate administrative script is never killed and
 * a fileless payload is:
 *   - Allow     : clean, or below the scanner's suspicious bar -> no action.
 *   - Alert     : suspicious (watched and reported, NOT terminated), OR a
 *                 block-worthy conviction whose target must never be terminated
 *                 (PID 0, System, or this service). Reported, never killed.
 *   - Terminate : the scanner's OWN high-confidence block verdict
 *                 (ScanResult::isBlocking() and the equivalents) AND a blockable
 *                 target -> terminate the offending process TREE in user mode via
 *                 ProcessKiller, which still refuses critical / PPL processes and
 *                 reports why. Killing the host is how the in-memory payload is
 *                 stopped.
 *
 * The legitimate-vs-malicious separation is therefore two independent gates: the
 * scanner's confidence (only its high-confidence conviction terminates; a merely
 * suspicious score is reported, not killed) AND the process-targeting guard
 * (infrastructure is never terminated). The DISCRIMINATION quality is the
 * scanners'; this component is the one, uniform, safe ACTION on it, so the six
 * modules cannot drift into six different enforcement behaviours.
 * ============================================================================
 */
#pragma once

#include <cstdint>
#include <string>

#include "ScriptsWiring.hpp"  // Wiring::Detail::ScriptModule

namespace ShadowStrike::Scripts {

/// The action the response policy selected for a conviction.
enum class ScriptResponseAction : std::uint8_t {
    Allow     = 0,  ///< legitimate / below the suspicious bar - no action
    Alert     = 1,  ///< reported and watched, deliberately NOT terminated
    Terminate = 2   ///< high-confidence malicious on a blockable target - terminated
};

/// A scanner conviction, normalized so ONE policy serves all six scanners.
struct ScriptConviction {
    std::uint32_t pid = 0;                               ///< originating/host process
    Wiring::Detail::ScriptModule module =
        Wiring::Detail::ScriptModule::PowerShell;        ///< which scanner convicted
    bool blockWorthy = false;  ///< the scanner's OWN high-confidence block decision
    bool suspicious  = false;  ///< status == SUSPICIOUS (watch, do not kill)
    int  riskScore   = 0;      ///< 0-100, for telemetry and logs
    std::wstring processImage; ///< host image (e.g. ...\\powershell.exe), for logs
    std::wstring reason;       ///< threat name / technique, for logs
};

/// PURE tiered policy. @p targetIsBlockable is IsKernelBlockTarget(pid): false for
/// PID 0, System (4) and this service, which must never be terminated. Kept a pure
/// function (no process, no I/O) so the policy is provable by exhaustive unit test.
///
/// Only a block-worthy conviction against a blockable target terminates; a
/// suspicious-but-not-block-worthy score is Alert, and a block-worthy conviction
/// against a non-blockable target is downgraded to Alert rather than ever touching
/// infrastructure.
[[nodiscard]] constexpr ScriptResponseAction DecideScriptResponse(
    bool blockWorthy, bool suspicious, bool targetIsBlockable) noexcept {
    if (blockWorthy) {
        return targetIsBlockable ? ScriptResponseAction::Terminate
                                 : ScriptResponseAction::Alert;
    }
    if (suspicious) {
        return ScriptResponseAction::Alert;
    }
    return ScriptResponseAction::Allow;
}

/// Classify @p conviction and enforce. On Terminate, terminates the process tree
/// via ProcessKiller (which refuses critical / PPL processes and is honestly
/// reported when it does), deduplicated within a short window per pid so repeated
/// scanner events do not re-kill or spam telemetry. Returns the action actually
/// taken - which is Alert, not Terminate, if ProcessKiller refused a critical /
/// protected target. noexcept: the response must never throw into a scanner's
/// detection flow.
ScriptResponseAction RespondToScriptThreat(const ScriptConviction& conviction) noexcept;

/// Stable names for logs, telemetry and tests.
[[nodiscard]] const char* ToString(ScriptResponseAction action) noexcept;

}  // namespace ShadowStrike::Scripts
