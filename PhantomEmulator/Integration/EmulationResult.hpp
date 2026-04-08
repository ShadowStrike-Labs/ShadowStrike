/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * EmulationResult.hpp — Aggregate result produced by a complete emulation session
 *
 * Contains every artefact collected across all analysis subsystems: CPU execution
 * stats, API traces, behavioral alerts, MITRE technique mappings, memory forensics,
 * unpacking layers, IOC extractions, evasion attempts, network behaviour, string
 * and crypto findings, and the final threat verdict.
 *
 * This is the single data structure returned to the caller by EmulationSession.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../Common/Types.hpp"
#include "../Common/Errors.hpp"
#include "../WinAPI/APITypes.hpp"
#include "../Analysis/BehaviorMonitor.hpp"
#include "../Analysis/APISequenceAnalyzer.hpp"
#include "../Analysis/MemoryForensics.hpp"
#include "../Analysis/UnpackingEngine.hpp"
#include "../Analysis/ThreatScorer.hpp"
#include "../Analysis/MITREMapper.hpp"
#include "../Analysis/IOCExtractor.hpp"
#include "../Analysis/StringExtractor.hpp"
#include "../Analysis/CryptoDetector.hpp"
#include "../Analysis/NetworkBehaviorAnalyzer.hpp"
#include "../Analysis/EvasionDetector.hpp"
#include "../Core/CLR/CLRTypes.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace Phantom {

// ============================================================================
// Execution Statistics
// ============================================================================

struct ExecutionStatistics {
    StopReason  stopReason           = StopReason::None;
    ErrorCode   errorCode            = ErrorCode::Success;
    uint64_t    instructionsExecuted = 0;
    uint64_t    apiCallCount         = 0;
    uint64_t    wallTimeMs           = 0;
    size_t      peakMemoryUsage      = 0;
    GuestAddress lastRIP             = 0;
    GuestAddress faultAddress        = 0;
    bool         is64Bit             = true;
};

// ============================================================================
// Unpacking Summary
// ============================================================================

struct UnpackingSummary {
    PackerType               detectedPacker  = PackerType::Unknown;
    std::vector<UnpackLayer> layers;
    std::vector<uint8_t>     finalPayload;
    GuestAddress             finalOEP        = 0;
    OEPMethod                oepMethod       = OEPMethod::WXTransition;
    bool                     successful      = false;
};

// ============================================================================
// Network Behaviour Summary
// ============================================================================

struct NetworkSummary {
    std::vector<NetworkConnection> connections;
    std::vector<NetworkAlert>      alerts;
    uint64_t totalBytesSent     = 0;
    uint64_t totalBytesReceived = 0;
    bool     hasC2Indicators    = false;
    bool     hasExfiltration    = false;
};

// ============================================================================
// PhantomEmulationResult — complete output from one emulation session
// ============================================================================
//
// Ownership: all vectors and strings are owned. The caller receives this by
// value (move) and can inspect, serialise, or discard it at will. No dangling
// references exist once the session is destroyed — all const char* pointers in
// BehaviorAlert/SequenceMatch/MITRETechnique point to static storage owned by
// the analysis modules and remain valid for the lifetime of the process.

struct PhantomEmulationResult {

    // === Verdict =============================================================

    ThreatVerdict   verdict;

    // === Execution ===========================================================

    ExecutionStatistics execution;

    // === API Trace ============================================================

    std::vector<APICallDetail> apiCalls;
    BehaviorFlag               aggregateBehaviorFlags = BehaviorFlag::None;

    // === Behavioural Analysis =================================================

    std::vector<BehaviorAlert>      behaviorAlerts;
    std::vector<SequenceMatch>      sequenceMatches;
    std::vector<TransitionAnomaly>  transitionAnomalies;

    // === Memory Forensics =====================================================

    std::vector<MemoryFindingDetail> memoryFindings;
    std::vector<ExtractedPayload>    extractedPayloads;

    // === Unpacking ============================================================

    UnpackingSummary unpacking;

    // === MITRE ATT&CK =========================================================

    std::vector<MITRETechnique> mitreTechniques;
    uint32_t                    killChainCoverage = 0;

    // === IOC Extraction =======================================================

    IOCReport iocReport;

    // === Evasion Detection ====================================================

    std::vector<EvasionAttempt> evasionAttempts;
    EvasionSummary              evasionSummary;

    // === Network Behaviour ====================================================

    NetworkSummary network;

    // === Strings ==============================================================

    std::vector<ExtractedString> extractedStrings;

    // === Cryptographic Artefacts ==============================================

    std::vector<CryptoFinding> cryptoFindings;
    CryptoStats                cryptoStats;

    // === .NET/CLR Analysis ====================================================

    CLR::DotNetAnalysisResult  dotNetAnalysis;

    // === Session Status =======================================================

    bool        success      = false;
    std::string errorMessage;

    // === Convenience Queries ==================================================

    [[nodiscard]] bool IsMalicious() const noexcept {
        return verdict.level >= ThreatLevel::Malicious;
    }

    [[nodiscard]] bool IsSuspicious() const noexcept {
        return verdict.level >= ThreatLevel::Suspicious;
    }

    [[nodiscard]] bool WasAborted() const noexcept {
        return execution.stopReason == StopReason::UserAborted;
    }

    [[nodiscard]] bool HitResourceLimit() const noexcept {
        return execution.stopReason == StopReason::InstructionLimit ||
               execution.stopReason == StopReason::TimeLimit ||
               execution.stopReason == StopReason::MemoryLimit;
    }

    [[nodiscard]] uint32_t TotalAlertCount() const noexcept {
        return static_cast<uint32_t>(behaviorAlerts.size()) +
               static_cast<uint32_t>(sequenceMatches.size()) +
               static_cast<uint32_t>(memoryFindings.size()) +
               static_cast<uint32_t>(evasionAttempts.size());
    }
};

} // namespace Phantom
