/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * DKOMDetector.hpp — High-level DKOM (Direct Kernel Object Manipulation)
 *                     detection and rootkit analysis
 *
 * Periodically scans emulated kernel state for DKOM attacks (process/driver
 * unlinking, SSDT/IDT hooking, token swaps, callback removal) and cross-
 * references findings with behavioral signals (API calls, MSR writes, ring
 * transitions) to assign severity scores and map to MITRE ATT&CK techniques.
 *
 * Produces a consolidated DKOMAnalysisReport with composite rootkit scoring.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../Common/Types.hpp"
#include "../Core/Kernel/KernelStructures.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace Phantom {

// ============================================================================
// Individual DKOM Finding — enriched with severity and MITRE ATT&CK data
// ============================================================================

struct DKOMFinding {
    DKOMDetection::Type type = DKOMDetection::Type::ProcessUnlinked;
    std::string         description;
    uint32_t            targetPid  = 0;
    GuestAddress        targetAddr = 0;

    // Severity analysis
    float       severityScore      = 0.0f;   // 0.0 – 100.0

    // MITRE ATT&CK mapping
    std::string mitreTechnique;              // e.g., "T1014"
    std::string mitreSubTechnique;           // e.g., "T1564.001"
    std::string mitreTactics;                // e.g., "Defense Evasion"

    // Behavioral correlation
    bool correlatedWithAPIBehavior    = false;
    bool correlatedWithMSRWrite       = false;
    bool correlatedWithRingTransition = false;
    std::vector<std::string> relatedAPICalls;
};

// ============================================================================
// Consolidated DKOM Analysis Report
// ============================================================================

struct DKOMAnalysisReport {
    std::vector<DKOMFinding> findings;

    uint32_t totalScans                      = 0;
    uint32_t processListIntegrityFailures    = 0;
    uint32_t ssdtHooksDetected               = 0;
    uint32_t idtHooksDetected                = 0;
    uint32_t driversUnlinked                 = 0;
    uint32_t processesHidden                 = 0;
    uint32_t tokensSwapped                   = 0;

    float    overallRootkitScore             = 0.0f;  // 0 – 100 composite
    bool     isRootkitDetected               = false;

    std::vector<std::string> mitreTechniquesUsed;
};

// ============================================================================
// DKOMDetector — Meyers' Singleton, PIMPL, thread-safe
// ============================================================================

class DKOMDetector {
public:
    static DKOMDetector& Instance();

    void Reset();
    bool Initialize();

    // --- Core scanning ---

    [[nodiscard]] DKOMAnalysisReport      RunFullScan();
    [[nodiscard]] std::vector<DKOMFinding> RunIncrementalScan();

    // --- Correlation inputs (called by other modules during emulation) ---

    void OnAPICall(const std::string& apiName, uint32_t pid);
    void OnMSRWrite(uint32_t msrIndex, uint64_t value);
    void OnRingTransition(uint8_t fromCPL, uint8_t toCPL);
    void OnMemoryWrite(GuestAddress addr, uint32_t size);

    // --- Thresholds ---

    void SetRootkitScoreThreshold(float threshold);
    [[nodiscard]] float GetRootkitScoreThreshold() const;

    // --- Statistics ---

    [[nodiscard]] uint32_t GetTotalScans()    const;
    [[nodiscard]] uint32_t GetTotalFindings() const;

private:
    DKOMDetector();
    ~DKOMDetector();

    DKOMDetector(const DKOMDetector&)            = delete;
    DKOMDetector& operator=(const DKOMDetector&) = delete;
    DKOMDetector(DKOMDetector&&)                 = delete;
    DKOMDetector& operator=(DKOMDetector&&)      = delete;

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
