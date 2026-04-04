/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ResultConverter.hpp — Converts Phantom internal types to ShadowStrike Core types
 *
 * Bridge between PhantomEmulator's analysis output and the ShadowStrike user-mode
 * agent's EmulationResult format.  The header uses forward declarations for both
 * type systems to avoid pulling in Windows SDK or WHP headers.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Forward declarations — Phantom types (defined in PhantomEmulator/)
// ---------------------------------------------------------------------------
namespace Phantom {
    enum class StopReason : uint8_t;
    enum class ThreatLevel : uint8_t;
    enum class EmulationTarget : uint8_t;
    enum class MalwareCategory : uint8_t;
    enum class PackerType : uint8_t;
    enum class IOCType : uint8_t;
    enum class MemoryFinding : uint8_t;
    enum class AlertSeverity : uint8_t;
    enum class BehaviorCategory : uint8_t;

    // WinAPI types — APICategory is Phantom's own enum
    enum class APICategory : uint8_t;
    enum class BehaviorFlag : uint32_t;

    struct APICallDetail;
    struct ThreatVerdict;
    struct BehaviorAlert;
    struct MITRETechnique;
    struct UnpackLayer;
    struct IOCEntry;
    struct IOCReport;
    struct MemoryFindingDetail;
    struct MemoryRegion;
    struct NetworkConnection;
    struct NetworkAlert;
    struct EvasionAttempt;
    struct EvasionSummary;
    struct EmulationConfig;
}

// ---------------------------------------------------------------------------
// Forward declarations — ShadowStrike types
// ---------------------------------------------------------------------------
namespace ShadowStrike::Core::Engine {
    struct EmulationResult;
    struct APICallRecord;
    struct DetectedTechnique;
    struct UnpackLayer;
    struct MemoryRegion;
    struct NetworkActivity;
    struct DroppedFile;
    struct RegistryModification;

    enum class EmulationState : uint8_t;
    enum class EmulationExitReason : uint8_t;
    enum class EmulationBackend : uint8_t;
    enum class EmulationArch : uint8_t;
    enum class APICategory : uint8_t;
    enum class APISeverity : uint8_t;
    enum class PackerType : uint16_t;
    enum class MemoryRegionType : uint8_t;
}

namespace Phantom::Integration {

// ============================================================================
// PhantomEmulationResult — aggregate of all Phantom analysis outputs
// ============================================================================
// This struct collects the outputs from every analysis module into a single
// object that Convert() can translate into ShadowStrike::Core::Engine types.

struct PhantomEmulationResult {
    // Core execution
    Phantom::StopReason        stopReason{};
    Phantom::EmulationTarget   target{};
    uint64_t                   instructionsExecuted = 0;
    uint64_t                   emulationTimeMs      = 0;
    size_t                     peakMemoryUsage      = 0;
    uint64_t                   contextSwitches      = 0;
    uint32_t                   exceptionsHandled    = 0;

    // Threat scoring
    Phantom::ThreatVerdict*           verdict       = nullptr;

    // API calls
    std::span<const Phantom::APICallDetail> apiCalls;

    // Behavior alerts
    std::span<const Phantom::BehaviorAlert> behaviorAlerts;

    // MITRE ATT&CK
    std::span<const Phantom::MITRETechnique> mitreTechniques;

    // Unpacking
    std::span<const Phantom::UnpackLayer> unpackLayers;
    std::span<const uint8_t>              unpackedPayload;
    std::string                           unpackedSha256;
    bool                                  unpackSuccessful = false;

    // IOCs
    const Phantom::IOCReport*             iocReport   = nullptr;

    // Memory forensics
    std::span<const Phantom::MemoryFindingDetail> memoryFindings;
    std::span<const Phantom::MemoryRegion>        memoryRegions;

    // Network
    std::span<const Phantom::NetworkConnection> networkConnections;
    std::span<const Phantom::NetworkAlert>      networkAlerts;

    // Evasion
    std::span<const Phantom::EvasionAttempt> evasionAttempts;
    const Phantom::EvasionSummary*           evasionSummary = nullptr;

    // YARA / signatures
    std::span<const std::string> yaraMatches;
    std::span<const std::string> memoryYaraMatches;
    std::span<const std::string> patternMatches;

    // Input metadata
    uint64_t    sessionId   = 0;
    std::string inputSha256;
    size_t      inputSize   = 0;
    std::string inputFileType;
};

// ============================================================================
// ResultConverter — stateless translator
// ============================================================================

class ResultConverter {
public:
    ResultConverter() = delete;

    [[nodiscard]] static ShadowStrike::Core::Engine::EmulationResult
    Convert(const PhantomEmulationResult& phantomResult) noexcept;

    [[nodiscard]] static ShadowStrike::Core::Engine::EmulationState
    ConvertStopReason(Phantom::StopReason reason) noexcept;

    [[nodiscard]] static ShadowStrike::Core::Engine::EmulationExitReason
    ConvertExitReason(Phantom::StopReason reason) noexcept;

    [[nodiscard]] static ShadowStrike::Core::Engine::APICallRecord
    ConvertAPICall(const Phantom::APICallDetail& call) noexcept;

    [[nodiscard]] static ShadowStrike::Core::Engine::PackerType
    ConvertPackerType(Phantom::PackerType packer) noexcept;

    [[nodiscard]] static ShadowStrike::Core::Engine::DetectedTechnique
    ConvertMITRE(const Phantom::MITRETechnique& tech) noexcept;

    [[nodiscard]] static ShadowStrike::Core::Engine::APICategory
    ConvertAPICategory(Phantom::APICategory cat) noexcept;

    [[nodiscard]] static ShadowStrike::Core::Engine::APISeverity
    ConvertAlertSeverity(Phantom::AlertSeverity sev) noexcept;

    [[nodiscard]] static ShadowStrike::Core::Engine::UnpackLayer
    ConvertUnpackLayer(const Phantom::UnpackLayer& layer) noexcept;

    [[nodiscard]] static ShadowStrike::Core::Engine::EmulationArch
    ConvertTarget(Phantom::EmulationTarget target) noexcept;

    [[nodiscard]] static std::string
    MalwareCategoryName(Phantom::MalwareCategory cat) noexcept;
};

} // namespace Phantom::Integration
