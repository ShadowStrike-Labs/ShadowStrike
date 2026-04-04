/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ThreatScorer.cpp — Aggregated threat scoring and malware classification
 *
 * Implements the full scoring pipeline that aggregates behavioral signals,
 * API sequence matches, memory forensics findings, and MITRE ATT&CK mappings
 * into a final threat verdict with malware category classification.
 *
 * Scoring Algorithm:
 *   rawScore = Σ (factor.weight × factor.score × factor.confidence)
 *   normalizedScore = min(100.0, rawScore × calibrationFactor)
 *
 * Thresholds:
 *   Clean:      score < 10
 *   Suspicious: 10 ≤ score < 35
 *   Likely:     35 ≤ score < 60
 *   Malicious:  60 ≤ score < 85
 *   Critical:   score ≥ 85
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "ThreatScorer.hpp"
#include "AnalysisTypes.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <numeric>
#include <shared_mutex>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace Phantom {

// ============================================================================
// Limits and Tuning Constants
// ============================================================================

static constexpr uint32_t kMaxScoringFactors     = 4096;
static constexpr uint32_t kMaxEvasionTechniques   = 256;
static constexpr uint32_t kMaxMITRETechniquesScored = 512;
static constexpr uint32_t kMaxReasonsInVerdict    = 64;

static constexpr float kCalibrationFactor         = 1.15f;

static constexpr float kThresholdClean            = 10.0f;
static constexpr float kThresholdSuspicious       = 35.0f;
static constexpr float kThresholdLikely           = 60.0f;
static constexpr float kThresholdMalicious        = 85.0f;

// Base weights by source and severity
static constexpr float kWeightBehaviorCritical    = 25.0f;
static constexpr float kWeightBehaviorHigh        = 15.0f;
static constexpr float kWeightBehaviorMedium      = 8.0f;
static constexpr float kWeightBehaviorLow         = 3.0f;

static constexpr float kWeightSequenceSev4        = 20.0f;
static constexpr float kWeightSequenceSev3        = 12.0f;
static constexpr float kWeightSequenceSev2        = 6.0f;
static constexpr float kWeightSequenceSev1        = 3.0f;

static constexpr float kWeightMemPEInjection      = 18.0f;
static constexpr float kWeightMemShellcode        = 15.0f;
static constexpr float kWeightMemROPChain         = 20.0f;
static constexpr float kWeightMemWXTransition     = 10.0f;
static constexpr float kWeightMemSelfModifying    = 10.0f;
static constexpr float kWeightMemHollowedProcess  = 18.0f;
static constexpr float kWeightMemHeapSpray        = 12.0f;
static constexpr float kWeightMemStackPivot       = 14.0f;
static constexpr float kWeightMemCodeCave         = 8.0f;
static constexpr float kWeightMemTrampoline       = 7.0f;
static constexpr float kWeightMemIATPatch         = 7.0f;
static constexpr float kWeightMemHighEntropy      = 6.0f;
static constexpr float kWeightMemSuspiciousString = 3.0f;

static constexpr float kWeightPacker              = 5.0f;
static constexpr float kWeightPackerAdvanced      = 8.0f;
static constexpr float kWeightEvasionBase         = 10.0f;
static constexpr float kWeightMITRETechnique      = 3.0f;

static constexpr size_t kCategoryCount = static_cast<size_t>(MalwareCategory::Count_);

// ============================================================================
// Category contribution table — maps BehaviorCategory → MalwareCategory weights
// ============================================================================

struct CategoryContribution {
    MalwareCategory target;
    float           fraction;
};

using ContribList = std::array<CategoryContribution, 5>;

struct BehaviorCategoryMapping {
    BehaviorCategory  behavior;
    ContribList       contributions;
    uint8_t           count;
};

// Sentinel value: no matching BehaviorCategory (used for flags that should not
// contribute to any malware-category bucket).
static constexpr auto kNoBehaviorCategory = static_cast<BehaviorCategory>(0xFF);

static constexpr BehaviorCategoryMapping kBehaviorCategoryMap[] = {
    { BehaviorCategory::ProcessInjection, {{
        { MalwareCategory::RAT,        0.30f },
        { MalwareCategory::Trojan,     0.25f },
        { MalwareCategory::APTImplant, 0.25f },
        { MalwareCategory::Backdoor,   0.20f },
        { MalwareCategory::Unknown,    0.00f },
    }}, 4 },
    { BehaviorCategory::ProcessHollowing, {{
        { MalwareCategory::Trojan,     0.30f },
        { MalwareCategory::APTImplant, 0.30f },
        { MalwareCategory::RAT,        0.20f },
        { MalwareCategory::Dropper,    0.20f },
        { MalwareCategory::Unknown,    0.00f },
    }}, 4 },
    { BehaviorCategory::DLLInjection, {{
        { MalwareCategory::RAT,        0.30f },
        { MalwareCategory::Trojan,     0.25f },
        { MalwareCategory::Backdoor,   0.25f },
        { MalwareCategory::APTImplant, 0.20f },
        { MalwareCategory::Unknown,    0.00f },
    }}, 4 },
    { BehaviorCategory::ReflectiveDLLLoad, {{
        { MalwareCategory::APTImplant, 0.35f },
        { MalwareCategory::Fileless,   0.25f },
        { MalwareCategory::Trojan,     0.20f },
        { MalwareCategory::Rootkit,    0.20f },
        { MalwareCategory::Unknown,    0.00f },
    }}, 4 },
    { BehaviorCategory::ShellcodeExecution, {{
        { MalwareCategory::Fileless,   0.45f },
        { MalwareCategory::APTImplant, 0.25f },
        { MalwareCategory::Trojan,     0.15f },
        { MalwareCategory::Rootkit,    0.15f },
        { MalwareCategory::Unknown,    0.00f },
    }}, 4 },
    { BehaviorCategory::Persistence, {{
        { MalwareCategory::Trojan,     0.30f },
        { MalwareCategory::Dropper,    0.25f },
        { MalwareCategory::Backdoor,   0.20f },
        { MalwareCategory::RAT,        0.15f },
        { MalwareCategory::Worm,       0.10f },
    }}, 5 },
    { BehaviorCategory::PrivilegeEscalation, {{
        { MalwareCategory::Rootkit,    0.30f },
        { MalwareCategory::APTImplant, 0.25f },
        { MalwareCategory::Exploit,    0.25f },
        { MalwareCategory::Trojan,     0.20f },
        { MalwareCategory::Unknown,    0.00f },
    }}, 4 },
    { BehaviorCategory::CredentialAccess, {{
        { MalwareCategory::InfoStealer,    0.35f },
        { MalwareCategory::BankingTrojan,  0.25f },
        { MalwareCategory::Spyware,        0.20f },
        { MalwareCategory::Keylogger,      0.10f },
        { MalwareCategory::APTImplant,     0.10f },
    }}, 5 },
    { BehaviorCategory::DefenseEvasion, {{
        { MalwareCategory::APTImplant, 0.35f },
        { MalwareCategory::Rootkit,    0.25f },
        { MalwareCategory::Trojan,     0.20f },
        { MalwareCategory::Fileless,   0.20f },
        { MalwareCategory::Unknown,    0.00f },
    }}, 4 },
    { BehaviorCategory::LateralMovement, {{
        { MalwareCategory::Worm,       0.30f },
        { MalwareCategory::APTImplant, 0.30f },
        { MalwareCategory::RAT,        0.20f },
        { MalwareCategory::Botnet,     0.20f },
        { MalwareCategory::Unknown,    0.00f },
    }}, 4 },
    { BehaviorCategory::DataExfiltration, {{
        { MalwareCategory::InfoStealer,   0.35f },
        { MalwareCategory::Spyware,       0.25f },
        { MalwareCategory::APTImplant,    0.20f },
        { MalwareCategory::BankingTrojan, 0.20f },
        { MalwareCategory::Unknown,       0.00f },
    }}, 4 },
    { BehaviorCategory::Ransomware, {{
        { MalwareCategory::Ransomware, 0.70f },
        { MalwareCategory::Wiper,      0.20f },
        { MalwareCategory::Trojan,     0.10f },
        { MalwareCategory::Unknown,    0.00f },
        { MalwareCategory::Unknown,    0.00f },
    }}, 3 },
    { BehaviorCategory::Downloader, {{
        { MalwareCategory::Dropper,    0.45f },
        { MalwareCategory::Downloader, 0.25f },
        { MalwareCategory::Trojan,     0.20f },
        { MalwareCategory::Worm,       0.10f },
        { MalwareCategory::Unknown,    0.00f },
    }}, 4 },
    { BehaviorCategory::Keylogger, {{
        { MalwareCategory::Keylogger,  0.45f },
        { MalwareCategory::Spyware,    0.30f },
        { MalwareCategory::InfoStealer,0.15f },
        { MalwareCategory::RAT,        0.10f },
        { MalwareCategory::Unknown,    0.00f },
    }}, 4 },
    { BehaviorCategory::ScreenCapture, {{
        { MalwareCategory::Spyware,    0.35f },
        { MalwareCategory::RAT,        0.30f },
        { MalwareCategory::InfoStealer,0.25f },
        { MalwareCategory::APTImplant, 0.10f },
        { MalwareCategory::Unknown,    0.00f },
    }}, 4 },
    { BehaviorCategory::Discovery, {{
        { MalwareCategory::Spyware,    0.30f },
        { MalwareCategory::APTImplant, 0.25f },
        { MalwareCategory::RAT,        0.25f },
        { MalwareCategory::InfoStealer,0.20f },
        { MalwareCategory::Unknown,    0.00f },
    }}, 4 },
    { BehaviorCategory::CommandAndControl, {{
        { MalwareCategory::RAT,        0.30f },
        { MalwareCategory::Backdoor,   0.25f },
        { MalwareCategory::Botnet,     0.25f },
        { MalwareCategory::APTImplant, 0.20f },
        { MalwareCategory::Unknown,    0.00f },
    }}, 4 },
    { BehaviorCategory::Execution, {{
        { MalwareCategory::Rootkit,    0.30f },
        { MalwareCategory::Trojan,     0.25f },
        { MalwareCategory::Backdoor,   0.25f },
        { MalwareCategory::APTImplant, 0.20f },
        { MalwareCategory::Unknown,    0.00f },
    }}, 4 },
    { BehaviorCategory::FileManipulation, {{
        { MalwareCategory::Wiper,      0.50f },
        { MalwareCategory::Ransomware, 0.30f },
        { MalwareCategory::Trojan,     0.20f },
        { MalwareCategory::Unknown,    0.00f },
        { MalwareCategory::Unknown,    0.00f },
    }}, 3 },
    { BehaviorCategory::AntiForensics, {{
        { MalwareCategory::APTImplant, 0.35f },
        { MalwareCategory::Rootkit,    0.25f },
        { MalwareCategory::Trojan,     0.20f },
        { MalwareCategory::Backdoor,   0.20f },
        { MalwareCategory::Unknown,    0.00f },
    }}, 4 },
};

static constexpr size_t kBehaviorCategoryMapSize =
    sizeof(kBehaviorCategoryMap) / sizeof(kBehaviorCategoryMap[0]);

// ============================================================================
// Helper: get readable name for MalwareCategory
// ============================================================================

static const char* CategoryToString(MalwareCategory cat) noexcept {
    switch (cat) {
        case MalwareCategory::Unknown:       return "Unknown";
        case MalwareCategory::Trojan:        return "Trojan";
        case MalwareCategory::Ransomware:    return "Ransomware";
        case MalwareCategory::Worm:          return "Worm";
        case MalwareCategory::Backdoor:      return "Backdoor";
        case MalwareCategory::RAT:           return "Remote Access Trojan";
        case MalwareCategory::Dropper:       return "Dropper";
        case MalwareCategory::Downloader:    return "Downloader";
        case MalwareCategory::Rootkit:       return "Rootkit";
        case MalwareCategory::Keylogger:     return "Keylogger";
        case MalwareCategory::Spyware:       return "Spyware";
        case MalwareCategory::Adware:        return "Adware";
        case MalwareCategory::CoinMiner:     return "Cryptocurrency Miner";
        case MalwareCategory::Wiper:         return "Wiper";
        case MalwareCategory::BankingTrojan: return "Banking Trojan";
        case MalwareCategory::InfoStealer:   return "Information Stealer";
        case MalwareCategory::Botnet:        return "Botnet Agent";
        case MalwareCategory::Exploit:       return "Exploit";
        case MalwareCategory::APTImplant:    return "APT Implant";
        case MalwareCategory::Fileless:      return "Fileless Malware";
        default:                             return "Unclassified";
    }
}

static const char* ThreatLevelToString(ThreatLevel level) noexcept {
    switch (level) {
        case ThreatLevel::Clean:      return "Clean";
        case ThreatLevel::Suspicious: return "Suspicious";
        case ThreatLevel::Likely:     return "Likely Malicious";
        case ThreatLevel::Malicious:  return "Malicious";
        case ThreatLevel::Critical:   return "Critical";
        default:                      return "Unknown";
    }
}

static const char* PackerToString(PackerType packer) noexcept {
    switch (packer) {
        case PackerType::Unknown:        return "Unknown Packer";
        case PackerType::UPX:            return "UPX";
        case PackerType::ASPack:         return "ASPack";
        case PackerType::PECompact:      return "PECompact";
        case PackerType::Themida:        return "Themida";
        case PackerType::VMProtect:      return "VMProtect";
        case PackerType::Armadillo:      return "Armadillo";
        case PackerType::MPRESS:         return "MPRESS";
        case PackerType::Petite:         return "Petite";
        case PackerType::FSG:            return "FSG";
        case PackerType::MEW:            return "MEW";
        case PackerType::NsPack:         return "NsPack";
        case PackerType::PEtite:         return "PEtite";
        case PackerType::Obsidium:       return "Obsidium";
        case PackerType::ExeCryptor:     return "ExeCryptor";
        case PackerType::ASProtect:      return "ASProtect";
        case PackerType::tElock:         return "tElock";
        case PackerType::PESpin:         return "PESpin";
        case PackerType::MoleBox:        return "MoleBox";
        case PackerType::BoxedApp:       return "BoxedApp";
        case PackerType::Enigma:         return "Enigma Protector";
        case PackerType::StarForce:      return "StarForce";
        case PackerType::SafeDisc:       return "SafeDisc";
        case PackerType::SecuROM:        return "SecuROM";
        case PackerType::CodeVirtualizer:return "Code Virtualizer";
        case PackerType::PackerCustom:   return "Custom Packer";
        case PackerType::DotNetObfuscator: return ".NET Obfuscator";
        case PackerType::AutoIt:         return "AutoIt";
        case PackerType::NSIS:           return "NSIS";
        case PackerType::InnoSetup:      return "InnoSetup";
        case PackerType::PyInstaller:    return "PyInstaller";
        default:                         return "Packer";
    }
}

// ============================================================================
// Helper: determine if packer is an advanced protector (higher suspicion)
// ============================================================================

static bool IsAdvancedPacker(PackerType packer) noexcept {
    switch (packer) {
        case PackerType::Themida:
        case PackerType::VMProtect:
        case PackerType::Enigma:
        case PackerType::Armadillo:
        case PackerType::ExeCryptor:
        case PackerType::Obsidium:
        case PackerType::ASProtect:
        case PackerType::CodeVirtualizer:
        case PackerType::StarForce:
            return true;
        default:
            return false;
    }
}

// ============================================================================
// Helper: Apply BehaviorCategory → MalwareCategory contributions
// ============================================================================

static void ApplyBehaviorContributions(
    BehaviorCategory behavior,
    float baseAmount,
    std::array<float, kCategoryCount>& categoryScores) noexcept
{
    for (size_t i = 0; i < kBehaviorCategoryMapSize; ++i) {
        if (kBehaviorCategoryMap[i].behavior == behavior) {
            const auto& mapping = kBehaviorCategoryMap[i];
            for (uint8_t c = 0; c < mapping.count; ++c) {
                auto idx = static_cast<size_t>(mapping.contributions[c].target);
                if (idx < kCategoryCount) {
                    categoryScores[idx] += baseAmount * mapping.contributions[c].fraction;
                }
            }
            return;
        }
    }
}

// ============================================================================
// ThreatScorer::Impl
// ============================================================================

struct ThreatScorer::Impl {
    const EmulationConfig& config;

    mutable std::shared_mutex mutex;

    std::vector<ScoringFactor> factors;
    std::array<float, kCategoryCount> categoryScores{};

    BehaviorFlag accumulatedFlags = BehaviorFlag::None;

    uint32_t mitreTechniqueCount = 0;
    uint32_t evasionCount        = 0;
    uint32_t behaviorAlertCount  = 0;
    uint32_t sequenceMatchCount  = 0;
    uint32_t memoryFindingCount  = 0;

    bool      packerDetected     = false;
    PackerType detectedPacker    = PackerType::Unknown;

    std::unordered_set<std::string> evasionTechniques;
    std::unordered_set<std::string> mitreTechniques;

    float maxAlertSeverityScore  = 0.0f;
    float maxSequenceSeverity    = 0.0f;
    float maxMemoryFindingScore  = 0.0f;

    explicit Impl(const EmulationConfig& cfg) noexcept
        : config(cfg)
    {
        factors.reserve(256);
        evasionTechniques.reserve(64);
        mitreTechniques.reserve(128);
    }

    void AddFactorInternal(ScoringFactor&& factor) noexcept {
        if (factors.size() >= kMaxScoringFactors) return;
        factors.push_back(std::move(factor));
    }

    void ContributeToCategory(MalwareCategory cat, float amount) noexcept {
        auto idx = static_cast<size_t>(cat);
        if (idx < kCategoryCount) {
            categoryScores[idx] += amount;
        }
    }

    float ComputeRawScore() const noexcept {
        float raw = 0.0f;
        for (const auto& f : factors) {
            raw += f.weight * f.score * f.confidence;
        }
        return raw;
    }

    float ComputeNormalizedScore() const noexcept {
        float raw = ComputeRawScore();
        float normalized = raw * kCalibrationFactor;

        // Apply synergy bonuses for multi-stage attacks
        float synergy = ComputeSynergyBonus();
        normalized += synergy;

        return std::min(100.0f, std::max(0.0f, normalized));
    }

    float ComputeSynergyBonus() const noexcept {
        float bonus = 0.0f;

        // Synergy: injection + persistence = established implant
        if (HasFlag(accumulatedFlags, BehaviorFlag::ProcessInjection) &&
            HasFlag(accumulatedFlags, BehaviorFlag::RegistryPersistence)) {
            bonus += 5.0f;
        }

        // Synergy: network C2 + injection = active RAT
        if (HasFlag(accumulatedFlags, BehaviorFlag::NetworkC2) &&
            HasFlag(accumulatedFlags, BehaviorFlag::ProcessInjection)) {
            bonus += 5.0f;
        }

        // Synergy: credential access + network = data exfiltration risk
        if (HasFlag(accumulatedFlags, BehaviorFlag::CredentialAccess) &&
            HasFlag(accumulatedFlags, BehaviorFlag::NetworkC2)) {
            bonus += 4.0f;
        }

        // Synergy: defense evasion + anti-analysis = sophisticated threat
        if (HasFlag(accumulatedFlags, BehaviorFlag::DefenseEvasion) &&
            HasFlag(accumulatedFlags, BehaviorFlag::AntiAnalysis)) {
            bonus += 3.0f;
        }

        // Synergy: file drop + persistence + network = dropper chain
        if (HasFlag(accumulatedFlags, BehaviorFlag::FileDropped) &&
            HasFlag(accumulatedFlags, BehaviorFlag::RegistryPersistence) &&
            HasFlag(accumulatedFlags, BehaviorFlag::NetworkC2)) {
            bonus += 6.0f;
        }

        // Synergy: process hollowing + network = advanced implant
        if (HasFlag(accumulatedFlags, BehaviorFlag::ProcessHollowing) &&
            HasFlag(accumulatedFlags, BehaviorFlag::NetworkC2)) {
            bonus += 5.0f;
        }

        // Synergy: DLL injection + credential access = credential stealer
        if (HasFlag(accumulatedFlags, BehaviorFlag::DLLInjection) &&
            HasFlag(accumulatedFlags, BehaviorFlag::CredentialAccess)) {
            bonus += 4.0f;
        }

        // Synergy: keylogging + screen capture = full surveillance
        if (HasFlag(accumulatedFlags, BehaviorFlag::Keylogging) &&
            HasFlag(accumulatedFlags, BehaviorFlag::ScreenCapture)) {
            bonus += 4.0f;
        }

        // Synergy: service manipulation + privilege escalation = rootkit behavior
        if (HasFlag(accumulatedFlags, BehaviorFlag::ServiceManipulation) &&
            HasFlag(accumulatedFlags, BehaviorFlag::PrivilegeEscalation)) {
            bonus += 4.0f;
        }

        // Synergy: WMI + PowerShell = fileless attack
        if (HasFlag(accumulatedFlags, BehaviorFlag::WMIExecution) &&
            HasFlag(accumulatedFlags, BehaviorFlag::PowershellExecution)) {
            bonus += 5.0f;
        }

        // Multi-technique breadth bonus
        uint32_t flagCount = 0;
        for (uint32_t bit = 0; bit < 19; ++bit) {
            if (static_cast<uint32_t>(accumulatedFlags) & (1u << bit)) {
                ++flagCount;
            }
        }
        if (flagCount >= 5) bonus += 3.0f;
        if (flagCount >= 8) bonus += 5.0f;
        if (flagCount >= 12) bonus += 8.0f;

        // MITRE breadth bonus
        if (mitreTechniqueCount >= 5) bonus += 2.0f;
        if (mitreTechniqueCount >= 10) bonus += 3.0f;
        if (mitreTechniqueCount >= 20) bonus += 5.0f;

        return std::min(20.0f, bonus);
    }

    ThreatLevel ScoreToLevel(float score) const noexcept {
        if (score < kThresholdClean)      return ThreatLevel::Clean;
        if (score < kThresholdSuspicious) return ThreatLevel::Suspicious;
        if (score < kThresholdLikely)     return ThreatLevel::Likely;
        if (score < kThresholdMalicious)  return ThreatLevel::Malicious;
        return ThreatLevel::Critical;
    }

    float ComputeOverallConfidence() const noexcept {
        if (factors.empty()) return 0.0f;

        float totalWeightedConf = 0.0f;
        float totalWeight = 0.0f;

        for (const auto& f : factors) {
            float effectiveWeight = f.weight * f.score;
            totalWeightedConf += f.confidence * effectiveWeight;
            totalWeight += effectiveWeight;
        }

        if (totalWeight <= 0.0f) return 0.0f;
        return std::min(1.0f, totalWeightedConf / totalWeight);
    }

    std::pair<MalwareCategory, MalwareCategory> GetTopCategories() const noexcept {
        MalwareCategory primary = MalwareCategory::Unknown;
        MalwareCategory secondary = MalwareCategory::Unknown;
        float topScore = 0.0f;
        float secondScore = 0.0f;

        for (size_t i = 1; i < kCategoryCount; ++i) {
            if (categoryScores[i] > topScore) {
                secondary = primary;
                secondScore = topScore;
                primary = static_cast<MalwareCategory>(i);
                topScore = categoryScores[i];
            } else if (categoryScores[i] > secondScore) {
                secondary = static_cast<MalwareCategory>(i);
                secondScore = categoryScores[i];
            }
        }

        return { primary, secondary };
    }

    std::string BuildSummary(ThreatLevel level, float score, float confidence,
                             MalwareCategory primary, MalwareCategory secondary) const noexcept {
        std::ostringstream ss;

        ss << "Verdict: " << ThreatLevelToString(level)
           << " (score=" << static_cast<int>(score)
           << "/100, confidence=" << static_cast<int>(confidence * 100.0f) << "%). ";

        if (level == ThreatLevel::Clean) {
            ss << "No significant malicious indicators detected.";
            return ss.str();
        }

        if (primary != MalwareCategory::Unknown) {
            ss << "Primary classification: " << CategoryToString(primary) << ". ";
        }
        if (secondary != MalwareCategory::Unknown &&
            secondary != primary) {
            ss << "Secondary classification: " << CategoryToString(secondary) << ". ";
        }

        // Summarize key indicators
        if (behaviorAlertCount > 0) {
            ss << behaviorAlertCount << " behavior alert(s)";
            if (sequenceMatchCount > 0 || memoryFindingCount > 0) ss << ", ";
            else ss << ". ";
        }
        if (sequenceMatchCount > 0) {
            ss << sequenceMatchCount << " API sequence match(es)";
            if (memoryFindingCount > 0) ss << ", ";
            else ss << ". ";
        }
        if (memoryFindingCount > 0) {
            ss << memoryFindingCount << " memory finding(s). ";
        }
        if (packerDetected) {
            ss << "Packed with " << PackerToString(detectedPacker) << ". ";
        }
        if (evasionCount > 0) {
            ss << evasionCount << " evasion technique(s) detected. ";
        }
        if (mitreTechniqueCount > 0) {
            ss << mitreTechniqueCount << " MITRE ATT&CK technique(s) mapped. ";
        }

        return ss.str();
    }

    std::vector<std::string> BuildReasons() const noexcept {
        std::vector<std::string> reasons;
        reasons.reserve(std::min(static_cast<size_t>(kMaxReasonsInVerdict), factors.size()));

        // Sort factors by effective contribution (weight * score * confidence) descending
        struct RankedFactor {
            size_t index;
            float  effective;
        };
        std::vector<RankedFactor> ranked;
        ranked.reserve(factors.size());
        for (size_t i = 0; i < factors.size(); ++i) {
            float eff = factors[i].weight * factors[i].score * factors[i].confidence;
            if (eff > 0.0f) {
                ranked.push_back({ i, eff });
            }
        }

        std::sort(ranked.begin(), ranked.end(),
                  [](const RankedFactor& a, const RankedFactor& b) {
                      return a.effective > b.effective;
                  });

        for (size_t i = 0; i < ranked.size() && reasons.size() < kMaxReasonsInVerdict; ++i) {
            const auto& f = factors[ranked[i].index];
            std::ostringstream ss;
            ss << "[" << f.source << "] " << f.description
               << " (weight=" << static_cast<int>(f.weight)
               << ", conf=" << static_cast<int>(f.confidence * 100.0f) << "%)";
            reasons.push_back(ss.str());
        }

        return reasons;
    }
};

// ============================================================================
// Constructor / Destructor
// ============================================================================

ThreatScorer::ThreatScorer(const EmulationConfig& config) noexcept
    : m_impl(std::make_unique<Impl>(config))
{
}

ThreatScorer::~ThreatScorer() noexcept = default;

// ============================================================================
// AddBehaviorAlert
// ============================================================================

void ThreatScorer::AddBehaviorAlert(const BehaviorAlert& alert) noexcept {
    std::unique_lock lock(m_impl->mutex);

    float weight = kWeightBehaviorLow;
    switch (alert.severity) {
        case AlertSeverity::Critical: weight = kWeightBehaviorCritical; break;
        case AlertSeverity::High:     weight = kWeightBehaviorHigh;     break;
        case AlertSeverity::Medium:   weight = kWeightBehaviorMedium;   break;
        case AlertSeverity::Low:      weight = kWeightBehaviorLow;      break;
        case AlertSeverity::Info:     weight = 1.0f;                    break;
    }

    float confidence = std::clamp(alert.confidence, 0.0f, 1.0f);
    float score = 1.0f;

    ScoringFactor factor;
    factor.source      = "BehaviorMonitor";
    factor.description = alert.description;
    factor.weight      = weight;
    factor.score       = score;
    factor.confidence  = confidence;

    m_impl->AddFactorInternal(std::move(factor));
    m_impl->behaviorAlertCount++;

    if (weight > m_impl->maxAlertSeverityScore) {
        m_impl->maxAlertSeverityScore = weight;
    }

    // Contribute to malware categories
    float categoryBase = weight * confidence;
    ApplyBehaviorContributions(alert.category, categoryBase, m_impl->categoryScores);
}

// ============================================================================
// AddSequenceMatch
// ============================================================================

void ThreatScorer::AddSequenceMatch(const SequenceMatch& match) noexcept {
    std::unique_lock lock(m_impl->mutex);

    float weight = kWeightSequenceSev1;
    switch (match.severity) {
        case 4:  weight = kWeightSequenceSev4; break;
        case 3:  weight = kWeightSequenceSev3; break;
        case 2:  weight = kWeightSequenceSev2; break;
        default: weight = kWeightSequenceSev1; break;
    }

    float confidence = std::clamp(match.confidence, 0.0f, 1.0f);

    ScoringFactor factor;
    factor.source      = "APISequence";
    factor.description = match.patternName ? match.patternName : "Unknown pattern";
    factor.weight     = weight;
    factor.score      = 1.0f;
    factor.confidence = confidence;

    m_impl->AddFactorInternal(std::move(factor));
    m_impl->sequenceMatchCount++;

    if (weight > m_impl->maxSequenceSeverity) {
        m_impl->maxSequenceSeverity = weight;
    }

    // Infer category contribution from MITRE technique ID if available
    float categoryBase = weight * confidence;
    if (match.mitreId && match.mitreId[0] != '\0') {
        std::string_view mid(match.mitreId);
        BehaviorCategory inferred = BehaviorCategory::Execution;
        if (mid.starts_with("T1055"))      inferred = BehaviorCategory::ProcessInjection;
        else if (mid.starts_with("T1059")) inferred = BehaviorCategory::Execution;
        else if (mid.starts_with("T1547") || mid.starts_with("T1543") ||
                 mid.starts_with("T1053") || mid.starts_with("T1546"))
                                           inferred = BehaviorCategory::Persistence;
        else if (mid.starts_with("T1134") || mid == "T1068" || mid.starts_with("T1548"))
                                           inferred = BehaviorCategory::PrivilegeEscalation;
        else if (mid.starts_with("T1003") || mid.starts_with("T1552") ||
                 mid.starts_with("T1555") || mid.starts_with("T1056"))
                                           inferred = BehaviorCategory::CredentialAccess;
        else if (mid.starts_with("T1071") || mid.starts_with("T1573") ||
                 mid == "T1095" || mid == "T1105")
                                           inferred = BehaviorCategory::CommandAndControl;
        else if (mid == "T1486")           inferred = BehaviorCategory::Ransomware;
        else if (mid.starts_with("T1041") || mid.starts_with("T1048") ||
                 mid.starts_with("T1567"))
                                           inferred = BehaviorCategory::DataExfiltration;
        else if (mid.starts_with("T1027") || mid.starts_with("T1070") ||
                 mid == "T1140" || mid.starts_with("T1562") ||
                 mid.starts_with("T1497"))
                                           inferred = BehaviorCategory::DefenseEvasion;
        else if (mid.starts_with("T1021") || mid == "T1570")
                                           inferred = BehaviorCategory::LateralMovement;
        ApplyBehaviorContributions(inferred, categoryBase, m_impl->categoryScores);
    }
}

// ============================================================================
// AddMemoryFinding
// ============================================================================

void ThreatScorer::AddMemoryFinding(const MemoryFindingDetail& finding) noexcept {
    std::unique_lock lock(m_impl->mutex);

    float weight = 0.0f;
    const char* findingName = "Memory anomaly";

    switch (finding.type) {
        // --- PE injection group ---
        case MemoryFinding::PEHeaderInMemory:
        case MemoryFinding::PEDOSStub:
        case MemoryFinding::PEImportTable:
        case MemoryFinding::PEExportTable:
        case MemoryFinding::ReflectiveDLLStub:
            weight = kWeightMemPEInjection;
            findingName = "PE injection detected in memory";
            m_impl->ContributeToCategory(MalwareCategory::RAT, weight * 0.3f);
            m_impl->ContributeToCategory(MalwareCategory::Trojan, weight * 0.3f);
            m_impl->ContributeToCategory(MalwareCategory::APTImplant, weight * 0.4f);
            break;

        // --- Shellcode group ---
        case MemoryFinding::ShellcodeNopSled:
        case MemoryFinding::ShellcodeDecoderStub:
        case MemoryFinding::ShellcodeEggHunter:
        case MemoryFinding::ShellcodeEncodedPayload:
        case MemoryFinding::StackShellcode:
            weight = kWeightMemShellcode;
            findingName = "Shellcode detected in memory";
            m_impl->ContributeToCategory(MalwareCategory::Exploit, weight * 0.3f);
            m_impl->ContributeToCategory(MalwareCategory::Backdoor, weight * 0.25f);
            m_impl->ContributeToCategory(MalwareCategory::APTImplant, weight * 0.25f);
            m_impl->ContributeToCategory(MalwareCategory::Fileless, weight * 0.2f);
            break;

        // --- ROP chain ---
        case MemoryFinding::ROPGadgetChain:
            weight = kWeightMemROPChain;
            findingName = "ROP chain detected";
            m_impl->ContributeToCategory(MalwareCategory::Exploit, weight * 0.5f);
            m_impl->ContributeToCategory(MalwareCategory::APTImplant, weight * 0.3f);
            m_impl->ContributeToCategory(MalwareCategory::Rootkit, weight * 0.2f);
            break;

        // --- Write-then-execute and self-modifying code ---
        case MemoryFinding::WriteExecuteTransition:
            weight = kWeightMemWXTransition;
            findingName = "Write-then-execute memory transition";
            m_impl->ContributeToCategory(MalwareCategory::Trojan, weight * 0.3f);
            m_impl->ContributeToCategory(MalwareCategory::Fileless, weight * 0.35f);
            m_impl->ContributeToCategory(MalwareCategory::APTImplant, weight * 0.35f);
            break;

        case MemoryFinding::SelfModifyingCode:
            weight = kWeightMemSelfModifying;
            findingName = "Self-modifying code detected";
            m_impl->ContributeToCategory(MalwareCategory::Trojan, weight * 0.3f);
            m_impl->ContributeToCategory(MalwareCategory::APTImplant, weight * 0.35f);
            m_impl->ContributeToCategory(MalwareCategory::Rootkit, weight * 0.35f);
            break;

        // --- Process hollowing ---
        case MemoryFinding::HollowedProcess:
            weight = kWeightMemHollowedProcess;
            findingName = "Process hollowing detected";
            m_impl->ContributeToCategory(MalwareCategory::Trojan, weight * 0.3f);
            m_impl->ContributeToCategory(MalwareCategory::APTImplant, weight * 0.3f);
            m_impl->ContributeToCategory(MalwareCategory::RAT, weight * 0.2f);
            m_impl->ContributeToCategory(MalwareCategory::Dropper, weight * 0.2f);
            break;

        // --- Heap spray ---
        case MemoryFinding::HeapSprayPattern:
        case MemoryFinding::HeapSprayNopRun:
            weight = kWeightMemHeapSpray;
            findingName = "Heap spray detected";
            m_impl->ContributeToCategory(MalwareCategory::Exploit, weight * 0.7f);
            m_impl->ContributeToCategory(MalwareCategory::Trojan, weight * 0.3f);
            break;

        // --- Stack pivot ---
        case MemoryFinding::StackPivotDetected:
            weight = kWeightMemStackPivot;
            findingName = "Stack pivot detected";
            m_impl->ContributeToCategory(MalwareCategory::Exploit, weight * 0.5f);
            m_impl->ContributeToCategory(MalwareCategory::Rootkit, weight * 0.3f);
            m_impl->ContributeToCategory(MalwareCategory::APTImplant, weight * 0.2f);
            break;

        // --- Code cave ---
        case MemoryFinding::CodeCaveUsed:
            weight = kWeightMemCodeCave;
            findingName = "Code cave injection detected";
            m_impl->ContributeToCategory(MalwareCategory::Trojan, weight * 0.3f);
            m_impl->ContributeToCategory(MalwareCategory::APTImplant, weight * 0.35f);
            m_impl->ContributeToCategory(MalwareCategory::Rootkit, weight * 0.35f);
            break;

        // --- Trampoline / IAT patching ---
        case MemoryFinding::TrampolineCode:
            weight = kWeightMemTrampoline;
            findingName = "Function trampoline/hook detected";
            m_impl->ContributeToCategory(MalwareCategory::Rootkit, weight * 0.4f);
            m_impl->ContributeToCategory(MalwareCategory::APTImplant, weight * 0.3f);
            m_impl->ContributeToCategory(MalwareCategory::Trojan, weight * 0.3f);
            break;

        case MemoryFinding::IATPatchDetected:
            weight = kWeightMemIATPatch;
            findingName = "IAT patch detected";
            m_impl->ContributeToCategory(MalwareCategory::Rootkit, weight * 0.4f);
            m_impl->ContributeToCategory(MalwareCategory::APTImplant, weight * 0.3f);
            m_impl->ContributeToCategory(MalwareCategory::Trojan, weight * 0.3f);
            break;

        // --- High-entropy / encoded regions (moderate weight) ---
        case MemoryFinding::HighEntropyRegion:
        case MemoryFinding::XOREncodedBlock:
        case MemoryFinding::Base64EncodedBlock:
            weight = kWeightMemHighEntropy;
            findingName = "Encoded or high-entropy region detected";
            m_impl->ContributeToCategory(MalwareCategory::Trojan, weight * 0.4f);
            m_impl->ContributeToCategory(MalwareCategory::APTImplant, weight * 0.3f);
            m_impl->ContributeToCategory(MalwareCategory::Dropper, weight * 0.3f);
            break;

        // --- Suspicious string table (low weight) ---
        case MemoryFinding::SuspiciousStringTable:
            weight = kWeightMemSuspiciousString;
            findingName = "Suspicious string table detected";
            m_impl->ContributeToCategory(MalwareCategory::Trojan, weight * 0.5f);
            m_impl->ContributeToCategory(MalwareCategory::Spyware, weight * 0.5f);
            break;

        default:
            return;
    }

    float confidence = std::clamp(finding.confidence, 0.0f, 1.0f);

    ScoringFactor factor;
    factor.source      = "MemoryForensics";
    factor.description = findingName;
    if (!finding.description.empty()) {
        factor.description += " — " + finding.description;
    }
    factor.weight     = weight;
    factor.score      = 1.0f;
    factor.confidence = confidence;

    m_impl->AddFactorInternal(std::move(factor));
    m_impl->memoryFindingCount++;

    if (weight > m_impl->maxMemoryFindingScore) {
        m_impl->maxMemoryFindingScore = weight;
    }
}

// ============================================================================
// AddBehaviorFlags — process each flag individually for category contributions
// ============================================================================

void ThreatScorer::AddBehaviorFlags(BehaviorFlag flags) noexcept {
    std::unique_lock lock(m_impl->mutex);

    BehaviorFlag newFlags = static_cast<BehaviorFlag>(
        static_cast<uint32_t>(flags) &
        ~static_cast<uint32_t>(m_impl->accumulatedFlags));

    if (newFlags == BehaviorFlag::None) return;

    m_impl->accumulatedFlags = m_impl->accumulatedFlags | flags;

    // Each flag contributes a scoring factor and category weights
    struct FlagMapping {
        BehaviorFlag     flag;
        const char*      name;
        float            weight;
        BehaviorCategory category;
    };

    static constexpr FlagMapping kFlagMappings[] = {
        { BehaviorFlag::FileDropped,          "File dropped to disk",
          4.0f, BehaviorCategory::Downloader },
        { BehaviorFlag::RegistryPersistence,  "Registry persistence mechanism",
          8.0f, BehaviorCategory::Persistence },
        { BehaviorFlag::ProcessInjection,     "Process injection detected",
          12.0f, BehaviorCategory::ProcessInjection },
        { BehaviorFlag::RemoteThreadCreation, "Remote thread created in another process",
          10.0f, BehaviorCategory::ProcessInjection },
        { BehaviorFlag::MemoryManipulation,   "Suspicious memory manipulation",
          6.0f, BehaviorCategory::DefenseEvasion },
        { BehaviorFlag::NetworkC2,            "Network command-and-control communication",
          10.0f, BehaviorCategory::CommandAndControl },
        { BehaviorFlag::AntiAnalysis,         "Anti-analysis technique detected",
          5.0f, BehaviorCategory::AntiForensics },
        { BehaviorFlag::PrivilegeEscalation,  "Privilege escalation attempt",
          10.0f, BehaviorCategory::PrivilegeEscalation },
        { BehaviorFlag::CredentialAccess,     "Credential access detected",
          12.0f, BehaviorCategory::CredentialAccess },
        { BehaviorFlag::DefenseEvasion,       "Defense evasion technique",
          7.0f, BehaviorCategory::DefenseEvasion },
        { BehaviorFlag::CodeInjection,        "Code injection into process memory",
          12.0f, BehaviorCategory::ProcessInjection },
        { BehaviorFlag::ProcessHollowing,     "Process hollowing detected",
          14.0f, BehaviorCategory::ProcessHollowing },
        { BehaviorFlag::DLLInjection,         "DLL injection detected",
          12.0f, BehaviorCategory::DLLInjection },
        { BehaviorFlag::Keylogging,           "Keylogging activity detected",
          10.0f, BehaviorCategory::Keylogger },
        { BehaviorFlag::ScreenCapture,        "Screen capture detected",
          8.0f, BehaviorCategory::ScreenCapture },
        { BehaviorFlag::ServiceManipulation,  "Windows service manipulation",
          8.0f, BehaviorCategory::Execution },
        { BehaviorFlag::WMIExecution,         "WMI-based execution",
          7.0f, BehaviorCategory::Execution },
        { BehaviorFlag::PowershellExecution,  "PowerShell execution detected",
          6.0f, BehaviorCategory::Execution },
        { BehaviorFlag::SuspiciousAPI,        "Suspicious API usage pattern",
          4.0f, kNoBehaviorCategory },
    };

    for (const auto& mapping : kFlagMappings) {
        if (HasFlag(newFlags, mapping.flag)) {
            ScoringFactor factor;
            factor.source      = "BehaviorFlags";
            factor.description = mapping.name;
            factor.weight      = mapping.weight;
            factor.score       = 1.0f;
            factor.confidence  = 0.85f;

            m_impl->AddFactorInternal(std::move(factor));

            // Category contribution
            if (mapping.category != kNoBehaviorCategory) {
                ApplyBehaviorContributions(mapping.category,
                                          mapping.weight * 0.85f,
                                          m_impl->categoryScores);
            }
        }
    }
}

// ============================================================================
// AddMITRETechnique
// ============================================================================

void ThreatScorer::AddMITRETechnique(const char* techniqueId, float confidence) noexcept {
    if (!techniqueId) return;

    std::unique_lock lock(m_impl->mutex);

    if (m_impl->mitreTechniques.size() >= kMaxMITRETechniquesScored) return;

    std::string id(techniqueId);
    auto [it, inserted] = m_impl->mitreTechniques.insert(id);
    if (!inserted) return; // already counted

    confidence = std::clamp(confidence, 0.0f, 1.0f);
    m_impl->mitreTechniqueCount++;

    ScoringFactor factor;
    factor.source      = "MITREMapping";
    factor.description = "MITRE ATT&CK technique " + id;
    factor.weight      = kWeightMITRETechnique;
    factor.score       = 1.0f;
    factor.confidence  = confidence;

    m_impl->AddFactorInternal(std::move(factor));

    // Category contributions based on technique ID prefix
    float catBase = kWeightMITRETechnique * confidence;

    // Map technique IDs to categories heuristically
    if (id.starts_with("T1055")) {
        // Process injection techniques
        m_impl->ContributeToCategory(MalwareCategory::RAT, catBase * 0.3f);
        m_impl->ContributeToCategory(MalwareCategory::APTImplant, catBase * 0.3f);
        m_impl->ContributeToCategory(MalwareCategory::Trojan, catBase * 0.4f);
    } else if (id.starts_with("T1059")) {
        // Command and scripting interpreters
        m_impl->ContributeToCategory(MalwareCategory::Fileless, catBase * 0.3f);
        m_impl->ContributeToCategory(MalwareCategory::APTImplant, catBase * 0.3f);
        m_impl->ContributeToCategory(MalwareCategory::Trojan, catBase * 0.4f);
    } else if (id.starts_with("T1547") || id.starts_with("T1543") ||
               id.starts_with("T1053") || id.starts_with("T1546") ||
               id == "T1197" || id.starts_with("T1505")) {
        // Persistence techniques
        m_impl->ContributeToCategory(MalwareCategory::Trojan, catBase * 0.3f);
        m_impl->ContributeToCategory(MalwareCategory::Backdoor, catBase * 0.3f);
        m_impl->ContributeToCategory(MalwareCategory::RAT, catBase * 0.2f);
        m_impl->ContributeToCategory(MalwareCategory::Dropper, catBase * 0.2f);
    } else if (id.starts_with("T1134") || id == "T1068" || id.starts_with("T1548")) {
        // Privilege escalation
        m_impl->ContributeToCategory(MalwareCategory::Rootkit, catBase * 0.3f);
        m_impl->ContributeToCategory(MalwareCategory::APTImplant, catBase * 0.3f);
        m_impl->ContributeToCategory(MalwareCategory::Exploit, catBase * 0.4f);
    } else if (id.starts_with("T1003") || id.starts_with("T1552") ||
               id.starts_with("T1555") || id.starts_with("T1056")) {
        // Credential access
        m_impl->ContributeToCategory(MalwareCategory::InfoStealer, catBase * 0.4f);
        m_impl->ContributeToCategory(MalwareCategory::BankingTrojan, catBase * 0.3f);
        m_impl->ContributeToCategory(MalwareCategory::Spyware, catBase * 0.3f);
    } else if (id.starts_with("T1071") || id.starts_with("T1573") ||
               id == "T1095" || id == "T1105" || id.starts_with("T1132") ||
               id == "T1572" || id == "T1090") {
        // C2 techniques
        m_impl->ContributeToCategory(MalwareCategory::RAT, catBase * 0.3f);
        m_impl->ContributeToCategory(MalwareCategory::Backdoor, catBase * 0.3f);
        m_impl->ContributeToCategory(MalwareCategory::Botnet, catBase * 0.2f);
        m_impl->ContributeToCategory(MalwareCategory::APTImplant, catBase * 0.2f);
    } else if (id == "T1486") {
        // Data encrypted for impact
        m_impl->ContributeToCategory(MalwareCategory::Ransomware, catBase * 0.8f);
        m_impl->ContributeToCategory(MalwareCategory::Wiper, catBase * 0.2f);
    } else if (id == "T1485" || id.starts_with("T1561")) {
        // Data destruction / disk wipe
        m_impl->ContributeToCategory(MalwareCategory::Wiper, catBase * 0.6f);
        m_impl->ContributeToCategory(MalwareCategory::Ransomware, catBase * 0.4f);
    } else if (id == "T1490" || id == "T1489") {
        // Inhibit recovery / service stop
        m_impl->ContributeToCategory(MalwareCategory::Ransomware, catBase * 0.5f);
        m_impl->ContributeToCategory(MalwareCategory::Wiper, catBase * 0.5f);
    } else if (id.starts_with("T1041") || id.starts_with("T1048") ||
               id.starts_with("T1567")) {
        // Exfiltration
        m_impl->ContributeToCategory(MalwareCategory::InfoStealer, catBase * 0.4f);
        m_impl->ContributeToCategory(MalwareCategory::Spyware, catBase * 0.3f);
        m_impl->ContributeToCategory(MalwareCategory::APTImplant, catBase * 0.3f);
    } else if (id.starts_with("T1027") || id.starts_with("T1070") ||
               id == "T1140" || id.starts_with("T1562") ||
               id.starts_with("T1497") || id.starts_with("T1036") ||
               id.starts_with("T1218") || id == "T1220") {
        // Defense evasion
        m_impl->ContributeToCategory(MalwareCategory::APTImplant, catBase * 0.3f);
        m_impl->ContributeToCategory(MalwareCategory::Rootkit, catBase * 0.3f);
        m_impl->ContributeToCategory(MalwareCategory::Trojan, catBase * 0.4f);
    } else if (id.starts_with("T1021") || id == "T1570") {
        // Lateral movement
        m_impl->ContributeToCategory(MalwareCategory::Worm, catBase * 0.3f);
        m_impl->ContributeToCategory(MalwareCategory::APTImplant, catBase * 0.4f);
        m_impl->ContributeToCategory(MalwareCategory::RAT, catBase * 0.3f);
    } else if (id == "T1113" || id == "T1115" || id == "T1005" ||
               id == "T1039" || id == "T1119") {
        // Collection
        m_impl->ContributeToCategory(MalwareCategory::Spyware, catBase * 0.3f);
        m_impl->ContributeToCategory(MalwareCategory::InfoStealer, catBase * 0.3f);
        m_impl->ContributeToCategory(MalwareCategory::RAT, catBase * 0.2f);
        m_impl->ContributeToCategory(MalwareCategory::APTImplant, catBase * 0.2f);
    } else {
        // Discovery or other — general-purpose threat
        m_impl->ContributeToCategory(MalwareCategory::Trojan, catBase * 0.5f);
        m_impl->ContributeToCategory(MalwareCategory::APTImplant, catBase * 0.5f);
    }
}

// ============================================================================
// AddPackerDetection
// ============================================================================

void ThreatScorer::AddPackerDetection(PackerType packer) noexcept {
    std::unique_lock lock(m_impl->mutex);

    if (m_impl->packerDetected) return; // only score first detection

    m_impl->packerDetected = true;
    m_impl->detectedPacker = packer;

    bool advanced = IsAdvancedPacker(packer);
    float weight = advanced ? kWeightPackerAdvanced : kWeightPacker;

    ScoringFactor factor;
    factor.source      = "PackerDetection";
    factor.description = std::string("Packed with ") + PackerToString(packer);
    factor.weight      = weight;
    factor.score       = 1.0f;
    factor.confidence  = 0.90f;

    m_impl->AddFactorInternal(std::move(factor));

    // Packing doesn't strongly indicate a specific category, but advanced
    // packers lean toward sophisticated threats
    float catBase = weight * 0.9f;
    if (advanced) {
        m_impl->ContributeToCategory(MalwareCategory::APTImplant, catBase * 0.3f);
        m_impl->ContributeToCategory(MalwareCategory::Rootkit, catBase * 0.2f);
        m_impl->ContributeToCategory(MalwareCategory::Trojan, catBase * 0.5f);
    } else {
        m_impl->ContributeToCategory(MalwareCategory::Trojan, catBase * 0.6f);
        m_impl->ContributeToCategory(MalwareCategory::Dropper, catBase * 0.4f);
    }
}

// ============================================================================
// AddEvasionAttempt
// ============================================================================

void ThreatScorer::AddEvasionAttempt(const std::string& technique,
                                     float severity) noexcept {
    std::unique_lock lock(m_impl->mutex);

    if (m_impl->evasionTechniques.size() >= kMaxEvasionTechniques) return;

    auto [it, inserted] = m_impl->evasionTechniques.insert(technique);
    if (!inserted) return; // already counted this evasion technique

    m_impl->evasionCount++;

    severity = std::clamp(severity, 0.0f, 1.0f);
    float weight = kWeightEvasionBase * severity;

    ScoringFactor factor;
    factor.source      = "EvasionDetection";
    factor.description = "Evasion: " + technique;
    factor.weight      = weight;
    factor.score       = 1.0f;
    factor.confidence  = 0.80f;

    m_impl->AddFactorInternal(std::move(factor));

    // Evasion contributes to sophisticated threat categories
    float catBase = weight * 0.8f;
    m_impl->ContributeToCategory(MalwareCategory::APTImplant, catBase * 0.40f);
    m_impl->ContributeToCategory(MalwareCategory::Rootkit, catBase * 0.25f);
    m_impl->ContributeToCategory(MalwareCategory::Trojan, catBase * 0.20f);
    m_impl->ContributeToCategory(MalwareCategory::Fileless, catBase * 0.15f);
}

// ============================================================================
// AddCustomFactor
// ============================================================================

void ThreatScorer::AddCustomFactor(const ScoringFactor& factor) noexcept {
    std::unique_lock lock(m_impl->mutex);

    if (m_impl->factors.size() >= kMaxScoringFactors) return;

    ScoringFactor f = factor;
    f.weight     = std::clamp(f.weight, 0.0f, 100.0f);
    f.score      = std::clamp(f.score, 0.0f, 1.0f);
    f.confidence = std::clamp(f.confidence, 0.0f, 1.0f);

    m_impl->AddFactorInternal(std::move(f));
}

// ============================================================================
// GenerateVerdict
// ============================================================================

ThreatVerdict ThreatScorer::GenerateVerdict() const noexcept {
    std::shared_lock lock(m_impl->mutex);

    ThreatVerdict verdict;

    verdict.score      = m_impl->ComputeNormalizedScore();
    verdict.level      = m_impl->ScoreToLevel(verdict.score);
    verdict.confidence = m_impl->ComputeOverallConfidence();

    auto [primary, secondary] = m_impl->GetTopCategories();
    verdict.primaryCategory   = primary;
    verdict.secondaryCategory = secondary;

    verdict.summary = m_impl->BuildSummary(
        verdict.level, verdict.score, verdict.confidence,
        primary, secondary);

    verdict.reasons = m_impl->BuildReasons();

    return verdict;
}

// ============================================================================
// GetFactors
// ============================================================================

const std::vector<ScoringFactor>& ThreatScorer::GetFactors() const noexcept {
    // Caller must hold appropriate synchronization if sharing across threads.
    // In typical usage, verdict is generated once at end of emulation.
    return m_impl->factors;
}

// ============================================================================
// GetRawScore / GetNormalizedScore
// ============================================================================

float ThreatScorer::GetRawScore() const noexcept {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->ComputeRawScore();
}

float ThreatScorer::GetNormalizedScore() const noexcept {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->ComputeNormalizedScore();
}

// ============================================================================
// ClassifyMalware
// ============================================================================

MalwareCategory ThreatScorer::ClassifyMalware() const noexcept {
    std::shared_lock lock(m_impl->mutex);
    auto [primary, _] = m_impl->GetTopCategories();
    return primary;
}

// ============================================================================
// GetCategoryScores
// ============================================================================

std::vector<std::pair<MalwareCategory, float>> ThreatScorer::GetCategoryScores() const noexcept {
    std::shared_lock lock(m_impl->mutex);

    std::vector<std::pair<MalwareCategory, float>> result;
    result.reserve(kCategoryCount);

    for (size_t i = 0; i < kCategoryCount; ++i) {
        if (m_impl->categoryScores[i] > 0.0f) {
            result.emplace_back(static_cast<MalwareCategory>(i),
                                m_impl->categoryScores[i]);
        }
    }

    std::sort(result.begin(), result.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    return result;
}

// ============================================================================
// Reset
// ============================================================================

void ThreatScorer::Reset() noexcept {
    std::unique_lock lock(m_impl->mutex);

    m_impl->factors.clear();
    m_impl->categoryScores.fill(0.0f);
    m_impl->accumulatedFlags      = BehaviorFlag::None;
    m_impl->mitreTechniqueCount   = 0;
    m_impl->evasionCount          = 0;
    m_impl->behaviorAlertCount    = 0;
    m_impl->sequenceMatchCount    = 0;
    m_impl->memoryFindingCount    = 0;
    m_impl->packerDetected        = false;
    m_impl->detectedPacker        = PackerType::Unknown;
    m_impl->maxAlertSeverityScore = 0.0f;
    m_impl->maxSequenceSeverity   = 0.0f;
    m_impl->maxMemoryFindingScore = 0.0f;
    m_impl->evasionTechniques.clear();
    m_impl->mitreTechniques.clear();
}

} // namespace Phantom
