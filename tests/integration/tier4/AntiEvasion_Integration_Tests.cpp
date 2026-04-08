/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Integration Tests – Tier 4: AntiEvasion ↔ Store Dependencies
 *
 * ============================================================================
 * PURPOSE
 * ============================================================================
 * Tests the production integration surface of the AntiEvasion sub-system —
 * specifically DebuggerEvasionDetector and VMEvasionDetector — and their
 * wiring to SignatureStore and ThreatIntelStore.
 *
 * Offline tests (Groups 1-10) require no disk stores or live OS handles.
 * Store-wiring tests (Groups 11-14) initialize real disk-backed stores in a
 * temporary directory, inject them into the detectors, and verify that the
 * detectors initialise cleanly and expose the correct API contracts.
 *
 * NOTE: This TU must NOT include BufferOverflowProtection.hpp because that
 * header defines type-aliases Clock, TimePoint, Hash256 in ShadowStrike::Exploits
 * which conflict with identically-named aliases in ShadowStrike::AntiEvasion /
 * ShadowStrike::Ransomware at TU level.
 *
 * ============================================================================
 * TEST GROUPS
 * ============================================================================
 *  GROUP 1   EvasionCategoryToString         - String mapping correctness
 *  GROUP 2   GetTechniqueCategory            - Range-based bucket mapping
 *  GROUP 3   GetDefaultTechniqueSeverity     - Severity assignments
 *  GROUP 4   EvasionTechniqueToMitreId       - MITRE ATT&CK id contracts
 *  GROUP 5   DetectedTechniqueAutoFill       - Constructor auto-populates fields
 *  GROUP 6   DebuggerEvasionResultDTO        - HasTechnique/HasCategory/GetBySeverity
 *  GROUP 7   KernelProcessContext            - hasKernelData() contracts
 *  GROUP 8   AnalysisFlagsComposition        - Bitwise operators + presets
 *  GROUP 9   AnalysisConfigDefaults          - Default field values
 *  GROUP 10  VMConstantsValidation           - Known-list sanity checks
 *  GROUP 11  VMEvasionDetectorStaticUtils    - VMTypeToString/CategoryToString/…
 *  GROUP 12  VMEvasionDetectorConfig         - CreateDefault() contracts
 *  GROUP 13  DebuggerDetector_StoreWiring    - Init with injected real stores
 *  GROUP 14  VMDetector_StoreWiring          - Init with injected real stores
 */

// ============================================================================
// PLATFORM / STANDARD HEADERS — must come before any Windows SDK header
// ============================================================================
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

// ============================================================================
// GOOGLETEST
// ============================================================================
#include <gtest/gtest.h>

// ============================================================================
// SHADOWSTRIKE MODULE HEADERS
// ============================================================================
#include "../../../src/Shared_modules/AntiEvasion/DebuggerEvasionDetector.hpp"
#include "../../../src/Shared_modules/AntiEvasion/VMEvasionDetector.hpp"
#include "../../../src/Shared_modules/SignatureStore/SignatureStore.hpp"
#include "../../../src/Shared_modules/ThreatIntel/ThreatIntelStore.hpp"

// ============================================================================
// CONVENIENCE ALIASES
// ============================================================================
namespace AE  = ShadowStrike::AntiEvasion;
namespace SS  = ShadowStrike::SignatureStore;
namespace TI  = ShadowStrike::ThreatIntel;
using DED     = AE::DebuggerEvasionDetector;
using VMED    = AE::VMEvasionDetector;
using ET      = AE::EvasionTechnique;
using EC      = AE::EvasionCategory;
using ES      = AE::EvasionSeverity;
using AF      = AE::AnalysisFlags;

// ============================================================================
// SCOPED TEMP DIRECTORY — RAII wrapper identical to the Tier 1 reference
// ============================================================================
class ScopedTempDir {
public:
    ScopedTempDir() {
        wchar_t tmp[MAX_PATH];
        GetTempPathW(MAX_PATH, tmp);
        m_path = std::wstring(tmp) +
                 L"SS_IntTier4_AE_" +
                 std::to_wstring(GetCurrentProcessId()) + L"_" +
                 std::to_wstring(s_counter.fetch_add(1, std::memory_order_relaxed));
        std::filesystem::create_directories(m_path);
    }

    ~ScopedTempDir() {
        std::error_code ec;
        std::filesystem::remove_all(m_path, ec);
    }

    [[nodiscard]] const std::wstring& Path() const noexcept { return m_path; }
    [[nodiscard]] std::wstring File(const std::wstring& name) const {
        return m_path + L"\\" + name;
    }

    ScopedTempDir(const ScopedTempDir&) = delete;
    ScopedTempDir& operator=(const ScopedTempDir&) = delete;

private:
    std::wstring m_path;
    inline static std::atomic<int> s_counter{ 0 };
};

// ============================================================================
// SKIP GUARD for store-wiring fixture
// ============================================================================
#define SKIP_IF_STORES_NOT_READY()                                      \
    do {                                                                \
        if (!AntiEvasionStoreFixture::s_setupSucceeded) {               \
            GTEST_SKIP() << "Store setup failed; skipping test.";       \
        }                                                               \
    } while (false)

// ============================================================================
// GROUP 1 — EvasionCategoryToString
// ============================================================================

/**
 * @brief EvasionCategoryToString must return a non-empty string for every
 *        named enum value.
 *
 * The detector emits these strings into logs and telemetry.  A blank or
 * "Unknown" value for a valid category is a latent reporting bug.
 */
TEST(EvasionCategoryToString, AllNamedValuesNonEmpty) {
    const auto check = [](EC cat, const char* expected) {
        const char* result = AE::EvasionCategoryToString(cat);
        ASSERT_NE(result, nullptr)    << "EvasionCategoryToString returned nullptr";
        EXPECT_STRNE(result, "")      << "Empty string for category " << static_cast<int>(cat);
        EXPECT_STRNE(result, "Unknown") << "Unexpected 'Unknown' for " << expected;
    };

    check(EC::PEBBased,                "PEBBased");
    check(EC::HardwareDebugRegisters,  "HardwareDebugRegisters");
    check(EC::APIBased,                "APIBased");
    check(EC::TimingBased,             "TimingBased");
    check(EC::ExceptionBased,          "ExceptionBased");
    check(EC::ObjectHandleBased,       "ObjectHandleBased");
    check(EC::ProcessRelationship,     "ProcessRelationship");
    check(EC::MemoryArtifacts,         "MemoryArtifacts");
    check(EC::SelfDebugging,           "SelfDebugging");
    check(EC::ThreadBased,             "ThreadBased");
    check(EC::KernelQueries,           "KernelQueries");
    check(EC::CodeIntegrity,           "CodeIntegrity");
    check(EC::Combined,                "Combined");
}

/**
 * @brief EvasionCategoryToString must return "Unknown" (the fallback) for
 *        the explicit Unknown enum value.
 */
TEST(EvasionCategoryToString, UnknownReturnsUnknownString) {
    EXPECT_STREQ(AE::EvasionCategoryToString(EC::Unknown), "Unknown");
}

/**
 * @brief Exact string values for a subset of commonly displayed categories.
 */
TEST(EvasionCategoryToString, ExactStrings) {
    EXPECT_STREQ(AE::EvasionCategoryToString(EC::PEBBased),   "PEB-Based");
    EXPECT_STREQ(AE::EvasionCategoryToString(EC::APIBased),   "API-Based");
    EXPECT_STREQ(AE::EvasionCategoryToString(EC::TimingBased),"Timing-Based");
    EXPECT_STREQ(AE::EvasionCategoryToString(EC::Combined),   "Combined");
}

// ============================================================================
// GROUP 2 — GetTechniqueCategory
// ============================================================================

/**
 * @brief EvasionTechnique::None (id=0) must map to EC::Unknown.
 */
TEST(GetTechniqueCategory, None_IsUnknown) {
    EXPECT_EQ(AE::GetTechniqueCategory(ET::None), EC::Unknown);
}

/**
 * @brief Boundary probe: id=1 (first PEB) → PEBBased, id=20 (last PEB) → PEBBased.
 */
TEST(GetTechniqueCategory, PEBBased_Boundaries) {
    EXPECT_EQ(AE::GetTechniqueCategory(ET::PEB_BeingDebugged), EC::PEBBased);
    EXPECT_EQ(AE::GetTechniqueCategory(ET::PEB_OSVersionCheck), EC::PEBBased);
}

/**
 * @brief Hardware debug register range (21-40) must map to HardwareDebugRegisters.
 */
TEST(GetTechniqueCategory, HardwareDebugRegisters_Range) {
    EXPECT_EQ(AE::GetTechniqueCategory(ET::HW_BreakpointRegisters),  EC::HardwareDebugRegisters);
    EXPECT_EQ(AE::GetTechniqueCategory(ET::HW_ContextDebugEnum),     EC::HardwareDebugRegisters);
}

/**
 * @brief API-based range (41-80) boundaries.
 */
TEST(GetTechniqueCategory, APIBased_Range) {
    EXPECT_EQ(AE::GetTechniqueCategory(ET::API_IsDebuggerPresent),            EC::APIBased);
    EXPECT_EQ(AE::GetTechniqueCategory(ET::API_DbgUiRemoteBreakin),           EC::APIBased);
}

/**
 * @brief Timing-based range (81-100).
 */
TEST(GetTechniqueCategory, TimingBased_Range) {
    EXPECT_EQ(AE::GetTechniqueCategory(ET::TIMING_RDTSC),             EC::TimingBased);
    EXPECT_EQ(AE::GetTechniqueCategory(ET::TIMING_WaitValidation),    EC::TimingBased);
}

/**
 * @brief Exception-based range (101-130).
 */
TEST(GetTechniqueCategory, ExceptionBased_Range) {
    EXPECT_EQ(AE::GetTechniqueCategory(ET::EXCEPTION_INT2D),              EC::ExceptionBased);
    EXPECT_EQ(AE::GetTechniqueCategory(ET::EXCEPTION_INT3),               EC::ExceptionBased);
}

/**
 * @brief Combined-techniques range (281-300).
 */
TEST(GetTechniqueCategory, Combined_Range) {
    // ADVANCED_EncryptedAntiDebug=283, ADVANCED_HypervisorDebug=285
    EXPECT_EQ(AE::GetTechniqueCategory(static_cast<ET>(283)), EC::Combined);
    EXPECT_EQ(AE::GetTechniqueCategory(static_cast<ET>(285)), EC::Combined);
}

// ============================================================================
// GROUP 3 — GetDefaultTechniqueSeverity
// ============================================================================

/**
 * @brief Critical severity for HideFromDebugger / AntiAttach techniques.
 */
TEST(GetDefaultTechniqueSeverity, Critical_HideFromDebugger) {
    EXPECT_EQ(
        AE::GetDefaultTechniqueSeverity(ET::API_NtSetInformationThread_HideFromDebugger),
        ES::Critical);
    EXPECT_EQ(
        AE::GetDefaultTechniqueSeverity(ET::API_NtCreateThreadEx_HideFromDebugger),
        ES::Critical);
}

/**
 * @brief High severity for hardware breakpoint and RDTSC timing checks.
 */
TEST(GetDefaultTechniqueSeverity, High_HardwareAndTiming) {
    EXPECT_EQ(AE::GetDefaultTechniqueSeverity(ET::HW_BreakpointRegisters), ES::High);
    EXPECT_EQ(AE::GetDefaultTechniqueSeverity(ET::TIMING_RDTSC),           ES::High);
    EXPECT_EQ(AE::GetDefaultTechniqueSeverity(ET::EXCEPTION_INT2D),        ES::High);
}

/**
 * @brief Medium severity for common PEB and API checks.
 */
TEST(GetDefaultTechniqueSeverity, Medium_PEBAndCommonAPI) {
    EXPECT_EQ(AE::GetDefaultTechniqueSeverity(ET::PEB_BeingDebugged),               ES::Medium);
    EXPECT_EQ(AE::GetDefaultTechniqueSeverity(ET::API_IsDebuggerPresent),            ES::Medium);
    EXPECT_EQ(AE::GetDefaultTechniqueSeverity(ET::API_CheckRemoteDebuggerPresent),   ES::Medium);
}

/**
 * @brief Low severity (default) for unclassified / rarely-malicious techniques.
 */
TEST(GetDefaultTechniqueSeverity, Low_DefaultFallback) {
    // Technique IDs not explicitly listed in the severity switch — fall to Low
    EXPECT_EQ(AE::GetDefaultTechniqueSeverity(ET::TIMING_GetTickCount64), ES::Low);
    EXPECT_EQ(AE::GetDefaultTechniqueSeverity(ET::None),                  ES::Low);
}

// ============================================================================
// GROUP 4 — EvasionTechniqueToMitreId
// ============================================================================

/**
 * @brief Common anti-debug techniques must map to T1622.
 */
TEST(EvasionTechniqueToMitreId, PEB_MapsTo_T1622) {
    EXPECT_STREQ(AE::EvasionTechniqueToMitreId(ET::PEB_BeingDebugged), "T1622");
    EXPECT_STREQ(AE::EvasionTechniqueToMitreId(ET::API_IsDebuggerPresent), "T1622");
    EXPECT_STREQ(AE::EvasionTechniqueToMitreId(ET::HW_BreakpointRegisters), "T1622");
}

/**
 * @brief Timing techniques must map to T1497.003.
 */
TEST(EvasionTechniqueToMitreId, Timing_MapsTo_T1497_003) {
    EXPECT_STREQ(AE::EvasionTechniqueToMitreId(ET::TIMING_RDTSC),                   "T1497.003");
    EXPECT_STREQ(AE::EvasionTechniqueToMitreId(ET::TIMING_QueryPerformanceCounter),  "T1497.003");
}

/**
 * @brief API abuse (debug port queries, HideFromDebugger) must map to T1106.
 */
TEST(EvasionTechniqueToMitreId, APIAbuse_MapsTo_T1106) {
    EXPECT_STREQ(
        AE::EvasionTechniqueToMitreId(ET::API_NtSetInformationThread_HideFromDebugger),
        "T1106");
    EXPECT_STREQ(
        AE::EvasionTechniqueToMitreId(ET::API_NtQueryInformationProcess_DebugPort),
        "T1106");
}

/**
 * @brief Default case must still return a non-empty MITRE ID (T1622 fallback).
 */
TEST(EvasionTechniqueToMitreId, Default_NonEmpty) {
    const char* id = AE::EvasionTechniqueToMitreId(ET::None);
    ASSERT_NE(id, nullptr);
    EXPECT_STRNE(id, "") << "Default MITRE ID must not be empty.";
}

// ============================================================================
// GROUP 5 — DetectedTechnique Auto-fill Constructor
// ============================================================================

/**
 * @brief Constructing DetectedTechnique with a technique ID must auto-fill
 *        category, severity, and mitreId from the compile-time helper functions.
 */
TEST(DetectedTechniqueAutoFill, PEBBeingDebugged_AutoFill) {
    AE::DetectedTechnique dt(ET::PEB_BeingDebugged);

    EXPECT_EQ(dt.technique, ET::PEB_BeingDebugged);
    EXPECT_EQ(dt.category,  AE::GetTechniqueCategory(ET::PEB_BeingDebugged));
    EXPECT_EQ(dt.severity,  AE::GetDefaultTechniqueSeverity(ET::PEB_BeingDebugged));
    EXPECT_EQ(dt.mitreId,   std::string(AE::EvasionTechniqueToMitreId(ET::PEB_BeingDebugged)));

    // detectionTime must be recent (within 5 seconds)
    const auto now   = std::chrono::system_clock::now();
    const auto delta = std::chrono::duration_cast<std::chrono::seconds>(now - dt.detectionTime);
    EXPECT_GE(delta.count(), 0);
    EXPECT_LT(delta.count(), 5) << "detectionTime must be populated with current time.";
}

/**
 * @brief HideFromDebugger auto-fill must yield Critical severity.
 */
TEST(DetectedTechniqueAutoFill, HideFromDebugger_CriticalSeverity) {
    AE::DetectedTechnique dt(ET::API_NtSetInformationThread_HideFromDebugger);
    EXPECT_EQ(dt.severity, ES::Critical);
    EXPECT_EQ(dt.category, EC::APIBased);
}

/**
 * @brief Default-constructed DetectedTechnique must have None technique and Low severity.
 */
TEST(DetectedTechniqueAutoFill, DefaultConstructed_Safe) {
    AE::DetectedTechnique dt;
    EXPECT_EQ(dt.technique, ET::None);
    EXPECT_EQ(dt.severity,  ES::Low);
    EXPECT_DOUBLE_EQ(dt.confidence, 0.0);
}

// ============================================================================
// GROUP 6 — DebuggerEvasionResult DTO Methods
// ============================================================================

namespace {

    /**
     * @brief Builds a pre-populated DebuggerEvasionResult for DTO method testing.
     *
     * Inserts two techniques into different categories so that HasTechnique,
     * HasCategory, GetBySeverity, and GetCategoryCount can be exercised.
     */
    AE::DebuggerEvasionResult BuildSampleResult() {
        AE::DebuggerEvasionResult result;
        result.isEvasive = true;

        // Technique 1: PEB_BeingDebugged (PEBBased, Medium)
        {
            AE::DetectedTechnique dt(ET::PEB_BeingDebugged);
            dt.confidence = 0.80;
            // Record in detectedCategories bitmask
            result.detectedCategories |= (1u << static_cast<uint32_t>(dt.category));
            result.detectedTechniques.push_back(dt);
        }

        // Technique 2: API_NtSetInformationThread_HideFromDebugger (APIBased, Critical)
        {
            AE::DetectedTechnique dt(ET::API_NtSetInformationThread_HideFromDebugger);
            dt.confidence = 0.99;
            result.detectedCategories |= (1u << static_cast<uint32_t>(dt.category));
            result.detectedTechniques.push_back(dt);
        }

        result.totalDetections = static_cast<uint32_t>(result.detectedTechniques.size());
        result.maxSeverity      = ES::Critical;
        return result;
    }

} // anonymous namespace

/**
 * @brief HasTechnique must return true for inserted techniques and false for
 *        techniques not in the result.
 */
TEST(DebuggerEvasionResultDTO, HasTechnique_PresentAndAbsent) {
    const auto result = BuildSampleResult();

    EXPECT_TRUE(result.HasTechnique(ET::PEB_BeingDebugged))
        << "PEB_BeingDebugged was inserted — HasTechnique must return true.";
    EXPECT_TRUE(result.HasTechnique(ET::API_NtSetInformationThread_HideFromDebugger))
        << "HideFromDebugger was inserted — HasTechnique must return true.";
    EXPECT_FALSE(result.HasTechnique(ET::TIMING_RDTSC))
        << "TIMING_RDTSC was not inserted — HasTechnique must return false.";
}

/**
 * @brief HasCategory must reflect the detectedCategories bitmask correctly.
 */
TEST(DebuggerEvasionResultDTO, HasCategory_PresentAndAbsent) {
    const auto result = BuildSampleResult();

    EXPECT_TRUE(result.HasCategory(EC::PEBBased))
        << "PEBBased category was set.";
    EXPECT_TRUE(result.HasCategory(EC::APIBased))
        << "APIBased category was set.";
    EXPECT_FALSE(result.HasCategory(EC::TimingBased))
        << "TimingBased category was not set.";
    EXPECT_FALSE(result.HasCategory(EC::Unknown));
}

/**
 * @brief GetBySeverity with threshold Critical must include only the Critical
 *        technique, not the Medium one.
 */
TEST(DebuggerEvasionResultDTO, GetBySeverity_CriticalOnly) {
    const auto result   = BuildSampleResult();
    const auto critical = result.GetBySeverity(ES::Critical);

    ASSERT_EQ(critical.size(), 1u);
    EXPECT_EQ(critical[0]->technique, ET::API_NtSetInformationThread_HideFromDebugger);
}

/**
 * @brief GetBySeverity with threshold Low must return all techniques.
 */
TEST(DebuggerEvasionResultDTO, GetBySeverity_LowIncludesAll) {
    const auto result = BuildSampleResult();
    const auto all    = result.GetBySeverity(ES::Low);
    EXPECT_EQ(all.size(), result.detectedTechniques.size());
}

/**
 * @brief GetCategoryCount must count only techniques in the given category.
 */
TEST(DebuggerEvasionResultDTO, GetCategoryCount_PerCategory) {
    const auto result = BuildSampleResult();

    EXPECT_EQ(result.GetCategoryCount(EC::PEBBased), 1u);
    EXPECT_EQ(result.GetCategoryCount(EC::APIBased),  1u);
    EXPECT_EQ(result.GetCategoryCount(EC::TimingBased), 0u);
}

/**
 * @brief Clear() must reset all fields to zero/empty.
 */
TEST(DebuggerEvasionResultDTO, Clear_ResetsAllFields) {
    auto result = BuildSampleResult();
    result.Clear();

    EXPECT_EQ(result.targetPid,          0u);
    EXPECT_FALSE(result.isEvasive);
    EXPECT_DOUBLE_EQ(result.evasionScore, 0.0);
    EXPECT_EQ(result.totalDetections,    0u);
    EXPECT_EQ(result.detectedCategories, 0u);
    EXPECT_TRUE(result.detectedTechniques.empty());
    EXPECT_FALSE(result.HasCategory(EC::PEBBased));
    EXPECT_FALSE(result.HasCategory(EC::APIBased));
    EXPECT_FALSE(result.HasTechnique(ET::PEB_BeingDebugged));
}

// ============================================================================
// GROUP 7 — KernelProcessContext
// ============================================================================

/**
 * @brief Default-constructed KernelProcessContext must report no kernel data.
 */
TEST(KernelProcessContext, DefaultConstructed_NoKernelData) {
    AE::KernelProcessContext ctx;
    EXPECT_FALSE(ctx.hasKernelData())
        << "Default-constructed KernelProcessContext must not have kernel data.";
}

/**
 * @brief Setting imagePath (non-empty) must make hasKernelData() return true.
 */
TEST(KernelProcessContext, ImagePath_HasKernelData) {
    AE::KernelProcessContext ctx;
    ctx.imagePath = L"C:\\Windows\\System32\\notepad.exe";
    EXPECT_TRUE(ctx.hasKernelData());
}

/**
 * @brief Setting parentProcessId (non-zero) must make hasKernelData() return true.
 */
TEST(KernelProcessContext, ParentPid_HasKernelData) {
    AE::KernelProcessContext ctx;
    ctx.parentProcessId = 4u;   // SYSTEM
    EXPECT_TRUE(ctx.hasKernelData());
}

/**
 * @brief commandLine alone does NOT constitute kernel data per the contract.
 *
 * hasKernelData() is defined as:
 *   return !imagePath.empty() || parentProcessId != 0;
 */
TEST(KernelProcessContext, CommandLineOnly_NoKernelData) {
    AE::KernelProcessContext ctx;
    ctx.commandLine = L"notepad.exe /t";
    EXPECT_FALSE(ctx.hasKernelData())
        << "commandLine alone must not satisfy hasKernelData().";
}

// ============================================================================
// GROUP 8 — AnalysisFlags Composition
// ============================================================================

/**
 * @brief Bitwise OR of two flags must produce a combined flag that passes
 *        HasFlag for both individual components.
 */
TEST(AnalysisFlags, BitwiseOR_HasFlag) {
    const AF combined = AF::ScanPEBTechniques | AF::ScanAPITechniques;
    EXPECT_TRUE(AE::HasFlag(combined, AF::ScanPEBTechniques));
    EXPECT_TRUE(AE::HasFlag(combined, AF::ScanAPITechniques));
    EXPECT_FALSE(AE::HasFlag(combined, AF::ScanHardwareBreakpoints))
        << "ScanHardwareBreakpoints was not ORed in.";
}

/**
 * @brief Bitwise AND must produce only the intersection.
 */
TEST(AnalysisFlags, BitwiseAND_Intersection) {
    const AF a = AF::ScanPEBTechniques | AF::ScanAPITechniques;
    const AF b = AF::ScanAPITechniques | AF::ScanTimingTechniques;
    const AF isect = a & b;

    EXPECT_TRUE(AE::HasFlag(isect, AF::ScanAPITechniques))
        << "APITechniques is in both operands — must be in intersection.";
    EXPECT_FALSE(AE::HasFlag(isect, AF::ScanPEBTechniques))
        << "PEBTechniques is only in 'a' — must not be in intersection.";
    EXPECT_FALSE(AE::HasFlag(isect, AF::ScanTimingTechniques))
        << "TimingTechniques is only in 'b' — must not be in intersection.";
}

/**
 * @brief Bitwise NOT must exclude the specified flag.
 */
TEST(AnalysisFlags, BitwiseNOT_ExcludesFlag) {
    const AF notPEB = ~AF::ScanPEBTechniques;
    EXPECT_FALSE(AE::HasFlag(notPEB, AF::ScanPEBTechniques))
        << "NOT(ScanPEBTechniques) must not contain ScanPEBTechniques.";
}

/**
 * @brief The QuickScan preset must include PEB and API but not TimingBased.
 */
TEST(AnalysisFlags, QuickScan_Preset) {
    EXPECT_TRUE(AE::HasFlag(AF::QuickScan, AF::ScanPEBTechniques));
    EXPECT_TRUE(AE::HasFlag(AF::QuickScan, AF::ScanAPITechniques));
    EXPECT_TRUE(AE::HasFlag(AF::QuickScan, AF::EnableCaching));
    EXPECT_FALSE(AE::HasFlag(AF::QuickScan, AF::ScanTimingTechniques));
}

/**
 * @brief The Default preset must equal StandardScan.
 */
TEST(AnalysisFlags, Default_EqualsStandardScan) {
    // Both are compile-time constants — simple integral equality is sufficient.
    EXPECT_EQ(static_cast<uint32_t>(AF::Default),
              static_cast<uint32_t>(AF::StandardScan));
}

/**
 * @brief AF::None must cause HasFlag to return false for any real flag.
 */
TEST(AnalysisFlags, None_HasNoFlags) {
    EXPECT_FALSE(AE::HasFlag(AF::None, AF::ScanPEBTechniques));
    EXPECT_FALSE(AE::HasFlag(AF::None, AF::EnableCaching));
}

// ============================================================================
// GROUP 9 — AnalysisConfig Defaults
// ============================================================================

/**
 * @brief Default AnalysisConfig must use Standard depth and Default flags.
 */
TEST(AnalysisConfigDefaults, DepthAndFlags) {
    AE::AnalysisConfig cfg;
    EXPECT_EQ(cfg.depth, AE::AnalysisDepth::Standard);
    EXPECT_EQ(cfg.flags, AF::Default);
}

/**
 * @brief Caching must be enabled by default.
 */
TEST(AnalysisConfigDefaults, CachingEnabled) {
    AE::AnalysisConfig cfg;
    EXPECT_TRUE(cfg.enableCaching);
}

/**
 * @brief Confidence threshold must be in [0, 1].
 */
TEST(AnalysisConfigDefaults, ConfidenceThresholdRange) {
    AE::AnalysisConfig cfg;
    EXPECT_GE(cfg.minConfidenceThreshold, 0.0);
    EXPECT_LE(cfg.minConfidenceThreshold, 1.0);
}

/**
 * @brief Optional kernelContext must be empty by default.
 */
TEST(AnalysisConfigDefaults, KernelContext_EmptyByDefault) {
    AE::AnalysisConfig cfg;
    EXPECT_FALSE(cfg.kernelContext.has_value())
        << "kernelContext must be empty by default.";
}

// ============================================================================
// GROUP 10 — VMConstantsValidation
// ============================================================================

/**
 * @brief ANTI_VM_MNEMONICS must contain known entries and all must be non-empty.
 */
TEST(VMConstantsValidation, AntiVMMnemonics_NonEmpty) {
    const auto& mnemonics = AE::VMConstants::ANTI_VM_MNEMONICS;
    EXPECT_FALSE(mnemonics.empty())
        << "ANTI_VM_MNEMONICS must not be empty.";
    for (const auto& m : mnemonics) {
        EXPECT_FALSE(m.empty())
            << "A mnemonic in ANTI_VM_MNEMONICS is empty.";
    }
}

/**
 * @brief ANTI_VM_MNEMONICS must contain "cpuid" and "rdtsc" — foundational
 *        VM detection instructions used by every major anti-VM technique.
 */
TEST(VMConstantsValidation, AntiVMMnemonics_ContainsCpuidAndRdtsc) {
    const auto& mnemonics = AE::VMConstants::ANTI_VM_MNEMONICS;
    const auto hasEntry = [&](std::string_view target) {
        return std::any_of(mnemonics.begin(), mnemonics.end(),
            [&](std::string_view sv) { return sv == target; });
    };
    EXPECT_TRUE(hasEntry("cpuid"))  << "\"cpuid\" must be in ANTI_VM_MNEMONICS.";
    EXPECT_TRUE(hasEntry("rdtsc"))  << "\"rdtsc\" must be in ANTI_VM_MNEMONICS.";
    EXPECT_TRUE(hasEntry("in"))     << "\"in\" (I/O port read) must be in ANTI_VM_MNEMONICS.";
}

/**
 * @brief All entries in ANTI_VM_MNEMONICS must be unique (no duplicates).
 */
TEST(VMConstantsValidation, AntiVMMnemonics_Unique) {
    const auto& mnemonics = AE::VMConstants::ANTI_VM_MNEMONICS;
    const std::unordered_set<std::string_view> unique(mnemonics.begin(), mnemonics.end());
    EXPECT_EQ(unique.size(), mnemonics.size())
        << "ANTI_VM_MNEMONICS must not contain duplicate entries.";
}

/**
 * @brief ANTI_VM_IMPORT_APIS must contain all API names non-empty and include
 *        the foundational IsDebuggerPresent check.
 */
TEST(VMConstantsValidation, AntiVMImportAPIs_NonEmptyAndContainsIsDebuggerPresent) {
    const auto& apis = AE::VMConstants::ANTI_VM_IMPORT_APIS;
    EXPECT_FALSE(apis.empty());
    for (const auto& api : apis)
        EXPECT_FALSE(api.empty()) << "API name in ANTI_VM_IMPORT_APIS is empty.";

    const auto has = [&](std::string_view target) {
        return std::any_of(apis.begin(), apis.end(),
            [&](std::string_view sv) { return sv == target; });
    };
    EXPECT_TRUE(has("IsDebuggerPresent"))
        << "ANTI_VM_IMPORT_APIS must contain IsDebuggerPresent.";
}

/**
 * @brief KNOWN_VM_REGISTRY_KEYS must have at least 10 entries (the header
 *        declares 24 but we guard against future trimming to a safe minimum).
 */
TEST(VMConstantsValidation, KnownVMRegistryKeys_MinimumCount) {
    const auto& keys = AE::VMConstants::KNOWN_VM_REGISTRY_KEYS;
    EXPECT_GE(keys.size(), 10u)
        << "KNOWN_VM_REGISTRY_KEYS must have at least 10 entries.";
    for (const auto& k : keys)
        EXPECT_FALSE(k.empty()) << "An entry in KNOWN_VM_REGISTRY_KEYS is empty.";
}

/**
 * @brief KNOWN_VM_FILES must be a non-trivial list with non-empty entries.
 */
TEST(VMConstantsValidation, KnownVMFiles_NonEmpty) {
    const auto& files = AE::VMConstants::KNOWN_VM_FILES;
    EXPECT_GE(files.size(), 10u)
        << "KNOWN_VM_FILES must contain at least 10 entries.";
    for (const auto& f : files)
        EXPECT_FALSE(f.empty()) << "An entry in KNOWN_VM_FILES is empty.";
}

// ============================================================================
// GROUP 11 — VMEvasionDetector Static Utilities
// ============================================================================

/**
 * @brief VMTypeToString must return a non-empty wide string for all named types.
 */
TEST(VMEvasionDetectorStaticUtils, VMTypeToString_AllKnown_NonEmpty) {
    const AE::VMType types[] = {
        AE::VMType::None, AE::VMType::VMware,    AE::VMType::VirtualBox,
        AE::VMType::HyperV, AE::VMType::QEMU,   AE::VMType::KVM,
        AE::VMType::Xen,    AE::VMType::Parallels
    };
    for (auto t : types) {
        EXPECT_FALSE(VMED::VMTypeToString(t).empty())
            << "VMTypeToString returned empty for type " << static_cast<int>(t);
    }
}

/**
 * @brief CategoryToString must return a non-empty string for CPUID and
 *        FileSystem categories.
 */
TEST(VMEvasionDetectorStaticUtils, CategoryToString_Selected_NonEmpty) {
    EXPECT_FALSE(VMED::CategoryToString(AE::VMDetectionCategory::CPUID).empty());
    EXPECT_FALSE(VMED::CategoryToString(AE::VMDetectionCategory::FileSystem).empty());
    EXPECT_FALSE(VMED::CategoryToString(AE::VMDetectionCategory::Registry).empty());
}

/**
 * @brief GetKnownVMRegistryKeys must return a non-empty span.
 */
TEST(VMEvasionDetectorStaticUtils, GetKnownVMRegistryKeys_NonEmpty) {
    const auto keys = VMED::GetKnownVMRegistryKeys();
    EXPECT_FALSE(keys.empty())
        << "GetKnownVMRegistryKeys() must not return an empty span.";
    for (const auto& k : keys)
        EXPECT_FALSE(k.empty());
}

/**
 * @brief GetKnownVMFiles must return a non-empty span.
 */
TEST(VMEvasionDetectorStaticUtils, GetKnownVMFiles_NonEmpty) {
    const auto files = VMED::GetKnownVMFiles();
    EXPECT_FALSE(files.empty())
        << "GetKnownVMFiles() must not return an empty span.";
    for (const auto& f : files)
        EXPECT_FALSE(f.empty());
}

/**
 * @brief GetKnownVMProcesses must return a non-empty span.
 */
TEST(VMEvasionDetectorStaticUtils, GetKnownVMProcesses_NonEmpty) {
    const auto procs = VMED::GetKnownVMProcesses();
    EXPECT_FALSE(procs.empty())
        << "GetKnownVMProcesses() must not return an empty span.";
}

/**
 * @brief GetInstructionEvasionScore must return > 0 for "cpuid" and 0 for
 *        a completely benign instruction.
 */
TEST(VMEvasionDetectorStaticUtils, GetInstructionEvasionScore_CpuidPositive) {
    EXPECT_GT(VMED::GetInstructionEvasionScore("cpuid"), 0.0f)
        << "cpuid must have a positive evasion score.";
    EXPECT_GT(VMED::GetInstructionEvasionScore("rdtsc"), 0.0f)
        << "rdtsc must have a positive evasion score.";
}

TEST(VMEvasionDetectorStaticUtils, GetInstructionEvasionScore_BenignInstruction_Zero) {
    EXPECT_FLOAT_EQ(VMED::GetInstructionEvasionScore("nop"), 0.0f)
        << "nop must have zero evasion score.";
    EXPECT_FLOAT_EQ(VMED::GetInstructionEvasionScore("mov"), 0.0f)
        << "mov must have zero evasion score.";
}

/**
 * @brief ClassifyImport must return None for unknown DLL/function combinations.
 */
TEST(VMEvasionDetectorStaticUtils, ClassifyImport_Unknown_ReturnsNone) {
    EXPECT_EQ(VMED::ClassifyImport("completely.dll", "BenignFunction"),
              AE::AntiVMTechnique::None)
        << "Unknown import must return AntiVMTechnique::None.";
}

// ============================================================================
// GROUP 12 — VMEvasionDetector Config
// ============================================================================

/**
 * @brief VMDetectionConfig::CreateDefault() must produce a valid configuration.
 */
TEST(VMEvasionDetectorConfig, CreateDefault_Valid) {
    const auto cfg = AE::VMDetectionConfig::CreateDefault();
    // minimumConfidenceThreshold should be in a sane range [0, 100] (it's a
    // percentage-style float, defaulting to 25.0f in the header).
    EXPECT_GE(cfg.minimumConfidenceThreshold, 0.0f);
    EXPECT_LE(cfg.minimumConfidenceThreshold, 100.0f);
}

/**
 * @brief VMEvasionDetector default-constructed (no stores) must not throw.
 */
TEST(VMEvasionDetectorConfig, DefaultConstruct_NoCrash) {
    ASSERT_NO_THROW({
        VMED detector;
        (void)detector.GetConfig();
    });
}

/**
 * @brief SetConfig round-trip: set a config, then read it back via GetConfig.
 */
TEST(VMEvasionDetectorConfig, SetConfig_GetConfig_RoundTrip) {
    VMED detector;
    auto cfg = AE::VMDetectionConfig::CreateDefault();
    // Toggle caching so we have a verifiable mutation to round-trip.
    cfg.enableCaching = false;

    detector.SetConfig(cfg);
    const auto got = detector.GetConfig();
    EXPECT_EQ(got.enableCaching, cfg.enableCaching);
}

// ============================================================================
// GROUP 13 — DebuggerEvasionDetector Store Wiring
// ============================================================================

class AntiEvasionStoreFixture : public ::testing::Test {
public:
    static bool s_setupSucceeded;
    static ScopedTempDir* s_tempDir;
    static std::shared_ptr<SS::SignatureStore>      s_sigStore;
    static std::shared_ptr<TI::ThreatIntelStore>    s_tiStore;

    static void SetUpTestSuite() {
        s_setupSucceeded = false;

        s_tempDir = new ScopedTempDir;

        // Initialize SignatureStore (write-mode, new empty database)
        s_sigStore = std::make_shared<SS::SignatureStore>();
        if (!s_sigStore->Initialize(s_tempDir->File(L"ae_sigs.sdb"), /*readOnly=*/false)) {
            ADD_FAILURE() << "SignatureStore::Initialize() failed.";
            return;
        }

        // Initialize ThreatIntelStore
        s_tiStore = std::make_shared<TI::ThreatIntelStore>();
        auto tiCfg = TI::StoreConfig::CreateDefault();
        if (!s_tiStore->Initialize(tiCfg)) {
            ADD_FAILURE() << "ThreatIntelStore::Initialize() failed.";
            return;
        }

        s_setupSucceeded = true;
    }

    static void TearDownTestSuite() {
        if (s_sigStore && s_sigStore->IsInitialized()) s_sigStore->Close();
        if (s_tiStore  && s_tiStore->IsInitialized())  s_tiStore->Shutdown();
        delete s_tempDir;
        s_tempDir = nullptr;
    }
};

bool                                         AntiEvasionStoreFixture::s_setupSucceeded = false;
ScopedTempDir*                               AntiEvasionStoreFixture::s_tempDir        = nullptr;
std::shared_ptr<SS::SignatureStore>          AntiEvasionStoreFixture::s_sigStore;
std::shared_ptr<TI::ThreatIntelStore>        AntiEvasionStoreFixture::s_tiStore;

/**
 * @brief DebuggerEvasionDetector initialized with both stores must report
 *        IsInitialized() == true.
 */
TEST_F(AntiEvasionStoreFixture, DebuggerDetector_InitWithBothStores_Initialized) {
    SKIP_IF_STORES_NOT_READY();

    DED detector(s_sigStore, s_tiStore);
    AE::Error err;
    ASSERT_TRUE(detector.Initialize(&err))
        << "Initialize with valid stores must succeed. Error: "
        << (err.HasError() ? "yes" : "none");
    EXPECT_TRUE(detector.IsInitialized());
    detector.Shutdown();
}

/**
 * @brief DebuggerEvasionDetector initialized with only SignatureStore (no TI)
 *        must still succeed.
 */
TEST_F(AntiEvasionStoreFixture, DebuggerDetector_InitWithSigStoreOnly_Initialized) {
    SKIP_IF_STORES_NOT_READY();

    DED detector(s_sigStore);
    ASSERT_TRUE(detector.Initialize());
    EXPECT_TRUE(detector.IsInitialized());
    detector.Shutdown();
}

/**
 * @brief DebuggerEvasionDetector initialized without any stores (null) must
 *        still succeed — stores are optional dependencies.
 */
TEST_F(AntiEvasionStoreFixture, DebuggerDetector_NoStores_StillInitializes) {
    SKIP_IF_STORES_NOT_READY();

    DED detector;
    ASSERT_TRUE(detector.Initialize());
    EXPECT_TRUE(detector.IsInitialized());
    detector.Shutdown();
}

/**
 * @brief After Shutdown(), IsInitialized() must return false.
 */
TEST_F(AntiEvasionStoreFixture, DebuggerDetector_ShutdownClearsInit) {
    SKIP_IF_STORES_NOT_READY();

    DED detector(s_sigStore, s_tiStore);
    ASSERT_TRUE(detector.Initialize());
    detector.Shutdown();
    EXPECT_FALSE(detector.IsInitialized())
        << "IsInitialized() must return false after Shutdown().";
}

/**
 * @brief ResetStatistics() after initialization must not crash, and
 *        GetStatistics() must return a usable snapshot.
 */
TEST_F(AntiEvasionStoreFixture, DebuggerDetector_Statistics_ResetAndRead) {
    SKIP_IF_STORES_NOT_READY();

    DED detector(s_sigStore, s_tiStore);
    ASSERT_TRUE(detector.Initialize());

    ASSERT_NO_THROW(detector.ResetStatistics());
    ASSERT_NO_THROW({ auto snap = detector.GetStatistics(); (void)snap; });

    detector.Shutdown();
}

// ============================================================================
// GROUP 14 — VMEvasionDetector Store Wiring
// ============================================================================

/**
 * @brief VMEvasionDetector constructed with ThreatIntelStore must survive
 *        construction and config access.
 */
TEST_F(AntiEvasionStoreFixture, VMDetector_ConstructWithTIStore_Usable) {
    SKIP_IF_STORES_NOT_READY();

    ASSERT_NO_THROW({
        VMED detector(s_tiStore);
        const auto cfg = detector.GetConfig();
        EXPECT_GE(cfg.minimumConfidenceThreshold, 0.0f);
    });
}

/**
 * @brief VMEvasionDetector constructed with both stores must survive
 *        construction and config round-trip.
 */
TEST_F(AntiEvasionStoreFixture, VMDetector_ConstructWithBothStores_Usable) {
    SKIP_IF_STORES_NOT_READY();

    ASSERT_NO_THROW({
        VMED detector(s_tiStore, s_sigStore);
        const auto cfg = detector.GetConfig();
        EXPECT_GE(cfg.minimumConfidenceThreshold, 0.0f);
    });
}

/**
 * @brief GetStatistics and ResetStatistics must be usable after construction.
 */
TEST_F(AntiEvasionStoreFixture, VMDetector_Statistics_AccessSafe) {
    SKIP_IF_STORES_NOT_READY();

    VMED detector(s_tiStore, s_sigStore);
    ASSERT_NO_THROW({
        detector.ResetStatistics();
        const auto& stats = detector.GetStatistics();
        (void)stats;
    });
}

/**
 * @brief InvalidateCache must not crash when called on a freshly constructed
 *        detector (no prior scan results to invalidate).
 */
TEST_F(AntiEvasionStoreFixture, VMDetector_InvalidateCache_NoCrash) {
    SKIP_IF_STORES_NOT_READY();

    VMED detector(s_tiStore);
    ASSERT_NO_THROW(detector.InvalidateCache());
    EXPECT_FALSE(detector.IsCacheValid())
        << "IsCacheValid() must return false immediately after InvalidateCache().";
}
