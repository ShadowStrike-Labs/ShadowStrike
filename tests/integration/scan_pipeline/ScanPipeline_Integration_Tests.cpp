/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Integration Tests - Tier 1: Core Scan Pipeline
 *
 * ============================================================================
 * PURPOSE
 * ============================================================================
 * This file tests the real, production integration between the Tier-1 modules
 * that form the heart of every file-scan decision:
 *
 *   SignatureStore  (HashStore + PatternStore + YaraRuleStore facade)
 *   ThreatIntelStore  (hash / domain / IP IOC lookups)
 *   WhitelistStore    (hash and path bypass)
 *
 * No mocks. No stubs. Every test exercises real, disk-backed databases.
 *
 * ============================================================================
 * TEST GROUPS
 * ============================================================================
 *   GROUP 1  HashDetection        - SHA-256 lookup via SignatureStore facade
 *   GROUP 2  PatternDetection     - byte-pattern detection via SignatureStore
 *   GROUP 3  YaraDetection        - YARA rule matching via SignatureStore
 *   GROUP 4  ThreatIntelIOC       - IOC lookups (hash, domain, IPv4)
 *   GROUP 5  WhitelistIntegration - hash/path whitelisting & bypass protocol
 *   GROUP 6  ScanMechanics        - options, metadata, edge cases, cache
 *   GROUP 7  DetectionCallback    - real-time callback wiring
 *   GROUP 8  ConcurrencySafety    - 8-thread simultaneous scan validation
 *
 * ============================================================================
 * SUITE SETUP  (once per suite, not per test)
 * ============================================================================
 *   1. YaraRuleStore::InitializeYara()
 *   2. Create a unique temporary directory (PID + atomic counter)
 *   3. Create sub-store databases: hash.hdb / pattern.pdb / yara.ydb
 *   4. Open SignatureStore via InitializeMulti (readOnly=false)
 *   5. Seed:
 *        - SHA-256 of kHashPayload as Critical-level malware hash
 *        - "SHADOWSTRIKE_PATTERN_TEST_001" as High-level pattern
 *        - YARA rule matching "SHADOWSTRIKE_YARA_TEST_MARKER_001"
 *   6. Create WhitelistStore (whitelist.wdb); seed kHashPayload hash +
 *      a known-clean directory path as whitelisted entries
 *   7. Initialize ThreatIntelStore (LowMemory config); seed:
 *        - SHA-256 hex of kMaliciousIntelPayload as Malicious FileHash IOC
 *        - SHA-256 hex of kSafeIntelPayload      as Safe     FileHash IOC
 *        - "malicious-test.shadowstrike.internal" as Malicious Domain IOC
 *        - "198.51.100.42" as Malicious IPv4 IOC (TEST-NET-3, RFC 5737)
 *
 * ============================================================================
 * TEARDOWN
 * ============================================================================
 *   All stores closed; temp directory deleted recursively.
 *
 * ============================================================================
 * NAMESPACE NOTES
 * ============================================================================
 *   ShadowStrike::SignatureStore::HashValue  (alignas(8), 72 bytes)
 *   ShadowStrike::Whitelist::HashValue       (alignas(4), 68 bytes)
 *   These are DISTINCT types - never interchange them.
 */

// ============================================================================
// WINDOWS + STANDARD HEADERS
// ============================================================================
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "pch.h"

#include <windows.h>

#include <array>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <mutex>
#include <span>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// ============================================================================
// GOOGLETEST
// ============================================================================
#include <gtest/gtest.h>

// ============================================================================
// SHADOWSTRIKE SHARED-MODULE HEADERS (relative to repo root)
// ============================================================================
#include "../../../src/PhantomCore/SignatureStore/SignatureFormat.hpp"
#include "../../../src/PhantomCore/SignatureStore/SignatureStore.hpp"
#include "../../../src/PhantomCore/SignatureStore/YaraRuleStore.hpp"
#include "../../../src/PhantomCore/HashStore/HashStore.hpp"
#include "../../../src/PhantomCore/PatternStore/PatternStore.hpp"
#include "../../../src/PhantomCore/ThreatIntel/ThreatIntelFormat.hpp"
#include "../../../src/PhantomCore/ThreatIntel/ThreatIntelStore.hpp"
#include "../../../src/PhantomCore/Whitelist/WhiteListFormat.hpp"
#include "../../../src/PhantomCore/Whitelist/WhiteListStore.hpp"
#include "../../../src/PhantomCore/Utils/HashUtils.hpp"

// ============================================================================
// CONVENIENCE NAMESPACE ALIASES
// ============================================================================
namespace SS  = ShadowStrike::SignatureStore;
namespace WL  = ShadowStrike::Whitelist;
namespace TI  = ShadowStrike::ThreatIntel;
namespace HU  = ShadowStrike::Utils::HashUtils;

// ============================================================================
// TEST CONSTANTS
// ============================================================================
namespace IntegrationTestData {

    // -----------------------------------------------------------------------
    // Hash-detection payload.
    // This exact 128-byte buffer is SHA-256 hashed in SetUpTestSuite and its
    // digest is registered in SignatureStore as a Critical-level detection.
    // Must NOT contain the pattern or YARA markers below.
    // -----------------------------------------------------------------------
    static constexpr std::array<uint8_t, 128> kHashPayload = {{
        0xDE,0xAD,0xBE,0xEF, 0xCA,0xFE,0xBA,0xBE,
        0x01,0x23,0x45,0x67, 0x89,0xAB,0xCD,0xEF,
        0xFE,0xDC,0xBA,0x98, 0x76,0x54,0x32,0x10,
        0xAA,0xBB,0xCC,0xDD, 0xEE,0xFF,0x00,0x11,
        0x22,0x33,0x44,0x55, 0x66,0x77,0x88,0x99,
        0xA0,0xB0,0xC0,0xD0, 0xE0,0xF0,0x0A,0x0B,
        0x0C,0x0D,0x0E,0x0F, 0x10,0x20,0x30,0x40,
        0x50,0x60,0x70,0x80, 0x90,0xA1,0xB1,0xC1,
        0xD1,0xE1,0xF1,0x02, 0x13,0x24,0x35,0x46,
        0x57,0x68,0x79,0x8A, 0x9B,0xAC,0xBD,0xCE,
        0xDF,0xE0,0xF1,0x02, 0x13,0x24,0x35,0x46,
        0x57,0x68,0x79,0x8A, 0x9B,0xAC,0xBD,0xCE,
        0x11,0x22,0x33,0x44, 0x55,0x66,0x77,0x88,
        0x99,0xAA,0xBB,0xCC, 0xDD,0xEE,0xFF,0x00,
        0x01,0x02,0x03,0x04, 0x05,0x06,0x07,0x08,
        0x09,0x0A,0x0B,0x0C, 0x0D,0x0E,0x0F,0x10
    }};

    // -----------------------------------------------------------------------
    // ThreatIntel malicious payload.
    // SHA-256 hex is seeded in ThreatIntelStore as a Malicious FileHash IOC.
    // Intentionally distinct from kHashPayload to keep test groups independent.
    // -----------------------------------------------------------------------
    static constexpr std::array<uint8_t, 64> kMaliciousIntelPayload = {{
        0xBA,0xD0,0xC0,0xDE, 0xBA,0xD0,0xC0,0xDE,
        0xBA,0xD0,0xC0,0xDE, 0xBA,0xD0,0xC0,0xDE,
        0x11,0x22,0x33,0x44, 0x55,0x66,0x77,0x88,
        0x99,0xAA,0xBB,0xCC, 0xDD,0xEE,0xFF,0xBA,
        0xAD,0xBE,0xEF,0xCA, 0xFE,0xBE,0xEF,0xCA,
        0xFE,0xBE,0xEF,0xCA, 0xFE,0xBE,0xEF,0xCA,
        0x00,0x11,0x22,0x33, 0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB, 0xCC,0xDD,0xEE,0xFF
    }};

    // -----------------------------------------------------------------------
    // ThreatIntel safe payload.
    // SHA-256 hex is seeded in ThreatIntelStore as a Safe FileHash IOC.
    // -----------------------------------------------------------------------
    static constexpr std::array<uint8_t, 64> kSafeIntelPayload = {{
        0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B, 0x1C,0x1D,0x1E,0x1F,
        0x20,0x21,0x22,0x23, 0x24,0x25,0x26,0x27,
        0x28,0x29,0x2A,0x2B, 0x2C,0x2D,0x2E,0x2F,
        0x30,0x31,0x32,0x33, 0x34,0x35,0x36,0x37,
        0x38,0x39,0x3A,0x3B, 0x3C,0x3D,0x3E,0x3F
    }};

    // Exact byte sequence registered in PatternStore (29 ASCII chars).
    static constexpr char kPatternMarker[] = "SHADOWSTRIKE_PATTERN_TEST_001";

    // Marker string embedded in kYaraPayload; matched by the YARA rule below (33 ASCII chars).
    static constexpr char kYaraMarker[]    = "SHADOWSTRIKE_YARA_TEST_MARKER_001";

    // YARA rule source that matches kYaraMarker.
    static constexpr char kYaraRuleSource[] =
        "rule ShadowStrike_Integration_YaraTest\n"
        "{\n"
        "    meta:\n"
        "        description = \"Integration test rule - matches YARA test marker\"\n"
        "        severity = \"high\"\n"
        "    strings:\n"
        "        $marker = \"SHADOWSTRIKE_YARA_TEST_MARKER_001\"\n"
        "    condition:\n"
        "        $marker\n"
        "}\n";

    // Malicious domain and IPv4 seeded in ThreatIntelStore.
    // IPv4 uses TEST-NET-3 (198.51.100.0/24, RFC 5737) - never routable.
    static constexpr char  kMaliciousDomain[]  = "malicious-test.shadowstrike.internal";
    static constexpr char  kMaliciousIPv4[]    = "198.51.100.42";

    // Whitelisted directory path (registered with Prefix match mode).
    static constexpr wchar_t kWhitelistedDirPath[] =
        L"C:\\ShadowStrike\\TrustedSoftware\\";

} // namespace IntegrationTestData

// ============================================================================
// SCOPED TEMP DIRECTORY (RAII)
// ============================================================================
class ScopedTempDir {
public:
    ScopedTempDir() {
        wchar_t base[MAX_PATH];
        const DWORD len = GetTempPathW(static_cast<DWORD>(std::size(base)), base);
        if (len == 0 || len >= static_cast<DWORD>(std::size(base))) return;

        static std::atomic<uint32_t> s_counter{0};
        m_path = std::wstring(base)
                 + L"SS_IntTier1_"
                 + std::to_wstring(GetCurrentProcessId())
                 + L"_"
                 + std::to_wstring(s_counter.fetch_add(1, std::memory_order_relaxed));

        if (!CreateDirectoryW(m_path.c_str(), nullptr)) {
            m_path.clear();
        }
    }

    ~ScopedTempDir() noexcept {
        if (!m_path.empty()) {
            std::error_code ec;
            std::filesystem::remove_all(m_path, ec);
        }
    }

    ScopedTempDir(const ScopedTempDir&) = delete;
    ScopedTempDir& operator=(const ScopedTempDir&) = delete;

    ScopedTempDir(ScopedTempDir&& o) noexcept : m_path(std::move(o.m_path)) {
        o.m_path.clear();
    }
    ScopedTempDir& operator=(ScopedTempDir&& o) noexcept {
        if (this != &o) {
            if (!m_path.empty()) {
                std::error_code ec;
                std::filesystem::remove_all(m_path, ec);
            }
            m_path = std::move(o.m_path);
            o.m_path.clear();
        }
        return *this;
    }

    [[nodiscard]] bool           Valid() const noexcept { return !m_path.empty(); }
    [[nodiscard]] const std::wstring& Path()  const noexcept { return m_path; }

    /// Returns a fully-qualified path to a file inside this directory.
    [[nodiscard]] std::wstring Child(const std::wstring& name) const {
        return m_path + L"\\" + name;
    }

private:
    std::wstring m_path;
};

// ============================================================================
// SHA-256 HELPER UTILITIES
// ============================================================================
namespace HashHelpers {

    /// Compute SHA-256 of a byte span; returns 32-byte vector or empty on failure.
    [[nodiscard]] static std::vector<uint8_t>
    ComputeSHA256Bytes(std::span<const uint8_t> data) {
        HU::Hasher h(HU::Algorithm::SHA256);
        if (!h.Init())                        return {};
        if (!h.Update(data.data(), data.size())) return {};
        std::vector<uint8_t> digest;
        if (!h.Final(digest))                 return {};
        return digest;
    }

    /// Compute SHA-256 of a byte span; returns lowercase hex string or empty on failure.
    /// Used for ThreatIntelStore IOC seeding which accepts hex strings.
    [[nodiscard]] static std::string
    ComputeSHA256Hex(std::span<const uint8_t> data) {
        HU::Hasher h(HU::Algorithm::SHA256);
        if (!h.Init())                           return {};
        if (!h.Update(data.data(), data.size())) return {};
        std::string hex;
        if (!h.FinalHex(hex, /*upper=*/false))   return {};
        return hex;
    }

    /// Wrap a 32-byte SHA-256 digest into ShadowStrike::SignatureStore::HashValue.
    [[nodiscard]] static SS::HashValue
    MakeSigStoreHashValue(const std::vector<uint8_t>& digest) {
        SS::HashValue hv{};
        hv.type   = SS::HashType::SHA256;
        hv.length = static_cast<uint8_t>(
            (std::min)(digest.size(), static_cast<size_t>(32u)));
        std::memcpy(hv.data.data(), digest.data(), hv.length);
        return hv;
    }

    /// Wrap a 32-byte SHA-256 digest into ShadowStrike::Whitelist::HashValue.
    [[nodiscard]] static WL::HashValue
    MakeWhitelistHashValue(const std::vector<uint8_t>& digest) {
        return WL::HashValue::Create(
            WL::HashAlgorithm::SHA256,
            digest.data(),
            static_cast<uint8_t>(
                (std::min)(digest.size(), static_cast<size_t>(32u))));
    }

    /// Build a test buffer: 64 bytes of header junk, embedded pattern/marker, 32 bytes of footer junk.
    [[nodiscard]] static std::vector<uint8_t>
    BuildMarkerPayload(const char* markerStr) {
        const size_t markerLen = std::strlen(markerStr);
        std::vector<uint8_t> buf(64u + markerLen + 32u);
        for (size_t i = 0; i < 64u; ++i)
            buf[i] = static_cast<uint8_t>((i + 0xF0u) & 0xFFu);
        std::memcpy(buf.data() + 64u, markerStr, markerLen);
        for (size_t i = 64u + markerLen; i < buf.size(); ++i)
            buf[i] = static_cast<uint8_t>((i * 3u + 7u) & 0xFFu);
        return buf;
    }

} // namespace HashHelpers

// ============================================================================
// SKIP GUARD MACRO
// ============================================================================
// Applied at the top of every TEST_F body.  If suite setup failed, the test
// is skipped with a descriptive message rather than crashing on a null store.
#define SKIP_IF_NOT_READY()                                               \
    do {                                                                  \
        if (!ScanPipelineFixture::s_setupSucceeded) {                     \
            GTEST_SKIP() << "Suite setup failed; skipping test.";         \
        }                                                                 \
    } while (false)

// ============================================================================
// TEST FIXTURE
// ============================================================================
class ScanPipelineFixture : public ::testing::Test {
protected:
    // Suite-level resources (shared across all tests - all reads, setup only once).
    static std::unique_ptr<SS::SignatureStore>     s_sigStore;
    static std::unique_ptr<WL::WhitelistStore>     s_wlStore;
    static std::unique_ptr<TI::ThreatIntelStore>   s_tiStore;
    static ScopedTempDir                           s_tempDir;

    // Computed payloads (built once in SetUpTestSuite from kXxx constants).
    static std::vector<uint8_t>  s_patternPayload;
    static std::vector<uint8_t>  s_yaraPayload;

    // Hex strings of seeded IOC payloads (needed for lookup calls).
    static std::string  s_maliciousIntelHex;
    static std::string  s_safeIntelHex;

    // Whitelist hash of kHashPayload (WL::HashValue form).
    static WL::HashValue  s_hashPayloadWlHash;

    // Benign 256-byte zero buffer used for negative tests.
    static std::array<uint8_t, 256>  s_benignPayload;

    // Sentinel: false if SetUpTestSuite encountered any error.
    static bool s_setupSucceeded;

public:
    void SetUp() override {
        if (s_sigStore) {
            s_sigStore->ClearQueryCache();
            s_sigStore->ClearResultCache();
            s_sigStore->RegisterDetectionCallback({});
        }
    }

    // -------------------------------------------------------------------------
    // SetUpTestSuite: runs once before all tests in this fixture.
    // -------------------------------------------------------------------------
    static void SetUpTestSuite() {
        using namespace IntegrationTestData;

        s_setupSucceeded = false;
        s_benignPayload.fill(0);

        // 1. Build dynamic payloads.
        s_patternPayload = HashHelpers::BuildMarkerPayload(kPatternMarker);
        s_yaraPayload    = HashHelpers::BuildMarkerPayload(kYaraMarker);

        // 2. Create temp directory.
        s_tempDir = ScopedTempDir();
        if (!s_tempDir.Valid()) {
            ADD_FAILURE() << "Failed to create temporary directory for integration tests.";
            return;
        }

        const std::wstring hashPath    = s_tempDir.Child(L"hash.hdb");
        const std::wstring patternPath = s_tempDir.Child(L"pattern.pdb");
        const std::wstring yaraPath    = s_tempDir.Child(L"yara.ydb");
        const std::wstring wlPath      = s_tempDir.Child(L"whitelist.wdb");

        // 3. Initialize YARA global state (must precede any YaraRuleStore::CreateNew).
        if (!SS::YaraRuleStore::InitializeYara().IsSuccess()) {
            ADD_FAILURE() << "YaraRuleStore::InitializeYara() returned failure.";
            return;
        }

        // 4. Create the three backing stores on disk.  The SignatureStore facade is
        // seeded after it opens these databases so the test exercises the live
        // facade/write path rather than relying on cross-instance persistence.
        {
            ShadowStrike::HashStore::HashStore hs;
            ShadowStrike::PatternStore::PatternStore ps;
            SS::YaraRuleStore yr;

            if (!hs.CreateNew(hashPath).IsSuccess()) {
                ADD_FAILURE() << "HashStore::CreateNew() failed.";
                return;
            }
            if (!ps.CreateNew(patternPath).IsSuccess()) {
                ADD_FAILURE() << "PatternStore::CreateNew() failed.";
                return;
            }
            if (!yr.CreateNew(yaraPath).IsSuccess()) {
                ADD_FAILURE() << "YaraRuleStore::CreateNew() failed.";
                return;
            }

            hs.Close();
            ps.Close();
            yr.Close();
        }

        // 5. Open SignatureStore facade over the seeded backing stores.
        s_sigStore = std::make_unique<SS::SignatureStore>();
        SS::StoreError initErr = s_sigStore->InitializeMulti(
            hashPath, patternPath, yaraPath, /*readOnly=*/false);
        if (!initErr.IsSuccess()) {
            ADD_FAILURE() << "SignatureStore::InitializeMulti() failed. code="
                          << static_cast<uint32_t>(initErr.code)
                          << " win32=" << initErr.win32Error
                          << " message=" << initErr.message;
            s_sigStore.reset();
            return;
        }

        // 6. Seed the live SignatureStore facade with one hash, one exact-byte
        // pattern, and one YARA rule so subsequent scans exercise the same
        // instances that the tests query.
        {
            const auto digest = HashHelpers::ComputeSHA256Bytes(
                std::span<const uint8_t>(kHashPayload.data(), kHashPayload.size()));
            if (digest.empty()) {
                ADD_FAILURE() << "SHA-256 computation failed for kHashPayload.";
                return;
            }

            const SS::HashValue hv = HashHelpers::MakeSigStoreHashValue(digest);
            const SS::StoreError hashErr = s_sigStore->AddHash(
                hv,
                "Test.Malware.HashPayload.SHA256",
                SS::ThreatLevel::Critical,
                "Integration-test hash entry");
            if (!hashErr.IsSuccess()) {
                ADD_FAILURE() << "SignatureStore::AddHash() failed. code="
                              << static_cast<uint32_t>(hashErr.code)
                              << " win32=" << hashErr.win32Error
                              << " message=" << hashErr.message;
                return;
            }

            const std::string patternHex =
                ShadowStrike::PatternStore::PatternUtils::BytesToHexString(
                    std::span<const uint8_t>(
                        reinterpret_cast<const uint8_t*>(kPatternMarker),
                        std::strlen(kPatternMarker)));
            const SS::StoreError patternErr = s_sigStore->AddPattern(
                patternHex,
                "Test.Malware.PatternMarker",
                SS::ThreatLevel::High,
                "Integration-test pattern");
            if (!patternErr.IsSuccess()) {
                ADD_FAILURE() << "SignatureStore::AddPattern() failed. code="
                              << static_cast<uint32_t>(patternErr.code)
                              << " win32=" << patternErr.win32Error
                              << " message=" << patternErr.message;
                return;
            }

            const SS::StoreError yaraErr = s_sigStore->AddYaraRule(
                std::string(kYaraRuleSource),
                "YaraIntegrationRuleSet");
            if (!yaraErr.IsSuccess()) {
                ADD_FAILURE() << "SignatureStore::AddYaraRule() failed. code="
                              << static_cast<uint32_t>(yaraErr.code)
                              << " win32=" << yaraErr.win32Error
                              << " message=" << yaraErr.message;
                return;
            }
        }

        // 7. Create WhitelistStore.
        {
            s_wlStore = std::make_unique<WL::WhitelistStore>();
            WL::StoreError wlErr = s_wlStore->Create(wlPath);
            if (!wlErr.IsSuccess()) {
                ADD_FAILURE() << "WhitelistStore::Create() failed.";
                s_wlStore.reset();
                return;
            }
        }

        // 8. Seed WhitelistStore: kHashPayload hash (trusted binary).
        {
            const auto digest = HashHelpers::ComputeSHA256Bytes(
                std::span<const uint8_t>(kHashPayload.data(), kHashPayload.size()));
            if (digest.empty()) {
                ADD_FAILURE() << "SHA-256 computation failed for whitelist seeding.";
                return;
            }
            s_hashPayloadWlHash = HashHelpers::MakeWhitelistHashValue(digest);
            WL::StoreError err = s_wlStore->AddHash(
                s_hashPayloadWlHash,
                WL::WhitelistReason::UserApproved,
                L"Integration test: hash of kHashPayload whitelisted as trusted binary");
            if (!err.IsSuccess()) {
                ADD_FAILURE() << "WhitelistStore::AddHash() failed.";
                return;
            }
        }

        // 9. Seed WhitelistStore: trusted directory path.
        {
            WL::StoreError err = s_wlStore->AddPath(
                kWhitelistedDirPath,
                WL::PathMatchMode::Prefix,
                WL::WhitelistReason::PolicyBased,
                L"Integration test: trusted software directory");
            if (!err.IsSuccess()) {
                ADD_FAILURE() << "WhitelistStore::AddPath() failed.";
                return;
            }
        }

        // 10. Initialize ThreatIntelStore.
        {
            TI::StoreConfig cfg = TI::StoreConfig::CreateLowMemory();
            auto ti = std::make_unique<TI::ThreatIntelStore>();
            if (!ti->Initialize(cfg)) {
                ADD_FAILURE() << "ThreatIntelStore::Initialize() failed.";
                return;
            }
            s_tiStore = std::move(ti);
        }

        // 11. Seed ThreatIntelStore: malicious hash IOC.
        {
            s_maliciousIntelHex = HashHelpers::ComputeSHA256Hex(
                std::span<const uint8_t>(kMaliciousIntelPayload.data(),
                                         kMaliciousIntelPayload.size()));
            if (s_maliciousIntelHex.empty()) {
                ADD_FAILURE() << "SHA-256 hex computation failed for malicious intel payload.";
                return;
            }
            if (!s_tiStore->AddIOC(
                    TI::IOCType::FileHash,
                    s_maliciousIntelHex,
                    TI::ReputationLevel::Malicious,
                    TI::ThreatIntelSource::InternalAnalysis)) {
                ADD_FAILURE() << "ThreatIntelStore::AddIOC() failed for malicious hash.";
                return;
            }
        }

        // 12. Seed ThreatIntelStore: safe hash IOC.
        {
            s_safeIntelHex = HashHelpers::ComputeSHA256Hex(
                std::span<const uint8_t>(kSafeIntelPayload.data(),
                                         kSafeIntelPayload.size()));
            if (s_safeIntelHex.empty()) {
                ADD_FAILURE() << "SHA-256 hex computation failed for safe intel payload.";
                return;
            }
            if (!s_tiStore->AddIOC(
                    TI::IOCType::FileHash,
                    s_safeIntelHex,
                    TI::ReputationLevel::Safe,
                    TI::ThreatIntelSource::InternalAnalysis)) {
                ADD_FAILURE() << "ThreatIntelStore::AddIOC() failed for safe hash.";
                return;
            }
        }

        // 13. Seed ThreatIntelStore: malicious domain.
        {
            if (!s_tiStore->AddIOC(
                    TI::IOCType::Domain,
                    kMaliciousDomain,
                    TI::ReputationLevel::Malicious,
                    TI::ThreatIntelSource::InternalAnalysis)) {
                ADD_FAILURE() << "ThreatIntelStore::AddIOC() failed for malicious domain.";
                return;
            }
        }

        // 14. Seed ThreatIntelStore: malicious IPv4.
        {
            if (!s_tiStore->AddIOC(
                    TI::IOCType::IPv4,
                    kMaliciousIPv4,
                    TI::ReputationLevel::Malicious,
                    TI::ThreatIntelSource::InternalAnalysis)) {
                ADD_FAILURE() << "ThreatIntelStore::AddIOC() failed for malicious IPv4.";
                return;
            }
        }

        s_setupSucceeded = true;
    }

    // -------------------------------------------------------------------------
    // TearDownTestSuite: runs once after all tests in this fixture.
    // -------------------------------------------------------------------------
    static void TearDownTestSuite() {
        s_sigStore.reset();
        s_wlStore.reset();
        s_tiStore.reset();
        // s_tempDir destructor removes the directory.
    }
};

// ============================================================================
// STATIC MEMBER DEFINITIONS
// ============================================================================
std::unique_ptr<SS::SignatureStore>    ScanPipelineFixture::s_sigStore;
std::unique_ptr<WL::WhitelistStore>    ScanPipelineFixture::s_wlStore;
std::unique_ptr<TI::ThreatIntelStore>  ScanPipelineFixture::s_tiStore;
ScopedTempDir                          ScanPipelineFixture::s_tempDir;
std::vector<uint8_t>                   ScanPipelineFixture::s_patternPayload;
std::vector<uint8_t>                   ScanPipelineFixture::s_yaraPayload;
std::string                            ScanPipelineFixture::s_maliciousIntelHex;
std::string                            ScanPipelineFixture::s_safeIntelHex;
WL::HashValue                          ScanPipelineFixture::s_hashPayloadWlHash{};
std::array<uint8_t, 256>               ScanPipelineFixture::s_benignPayload{};
bool                                   ScanPipelineFixture::s_setupSucceeded = false;

// ============================================================================
// GROUP 1: HASH DETECTION
// ============================================================================
// Tests that SignatureStore correctly identifies kHashPayload through its
// SHA-256 hash lookup sub-system.
// ============================================================================

/// Scanning a buffer whose SHA-256 matches a seeded Critical hash must yield
/// at least one detection, and HasDetections() must return true.
TEST_F(ScanPipelineFixture, HashDetection_KnownMaliciousHash_DetectsCorrectly) {
    SKIP_IF_NOT_READY();
    using namespace IntegrationTestData;

    SS::ScanOptions opts{};
    opts.enableHashLookup  = true;
    opts.enablePatternScan = false;
    opts.enableYaraScan    = false;

    const SS::ScanResult result = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(kHashPayload.data(), kHashPayload.size()), opts);

    EXPECT_TRUE(result.HasDetections())
        << "Expected a hash detection for kHashPayload but none was reported.";
    EXPECT_FALSE(result.hashMatches.empty())
        << "hashMatches should be non-empty when hash lookup triggers.";
}

/// Hash detections must preserve the authoritative threat level stored with the
/// seeded HashStore record.
TEST_F(ScanPipelineFixture, HashDetection_KnownMaliciousHash_ThreatLevelPreserved) {
    SKIP_IF_NOT_READY();
    using namespace IntegrationTestData;

    SS::ScanOptions opts{};
    opts.enableHashLookup  = true;
    opts.enablePatternScan = false;
    opts.enableYaraScan    = false;

    const SS::ScanResult result = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(kHashPayload.data(), kHashPayload.size()), opts);

    ASSERT_FALSE(result.hashMatches.empty());
    EXPECT_EQ(result.hashMatches.front().threatLevel, SS::ThreatLevel::Critical)
        << "Hash detections must preserve the seeded HashStore threat level.";
}

/// Hash detections must preserve the signature name stored in HashStore.
TEST_F(ScanPipelineFixture, HashDetection_KnownMaliciousHash_SignatureNamePopulated) {
    SKIP_IF_NOT_READY();
    using namespace IntegrationTestData;

    SS::ScanOptions opts{};
    opts.enableHashLookup  = true;
    opts.enablePatternScan = false;
    opts.enableYaraScan    = false;

    const SS::ScanResult result = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(kHashPayload.data(), kHashPayload.size()), opts);

    ASSERT_FALSE(result.hashMatches.empty());
    EXPECT_EQ(result.hashMatches.front().signatureName, "Test.Malware.HashPayload.SHA256")
        << "Hash detections must expose the seeded signature name.";
}

/// A benign all-zeros buffer must produce no hash detections.
TEST_F(ScanPipelineFixture, HashDetection_UnknownHash_NoDetection) {
    SKIP_IF_NOT_READY();

    SS::ScanOptions opts{};
    opts.enableHashLookup  = true;
    opts.enablePatternScan = false;
    opts.enableYaraScan    = false;

    const SS::ScanResult result = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(s_benignPayload.data(), s_benignPayload.size()), opts);

    EXPECT_FALSE(result.HasDetections())
        << "Benign buffer produced unexpected hash detections.";
    EXPECT_TRUE(result.hashMatches.empty());
}

/// Enabling only hash lookup must not produce pattern or YARA results, even
/// when the buffer contains embedded pattern/YARA markers (it does not here,
/// but the point is that the component switch is honoured).
TEST_F(ScanPipelineFixture, HashDetection_HashOnlyOption_PatternYaraDisabled) {
    SKIP_IF_NOT_READY();
    using namespace IntegrationTestData;

    SS::ScanOptions opts{};
    opts.enableHashLookup  = true;
    opts.enablePatternScan = false;
    opts.enableYaraScan    = false;

    const SS::ScanResult result = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(kHashPayload.data(), kHashPayload.size()), opts);

    EXPECT_TRUE(result.patternMatches.empty())
        << "patternMatches must be empty when enablePatternScan=false.";
    EXPECT_TRUE(result.yaraMatches.empty())
        << "yaraMatches must be empty when enableYaraScan=false.";
}

/// Disabling hash lookup must suppress hash detection entirely.
TEST_F(ScanPipelineFixture, HashDetection_HashDisabledViaOptions_NoHashDetection) {
    SKIP_IF_NOT_READY();
    using namespace IntegrationTestData;

    SS::ScanOptions opts{};
    opts.enableHashLookup  = false;
    opts.enablePatternScan = true;
    opts.enableYaraScan    = true;

    const SS::ScanResult result = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(kHashPayload.data(), kHashPayload.size()), opts);

    EXPECT_TRUE(result.hashMatches.empty())
        << "Hash matches must be suppressed when enableHashLookup=false.";
}

/// When stopOnFirstMatch=true and kHashPayload triggers a hash detection,
/// ScanResult::stoppedEarly must be true.
TEST_F(ScanPipelineFixture, HashDetection_StopOnFirstMatch_StopsEarly) {
    SKIP_IF_NOT_READY();
    using namespace IntegrationTestData;

    SS::ScanOptions opts{};
    opts.enableHashLookup  = true;
    opts.enablePatternScan = false;
    opts.enableYaraScan    = false;
    opts.stopOnFirstMatch  = true;

    const SS::ScanResult result = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(kHashPayload.data(), kHashPayload.size()), opts);

    EXPECT_TRUE(result.HasDetections());
    EXPECT_TRUE(result.stoppedEarly)
        << "stoppedEarly must be true when stopOnFirstMatch=true and a match was found.";
}

// ============================================================================
// GROUP 2: PATTERN DETECTION
// ============================================================================
// Tests that SignatureStore correctly identifies the embedded pattern marker
// in s_patternPayload through its byte-pattern scan sub-system.
// ============================================================================

/// Scanning s_patternPayload must yield at least one pattern detection.
TEST_F(ScanPipelineFixture, PatternDetection_KnownPattern_DetectsCorrectly) {
    SKIP_IF_NOT_READY();

    SS::ScanOptions opts{};
    opts.enableHashLookup  = false;
    opts.enablePatternScan = true;
    opts.enableYaraScan    = false;

    const SS::ScanResult result = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(s_patternPayload.data(), s_patternPayload.size()), opts);

    EXPECT_TRUE(result.HasDetections())
        << "Expected a pattern detection but HasDetections() returned false.";
    EXPECT_FALSE(result.patternMatches.empty())
        << "patternMatches must contain at least one entry.";
}

/// The fileOffset in the detection result must equal 64 because BuildMarkerPayload
/// places the marker at byte offset 64.
TEST_F(ScanPipelineFixture, PatternDetection_PatternAtOffset_OffsetPopulated) {
    SKIP_IF_NOT_READY();

    SS::ScanOptions opts{};
    opts.enableHashLookup  = false;
    opts.enablePatternScan = true;
    opts.enableYaraScan    = false;

    const SS::ScanResult result = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(s_patternPayload.data(), s_patternPayload.size()), opts);

    ASSERT_FALSE(result.patternMatches.empty());
    EXPECT_EQ(result.patternMatches.front().fileOffset, 64u)
        << "Pattern was embedded at offset 64; fileOffset must reflect this.";
}

/// A benign all-zeros buffer must produce no pattern detections.
TEST_F(ScanPipelineFixture, PatternDetection_PatternAbsent_NoDetection) {
    SKIP_IF_NOT_READY();

    SS::ScanOptions opts{};
    opts.enableHashLookup  = false;
    opts.enablePatternScan = true;
    opts.enableYaraScan    = false;

    const SS::ScanResult result = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(s_benignPayload.data(), s_benignPayload.size()), opts);

    EXPECT_TRUE(result.patternMatches.empty())
        << "No pattern should match an all-zero benign buffer.";
}

/// Setting enablePatternScan=false must suppress pattern detections even when
/// the pattern is present in the buffer.
TEST_F(ScanPipelineFixture, PatternDetection_PatternDisabledViaOptions_NoPatternDetection) {
    SKIP_IF_NOT_READY();

    SS::ScanOptions opts{};
    opts.enableHashLookup  = false;
    opts.enablePatternScan = false;
    opts.enableYaraScan    = false;

    const SS::ScanResult result = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(s_patternPayload.data(), s_patternPayload.size()), opts);

    EXPECT_TRUE(result.patternMatches.empty())
        << "patternMatches must be empty when enablePatternScan=false.";
}

/// The ThreatLevel in the pattern detection must match the High level seeded.
TEST_F(ScanPipelineFixture, PatternDetection_PatternThreatLevel_MatchesSeeded) {
    SKIP_IF_NOT_READY();

    SS::ScanOptions opts{};
    opts.enableHashLookup  = false;
    opts.enablePatternScan = true;
    opts.enableYaraScan    = false;

    const SS::ScanResult result = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(s_patternPayload.data(), s_patternPayload.size()), opts);

    ASSERT_FALSE(result.patternMatches.empty());
    EXPECT_EQ(result.patternMatches.front().threatLevel, SS::ThreatLevel::High)
        << "Pattern was seeded with ThreatLevel::High; detection must preserve it.";
}

// ============================================================================
// GROUP 3: YARA DETECTION
// ============================================================================
// Tests that SignatureStore correctly executes the seeded YARA rule against
// s_yaraPayload which contains the YARA marker string.
// ============================================================================

/// Scanning s_yaraPayload must yield at least one YARA match.
TEST_F(ScanPipelineFixture, YaraDetection_KnownYaraRule_DetectsCorrectly) {
    SKIP_IF_NOT_READY();

    SS::ScanOptions opts{};
    opts.enableHashLookup  = false;
    opts.enablePatternScan = false;
    opts.enableYaraScan    = true;

    const SS::ScanResult result = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(s_yaraPayload.data(), s_yaraPayload.size()), opts);

    EXPECT_TRUE(result.HasDetections())
        << "YARA scan of marker-containing payload must report a detection.";
    EXPECT_FALSE(result.yaraMatches.empty())
        << "yaraMatches must be non-empty after a successful YARA match.";
}

/// The ruleName field in the first YaraMatch must equal the name from the
/// seeded YARA rule source.
TEST_F(ScanPipelineFixture, YaraDetection_YaraMatch_RuleNamePopulated) {
    SKIP_IF_NOT_READY();

    SS::ScanOptions opts{};
    opts.enableHashLookup  = false;
    opts.enablePatternScan = false;
    opts.enableYaraScan    = true;

    const SS::ScanResult result = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(s_yaraPayload.data(), s_yaraPayload.size()), opts);

    ASSERT_FALSE(result.yaraMatches.empty());
    EXPECT_EQ(result.yaraMatches.front().ruleName, "ShadowStrike_Integration_YaraTest")
        << "YARA match must report the exact rule name from the source.";
}

/// A benign all-zeros buffer must not trigger the YARA rule.
TEST_F(ScanPipelineFixture, YaraDetection_YaraMarkerAbsent_NoDetection) {
    SKIP_IF_NOT_READY();

    SS::ScanOptions opts{};
    opts.enableHashLookup  = false;
    opts.enablePatternScan = false;
    opts.enableYaraScan    = true;

    const SS::ScanResult result = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(s_benignPayload.data(), s_benignPayload.size()), opts);

    EXPECT_TRUE(result.yaraMatches.empty())
        << "YARA rule must not fire on an all-zero benign buffer.";
}

/// Setting enableYaraScan=false must suppress YARA matches even when the
/// marker is present in the buffer.
TEST_F(ScanPipelineFixture, YaraDetection_YaraDisabledViaOptions_NoYaraDetection) {
    SKIP_IF_NOT_READY();

    SS::ScanOptions opts{};
    opts.enableHashLookup  = false;
    opts.enablePatternScan = false;
    opts.enableYaraScan    = false;

    const SS::ScanResult result = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(s_yaraPayload.data(), s_yaraPayload.size()), opts);

    EXPECT_TRUE(result.yaraMatches.empty())
        << "yaraMatches must be empty when enableYaraScan=false.";
}

// ============================================================================
// GROUP 4: THREAT INTEL IOC LOOKUPS
// ============================================================================
// Tests that ThreatIntelStore correctly resolves seeded hash, domain, and IPv4
// IOCs and correctly reports unknown ones as not-found.
// ============================================================================

/// Looking up the SHA-256 hex of kMaliciousIntelPayload must return
/// IsMalicious()=true and found=true.
TEST_F(ScanPipelineFixture, ThreatIntelIOC_HashLookup_MaliciousHash_IsMalicious) {
    SKIP_IF_NOT_READY();

    const TI::StoreLookupResult result =
        s_tiStore->LookupHash("SHA256", s_maliciousIntelHex);

    EXPECT_TRUE(result.found)
        << "Seeded malicious hash IOC must be found in ThreatIntelStore.";
    EXPECT_TRUE(result.IsMalicious())
        << "Seeded IOC has Malicious reputation; IsMalicious() must return true.";
}

/// Looking up the SHA-256 hex of kSafeIntelPayload must return
/// IsMalicious()=false, IsSuspicious()=false, and found=true.
TEST_F(ScanPipelineFixture, ThreatIntelIOC_HashLookup_SafeHash_NotMalicious) {
    SKIP_IF_NOT_READY();

    const TI::StoreLookupResult result =
        s_tiStore->LookupHash("SHA256", s_safeIntelHex);

    EXPECT_TRUE(result.found)
        << "Seeded safe hash IOC must be found in ThreatIntelStore.";
    EXPECT_FALSE(result.IsMalicious())
        << "Safe IOC must not be reported as malicious.";
    EXPECT_FALSE(result.IsSuspicious())
        << "Safe IOC must not be reported as suspicious.";
}

/// Looking up a completely unknown SHA-256 hex must return found=false.
TEST_F(ScanPipelineFixture, ThreatIntelIOC_HashLookup_UnknownHash_NotFound) {
    SKIP_IF_NOT_READY();

    // 64-char hex string that was never seeded.
    static constexpr char kUnknownHex[] =
        "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";

    const TI::StoreLookupResult result = s_tiStore->LookupHash("SHA256", kUnknownHex);

    EXPECT_FALSE(result.found)
        << "An un-seeded hash must not be found in ThreatIntelStore.";
}

/// Looking up the seeded malicious domain must return IsMalicious()=true.
TEST_F(ScanPipelineFixture, ThreatIntelIOC_DomainLookup_MaliciousDomain_IsMalicious) {
    SKIP_IF_NOT_READY();

    const TI::StoreLookupResult result =
        s_tiStore->LookupDomain(IntegrationTestData::kMaliciousDomain);

    EXPECT_TRUE(result.found)
        << "Seeded malicious domain must be found in ThreatIntelStore.";
    EXPECT_TRUE(result.IsMalicious())
        << "Seeded domain has Malicious reputation; IsMalicious() must return true.";
}

/// Looking up an unknown domain must return found=false.
TEST_F(ScanPipelineFixture, ThreatIntelIOC_DomainLookup_UnknownDomain_NotFound) {
    SKIP_IF_NOT_READY();

    const TI::StoreLookupResult result =
        s_tiStore->LookupDomain("benign.example.com");

    EXPECT_FALSE(result.found)
        << "Un-seeded domain must not be found in ThreatIntelStore.";
}

/// Looking up the seeded malicious IPv4 must return IsMalicious()=true.
TEST_F(ScanPipelineFixture, ThreatIntelIOC_IPv4Lookup_MaliciousIP_IsMalicious) {
    SKIP_IF_NOT_READY();

    const TI::StoreLookupResult result =
        s_tiStore->LookupIPv4(IntegrationTestData::kMaliciousIPv4);

    EXPECT_TRUE(result.found)
        << "Seeded malicious IPv4 must be found in ThreatIntelStore.";
    EXPECT_TRUE(result.IsMalicious())
        << "Seeded IPv4 has Malicious reputation; IsMalicious() must return true.";
}

/// Looking up an unknown IPv4 (loopback) must return found=false.
TEST_F(ScanPipelineFixture, ThreatIntelIOC_IPv4Lookup_UnknownIP_NotFound) {
    SKIP_IF_NOT_READY();

    const TI::StoreLookupResult result = s_tiStore->LookupIPv4("127.0.0.1");

    EXPECT_FALSE(result.found)
        << "Loopback address was never seeded; it must not be found.";
}

// ============================================================================
// GROUP 5: WHITELIST INTEGRATION
// ============================================================================
// Tests that WhitelistStore correctly handles seeded hash and path entries,
// and validates the bypass protocol: SignatureStore detects the hash while
// WhitelistStore overrides that decision at the caller level.
// ============================================================================

/// A hash that was explicitly whitelisted must be reported as found.
TEST_F(ScanPipelineFixture, WhitelistIntegration_HashWhitelisted_LookupReturnsFound) {
    SKIP_IF_NOT_READY();

    const WL::LookupResult result = s_wlStore->IsHashWhitelisted(s_hashPayloadWlHash);

    EXPECT_TRUE(result.found)
        << "The hash of kHashPayload was seeded as a trusted binary; lookup must return found=true.";
}

/// An arbitrary hash that was never whitelisted must not be found.
TEST_F(ScanPipelineFixture, WhitelistIntegration_HashNotWhitelisted_LookupReturnsFalse) {
    SKIP_IF_NOT_READY();

    // Construct a plausible but un-seeded SHA-256 whitelist entry.
    static constexpr uint8_t kUnknownDigest[32] = {
        0x99,0x88,0x77,0x66, 0x55,0x44,0x33,0x22,
        0x11,0x00,0xFF,0xEE, 0xDD,0xCC,0xBB,0xAA,
        0x99,0x88,0x77,0x66, 0x55,0x44,0x33,0x22,
        0x11,0x00,0xFF,0xEE, 0xDD,0xCC,0xBB,0xAA
    };
    const WL::HashValue unknownHash =
        WL::HashValue::Create(WL::HashAlgorithm::SHA256, kUnknownDigest, 32);

    const WL::LookupResult result = s_wlStore->IsHashWhitelisted(unknownHash);

    EXPECT_FALSE(result.found)
        << "Un-seeded hash must not be found in WhitelistStore.";
}

/// A path that starts with the whitelisted prefix must match when using
/// the Prefix match mode that was seeded.
TEST_F(ScanPipelineFixture, WhitelistIntegration_PathWhitelisted_PrefixMatch_LookupFound) {
    SKIP_IF_NOT_READY();

    const std::wstring childPath =
        std::wstring(IntegrationTestData::kWhitelistedDirPath) + L"child_binary.exe";

    const WL::LookupResult result = s_wlStore->IsPathWhitelisted(childPath);

    EXPECT_TRUE(result.found)
        << "A path under the whitelisted prefix must be found in WhitelistStore.";
}

/// A path that does NOT start with the whitelisted prefix must not match.
TEST_F(ScanPipelineFixture, WhitelistIntegration_PathNotWhitelisted_NonMatchingPath_NotFound) {
    SKIP_IF_NOT_READY();

    const WL::LookupResult result =
        s_wlStore->IsPathWhitelisted(L"C:\\Malware\\evil.exe");

    EXPECT_FALSE(result.found)
        << "A completely unrelated path must not match the whitelisted prefix.";
}

/// Bypass protocol test: SignatureStore detects kHashPayload as malicious, AND
/// WhitelistStore reports the same hash as trusted.  The caller is expected to
/// suppress the alert when both are true.  This test validates that both APIs
/// return the expected values simultaneously so that the combined decision
/// logic in the upper layers can be exercised.
TEST_F(ScanPipelineFixture, WhitelistIntegration_BypassProtocol_ScannerDetects_WhitelistOverrides) {
    SKIP_IF_NOT_READY();
    using namespace IntegrationTestData;

    // SignatureStore must detect.
    SS::ScanOptions opts{};
    opts.enableHashLookup  = true;
    opts.enablePatternScan = false;
    opts.enableYaraScan    = false;

    const SS::ScanResult scanResult = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(kHashPayload.data(), kHashPayload.size()), opts);

    EXPECT_TRUE(scanResult.HasDetections())
        << "SignatureStore must detect kHashPayload as malicious.";

    // WhitelistStore must say it is trusted (the bypass).
    const WL::LookupResult wlResult = s_wlStore->IsHashWhitelisted(s_hashPayloadWlHash);
    EXPECT_TRUE(wlResult.found)
        << "WhitelistStore must confirm kHashPayload is a trusted binary.";

    // The combined result: detection found AND whitelist found => suppress alert.
    // (No assertion on suppression here - that is upper-layer logic.  We only
    // verify both inputs are correct so the caller's decision is based on fact.)
    EXPECT_TRUE(scanResult.HasDetections() && wlResult.found)
        << "Both detection and whitelist override must be simultaneously true "
           "for the bypass protocol to function correctly.";
}

/// BatchLookupHashes must correctly identify known vs unknown hashes in one call.
TEST_F(ScanPipelineFixture, WhitelistIntegration_BatchHashLookup_MultipleHashes_CorrectResults) {
    SKIP_IF_NOT_READY();

    static constexpr uint8_t kUnknownDigest[32] = {
        0xAB,0xCD,0xEF,0x01, 0x23,0x45,0x67,0x89,
        0xAB,0xCD,0xEF,0x01, 0x23,0x45,0x67,0x89,
        0xAB,0xCD,0xEF,0x01, 0x23,0x45,0x67,0x89,
        0xAB,0xCD,0xEF,0x01, 0x23,0x45,0x67,0x89
    };
    const WL::HashValue unknownHash =
        WL::HashValue::Create(WL::HashAlgorithm::SHA256, kUnknownDigest, 32);

    const std::vector<WL::HashValue> batch = {s_hashPayloadWlHash, unknownHash};
    const std::vector<WL::LookupResult> results = s_wlStore->BatchLookupHashes(batch);

    ASSERT_EQ(results.size(), batch.size())
        << "BatchLookupHashes must return one result per input hash.";
    EXPECT_TRUE(results[0].found)
        << "First hash (kHashPayload) must be found - it was whitelisted.";
    EXPECT_FALSE(results[1].found)
        << "Second hash (unknown) must not be found - it was never seeded.";
}

// ============================================================================
// GROUP 6: SCAN MECHANICS
// ============================================================================
// Tests ScanOptions edge cases, metadata accuracy, cache behaviour, timeout
// configuration, and behaviour of an uninitialized store.
// ============================================================================

/// Scanning an empty span must not crash and must report no detections.
TEST_F(ScanPipelineFixture, ScanMechanics_EmptyBuffer_NoDetectionNoCrash) {
    SKIP_IF_NOT_READY();

    SS::ScanOptions opts{};
    opts.enableHashLookup  = true;
    opts.enablePatternScan = true;
    opts.enableYaraScan    = true;

    EXPECT_NO_FATAL_FAILURE({
        const SS::ScanResult result = s_sigStore->ScanBuffer(
            std::span<const uint8_t>{}, opts);
        EXPECT_FALSE(result.HasDetections())
            << "Empty buffer must not trigger any detection.";
    });
}

/// totalBytesScanned in ScanResult must equal the size of the scanned buffer.
TEST_F(ScanPipelineFixture, ScanMechanics_MetadataPopulated_TotalBytesScanned) {
    SKIP_IF_NOT_READY();

    SS::ScanOptions opts{};
    opts.enableHashLookup  = true;
    opts.enablePatternScan = true;
    opts.enableYaraScan    = true;

    const SS::ScanResult result = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(s_benignPayload.data(), s_benignPayload.size()), opts);

    EXPECT_EQ(result.totalBytesScanned, s_benignPayload.size())
        << "totalBytesScanned must equal the size of the input buffer.";
}

/// scanTimeMicroseconds must be greater than zero after any scan that
/// exercises at least one sub-component.
TEST_F(ScanPipelineFixture, ScanMechanics_MetadataPopulated_ScanTimeMicroseconds) {
    SKIP_IF_NOT_READY();

    SS::ScanOptions opts{};
    opts.enableHashLookup  = true;
    opts.enablePatternScan = true;
    opts.enableYaraScan    = false;

    const SS::ScanResult result = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(s_benignPayload.data(), s_benignPayload.size()), opts);

    EXPECT_GT(result.scanTimeMicroseconds, 0u)
        << "scanTimeMicroseconds must be non-zero after a real scan.";
}

/// Scanning the same buffer twice (with the cache enabled) must set cacheHit=true
/// on the second result.  The cache must be cleared before the test.
TEST_F(ScanPipelineFixture, ScanMechanics_CacheHit_SecondScanReturnsCacheHit) {
    SKIP_IF_NOT_READY();
    using namespace IntegrationTestData;

    s_sigStore->ClearAllCaches();

    SS::ScanOptions opts{};
    opts.enableHashLookup   = true;
    opts.enablePatternScan  = false;
    opts.enableYaraScan     = false;
    opts.enableResultCache  = true;

    // First scan populates the cache.
    const SS::ScanResult r1 = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(kHashPayload.data(), kHashPayload.size()), opts);
    EXPECT_FALSE(r1.cacheHit) << "First scan must NOT be a cache hit.";

    // Second scan should retrieve from the cache.
    const SS::ScanResult r2 = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(kHashPayload.data(), kHashPayload.size()), opts);
    EXPECT_TRUE(r2.cacheHit)
        << "Second scan of the same buffer with enableResultCache=true must be a cache hit.";
}

/// When stopOnFirstMatch=true and the buffer contains a hash match, errorCount
/// must remain zero while stoppedEarly must be true.
TEST_F(ScanPipelineFixture, ScanMechanics_StopOnFirstMatch_StopsEarly) {
    SKIP_IF_NOT_READY();
    using namespace IntegrationTestData;

    SS::ScanOptions opts{};
    opts.enableHashLookup  = true;
    opts.enablePatternScan = true;
    opts.enableYaraScan    = true;
    opts.stopOnFirstMatch  = true;

    const SS::ScanResult result = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(kHashPayload.data(), kHashPayload.size()), opts);

    EXPECT_TRUE(result.stoppedEarly)
        << "stopOnFirstMatch=true must set stoppedEarly=true when a detection fires.";
    EXPECT_EQ(result.errorCount, 0u)
        << "Early stop must not increment errorCount.";
}

/// Setting minThreatLevel to Critical must still surface Critical detections.
/// Setting it above the seeded level (beyond Critical) must suppress them.
TEST_F(ScanPipelineFixture, ScanMechanics_MinThreatLevelFilter_SuppressesLower) {
    SKIP_IF_NOT_READY();
    using namespace IntegrationTestData;

    // Should detect (Critical >= Critical).
    {
        SS::ScanOptions opts{};
        opts.enableHashLookup  = true;
        opts.enablePatternScan = false;
        opts.enableYaraScan    = false;
        opts.minThreatLevel    = SS::ThreatLevel::Critical;

        const SS::ScanResult r = s_sigStore->ScanBuffer(
            std::span<const uint8_t>(kHashPayload.data(), kHashPayload.size()), opts);
        EXPECT_TRUE(r.HasDetections())
            << "minThreatLevel=Critical must not suppress a Critical detection.";
    }

    // Should also detect with a lower filter (High <= Critical).
    {
        SS::ScanOptions opts{};
        opts.enableHashLookup  = true;
        opts.enablePatternScan = false;
        opts.enableYaraScan    = false;
        opts.minThreatLevel    = SS::ThreatLevel::High;

        const SS::ScanResult r = s_sigStore->ScanBuffer(
            std::span<const uint8_t>(kHashPayload.data(), kHashPayload.size()), opts);
        EXPECT_TRUE(r.HasDetections())
            << "minThreatLevel=High must not suppress a Critical detection.";
    }
}

/// A freshly constructed, never-initialized SignatureStore must not crash when
/// ScanBuffer is called; it must return an empty/safe ScanResult.
TEST_F(ScanPipelineFixture, ScanMechanics_UninitializedStore_SafelyReturnsEmpty) {
    SKIP_IF_NOT_READY();

    SS::SignatureStore uninitStore;
    const std::array<uint8_t, 8> buf = {{0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08}};

    EXPECT_NO_FATAL_FAILURE({
        const SS::ScanResult result = uninitStore.ScanBuffer(
            std::span<const uint8_t>(buf.data(), buf.size()), SS::ScanOptions{});
        EXPECT_FALSE(result.HasDetections())
            << "Uninitialized store must return no detections without crashing.";
    });
}

/// GetStatus() must report all three sub-stores as ready after a successful
/// InitializeMulti call.
TEST_F(ScanPipelineFixture, ScanMechanics_GetStatus_AllComponentsReady) {
    SKIP_IF_NOT_READY();

    const SS::SignatureStore::InitializationStatus status = s_sigStore->GetStatus();

    EXPECT_TRUE(status.hashStoreReady)
        << "HashStore must be marked ready after InitializeMulti.";
    EXPECT_TRUE(status.patternStoreReady)
        << "PatternStore must be marked ready after InitializeMulti.";
    EXPECT_TRUE(status.yaraStoreReady)
        << "YaraRuleStore must be marked ready after InitializeMulti.";
}

// ============================================================================
// GROUP 7: DETECTION CALLBACK
// ============================================================================
// Tests that the real-time detection callback is invoked correctly, with the
// right data, and that unregistering it prevents spurious invocations.
// ============================================================================

/// Registering a callback and scanning a matching buffer must invoke the
/// callback at least once with the correct ThreatLevel.
TEST_F(ScanPipelineFixture, DetectionCallback_Callback_HashMatch_InvokedWithCorrectData) {
    SKIP_IF_NOT_READY();
    using namespace IntegrationTestData;

    std::atomic<int>            callCount{0};
    SS::ThreatLevel             capturedLevel{SS::ThreatLevel::Info};
    std::string                 capturedName;
    std::mutex                  captureMtx;

    s_sigStore->RegisterDetectionCallback(
        [&](const SS::DetectionResult& det) {
            std::lock_guard<std::mutex> lk(captureMtx);
            ++callCount;
            capturedLevel = det.threatLevel;
            capturedName  = det.signatureName;
        });

    SS::ScanOptions opts{};
    opts.enableHashLookup  = true;
    opts.enablePatternScan = false;
    opts.enableYaraScan    = false;

    const SS::ScanResult r1 = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(kHashPayload.data(), kHashPayload.size()), opts);
    (void)r1;

    s_sigStore->UnregisterDetectionCallback();

    EXPECT_GT(callCount.load(), 0)
        << "Detection callback must be invoked at least once for a hash match.";
    {
        std::lock_guard<std::mutex> lk(captureMtx);
        EXPECT_EQ(capturedLevel, SS::ThreatLevel::Critical)
            << "Callback must receive the seeded hash-detection ThreatLevel.";
        EXPECT_EQ(capturedName, "Test.Malware.HashPayload.SHA256")
            << "Callback must receive the seeded hash signature name.";
    }
}

/// When scanning a buffer that produces no detections, the callback must not
/// be invoked.
TEST_F(ScanPipelineFixture, DetectionCallback_Callback_NoMatch_NotInvoked) {
    SKIP_IF_NOT_READY();

    std::atomic<int> callCount{0};

    s_sigStore->RegisterDetectionCallback(
        [&](const SS::DetectionResult&) {
            ++callCount;
        });

    SS::ScanOptions opts{};
    opts.enableHashLookup  = true;
    opts.enablePatternScan = true;
    opts.enableYaraScan    = true;

    const SS::ScanResult r2 = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(s_benignPayload.data(), s_benignPayload.size()), opts);
    (void)r2;

    s_sigStore->UnregisterDetectionCallback();

    EXPECT_EQ(callCount.load(), 0)
        << "Callback must NOT be invoked when no detection fires.";
}

/// Calling UnregisterDetectionCallback and then scanning a matching buffer
/// must not crash and must not invoke the previously registered callback.
TEST_F(ScanPipelineFixture, DetectionCallback_Callback_Unregistered_DoesNotCrash) {
    SKIP_IF_NOT_READY();
    using namespace IntegrationTestData;

    std::atomic<int> callCount{0};

    s_sigStore->RegisterDetectionCallback(
        [&](const SS::DetectionResult&) {
            ++callCount;
        });

    // Unregister before scanning.
    s_sigStore->UnregisterDetectionCallback();

    SS::ScanOptions opts{};
    opts.enableHashLookup  = true;
    opts.enablePatternScan = false;
    opts.enableYaraScan    = false;

    EXPECT_NO_FATAL_FAILURE({
        const SS::ScanResult r3 = s_sigStore->ScanBuffer(
            std::span<const uint8_t>(kHashPayload.data(), kHashPayload.size()), opts);
        (void)r3;
    });

    EXPECT_EQ(callCount.load(), 0)
        << "Unregistered callback must never be invoked.";
}

// ============================================================================
// GROUP 8: CONCURRENCY SAFETY
// ============================================================================
// Tests that SignatureStore and WhitelistStore are safe under concurrent
// read access from multiple threads (matching the typical hot-path workload
// on a live endpoint: many scanner threads reading simultaneously).
// ============================================================================

/// Eight threads each perform 20 synchronous ScanBuffer calls on kHashPayload.
/// All must succeed without crashes, data corruption, or incorrect results.
TEST_F(ScanPipelineFixture, ConcurrencySafety_EightThreads_SimultaneousScan_NoCrashNoCorruption) {
    SKIP_IF_NOT_READY();
    using namespace IntegrationTestData;

    constexpr int kThreads    = 8;
    constexpr int kIterations = 20;

    std::atomic<int>  successCount{0};
    std::atomic<int>  failureCount{0};
    std::vector<std::thread> threads;
    threads.reserve(kThreads);

    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&]() {
            SS::ScanOptions opts{};
            opts.enableHashLookup  = true;
            opts.enablePatternScan = false;
            opts.enableYaraScan    = false;

            const std::string expectedName = "Test.Malware.HashPayload.SHA256";

            for (int i = 0; i < kIterations; ++i) {
                const SS::ScanResult result = s_sigStore->ScanBuffer(
                    std::span<const uint8_t>(kHashPayload.data(), kHashPayload.size()), opts);

                if (result.HasDetections() &&
                    !result.hashMatches.empty() &&
                    result.hashMatches.front().threatLevel == SS::ThreatLevel::Critical &&
                    result.hashMatches.front().signatureName == expectedName) {
                    successCount.fetch_add(1, std::memory_order_relaxed);
                } else {
                    failureCount.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    for (auto& th : threads) th.join();

    const int expected = kThreads * kIterations;
    EXPECT_EQ(successCount.load(), expected)
        << "All " << expected << " concurrent scans must produce the current deterministic hash detections.";
    EXPECT_EQ(failureCount.load(), 0)
        << "No scan iteration must return an incorrect or missing result.";
}

/// Eight threads each perform 20 concurrent WhitelistStore hash lookups.
/// All must return consistent results (found=true for the known hash).
TEST_F(ScanPipelineFixture, ConcurrencySafety_ConcurrentWhitelistLookups_ThreadSafe) {
    SKIP_IF_NOT_READY();

    constexpr int kThreads    = 8;
    constexpr int kIterations = 20;

    std::atomic<int>  foundCount{0};
    std::atomic<int>  notFoundCount{0};
    std::vector<std::thread> threads;
    threads.reserve(kThreads);

    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&]() {
            for (int i = 0; i < kIterations; ++i) {
                const WL::LookupResult result =
                    s_wlStore->IsHashWhitelisted(s_hashPayloadWlHash);

                if (result.found) {
                    foundCount.fetch_add(1, std::memory_order_relaxed);
                } else {
                    notFoundCount.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    for (auto& th : threads) th.join();

    const int expected = kThreads * kIterations;
    EXPECT_EQ(foundCount.load(), expected)
        << "All " << expected << " concurrent whitelist lookups must find the seeded hash.";
    EXPECT_EQ(notFoundCount.load(), 0)
        << "No lookup iteration must fail to find the seeded hash.";
}

// ============================================================================
// GROUP 9: CONTRACT HARDENING
// ============================================================================
// These tests lock down deterministic edge contracts that are easy to regress
// in a multi-store pipeline: result limiting, cache semantics, normalization,
// batch summaries, invalid-input handling, and metadata preservation.
// ============================================================================

/// Hash-only scans should expose a single Critical detection through the
/// aggregate convenience helpers so callers can make fast verdict decisions
/// without manually inspecting the underlying vectors.
TEST_F(ScanPipelineFixture, ContractHardening_HashOnlyScan_CountAndMaxThreatAreConsistent) {
    SKIP_IF_NOT_READY();
    using namespace IntegrationTestData;

    SS::ScanOptions opts{};
    opts.enableHashLookup = true;
    opts.enablePatternScan = false;
    opts.enableYaraScan = false;

    const SS::ScanResult result = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(kHashPayload.data(), kHashPayload.size()), opts);

    ASSERT_TRUE(result.HasDetections());
    EXPECT_EQ(result.GetDetectionCount(), 1u);
    EXPECT_EQ(result.GetMaxThreatLevel(), SS::ThreatLevel::Critical);
    EXPECT_TRUE(result.IsSuccessful());
}

/// Pattern detections must preserve the seeded signature name so upstream
/// telemetry and alert rendering can attribute the detection to the right rule.
TEST_F(ScanPipelineFixture, ContractHardening_PatternDetection_PreservesSignatureName) {
    SKIP_IF_NOT_READY();

    SS::ScanOptions opts{};
    opts.enableHashLookup = false;
    opts.enablePatternScan = true;
    opts.enableYaraScan = false;

    const SS::ScanResult result = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(s_patternPayload.data(), s_patternPayload.size()), opts);

    ASSERT_FALSE(result.patternMatches.empty());
    EXPECT_EQ(result.patternMatches.front().signatureName, "Test.Malware.PatternMarker");
    EXPECT_EQ(result.patternMatches.front().threatLevel, SS::ThreatLevel::High);
}

/// maxResults=0 is treated as "return no detections" rather than "use the
/// default", and the scan should still account for the bytes it evaluated.
TEST_F(ScanPipelineFixture, ContractHardening_MaxResultsZero_SuppressesDetectionsButCountsBytes) {
    SKIP_IF_NOT_READY();
    using namespace IntegrationTestData;

    SS::ScanOptions opts{};
    opts.enableHashLookup = true;
    opts.enablePatternScan = false;
    opts.enableYaraScan = false;
    opts.maxResults = 0;

    const SS::ScanResult result = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(kHashPayload.data(), kHashPayload.size()), opts);

    EXPECT_FALSE(result.HasDetections());
    EXPECT_TRUE(result.hashMatches.empty());
    EXPECT_EQ(result.totalBytesScanned, kHashPayload.size());
    EXPECT_TRUE(result.IsSuccessful());
}

/// Disabling the result cache must keep repeated scans from being marked as
/// cache hits even when the payload is identical.
TEST_F(ScanPipelineFixture, ContractHardening_ResultCacheDisabled_RepeatedScanNeverHitsCache) {
    SKIP_IF_NOT_READY();
    using namespace IntegrationTestData;

    s_sigStore->ClearAllCaches();

    SS::ScanOptions opts{};
    opts.enableHashLookup = true;
    opts.enablePatternScan = false;
    opts.enableYaraScan = false;
    opts.enableResultCache = false;

    const SS::ScanResult first = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(kHashPayload.data(), kHashPayload.size()), opts);
    const SS::ScanResult second = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(kHashPayload.data(), kHashPayload.size()), opts);

    EXPECT_FALSE(first.cacheHit);
    EXPECT_FALSE(second.cacheHit);
    EXPECT_TRUE(second.HasDetections());
}

/// A buffer containing both seeded markers must surface both pattern and YARA
/// detections when both engines are enabled.
TEST_F(ScanPipelineFixture, ContractHardening_CombinedPatternAndYaraPayload_DetectsBothEngines) {
    SKIP_IF_NOT_READY();

    std::vector<uint8_t> combined(48u, 0x41u);
    combined.insert(
        combined.end(),
        IntegrationTestData::kPatternMarker,
        IntegrationTestData::kPatternMarker + (sizeof(IntegrationTestData::kPatternMarker) - 1));
    combined.insert(combined.end(), 17u, 0x42u);
    combined.insert(
        combined.end(),
        IntegrationTestData::kYaraMarker,
        IntegrationTestData::kYaraMarker + (sizeof(IntegrationTestData::kYaraMarker) - 1));
    combined.insert(combined.end(), 33u, 0x43u);

    SS::ScanOptions opts{};
    opts.enableHashLookup = false;
    opts.enablePatternScan = true;
    opts.enableYaraScan = true;
    opts.parallelExecution = false;

    const SS::ScanResult result = s_sigStore->ScanBuffer(
        std::span<const uint8_t>(combined.data(), combined.size()), opts);

    EXPECT_FALSE(result.patternMatches.empty());
    EXPECT_FALSE(result.yaraMatches.empty());
    EXPECT_GE(result.GetDetectionCount(), 2u);
}

/// Threat-intel hash parsing must accept uppercase hex and the hyphenated
/// SHA-256 algorithm spelling used by some vendors and feeds.
TEST_F(ScanPipelineFixture, ContractHardening_ThreatIntelHashLookup_HyphenatedAlgorithmAndUpperHexAccepted) {
    SKIP_IF_NOT_READY();

    std::string uppercaseHex = s_maliciousIntelHex;
    for (char& ch : uppercaseHex) {
        if (ch >= 'a' && ch <= 'f') {
            ch = static_cast<char>(ch - ('a' - 'A'));
        }
    }

    const TI::StoreLookupResult result =
        s_tiStore->LookupHash("SHA-256", uppercaseHex);

    EXPECT_TRUE(result.found);
    EXPECT_TRUE(result.IsMalicious());
}

/// Unsupported explicit hash algorithms must fail closed instead of silently
/// auto-detecting to a different algorithm family.
TEST_F(ScanPipelineFixture, ContractHardening_ThreatIntelHashLookup_UnsupportedAlgorithmRejected) {
    SKIP_IF_NOT_READY();

    const TI::StoreLookupResult result =
        s_tiStore->LookupHash("SHA384", s_maliciousIntelHex);

    EXPECT_FALSE(result.found);
    EXPECT_FALSE(result.IsMalicious());
}

/// Batch domain lookups should preserve input cardinality and summary counts so
/// callers can make a single pass decision without recomputing aggregates.
TEST_F(ScanPipelineFixture, ContractHardening_ThreatIntelBatchDomainLookup_SummaryCountsAreCorrect) {
    SKIP_IF_NOT_READY();

    const std::vector<std::string> domains = {
        IntegrationTestData::kMaliciousDomain,
        "benign.example.com"
    };

    const TI::StoreBatchLookupResult result = s_tiStore->BatchLookupDomains(domains);

    ASSERT_EQ(result.results.size(), domains.size());
    EXPECT_EQ(result.totalProcessed, domains.size());
    EXPECT_EQ(result.foundCount, 1u);
    EXPECT_EQ(result.notFoundCount, 1u);
    EXPECT_EQ(result.maliciousCount, 1u);
    EXPECT_TRUE(result.HasMalicious());
    EXPECT_TRUE(result.results[0].found);
    EXPECT_TRUE(result.results[0].IsMalicious());
    EXPECT_FALSE(result.results[1].found);
}

/// Whitelist hash lookups must preserve the seeded reason, type, and
/// description so the caller can explain why a detection was bypassed.
TEST_F(ScanPipelineFixture, ContractHardening_WhitelistHashLookup_MetadataIsPreserved) {
    SKIP_IF_NOT_READY();

    const WL::LookupResult result = s_wlStore->IsHashWhitelisted(s_hashPayloadWlHash);

    ASSERT_TRUE(result.found);
    EXPECT_EQ(result.type, WL::WhitelistEntryType::FileHash);
    EXPECT_EQ(result.reason, WL::WhitelistReason::UserApproved);
    EXPECT_FALSE(result.description.empty());
    EXPECT_EQ(result.description, "Integration test: hash of kHashPayload whitelisted as trusted binary");
}

/// The whitelist query cache should convert the second identical lookup into a
/// cache hit after an explicit cache clear.
TEST_F(ScanPipelineFixture, ContractHardening_WhitelistHashLookup_SecondLookupUsesCache) {
    SKIP_IF_NOT_READY();

    s_wlStore->ClearCache();

    const WL::LookupResult first = s_wlStore->IsHashWhitelisted(s_hashPayloadWlHash);
    const WL::LookupResult second = s_wlStore->IsHashWhitelisted(s_hashPayloadWlHash);

    ASSERT_TRUE(first.found);
    ASSERT_TRUE(second.found);
    EXPECT_FALSE(first.cacheHit);
    EXPECT_TRUE(second.cacheHit);
}

/// Path whitelisting should remain stable across case changes and slash-style
/// differences because path normalization is part of the production contract.
TEST_F(ScanPipelineFixture, ContractHardening_WhitelistPathLookup_NormalizesCaseAndSeparators) {
    SKIP_IF_NOT_READY();

    const WL::LookupResult result = s_wlStore->IsPathWhitelisted(
        L"c:/shadowstrike/trustedsoftware/Child_Binary.EXE");

    EXPECT_TRUE(result.found);
    EXPECT_EQ(result.reason, WL::WhitelistReason::PolicyBased);
}

/// Empty batch lookups should return an empty vector rather than a singleton
/// error record or an out-of-bounds-sized result set.
TEST_F(ScanPipelineFixture, ContractHardening_WhitelistBatchLookup_EmptyInputReturnsEmptyVector) {
    SKIP_IF_NOT_READY();

    const std::vector<WL::HashValue> emptyBatch;
    const std::vector<WL::LookupResult> results = s_wlStore->BatchLookupHashes(emptyBatch);

    EXPECT_TRUE(results.empty());
}

/// Freshly constructed stores that were never initialized must fail closed and
/// return "not found" without crashing.
TEST_F(ScanPipelineFixture, ContractHardening_UninitializedThreatIntelAndWhitelist_FailClosed) {
    SKIP_IF_NOT_READY();

    TI::ThreatIntelStore tiStore;
    WL::WhitelistStore wlStore;

    const TI::StoreLookupResult tiResult =
        tiStore.LookupDomain(IntegrationTestData::kMaliciousDomain);
    const WL::LookupResult wlHashResult = wlStore.IsHashWhitelisted(s_hashPayloadWlHash);
    const WL::LookupResult wlPathResult =
        wlStore.IsPathWhitelisted(IntegrationTestData::kWhitelistedDirPath);

    EXPECT_FALSE(tiResult.found);
    EXPECT_FALSE(wlHashResult.found);
    EXPECT_FALSE(wlPathResult.found);
}

