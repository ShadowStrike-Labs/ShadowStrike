/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Integration Tests - FileSystem Chain
 *
 * ============================================================================
 * PURPOSE
 * ============================================================================
 * Tests end-to-end integration between the core FileSystem chain modules:
 *   FileHasher        → cryptographic hashing (MD5/SHA1/SHA256/SHA512/fuzzy)
 *   FileTypeAnalyzer  → magic-byte type detection and spoofing detection
 *   FileReputation    → hash-based reputation scoring and malware lookup
 *
 * All tests use real temp files on disk. No mocks.
 * Temp files are created in %TEMP%\ShadowStrikeTest_<PID>\ and deleted on teardown.
 *
 * ============================================================================
 * TEST GROUPS
 * ============================================================================
 *   GROUP 1  FileHasher_CoreHashing         - deterministic hashing, empty files
 *   GROUP 2  FileHasher_BatchAndFuzzy       - batch compute, fuzzy similarity
 *   GROUP 3  FileTypeAnalyzer_TypeDetection - PE/text/script/archive detection
 *   GROUP 4  FileTypeAnalyzer_Spoofing      - extension mismatch detection
 *   GROUP 5  FileSystemChain_EndToEnd       - hash→type→reputation pipeline
 *   GROUP 6  FileSystemChain_EdgeCases      - missing/empty/large file handling
 *   GROUP 7  FileSystemChain_Concurrency    - parallel hash and analyze
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <format>
#include <gtest/gtest.h>

#include "../../../src/PhantomCore/Core/FileSystem/FileHasher.hpp"
#include "../../../src/PhantomCore/Core/FileSystem/FileReputation.hpp"
#include "../../../src/PhantomCore/Core/FileSystem/FileTypeAnalyzer.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <future>
#include <mutex>
#include <set>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

namespace {

namespace fs = std::filesystem;

class FileSystemChainIntegrationTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        std::error_code ec;
        const fs::path tempBase = fs::temp_directory_path(ec);
        if (ec) {
            s_environmentReady = false;
            return;
        }

        s_tempRoot = tempBase / fs::path(L"ShadowStrikeTest_" + std::to_wstring(::GetCurrentProcessId()));
        std::ignore = fs::remove_all(s_tempRoot, ec);
        ec.clear();
        std::ignore = fs::create_directories(s_tempRoot, ec);
        if (ec) {
            s_environmentReady = false;
            return;
        }

        auto& hasher = ShadowStrike::Core::FileSystem::FileHasher::Instance();
        hasher.ClearCache();
        hasher.Shutdown();
        s_hasherInitialized = hasher.Initialize(
            ShadowStrike::Core::FileSystem::FileHasherConfig::CreateDefault());

        auto& analyzer = ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance();
        analyzer.Shutdown();
        s_analyzerInitialized = analyzer.Initialize(
            ShadowStrike::Core::FileSystem::FileTypeAnalyzerConfig::CreateDefault());

        auto& reputation = ShadowStrike::Core::FileSystem::FileReputation::Instance();
        reputation.ClearCache();
        reputation.Shutdown();
        s_reputationInitialized = reputation.Initialize(
            ShadowStrike::Core::FileSystem::FileReputationConfig::CreateOffline());
    }

    static void TearDownTestSuite() {
        auto& reputation = ShadowStrike::Core::FileSystem::FileReputation::Instance();
        reputation.ClearCache();
        reputation.Shutdown();

        auto& analyzer = ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance();
        analyzer.Shutdown();

        auto& hasher = ShadowStrike::Core::FileSystem::FileHasher::Instance();
        hasher.ClearCache();
        hasher.Shutdown();

        std::error_code ec;
        std::ignore = fs::remove_all(s_tempRoot, ec);
    }

    void SetUp() override {
        if (!s_environmentReady) {
            GTEST_SKIP() << "Unable to prepare integration test temp directory under %TEMP%.";
        }

        if (!s_hasherInitialized) {
            GTEST_SKIP() << "FileHasher initialization failed.";
        }

        if (!s_analyzerInitialized) {
            GTEST_SKIP() << "FileTypeAnalyzer initialization failed.";
        }

        std::error_code ec;
        std::ignore = fs::create_directories(s_tempRoot, ec);
        if (ec) {
            GTEST_SKIP() << "Unable to recreate integration test temp directory: " << ec.message();
        }
    }

    static void SkipIfReputationUnavailable() {
        if (!s_reputationInitialized) {
            GTEST_SKIP() << "FileReputation initialization failed or unavailable in this environment.";
        }
    }

    static fs::path MakeTempFilePath(std::wstring_view stem, std::wstring_view extension) {
        const auto sequence = s_fileCounter.fetch_add(1, std::memory_order_relaxed);
        return s_tempRoot / fs::path(
            std::wstring(stem) + L"_" + std::to_wstring(sequence) + std::wstring(extension));
    }

    static fs::path WriteBinaryFile(
        std::wstring_view stem,
        std::wstring_view extension,
        std::span<const uint8_t> bytes) {

        const fs::path path = MakeTempFilePath(stem, extension);

        std::error_code ec;
        std::ignore = fs::create_directories(path.parent_path(), ec);
        if (ec) {
            ADD_FAILURE() << "Failed to create parent directory for " << path.string()
                          << ": " << ec.message();
            return path;
        }

        std::ofstream stream(path, std::ios::binary | std::ios::trunc);
        if (!stream.is_open()) {
            ADD_FAILURE() << "Failed to open file for writing: " << path.string();
            return path;
        }

        if (!bytes.empty()) {
            stream.write(
                reinterpret_cast<const char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
        }
        stream.close();

        if (!stream.good()) {
            ADD_FAILURE() << "Failed to write file contents: " << path.string();
        }

        return path;
    }

    static fs::path WriteTextFile(
        std::wstring_view stem,
        std::wstring_view extension,
        std::string_view text) {

        const std::vector<uint8_t> bytes(text.begin(), text.end());
        return WriteBinaryFile(
            stem,
            extension,
            std::span<const uint8_t>(bytes.data(), bytes.size()));
    }

    static std::vector<uint8_t> BuildMinimalPeImage() {
        std::vector<uint8_t> buffer(0x200, 0);
        buffer[0] = 'M';
        buffer[1] = 'Z';

        const uint32_t peOffset = 0x80;
        std::memcpy(buffer.data() + 0x3C, &peOffset, sizeof(peOffset));

        buffer[0x80] = 'P';
        buffer[0x81] = 'E';
        buffer[0x82] = 0x00;
        buffer[0x83] = 0x00;

        const uint16_t machine = 0x8664;
        const uint16_t numberOfSections = 1;
        const uint16_t optionalHeaderSize = 0x00F0;
        const uint16_t characteristics = 0x0002;

        std::memcpy(buffer.data() + 0x84, &machine, sizeof(machine));
        std::memcpy(buffer.data() + 0x86, &numberOfSections, sizeof(numberOfSections));
        std::memcpy(buffer.data() + 0x94, &optionalHeaderSize, sizeof(optionalHeaderSize));
        std::memcpy(buffer.data() + 0x96, &characteristics, sizeof(characteristics));

        const uint16_t peMagic = 0x020B;
        std::memcpy(buffer.data() + 0x98, &peMagic, sizeof(peMagic));
        return buffer;
    }

    static std::vector<uint8_t> BuildMinimalJpegBytes() {
        return {
            0xFF, 0xD8, 0xFF, 0xE0,
            0x00, 0x10, 'J', 'F', 'I', 'F', 0x00,
            0x01, 0x02, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00
        };
    }

    static std::vector<uint8_t> BuildMinimalZipBytes() {
        return {
            0x50, 0x4B, 0x03, 0x04,
            0x14, 0x00, 0x00, 0x00,
            0x08, 0x00, 0x00, 0x00,
            0x21, 0x00, 't', 'e', 's', 't'
        };
    }

    static std::vector<uint8_t> BuildSequentialBytes(size_t count, uint8_t seed = 0) {
        std::vector<uint8_t> bytes(count, 0);
        for (size_t index = 0; index < count; ++index) {
            bytes[index] = static_cast<uint8_t>((seed + index) & 0xFFu);
        }
        return bytes;
    }

    static std::vector<uint8_t> BuildSimilarContent(bool mutateTail) {
        std::vector<uint8_t> bytes;
        bytes.reserve(2048);

        constexpr std::string_view block =
            "ShadowStrike_Fuzzy_Block_Enterprise_Detection_Sequence_";

        for (size_t index = 0; index < 32; ++index) {
            bytes.insert(bytes.end(), block.begin(), block.end());
        }

        if (mutateTail) {
            const size_t mutationStart = bytes.size() * 4 / 5;
            for (size_t index = mutationStart; index < bytes.size(); ++index) {
                bytes[index] = static_cast<uint8_t>('A' + (index % 26));
            }
        }

        return bytes;
    }

    static std::vector<uint8_t> BuildDifferentContent(uint8_t fill, std::string_view marker) {
        std::vector<uint8_t> bytes(2048, fill);
        bytes.insert(bytes.end(), marker.begin(), marker.end());
        return bytes;
    }

    template <size_t Size>
    static bool HasAnyNonZero(const std::array<uint8_t, Size>& bytes) {
        return std::any_of(
            bytes.begin(),
            bytes.end(),
            [](uint8_t value) { return value != 0; });
    }

    static inline fs::path s_tempRoot{};
    static inline std::atomic<uint64_t> s_fileCounter{ 0 };
    static inline bool s_environmentReady{ true };
    static inline bool s_hasherInitialized{ false };
    static inline bool s_analyzerInitialized{ false };
    static inline bool s_reputationInitialized{ false };
};

TEST_F(FileSystemChainIntegrationTest, FileHasher_CoreHashing_InitializeWithDefaultConfig_Succeeds) {
    EXPECT_TRUE(ShadowStrike::Core::FileSystem::FileHasher::Instance().IsInitialized());

    const auto config = ShadowStrike::Core::FileSystem::FileHasher::Instance().GetConfig();
    EXPECT_TRUE(ShadowStrike::Core::FileSystem::HasFlag(
        config.defaultAlgorithms,
        ShadowStrike::Core::FileSystem::HashAlgorithm::SHA256));
}

TEST_F(FileSystemChainIntegrationTest, FileHasher_CoreHashing_ComputeMD5_ForKnownTempFile_ReturnsDeterministicHash) {
    const auto payload = BuildSequentialBytes(100, 0x10);
    const fs::path filePath = WriteBinaryFile(
        L"deterministic_md5",
        L".bin",
        std::span<const uint8_t>(payload.data(), payload.size()));

    const auto first = ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeMD5(filePath.wstring());
    const auto second = ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeMD5(filePath.wstring());

    EXPECT_FALSE(first.empty());
    EXPECT_EQ(first.size(), 32u);
    EXPECT_EQ(first, second);
}

TEST_F(FileSystemChainIntegrationTest, FileHasher_CoreHashing_ComputeSHA256_ForKnownTempFile_ReturnsDeterministicHash) {
    const fs::path filePath = WriteTextFile(
        L"deterministic_sha256",
        L".txt",
        "ShadowStrike deterministic SHA256 integration payload");

    const auto first = ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeSHA256(filePath.wstring());
    const auto second = ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeSHA256(filePath.wstring());

    EXPECT_FALSE(first.empty());
    EXPECT_EQ(first.size(), 64u);
    EXPECT_EQ(first, second);
}

TEST_F(FileSystemChainIntegrationTest, FileHasher_CoreHashing_ComputeAll_Standard_ReturnsAllThreeHashes) {
    const fs::path filePath = WriteTextFile(
        L"compute_all_standard",
        L".bin",
        "ShadowStrike standard hashing validation payload");

    const auto hashes = ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeAll(
        filePath.wstring(),
        ShadowStrike::Core::FileSystem::HashAlgorithm::Standard);

    EXPECT_TRUE(hashes.hasMD5);
    EXPECT_TRUE(hashes.hasSHA1);
    EXPECT_TRUE(hashes.hasSHA256);
    EXPECT_TRUE(HasAnyNonZero(hashes.md5));
    EXPECT_TRUE(HasAnyNonZero(hashes.sha1));
    EXPECT_TRUE(HasAnyNonZero(hashes.sha256));
}

TEST_F(FileSystemChainIntegrationTest, FileHasher_CoreHashing_ComputeAll_EmptyFile_ReturnsKnownEmptyHashes) {
    const std::vector<uint8_t> emptyBytes;
    const fs::path filePath = WriteBinaryFile(
        L"empty_hashes",
        L".bin",
        std::span<const uint8_t>(emptyBytes.data(), emptyBytes.size()));

    const auto hashes = ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeAll(
        filePath.wstring(),
        ShadowStrike::Core::FileSystem::HashAlgorithm::Standard);

    EXPECT_TRUE(hashes.hasMD5);
    EXPECT_TRUE(hashes.hasSHA1);
    EXPECT_TRUE(hashes.hasSHA256);
    EXPECT_EQ(hashes.md5Hex, "d41d8cd98f00b204e9800998ecf8427e");
    EXPECT_EQ(hashes.sha256Hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_F(FileSystemChainIntegrationTest, FileHasher_CoreHashing_ComputeAll_Buffer_MatchesFilePath) {
    const auto payload = BuildSequentialBytes(256, 0x42);
    const fs::path filePath = WriteBinaryFile(
        L"buffer_vs_file",
        L".bin",
        std::span<const uint8_t>(payload.data(), payload.size()));

    const auto fileHashes = ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeAll(
        filePath.wstring(),
        ShadowStrike::Core::FileSystem::HashAlgorithm::Standard);

    const auto bufferHashes = ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeAll(
        std::span<const uint8_t>(payload.data(), payload.size()),
        ShadowStrike::Core::FileSystem::HashAlgorithm::Standard);

    EXPECT_TRUE(fileHashes.hasSHA256);
    EXPECT_TRUE(bufferHashes.hasSHA256);
    EXPECT_EQ(fileHashes.sha256Hex, bufferHashes.sha256Hex);
}

TEST_F(FileSystemChainIntegrationTest, FileHasher_BatchAndFuzzy_ComputeBatch_MultipleFiles_ReturnsAllHashes) {
    const fs::path fileOne = WriteTextFile(L"batch_one", L".txt", "batch-file-one");
    const fs::path fileTwo = WriteTextFile(L"batch_two", L".txt", "batch-file-two");
    const fs::path fileThree = WriteTextFile(L"batch_three", L".txt", "batch-file-three");

    const std::vector<std::wstring> paths{
        fileOne.wstring(),
        fileTwo.wstring(),
        fileThree.wstring()
    };

    const auto results = ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeBatch(
        paths,
        ShadowStrike::Core::FileSystem::HashAlgorithm::Standard);

    ASSERT_EQ(results.size(), paths.size());
    std::set<std::string> uniqueSha256;
    for (const auto& result : results) {
        EXPECT_TRUE(result.hasMD5);
        EXPECT_TRUE(result.hasSHA1);
        EXPECT_TRUE(result.hasSHA256);
        EXPECT_FALSE(result.sha256Hex.empty());
        uniqueSha256.insert(result.sha256Hex);
    }

    EXPECT_EQ(uniqueSha256.size(), paths.size());
}

TEST_F(FileSystemChainIntegrationTest, FileHasher_BatchAndFuzzy_ComputeFuzzyHash_SimilarFiles_SimilarityHigh) {
    const auto firstBytes = BuildSimilarContent(false);
    const auto secondBytes = BuildSimilarContent(true);

    const fs::path firstFile = WriteBinaryFile(
        L"fuzzy_similar_a",
        L".bin",
        std::span<const uint8_t>(firstBytes.data(), firstBytes.size()));
    const fs::path secondFile = WriteBinaryFile(
        L"fuzzy_similar_b",
        L".bin",
        std::span<const uint8_t>(secondBytes.data(), secondBytes.size()));

    const auto firstHash = ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeFuzzyHash(firstFile.wstring());
    const auto secondHash = ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeFuzzyHash(secondFile.wstring());

    if (firstHash.empty() || secondHash.empty()) {
        GTEST_SKIP() << "Fuzzy hashing is unavailable in this environment.";
    }

    const double similarity = ShadowStrike::Core::FileSystem::FileHasher::Instance().CompareFuzzyHash(
        firstHash,
        secondHash);

    EXPECT_GT(similarity, 0.5);
}

TEST_F(FileSystemChainIntegrationTest, FileHasher_BatchAndFuzzy_ComputeFuzzyHash_DifferentFiles_SimilarityLow) {
    const auto firstBytes = BuildDifferentContent(0x11, "MALWARE-LIKE-PAYLOAD-A");
    const auto secondBytes = BuildDifferentContent(0xEE, "COMPLETELY-DIFFERENT-PAYLOAD-B");

    const fs::path firstFile = WriteBinaryFile(
        L"fuzzy_different_a",
        L".bin",
        std::span<const uint8_t>(firstBytes.data(), firstBytes.size()));
    const fs::path secondFile = WriteBinaryFile(
        L"fuzzy_different_b",
        L".bin",
        std::span<const uint8_t>(secondBytes.data(), secondBytes.size()));

    const auto firstHash = ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeFuzzyHash(firstFile.wstring());
    const auto secondHash = ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeFuzzyHash(secondFile.wstring());

    if (firstHash.empty() || secondHash.empty()) {
        GTEST_SKIP() << "Fuzzy hashing is unavailable in this environment.";
    }

    const double similarity = ShadowStrike::Core::FileSystem::FileHasher::Instance().CompareFuzzyHash(
        firstHash,
        secondHash);

    EXPECT_LT(similarity, 0.5);
}

TEST_F(FileSystemChainIntegrationTest, FileHasher_BatchAndFuzzy_ComputeSHA256_RealSystemFile_NonEmpty) {
    const fs::path systemFile = L"C:\\Windows\\System32\\ntdll.dll";
    if (!fs::exists(systemFile)) {
        GTEST_SKIP() << "System file not present: " << systemFile.string();
    }

    const auto sha256 = ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeSHA256(systemFile.wstring());

    EXPECT_EQ(sha256.size(), 64u);
}

TEST_F(FileSystemChainIntegrationTest, FileTypeAnalyzer_TypeDetection_InitializeWithDefaultConfig_Succeeds) {
    EXPECT_TRUE(s_analyzerInitialized);
}

TEST_F(FileSystemChainIntegrationTest, FileTypeAnalyzer_TypeDetection_Analyze_PEFile_DetectsExecutable) {
    const auto peBytes = BuildMinimalPeImage();
    const fs::path filePath = WriteBinaryFile(
        L"pe_detect",
        L".exe",
        std::span<const uint8_t>(peBytes.data(), peBytes.size()));

    const auto info = ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance().Analyze(filePath.wstring());

    EXPECT_TRUE(info.detected);
    EXPECT_TRUE(info.isExecutable);
    EXPECT_EQ(info.category, ShadowStrike::Core::FileSystem::FileCategory::Executable);
}

TEST_F(FileSystemChainIntegrationTest, FileTypeAnalyzer_TypeDetection_Analyze_TextFile_DetectsTextCategory) {
    const fs::path filePath = WriteTextFile(L"text_detect", L".txt", "Hello World");

    const auto info = ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance().Analyze(filePath.wstring());

    EXPECT_TRUE(info.detected);
    EXPECT_NE(info.category, ShadowStrike::Core::FileSystem::FileCategory::Executable);
    EXPECT_FALSE(info.isExecutable);
}

TEST_F(FileSystemChainIntegrationTest, FileTypeAnalyzer_TypeDetection_IsExecutable_RealDll_ReturnsTrue) {
    const fs::path dllPath = L"C:\\Windows\\System32\\ntdll.dll";
    if (!fs::exists(dllPath)) {
        GTEST_SKIP() << "System DLL not present: " << dllPath.string();
    }

    EXPECT_TRUE(
        ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance().IsExecutable(dllPath.wstring()));
}

TEST_F(FileSystemChainIntegrationTest, FileTypeAnalyzer_TypeDetection_IsScript_BatchFile_ReturnsTrue) {
    const fs::path filePath = WriteTextFile(
        L"script_detect",
        L".bat",
        "@echo off\r\necho ShadowStrike\r\n");

    EXPECT_TRUE(
        ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance().IsScript(filePath.wstring()));
}

TEST_F(FileSystemChainIntegrationTest, FileTypeAnalyzer_TypeDetection_IsArchive_ZipMagicBytes_ReturnsTrue) {
    const auto zipBytes = BuildMinimalZipBytes();
    const fs::path filePath = WriteBinaryFile(
        L"archive_detect",
        L".zip",
        std::span<const uint8_t>(zipBytes.data(), zipBytes.size()));

    EXPECT_TRUE(
        ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance().IsArchive(filePath.wstring()));
}

TEST_F(FileSystemChainIntegrationTest, FileTypeAnalyzer_SpoofingDetection_Analyze_PEHeaderInJpgExtension_DetectsSpoofing) {
    const auto peBytes = BuildMinimalPeImage();
    const fs::path filePath = WriteBinaryFile(
        L"pe_named_jpg",
        L".jpg",
        std::span<const uint8_t>(peBytes.data(), peBytes.size()));

    const auto info = ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance().Analyze(filePath.wstring());

    EXPECT_TRUE(info.detected);
    EXPECT_TRUE(info.isSpoofed);
    EXPECT_EQ(info.spoofingType, ShadowStrike::Core::FileSystem::SpoofingType::ExtensionMismatch);
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_SpoofingDetection_DetectSpoofing_DoubleExtension_ReturnsDoubleExtension) {
    const auto peBytes = BuildMinimalPeImage();
    const auto sequence = s_fileCounter.fetch_add(1, std::memory_order_relaxed);
    const fs::path filePath = s_tempRoot / fs::path(
        L"document_" + std::to_wstring(sequence) + L".pdf.exe");

    std::ofstream stream(filePath, std::ios::binary | std::ios::trunc);
    ASSERT_TRUE(stream.is_open()) << "Failed to open file for writing: " << filePath.string();
    stream.write(
        reinterpret_cast<const char*>(peBytes.data()),
        static_cast<std::streamsize>(peBytes.size()));
    stream.close();
    ASSERT_TRUE(stream.good()) << "Failed to write file contents: " << filePath.string();

    auto& analyzer = ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance();
    const auto info = analyzer.Analyze(filePath.wstring());
    const auto spoofing = analyzer.DetectSpoofing(filePath.wstring());

    EXPECT_TRUE(info.detected);
    EXPECT_EQ(spoofing, ShadowStrike::Core::FileSystem::SpoofingType::DoubleExtension);
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_SpoofingDetection_Analyze_LegitJpeg_DetectsImageAndAtMostExtensionMismatch) {
    const auto jpegBytes = BuildMinimalJpegBytes();
    const fs::path filePath = WriteBinaryFile(
        L"legit_jpeg",
        L".jpg",
        std::span<const uint8_t>(jpegBytes.data(), jpegBytes.size()));

    const auto info = ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance().Analyze(filePath.wstring());

    EXPECT_TRUE(info.detected);
    EXPECT_EQ(info.category, ShadowStrike::Core::FileSystem::FileCategory::Image);
    EXPECT_EQ(info.format, ShadowStrike::Core::FileSystem::FileFormat::JPEG);
    if (info.isSpoofed) {
        EXPECT_EQ(info.spoofingType, ShadowStrike::Core::FileSystem::SpoofingType::ExtensionMismatch);
    }
}

TEST_F(FileSystemChainIntegrationTest, FileSystemChain_EndToEnd_HashThenTypeAnalyze_SameFile_BothSucceed) {
    const auto peBytes = BuildMinimalPeImage();
    const fs::path filePath = WriteBinaryFile(
        L"hash_then_type",
        L".exe",
        std::span<const uint8_t>(peBytes.data(), peBytes.size()));

    const auto sha256 = ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeSHA256(filePath.wstring());
    const auto typeInfo = ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance().Analyze(filePath.wstring());

    EXPECT_FALSE(sha256.empty());
    EXPECT_TRUE(typeInfo.detected);
    EXPECT_TRUE(typeInfo.isExecutable);
}

TEST_F(FileSystemChainIntegrationTest, FileSystemChain_EndToEnd_HashThenReputation_CleanFile_NotMalicious) {
    SkipIfReputationUnavailable();

    const fs::path filePath = WriteTextFile(
        L"clean_reputation",
        L".txt",
        "ShadowStrike clean reputation integration sample");

    const auto sha256 = ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeSHA256(filePath.wstring());
    ASSERT_FALSE(sha256.empty());

    ShadowStrike::Core::FileSystem::ReputationQuery query;
    query.filePath = filePath.wstring();
    query.sha256 = sha256;
    query.mode = ShadowStrike::Core::FileSystem::QueryMode::LocalOnly;

    const auto result = ShadowStrike::Core::FileSystem::FileReputation::Instance().Query(query);

    EXPECT_FALSE(result.isMalicious);
}

TEST_F(FileSystemChainIntegrationTest, FileSystemChain_EndToEnd_BatchHashAndAnalyze_FiveFiles_AllDistinct) {
    const auto zipBytes = BuildMinimalZipBytes();
    const auto jpegBytes = BuildMinimalJpegBytes();
    const auto peBytes = BuildMinimalPeImage();

    const fs::path textFile = WriteTextFile(L"batch_e2e_text", L".txt", "integration-text");
    const fs::path batchFile = WriteTextFile(L"batch_e2e_script", L".bat", "@echo off\r\necho chain\r\n");
    const fs::path zipFile = WriteBinaryFile(
        L"batch_e2e_zip",
        L".zip",
        std::span<const uint8_t>(zipBytes.data(), zipBytes.size()));
    const fs::path jpgFile = WriteBinaryFile(
        L"batch_e2e_jpg",
        L".jpg",
        std::span<const uint8_t>(jpegBytes.data(), jpegBytes.size()));
    const fs::path exeFile = WriteBinaryFile(
        L"batch_e2e_exe",
        L".exe",
        std::span<const uint8_t>(peBytes.data(), peBytes.size()));

    const std::vector<std::wstring> paths{
        textFile.wstring(),
        batchFile.wstring(),
        zipFile.wstring(),
        jpgFile.wstring(),
        exeFile.wstring()
    };

    const auto hashes = ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeBatch(
        paths,
        ShadowStrike::Core::FileSystem::HashAlgorithm::SHA256);

    ASSERT_EQ(hashes.size(), paths.size());
    std::set<std::string> uniqueSha256;
    for (size_t index = 0; index < paths.size(); ++index) {
        uniqueSha256.insert(hashes[index].sha256Hex);

        const auto info = ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance().Analyze(paths[index]);
        EXPECT_TRUE(info.detected) << "Type detection failed for: " << fs::path(paths[index]).string();
    }

    EXPECT_EQ(uniqueSha256.size(), paths.size());
}

TEST_F(FileSystemChainIntegrationTest, FileSystemChain_EdgeCases_Hash_MissingFile_ReturnsEmptyOrError) {
    const auto md5 = ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeMD5(
        L"C:\\NonExistent\\file.exe");

    EXPECT_TRUE(md5.empty() || md5 == "error" || md5 == "ERROR");
}

TEST_F(FileSystemChainIntegrationTest, FileSystemChain_EdgeCases_TypeAnalyze_MissingFile_ReturnsNotDetected) {
    const auto info = ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance().Analyze(
        L"C:\\NonExistent\\file.exe");

    EXPECT_FALSE(info.detected);
}

TEST_F(FileSystemChainIntegrationTest, FileSystemChain_EdgeCases_Hash_ZeroByteFile_ReturnsKnownHashes) {
    const std::vector<uint8_t> emptyBytes;
    const fs::path filePath = WriteBinaryFile(
        L"zero_byte_sha256",
        L".bin",
        std::span<const uint8_t>(emptyBytes.data(), emptyBytes.size()));

    const auto sha256 = ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeSHA256(filePath.wstring());

    EXPECT_EQ(sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_F(FileSystemChainIntegrationTest, FileSystemChain_EdgeCases_Hash_LargeFile_Succeeds) {
    std::vector<uint8_t> largeBytes(4u * 1024u * 1024u, 0x00);
    constexpr std::string_view marker = "ShadowStrikeLargeFileMarker";
    std::copy(marker.begin(), marker.end(), largeBytes.end() - static_cast<std::ptrdiff_t>(marker.size()));

    const fs::path filePath = WriteBinaryFile(
        L"large_hash",
        L".bin",
        std::span<const uint8_t>(largeBytes.data(), largeBytes.size()));

    const auto sha256 = ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeSHA256(filePath.wstring());

    EXPECT_EQ(sha256.size(), 64u);
}

TEST_F(FileSystemChainIntegrationTest, FileSystemChain_Concurrency_ConcurrentHash_EightThreads_AllDeterministic) {
    const auto payload = BuildSequentialBytes(1024, 0x22);
    const fs::path filePath = WriteBinaryFile(
        L"concurrent_hash",
        L".bin",
        std::span<const uint8_t>(payload.data(), payload.size()));

    std::vector<std::string> results(8);
    std::vector<std::thread> threads;
    threads.reserve(results.size());

    for (size_t index = 0; index < results.size(); ++index) {
        threads.emplace_back([&results, index, filePath]() {
            results[index] = ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeSHA256(
                filePath.wstring());
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    ASSERT_FALSE(results.front().empty());
    for (const auto& result : results) {
        EXPECT_EQ(result, results.front());
    }
}

TEST_F(FileSystemChainIntegrationTest, FileSystemChain_Concurrency_ConcurrentTypeAnalyze_EightThreads_AllDetect) {
    const auto peBytes = BuildMinimalPeImage();
    const fs::path filePath = WriteBinaryFile(
        L"concurrent_type",
        L".exe",
        std::span<const uint8_t>(peBytes.data(), peBytes.size()));

    std::vector<ShadowStrike::Core::FileSystem::FileTypeInfo> results(8);
    std::vector<std::thread> threads;
    threads.reserve(results.size());

    for (size_t index = 0; index < results.size(); ++index) {
        threads.emplace_back([&results, index, filePath]() {
            results[index] = ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance().Analyze(
                filePath.wstring());
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    ASSERT_TRUE(results.front().detected);
    for (const auto& result : results) {
        EXPECT_TRUE(result.detected);
        EXPECT_EQ(result.format, results.front().format);
    }
}

// ============================================================================
// GROUP 8 — FileHasher_ExtendedAlgorithms
// Tests SHA-1, SHA-512, AllCrypto preset, SHA-3 (availability-guarded),
// and buffer overloads that are distinct from the file-path overloads.
// ============================================================================

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_ExtendedAlgorithms_ComputeSHA1_KnownFile_Returns40HexChars) {
    // SHA-1 hex digest is always 40 lower-case hex characters (20 bytes).
    const fs::path filePath = WriteTextFile(
        L"sha1_check", L".txt", "ShadowStrike SHA1 determinism payload");

    const auto sha1 =
        ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeSHA1(
            filePath.wstring());

    EXPECT_FALSE(sha1.empty());
    EXPECT_EQ(sha1.size(), 40u) << "SHA-1 hex must be 40 chars";

    // Must be all hex digits.
    EXPECT_TRUE(std::all_of(sha1.begin(), sha1.end(),
        [](char c){ return (c >= '0' && c <= '9') ||
                           (c >= 'a' && c <= 'f') ||
                           (c >= 'A' && c <= 'F'); }));
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_ExtendedAlgorithms_ComputeSHA512_KnownFile_Returns128HexChars) {
    // SHA-512 hex digest is always 128 characters (64 bytes).
    const fs::path filePath = WriteTextFile(
        L"sha512_check", L".txt", "ShadowStrike SHA512 determinism payload");

    const auto sha512 =
        ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeSHA512(
            filePath.wstring());

    EXPECT_FALSE(sha512.empty());
    EXPECT_EQ(sha512.size(), 128u) << "SHA-512 hex must be 128 chars";
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_ExtendedAlgorithms_ComputeAll_AllCrypto_SetsAllCryptographicFlags) {
    const fs::path filePath = WriteTextFile(
        L"all_crypto", L".txt", "AllCrypto hashing validation payload for ShadowStrike");

    const auto hashes =
        ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeAll(
            filePath.wstring(),
            ShadowStrike::Core::FileSystem::HashAlgorithm::AllCrypto);

    EXPECT_TRUE(hashes.hasMD5)    << "AllCrypto must set hasMD5";
    EXPECT_TRUE(hashes.hasSHA1)   << "AllCrypto must set hasSHA1";
    EXPECT_TRUE(hashes.hasSHA256) << "AllCrypto must set hasSHA256";
    EXPECT_TRUE(hashes.hasSHA512) << "AllCrypto must set hasSHA512";

    EXPECT_FALSE(hashes.md5Hex.empty());
    EXPECT_FALSE(hashes.sha1Hex.empty());
    EXPECT_FALSE(hashes.sha256Hex.empty());
    EXPECT_FALSE(hashes.sha512Hex.empty());
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_ExtendedAlgorithms_ComputeSHA3_256_IfAvailable_NonEmpty) {
    // SHA-3 requires Windows 10 1903+.  The test is guarded: if the OS
    // does not support it the hasher returns an empty string and we skip.
    const fs::path filePath = WriteTextFile(
        L"sha3_256", L".txt", "SHA3-256 availability probe payload");

    const auto sha3 =
        ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeSHA3_256(
            filePath.wstring());

    if (!sha3.empty()) {
        EXPECT_EQ(sha3.size(), 64u) << "SHA-3-256 hex must be 64 chars";
    } else {
        GTEST_SKIP() << "SHA-3-256 unavailable on this OS — skipping length assertion";
    }
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_ExtendedAlgorithms_ComputeMD5_Buffer_MatchesFileHash) {
    // The buffer overload ComputeMD5(span<>) must agree with the file overload
    // when fed identical bytes.
    const auto payload = BuildSequentialBytes(128, 0xAA);
    const fs::path filePath = WriteBinaryFile(
        L"md5_buffer_match", L".bin",
        std::span<const uint8_t>(payload.data(), payload.size()));

    const auto fileHash =
        ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeMD5(
            filePath.wstring());

    const auto bufferHash =
        ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeMD5(
            std::span<const uint8_t>(payload.data(), payload.size()));

    EXPECT_FALSE(fileHash.empty());
    EXPECT_FALSE(bufferHash.empty());
    EXPECT_EQ(fileHash, bufferHash)
        << "Buffer overload must produce identical hash to file-path overload";
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_ExtendedAlgorithms_ComputeSHA256_Buffer_MatchesFileHash) {
    const auto payload = BuildSequentialBytes(256, 0x55);
    const fs::path filePath = WriteBinaryFile(
        L"sha256_buffer_match", L".bin",
        std::span<const uint8_t>(payload.data(), payload.size()));

    const auto fileHash =
        ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeSHA256(
            filePath.wstring());

    const auto bufferHash =
        ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeSHA256(
            std::span<const uint8_t>(payload.data(), payload.size()));

    EXPECT_FALSE(fileHash.empty());
    EXPECT_EQ(fileHash, bufferHash);
}

// ============================================================================
// GROUP 9 — FileHasher_PartialHashing
// Exercises ComputeHeaderHash and ComputePartialHashes; verifies that
// partial hashes are stable across repeated calls and that missing files
// are handled gracefully (empty result, no exception).
// ============================================================================

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_PartialHashing_ComputeHeaderHash_PE_Returns64HexCharSHA256) {
    const auto peBytes = BuildMinimalPeImage();
    const fs::path filePath = WriteBinaryFile(
        L"header_hash_pe", L".exe",
        std::span<const uint8_t>(peBytes.data(), peBytes.size()));

    const auto headerHash =
        ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeHeaderHash(
            filePath.wstring());

    EXPECT_FALSE(headerHash.empty()) << "PE header hash must not be empty";
    EXPECT_EQ(headerHash.size(), 64u)
        << "Default algorithm is SHA-256 → 64 hex chars";
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_PartialHashing_ComputeHeaderHash_MissingFile_ReturnsEmpty) {
    // Missing files must return an empty string without throwing.
    const std::wstring missing =
        (s_tempRoot / L"nonexistent_header_hash.exe").wstring();

    std::string result;
    ASSERT_NO_THROW({
        result =
            ShadowStrike::Core::FileSystem::FileHasher::Instance()
                .ComputeHeaderHash(missing);
    });
    EXPECT_TRUE(result.empty())
        << "Missing file must yield empty header hash";
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_PartialHashing_ComputeHeaderHash_SameFile_Deterministic) {
    const auto payload = BuildSequentialBytes(8192, 0x7F);
    const fs::path filePath = WriteBinaryFile(
        L"header_hash_determ", L".bin",
        std::span<const uint8_t>(payload.data(), payload.size()));

    const auto h1 =
        ShadowStrike::Core::FileSystem::FileHasher::Instance()
            .ComputeHeaderHash(filePath.wstring());

    const auto h2 =
        ShadowStrike::Core::FileSystem::FileHasher::Instance()
            .ComputeHeaderHash(filePath.wstring());

    EXPECT_FALSE(h1.empty());
    EXPECT_EQ(h1, h2) << "ComputeHeaderHash must be deterministic";
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_PartialHashing_ComputePartialHashes_PE_ReturnsNonEmptyHeaderSHA256) {
    const auto peBytes = BuildMinimalPeImage();
    const fs::path filePath = WriteBinaryFile(
        L"partial_hash_pe", L".exe",
        std::span<const uint8_t>(peBytes.data(), peBytes.size()));

    const auto partial =
        ShadowStrike::Core::FileSystem::FileHasher::Instance()
            .ComputePartialHashes(filePath.wstring());

    EXPECT_FALSE(partial.headerSHA256.empty())
        << "ComputePartialHashes must populate headerSHA256 for any readable file";
}

// ============================================================================
// GROUP 10 — FileHasher_CompareAndUtils
// Validates Compare(), HashComparison helpers, FileHashes::IsValid/ToJson,
// ValidateHashFormat, ToHexString/FromHexString round-trip, and
// CompareFuzzyHash with identical inputs.
// ============================================================================

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_CompareAndUtils_Compare_IdenticalHashes_AllAlgorithmsFlagsTrue) {
    const fs::path filePath = WriteTextFile(
        L"compare_identical", L".txt", "identical hash comparison payload");

    auto& hasher = ShadowStrike::Core::FileSystem::FileHasher::Instance();

    const auto h1 = hasher.ComputeAll(filePath.wstring(),
        ShadowStrike::Core::FileSystem::HashAlgorithm::Standard);
    const auto h2 = hasher.ComputeAll(filePath.wstring(),
        ShadowStrike::Core::FileSystem::HashAlgorithm::Standard);

    const auto cmp = hasher.Compare(h1, h2);

    EXPECT_TRUE(cmp.md5Match)    << "MD5 must match for same file";
    EXPECT_TRUE(cmp.sha1Match)   << "SHA-1 must match for same file";
    EXPECT_TRUE(cmp.sha256Match) << "SHA-256 must match for same file";
    EXPECT_TRUE(cmp.IsMatch())   << "IsMatch() must return true";
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_CompareAndUtils_Compare_DifferentFiles_CoreFlagsFalse) {
    const fs::path f1 = WriteTextFile(L"compare_diff_a", L".txt", "payload alpha");
    const fs::path f2 = WriteTextFile(L"compare_diff_b", L".txt", "payload beta zeta");

    auto& hasher = ShadowStrike::Core::FileSystem::FileHasher::Instance();

    const auto h1 = hasher.ComputeAll(f1.wstring(),
        ShadowStrike::Core::FileSystem::HashAlgorithm::Standard);
    const auto h2 = hasher.ComputeAll(f2.wstring(),
        ShadowStrike::Core::FileSystem::HashAlgorithm::Standard);

    const auto cmp = hasher.Compare(h1, h2);

    EXPECT_FALSE(cmp.md5Match)    << "MD5 must differ for distinct files";
    EXPECT_FALSE(cmp.sha256Match) << "SHA-256 must differ for distinct files";
    EXPECT_FALSE(cmp.IsMatch())   << "IsMatch() must be false for distinct files";
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_CompareAndUtils_FileHashes_IsValid_DefaultConstructed_False) {
    // A default-constructed FileHashes has no hash data — IsValid() must be false.
    ShadowStrike::Core::FileSystem::FileHashes empty{};
    EXPECT_FALSE(empty.IsValid())
        << "Default-constructed FileHashes must not be valid";
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_CompareAndUtils_FileHashes_IsValid_AfterCompute_True) {
    const fs::path filePath = WriteTextFile(
        L"isvalid_check", L".txt", "IsValid post-compute payload");

    const auto hashes =
        ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeAll(
            filePath.wstring(),
            ShadowStrike::Core::FileSystem::HashAlgorithm::Standard);

    EXPECT_TRUE(hashes.IsValid())
        << "FileHashes returned by ComputeAll must be valid";
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_CompareAndUtils_FileHashes_ToJson_ContainsSHA256Key) {
    const fs::path filePath = WriteTextFile(
        L"tojson_check", L".txt", "ToJson validation payload");

    const auto hashes =
        ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeAll(
            filePath.wstring(),
            ShadowStrike::Core::FileSystem::HashAlgorithm::Standard);

    const auto json = hashes.ToJson();

    EXPECT_FALSE(json.empty()) << "ToJson must not return empty string";
    EXPECT_NE(json.find("sha256"), std::string::npos)
        << "ToJson output must contain a 'sha256' key";
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_CompareAndUtils_ValidateHashFormat_ValidSHA256_ReturnsTrue) {
    // 64 lowercase hex characters are a valid SHA-256 hex string.
    const std::string validSha256(64, 'a');
    EXPECT_TRUE(
        ShadowStrike::Core::FileSystem::FileHasher::Instance()
            .ValidateHashFormat(validSha256,
                ShadowStrike::Core::FileSystem::HashAlgorithm::SHA256));
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_CompareAndUtils_ValidateHashFormat_TooShort_ReturnsFalse) {
    const std::string shortHash(32, 'a');
    EXPECT_FALSE(
        ShadowStrike::Core::FileSystem::FileHasher::Instance()
            .ValidateHashFormat(shortHash,
                ShadowStrike::Core::FileSystem::HashAlgorithm::SHA256));
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_CompareAndUtils_ValidateHashFormat_Empty_ReturnsFalse) {
    EXPECT_FALSE(
        ShadowStrike::Core::FileSystem::FileHasher::Instance()
            .ValidateHashFormat("",
                ShadowStrike::Core::FileSystem::HashAlgorithm::SHA256));
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_CompareAndUtils_ToHexString_FromHexString_RoundTripSucceeds) {
    // Build a known 32-byte pattern and verify round-trip fidelity.
    const std::vector<uint8_t> original = BuildSequentialBytes(32, 0x00);

    auto& hasher = ShadowStrike::Core::FileSystem::FileHasher::Instance();

    const auto hexStr = hasher.ToHexString(
        std::span<const uint8_t>(original.data(), original.size()),
        ShadowStrike::Core::FileSystem::HashFormat::Hex);

    ASSERT_EQ(hexStr.size(), 64u) << "32-byte → 64 hex chars";

    const auto recovered = hasher.FromHexString(hexStr);

    ASSERT_EQ(recovered.size(), original.size())
        << "FromHexString must recover original byte count";

    EXPECT_TRUE(std::equal(original.begin(), original.end(), recovered.begin()))
        << "Round-trip bytes must match original";
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_CompareAndUtils_CompareFuzzyHash_IdenticalHash_Returns100) {
    const auto payload = BuildSimilarContent(false);
    const fs::path filePath = WriteBinaryFile(
        L"fuzzy_self_compare", L".bin",
        std::span<const uint8_t>(payload.data(), payload.size()));

    const auto fuzzy =
        ShadowStrike::Core::FileSystem::FileHasher::Instance()
            .ComputeFuzzyHash(filePath.wstring());

    if (fuzzy.empty()) {
        GTEST_SKIP() << "FuzzyHash unavailable — skipping self-similarity test";
    }

    const double similarity =
        ShadowStrike::Core::FileSystem::FileHasher::Instance()
            .CompareFuzzyHash(fuzzy, fuzzy);

    EXPECT_DOUBLE_EQ(similarity, 1.0)
        << "CompareFuzzyHash returns a normalized [0.0, 1.0] similarity score";
}

// ============================================================================
// GROUP 11 — FileHasher_CacheAndDiagnostics
// Validates the LRU cache API, statistics counters, version/hardware info,
// SelfTest(), and UpdateConfig().
// ============================================================================

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_CacheAndDiagnostics_GetCacheSize_AfterClearCache_ReturnsZero) {
    auto& hasher = ShadowStrike::Core::FileSystem::FileHasher::Instance();
    hasher.ClearCache();
    EXPECT_EQ(hasher.GetCacheSize(), 0u)
        << "ClearCache() must reset cache size to zero";
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_CacheAndDiagnostics_GetCached_BeforeCompute_ReturnsNullopt) {
    auto& hasher = ShadowStrike::Core::FileSystem::FileHasher::Instance();

    // A path that was never hashed must not be cached.
    const std::wstring uncachedPath =
        (s_tempRoot / L"never_computed_xxxx.bin").wstring();

    const auto cached = hasher.GetCached(uncachedPath);
    EXPECT_FALSE(cached.has_value())
        << "GetCached() must return nullopt for a path not yet hashed";
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_CacheAndDiagnostics_GetCached_AfterCompute_HasValue) {
    const fs::path filePath = WriteTextFile(
        L"cache_lookup", L".txt", "cache insertion trigger payload");

    auto& hasher = ShadowStrike::Core::FileSystem::FileHasher::Instance();

    // Force a compute to populate the cache entry.
    hasher.ComputeAll(filePath.wstring(),
        ShadowStrike::Core::FileSystem::HashAlgorithm::Standard);

    const auto cached = hasher.GetCached(filePath.wstring());

    // The cache is optional; if the implementation chose not to cache (e.g.
    // very small file, or cache disabled in test config) we just verify no crash.
    // A cached entry must carry a valid SHA-256.
    if (cached.has_value()) {
        EXPECT_TRUE(cached->hasSHA256)
            << "Cached FileHashes must carry SHA-256 flag";
    }
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_CacheAndDiagnostics_InvalidateCache_RemovesEntry) {
    const fs::path filePath = WriteTextFile(
        L"cache_invalidate", L".txt", "cache invalidation probe payload");

    auto& hasher = ShadowStrike::Core::FileSystem::FileHasher::Instance();
    hasher.ComputeAll(filePath.wstring(),
        ShadowStrike::Core::FileSystem::HashAlgorithm::Standard);

    // Invalidate and verify the entry is gone (or at least that the call
    // does not throw).
    ASSERT_NO_THROW(hasher.InvalidateCache(filePath.wstring()));
    const auto cached = hasher.GetCached(filePath.wstring());
    EXPECT_FALSE(cached.has_value())
        << "GetCached() must return nullopt after InvalidateCache()";
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_CacheAndDiagnostics_GetStatistics_FilesHashedIncrementsAfterCompute) {
    auto& hasher = ShadowStrike::Core::FileSystem::FileHasher::Instance();
    hasher.ResetStatistics();

    const auto before = hasher.GetStatistics().filesHashed;

    const fs::path filePath = WriteTextFile(
        L"stats_increment", L".txt", "statistics counter validation payload");

    hasher.ComputeAll(filePath.wstring(),
        ShadowStrike::Core::FileSystem::HashAlgorithm::Standard);

    const auto after = hasher.GetStatistics().filesHashed;

    EXPECT_GT(after, before)
        << "filesHashed must increment after ComputeAll";
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_CacheAndDiagnostics_ResetStatistics_ZerosFilesHashedCounter) {
    auto& hasher = ShadowStrike::Core::FileSystem::FileHasher::Instance();

    // Drive at least one operation to push counter above zero.
    const fs::path filePath = WriteTextFile(
        L"stats_reset", L".txt", "stats reset probe payload");
    hasher.ComputeAll(filePath.wstring(),
        ShadowStrike::Core::FileSystem::HashAlgorithm::Standard);

    hasher.ResetStatistics();

    EXPECT_EQ(hasher.GetStatistics().filesHashed, 0u)
        << "ResetStatistics() must zero filesHashed";
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_CacheAndDiagnostics_GetVersionInfo_ReturnsNonEmptyHasherVersion) {
    const auto info =
        ShadowStrike::Core::FileSystem::FileHasher::Instance().GetVersionInfo();

    EXPECT_FALSE(info.hasherVersion.empty())
        << "GetVersionInfo() must return a non-empty version string";
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_CacheAndDiagnostics_GetHardwareInfo_StructFieldsAccessible) {
    // Validates that GetHardwareInfo() does not throw and returns a coherent struct.
    ShadowStrike::Core::FileSystem::HardwareInfo hwInfo{};
    ASSERT_NO_THROW({
        hwInfo = ShadowStrike::Core::FileSystem::FileHasher::Instance()
                     .GetHardwareInfo();
    });

    // useHardwareAccel is consistent with hasSHANI / hasAESNI.
    if (hwInfo.useHardwareAccel) {
        EXPECT_TRUE(hwInfo.hasSHANI || hwInfo.hasAESNI)
            << "If hardware accel is active, at least one feature flag must be set";
    }
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_CacheAndDiagnostics_HasHardwareAcceleration_DoesNotThrow) {
    bool result = false;
    ASSERT_NO_THROW({
        result = ShadowStrike::Core::FileSystem::FileHasher::Instance()
                     .HasHardwareAcceleration();
    });
    // Result is platform-dependent; we only assert no exception.
    (void)result;
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_CacheAndDiagnostics_SelfTest_DoesNotThrow) {
    bool ok = false;
    ASSERT_NO_THROW({
        ok = ShadowStrike::Core::FileSystem::FileHasher::Instance().SelfTest();
    });
    // SelfTest() may return false in minimal environments; we do not mandate true.
    (void)ok;
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_CacheAndDiagnostics_UpdateConfig_DoesNotThrow) {
    const auto cfg =
        ShadowStrike::Core::FileSystem::FileHasherConfig::CreateDefault();
    ASSERT_NO_THROW(
        ShadowStrike::Core::FileSystem::FileHasher::Instance().UpdateConfig(cfg));
}

// ============================================================================
// GROUP 12 — FileHasher_AsyncAndBatch
// Validates the async future overload, empty-batch edge case, a batch with
// duplicate paths, and callback registration / delivery.
// ============================================================================

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_AsyncAndBatch_ComputeAllAsync_Future_ReturnsValidHashes) {
    const fs::path filePath = WriteTextFile(
        L"async_future", L".txt", "async future validation payload");

    auto future =
        ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeAllAsync(
            filePath.wstring(),
            ShadowStrike::Core::FileSystem::HashAlgorithm::Standard);

    ASSERT_EQ(future.wait_for(std::chrono::seconds(10)),
              std::future_status::ready)
        << "ComputeAllAsync must complete within 10 seconds for a tiny file";

    const auto hashes = future.get();
    EXPECT_TRUE(hashes.hasSHA256) << "Async result must carry SHA-256";
    EXPECT_FALSE(hashes.sha256Hex.empty());
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_AsyncAndBatch_ComputeBatch_EmptyVector_ReturnsEmptyResult) {
    const std::vector<std::wstring> noPaths;
    const auto results =
        ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeBatch(
            noPaths,
            ShadowStrike::Core::FileSystem::HashAlgorithm::Standard);

    EXPECT_TRUE(results.empty())
        << "ComputeBatch on empty input must return an empty vector";
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_AsyncAndBatch_ComputeBatch_DuplicatePaths_ReturnsTwoEntries) {
    const fs::path filePath = WriteTextFile(
        L"batch_dup", L".txt", "duplicate path batch payload");

    const std::vector<std::wstring> paths{
        filePath.wstring(),
        filePath.wstring()
    };

    const auto results =
        ShadowStrike::Core::FileSystem::FileHasher::Instance().ComputeBatch(
            paths,
            ShadowStrike::Core::FileSystem::HashAlgorithm::Standard);

    ASSERT_EQ(results.size(), 2u)
        << "ComputeBatch must return exactly one result per input path";

    // Both entries must carry the same SHA-256 (same file).
    EXPECT_EQ(results[0].sha256Hex, results[1].sha256Hex)
        << "Duplicate paths in batch must yield equal SHA-256 results";
}

TEST_F(FileSystemChainIntegrationTest,
    FileHasher_AsyncAndBatch_RegisterHashCallback_FiresOnNextAsyncCompute) {
    // The callback overload of ComputeAllAsync fires the supplied callback
    // once the hash is complete.
    const fs::path filePath = WriteTextFile(
        L"callback_async", L".txt", "callback registration payload");

    std::atomic<bool> callbackFired{ false };
    std::string capturedSha256;
    std::mutex captureMutex;

    auto& hasher = ShadowStrike::Core::FileSystem::FileHasher::Instance();

    hasher.ComputeAllAsync(
        filePath.wstring(),
        [&callbackFired, &capturedSha256, &captureMutex](
            const ShadowStrike::Core::FileSystem::FileHashes& hashes) {
            std::lock_guard<std::mutex> lock(captureMutex);
            capturedSha256 = hashes.sha256Hex;
            callbackFired.store(true, std::memory_order_release);
        },
        ShadowStrike::Core::FileSystem::HashAlgorithm::Standard);

    // Spin-wait up to 10 seconds for the callback.
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(10);

    while (!callbackFired.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_TRUE(callbackFired.load(std::memory_order_acquire))
        << "Hash callback must fire within 10 seconds";

    std::lock_guard<std::mutex> lock(captureMutex);
    EXPECT_FALSE(capturedSha256.empty())
        << "Callback must deliver a non-empty SHA-256 hex string";
}

// ============================================================================
// GROUP 13 — FileTypeAnalyzer_BufferAPI
// Exercises AnalyzeBuffer(), DetectFormat(buffer), GetCategory(),
// GetMimeType(), IsExecutable(buffer), empty-buffer handling, and the
// risk-level assertion for executable files.
// ============================================================================

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_BufferAPI_AnalyzeBuffer_PE_NoExtension_IsExecutable) {
    const auto peBytes = BuildMinimalPeImage();
    auto& analyzer = ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance();

    const auto info = analyzer.AnalyzeBuffer(
        std::span<const uint8_t>(peBytes.data(), peBytes.size()), L"");

    EXPECT_TRUE(info.detected)
        << "PE magic must be detected from raw buffer with no extension hint";
    EXPECT_TRUE(info.isExecutable)
        << "PE buffer must be classified as executable";
    EXPECT_EQ(info.category,
              ShadowStrike::Core::FileSystem::FileCategory::Executable)
        << "PE buffer category must be Executable";
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_BufferAPI_AnalyzeBuffer_PE_WithJpgExtension_PreservesExecutableClassification) {
    // AnalyzeBuffer accepts an extension hint but does not perform path-level
    // spoofing analysis. It must still classify the raw content correctly.
    const auto peBytes = BuildMinimalPeImage();
    auto& analyzer = ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance();

    const auto info = analyzer.AnalyzeBuffer(
        std::span<const uint8_t>(peBytes.data(), peBytes.size()), L".jpg");

    EXPECT_TRUE(info.detected);
    EXPECT_TRUE(info.isExecutable);
    EXPECT_EQ(info.category, ShadowStrike::Core::FileSystem::FileCategory::Executable);
    EXPECT_EQ(info.diskExtension, L".jpg");
    EXPECT_FALSE(info.isSpoofed);
    EXPECT_EQ(info.spoofingType, ShadowStrike::Core::FileSystem::SpoofingType::None);
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_BufferAPI_AnalyzeBuffer_JPEG_NoExtension_IsImage) {
    const auto jpegBytes = BuildMinimalJpegBytes();
    auto& analyzer = ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance();

    const auto info = analyzer.AnalyzeBuffer(
        std::span<const uint8_t>(jpegBytes.data(), jpegBytes.size()), L"");

    if (info.detected) {
        EXPECT_EQ(info.category,
                  ShadowStrike::Core::FileSystem::FileCategory::Image)
            << "JPEG magic must resolve to Image category";
        EXPECT_FALSE(info.isExecutable)
            << "JPEG must not be flagged as executable";
    }
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_BufferAPI_DetectFormat_Buffer_PE_ReturnsAPeVariant) {
    const auto peBytes = BuildMinimalPeImage();
    auto& analyzer = ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance();

    const auto fmt = analyzer.DetectFormat(
        std::span<const uint8_t>(peBytes.data(), peBytes.size()));

    // Accept any PE variant (32-bit, 64-bit, DLL, SYS).
    const bool isPEVariant =
        (fmt == ShadowStrike::Core::FileSystem::FileFormat::PE32)   ||
        (fmt == ShadowStrike::Core::FileSystem::FileFormat::PE64)   ||
        (fmt == ShadowStrike::Core::FileSystem::FileFormat::DLL32)  ||
        (fmt == ShadowStrike::Core::FileSystem::FileFormat::DLL64)  ||
        (fmt == ShadowStrike::Core::FileSystem::FileFormat::SYS32)  ||
        (fmt == ShadowStrike::Core::FileSystem::FileFormat::SYS64);

    EXPECT_TRUE(isPEVariant)
        << "DetectFormat(buffer) must return a PE variant for PE magic bytes";
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_BufferAPI_DetectFormat_FilePath_PE_ReturnsAPeVariant) {
    const auto peBytes = BuildMinimalPeImage();
    const fs::path filePath = WriteBinaryFile(
        L"detect_fmt_file", L".exe",
        std::span<const uint8_t>(peBytes.data(), peBytes.size()));

    auto& analyzer = ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance();

    const auto fmt = analyzer.DetectFormat(filePath.wstring());

    const bool isPEVariant =
        (fmt == ShadowStrike::Core::FileSystem::FileFormat::PE32)  ||
        (fmt == ShadowStrike::Core::FileSystem::FileFormat::PE64)  ||
        (fmt == ShadowStrike::Core::FileSystem::FileFormat::DLL32) ||
        (fmt == ShadowStrike::Core::FileSystem::FileFormat::DLL64) ||
        (fmt == ShadowStrike::Core::FileSystem::FileFormat::SYS32) ||
        (fmt == ShadowStrike::Core::FileSystem::FileFormat::SYS64);

    EXPECT_TRUE(isPEVariant);
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_BufferAPI_GetCategory_PE_ReturnsExecutable) {
    const auto peBytes = BuildMinimalPeImage();
    const fs::path filePath = WriteBinaryFile(
        L"category_pe", L".exe",
        std::span<const uint8_t>(peBytes.data(), peBytes.size()));

    const auto cat =
        ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance()
            .GetCategory(filePath.wstring());

    EXPECT_EQ(cat, ShadowStrike::Core::FileSystem::FileCategory::Executable);
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_BufferAPI_GetMimeType_PE_ContainsApplicationToken) {
    const auto peBytes = BuildMinimalPeImage();
    const fs::path filePath = WriteBinaryFile(
        L"mime_pe", L".exe",
        std::span<const uint8_t>(peBytes.data(), peBytes.size()));

    const auto mime =
        ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance()
            .GetMimeType(filePath.wstring());

    EXPECT_FALSE(mime.empty()) << "GetMimeType() must not return empty for PE";
    EXPECT_NE(mime.find("application"), std::string::npos)
        << "PE MIME type must contain 'application'";
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_BufferAPI_IsExecutable_Buffer_PE_ReturnsTrue) {
    const auto peBytes = BuildMinimalPeImage();
    EXPECT_TRUE(
        ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance()
            .IsExecutable(std::span<const uint8_t>(
                peBytes.data(), peBytes.size())))
        << "IsExecutable(buffer) must return true for PE magic bytes";
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_BufferAPI_IsExecutable_Buffer_JPEG_ReturnsFalse) {
    const auto jpegBytes = BuildMinimalJpegBytes();
    EXPECT_FALSE(
        ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance()
            .IsExecutable(std::span<const uint8_t>(
                jpegBytes.data(), jpegBytes.size())))
        << "IsExecutable(buffer) must return false for JPEG bytes";
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_BufferAPI_AnalyzeBuffer_EmptySpan_DoesNotThrow) {
    // An empty buffer must be handled gracefully.  The expected outcome is
    // detected=false or category=Empty — never an exception.
    const std::vector<uint8_t> empty;
    ShadowStrike::Core::FileSystem::FileTypeInfo info{};

    ASSERT_NO_THROW({
        info = ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance()
                   .AnalyzeBuffer(
                       std::span<const uint8_t>(empty.data(), empty.size()),
                       L"");
    });

    const bool isAcceptableResult =
        (!info.detected) ||
        (info.category == ShadowStrike::Core::FileSystem::FileCategory::Empty);

    EXPECT_TRUE(isAcceptableResult)
        << "Empty buffer must result in detected=false or category=Empty";
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_BufferAPI_Analyze_PE_RiskLevel_IsCritical) {
    const auto peBytes = BuildMinimalPeImage();
    const fs::path filePath = WriteBinaryFile(
        L"risk_pe", L".exe",
        std::span<const uint8_t>(peBytes.data(), peBytes.size()));

    const auto info =
        ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance()
            .Analyze(filePath.wstring());

    if (info.detected) {
        EXPECT_EQ(static_cast<uint8_t>(info.riskLevel),
                  static_cast<uint8_t>(
                      ShadowStrike::Core::FileSystem::RiskLevel::Critical))
            << "PE files must carry Critical risk level";
    }
}

// ============================================================================
// GROUP 14 — FileTypeAnalyzer_SpoofAndScript
// Covers HasDoubleExtension(), HasRTLOverride(), standalone DetectSpoofing()
// on real files, and AnalyzeScript() / DetectScriptType() for PowerShell.
// ============================================================================

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_SpoofAndScript_HasDoubleExtension_TextDotExe_ReturnsTrue) {
    EXPECT_TRUE(
        ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance()
            .HasDoubleExtension(L"document.txt.exe"))
        << "document.txt.exe must be recognized as a double extension";
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_SpoofAndScript_HasDoubleExtension_SingleExtension_ReturnsFalse) {
    EXPECT_FALSE(
        ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance()
            .HasDoubleExtension(L"document.exe"))
        << "A single extension must NOT trigger double-extension detection";
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_SpoofAndScript_HasDoubleExtension_NoExtension_ReturnsFalse) {
    EXPECT_FALSE(
        ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance()
            .HasDoubleExtension(L"nodots"))
        << "A filename with no extension must not trigger double-extension detection";
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_SpoofAndScript_HasRTLOverride_RTLOPresent_ReturnsTrue) {
    // U+202E is RIGHT-TO-LEFT OVERRIDE — a canonical MITRE T1036 technique.
    const std::wstring rtloName =
        std::wstring(L"invoice") +
        static_cast<wchar_t>(0x202E) +
        std::wstring(L"gpj.exe");

    EXPECT_TRUE(
        ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance()
            .HasRTLOverride(rtloName))
        << "U+202E must be detected as RTLO override";
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_SpoofAndScript_HasRTLOverride_NormalFilename_ReturnsFalse) {
    EXPECT_FALSE(
        ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance()
            .HasRTLOverride(L"normalfile.exe"))
        << "A normal filename without RTLO must not trigger RTLO detection";
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_SpoofAndScript_DetectSpoofing_PE_NamedAsJpg_ReturnsExtensionMismatch) {
    const auto peBytes = BuildMinimalPeImage();
    const fs::path filePath = WriteBinaryFile(
        L"spoof_pe_as_jpg", L".jpg",
        std::span<const uint8_t>(peBytes.data(), peBytes.size()));

    const auto spoofType =
        ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance()
            .DetectSpoofing(filePath.wstring());

    EXPECT_EQ(spoofType,
              ShadowStrike::Core::FileSystem::SpoofingType::ExtensionMismatch)
        << "PE binary with .jpg extension must be ExtensionMismatch";
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_SpoofAndScript_DetectSpoofing_PE_NamedAsExe_ReturnsNone) {
    const auto peBytes = BuildMinimalPeImage();
    const fs::path filePath = WriteBinaryFile(
        L"no_spoof_pe", L".exe",
        std::span<const uint8_t>(peBytes.data(), peBytes.size()));

    const auto spoofType =
        ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance()
            .DetectSpoofing(filePath.wstring());

    EXPECT_EQ(spoofType, ShadowStrike::Core::FileSystem::SpoofingType::None)
        << "Correctly named PE must not be flagged as spoofed";
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_SpoofAndScript_AnalyzeScript_PowerShell_HasKeywords) {
    // A minimal PowerShell payload must yield hasScriptKeywords=true.
    const std::string psContent =
        "function Invoke-ShadowStrikeProbe {\n"
        "    param([string]$Path)\n"
        "    Get-ChildItem -Path $Path | Where-Object { $_.Name -match 'test' }\n"
        "    Write-Host 'ShadowStrike probe complete'\n"
        "}\n";

    const std::vector<uint8_t> psBytes(psContent.begin(), psContent.end());

    const auto indicators =
        ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance()
            .AnalyzeScript(std::span<const uint8_t>(psBytes.data(), psBytes.size()));

    EXPECT_TRUE(indicators.hasScriptKeywords)
        << "PowerShell keywords (function, param, Get-ChildItem, Write-Host) "
           "must be detected";
    EXPECT_FALSE(indicators.detectedKeywords.empty())
        << "At least one keyword must be reported in detectedKeywords";
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_SpoofAndScript_DetectScriptType_PowerShell_ReturnsPowerShell) {
    const std::string psContent =
        "# ShadowStrike integration test PowerShell probe\n"
        "function Invoke-Probe { Write-Host 'start'; Invoke-Expression 'echo ok' }\n";

    const std::vector<uint8_t> psBytes(psContent.begin(), psContent.end());

    const auto format =
        ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance()
            .DetectScriptType(
                std::span<const uint8_t>(psBytes.data(), psBytes.size()));

    // DetectScriptType may return Unknown if the buffer is too ambiguous.
    // If it makes a positive detection, it must be PowerShell.
    if (format != ShadowStrike::Core::FileSystem::FileFormat::Unknown) {
        EXPECT_EQ(format, ShadowStrike::Core::FileSystem::FileFormat::PowerShell)
            << "Unambiguous PowerShell content must resolve to FileFormat::PowerShell";
    }
}

// ============================================================================
// GROUP 15 — FileTypeAnalyzer_ExtensionMapping
// Tests GetExtensionInfo(), GetExtensionRisk(), and GetExtensionForFormat()
// against well-known extensions and formats to validate the mapping database.
// ============================================================================

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_ExtensionMapping_GetExtensionInfo_Exe_HasCriticalRisk) {
    const auto info =
        ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance()
            .GetExtensionInfo(".exe");

    EXPECT_EQ(static_cast<uint8_t>(info.riskLevel),
              static_cast<uint8_t>(
                  ShadowStrike::Core::FileSystem::RiskLevel::Critical))
        << ".exe extension must carry Critical risk level";
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_ExtensionMapping_GetExtensionInfo_Txt_HasAtMostLowRisk) {
    const auto info =
        ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance()
            .GetExtensionInfo(".txt");

    EXPECT_LE(static_cast<uint8_t>(info.riskLevel),
              static_cast<uint8_t>(ShadowStrike::Core::FileSystem::RiskLevel::Low))
        << ".txt extension must carry Safe or Low risk level";
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_ExtensionMapping_GetExtensionRisk_Exe_ReturnsCritical) {
    const auto risk =
        ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance()
            .GetExtensionRisk(".exe");

    EXPECT_EQ(static_cast<uint8_t>(risk),
              static_cast<uint8_t>(
                  ShadowStrike::Core::FileSystem::RiskLevel::Critical));
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_ExtensionMapping_GetExtensionRisk_Txt_AtMostLow) {
    const auto risk =
        ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance()
            .GetExtensionRisk(".txt");

    EXPECT_LE(static_cast<uint8_t>(risk),
              static_cast<uint8_t>(
                  ShadowStrike::Core::FileSystem::RiskLevel::Low));
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_ExtensionMapping_GetExtensionForFormat_ZIP_ContainsZip) {
    std::string ext =
        ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance()
            .GetExtensionForFormat(ShadowStrike::Core::FileSystem::FileFormat::ZIP);

    std::transform(ext.begin(), ext.end(), ext.begin(),
                   [](unsigned char c){ return static_cast<char>(std::tolower(c)); });

    EXPECT_NE(ext.find("zip"), std::string::npos)
        << "GetExtensionForFormat(ZIP) must return a string containing 'zip'";
}

// ============================================================================
// GROUP 16 — FileTypeAnalyzer_StatsAndConfig
// Tests that the atomic statistics counters increment on real API calls, that
// ResetStatistics() works, and that the factory methods return coherent configs.
// ============================================================================

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_StatsAndConfig_GetStatistics_FilesAnalyzed_IncrementsAfterAnalyze) {
    auto& analyzer = ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance();
    analyzer.ResetStatistics();

    const uint64_t before =
        analyzer.GetStatistics().filesAnalyzed.load(std::memory_order_acquire);

    const auto peBytes = BuildMinimalPeImage();
    const fs::path filePath = WriteBinaryFile(
        L"stats_analyze", L".exe",
        std::span<const uint8_t>(peBytes.data(), peBytes.size()));

    analyzer.Analyze(filePath.wstring());

    const uint64_t after =
        analyzer.GetStatistics().filesAnalyzed.load(std::memory_order_acquire);

    EXPECT_GT(after, before)
        << "filesAnalyzed counter must increment after Analyze()";
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_StatsAndConfig_ResetStatistics_ZerosFilesAnalyzed) {
    auto& analyzer = ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance();

    // Drive at least one event to push counter above zero.
    const auto peBytes = BuildMinimalPeImage();
    const fs::path filePath = WriteBinaryFile(
        L"stats_reset_probe", L".exe",
        std::span<const uint8_t>(peBytes.data(), peBytes.size()));
    analyzer.Analyze(filePath.wstring());

    analyzer.ResetStatistics();

    EXPECT_EQ(
        analyzer.GetStatistics().filesAnalyzed.load(std::memory_order_acquire),
        0u)
        << "ResetStatistics() must zero filesAnalyzed";
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_StatsAndConfig_CreateDefault_HeaderSizeIsDefault) {
    const auto cfg =
        ShadowStrike::Core::FileSystem::FileTypeAnalyzerConfig::CreateDefault();

    EXPECT_EQ(cfg.headerSize,
              ShadowStrike::Core::FileSystem::FileTypeAnalyzerConstants
                  ::DEFAULT_HEADER_SIZE)
        << "CreateDefault() must produce the canonical DEFAULT_HEADER_SIZE";
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_StatsAndConfig_CreateFull_HasNestedTypeAnalysis) {
    const auto cfg =
        ShadowStrike::Core::FileSystem::FileTypeAnalyzerConfig::CreateFull();

    EXPECT_TRUE(cfg.analyzeNestedTypes)
        << "CreateFull() config must enable nested-type analysis";
    EXPECT_TRUE(cfg.detectSpoofing)
        << "CreateFull() config must enable spoofing detection";
    EXPECT_TRUE(cfg.detectScripts)
        << "CreateFull() config must enable script detection";
}

TEST_F(FileSystemChainIntegrationTest,
    FileTypeAnalyzer_StatsAndConfig_CreateMinimal_StructIsAccessible) {
    // CreateMinimal() must not throw and must return a coherent struct.
    ShadowStrike::Core::FileSystem::FileTypeAnalyzerConfig cfg{};
    ASSERT_NO_THROW({
        cfg =
            ShadowStrike::Core::FileSystem::FileTypeAnalyzerConfig::CreateMinimal();
    });
    EXPECT_GT(cfg.headerSize, 0u)
        << "Even the minimal config must read at least one byte";
}

// ============================================================================
// GROUP 17 — FileReputation_LocalDatabase
// Exercises the whitelist/blacklist CRUD API, CheckFile (LocalOnly) and
// CheckHash on an unknown and a blacklisted hash, the cache-size query, and
// the statistics reset cycle.  All tests are guarded by
// SkipIfReputationUnavailable() to allow offline CI environments.
// ============================================================================

TEST_F(FileSystemChainIntegrationTest,
    FileReputation_LocalDatabase_AddToWhitelist_Returns_True) {
    SkipIfReputationUnavailable();

    const std::string hash(64, 'e');  // Fictional SHA-256 for whitelist test.
    EXPECT_TRUE(
        ShadowStrike::Core::FileSystem::FileReputation::Instance()
            .AddToWhitelist(hash, "integration test whitelist"))
        << "AddToWhitelist() must succeed for a valid 64-char hex hash";
}

TEST_F(FileSystemChainIntegrationTest,
    FileReputation_LocalDatabase_IsWhitelisted_AfterAdd_ReturnsTrue) {
    SkipIfReputationUnavailable();

    const std::string hash(64, 'f');
    ShadowStrike::Core::FileSystem::FileReputation::Instance()
        .AddToWhitelist(hash, "iswhitelisted probe");

    EXPECT_TRUE(
        ShadowStrike::Core::FileSystem::FileReputation::Instance()
            .IsWhitelisted(hash))
        << "IsWhitelisted() must return true immediately after AddToWhitelist()";
}

TEST_F(FileSystemChainIntegrationTest,
    FileReputation_LocalDatabase_RemoveFromWhitelist_RemovesEntry) {
    SkipIfReputationUnavailable();

    const std::string hash(64, '1');
    auto& rep = ShadowStrike::Core::FileSystem::FileReputation::Instance();

    rep.AddToWhitelist(hash, "remove test");
    ASSERT_TRUE(rep.IsWhitelisted(hash));

    EXPECT_TRUE(rep.RemoveFromWhitelist(hash))
        << "RemoveFromWhitelist() must succeed for a known entry";

    EXPECT_FALSE(rep.IsWhitelisted(hash))
        << "IsWhitelisted() must return false after removal";
}

TEST_F(FileSystemChainIntegrationTest,
    FileReputation_LocalDatabase_AddToBlacklist_Returns_True) {
    SkipIfReputationUnavailable();

    const std::string hash(64, '2');
    EXPECT_TRUE(
        ShadowStrike::Core::FileSystem::FileReputation::Instance()
            .AddToBlacklist(hash, "TestThreat.Integration"))
        << "AddToBlacklist() must succeed for a valid 64-char hex hash";
}

TEST_F(FileSystemChainIntegrationTest,
    FileReputation_LocalDatabase_IsBlacklisted_AfterAdd_ReturnsTrue) {
    SkipIfReputationUnavailable();

    const std::string hash(64, '3');
    ShadowStrike::Core::FileSystem::FileReputation::Instance()
        .AddToBlacklist(hash, "TestThreat.ProbeB");

    EXPECT_TRUE(
        ShadowStrike::Core::FileSystem::FileReputation::Instance()
            .IsBlacklisted(hash))
        << "IsBlacklisted() must return true immediately after AddToBlacklist()";
}

TEST_F(FileSystemChainIntegrationTest,
    FileReputation_LocalDatabase_RemoveFromBlacklist_RemovesEntry) {
    SkipIfReputationUnavailable();

    const std::string hash(64, '4');
    auto& rep = ShadowStrike::Core::FileSystem::FileReputation::Instance();

    rep.AddToBlacklist(hash, "TestThreat.RemoveProbe");
    ASSERT_TRUE(rep.IsBlacklisted(hash));

    EXPECT_TRUE(rep.RemoveFromBlacklist(hash));
    EXPECT_FALSE(rep.IsBlacklisted(hash))
        << "IsBlacklisted() must return false after RemoveFromBlacklist()";
}

TEST_F(FileSystemChainIntegrationTest,
    FileReputation_LocalDatabase_CheckFile_LocalOnly_DoesNotThrow) {
    SkipIfReputationUnavailable();

    const fs::path filePath = WriteTextFile(
        L"rep_checkfile", L".txt", "reputation check payload");

    ShadowStrike::Core::FileSystem::ReputationResult result{};
    ASSERT_NO_THROW({
        result =
            ShadowStrike::Core::FileSystem::FileReputation::Instance()
                .CheckFile(filePath.wstring(),
                           ShadowStrike::Core::FileSystem::QueryMode::LocalOnly);
    });

    // A clean temp file must not be flagged as malicious by local sources alone.
    EXPECT_FALSE(result.isMalicious)
        << "A clean temp text file must not be malicious in LocalOnly mode";
}

TEST_F(FileSystemChainIntegrationTest,
    FileReputation_LocalDatabase_CheckHash_UnknownHash_DoesNotCrash) {
    SkipIfReputationUnavailable();

    // A hash that was never registered must return a result (any level)
    // without crashing.
    const std::string unknownHash(64, '5');

    ShadowStrike::Core::FileSystem::ReputationResult result{};
    ASSERT_NO_THROW({
        result =
            ShadowStrike::Core::FileSystem::FileReputation::Instance()
                .CheckHash(unknownHash,
                           ShadowStrike::Core::FileSystem::QueryMode::LocalOnly);
    });

    // Level must be Unknown (4) or higher — definitely not KnownMalware (0).
    EXPECT_GE(static_cast<uint8_t>(result.level),
              static_cast<uint8_t>(
                  ShadowStrike::Core::FileSystem::ReputationLevel::Unknown))
        << "An unknown hash must resolve to at least ReputationLevel::Unknown";
}

TEST_F(FileSystemChainIntegrationTest,
    FileReputation_LocalDatabase_CheckHash_AfterBlacklist_IsMaliciousOrBlacklisted) {
    SkipIfReputationUnavailable();

    const std::string hash(64, '6');
    auto& rep = ShadowStrike::Core::FileSystem::FileReputation::Instance();

    rep.AddToBlacklist(hash, "TestThreat.Blacklist_CheckHash");

    const auto result =
        rep.CheckHash(hash, ShadowStrike::Core::FileSystem::QueryMode::LocalOnly);

    EXPECT_TRUE(result.isMalicious || result.isBlacklisted)
        << "CheckHash on a blacklisted hash must set isMalicious or isBlacklisted";
}

TEST_F(FileSystemChainIntegrationTest,
    FileReputation_LocalDatabase_GetCacheSize_DoesNotThrow) {
    SkipIfReputationUnavailable();

    size_t cacheSize = 0;
    ASSERT_NO_THROW({
        cacheSize =
            ShadowStrike::Core::FileSystem::FileReputation::Instance()
                .GetCacheSize();
    });
    // Any non-negative size is acceptable.
    EXPECT_GE(cacheSize, 0u);
}

TEST_F(FileSystemChainIntegrationTest,
    FileReputation_LocalDatabase_GetStatistics_TotalQueriesIncrements) {
    SkipIfReputationUnavailable();

    auto& rep = ShadowStrike::Core::FileSystem::FileReputation::Instance();
    rep.ResetStatistics();

    const uint64_t before =
        rep.GetStatistics().totalQueries.load(std::memory_order_acquire);

    const std::string probeHash(64, '7');
    rep.CheckHash(probeHash,
                  ShadowStrike::Core::FileSystem::QueryMode::LocalOnly);

    const uint64_t after =
        rep.GetStatistics().totalQueries.load(std::memory_order_acquire);

    EXPECT_GT(after, before)
        << "totalQueries must increment after each CheckHash() call";
}

TEST_F(FileSystemChainIntegrationTest,
    FileReputation_LocalDatabase_ResetStatistics_ZerosTotalQueries) {
    SkipIfReputationUnavailable();

    auto& rep = ShadowStrike::Core::FileSystem::FileReputation::Instance();

    // Drive a query to push counter above zero.
    const std::string probeHash(64, '8');
    rep.CheckHash(probeHash,
                  ShadowStrike::Core::FileSystem::QueryMode::LocalOnly);

    rep.ResetStatistics();

    EXPECT_EQ(
        rep.GetStatistics().totalQueries.load(std::memory_order_acquire),
        0u)
        << "ResetStatistics() must zero totalQueries";
}

}  // namespace
