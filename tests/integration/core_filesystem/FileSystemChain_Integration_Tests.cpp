/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Integration Tests - Tier 5: FileSystem Chain
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

#include "pch.h"

#include "../../../src/Shared_modules/Core/FileSystem/FileHasher.hpp"
#include "../../../src/Shared_modules/Core/FileSystem/FileReputation.hpp"
#include "../../../src/Shared_modules/Core/FileSystem/FileTypeAnalyzer.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <set>
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

TEST_F(FileSystemChainIntegrationTest, FileTypeAnalyzer_SpoofingDetection_Analyze_DoubleExtension_DetectsSpoofing) {
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

    const auto info = ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance().Analyze(filePath.wstring());

    EXPECT_TRUE(info.detected);
    EXPECT_TRUE(info.isSpoofed);
    EXPECT_EQ(info.spoofingType, ShadowStrike::Core::FileSystem::SpoofingType::DoubleExtension);
}

TEST_F(FileSystemChainIntegrationTest, FileTypeAnalyzer_SpoofingDetection_Analyze_LegitJpeg_NotSpoofed) {
    const auto jpegBytes = BuildMinimalJpegBytes();
    const fs::path filePath = WriteBinaryFile(
        L"legit_jpeg",
        L".jpg",
        std::span<const uint8_t>(jpegBytes.data(), jpegBytes.size()));

    const auto info = ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance().Analyze(filePath.wstring());

    EXPECT_TRUE(info.detected);
    EXPECT_FALSE(info.isSpoofed);
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

}  // namespace
