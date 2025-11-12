/*
 * ============================================================================
 * ShadowStrike FileUtils - ENTERPRISE-GRADE UNIT TESTS
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Comprehensive unit test suite for FileUtils module
 * Coverage: Path operations, file I/O, atomic operations, directory management,
 *           walking, ADS, SHA-256, secure erase, permissions, edge cases
 *
 * Test Standards: Sophos/CrowdStrike enterprise quality
 *
 * ============================================================================
 */

#include <gtest/gtest.h>
#include "../../../src/Utils/FileUtils.hpp"

#include <vector>
#include <string>
#include <random>
#include <algorithm>
#include <chrono>
#include <thread>
#include <atomic>
#include <filesystem>

using namespace ShadowStrike::Utils::FileUtils;

// ============================================================================
// Logger Safety Macros for Test Environment
// ============================================================================
#ifdef SS_LOG_ERROR
    // Logger already defined
#else
    #define SS_LOG_ERROR(...)
    #define SS_LOG_LAST_ERROR(...)
    #define SS_LOG_WARN(...)
#endif

// ============================================================================
// Test Fixture with Comprehensive Helper Methods
// ============================================================================
class FileUtilsTest : public ::testing::Test {
protected:
    std::wstring testRoot;
    std::wstring tempDir;
    bool setupSuccess = false;

    void SetUp() override {
        try {
            wchar_t tempPath[MAX_PATH]{};
            ASSERT_NE(GetTempPathW(MAX_PATH, tempPath), 0u) << "GetTempPathW failed";
            
            GUID guid{};
            HRESULT hr = CoCreateGuid(&guid);
            ASSERT_TRUE(SUCCEEDED(hr)) << "CoCreateGuid failed with hr=" << std::hex << hr;
            
            wchar_t guidStr[64];
            swprintf_s(guidStr, L"%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                guid.Data1, guid.Data2, guid.Data3,
                guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
                guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
            
            testRoot = std::wstring(tempPath) + L"ShadowStrike_FileUtils_UT_" + guidStr;
            tempDir = testRoot + L"\\temp";
            
            Error err{};
            ASSERT_TRUE(CreateDirectories(testRoot, &err)) 
                << "Failed to create test root: " << err.win32;
            ASSERT_TRUE(CreateDirectories(tempDir, &err))
                << "Failed to create temp dir: " << err.win32;
            
            setupSuccess = true;
        }
        catch (const std::exception& e) {
            FAIL() << "SetUp exception: " << e.what();
        }
    }

    void TearDown() override {
        if (!testRoot.empty()) {
            try {
                Error err{};
                RemoveDirectoryRecursive(testRoot, &err);
            }
            catch (...) {
                // Ignore cleanup errors
            }
        }
    }

    // Helper: Generate random bytes
    static std::vector<std::byte> RandomBytes(size_t n) {
        static std::mt19937_64 rng(std::random_device{}());
        std::uniform_int_distribution<int> dist(0, 255);
        std::vector<std::byte> v(n);
        for (size_t i = 0; i < n; ++i) {
            v[i] = static_cast<std::byte>(dist(rng));
        }
        return v;
    }

    // Helper: Generate pattern bytes
    static std::vector<std::byte> PatternBytes(size_t n) {
        static const char pattern[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        static const size_t patternLen = 36;
        std::vector<std::byte> v(n);
        for (size_t i = 0; i < n; ++i) {
            v[i] = static_cast<std::byte>(pattern[i % patternLen]);
        }
        return v;
    }

    // Helper: Build full path
    std::wstring Path(std::wstring_view relative) const {
        return testRoot + L"\\" + std::wstring(relative);
    }

    // Helper: Write file with bytes
    std::wstring WriteBytes(std::wstring_view relative, const std::vector<std::byte>& data) {
        std::wstring path = Path(relative);
        Error err{};
        EXPECT_TRUE(WriteAllBytesAtomic(path, data, &err))
            << "Failed to write: " << path << ", error: " << err.win32;
        return path;
    }

    // Helper: Write file with text
    std::wstring WriteText(std::wstring_view relative, std::string_view text) {
        std::wstring path = Path(relative);
        Error err{};
        EXPECT_TRUE(WriteAllTextUtf8Atomic(path, text, &err))
            << "Failed to write text: " << path << ", error: " << err.win32;
        return path;
    }

    // Helper: Verify file content matches
    bool VerifyContent(std::wstring_view path, const std::vector<std::byte>& expected) {
        std::vector<std::byte> actual;
        Error err{};
        if (!ReadAllBytes(path, actual, &err)) return false;
        return actual == expected;
    }
};

// ============================================================================
// PATH HELPER TESTS
// ============================================================================

TEST_F(FileUtilsTest, AddLongPathPrefix_RegularPath) {
    EXPECT_EQ(AddLongPathPrefix(L"C:\\Windows\\System32"), 
              L"\\\\?\\C:\\Windows\\System32");
}

TEST_F(FileUtilsTest, AddLongPathPrefix_UNCPath) {
    EXPECT_EQ(AddLongPathPrefix(L"\\\\server\\share\\folder"), 
              L"\\\\?\\UNC\\server\\share\\folder");
}

TEST_F(FileUtilsTest, AddLongPathPrefix_AlreadyPrefixed) {
    std::wstring already = L"\\\\?\\C:\\Data";
    EXPECT_EQ(AddLongPathPrefix(already), already);
}

TEST_F(FileUtilsTest, AddLongPathPrefix_EmptyPath) {
    EXPECT_TRUE(AddLongPathPrefix(L"").empty());
}

TEST_F(FileUtilsTest, AddLongPathPrefix_RelativePath) {
    std::wstring result = AddLongPathPrefix(L"relative\\path");
    EXPECT_EQ(result, L"\\\\?\\relative\\path");
}

TEST_F(FileUtilsTest, NormalizePath_RelativePath) {
    Error err{};
    std::wstring normalized = NormalizePath(L"..\\Windows", false, &err);
    EXPECT_FALSE(normalized.empty());
    EXPECT_NE(normalized.find(L"Windows"), std::wstring::npos);
}

TEST_F(FileUtilsTest, NormalizePath_WithResolve) {
    auto testFile = WriteText(L"normalize.txt", "test");
    Error err{};
    std::wstring normalized = NormalizePath(testFile, true, &err);
    EXPECT_FALSE(normalized.empty());
    EXPECT_NE(normalized.find(L"normalize.txt"), std::wstring::npos);
}

TEST_F(FileUtilsTest, NormalizePath_EmptyPath) {
    Error err{};
    std::wstring result = NormalizePath(L"", false, &err);
    EXPECT_TRUE(result.empty());
    EXPECT_NE(err.win32, static_cast<DWORD>(0));
}

TEST_F(FileUtilsTest, NormalizePath_InvalidCharacters) {
    Error err{};
    std::wstring result = NormalizePath(L"C:\\invalid<>|?.txt", false, &err);
    // Windows will normalize but may fail on actual file operations
    EXPECT_NE(err.win32, static_cast<DWORD>(0));
}

// ============================================================================
// EXISTS & STAT TESTS
// ============================================================================

TEST_F(FileUtilsTest, Exists_File) {
    auto file = WriteText(L"exists_file.txt", "content");
    EXPECT_TRUE(Exists(file));
}

TEST_F(FileUtilsTest, Exists_Directory) {
    EXPECT_TRUE(Exists(testRoot));
}

TEST_F(FileUtilsTest, Exists_NonExistent) {
    EXPECT_FALSE(Exists(Path(L"nonexistent.txt")));
}

TEST_F(FileUtilsTest, IsDirectory_File) {
    auto file = WriteText(L"isdir_file.txt", "data");
    EXPECT_FALSE(IsDirectory(file));
}

TEST_F(FileUtilsTest, IsDirectory_Directory) {
    EXPECT_TRUE(IsDirectory(testRoot));
}

TEST_F(FileUtilsTest, IsDirectory_NonExistent) {
    EXPECT_FALSE(IsDirectory(Path(L"nonexistent_dir")));
}

TEST_F(FileUtilsTest, Stat_File) {
    std::string content = "Stat test data";
    auto file = WriteText(L"stat_file.txt", content);
    
    FileStat stat{};
    Error err{};
    ASSERT_TRUE(Stat(file, stat, &err));
    
    EXPECT_TRUE(stat.exists);
    EXPECT_FALSE(stat.isDirectory);
    EXPECT_FALSE(stat.isReparsePoint);
    EXPECT_EQ(stat.size, content.size());
    EXPECT_NE(stat.attributes, static_cast<DWORD>(0));
}

TEST_F(FileUtilsTest, Stat_Directory) {
    FileStat stat{};
    Error err{};
    ASSERT_TRUE(Stat(testRoot, stat, &err));
    
    EXPECT_TRUE(stat.exists);
    EXPECT_TRUE(stat.isDirectory);
    EXPECT_EQ(stat.size, static_cast<uint64_t>(0));
}

TEST_F(FileUtilsTest, Stat_NonExistent) {
    FileStat stat{};
    Error err{};
    EXPECT_FALSE(Stat(Path(L"missing.txt"), stat, &err));
    EXPECT_FALSE(stat.exists);
    EXPECT_NE(err.win32, static_cast<DWORD>(0));
}

TEST_F(FileUtilsTest, Stat_HiddenFile) {
    auto file = WriteText(L"hidden.txt", "hidden content");
    SetFileAttributesW(file.c_str(), FILE_ATTRIBUTE_HIDDEN);
    
    FileStat stat{};
    Error err{};
    ASSERT_TRUE(Stat(file, stat, &err));
    EXPECT_TRUE(stat.isHidden);
    EXPECT_TRUE(stat.attributes & FILE_ATTRIBUTE_HIDDEN);
    
    // Cleanup
    SetFileAttributesW(file.c_str(), FILE_ATTRIBUTE_NORMAL);
}

TEST_F(FileUtilsTest, Stat_SystemFile) {
    auto file = WriteText(L"system.txt", "system content");
    SetFileAttributesW(file.c_str(), FILE_ATTRIBUTE_SYSTEM);
    
    FileStat stat{};
    Error err{};
    ASSERT_TRUE(Stat(file, stat, &err));
    EXPECT_TRUE(stat.isSystem);
    
    // Cleanup
    SetFileAttributesW(file.c_str(), FILE_ATTRIBUTE_NORMAL);
}

// ============================================================================
// READ OPERATIONS TESTS
// ============================================================================

TEST_F(FileUtilsTest, ReadAllBytes_SmallFile) {
    auto data = RandomBytes(1024);
    auto file = WriteBytes(L"read_small.bin", data);
    
    std::vector<std::byte> read;
    Error err{};
    ASSERT_TRUE(ReadAllBytes(file, read, &err));
    EXPECT_EQ(read, data);
}

TEST_F(FileUtilsTest, ReadAllBytes_EmptyFile) {
    std::vector<std::byte> empty;
    auto file = WriteBytes(L"read_empty.bin", empty);
    
    std::vector<std::byte> read;
    Error err{};
    ASSERT_TRUE(ReadAllBytes(file, read, &err));
    EXPECT_TRUE(read.empty());
}

TEST_F(FileUtilsTest, ReadAllBytes_LargeFile) {
    // 5MB file
    auto data = PatternBytes(5 * 1024 * 1024);
    auto file = WriteBytes(L"read_large.bin", data);
    
    std::vector<std::byte> read;
    Error err{};
    ASSERT_TRUE(ReadAllBytes(file, read, &err));
    EXPECT_EQ(read.size(), data.size());
    EXPECT_EQ(read, data);
}

TEST_F(FileUtilsTest, ReadAllBytes_NonExistent) {
    std::vector<std::byte> read;
    Error err{};
    EXPECT_FALSE(ReadAllBytes(Path(L"nonexistent.bin"), read, &err));
    EXPECT_NE(err.win32, static_cast<DWORD>(0));
}

TEST_F(FileUtilsTest, ReadAllTextUtf8_SimpleText) {
    std::string content = "Hello, ShadowStrike!\nTest line 2.";
    auto file = WriteText(L"read_text.txt", content);
    
    std::string read;
    Error err{};
    ASSERT_TRUE(ReadAllTextUtf8(file, read, &err));
    EXPECT_EQ(read, content);
}

TEST_F(FileUtilsTest, ReadAllTextUtf8_EmptyFile) {
    auto file = WriteText(L"read_empty.txt", "");
    
    std::string read;
    Error err{};
    ASSERT_TRUE(ReadAllTextUtf8(file, read, &err));
    EXPECT_TRUE(read.empty());
}

TEST_F(FileUtilsTest, ReadAllTextUtf8_MultilineText) {
    std::string content = "Line 1\nLine 2\r\nLine 3\nLine 4";
    auto file = WriteText(L"read_multiline.txt", content);
    
    std::string read;
    Error err{};
    ASSERT_TRUE(ReadAllTextUtf8(file, read, &err));
    EXPECT_EQ(read, content);
}

TEST_F(FileUtilsTest, ReadAllTextUtf8_UTF8Content) {
    // UTF-8 encoded strings (Euro sign, Turkish, etc.)
    std::string content = "UTF-8: \xE2\x82\xAC \xC4\x9E\xC3\xBC\xC5\x9F";
    auto file = WriteText(L"read_utf8.txt", content);
    
    std::string read;
    Error err{};
    ASSERT_TRUE(ReadAllTextUtf8(file, read, &err));
    EXPECT_EQ(read, content);
}

// ============================================================================
// WRITE OPERATIONS TESTS
// ============================================================================

TEST_F(FileUtilsTest, WriteAllBytesAtomic_NewFile) {
    auto data = RandomBytes(2048);
    std::wstring path = Path(L"write_new.bin");
    
    Error err{};
    ASSERT_TRUE(WriteAllBytesAtomic(path, data, &err));
    EXPECT_TRUE(Exists(path));
    EXPECT_TRUE(VerifyContent(path, data));
}

TEST_F(FileUtilsTest, WriteAllBytesAtomic_Overwrite) {
    auto original = RandomBytes(1024);
    auto file = WriteBytes(L"write_overwrite.bin", original);
    
    auto newData = RandomBytes(2048);
    Error err{};
    ASSERT_TRUE(WriteAllBytesAtomic(file, newData, &err));
    EXPECT_TRUE(VerifyContent(file, newData));
}

TEST_F(FileUtilsTest, WriteAllBytesAtomic_EmptyData) {
    std::vector<std::byte> empty;
    std::wstring path = Path(L"write_empty.bin");
    
    Error err{};
    ASSERT_TRUE(WriteAllBytesAtomic(path, empty, &err));
    EXPECT_TRUE(Exists(path));
    
    FileStat stat{};
    ASSERT_TRUE(Stat(path, stat, &err));
    EXPECT_EQ(stat.size, static_cast<uint64_t>(0));
}

TEST_F(FileUtilsTest, WriteAllBytesAtomic_NullPointer) {
    Error err{};
    EXPECT_FALSE(WriteAllBytesAtomic(Path(L"null.bin"), nullptr, 100, &err));
    EXPECT_NE(err.win32, static_cast<DWORD>(0));
}

TEST_F(FileUtilsTest, WriteAllBytesAtomic_NullPointerZeroSize) {
    Error err{};
    // nullptr with size 0 should succeed (empty file)
    EXPECT_TRUE(WriteAllBytesAtomic(Path(L"null_zero.bin"), nullptr, 0, &err));
}

TEST_F(FileUtilsTest, WriteAllBytesAtomic_VectorOverload) {
    auto data = RandomBytes(4096);
    std::wstring path = Path(L"write_vector.bin");
    
    Error err{};
    ASSERT_TRUE(WriteAllBytesAtomic(path, data, &err));
    EXPECT_TRUE(VerifyContent(path, data));
}

TEST_F(FileUtilsTest, WriteAllTextUtf8Atomic_SimpleText) {
    std::wstring path = Path(L"write_text.txt");
    std::string content = "Hello, ShadowStrike!";
    
    Error err{};
    ASSERT_TRUE(WriteAllTextUtf8Atomic(path, content, &err));
    
    std::string read;
    ASSERT_TRUE(ReadAllTextUtf8(path, read, &err));
    EXPECT_EQ(read, content);
}

TEST_F(FileUtilsTest, WriteAllTextUtf8Atomic_MultilineText) {
    std::wstring path = Path(L"write_multiline.txt");
    std::string content = "Line 1\nLine 2\r\nLine 3\n";
    
    Error err{};
    ASSERT_TRUE(WriteAllTextUtf8Atomic(path, content, &err));
    
    std::string read;
    ASSERT_TRUE(ReadAllTextUtf8(path, read, &err));
    EXPECT_EQ(read, content);
}

TEST_F(FileUtilsTest, WriteAllTextUtf8Atomic_UTF8Content) {
    std::wstring path = Path(L"write_utf8.txt");
    std::string content = "UTF-8 Test: \xE2\x82\xAC \xC3\xA7 \xC4\x9F";
    
    Error err{};
    ASSERT_TRUE(WriteAllTextUtf8Atomic(path, content, &err));
    
    std::string read;
    ASSERT_TRUE(ReadAllTextUtf8(path, read, &err));
    EXPECT_EQ(read, content);
}

// ============================================================================
// REPLACE FILE ATOMIC TESTS
// ============================================================================

TEST_F(FileUtilsTest, ReplaceFileAtomic_Basic) {
    auto srcData = RandomBytes(1024);
    auto srcFile = WriteBytes(L"replace_src.bin", srcData);
    
    auto dstData = RandomBytes(512);
    auto dstFile = WriteBytes(L"replace_dst.bin", dstData);
    
    Error err{};
    ASSERT_TRUE(ReplaceFileAtomic(srcFile, dstFile, &err));
    
    EXPECT_FALSE(Exists(srcFile));
    EXPECT_TRUE(Exists(dstFile));
    EXPECT_TRUE(VerifyContent(dstFile, srcData));
}

TEST_F(FileUtilsTest, ReplaceFileAtomic_CreateNew) {
    auto srcData = RandomBytes(1024);
    auto srcFile = WriteBytes(L"replace_src2.bin", srcData);
    
    std::wstring dstFile = Path(L"replace_dst2.bin");
    
    Error err{};
    ASSERT_TRUE(ReplaceFileAtomic(srcFile, dstFile, &err));
    
    EXPECT_FALSE(Exists(srcFile));
    EXPECT_TRUE(Exists(dstFile));
    EXPECT_TRUE(VerifyContent(dstFile, srcData));
}

TEST_F(FileUtilsTest, ReplaceFileAtomic_SourceMissing) {
    Error err{};
    EXPECT_FALSE(ReplaceFileAtomic(
        Path(L"nonexistent_src.bin"),
        Path(L"target.bin"),
        &err));
    EXPECT_NE(err.win32, static_cast<DWORD>(0));
}

// ============================================================================
// DIRECTORY OPERATIONS TESTS
// ============================================================================

TEST_F(FileUtilsTest, CreateDirectories_SingleLevel) {
    std::wstring dirPath = Path(L"single_level");
    Error err{};
    ASSERT_TRUE(CreateDirectories(dirPath, &err));
    EXPECT_TRUE(IsDirectory(dirPath));
}

TEST_F(FileUtilsTest, CreateDirectories_MultipleLevels) {
    std::wstring dirPath = Path(L"level1\\level2\\level3");
    Error err{};
    ASSERT_TRUE(CreateDirectories(dirPath, &err));
    EXPECT_TRUE(IsDirectory(dirPath));
}

TEST_F(FileUtilsTest, CreateDirectories_AlreadyExists) {
    Error err{};
    ASSERT_TRUE(CreateDirectories(testRoot, &err));
    // Should succeed when directory already exists
    EXPECT_TRUE(CreateDirectories(testRoot, &err));
}

TEST_F(FileUtilsTest, CreateDirectories_EmptyPath) {
    Error err{};
    EXPECT_TRUE(CreateDirectories(L"", &err));
}

TEST_F(FileUtilsTest, CreateDirectories_PathTraversal) {
    std::wstring malicious = Path(L"..\\..\\..\\Windows\\System32\\malicious");
    Error err{};
    EXPECT_FALSE(CreateDirectories(malicious, &err));
    EXPECT_NE(err.win32, static_cast<DWORD>(0));
}

TEST_F(FileUtilsTest, CreateDirectories_InvalidCharacters) {
    std::wstring invalid = Path(L"invalid<>|*?.dir");
    Error err{};
    EXPECT_FALSE(CreateDirectories(invalid, &err));
}

TEST_F(FileUtilsTest, CreateDirectories_InvalidColon) {
    std::wstring invalid = Path(L"sub\\bad:name");
    Error err{};
    EXPECT_FALSE(CreateDirectories(invalid, &err));
}

TEST_F(FileUtilsTest, RemoveFile_Existing) {
    auto file = WriteText(L"remove_test.txt", "test");
    
    Error err{};
    ASSERT_TRUE(RemoveFile(file, &err));
    EXPECT_FALSE(Exists(file));
}

TEST_F(FileUtilsTest, RemoveFile_NonExistent) {
    Error err{};
    // Should succeed for non-existent files
    EXPECT_TRUE(RemoveFile(Path(L"nonexistent.txt"), &err));
}

TEST_F(FileUtilsTest, RemoveFile_ReadOnly) {
    auto file = WriteText(L"readonly.txt", "readonly");
    SetFileAttributesW(file.c_str(), FILE_ATTRIBUTE_READONLY);
    
    Error err{};
    EXPECT_FALSE(RemoveFile(file, &err));
    
    // Cleanup
    SetFileAttributesW(file.c_str(), FILE_ATTRIBUTE_NORMAL);
    RemoveFile(file, &err);
}

TEST_F(FileUtilsTest, RemoveDirectoryRecursive_Empty) {
    std::wstring emptyDir = Path(L"empty_dir");
    Error err{};
    CreateDirectories(emptyDir, &err);
    
    ASSERT_TRUE(RemoveDirectoryRecursive(emptyDir, &err));
    EXPECT_FALSE(Exists(emptyDir));
}

TEST_F(FileUtilsTest, RemoveDirectoryRecursive_WithFiles) {
    std::wstring dirPath = Path(L"dir_with_files");
    Error err{};
    CreateDirectories(dirPath, &err);
    
    WriteText(L"dir_with_files\\file1.txt", "content1");
    WriteText(L"dir_with_files\\file2.txt", "content2");
    
    ASSERT_TRUE(RemoveDirectoryRecursive(dirPath, &err));
    EXPECT_FALSE(Exists(dirPath));
}

TEST_F(FileUtilsTest, RemoveDirectoryRecursive_Nested) {
    std::wstring basePath = Path(L"nested");
    Error err{};
    CreateDirectories(basePath + L"\\a\\b\\c", &err);
    
    WriteText(L"nested\\file1.txt", "1");
    WriteText(L"nested\\a\\file2.txt", "2");
    WriteText(L"nested\\a\\b\\file3.txt", "3");
    WriteText(L"nested\\a\\b\\c\\file4.txt", "4");
    
    ASSERT_TRUE(RemoveDirectoryRecursive(basePath, &err));
    EXPECT_FALSE(Exists(basePath));
}

TEST_F(FileUtilsTest, RemoveDirectoryRecursive_NonExistent) {
    Error err{};
    EXPECT_TRUE(RemoveDirectoryRecursive(Path(L"nonexistent_dir"), &err));
}

// ============================================================================
// WALK DIRECTORY TESTS
// ============================================================================

TEST_F(FileUtilsTest, WalkDirectory_EmptyDirectory) {
    std::wstring emptyDir = Path(L"walk_empty");
    Error err{};
    CreateDirectories(emptyDir, &err);
    
    int fileCount = 0;
    WalkOptions opts{};
    opts.recursive = false;
    
    ASSERT_TRUE(WalkDirectory(emptyDir, opts,
        [&](const std::wstring&, const WIN32_FIND_DATAW&) {
            fileCount++;
            return true;
        }, &err));
    
    EXPECT_EQ(fileCount, 0);
}

TEST_F(FileUtilsTest, WalkDirectory_SingleLevel) {
    std::wstring walkDir = Path(L"walk_single");
    Error err{};
    CreateDirectories(walkDir, &err);
    
    WriteText(L"walk_single\\file1.txt", "1");
    WriteText(L"walk_single\\file2.txt", "2");
    WriteText(L"walk_single\\file3.txt", "3");
    
    int fileCount = 0;
    WalkOptions opts{};
    opts.recursive = false;
    
    ASSERT_TRUE(WalkDirectory(walkDir, opts,
        [&](const std::wstring&, const WIN32_FIND_DATAW&) {
            fileCount++;
            return true;
        }, &err));
    
    EXPECT_EQ(fileCount, 3);
}

TEST_F(FileUtilsTest, WalkDirectory_Recursive) {
    std::wstring walkDir = Path(L"walk_recursive");
    Error err{};
    CreateDirectories(walkDir + L"\\sub1\\sub2", &err);
    
    WriteText(L"walk_recursive\\root.txt", "root");
    WriteText(L"walk_recursive\\sub1\\file1.txt", "1");
    WriteText(L"walk_recursive\\sub1\\sub2\\file2.txt", "2");
    
    int fileCount = 0;
    WalkOptions opts{};
    opts.recursive = true;
    opts.includeDirs = false;
    
    ASSERT_TRUE(WalkDirectory(walkDir, opts,
        [&](const std::wstring&, const WIN32_FIND_DATAW&) {
            fileCount++;
            return true;
        }, &err));
    
    EXPECT_EQ(fileCount, 3);
}

TEST_F(FileUtilsTest, WalkDirectory_IncludeDirs) {
    std::wstring walkDir = Path(L"walk_dirs");
    Error err{};
    CreateDirectories(walkDir + L"\\subdir1", &err);
    CreateDirectories(walkDir + L"\\subdir2", &err);
    WriteText(L"walk_dirs\\file.txt", "test");
    
    int dirCount = 0;
    int fileCount = 0;
    WalkOptions opts{};
    opts.recursive = true;
    opts.includeDirs = true;
    
    ASSERT_TRUE(WalkDirectory(walkDir, opts,
        [&](const std::wstring&, const WIN32_FIND_DATAW& fd) {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                dirCount++;
            } else {
                fileCount++;
            }
            return true;
        }, &err));
    
    EXPECT_EQ(dirCount, 2);
    EXPECT_EQ(fileCount, 1);
}

TEST_F(FileUtilsTest, WalkDirectory_MaxDepth) {
    std::wstring walkDir = Path(L"walk_depth");
    Error err{};
    CreateDirectories(walkDir + L"\\l1\\l2\\l3\\l4", &err);
    
    WriteText(L"walk_depth\\f0.txt", "0");
    WriteText(L"walk_depth\\l1\\f1.txt", "1");
    WriteText(L"walk_depth\\l1\\l2\\f2.txt", "2");
    WriteText(L"walk_depth\\l1\\l2\\l3\\f3.txt", "3");
    WriteText(L"walk_depth\\l1\\l2\\l3\\l4\\f4.txt", "4");
    
    int fileCount = 0;
    WalkOptions opts{};
    opts.recursive = true;
    opts.maxDepth = 2;
    
    ASSERT_TRUE(WalkDirectory(walkDir, opts,
        [&](const std::wstring&, const WIN32_FIND_DATAW&) {
            fileCount++;
            return true;
        }, &err));
    
    // Should find: f0.txt, f1.txt, f2.txt (depth 0, 1, 2)
    EXPECT_LE(fileCount, 3);
}

TEST_F(FileUtilsTest, WalkDirectory_SkipHidden) {
    std::wstring walkDir = Path(L"walk_hidden");
    Error err{};
    CreateDirectories(walkDir, &err);
    
    auto normalFile = WriteText(L"walk_hidden\\normal.txt", "normal");
    auto hiddenFile = WriteText(L"walk_hidden\\hidden.txt", "hidden");
    SetFileAttributesW(hiddenFile.c_str(), FILE_ATTRIBUTE_HIDDEN);
    
    int fileCount = 0;
    WalkOptions opts{};
    opts.recursive = false;
    opts.skipHidden = true;
    
    ASSERT_TRUE(WalkDirectory(walkDir, opts,
        [&](const std::wstring&, const WIN32_FIND_DATAW&) {
            fileCount++;
            return true;
        }, &err));
    
    EXPECT_EQ(fileCount, 1);
    
    // Cleanup
    SetFileAttributesW(hiddenFile.c_str(), FILE_ATTRIBUTE_NORMAL);
}

TEST_F(FileUtilsTest, WalkDirectory_EarlyExit) {
    std::wstring walkDir = Path(L"walk_exit");
    Error err{};
    CreateDirectories(walkDir, &err);
    
    for (int i = 0; i < 10; i++) {
        std::wstring name = L"walk_exit\\file" + std::to_wstring(i) + L".txt";
        WriteText(name.c_str(), std::to_string(i));
    }
    
    int fileCount = 0;
    WalkOptions opts{};
    
    ASSERT_TRUE(WalkDirectory(walkDir, opts,
        [&](const std::wstring&, const WIN32_FIND_DATAW&) {
            fileCount++;
            return fileCount < 5; // Stop after 5 files
        }, &err));
    
    EXPECT_EQ(fileCount, 5);
}

TEST_F(FileUtilsTest, WalkDirectory_Cancellation) {
    std::wstring walkDir = Path(L"walk_cancel");
    Error err{};
    CreateDirectories(walkDir, &err);
    
    for (int i = 0; i < 20; i++) {
        std::wstring name = L"walk_cancel\\file" + std::to_wstring(i) + L".txt";
        WriteText(name.c_str(), std::to_string(i));
    }
    
    std::atomic<bool> cancelFlag{false};
    int fileCount = 0;
    
    WalkOptions opts{};
    opts.cancelFlag = &cancelFlag;
    
    ASSERT_TRUE(WalkDirectory(walkDir, opts,
        [&](const std::wstring&, const WIN32_FIND_DATAW&) {
            fileCount++;
            if (fileCount >= 10) {
                cancelFlag.store(true);
            }
            return true;
        }, &err));
    
    EXPECT_LE(fileCount, 11);
}

// ============================================================================
// ALTERNATE DATA STREAMS TESTS
// ============================================================================

TEST_F(FileUtilsTest, ListAlternateStreams_NoStreams) {
    auto testFile = WriteText(L"ads_none.txt", "main content");
    
    std::vector<AlternateStreamInfo> streams;
    Error err{};
    ASSERT_TRUE(ListAlternateStreams(testFile, streams, &err));
    EXPECT_TRUE(streams.empty());
}

TEST_F(FileUtilsTest, ListAlternateStreams_WithStream) {
    auto testFile = WriteText(L"ads_test.txt", "main content");
    
    // Create alternate data stream
    std::wstring adsPath = testFile + L":stream1:$DATA";
    HANDLE h = CreateFileW(adsPath.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        GTEST_SKIP() << "ADS not supported on this file system";
    }
    
    const char* data = "ADS content";
    DWORD written;
    WriteFile(h, data, static_cast<DWORD>(strlen(data)), &written, nullptr);
    CloseHandle(h);
    
    std::vector<AlternateStreamInfo> streams;
    Error err{};
    ASSERT_TRUE(ListAlternateStreams(testFile, streams, &err));
    
    bool foundStream = false;
    for (const auto& stream : streams) {
        if (stream.name.find(L"stream1") != std::wstring::npos) {
            foundStream = true;
            EXPECT_GT(stream.size, 0u);
        }
    }
    EXPECT_TRUE(foundStream);
}

TEST_F(FileUtilsTest, ListAlternateStreams_NonExistent) {
    std::vector<AlternateStreamInfo> streams;
    Error err{};
    EXPECT_FALSE(ListAlternateStreams(Path(L"nonexistent.txt"), streams, &err));
    EXPECT_NE(err.win32, static_cast<DWORD>(0));
}

// ============================================================================
// SHA-256 HASH TESTS
// ============================================================================

TEST_F(FileUtilsTest, ComputeFileSHA256_SmallFile) {
    std::string content = "Hello, ShadowStrike!";
    auto testFile = WriteText(L"sha256_small.txt", content);
    
    std::array<uint8_t, 32> hash{};
    Error err{};
    ASSERT_TRUE(ComputeFileSHA256(testFile, hash, &err));
    
    // Verify hash is not all zeros
    bool allZeros = true;
    for (auto byte : hash) {
        if (byte != 0) {
            allZeros = false;
            break;
        }
    }
    EXPECT_FALSE(allZeros);
}

TEST_F(FileUtilsTest, ComputeFileSHA256_EmptyFile) {
    auto testFile = WriteText(L"sha256_empty.txt", "");
    
    std::array<uint8_t, 32> hash{};
    Error err{};
    ASSERT_TRUE(ComputeFileSHA256(testFile, hash, &err));
    
    // SHA-256 of empty file is known
    // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    EXPECT_EQ(hash[0], 0xe3);
    EXPECT_EQ(hash[1], 0xb0);
    EXPECT_EQ(hash[2], 0xc4);
    EXPECT_EQ(hash[3], 0x42);
}

TEST_F(FileUtilsTest, ComputeFileSHA256_SameContent) {
    std::string content = "Test content for hash verification";
    auto file1 = WriteText(L"sha256_1.txt", content);
    auto file2 = WriteText(L"sha256_2.txt", content);
    
    std::array<uint8_t, 32> hash1{}, hash2{};
    Error err{};
    ASSERT_TRUE(ComputeFileSHA256(file1, hash1, &err));
    ASSERT_TRUE(ComputeFileSHA256(file2, hash2, &err));
    
    EXPECT_EQ(hash1, hash2);
}

TEST_F(FileUtilsTest, ComputeFileSHA256_DifferentContent) {
    auto file1 = WriteText(L"sha256_diff1.txt", "Content 1");
    auto file2 = WriteText(L"sha256_diff2.txt", "Content 2");
    
    std::array<uint8_t, 32> hash1{}, hash2{};
    Error err{};
    ASSERT_TRUE(ComputeFileSHA256(file1, hash1, &err));
    ASSERT_TRUE(ComputeFileSHA256(file2, hash2, &err));
    
    EXPECT_NE(hash1, hash2);
}

TEST_F(FileUtilsTest, ComputeFileSHA256_NonExistent) {
    std::array<uint8_t, 32> hash{};
    Error err{};
    
    EXPECT_FALSE(ComputeFileSHA256(Path(L"nonexistent.txt"), hash, &err));
    EXPECT_NE(err.win32, static_cast<DWORD>(0));
}

TEST_F(FileUtilsTest, ComputeFileSHA256_LargeFile) {
    // 2MB file
    auto data = PatternBytes(2 * 1024 * 1024);
    auto testFile = WriteBytes(L"sha256_large.bin", data);
    
    std::array<uint8_t, 32> hash{};
    Error err{};
    ASSERT_TRUE(ComputeFileSHA256(testFile, hash, &err));
    
    bool allZeros = true;
    for (auto byte : hash) {
        if (byte != 0) {
            allZeros = false;
            break;
        }
    }
    EXPECT_FALSE(allZeros);
}

// ============================================================================
// SECURE ERASE TESTS
// ============================================================================

TEST_F(FileUtilsTest, SecureEraseFile_SinglePass) {
    auto data = RandomBytes(4096);
    auto testFile = WriteBytes(L"secure_erase1.bin", data);
    
    Error err{};
    ASSERT_TRUE(SecureEraseFile(testFile, SecureEraseMode::SinglePassZero, &err));
    EXPECT_FALSE(Exists(testFile));
}

TEST_F(FileUtilsTest, SecureEraseFile_TriplePass) {
    auto data = RandomBytes(4096);
    auto testFile = WriteBytes(L"secure_erase2.bin", data);
    
    Error err{};
    ASSERT_TRUE(SecureEraseFile(testFile, SecureEraseMode::TriplePass, &err));
    EXPECT_FALSE(Exists(testFile));
}

TEST_F(FileUtilsTest, SecureEraseFile_SmallFile) {
    auto testFile = WriteText(L"secure_erase_small.txt", "test");
    
    Error err{};
    ASSERT_TRUE(SecureEraseFile(testFile, SecureEraseMode::SinglePassZero, &err));
    EXPECT_FALSE(Exists(testFile));
}

TEST_F(FileUtilsTest, SecureEraseFile_Directory) {
    std::wstring dirPath = Path(L"secure_erase_dir");
    Error err{};
    CreateDirectories(dirPath, &err);
    
    // Should fail on directory
    EXPECT_FALSE(SecureEraseFile(dirPath, SecureEraseMode::SinglePassZero, &err));
    EXPECT_EQ(err.win32, static_cast<DWORD>(ERROR_ACCESS_DENIED));
}

TEST_F(FileUtilsTest, SecureEraseFile_NonExistent) {
    Error err{};
    EXPECT_FALSE(SecureEraseFile(Path(L"nonexistent.bin"), 
                                 SecureEraseMode::SinglePassZero, &err));
    EXPECT_NE(err.win32, static_cast<DWORD>(0));
}

// ============================================================================
// EXCLUSIVE FILE HANDLE TESTS
// ============================================================================

TEST_F(FileUtilsTest, OpenFileExclusive_Success) {
    auto testFile = WriteText(L"exclusive.txt", "test");
    
    Error err{};
    HANDLE h = OpenFileExclusive(testFile, &err);
    ASSERT_NE(h, INVALID_HANDLE_VALUE);
    
    // Try to open again - should fail
    HANDLE h2 = OpenFileExclusive(testFile, &err);
    EXPECT_EQ(h2, INVALID_HANDLE_VALUE);
    
    CloseHandle(h);
}

TEST_F(FileUtilsTest, OpenFileExclusive_NonExistent) {
    Error err{};
    HANDLE h = OpenFileExclusive(Path(L"nonexistent.txt"), &err);
    EXPECT_EQ(h, INVALID_HANDLE_VALUE);
    EXPECT_NE(err.win32, static_cast<DWORD>(0));
}

// ============================================================================
// TIME OPERATIONS TESTS
// ============================================================================

TEST_F(FileUtilsTest, GetTimes_ValidFile) {
    auto testFile = WriteText(L"times_test.txt", "test");
    
    FILETIME creation{}, lastAccess{}, lastWrite{};
    Error err{};
    ASSERT_TRUE(GetTimes(testFile, creation, lastAccess, lastWrite, &err));
    
    // All times should be non-zero
    EXPECT_TRUE(creation.dwLowDateTime != 0 || creation.dwHighDateTime != 0);
    EXPECT_TRUE(lastWrite.dwLowDateTime != 0 || lastWrite.dwHighDateTime != 0);
}

TEST_F(FileUtilsTest, GetTimes_NonExistent) {
    FILETIME creation{}, lastAccess{}, lastWrite{};
    Error err{};
    
    EXPECT_FALSE(GetTimes(Path(L"nonexistent.txt"), 
                          creation, lastAccess, lastWrite, &err));
    EXPECT_NE(err.win32, static_cast<DWORD>(0));
}

// ============================================================================
// EDGE CASES & SECURITY TESTS
// ============================================================================

TEST_F(FileUtilsTest, EdgeCase_VeryLongPath) {
    // Create a path with > 260 characters
    std::wstring longPath = testRoot;
    for (int i = 0; i < 10; i++) {
        longPath += L"\\very_long_directory_name_" + std::to_wstring(i);
    }
    longPath += L"\\file.txt";
    
    Error err{};
    ASSERT_TRUE(CreateDirectories(
        longPath.substr(0, longPath.find_last_of(L"\\")), &err));
    ASSERT_TRUE(WriteAllTextUtf8Atomic(longPath, "long path test", &err));
    
    std::string content;
    ASSERT_TRUE(ReadAllTextUtf8(longPath, content, &err));
    EXPECT_EQ(content, "long path test");
}

TEST_F(FileUtilsTest, EdgeCase_SpecialCharacters) {
    // Valid special characters in Windows filenames
    std::wstring filename = L"test_file_!@#$%^&()_+={}[];',~.txt";
    std::wstring path = Path(filename);
    
    Error err{};
    ASSERT_TRUE(WriteAllTextUtf8Atomic(path, "special chars", &err));
    EXPECT_TRUE(Exists(path));
}

TEST_F(FileUtilsTest, Security_PathTraversal) {
    std::wstring traversal = Path(L"..\\..\\..\\Windows\\System32\\test.txt");
    Error err{};
    
    // Should fail
    EXPECT_FALSE(CreateDirectories(traversal, &err));
    EXPECT_NE(err.win32, static_cast<DWORD>(0));
}

TEST_F(FileUtilsTest, Security_InvalidColonPosition) {
    std::wstring invalidPath = Path(L"sub\\file:name.txt");
    Error err{};
    
    EXPECT_FALSE(CreateDirectories(invalidPath, &err));
    EXPECT_EQ(err.win32, static_cast<DWORD>(ERROR_INVALID_NAME));
}

TEST_F(FileUtilsTest, EdgeCase_ZeroByte) {
    std::vector<std::byte> data(1024);
    std::fill(data.begin(), data.end(), std::byte{0});
    
    auto file = WriteBytes(L"zero_bytes.bin", data);
    
    std::vector<std::byte> read;
    Error err{};
    ASSERT_TRUE(ReadAllBytes(file, read, &err));
    EXPECT_EQ(read, data);
}

TEST_F(FileUtilsTest, EdgeCase_AllOnes) {
    std::vector<std::byte> data(1024);
    std::fill(data.begin(), data.end(), std::byte{0xFF});
    
    auto file = WriteBytes(L"all_ones.bin", data);
    
    std::vector<std::byte> read;
    Error err{};
    ASSERT_TRUE(ReadAllBytes(file, read, &err));
    EXPECT_EQ(read, data);
}

TEST_F(FileUtilsTest, Boundary_EmptyDirectory) {
    std::wstring emptyDir = Path(L"empty_boundary");
    Error err{};
    ASSERT_TRUE(CreateDirectories(emptyDir, &err));
    
    // Walk empty directory
    int count = 0;
    WalkOptions opts{};
    ASSERT_TRUE(WalkDirectory(emptyDir, opts,
        [&](const std::wstring&, const WIN32_FIND_DATAW&) {
            count++;
            return true;
        }, &err));
    
    EXPECT_EQ(count, 0);
}

TEST_F(FileUtilsTest, Boundary_SingleFile) {
    auto file = WriteText(L"single.txt", "x");
    
    FileStat stat{};
    Error err{};
    ASSERT_TRUE(Stat(file, stat, &err));
    EXPECT_EQ(stat.size, static_cast<uint64_t>(1));
}
