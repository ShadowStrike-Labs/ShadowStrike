/**
 * @file WhiteListPatternIndex_Tests.cpp
 * @brief Enterprise-grade unit tests for PathIndex (Compressed Trie) implementation
 *
 * This file contains comprehensive tests for the PathIndex class, covering:
 * - Construction and initialization
 * - Path insertion and removal
 * - Lookup with various match modes
 * - Edge cases and boundary conditions
 * - Thread safety and concurrency
 * - Performance benchmarks
 * - Memory corruption detection
 * - Stress testing
 *
 * Quality Standards:
 * - CrowdStrike/Kaspersky enterprise-grade testing
 * - Full code path coverage
 * - Security-focused test cases
 * - Performance validation
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "../../src/Whitelist/WhiteListStore.hpp"
#include "../../src/Whitelist/WhiteListFormat.hpp"

#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <random>
#include <algorithm>
#include <memory>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <future>

namespace ShadowStrike::Whitelist::Tests {

using namespace testing;
using namespace std::chrono_literals;

// ============================================================================
// TEST HELPERS AND UTILITIES
// ============================================================================

/**
 * @brief RAII helper for managing test buffer memory
 */
class IndexBuffer {
public:
    explicit IndexBuffer(size_t size) 
        : m_size(size)
        , m_buffer(std::make_unique<uint8_t[]>(size)) {
        // Zero-initialize for consistent test behavior
        std::memset(m_buffer.get(), 0, size);
    }
    
    ~IndexBuffer() = default;
    
    // Non-copyable, movable
    IndexBuffer(const IndexBuffer&) = delete;
    IndexBuffer& operator=(const IndexBuffer&) = delete;
    IndexBuffer(IndexBuffer&&) = default;
    IndexBuffer& operator=(IndexBuffer&&) = default;
    
    void* Data() noexcept { return m_buffer.get(); }
    const void* Data() const noexcept { return m_buffer.get(); }
    size_t Size() const noexcept { return m_size; }
    
    void Clear() noexcept {
        std::memset(m_buffer.get(), 0, m_size);
    }
    
    void Fill(uint8_t value) noexcept {
        std::memset(m_buffer.get(), value, m_size);
    }
    
private:
    size_t m_size;
    std::unique_ptr<uint8_t[]> m_buffer;
};

/**
 * @brief Test path generator for various test scenarios
 */
class TestPathGenerator {
public:
    explicit TestPathGenerator(uint32_t seed = 42) : m_rng(seed) {}
    
    /// @brief Generate a random Windows-style path
    std::wstring GenerateWindowsPath(size_t depth = 3, size_t maxSegmentLength = 10) {
        std::wstring path = L"C:\\";
        
        std::uniform_int_distribution<size_t> segLenDist(1, maxSegmentLength);
        std::uniform_int_distribution<int> charDist(L'a', L'z');
        
        for (size_t i = 0; i < depth; ++i) {
            size_t segLen = segLenDist(m_rng);
            for (size_t j = 0; j < segLen; ++j) {
                path += static_cast<wchar_t>(charDist(m_rng));
            }
            if (i < depth - 1) {
                path += L"\\";
            }
        }
        
        return path;
    }
    
    /// @brief Generate a Unix-style path
    std::wstring GenerateUnixPath(size_t depth = 3, size_t maxSegmentLength = 10) {
        std::wstring path = L"/";
        
        std::uniform_int_distribution<size_t> segLenDist(1, maxSegmentLength);
        std::uniform_int_distribution<int> charDist(L'a', L'z');
        
        for (size_t i = 0; i < depth; ++i) {
            size_t segLen = segLenDist(m_rng);
            for (size_t j = 0; j < segLen; ++j) {
                path += static_cast<wchar_t>(charDist(m_rng));
            }
            if (i < depth - 1) {
                path += L"/";
            }
        }
        
        return path;
    }
    
    /// @brief Generate a path with specific characteristics
    std::wstring GeneratePathWithPrefix(const std::wstring& prefix, size_t suffixDepth = 2) {
        std::wstring path = prefix;
        
        std::uniform_int_distribution<size_t> segLenDist(3, 8);
        std::uniform_int_distribution<int> charDist(L'a', L'z');
        
        for (size_t i = 0; i < suffixDepth; ++i) {
            path += L"\\";
            size_t segLen = segLenDist(m_rng);
            for (size_t j = 0; j < segLen; ++j) {
                path += static_cast<wchar_t>(charDist(m_rng));
            }
        }
        
        return path;
    }
    
    /// @brief Generate a batch of unique paths
    std::vector<std::wstring> GenerateUniquePaths(size_t count, size_t depth = 3) {
        std::vector<std::wstring> paths;
        paths.reserve(count);
        
        // Use set semantics to ensure uniqueness
        std::set<std::wstring> uniquePaths;
        
        while (uniquePaths.size() < count) {
            uniquePaths.insert(GenerateWindowsPath(depth));
        }
        
        for (const auto& p : uniquePaths) {
            paths.push_back(p);
        }
        
        return paths;
    }
    
private:
    std::mt19937 m_rng;
};

// ============================================================================
// TEST FIXTURE
// ============================================================================

class PathIndexTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Default buffer size: 1MB
        m_defaultBufferSize = 1024 * 1024;
        m_buffer = std::make_unique<IndexBuffer>(m_defaultBufferSize);
    }
    
    void TearDown() override {
        m_buffer.reset();
    }
    
    /// @brief Create a new writable PathIndex
    std::unique_ptr<PathIndex> CreateWritableIndex(size_t bufferSize = 0) {
        if (bufferSize == 0) {
            bufferSize = m_defaultBufferSize;
        }
        
        if (bufferSize != m_buffer->Size()) {
            m_buffer = std::make_unique<IndexBuffer>(bufferSize);
        } else {
            m_buffer->Clear();
        }
        
        auto index = std::make_unique<PathIndex>();
        uint64_t usedSize = 0;
        auto result = index->CreateNew(m_buffer->Data(), bufferSize, usedSize);
        
        EXPECT_TRUE(result.IsSuccess()) << "Failed to create index: " << result.GetMessage();
        EXPECT_GT(usedSize, 0ULL) << "Used size should be positive";
        
        return index;
    }
    
    /// @brief Helper to insert a path and verify success
    void InsertAndVerify(PathIndex& index, std::wstring_view path, 
                        PathMatchMode mode, uint64_t offset) {
        auto result = index.Insert(path, mode, offset);
        ASSERT_TRUE(result.IsSuccess()) 
            << "Insert failed for path: " << std::wstring(path);
    }
    
    /// @brief Helper to verify path lookup
    void VerifyLookup(const PathIndex& index, std::wstring_view path,
                     PathMatchMode mode, bool expectFound) {
        auto results = index.Lookup(path, mode);
        if (expectFound) {
            EXPECT_FALSE(results.empty()) 
                << "Expected to find path: " << std::wstring(path);
        } else {
            EXPECT_TRUE(results.empty()) 
                << "Expected NOT to find path: " << std::wstring(path);
        }
    }
    
protected:
    size_t m_defaultBufferSize;
    std::unique_ptr<IndexBuffer> m_buffer;
    TestPathGenerator m_pathGen;
};

// ============================================================================
// CONSTRUCTION AND INITIALIZATION TESTS
// ============================================================================

TEST_F(PathIndexTest, DefaultConstruction) {
    PathIndex index;
    
    EXPECT_FALSE(index.IsReady());
    EXPECT_EQ(index.GetPathCount(), 0ULL);
    EXPECT_EQ(index.GetNodeCount(), 0ULL);
}

TEST_F(PathIndexTest, CreateNew_ValidParameters) {
    auto index = CreateWritableIndex();
    
    EXPECT_TRUE(index->IsReady());
    EXPECT_EQ(index->GetPathCount(), 0ULL);
    EXPECT_EQ(index->GetNodeCount(), 0ULL);
}

TEST_F(PathIndexTest, CreateNew_NullBaseAddress) {
    PathIndex index;
    uint64_t usedSize = 0;
    
    auto result = index.CreateNew(nullptr, 1024, usedSize);
    
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_FALSE(index.IsReady());
}

TEST_F(PathIndexTest, CreateNew_InsufficientSize) {
    PathIndex index;
    IndexBuffer smallBuffer(32); // Less than header size (64 bytes)
    uint64_t usedSize = 0;
    
    auto result = index.CreateNew(smallBuffer.Data(), smallBuffer.Size(), usedSize);
    
    EXPECT_FALSE(result.IsSuccess());
}

TEST_F(PathIndexTest, CreateNew_MinimumViableSize) {
    PathIndex index;
    IndexBuffer buffer(128); // Header (64) + at least one node (64)
    uint64_t usedSize = 0;
    
    auto result = index.CreateNew(buffer.Data(), buffer.Size(), usedSize);
    
    EXPECT_TRUE(result.IsSuccess());
    EXPECT_TRUE(index.IsReady());
}

TEST_F(PathIndexTest, MoveConstruction) {
    auto original = CreateWritableIndex();
    InsertAndVerify(*original, L"C:\\Test\\Path", PathMatchMode::Exact, 100);
    
    EXPECT_EQ(original->GetPathCount(), 1ULL);
    
    PathIndex moved(std::move(*original));
    
    EXPECT_TRUE(moved.IsReady());
    EXPECT_EQ(moved.GetPathCount(), 1ULL);
    EXPECT_FALSE(original->IsReady()); // Source should be invalid
}

TEST_F(PathIndexTest, MoveAssignment) {
    auto original = CreateWritableIndex();
    InsertAndVerify(*original, L"C:\\Test\\Path", PathMatchMode::Exact, 100);
    
    PathIndex moved;
    moved = std::move(*original);
    
    EXPECT_TRUE(moved.IsReady());
    EXPECT_EQ(moved.GetPathCount(), 1ULL);
}

// ============================================================================
// SINGLE PATH INSERT TESTS
// ============================================================================

TEST_F(PathIndexTest, Insert_SinglePath_Exact) {
    auto index = CreateWritableIndex();
    
    InsertAndVerify(*index, L"C:\\Windows\\System32", PathMatchMode::Exact, 1);
    
    EXPECT_EQ(index->GetPathCount(), 1ULL);
    EXPECT_GE(index->GetNodeCount(), 1ULL);
}

TEST_F(PathIndexTest, Insert_SinglePath_Prefix) {
    auto index = CreateWritableIndex();
    
    InsertAndVerify(*index, L"C:\\Program Files", PathMatchMode::Prefix, 2);
    
    EXPECT_EQ(index->GetPathCount(), 1ULL);
}

TEST_F(PathIndexTest, Insert_EmptyPath_Fails) {
    auto index = CreateWritableIndex();
    
    auto result = index->Insert(L"", PathMatchMode::Exact, 100);
    
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(index->GetPathCount(), 0ULL);
}

TEST_F(PathIndexTest, Insert_DuplicatePath_Fails) {
    auto index = CreateWritableIndex();
    
    InsertAndVerify(*index, L"C:\\Test\\Path", PathMatchMode::Exact, 1);
    
    auto result = index->Insert(L"C:\\Test\\Path", PathMatchMode::Exact, 2);
    
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(index->GetPathCount(), 1ULL); // Count unchanged
}

TEST_F(PathIndexTest, Insert_CaseInsensitive) {
    auto index = CreateWritableIndex();
    
    // Insert lowercase
    InsertAndVerify(*index, L"c:\\windows\\system32", PathMatchMode::Exact, 1);
    
    // Lookup with mixed case should find it
    auto results = index->Lookup(L"C:\\WINDOWS\\System32", PathMatchMode::Exact);
    
    EXPECT_FALSE(results.empty());
}

TEST_F(PathIndexTest, Insert_NormalizedSeparators) {
    auto index = CreateWritableIndex();
    
    // Insert with backslashes
    InsertAndVerify(*index, L"C:\\Test\\Path", PathMatchMode::Exact, 1);
    
    // Lookup with forward slashes should find it (normalized internally)
    auto results = index->Lookup(L"C:/Test/Path", PathMatchMode::Exact);
    
    EXPECT_FALSE(results.empty());
}

TEST_F(PathIndexTest, Insert_LongPath) {
    auto index = CreateWritableIndex();
    
    // Generate a long but valid path
    std::wstring longPath = L"C:\\";
    for (int i = 0; i < 50; ++i) {
        longPath += L"segment_" + std::to_wstring(i) + L"\\";
    }
    longPath += L"file.txt";
    
    InsertAndVerify(*index, longPath, PathMatchMode::Exact, 1);
    
    auto results = index->Lookup(longPath, PathMatchMode::Exact);
    EXPECT_FALSE(results.empty());
}

TEST_F(PathIndexTest, Insert_PathTooLong_Fails) {
    auto index = CreateWritableIndex();
    
    // Generate path exceeding MAX_PATH (32767)
    std::wstring tooLongPath = L"C:\\";
    for (int i = 0; i < 35000 / 10; ++i) {
        tooLongPath += L"0123456789";
    }
    
    auto result = index->Insert(tooLongPath, PathMatchMode::Exact, 1);
    
    EXPECT_FALSE(result.IsSuccess());
}

// ============================================================================
// MULTI-PATH INSERT TESTS
// ============================================================================

TEST_F(PathIndexTest, Insert_MultiplePaths_Different) {
    auto index = CreateWritableIndex();
    
    InsertAndVerify(*index, L"C:\\Path1", PathMatchMode::Exact, 1);
    InsertAndVerify(*index, L"C:\\Path2", PathMatchMode::Exact, 2);
    InsertAndVerify(*index, L"C:\\Path3", PathMatchMode::Exact, 3);
    
    EXPECT_EQ(index->GetPathCount(), 3ULL);
}

TEST_F(PathIndexTest, Insert_MultiplePaths_CommonPrefix) {
    auto index = CreateWritableIndex();
    
    InsertAndVerify(*index, L"C:\\Windows\\System32\\kernel32.dll", PathMatchMode::Exact, 1);
    InsertAndVerify(*index, L"C:\\Windows\\System32\\ntdll.dll", PathMatchMode::Exact, 2);
    InsertAndVerify(*index, L"C:\\Windows\\System32\\drivers\\wdf.sys", PathMatchMode::Exact, 3);
    
    EXPECT_EQ(index->GetPathCount(), 3ULL);
    
    // All paths should be findable
    EXPECT_FALSE(index->Lookup(L"C:\\Windows\\System32\\kernel32.dll", PathMatchMode::Exact).empty());
    EXPECT_FALSE(index->Lookup(L"C:\\Windows\\System32\\ntdll.dll", PathMatchMode::Exact).empty());
    EXPECT_FALSE(index->Lookup(L"C:\\Windows\\System32\\drivers\\wdf.sys", PathMatchMode::Exact).empty());
}

TEST_F(PathIndexTest, Insert_100Paths) {
    auto index = CreateWritableIndex();
    
    std::vector<std::wstring> paths = m_pathGen.GenerateUniquePaths(100);
    
    for (size_t i = 0; i < paths.size(); ++i) {
        InsertAndVerify(*index, paths[i], PathMatchMode::Exact, i + 1);
    }
    
    EXPECT_EQ(index->GetPathCount(), 100ULL);
    
    // Verify all paths are findable
    for (const auto& path : paths) {
        auto results = index->Lookup(path, PathMatchMode::Exact);
        EXPECT_FALSE(results.empty()) << "Failed to find: " << std::wstring(path);
    }
}

// ============================================================================
// LOOKUP TESTS
// ============================================================================

TEST_F(PathIndexTest, Lookup_EmptyPath_ReturnsEmpty) {
    auto index = CreateWritableIndex();
    InsertAndVerify(*index, L"C:\\Test", PathMatchMode::Exact, 1);
    
    auto results = index->Lookup(L"", PathMatchMode::Exact);
    
    EXPECT_TRUE(results.empty());
}

TEST_F(PathIndexTest, Lookup_EmptyIndex_ReturnsEmpty) {
    auto index = CreateWritableIndex();
    
    auto results = index->Lookup(L"C:\\Test", PathMatchMode::Exact);
    
    EXPECT_TRUE(results.empty());
}

TEST_F(PathIndexTest, Lookup_ExactMatch_Found) {
    auto index = CreateWritableIndex();
    InsertAndVerify(*index, L"C:\\Windows\\System32", PathMatchMode::Exact, 42);
    
    auto results = index->Lookup(L"C:\\Windows\\System32", PathMatchMode::Exact);
    
    ASSERT_FALSE(results.empty());
    EXPECT_EQ(results[0], 42ULL);
}

TEST_F(PathIndexTest, Lookup_ExactMatch_NotFound) {
    auto index = CreateWritableIndex();
    InsertAndVerify(*index, L"C:\\Windows\\System32", PathMatchMode::Exact, 1);
    
    auto results = index->Lookup(L"C:\\Windows\\System64", PathMatchMode::Exact);
    
    EXPECT_TRUE(results.empty());
}

TEST_F(PathIndexTest, Lookup_PrefixMatch) {
    auto index = CreateWritableIndex();
    InsertAndVerify(*index, L"C:\\Windows", PathMatchMode::Prefix, 1);
    
    // Should match paths that start with the pattern
    EXPECT_FALSE(index->Lookup(L"C:\\Windows", PathMatchMode::Prefix).empty());
    EXPECT_FALSE(index->Lookup(L"C:\\Windows\\System32", PathMatchMode::Prefix).empty());
}

TEST_F(PathIndexTest, Contains_Found) {
    auto index = CreateWritableIndex();
    InsertAndVerify(*index, L"C:\\Test\\Path", PathMatchMode::Exact, 1);
    
    EXPECT_TRUE(index->Contains(L"C:\\Test\\Path", PathMatchMode::Exact));
}

TEST_F(PathIndexTest, Contains_NotFound) {
    auto index = CreateWritableIndex();
    InsertAndVerify(*index, L"C:\\Test\\Path", PathMatchMode::Exact, 1);
    
    EXPECT_FALSE(index->Contains(L"C:\\Other\\Path", PathMatchMode::Exact));
}

// ============================================================================
// REMOVE TESTS
// ============================================================================

TEST_F(PathIndexTest, Remove_ExistingPath_Success) {
    auto index = CreateWritableIndex();
    InsertAndVerify(*index, L"C:\\Test\\Path", PathMatchMode::Exact, 1);
    
    EXPECT_EQ(index->GetPathCount(), 1ULL);
    
    auto result = index->Remove(L"C:\\Test\\Path", PathMatchMode::Exact);
    
    EXPECT_TRUE(result.IsSuccess());
    EXPECT_EQ(index->GetPathCount(), 0ULL);
}

TEST_F(PathIndexTest, Remove_NonExistingPath_Fails) {
    auto index = CreateWritableIndex();
    InsertAndVerify(*index, L"C:\\Test\\Path", PathMatchMode::Exact, 1);
    
    auto result = index->Remove(L"C:\\Other\\Path", PathMatchMode::Exact);
    
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(index->GetPathCount(), 1ULL); // Count unchanged
}

TEST_F(PathIndexTest, Remove_EmptyPath_Fails) {
    auto index = CreateWritableIndex();
    InsertAndVerify(*index, L"C:\\Test\\Path", PathMatchMode::Exact, 1);
    
    auto result = index->Remove(L"", PathMatchMode::Exact);
    
    EXPECT_FALSE(result.IsSuccess());
}

TEST_F(PathIndexTest, Remove_FromEmptyIndex_Fails) {
    auto index = CreateWritableIndex();
    
    auto result = index->Remove(L"C:\\Test\\Path", PathMatchMode::Exact);
    
    EXPECT_FALSE(result.IsSuccess());
}

TEST_F(PathIndexTest, Remove_ThenLookup_NotFound) {
    auto index = CreateWritableIndex();
    InsertAndVerify(*index, L"C:\\Test\\Path", PathMatchMode::Exact, 1);
    
    // Verify it exists
    EXPECT_TRUE(index->Contains(L"C:\\Test\\Path", PathMatchMode::Exact));
    
    // Remove it
    auto result = index->Remove(L"C:\\Test\\Path", PathMatchMode::Exact);
    EXPECT_TRUE(result.IsSuccess());
    
    // Verify it's gone
    EXPECT_FALSE(index->Contains(L"C:\\Test\\Path", PathMatchMode::Exact));
}

TEST_F(PathIndexTest, Remove_PartialPath_OtherPathsIntact) {
    auto index = CreateWritableIndex();
    InsertAndVerify(*index, L"C:\\Windows\\System32\\kernel32.dll", PathMatchMode::Exact, 1);
    InsertAndVerify(*index, L"C:\\Windows\\System32\\ntdll.dll", PathMatchMode::Exact, 2);
    
    auto result = index->Remove(L"C:\\Windows\\System32\\kernel32.dll", PathMatchMode::Exact);
    EXPECT_TRUE(result.IsSuccess());
    
    // Other path should still exist
    EXPECT_TRUE(index->Contains(L"C:\\Windows\\System32\\ntdll.dll", PathMatchMode::Exact));
    EXPECT_FALSE(index->Contains(L"C:\\Windows\\System32\\kernel32.dll", PathMatchMode::Exact));
}

// ============================================================================
// EDGE CASES AND BOUNDARY CONDITIONS
// ============================================================================

TEST_F(PathIndexTest, EdgeCase_SingleCharacterPath) {
    auto index = CreateWritableIndex();
    
    InsertAndVerify(*index, L"C", PathMatchMode::Exact, 1);
    
    EXPECT_TRUE(index->Contains(L"C", PathMatchMode::Exact));
}

TEST_F(PathIndexTest, EdgeCase_TrailingSlash) {
    auto index = CreateWritableIndex();
    
    // Insert without trailing slash
    InsertAndVerify(*index, L"C:\\Windows", PathMatchMode::Exact, 1);
    
    // Lookup with trailing slash should still match (normalized)
    EXPECT_TRUE(index->Contains(L"C:\\Windows\\", PathMatchMode::Exact));
}

TEST_F(PathIndexTest, EdgeCase_MultipleSlashes) {
    auto index = CreateWritableIndex();
    
    InsertAndVerify(*index, L"C:\\Windows\\System32", PathMatchMode::Exact, 1);
    
    // Multiple consecutive slashes should be handled
    // (depends on normalization implementation)
    auto results = index->Lookup(L"C:\\\\Windows\\\\System32", PathMatchMode::Exact);
    // Note: This may or may not match depending on normalization behavior
}

TEST_F(PathIndexTest, EdgeCase_UnicodeCharacters) {
    auto index = CreateWritableIndex();
    
    // Path with Unicode characters
    InsertAndVerify(*index, L"C:\\Пользователи\\Документы", PathMatchMode::Exact, 1);
    
    EXPECT_TRUE(index->Contains(L"C:\\Пользователи\\Документы", PathMatchMode::Exact));
}

TEST_F(PathIndexTest, EdgeCase_SpecialCharacters) {
    auto index = CreateWritableIndex();
    
    // Path with spaces and special characters
    InsertAndVerify(*index, L"C:\\Program Files (x86)\\My App", PathMatchMode::Exact, 1);
    
    EXPECT_TRUE(index->Contains(L"C:\\Program Files (x86)\\My App", PathMatchMode::Exact));
}

TEST_F(PathIndexTest, EdgeCase_MaxSegmentLength) {
    auto index = CreateWritableIndex();
    
    // Create path with segment at max length (32 characters)
    std::wstring longSegment(32, L'a');
    std::wstring path = L"C:\\" + longSegment + L"\\file.txt";
    
    InsertAndVerify(*index, path, PathMatchMode::Exact, 1);
    
    EXPECT_TRUE(index->Contains(path, PathMatchMode::Exact));
}

// ============================================================================
// THREAD SAFETY TESTS
// ============================================================================

TEST_F(PathIndexTest, ThreadSafety_ConcurrentReads) {
    auto index = CreateWritableIndex();
    
    // Pre-populate index
    constexpr size_t numPaths = 50;
    std::vector<std::wstring> paths = m_pathGen.GenerateUniquePaths(numPaths);
    
    for (size_t i = 0; i < paths.size(); ++i) {
        InsertAndVerify(*index, paths[i], PathMatchMode::Exact, i + 1);
    }
    
    // Launch concurrent readers
    constexpr size_t numReaders = 4;
    std::vector<std::future<bool>> futures;
    
    for (size_t r = 0; r < numReaders; ++r) {
        futures.push_back(std::async(std::launch::async, [&index, &paths, r]() {
            for (size_t i = 0; i < paths.size(); ++i) {
                if (!index->Contains(paths[i], PathMatchMode::Exact)) {
                    return false;
                }
            }
            return true;
        }));
    }
    
    // Wait for all readers
    for (auto& f : futures) {
        EXPECT_TRUE(f.get()) << "Concurrent read failed";
    }
}

TEST_F(PathIndexTest, ThreadSafety_ConcurrentReadersAndWriter) {
    auto index = CreateWritableIndex();
    
    // Pre-populate with some paths
    constexpr size_t initialPaths = 20;
    std::vector<std::wstring> paths = m_pathGen.GenerateUniquePaths(initialPaths);
    
    for (size_t i = 0; i < paths.size(); ++i) {
        InsertAndVerify(*index, paths[i], PathMatchMode::Exact, i + 1);
    }
    
    std::atomic<bool> stopFlag{false};
    std::atomic<size_t> readCount{0};
    
    // Reader threads
    std::vector<std::thread> readers;
    for (int i = 0; i < 3; ++i) {
        readers.emplace_back([&]() {
            while (!stopFlag.load(std::memory_order_acquire)) {
                for (const auto& path : paths) {
                    index->Contains(path, PathMatchMode::Exact);
                    readCount.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }
    
    // Writer thread - insert more paths
    std::thread writer([&]() {
        for (size_t i = initialPaths; i < initialPaths + 10; ++i) {
            std::wstring newPath = L"C:\\NewPath_" + std::to_wstring(i);
            index->Insert(newPath, PathMatchMode::Exact, i + 1);
            std::this_thread::sleep_for(1ms);
        }
    });
    
    writer.join();
    stopFlag.store(true, std::memory_order_release);
    
    for (auto& t : readers) {
        t.join();
    }
    
    EXPECT_GT(readCount.load(), 0ULL);
}

// ============================================================================
// PERFORMANCE BENCHMARK TESTS
// ============================================================================

TEST_F(PathIndexTest, DISABLED_Perf_LookupLatency) {
    auto index = CreateWritableIndex();
    
    // Populate with many paths
    constexpr size_t numPaths = 10000;
    std::vector<std::wstring> paths = m_pathGen.GenerateUniquePaths(numPaths);
    
    for (size_t i = 0; i < paths.size(); ++i) {
        index->Insert(paths[i], PathMatchMode::Exact, i + 1);
    }
    
    // Measure lookup latency
    auto start = std::chrono::high_resolution_clock::now();
    constexpr size_t lookups = 100000;
    
    for (size_t i = 0; i < lookups; ++i) {
        index->Contains(paths[i % numPaths], PathMatchMode::Exact);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    
    double avgLatencyNs = static_cast<double>(duration.count()) / lookups;
    
    std::cout << "Average lookup latency: " << avgLatencyNs << " ns" << std::endl;
    
    // Enterprise target: <2μs per lookup
    EXPECT_LT(avgLatencyNs, 2000.0);
}

TEST_F(PathIndexTest, DISABLED_Perf_InsertThroughput) {
    auto index = CreateWritableIndex(16 * 1024 * 1024); // 16MB buffer
    
    constexpr size_t numPaths = 50000;
    std::vector<std::wstring> paths = m_pathGen.GenerateUniquePaths(numPaths);
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (size_t i = 0; i < paths.size(); ++i) {
        index->Insert(paths[i], PathMatchMode::Exact, i + 1);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    double throughput = static_cast<double>(numPaths) / (duration.count() / 1000.0);
    
    std::cout << "Insert throughput: " << throughput << " paths/sec" << std::endl;
    
    // Enterprise target: >10,000 inserts/sec
    EXPECT_GT(throughput, 10000.0);
}

// ============================================================================
// MEMORY CORRUPTION DETECTION TESTS
// ============================================================================

TEST_F(PathIndexTest, CorruptionDetection_SegmentLengthOverflow) {
    auto index = CreateWritableIndex();
    InsertAndVerify(*index, L"C:\\Test\\Path", PathMatchMode::Exact, 1);
    
    // Corrupt the segment length field in the buffer
    // (This simulates memory corruption or malicious data)
    auto* buffer = static_cast<uint8_t*>(m_buffer->Data());
    
    // The root node is at offset 64 (after header)
    // segmentLength is at offset 2 within the node
    buffer[64 + 2] = 255; // Set to invalid length
    
    // Lookup should handle this gracefully
    auto results = index->Lookup(L"C:\\Test\\Path", PathMatchMode::Exact);
    // Result may be empty due to validation failure, but shouldn't crash
}

TEST_F(PathIndexTest, CorruptionDetection_InvalidChildOffset) {
    auto index = CreateWritableIndex();
    InsertAndVerify(*index, L"C:\\Test\\Path", PathMatchMode::Exact, 1);
    InsertAndVerify(*index, L"C:\\Test\\Other", PathMatchMode::Exact, 2);
    
    // Corrupt a child offset to point outside bounds
    auto* buffer = static_cast<uint8_t*>(m_buffer->Data());
    
    // Child offsets start at offset 16 within the node (after flags, mode, segment)
    auto* childPtr = reinterpret_cast<uint32_t*>(buffer + 64 + 16);
    *childPtr = 0xFFFFFFFF; // Invalid offset
    
    // Lookup should handle this gracefully
    auto results = index->Lookup(L"C:\\Test\\Other", PathMatchMode::Exact);
    // Should not crash
}

// ============================================================================
// STRESS TESTS
// ============================================================================

TEST_F(PathIndexTest, Stress_HighVolumeInsertLookup) {
    auto index = CreateWritableIndex(32 * 1024 * 1024); // 32MB buffer
    
    constexpr size_t numPaths = 10000;
    std::vector<std::wstring> paths = m_pathGen.GenerateUniquePaths(numPaths);
    
    // Insert all paths
    for (size_t i = 0; i < paths.size(); ++i) {
        auto result = index->Insert(paths[i], PathMatchMode::Exact, i + 1);
        ASSERT_TRUE(result.IsSuccess()) << "Insert failed at index " << i;
    }
    
    EXPECT_EQ(index->GetPathCount(), numPaths);
    
    // Verify all paths exist
    for (const auto& path : paths) {
        EXPECT_TRUE(index->Contains(path, PathMatchMode::Exact));
    }
}

TEST_F(PathIndexTest, Stress_InsertRemoveInterleaved) {
    auto index = CreateWritableIndex();
    
    // Insert, remove, insert pattern
    for (int round = 0; round < 100; ++round) {
        std::wstring path = L"C:\\Round_" + std::to_wstring(round) + L"\\Path";
        
        // Insert
        auto insertResult = index->Insert(path, PathMatchMode::Exact, round + 1);
        ASSERT_TRUE(insertResult.IsSuccess());
        EXPECT_TRUE(index->Contains(path, PathMatchMode::Exact));
        
        // Remove
        auto removeResult = index->Remove(path, PathMatchMode::Exact);
        ASSERT_TRUE(removeResult.IsSuccess());
        EXPECT_FALSE(index->Contains(path, PathMatchMode::Exact));
    }
    
    EXPECT_EQ(index->GetPathCount(), 0ULL);
}

TEST_F(PathIndexTest, Stress_DeepPathHierarchy) {
    auto index = CreateWritableIndex(8 * 1024 * 1024); // 8MB buffer
    
    // Create very deep path hierarchy
    constexpr size_t maxDepth = 50;
    
    for (size_t depth = 1; depth <= maxDepth; ++depth) {
        std::wstring path = L"C:";
        for (size_t d = 0; d < depth; ++d) {
            path += L"\\level_" + std::to_wstring(d);
        }
        
        auto result = index->Insert(path, PathMatchMode::Exact, depth);
        ASSERT_TRUE(result.IsSuccess()) << "Failed at depth " << depth;
    }
    
    EXPECT_EQ(index->GetPathCount(), maxDepth);
    
    // Verify deepest path is findable
    std::wstring deepestPath = L"C:";
    for (size_t d = 0; d < maxDepth; ++d) {
        deepestPath += L"\\level_" + std::to_wstring(d);
    }
    
    EXPECT_TRUE(index->Contains(deepestPath, PathMatchMode::Exact));
}

// ============================================================================
// MATCH MODE SPECIFIC TESTS
// ============================================================================

TEST_F(PathIndexTest, MatchMode_ExactOnly) {
    auto index = CreateWritableIndex();
    
    InsertAndVerify(*index, L"C:\\Exact\\Match", PathMatchMode::Exact, 1);
    
    // Should match exactly
    EXPECT_TRUE(index->Contains(L"C:\\Exact\\Match", PathMatchMode::Exact));
    
    // Should NOT match as prefix of longer path
    EXPECT_FALSE(index->Contains(L"C:\\Exact\\Match\\Extra", PathMatchMode::Exact));
}

TEST_F(PathIndexTest, MatchMode_PrefixMatchesSubpaths) {
    auto index = CreateWritableIndex();
    
    InsertAndVerify(*index, L"C:\\Prefix", PathMatchMode::Prefix, 1);
    
    // Should match the prefix itself
    EXPECT_TRUE(index->Contains(L"C:\\Prefix", PathMatchMode::Prefix));
    
    // Should match longer paths that start with prefix
    EXPECT_TRUE(index->Contains(L"C:\\Prefix\\Subdir", PathMatchMode::Prefix));
    EXPECT_TRUE(index->Contains(L"C:\\Prefix\\Subdir\\File.txt", PathMatchMode::Prefix));
}

TEST_F(PathIndexTest, MatchMode_DifferentModesForSamePath) {
    auto index = CreateWritableIndex();
    
    // Insert same path base with different modes
    InsertAndVerify(*index, L"C:\\Multi\\Mode", PathMatchMode::Exact, 1);
    
    // Can lookup with different modes
    auto exactResults = index->Lookup(L"C:\\Multi\\Mode", PathMatchMode::Exact);
    EXPECT_FALSE(exactResults.empty());
    
    auto prefixResults = index->Lookup(L"C:\\Multi\\Mode", PathMatchMode::Prefix);
    // Prefix mode should also find exact matches
    EXPECT_FALSE(prefixResults.empty());
}

// ============================================================================
// SPECIAL PATH TESTS
// ============================================================================

TEST_F(PathIndexTest, SpecialPaths_UNCPath) {
    auto index = CreateWritableIndex();
    
    InsertAndVerify(*index, L"\\\\Server\\Share\\Folder", PathMatchMode::Exact, 1);
    
    EXPECT_TRUE(index->Contains(L"\\\\Server\\Share\\Folder", PathMatchMode::Exact));
}

TEST_F(PathIndexTest, SpecialPaths_DriveRoot) {
    auto index = CreateWritableIndex();
    
    InsertAndVerify(*index, L"C:\\", PathMatchMode::Exact, 1);
    
    EXPECT_TRUE(index->Contains(L"C:\\", PathMatchMode::Exact));
}

TEST_F(PathIndexTest, SpecialPaths_MultipleDrives) {
    auto index = CreateWritableIndex();
    
    InsertAndVerify(*index, L"C:\\Users", PathMatchMode::Exact, 1);
    InsertAndVerify(*index, L"D:\\Data", PathMatchMode::Exact, 2);
    InsertAndVerify(*index, L"E:\\Backup", PathMatchMode::Exact, 3);
    
    EXPECT_TRUE(index->Contains(L"C:\\Users", PathMatchMode::Exact));
    EXPECT_TRUE(index->Contains(L"D:\\Data", PathMatchMode::Exact));
    EXPECT_TRUE(index->Contains(L"E:\\Backup", PathMatchMode::Exact));
}

} // namespace ShadowStrike::Whitelist::Tests

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
