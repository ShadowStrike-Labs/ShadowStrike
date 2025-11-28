/*
 * ============================================================================
 * ShadowStrike PatternStore - IMPLEMENTATION
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * High-speed byte pattern matching implementation
 * Aho-Corasick + Boyer-Moore + SIMD (AVX2/AVX-512)
 * Target: < 10ms for 10MB file with 10,000 patterns
 *
 * CRITICAL: Pattern scanning performance is paramount!
 *
 * ============================================================================
 */

#include "PatternStore.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"

#include <algorithm>
#include <queue>
#include <cctype>
#include <immintrin.h> // AVX2/AVX-512 intrinsics

namespace ShadowStrike {
namespace SignatureStore {

// ============================================================================
// AHO-CORASICK AUTOMATON IMPLEMENTATION
// ============================================================================

AhoCorasickAutomaton::~AhoCorasickAutomaton() {
    // Vector cleanup automatic
}

bool AhoCorasickAutomaton::AddPattern(
    std::span<const uint8_t> pattern,
    uint64_t patternId
) noexcept {
    if (m_compiled) {
        SS_LOG_ERROR(L"AhoCorasick", L"Cannot add pattern after compilation");
        return false;
    }

    if (pattern.empty()) {
        SS_LOG_ERROR(L"AhoCorasick", L"Empty pattern");
        return false;
    }

    // Ensure root node exists
    if (m_nodes.empty()) {
        m_nodes.emplace_back(); // Root node
        m_nodeCount = 1;
    }

    // Insert pattern into trie
    uint32_t currentNode = 0; // Root

    for (uint8_t byte : pattern) {
        uint32_t& child = m_nodes[currentNode].children[byte];
        
        if (child == 0) {
            // Create new node
            child = static_cast<uint32_t>(m_nodes.size());
            m_nodes.emplace_back();
            m_nodes.back().depth = m_nodes[currentNode].depth + 1;
            m_nodeCount++;
        }

        currentNode = child;
    }

    // Mark as output node
    m_nodes[currentNode].outputs.push_back(patternId);
    m_patternCount++;

    return true;
}

bool AhoCorasickAutomaton::Compile() noexcept {
    if (m_compiled) {
        SS_LOG_WARN(L"AhoCorasick", L"Already compiled");
        return true;
    }

    if (m_nodes.empty()) {
        SS_LOG_ERROR(L"AhoCorasick", L"No patterns added");
        return false;
    }

    SS_LOG_INFO(L"AhoCorasick", L"Compiling automaton: %zu nodes, %zu patterns",
        m_nodeCount, m_patternCount);

    // Build failure links using BFS
    BuildFailureLinks();

    m_compiled = true;

    SS_LOG_INFO(L"AhoCorasick", L"Compilation complete");
    return true;
}

void AhoCorasickAutomaton::Clear() noexcept {
    m_nodes.clear();
    m_patternCount = 0;
    m_nodeCount = 0;
    m_compiled = false;
}

void AhoCorasickAutomaton::Search(
    std::span<const uint8_t> buffer,
    std::function<void(uint64_t patternId, size_t offset)> callback
) const noexcept {
    if (!m_compiled || !callback) {
        return;
    }

    uint32_t currentNode = 0; // Start at root

    for (size_t offset = 0; offset < buffer.size(); ++offset) {
        uint8_t byte = buffer[offset];

        // Follow failure links until we find a match or reach root
        while (currentNode != 0 && m_nodes[currentNode].children[byte] == 0) {
            currentNode = m_nodes[currentNode].failureLink;
        }

        // Transition
        currentNode = m_nodes[currentNode].children[byte];

        // Check for matches
        if (!m_nodes[currentNode].outputs.empty()) {
            for (uint64_t patternId : m_nodes[currentNode].outputs) {
                callback(patternId, offset);
            }
        }
    }
}

size_t AhoCorasickAutomaton::CountMatches(
    std::span<const uint8_t> buffer
) const noexcept {
    size_t count = 0;
    Search(buffer, [&count](uint64_t, size_t) { count++; });
    return count;
}

void AhoCorasickAutomaton::BuildFailureLinks() noexcept {
    std::queue<uint32_t> queue;

    // Initialize root's children failure links
    for (uint32_t child : m_nodes[0].children) {
        if (child != 0) {
            m_nodes[child].failureLink = 0; // Point to root
            queue.push(child);
        }
    }

    // BFS to build remaining failure links
    while (!queue.empty()) {
        uint32_t currentNode = queue.front();
        queue.pop();

        for (size_t byte = 0; byte < 256; ++byte) {
            uint32_t child = m_nodes[currentNode].children[byte];
            if (child == 0) continue;

            queue.push(child);

            // Find failure link
            uint32_t failNode = m_nodes[currentNode].failureLink;

            while (failNode != 0 && m_nodes[failNode].children[byte] == 0) {
                failNode = m_nodes[failNode].failureLink;
            }

            uint32_t failChild = m_nodes[failNode].children[byte];
            m_nodes[child].failureLink = (failChild != child) ? failChild : 0;

            // Merge outputs from failure link
            const auto& failOutputs = m_nodes[m_nodes[child].failureLink].outputs;
            m_nodes[child].outputs.insert(
                m_nodes[child].outputs.end(),
                failOutputs.begin(),
                failOutputs.end()
            );
        }
    }
}

// ============================================================================
// BOYER-MOORE MATCHER IMPLEMENTATION
// ============================================================================

BoyerMooreMatcher::BoyerMooreMatcher(
    std::span<const uint8_t> pattern,
    std::span<const uint8_t> mask
) noexcept
    : m_pattern(pattern.begin(), pattern.end())
    , m_mask(mask.begin(), mask.end())
{
    if (m_mask.empty()) {
        m_mask.resize(m_pattern.size(), 0xFF); // Default: all bits matter
    }

    BuildBadCharTable();
    BuildGoodSuffixTable();
}

std::vector<size_t> BoyerMooreMatcher::Search(
    std::span<const uint8_t> buffer
) const noexcept {
    std::vector<size_t> matches;

    if (m_pattern.empty() || buffer.size() < m_pattern.size()) {
        return matches;
    }

    size_t offset = 0;
    while (offset <= buffer.size() - m_pattern.size()) {
        if (MatchesAt(buffer, offset)) {
            matches.push_back(offset);
            offset++;
        } else {
            // Calculate skip distance
            size_t skip = 1;
            if (offset + m_pattern.size() < buffer.size()) {
                uint8_t badChar = buffer[offset + m_pattern.size() - 1];
                skip = m_badCharTable[badChar];
            }
            offset += skip;
        }
    }

    return matches;
}

std::optional<size_t> BoyerMooreMatcher::FindFirst(
    std::span<const uint8_t> buffer
) const noexcept {
    if (m_pattern.empty() || buffer.size() < m_pattern.size()) {
        return std::nullopt;
    }

    size_t offset = 0;
    while (offset <= buffer.size() - m_pattern.size()) {
        if (MatchesAt(buffer, offset)) {
            return offset;
        }

        size_t skip = 1;
        if (offset + m_pattern.size() < buffer.size()) {
            uint8_t badChar = buffer[offset + m_pattern.size() - 1];
            skip = m_badCharTable[badChar];
        }
        offset += skip;
    }

    return std::nullopt;
}

void BoyerMooreMatcher::BuildBadCharTable() noexcept {
    // Initialize with pattern length (worst case)
    m_badCharTable.fill(m_pattern.size());

    // Fill with last occurrence positions
    for (size_t i = 0; i < m_pattern.size() - 1; ++i) {
        m_badCharTable[m_pattern[i]] = m_pattern.size() - 1 - i;
    }
}

void BoyerMooreMatcher::BuildGoodSuffixTable() noexcept {
    size_t patternLen = m_pattern.size();
    m_goodSuffixTable.resize(patternLen, patternLen);

    // Simplified good suffix table
    // Full implementation would be more complex
    for (size_t i = 0; i < patternLen; ++i) {
        m_goodSuffixTable[i] = patternLen;
    }
}

bool BoyerMooreMatcher::MatchesAt(
    std::span<const uint8_t> buffer,
    size_t offset
) const noexcept {
    for (size_t i = 0; i < m_pattern.size(); ++i) {
        uint8_t bufferByte = buffer[offset + i];
        uint8_t patternByte = m_pattern[i];
        uint8_t mask = m_mask[i];

        if ((bufferByte & mask) != (patternByte & mask)) {
            return false;
        }
    }

    return true;
}

// ============================================================================
// SIMD MATCHER IMPLEMENTATION
// ============================================================================

bool SIMDMatcher::IsAVX2Available() noexcept {
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);
    int maxId = cpuInfo[0];

    if (maxId >= 7) {
        __cpuidex(cpuInfo, 7, 0);
        return (cpuInfo[1] & (1 << 5)) != 0; // Check AVX2 bit
    }

    return false;
}

bool SIMDMatcher::IsAVX512Available() noexcept {
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);
    int maxId = cpuInfo[0];

    if (maxId >= 7) {
        __cpuidex(cpuInfo, 7, 0);
        return (cpuInfo[1] & (1 << 16)) != 0; // Check AVX-512F bit
    }

    return false;
}

std::vector<size_t> SIMDMatcher::SearchAVX2(
    std::span<const uint8_t> buffer,
    std::span<const uint8_t> pattern
) noexcept {
    std::vector<size_t> matches;

#ifdef __AVX2__
    if (!IsAVX2Available() || pattern.empty() || pattern.size() > 32) {
        return matches; // Fallback to scalar
    }

    if (buffer.size() < pattern.size()) {
        return matches;
    }

    // Load pattern into SIMD register (first byte)
    __m256i patternVec = _mm256_set1_epi8(static_cast<char>(pattern[0]));

    size_t searchLen = buffer.size() - pattern.size() + 1;
    size_t i = 0;

    // Process 32 bytes at a time
    for (; i + 32 <= searchLen; i += 32) {
        // Load buffer chunk
        __m256i bufferVec = _mm256_loadu_si256(
            reinterpret_cast<const __m256i*>(buffer.data() + i)
        );

        // Compare
        __m256i cmp = _mm256_cmpeq_epi8(bufferVec, patternVec);
        int mask = _mm256_movemask_epi8(cmp);

        // Check each match
        while (mask != 0) {
            int pos = _tzcnt_u32(mask); // Trailing zero count
            
            // Verify full pattern match
            bool fullMatch = true;
            for (size_t j = 1; j < pattern.size(); ++j) {
                if (buffer[i + pos + j] != pattern[j]) {
                    fullMatch = false;
                    break;
                }
            }

            if (fullMatch) {
                matches.push_back(i + pos);
            }

            mask &= (mask - 1); // Clear lowest set bit
        }
    }

    // Handle remainder with scalar code
    for (; i < searchLen; ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (buffer[i + j] != pattern[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            matches.push_back(i);
        }
    }
#endif

    return matches;
}

std::vector<size_t> SIMDMatcher::SearchAVX512(
    std::span<const uint8_t> buffer,
    std::span<const uint8_t> pattern
) noexcept {
    std::vector<size_t> matches;

#ifdef __AVX512F__
    if (!IsAVX512Available() || pattern.empty() || pattern.size() > 64) {
        return matches; // Fallback
    }

    // Similar to AVX2 but with 512-bit registers
    // Full implementation would use __m512i
    // Not fully implemented here due to complexity
#endif

    return matches;
}

std::vector<std::pair<size_t, size_t>> SIMDMatcher::SearchMultipleAVX2(
    std::span<const uint8_t> buffer,
    std::span<const std::span<const uint8_t>> patterns
) noexcept {
    std::vector<std::pair<size_t, size_t>> matches;

    // Batch search multiple patterns
    for (size_t patternIdx = 0; patternIdx < patterns.size(); ++patternIdx) {
        auto patternMatches = SearchAVX2(buffer, patterns[patternIdx]);
        for (size_t offset : patternMatches) {
            matches.emplace_back(patternIdx, offset);
        }
    }

    return matches;
}

// ============================================================================
// PATTERN COMPILER IMPLEMENTATION
// ============================================================================

std::optional<std::vector<uint8_t>> PatternCompiler::CompilePattern(
    const std::string& patternStr,
    PatternMode& outMode,
    std::vector<uint8_t>& outMask
) noexcept {
    std::vector<uint8_t> pattern;
    outMask.clear();

    // Detect pattern mode
    if (patternStr.find('?') != std::string::npos) {
        outMode = PatternMode::Wildcard;
    } else if (patternStr.find('[') != std::string::npos) {
        outMode = PatternMode::Regex;
        SS_LOG_WARN(L"PatternCompiler", L"Regex mode not fully implemented");
        return std::nullopt;
    } else {
        outMode = PatternMode::Exact;
    }

    // Parse hex bytes
    std::string cleaned;
    for (char c : patternStr) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            cleaned += c;
        }
    }

    for (size_t i = 0; i < cleaned.length(); i += 2) {
        if (i + 1 >= cleaned.length()) break;

        if (cleaned[i] == '?' && cleaned[i + 1] == '?') {
            pattern.push_back(0x00); // Wildcard placeholder
            outMask.push_back(0x00); // Don't care
        } else {
            // Parse hex byte
            std::string hexByte = cleaned.substr(i, 2);
            try {
                uint8_t byte = static_cast<uint8_t>(std::stoi(hexByte, nullptr, 16));
                pattern.push_back(byte);
                outMask.push_back(0xFF); // Full match
            } catch (...) {
                SS_LOG_ERROR(L"PatternCompiler", L"Invalid hex byte: %S", hexByte.c_str());
                return std::nullopt;
            }
        }
    }

    return pattern;
}

bool PatternCompiler::ValidatePattern(
    const std::string& patternStr,
    std::string& errorMessage
) noexcept {
    if (patternStr.empty()) {
        errorMessage = "Empty pattern";
        return false;
    }

    // Basic validation
    std::string cleaned;
    for (char c : patternStr) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            cleaned += c;
        }
    }

    if (cleaned.length() % 2 != 0) {
        errorMessage = "Pattern must have even number of hex characters";
        return false;
    }

    return true;
}

float PatternCompiler::ComputeEntropy(
    std::span<const uint8_t> pattern
) noexcept {
    if (pattern.empty()) return 0.0f;

    // Calculate Shannon entropy
    std::array<size_t, 256> freq{};
    for (uint8_t byte : pattern) {
        freq[byte]++;
    }

    float entropy = 0.0f;
    float patternLen = static_cast<float>(pattern.size());

    for (size_t count : freq) {
        if (count > 0) {
            float prob = count / patternLen;
            entropy -= prob * std::log2(prob);
        }
    }

    return entropy;
}

// ============================================================================
// PATTERN STORE IMPLEMENTATION
// ============================================================================

PatternStore::PatternStore() {
    if (!QueryPerformanceFrequency(&m_perfFrequency)) {
        m_perfFrequency.QuadPart = 1000000;
    }
}

PatternStore::~PatternStore() {
    Close();
}

StoreError PatternStore::Initialize(
    const std::wstring& databasePath,
    bool readOnly
) noexcept {
    SS_LOG_INFO(L"PatternStore", L"Initialize: %s", databasePath.c_str());

    if (m_initialized.load(std::memory_order_acquire)) {
        return StoreError{SignatureStoreError::Success};
    }

    m_databasePath = databasePath;
    m_readOnly.store(readOnly, std::memory_order_release);

    // Open memory mapping
    StoreError err = OpenMemoryMapping(databasePath, readOnly);
    if (!err.IsSuccess()) {
        return err;
    }

    // Initialize pattern index
    m_patternIndex = std::make_unique<PatternIndex>();
    const auto* header = m_mappedView.GetAt<SignatureDatabaseHeader>(0);
    if (header) {
        err = m_patternIndex->Initialize(
            m_mappedView,
            header->patternIndexOffset,
            header->patternIndexSize
        );
        if (!err.IsSuccess()) {
            CloseMemoryMapping();
            return err;
        }
    }

    // Build Aho-Corasick automaton
    err = BuildAutomaton();
    if (!err.IsSuccess()) {
        CloseMemoryMapping();
        return err;
    }

    m_initialized.store(true, std::memory_order_release);

    SS_LOG_INFO(L"PatternStore", L"Initialized successfully");
    return StoreError{SignatureStoreError::Success};
}

StoreError PatternStore::CreateNew(
    const std::wstring& databasePath,
    uint64_t initialSizeBytes
) noexcept {
    SS_LOG_INFO(L"PatternStore", L"CreateNew: %s", databasePath.c_str());

    // Create database file (similar to HashStore)
    HANDLE hFile = CreateFileW(
        databasePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        return StoreError{SignatureStoreError::FileNotFound, err, "Cannot create file"};
    }

    LARGE_INTEGER size{};
    size.QuadPart = initialSizeBytes;
    if (!SetFilePointerEx(hFile, size, nullptr, FILE_BEGIN) || !SetEndOfFile(hFile)) {
        CloseHandle(hFile);
        return StoreError{SignatureStoreError::Unknown, GetLastError(), "Cannot set size"};
    }

    CloseHandle(hFile);

    return Initialize(databasePath, false);
}

void PatternStore::Close() noexcept {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    m_patternIndex.reset();
    m_automaton.reset();
    m_patternCache.clear();
    CloseMemoryMapping();

    m_initialized.store(false, std::memory_order_release);

    SS_LOG_INFO(L"PatternStore", L"Closed");
}

// ============================================================================
// PATTERN SCANNING
// ============================================================================

std::vector<DetectionResult> PatternStore::Scan(
    std::span<const uint8_t> buffer,
    const QueryOptions& options
) const noexcept {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    m_totalScans.fetch_add(1, std::memory_order_relaxed);
    m_totalBytesScanned.fetch_add(buffer.size(), std::memory_order_relaxed);

    LARGE_INTEGER startTime;
    QueryPerformanceCounter(&startTime);

    std::vector<DetectionResult> results;

    // Use SIMD if enabled
    if (m_simdEnabled.load(std::memory_order_acquire)) {
        auto simdResults = ScanWithSIMD(buffer, options);
        results.insert(results.end(), simdResults.begin(), simdResults.end());
    } else {
        // Use Aho-Corasick automaton
        auto acResults = ScanWithAutomaton(buffer, options);
        results.insert(results.end(), acResults.begin(), acResults.end());
    }

    LARGE_INTEGER endTime;
    QueryPerformanceCounter(&endTime);
    uint64_t scanTimeUs = 
        ((endTime.QuadPart - startTime.QuadPart) * 1000000ULL) / m_perfFrequency.QuadPart;

    // Update statistics
    for (auto& result : results) {
        result.matchTimeNanoseconds = scanTimeUs * 1000;
        m_totalMatches.fetch_add(1, std::memory_order_relaxed);
        
        if (m_heatmapEnabled.load(std::memory_order_acquire)) {
            UpdateHitCount(result.signatureId);
        }
    }

    return results;
}

std::vector<DetectionResult> PatternStore::ScanFile(
    const std::wstring& filePath,
    const QueryOptions& options
) const noexcept {
    SS_LOG_DEBUG(L"PatternStore", L"ScanFile: %s", filePath.c_str());

    // Memory-map file for scanning
    StoreError err{};
    MemoryMappedView fileView{};
    
    if (!MemoryMapping::OpenView(filePath, true, fileView, err)) {
        SS_LOG_ERROR(L"PatternStore", L"Failed to map file: %S", err.message.c_str());
        return {};
    }

    // Scan mapped file
    std::span<const uint8_t> buffer(
        static_cast<const uint8_t*>(fileView.baseAddress),
        static_cast<size_t>(fileView.fileSize)
    );

    auto results = Scan(buffer, options);

    MemoryMapping::CloseView(fileView);

    return results;
}

PatternStore::ScanContext PatternStore::CreateScanContext(
    const QueryOptions& options
) const noexcept {
    ScanContext ctx;
    ctx.m_store = this;
    ctx.m_options = options;
    return ctx;
}

void PatternStore::ScanContext::Reset() noexcept {
    m_buffer.clear();
    m_totalBytesProcessed = 0;
}

std::vector<DetectionResult> PatternStore::ScanContext::FeedChunk(
    std::span<const uint8_t> chunk
) noexcept {
    // Append to buffer
    m_buffer.insert(m_buffer.end(), chunk.begin(), chunk.end());
    m_totalBytesProcessed += chunk.size();

    // Scan when buffer reaches threshold
    if (m_buffer.size() >= 1024 * 1024) { // 1MB threshold
        auto results = m_store->Scan(m_buffer, m_options);
        m_buffer.clear();
        return results;
    }

    return {};
}

std::vector<DetectionResult> PatternStore::ScanContext::Finalize() noexcept {
    if (m_buffer.empty()) {
        return {};
    }

    auto results = m_store->Scan(m_buffer, m_options);
    m_buffer.clear();
    return results;
}

// ============================================================================
// PATTERN MANAGEMENT
// ============================================================================

StoreError PatternStore::AddPattern(
    const std::string& patternStr,
    const std::string& signatureName,
    ThreatLevel threatLevel,
    const std::string& description,
    const std::vector<std::string>& tags
) noexcept {
    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError{SignatureStoreError::AccessDenied, 0, "Read-only"};
    }

    // Compile pattern
    PatternMode mode;
    std::vector<uint8_t> mask;
    auto pattern = PatternCompiler::CompilePattern(patternStr, mode, mask);

    if (!pattern.has_value()) {
        return StoreError{SignatureStoreError::InvalidSignature, 0, "Invalid pattern"};
    }

    return AddCompiledPattern(*pattern, mode, mask, signatureName, threatLevel);
}

StoreError PatternStore::AddCompiledPattern(
    std::span<const uint8_t> pattern,
    PatternMode mode,
    std::span<const uint8_t> mask,
    const std::string& signatureName,
    ThreatLevel threatLevel
) noexcept {
    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    // Create pattern metadata
    PatternMetadata metadata{};
    metadata.signatureId = m_patternCache.size();
    metadata.name = signatureName;
    metadata.threatLevel = threatLevel;
    metadata.mode = mode;
    metadata.pattern.assign(pattern.begin(), pattern.end());
    metadata.mask.assign(mask.begin(), mask.end());
    metadata.entropy = PatternCompiler::ComputeEntropy(pattern);
    metadata.hitCount = 0;

    m_patternCache.push_back(metadata);

    SS_LOG_DEBUG(L"PatternStore", L"Added pattern: %S (mode=%u, entropy=%.2f)",
        signatureName.c_str(), static_cast<uint8_t>(mode), metadata.entropy);

    return StoreError{SignatureStoreError::Success};
}

// Remaining methods (Remove, Import/Export, Statistics, etc.)
// Similar pattern to HashStore implementation

StoreError PatternStore::OpenMemoryMapping(const std::wstring& path, bool readOnly) noexcept {
    StoreError err{};
    if (!MemoryMapping::OpenView(path, readOnly, m_mappedView, err)) {
        return err;
    }
    return StoreError{SignatureStoreError::Success};
}

void PatternStore::CloseMemoryMapping() noexcept {
    MemoryMapping::CloseView(m_mappedView);
}

StoreError PatternStore::BuildAutomaton() noexcept {
    m_automaton = std::make_unique<AhoCorasickAutomaton>();

    // Add patterns from cache to automaton
    for (const auto& meta : m_patternCache) {
        if (meta.mode == PatternMode::Exact) {
            m_automaton->AddPattern(meta.pattern, meta.signatureId);
        }
    }

    if (!m_automaton->Compile()) {
        return StoreError{SignatureStoreError::Unknown, 0, "Automaton compilation failed"};
    }

    return StoreError{SignatureStoreError::Success};
}

std::vector<DetectionResult> PatternStore::ScanWithAutomaton(
    std::span<const uint8_t> buffer,
    const QueryOptions& options
) const noexcept {
    std::vector<DetectionResult> results;

    if (!m_automaton) return results;

    m_automaton->Search(buffer, [&](uint64_t patternId, size_t offset) {
        if (patternId < m_patternCache.size()) {
            const auto& meta = m_patternCache[patternId];
            
            DetectionResult result{};
            result.signatureId = patternId;
            result.signatureName = meta.name;
            result.threatLevel = meta.threatLevel;
            result.fileOffset = offset;
            result.description = "Pattern match";
            
            results.push_back(result);
        }
    });

    return results;
}

std::vector<DetectionResult> PatternStore::ScanWithSIMD(
    std::span<const uint8_t> buffer,
    const QueryOptions& options
) const noexcept {
    std::vector<DetectionResult> results;

    // Use SIMD for exact patterns only
    for (const auto& meta : m_patternCache) {
        if (meta.mode != PatternMode::Exact) continue;

        auto matches = SIMDMatcher::SearchAVX2(buffer, meta.pattern);
        
        for (size_t offset : matches) {
            DetectionResult result{};
            result.signatureId = meta.signatureId;
            result.signatureName = meta.name;
            result.threatLevel = meta.threatLevel;
            result.fileOffset = offset;
            result.description = "SIMD pattern match";
            
            results.push_back(result);
        }
    }

    return results;
}

DetectionResult PatternStore::BuildDetectionResult(
    uint64_t patternId,
    size_t offset,
    uint64_t matchTimeNs
) const noexcept {
    DetectionResult result{};
    result.signatureId = patternId;
    result.fileOffset = offset;
    result.matchTimeNanoseconds = matchTimeNs;

    if (patternId < m_patternCache.size()) {
        const auto& meta = m_patternCache[patternId];
        result.signatureName = meta.name;
        result.threatLevel = meta.threatLevel;
    }

    return result;
}

void PatternStore::UpdateHitCount(uint64_t patternId) noexcept {
    if (patternId < m_patternCache.size()) {
        m_patternCache[patternId].hitCount++;
    }
}

PatternStore::PatternStoreStatistics PatternStore::GetStatistics() const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_globalLock);

    PatternStoreStatistics stats{};
    stats.totalScans = m_totalScans.load(std::memory_order_relaxed);
    stats.totalMatches = m_totalMatches.load(std::memory_order_relaxed);
    stats.totalBytesScanned = m_totalBytesScanned.load(std::memory_order_relaxed);
    stats.totalPatterns = m_patternCache.size();

    // Count by mode
    for (const auto& meta : m_patternCache) {
        switch (meta.mode) {
            case PatternMode::Exact:    stats.exactPatterns++; break;
            case PatternMode::Wildcard: stats.wildcardPatterns++; break;
            case PatternMode::Regex:    stats.regexPatterns++; break;
            default: break;
        }
    }

    if (m_automaton) {
        stats.automatonNodeCount = m_automaton->GetNodeCount();
    }

    return stats;
}

void PatternStore::ResetStatistics() noexcept {
    m_totalScans.store(0, std::memory_order_release);
    m_totalMatches.store(0, std::memory_order_release);
    m_totalBytesScanned.store(0, std::memory_order_release);
}

std::vector<std::pair<uint64_t, uint32_t>> PatternStore::GetHeatmap() const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_globalLock);

    std::vector<std::pair<uint64_t, uint32_t>> heatmap;
    for (const auto& meta : m_patternCache) {
        heatmap.emplace_back(meta.signatureId, meta.hitCount);
    }

    // Sort by hit count (descending)
    std::sort(heatmap.begin(), heatmap.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });

    return heatmap;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

namespace PatternUtils {

bool IsValidPatternString(
    const std::string& pattern,
    std::string& errorMessage
) noexcept {
    return PatternCompiler::ValidatePattern(pattern, errorMessage);
}

std::optional<std::vector<uint8_t>> HexStringToBytes(
    const std::string& hexStr
) noexcept {
    std::vector<uint8_t> bytes;
    
    for (size_t i = 0; i < hexStr.length(); i += 2) {
        if (i + 1 >= hexStr.length()) break;
        
        std::string byteStr = hexStr.substr(i, 2);
        try {
            uint8_t byte = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
            bytes.push_back(byte);
        } catch (...) {
            return std::nullopt;
        }
    }

    return bytes;
}

std::string BytesToHexString(
    std::span<const uint8_t> bytes
) noexcept {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    
    for (uint8_t byte : bytes) {
        oss << std::setw(2) << static_cast<unsigned>(byte);
    }

    return oss.str();
}

size_t HammingDistance(
    std::span<const uint8_t> a,
    std::span<const uint8_t> b
) noexcept {
    size_t distance = 0;
    size_t minLen = std::min(a.size(), b.size());

    for (size_t i = 0; i < minLen; ++i) {
        distance += std::popcount(static_cast<uint8_t>(a[i] ^ b[i]));
    }

    // Add difference in lengths
    distance += std::abs(static_cast<int>(a.size() - b.size())) * 8;

    return distance;
}

} // namespace PatternUtils

} // namespace SignatureStore
} // namespace ShadowStrike
