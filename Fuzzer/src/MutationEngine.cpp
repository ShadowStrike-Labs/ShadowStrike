// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file MutationEngine.cpp
 * @brief Implementation of the byte-level mutation engine.
 */

#include "ShadowStrike/Fuzzer/Core/MutationEngine.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>

namespace ShadowStrike::Fuzzer {

// ============================================================================
// Static Data: Interesting Values
// ============================================================================

namespace {

// Interesting byte values for mutation
constexpr std::array<uint8_t, 16> kInterestingBytes = {
    0x00,  // Zero
    0x01,  // One
    0x7F,  // Max signed byte
    0x80,  // Min signed byte (negative)
    0xFF,  // Max unsigned / -1
    0xFE,  // -2
    0x02,  // Two
    0x10,  // 16
    0x20,  // 32
    0x40,  // 64
    0x41,  // 'A'
    0x4D,  // 'M' (for MZ)
    0x5A,  // 'Z' (for MZ)
    0x50,  // 'P' (for PE)
    0x45,  // 'E' (for PE)
    0x2E,  // '.' (for section names)
};

// Interesting 16-bit values
constexpr std::array<uint16_t, 16> kInterestingWords = {
    0x0000,  // Zero
    0x0001,  // One
    0x0002,  // Two
    0x0100,  // 256
    0x7FFF,  // Max signed short
    0x8000,  // Min signed short
    0xFFFF,  // Max unsigned / -1
    0xFFFE,  // -2
    0x5A4D,  // 'MZ' DOS signature
    0x4550,  // 'PE' NT signature (partial)
    0x014C,  // i386 machine type
    0x8664,  // x64 machine type
    0x010B,  // PE32 magic
    0x020B,  // PE32+ magic
    0x0200,  // 512 (common alignment)
    0x1000,  // 4096 (page size)
};

// Interesting 32-bit values
constexpr std::array<uint32_t, 20> kInterestingDwords = {
    0x00000000,  // Zero
    0x00000001,  // One
    0x00000002,  // Two
    0x7FFFFFFF,  // Max signed int
    0x80000000,  // Min signed int
    0xFFFFFFFF,  // Max unsigned / -1
    0xFFFFFFFE,  // -2
    0x00004550,  // 'PE\0\0' signature
    0x00001000,  // Page size
    0x00000200,  // 512 (file alignment)
    0x10000000,  // 256MB
    0x00010000,  // 64KB (section alignment)
    0x00100000,  // 1MB
    0x01000000,  // 16MB
    0x00400000,  // 4MB (typical ImageBase)
    0x00000040,  // 64 (minimal e_lfanew)
    0x000000E0,  // 224 (typical SizeOfOptionalHeader PE32)
    0x000000F0,  // 240 (typical SizeOfOptionalHeader PE64)
    0x60000020,  // Executable|Readable|Code characteristics
    0xE0000020,  // Writable|Executable|Readable|Code (suspicious)
};

// PE-specific dictionary tokens
const std::array<std::vector<uint8_t>, 16> kPEDictionaryData = {{
    {'M', 'Z'},                           // DOS signature
    {'P', 'E', 0, 0},                     // NT signature
    {'.', 't', 'e', 'x', 't', 0, 0, 0},   // .text section
    {'.', 'd', 'a', 't', 'a', 0, 0, 0},   // .data section
    {'.', 'r', 'd', 'a', 't', 'a', 0, 0}, // .rdata section
    {'.', 'r', 's', 'r', 'c', 0, 0, 0},   // .rsrc section
    {'.', 'r', 'e', 'l', 'o', 'c', 0, 0}, // .reloc section
    {'.', 'i', 'd', 'a', 't', 'a', 0, 0}, // .idata section
    {'.', 'e', 'd', 'a', 't', 'a', 0, 0}, // .edata section
    {'.', 'b', 's', 's', 0, 0, 0, 0},     // .bss section
    {'.', 't', 'l', 's', 0, 0, 0, 0},     // .tls section
    {'.', 'p', 'd', 'a', 't', 'a', 0, 0}, // .pdata section
    {'U', 'P', 'X', '0', 0, 0, 0, 0},     // UPX packer section
    {'U', 'P', 'X', '1', 0, 0, 0, 0},     // UPX packer section
    {0x0B, 0x01},                          // PE32 magic (little-endian)
    {0x0B, 0x02},                          // PE32+ magic (little-endian)
}};

// Build span array at initialization time
std::array<std::span<const uint8_t>, kPEDictionaryData.size()> BuildDictionarySpans() {
    std::array<std::span<const uint8_t>, kPEDictionaryData.size()> spans;
    for (size_t i = 0; i < kPEDictionaryData.size(); ++i) {
        spans[i] = std::span<const uint8_t>(kPEDictionaryData[i]);
    }
    return spans;
}

const auto kPEDictionarySpans = BuildDictionarySpans();

}  // namespace

// ============================================================================
// Public API: Interesting Values Access
// ============================================================================

std::span<const uint8_t> GetInterestingBytes() noexcept {
    return kInterestingBytes;
}

std::span<const uint16_t> GetInterestingWords() noexcept {
    return kInterestingWords;
}

std::span<const uint32_t> GetInterestingDwords() noexcept {
    return kInterestingDwords;
}

std::span<const std::span<const uint8_t>> GetPEDictionary() noexcept {
    return kPEDictionarySpans;
}

// ============================================================================
// MutationStrategy Conversion
// ============================================================================

std::string_view ToString(MutationStrategy strategy) noexcept {
    switch (strategy) {
    case MutationStrategy::BitFlip:           return "BitFlip";
    case MutationStrategy::ByteFlip:          return "ByteFlip";
    case MutationStrategy::Arithmetic:        return "Arithmetic";
    case MutationStrategy::InterestingValues: return "InterestingValues";
    case MutationStrategy::BlockDelete:       return "BlockDelete";
    case MutationStrategy::BlockInsert:       return "BlockInsert";
    case MutationStrategy::BlockOverwrite:    return "BlockOverwrite";
    case MutationStrategy::DictionaryInsert:  return "DictionaryInsert";
    case MutationStrategy::Splice:            return "Splice";
    case MutationStrategy::Havoc:             return "Havoc";
    case MutationStrategy::COUNT:             return "COUNT";
    }
    return "Unknown";
}

// ============================================================================
// MutationEngine Implementation
// ============================================================================

MutationEngine::MutationEngine() noexcept
    : m_config{}
    , m_rng{}
    , m_currentSeed(0)
    , m_totalMutations(0)
{
    SeedFromRandom();
}

MutationEngine::MutationEngine(const MutationConfig& config) noexcept
    : m_config(config)
    , m_rng{}
    , m_currentSeed(0)
    , m_totalMutations(0)
{
    SeedFromRandom();
}

void MutationEngine::Seed(uint64_t seed) noexcept {
    m_currentSeed = seed;
    m_rng.seed(seed);
}

void MutationEngine::SeedFromRandom() noexcept {
    try {
        std::random_device rd;
        m_currentSeed = (static_cast<uint64_t>(rd()) << 32) | rd();
        m_rng.seed(m_currentSeed);
    } catch (...) {
        // Fallback to time-based seed if random_device fails
        m_currentSeed = static_cast<uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count());
        m_rng.seed(m_currentSeed);
    }
}

uint64_t MutationEngine::GetCurrentSeed() const noexcept {
    return m_currentSeed;
}

const MutationConfig& MutationEngine::GetConfig() const noexcept {
    return m_config;
}

void MutationEngine::SetConfig(const MutationConfig& config) noexcept {
    m_config = config;
}

uint64_t MutationEngine::GetTotalMutations() const noexcept {
    return m_totalMutations;
}

void MutationEngine::ResetStatistics() noexcept {
    m_totalMutations = 0;
}

// ============================================================================
// Random Helpers
// ============================================================================

size_t MutationEngine::RandomIndex(size_t maxExclusive) noexcept {
    if (maxExclusive == 0) return 0;
    std::uniform_int_distribution<size_t> dist(0, maxExclusive - 1);
    return dist(m_rng);
}

size_t MutationEngine::RandomRange(size_t minInclusive, size_t maxInclusive) noexcept {
    if (minInclusive >= maxInclusive) return minInclusive;
    std::uniform_int_distribution<size_t> dist(minInclusive, maxInclusive);
    return dist(m_rng);
}

uint8_t MutationEngine::RandomByte() noexcept {
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    return static_cast<uint8_t>(dist(m_rng));
}

bool MutationEngine::RandomBool() noexcept {
    return (m_rng() & 1) != 0;
}

MutationStrategy MutationEngine::ChooseRandomStrategy() noexcept {
    // Exclude Splice (needs external buffer) and COUNT from random selection
    // Havoc has lower probability to avoid infinite recursion
    constexpr size_t numStrategies = static_cast<size_t>(MutationStrategy::COUNT) - 1;
    
    size_t choice = RandomIndex(numStrategies);
    if (choice >= static_cast<size_t>(MutationStrategy::Splice)) {
        // Skip Splice and map to Havoc-1 strategies
        choice = RandomIndex(static_cast<size_t>(MutationStrategy::Splice));
    }
    
    return static_cast<MutationStrategy>(choice);
}

void MutationEngine::EnsureMaxSize(std::vector<uint8_t>& data) noexcept {
    if (data.size() > m_config.maxOutputSize) {
        data.resize(m_config.maxOutputSize);
    }
}

// ============================================================================
// Main Mutation Entry Points
// ============================================================================

MutationResult MutationEngine::Mutate(std::span<const uint8_t> input) noexcept {
    MutationResult result;
    result.seed = m_currentSeed;
    result.success = false;
    result.mutationCount = 0;
    
    if (input.empty()) {
        // Generate some random data for empty input
        result.data.resize(RandomRange(1, 64));
        for (auto& byte : result.data) {
            byte = RandomByte();
        }
        result.appliedStrategy = MutationStrategy::BlockInsert;
        result.mutationCount = 1;
        result.success = true;
        ++m_totalMutations;
        return result;
    }
    
    // Copy input to output buffer
    result.data.assign(input.begin(), input.end());
    
    // Choose and apply strategy
    result.appliedStrategy = ChooseRandomStrategy();
    
    switch (result.appliedStrategy) {
    case MutationStrategy::BitFlip:
        result.mutationCount = ApplyBitFlip(result.data);
        break;
    case MutationStrategy::ByteFlip:
        result.mutationCount = ApplyByteFlip(result.data);
        break;
    case MutationStrategy::Arithmetic:
        result.mutationCount = ApplyArithmetic(result.data);
        break;
    case MutationStrategy::InterestingValues:
        result.mutationCount = ApplyInterestingValues(result.data);
        break;
    case MutationStrategy::BlockDelete:
        result.mutationCount = ApplyBlockDelete(result.data);
        break;
    case MutationStrategy::BlockInsert:
        result.mutationCount = ApplyBlockInsert(result.data);
        break;
    case MutationStrategy::BlockOverwrite:
        result.mutationCount = ApplyBlockOverwrite(result.data);
        break;
    case MutationStrategy::DictionaryInsert:
        result.mutationCount = ApplyDictionaryInsert(result.data);
        break;
    case MutationStrategy::Havoc:
        result.mutationCount = ApplyHavoc(result.data);
        break;
    default:
        result.mutationCount = ApplyByteFlip(result.data);
        break;
    }
    
    EnsureMaxSize(result.data);
    result.success = result.mutationCount > 0 || !result.data.empty();
    m_totalMutations += result.mutationCount;
    
    return result;
}

MutationResult MutationEngine::Mutate(
    std::span<const uint8_t> input,
    MutationStrategy strategy) noexcept
{
    MutationResult result;
    result.seed = m_currentSeed;
    result.appliedStrategy = strategy;
    result.success = false;
    result.mutationCount = 0;
    
    if (input.empty() && strategy != MutationStrategy::BlockInsert) {
        return result;
    }
    
    result.data.assign(input.begin(), input.end());
    
    switch (strategy) {
    case MutationStrategy::BitFlip:
        result.mutationCount = ApplyBitFlip(result.data);
        break;
    case MutationStrategy::ByteFlip:
        result.mutationCount = ApplyByteFlip(result.data);
        break;
    case MutationStrategy::Arithmetic:
        result.mutationCount = ApplyArithmetic(result.data);
        break;
    case MutationStrategy::InterestingValues:
        result.mutationCount = ApplyInterestingValues(result.data);
        break;
    case MutationStrategy::BlockDelete:
        result.mutationCount = ApplyBlockDelete(result.data);
        break;
    case MutationStrategy::BlockInsert:
        result.mutationCount = ApplyBlockInsert(result.data);
        break;
    case MutationStrategy::BlockOverwrite:
        result.mutationCount = ApplyBlockOverwrite(result.data);
        break;
    case MutationStrategy::DictionaryInsert:
        result.mutationCount = ApplyDictionaryInsert(result.data);
        break;
    case MutationStrategy::Havoc:
        result.mutationCount = ApplyHavoc(result.data);
        break;
    default:
        break;
    }
    
    EnsureMaxSize(result.data);
    result.success = result.mutationCount > 0 || !result.data.empty();
    m_totalMutations += result.mutationCount;
    
    return result;
}

MutationResult MutationEngine::MutateWithSplice(
    std::span<const uint8_t> input,
    std::span<const uint8_t> spliceSource) noexcept
{
    MutationResult result;
    result.seed = m_currentSeed;
    result.success = false;
    result.mutationCount = 0;
    
    if (input.empty() && spliceSource.empty()) {
        return result;
    }
    
    result.data.assign(input.begin(), input.end());
    
    // 50% chance of splice vs havoc with splice
    if (RandomBool() && !spliceSource.empty()) {
        result.appliedStrategy = MutationStrategy::Splice;
        result.mutationCount = ApplySplice(result.data, spliceSource);
    } else {
        result.appliedStrategy = MutationStrategy::Havoc;
        result.mutationCount = ApplyHavoc(result.data, spliceSource);
    }
    
    EnsureMaxSize(result.data);
    result.success = result.mutationCount > 0 || !result.data.empty();
    m_totalMutations += result.mutationCount;
    
    return result;
}

// ============================================================================
// Individual Mutation Strategies
// ============================================================================

size_t MutationEngine::ApplyBitFlip(std::vector<uint8_t>& data) noexcept {
    if (data.empty()) return 0;
    
    // Choose flip width: 1, 2, 4, or 8 bits
    const size_t flipWidth = static_cast<size_t>(1) << RandomIndex(4);  // 1, 2, 4, or 8
    
    const size_t pos = RandomIndex(data.size());
    
    if (flipWidth <= 8) {
        // Single byte bit flip
        const uint8_t mask = static_cast<uint8_t>((1 << flipWidth) - 1);
        const size_t bitOffset = RandomIndex(9 - flipWidth);
        data[pos] ^= static_cast<uint8_t>(mask << bitOffset);
    }
    
    return 1;
}

size_t MutationEngine::ApplyByteFlip(std::vector<uint8_t>& data) noexcept {
    if (data.empty()) return 0;
    
    // Choose flip width: 1, 2, or 4 bytes
    const size_t flipWidth = static_cast<size_t>(1) << RandomIndex(3);  // 1, 2, or 4
    
    if (data.size() < flipWidth) {
        data[0] ^= 0xFF;
        return 1;
    }
    
    const size_t pos = RandomIndex(data.size() - flipWidth + 1);
    
    for (size_t i = 0; i < flipWidth; ++i) {
        data[pos + i] ^= 0xFF;
    }
    
    return 1;
}

size_t MutationEngine::ApplyArithmetic(std::vector<uint8_t>& data) noexcept {
    if (data.empty()) return 0;
    
    // Choose operation width: 1, 2, or 4 bytes
    const size_t width = static_cast<size_t>(1) << RandomIndex(3);  // 1, 2, or 4
    
    if (data.size() < width) {
        // Single byte arithmetic
        const int32_t delta = static_cast<int32_t>(RandomRange(1, m_config.arithmeticRange));
        if (RandomBool()) {
            data[0] = static_cast<uint8_t>(data[0] + delta);
        } else {
            data[0] = static_cast<uint8_t>(data[0] - delta);
        }
        return 1;
    }
    
    const size_t pos = RandomIndex(data.size() - width + 1);
    const int32_t delta = static_cast<int32_t>(RandomRange(1, m_config.arithmeticRange));
    const bool add = RandomBool();
    
    switch (width) {
    case 1: {
        if (add) {
            data[pos] = static_cast<uint8_t>(data[pos] + delta);
        } else {
            data[pos] = static_cast<uint8_t>(data[pos] - delta);
        }
        break;
    }
    case 2: {
        uint16_t val;
        std::memcpy(&val, &data[pos], 2);
        if (add) {
            val = static_cast<uint16_t>(val + delta);
        } else {
            val = static_cast<uint16_t>(val - delta);
        }
        std::memcpy(&data[pos], &val, 2);
        break;
    }
    case 4: {
        uint32_t val;
        std::memcpy(&val, &data[pos], 4);
        if (add) {
            val = static_cast<uint32_t>(val + delta);
        } else {
            val = static_cast<uint32_t>(val - delta);
        }
        std::memcpy(&data[pos], &val, 4);
        break;
    }
    default:
        break;
    }
    
    return 1;
}

size_t MutationEngine::ApplyInterestingValues(std::vector<uint8_t>& data) noexcept {
    if (data.empty()) return 0;
    
    // Choose value width: 1, 2, or 4 bytes
    const size_t width = static_cast<size_t>(1) << RandomIndex(3);  // 1, 2, or 4
    
    if (data.size() < width) {
        // Single byte interesting value
        data[0] = kInterestingBytes[RandomIndex(kInterestingBytes.size())];
        return 1;
    }
    
    const size_t pos = RandomIndex(data.size() - width + 1);
    
    switch (width) {
    case 1: {
        data[pos] = kInterestingBytes[RandomIndex(kInterestingBytes.size())];
        break;
    }
    case 2: {
        const uint16_t val = kInterestingWords[RandomIndex(kInterestingWords.size())];
        std::memcpy(&data[pos], &val, 2);
        break;
    }
    case 4: {
        const uint32_t val = kInterestingDwords[RandomIndex(kInterestingDwords.size())];
        std::memcpy(&data[pos], &val, 4);
        break;
    }
    default:
        break;
    }
    
    return 1;
}

size_t MutationEngine::ApplyBlockDelete(std::vector<uint8_t>& data) noexcept {
    if (data.size() < 2) return 0;
    
    // Delete between 1 and min(maxBlockSize, data.size()-1) bytes
    const size_t maxDelete = std::min(m_config.maxBlockSize, data.size() - 1);
    const size_t deleteSize = RandomRange(1, maxDelete);
    const size_t pos = RandomIndex(data.size() - deleteSize + 1);
    
    data.erase(data.begin() + static_cast<ptrdiff_t>(pos),
               data.begin() + static_cast<ptrdiff_t>(pos + deleteSize));
    
    return deleteSize;
}

size_t MutationEngine::ApplyBlockInsert(std::vector<uint8_t>& data) noexcept {
    // Check if we can insert more data
    if (data.size() >= m_config.maxOutputSize) return 0;
    
    const size_t maxInsert = std::min(
        m_config.maxInsertSize,
        m_config.maxOutputSize - data.size()
    );
    
    if (maxInsert == 0) return 0;
    
    const size_t insertSize = RandomRange(1, maxInsert);
    const size_t pos = data.empty() ? 0 : RandomIndex(data.size() + 1);
    
    // Choose content: random bytes, repeated byte, or zero bytes
    std::vector<uint8_t> toInsert(insertSize);
    
    const size_t choice = RandomIndex(3);
    switch (choice) {
    case 0:
        // Random bytes
        for (auto& byte : toInsert) {
            byte = RandomByte();
        }
        break;
    case 1:
        // Repeated single byte
        std::fill(toInsert.begin(), toInsert.end(), RandomByte());
        break;
    case 2:
        // Zero bytes
        std::fill(toInsert.begin(), toInsert.end(), static_cast<uint8_t>(0));
        break;
    }
    
    data.insert(data.begin() + static_cast<ptrdiff_t>(pos),
                toInsert.begin(), toInsert.end());
    
    return insertSize;
}

size_t MutationEngine::ApplyBlockOverwrite(std::vector<uint8_t>& data) noexcept {
    if (data.empty()) return 0;
    
    const size_t maxOverwrite = std::min(m_config.maxBlockSize, data.size());
    const size_t overwriteSize = RandomRange(1, maxOverwrite);
    const size_t pos = RandomIndex(data.size() - overwriteSize + 1);
    
    // Choose content type
    const size_t choice = RandomIndex(3);
    switch (choice) {
    case 0:
        // Random bytes
        for (size_t i = 0; i < overwriteSize; ++i) {
            data[pos + i] = RandomByte();
        }
        break;
    case 1:
        // Repeated byte
        {
            const uint8_t fillByte = RandomByte();
            for (size_t i = 0; i < overwriteSize; ++i) {
                data[pos + i] = fillByte;
            }
        }
        break;
    case 2:
        // Zero bytes
        std::fill(data.begin() + static_cast<ptrdiff_t>(pos),
                  data.begin() + static_cast<ptrdiff_t>(pos + overwriteSize),
                  static_cast<uint8_t>(0));
        break;
    }
    
    return overwriteSize;
}

size_t MutationEngine::ApplyDictionaryInsert(std::vector<uint8_t>& data) noexcept {
    // Check if we can insert more data
    if (data.size() >= m_config.maxOutputSize) return 0;
    
    // Select a dictionary entry
    const auto& dict = kPEDictionaryData;
    const size_t entryIdx = RandomIndex(dict.size());
    const auto& entry = dict[entryIdx];
    
    if (entry.empty()) return 0;
    
    // Check size limits
    if (data.size() + entry.size() > m_config.maxOutputSize) return 0;
    
    // Choose insertion strategy: insert or overwrite
    const bool overwrite = !data.empty() && RandomBool();
    
    if (overwrite && data.size() >= entry.size()) {
        // Overwrite at random position
        const size_t pos = RandomIndex(data.size() - entry.size() + 1);
        std::copy(entry.begin(), entry.end(), data.begin() + static_cast<ptrdiff_t>(pos));
    } else {
        // Insert at random position
        const size_t pos = data.empty() ? 0 : RandomIndex(data.size() + 1);
        data.insert(data.begin() + static_cast<ptrdiff_t>(pos), entry.begin(), entry.end());
    }
    
    return entry.size();
}

size_t MutationEngine::ApplySplice(
    std::vector<uint8_t>& data,
    std::span<const uint8_t> source) noexcept
{
    if (source.empty()) return 0;
    
    if (data.empty()) {
        // Just copy from source
        const size_t copySize = std::min(source.size(), m_config.maxOutputSize);
        data.assign(source.begin(), source.begin() + static_cast<ptrdiff_t>(copySize));
        return copySize;
    }
    
    // Choose splice point in both buffers
    const size_t dataPos = RandomIndex(data.size());
    const size_t sourcePos = RandomIndex(source.size());
    
    // Take prefix from data, suffix from source
    const size_t sourceLen = source.size() - sourcePos;
    const size_t newSize = dataPos + sourceLen;
    
    if (newSize > m_config.maxOutputSize) {
        // Truncate
        const size_t allowedSourceLen = m_config.maxOutputSize - dataPos;
        data.resize(dataPos);
        data.insert(data.end(),
                    source.begin() + static_cast<ptrdiff_t>(sourcePos),
                    source.begin() + static_cast<ptrdiff_t>(sourcePos + allowedSourceLen));
        return allowedSourceLen;
    }
    
    data.resize(dataPos);
    data.insert(data.end(),
                source.begin() + static_cast<ptrdiff_t>(sourcePos),
                source.end());
    
    return sourceLen;
}

size_t MutationEngine::ApplyHavoc(
    std::vector<uint8_t>& data,
    std::span<const uint8_t> spliceSource) noexcept
{
    // Apply 2-8 random mutations in sequence
    const size_t numMutations = RandomRange(m_config.minMutationCount, m_config.maxMutationCount);
    size_t totalApplied = 0;
    
    for (size_t i = 0; i < numMutations && !data.empty(); ++i) {
        // Choose a strategy (excluding Havoc to prevent recursion)
        const size_t strategyChoice = RandomIndex(
            static_cast<size_t>(MutationStrategy::Havoc));
        const auto strategy = static_cast<MutationStrategy>(strategyChoice);
        
        size_t applied = 0;
        
        switch (strategy) {
        case MutationStrategy::BitFlip:
            applied = ApplyBitFlip(data);
            break;
        case MutationStrategy::ByteFlip:
            applied = ApplyByteFlip(data);
            break;
        case MutationStrategy::Arithmetic:
            applied = ApplyArithmetic(data);
            break;
        case MutationStrategy::InterestingValues:
            applied = ApplyInterestingValues(data);
            break;
        case MutationStrategy::BlockDelete:
            applied = ApplyBlockDelete(data);
            break;
        case MutationStrategy::BlockInsert:
            applied = ApplyBlockInsert(data);
            break;
        case MutationStrategy::BlockOverwrite:
            applied = ApplyBlockOverwrite(data);
            break;
        case MutationStrategy::DictionaryInsert:
            applied = ApplyDictionaryInsert(data);
            break;
        case MutationStrategy::Splice:
            if (m_config.enableSplice && !spliceSource.empty()) {
                applied = ApplySplice(data, spliceSource);
            }
            break;
        default:
            break;
        }
        
        totalApplied += (applied > 0 ? 1 : 0);
        EnsureMaxSize(data);
    }
    
    return totalApplied;
}

}  // namespace ShadowStrike::Fuzzer
