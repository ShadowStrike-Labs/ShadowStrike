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
#pragma once
/**
 * @file MutationEngine.hpp
 * @brief Byte-level and structure-aware mutation engine for fuzzing.
 *
 * Provides comprehensive mutation strategies including:
 * - Bit/byte flipping
 * - Arithmetic mutations
 * - Interesting value injection
 * - Block operations (insert, delete, overwrite)
 * - Dictionary-based mutations for PE files
 * - Splice mutations combining corpus entries
 * - Havoc mode chaining multiple mutations
 *
 * @copyright ShadowStrike Security Suite
 */

#include <cstdint>
#include <cstddef>
#include <vector>
#include <span>
#include <random>
#include <string_view>
#include <optional>

namespace ShadowStrike::Fuzzer {

/**
 * @brief Enumeration of available mutation strategies.
 */
enum class MutationStrategy : uint32_t {
    BitFlip,            ///< Flip 1/2/4/8 bits at random positions
    ByteFlip,           ///< Flip 1/2/4 bytes at random positions
    Arithmetic,         ///< Add/subtract small values
    InterestingValues,  ///< Replace with edge-case values
    BlockDelete,        ///< Remove a random range of bytes
    BlockInsert,        ///< Insert random or repeated bytes
    BlockOverwrite,     ///< Overwrite with random data
    DictionaryInsert,   ///< Insert PE-specific tokens
    Splice,             ///< Combine with another corpus entry
    Havoc,              ///< Chain multiple mutations

    COUNT               ///< Number of strategies (for iteration)
};

/**
 * @brief Convert mutation strategy to string.
 */
[[nodiscard]] std::string_view ToString(MutationStrategy strategy) noexcept;

/**
 * @brief Configuration for the mutation engine.
 */
struct MutationConfig {
    size_t maxOutputSize = 16 * 1024 * 1024;  ///< Maximum output buffer size (16MB)
    size_t minMutationCount = 1;              ///< Minimum mutations per iteration
    size_t maxMutationCount = 8;              ///< Maximum mutations for havoc mode
    int32_t arithmeticRange = 35;             ///< Range for arithmetic mutations (+/- this value)
    size_t maxBlockSize = 4096;               ///< Maximum block size for block operations
    size_t maxInsertSize = 128;               ///< Maximum size for block insert
    bool enableSplice = true;                 ///< Enable splice mutations (requires corpus)
};

/**
 * @brief Result of a mutation operation.
 */
struct MutationResult {
    std::vector<uint8_t> data;          ///< Mutated data
    MutationStrategy appliedStrategy;   ///< Primary strategy used
    size_t mutationCount;               ///< Number of mutations applied
    uint64_t seed;                       ///< PRNG seed used (for replay)
    bool success;                        ///< Whether mutation succeeded
};

/**
 * @brief Byte-level and structure-aware mutation engine.
 *
 * This class provides comprehensive mutation capabilities for fuzzing.
 * It uses a Mersenne Twister PRNG (mt19937_64) for high-quality randomness
 * and supports deterministic replay via explicit seeding.
 *
 * Thread safety: Each instance should be used from a single thread.
 * For parallel fuzzing, create one MutationEngine per thread.
 *
 * Usage:
 * @code
 *   MutationEngine engine;
 *   engine.Seed(12345);  // Optional: deterministic seed
 *   
 *   std::vector<uint8_t> input = LoadCorpusEntry();
 *   MutationResult result = engine.Mutate(input);
 *   
 *   if (result.success) {
 *       RunHarness(result.data);
 *   }
 * @endcode
 */
class MutationEngine {
public:
    /**
     * @brief Construct engine with default configuration.
     *
     * Seeds the PRNG from std::random_device for non-determinism.
     */
    MutationEngine() noexcept;

    /**
     * @brief Construct engine with custom configuration.
     * @param config Mutation configuration.
     */
    explicit MutationEngine(const MutationConfig& config) noexcept;

    // Non-copyable, movable
    MutationEngine(const MutationEngine&) = delete;
    MutationEngine& operator=(const MutationEngine&) = delete;
    MutationEngine(MutationEngine&&) noexcept = default;
    MutationEngine& operator=(MutationEngine&&) noexcept = default;

    ~MutationEngine() = default;

    // ========================================================================
    // Seeding
    // ========================================================================

    /**
     * @brief Seed the PRNG for deterministic replay.
     * @param seed 64-bit seed value.
     */
    void Seed(uint64_t seed) noexcept;

    /**
     * @brief Seed the PRNG from hardware random source.
     */
    void SeedFromRandom() noexcept;

    /**
     * @brief Get the current PRNG seed (for replay).
     * @return Last seed used.
     */
    [[nodiscard]] uint64_t GetCurrentSeed() const noexcept;

    // ========================================================================
    // Mutation Operations
    // ========================================================================

    /**
     * @brief Mutate input using a random strategy.
     * @param input Input buffer to mutate.
     * @return Mutation result with mutated data.
     */
    [[nodiscard]] MutationResult Mutate(std::span<const uint8_t> input) noexcept;

    /**
     * @brief Mutate input using a specific strategy.
     * @param input Input buffer to mutate.
     * @param strategy Strategy to apply.
     * @return Mutation result with mutated data.
     */
    [[nodiscard]] MutationResult Mutate(
        std::span<const uint8_t> input,
        MutationStrategy strategy) noexcept;

    /**
     * @brief Mutate with splice from another corpus entry.
     * @param input Input buffer to mutate.
     * @param spliceSource Second buffer for splice operations.
     * @return Mutation result with mutated data.
     */
    [[nodiscard]] MutationResult MutateWithSplice(
        std::span<const uint8_t> input,
        std::span<const uint8_t> spliceSource) noexcept;

    // ========================================================================
    // Individual Mutation Strategies
    // ========================================================================

    /**
     * @brief Flip bits at random positions.
     * @param data Buffer to mutate (modified in-place).
     * @return Number of mutations applied.
     */
    [[nodiscard]] size_t ApplyBitFlip(std::vector<uint8_t>& data) noexcept;

    /**
     * @brief Flip bytes at random positions.
     * @param data Buffer to mutate (modified in-place).
     * @return Number of mutations applied.
     */
    [[nodiscard]] size_t ApplyByteFlip(std::vector<uint8_t>& data) noexcept;

    /**
     * @brief Apply arithmetic mutations (add/subtract small values).
     * @param data Buffer to mutate (modified in-place).
     * @return Number of mutations applied.
     */
    [[nodiscard]] size_t ApplyArithmetic(std::vector<uint8_t>& data) noexcept;

    /**
     * @brief Replace positions with interesting values.
     * @param data Buffer to mutate (modified in-place).
     * @return Number of mutations applied.
     */
    [[nodiscard]] size_t ApplyInterestingValues(std::vector<uint8_t>& data) noexcept;

    /**
     * @brief Delete a random block of bytes.
     * @param data Buffer to mutate (modified in-place).
     * @return Number of bytes deleted.
     */
    [[nodiscard]] size_t ApplyBlockDelete(std::vector<uint8_t>& data) noexcept;

    /**
     * @brief Insert random or repeated bytes at a random position.
     * @param data Buffer to mutate (modified in-place).
     * @return Number of bytes inserted.
     */
    [[nodiscard]] size_t ApplyBlockInsert(std::vector<uint8_t>& data) noexcept;

    /**
     * @brief Overwrite a random block with random data.
     * @param data Buffer to mutate (modified in-place).
     * @return Number of bytes overwritten.
     */
    [[nodiscard]] size_t ApplyBlockOverwrite(std::vector<uint8_t>& data) noexcept;

    /**
     * @brief Insert PE-specific dictionary tokens.
     * @param data Buffer to mutate (modified in-place).
     * @return Number of bytes inserted.
     */
    [[nodiscard]] size_t ApplyDictionaryInsert(std::vector<uint8_t>& data) noexcept;

    /**
     * @brief Splice two buffers together.
     * @param data Buffer to mutate (modified in-place).
     * @param source Source buffer for splice.
     * @return Number of bytes from source incorporated.
     */
    [[nodiscard]] size_t ApplySplice(
        std::vector<uint8_t>& data,
        std::span<const uint8_t> source) noexcept;

    /**
     * @brief Apply multiple random mutations (havoc mode).
     * @param data Buffer to mutate (modified in-place).
     * @param spliceSource Optional splice source buffer.
     * @return Number of mutations applied.
     */
    [[nodiscard]] size_t ApplyHavoc(
        std::vector<uint8_t>& data,
        std::span<const uint8_t> spliceSource = {}) noexcept;

    // ========================================================================
    // Configuration
    // ========================================================================

    /**
     * @brief Get current configuration.
     * @return Reference to configuration.
     */
    [[nodiscard]] const MutationConfig& GetConfig() const noexcept;

    /**
     * @brief Update configuration.
     * @param config New configuration.
     */
    void SetConfig(const MutationConfig& config) noexcept;

    // ========================================================================
    // Statistics
    // ========================================================================

    /**
     * @brief Get total mutations performed.
     * @return Mutation count since construction or reset.
     */
    [[nodiscard]] uint64_t GetTotalMutations() const noexcept;

    /**
     * @brief Reset statistics counters.
     */
    void ResetStatistics() noexcept;

private:
    // Random number generation
    [[nodiscard]] size_t RandomIndex(size_t maxExclusive) noexcept;
    [[nodiscard]] size_t RandomRange(size_t minInclusive, size_t maxInclusive) noexcept;
    [[nodiscard]] uint8_t RandomByte() noexcept;
    [[nodiscard]] bool RandomBool() noexcept;

    // Internal helpers
    [[nodiscard]] MutationStrategy ChooseRandomStrategy() noexcept;
    void EnsureMaxSize(std::vector<uint8_t>& data) noexcept;

    MutationConfig m_config;
    std::mt19937_64 m_rng;
    uint64_t m_currentSeed = 0;
    uint64_t m_totalMutations = 0;
};

/**
 * @brief Get PE-specific dictionary tokens for mutation.
 * @return Span of dictionary entry spans.
 */
[[nodiscard]] std::span<const std::span<const uint8_t>> GetPEDictionary() noexcept;

/**
 * @brief Get interesting byte values for mutation.
 * @return Span of interesting byte values.
 */
[[nodiscard]] std::span<const uint8_t> GetInterestingBytes() noexcept;

/**
 * @brief Get interesting 16-bit values for mutation.
 * @return Span of interesting 16-bit values.
 */
[[nodiscard]] std::span<const uint16_t> GetInterestingWords() noexcept;

/**
 * @brief Get interesting 32-bit values for mutation.
 * @return Span of interesting 32-bit values.
 */
[[nodiscard]] std::span<const uint32_t> GetInterestingDwords() noexcept;

}  // namespace ShadowStrike::Fuzzer
