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
 * @file FuzzLoop.hpp
 * @brief Main fuzzing iteration loop for corpus-based mutation testing.
 *
 * Provides the core fuzzing infrastructure including:
 * - Corpus management and loading
 * - Mutation and harness execution loop
 * - Crash collection and deduplication
 * - Coverage-guided corpus expansion
 * - Progress reporting and statistics
 * - Graceful shutdown handling
 *
 * @copyright ShadowStrike Security Suite
 */

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <string_view>
#include <filesystem>
#include <functional>
#include <memory>
#include <atomic>
#include <chrono>
#include <span>
#include <optional>

namespace ShadowStrike::Fuzzer {

/**
 * @brief Result from a single harness execution.
 */
struct HarnessResult {
    bool crashed = false;               ///< Whether a crash was detected
    std::string crashSignal;            ///< Crash signal/exception info (e.g., "EXCEPTION_ACCESS_VIOLATION")
    bool parsedOk = false;              ///< Whether initial parsing succeeded
    uint32_t anomalyCount = 0;          ///< Number of anomalies detected
    uint32_t validationIssueCount = 0;  ///< Number of validation issues
    uint64_t parseTimeNs = 0;           ///< Parsing time in nanoseconds
    std::string errorMessage;           ///< Optional error message
};

/**
 * @brief Type alias for harness function.
 *
 * A harness function takes input data and returns execution results.
 * It must be noexcept-safe (catch all exceptions internally).
 */
using HarnessFunction = std::function<HarnessResult(std::span<const uint8_t>)>;

/**
 * @brief Configuration for the fuzzing loop.
 */
struct FuzzLoopConfig {
    uint64_t maxIterations = 0;                 ///< Maximum iterations (0 = unlimited)
    uint64_t maxDurationSeconds = 0;            ///< Maximum duration (0 = unlimited)
    size_t maxInputSize = 16 * 1024 * 1024;     ///< Maximum input size (16MB)
    size_t reportIntervalIterations = 1000;     ///< Report progress every N iterations
    size_t minSeedSize = 64;                    ///< Minimum seed size for generated seeds
    bool saveAllInputs = false;                 ///< Save all inputs (not just crashes)
    bool enableCorpusExpansion = true;          ///< Add interesting inputs to corpus
    std::string targetName = "unknown";         ///< Name of the target being fuzzed
};

/**
 * @brief Statistics for the fuzzing session.
 */
struct FuzzStatistics {
    uint64_t totalIterations = 0;           ///< Total iterations executed
    uint64_t crashesFound = 0;              ///< Total crashes found
    uint64_t uniqueCrashes = 0;             ///< Unique crash signals
    uint64_t corpusSize = 0;                ///< Current corpus size
    uint64_t corpusAdditions = 0;           ///< Inputs added to corpus
    uint64_t totalBytesProcessed = 0;       ///< Total bytes fed to harness
    uint64_t parseSuccesses = 0;            ///< Successful parses
    uint64_t parseFailures = 0;             ///< Failed parses
    double iterationsPerSecond = 0.0;       ///< Current iteration rate
    uint64_t durationMs = 0;                ///< Total duration in milliseconds
    std::chrono::steady_clock::time_point startTime;  ///< Session start time
};

/**
 * @brief Information about a saved crash.
 */
struct CrashInfo {
    std::string signal;                 ///< Crash signal identifier
    std::filesystem::path inputPath;    ///< Path to saved input
    std::filesystem::path metadataPath; ///< Path to metadata JSON
    uint64_t iterationNumber = 0;       ///< Iteration when crash was found
    uint64_t prngSeed = 0;              ///< PRNG seed for replay
    size_t inputSize = 0;               ///< Size of crashing input
    std::string timestamp;              ///< ISO timestamp of crash
};

/**
 * @brief Corpus entry for fuzzing.
 */
struct CorpusEntry {
    std::vector<uint8_t> data;          ///< Input data
    std::filesystem::path sourcePath;   ///< Original file path (if loaded from disk)
    uint64_t hitCount = 0;              ///< Number of times selected for mutation
    bool fromSeed = false;              ///< Whether this is a seed file
};

/**
 * @brief Main fuzzing iteration loop.
 *
 * This class manages the core fuzzing loop including:
 * - Loading and managing the input corpus
 * - Mutating inputs and feeding them to the harness
 * - Detecting and saving crashes
 * - Expanding the corpus with interesting inputs
 * - Reporting progress and statistics
 *
 * Thread safety: A single FuzzLoop instance should be used from one thread.
 * For parallel fuzzing, create multiple instances with different corpus shards.
 *
 * Usage:
 * @code
 *   FuzzLoopConfig config;
 *   config.maxIterations = 100000;
 *   config.targetName = "pe-parser";
 *
 *   FuzzLoop loop(corpusDir, crashDir, PEParserHarness::Run, config);
 *   loop.Run();
 *
 *   const auto& stats = loop.GetStatistics();
 *   std::cout << "Crashes found: " << stats.uniqueCrashes << '\n';
 * @endcode
 */
class FuzzLoop {
public:
    /**
     * @brief Construct a new fuzz loop.
     * @param corpusDirectory Directory containing corpus files (*.bin).
     * @param crashDirectory Directory to save crashes.
     * @param harness Harness function to execute.
     * @param config Loop configuration.
     */
    FuzzLoop(
        const std::filesystem::path& corpusDirectory,
        const std::filesystem::path& crashDirectory,
        HarnessFunction harness,
        const FuzzLoopConfig& config = {}) noexcept;

    ~FuzzLoop();

    // Non-copyable, non-movable (owns threads and state)
    FuzzLoop(const FuzzLoop&) = delete;
    FuzzLoop& operator=(const FuzzLoop&) = delete;
    FuzzLoop(FuzzLoop&&) = delete;
    FuzzLoop& operator=(FuzzLoop&&) = delete;

    // ========================================================================
    // Corpus Management
    // ========================================================================

    /**
     * @brief Load corpus from the corpus directory.
     * @return Number of files loaded.
     */
    [[nodiscard]] size_t LoadCorpus() noexcept;

    /**
     * @brief Generate minimal seed inputs if corpus is empty.
     *
     * Generates:
     * - Minimal valid PE32 (MZ + PE signature + headers)
     * - Minimal valid PE64
     * - Empty buffer
     * - Buffer of 0xFF bytes
     * - Random buffers of various sizes
     *
     * @return Number of seeds generated.
     */
    [[nodiscard]] size_t GenerateMinimalSeeds() noexcept;

    /**
     * @brief Add an entry to the corpus.
     * @param data Input data.
     * @param sourcePath Optional source path.
     * @return true if added successfully.
     */
    [[nodiscard]] bool AddToCorpus(
        std::span<const uint8_t> data,
        const std::filesystem::path& sourcePath = {}) noexcept;

    /**
     * @brief Get current corpus size.
     * @return Number of entries in corpus.
     */
    [[nodiscard]] size_t GetCorpusSize() const noexcept;

    // ========================================================================
    // Fuzzing Loop
    // ========================================================================

    /**
     * @brief Run the main fuzzing loop.
     *
     * Runs until one of:
     * - maxIterations reached
     * - maxDurationSeconds elapsed
     * - Stop() is called
     * - Ctrl+C / SIGINT received
     *
     * @return true if loop completed normally, false if interrupted.
     */
    [[nodiscard]] bool Run() noexcept;

    /**
     * @brief Request graceful stop of the fuzzing loop.
     *
     * Thread-safe. Can be called from signal handlers or other threads.
     */
    void Stop() noexcept;

    /**
     * @brief Check if the loop is running.
     * @return true if currently in Run().
     */
    [[nodiscard]] bool IsRunning() const noexcept;

    // ========================================================================
    // Results and Statistics
    // ========================================================================

    /**
     * @brief Get current statistics.
     * @return Reference to statistics structure.
     */
    [[nodiscard]] const FuzzStatistics& GetStatistics() const noexcept;

    /**
     * @brief Get list of crashes found.
     * @return Vector of crash information.
     */
    [[nodiscard]] const std::vector<CrashInfo>& GetCrashes() const noexcept;

    /**
     * @brief Write summary JSON to a file.
     * @param path Output path.
     * @return true if written successfully.
     */
    [[nodiscard]] bool WriteSummaryJson(const std::filesystem::path& path) const noexcept;

    /**
     * @brief Write summary JSON to a string.
     * @return JSON string.
     */
    [[nodiscard]] std::string BuildSummaryJson() const noexcept;

    /**
     * @brief Print progress to stdout.
     */
    void PrintProgress() const noexcept;

    // ========================================================================
    // Configuration
    // ========================================================================

    /**
     * @brief Get current configuration.
     * @return Reference to configuration.
     */
    [[nodiscard]] const FuzzLoopConfig& GetConfig() const noexcept;

    /**
     * @brief Update configuration.
     *
     * Some settings (corpusDirectory, crashDirectory) cannot be changed
     * while running.
     *
     * @param config New configuration.
     */
    void SetConfig(const FuzzLoopConfig& config) noexcept;

    // ========================================================================
    // Crash Handling
    // ========================================================================

    /**
     * @brief Save a crashing input.
     * @param data Input data that caused crash.
     * @param result Harness result with crash info.
     * @param prngSeed PRNG seed for replay.
     * @return Path to saved crash file, or empty on failure.
     */
    [[nodiscard]] std::filesystem::path SaveCrash(
        std::span<const uint8_t> data,
        const HarnessResult& result,
        uint64_t prngSeed) noexcept;

private:
    // Internal implementation
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

/**
 * @brief Generate a minimal valid PE32 seed.
 * @return Byte vector containing minimal PE32.
 */
[[nodiscard]] std::vector<uint8_t> GenerateMinimalPE32Seed() noexcept;

/**
 * @brief Generate a minimal valid PE64 seed.
 * @return Byte vector containing minimal PE64.
 */
[[nodiscard]] std::vector<uint8_t> GenerateMinimalPE64Seed() noexcept;

/**
 * @brief Install Ctrl+C handler for graceful shutdown.
 *
 * Sets up a console control handler that sets a global stop flag.
 * Call this once at program start.
 *
 * @return true if handler installed successfully.
 */
[[nodiscard]] bool InstallCtrlCHandler() noexcept;

/**
 * @brief Check if Ctrl+C was received.
 * @return true if stop was requested.
 */
[[nodiscard]] bool WasCtrlCReceived() noexcept;

/**
 * @brief Reset the Ctrl+C flag.
 */
void ResetCtrlCFlag() noexcept;

/**
 * @brief Escape a string for JSON output.
 * @param value String to escape.
 * @return Escaped string.
 */
[[nodiscard]] std::string EscapeJsonString(std::string_view value) noexcept;

/**
 * @brief Get current ISO timestamp.
 * @return Timestamp string (e.g., "2026-01-15T14:30:00Z").
 */
[[nodiscard]] std::string GetIsoTimestamp() noexcept;

}  // namespace ShadowStrike::Fuzzer
