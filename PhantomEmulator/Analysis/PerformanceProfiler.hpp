/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * PerformanceProfiler.hpp — Emulation throughput tracking, hot-path
 * detection, and basic-block profiling for performance optimization
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../Common/Types.hpp"
#include "../Core/CPU/Executor/Decoder/Instruction.hpp"

#include <cstdint>
#include <memory>
#include <vector>

namespace Phantom {

struct ThroughputStats {
    uint64_t totalInstructions = 0;
    uint64_t totalCycles = 0;
    double   instructionsPerSecond = 0.0;
    double   avgNanosPerInstruction = 0.0;
    double   peakIPS = 0.0;
    uint64_t decodeTimeNs = 0;
    uint64_t executeTimeNs = 0;
    uint64_t memoryAccessTimeNs = 0;
    uint64_t apiDispatchTimeNs = 0;
};

struct BasicBlock {
    GuestAddress startAddress = 0;
    uint32_t     instructionCount = 0;
    uint32_t     byteLength = 0;
    uint64_t     executionCount = 0;
    uint64_t     lastExecuted = 0;
    bool         isHot = false;

    static constexpr uint32_t kMaxBlockInstructions = 64;
    DecodedInstruction instructions[kMaxBlockInstructions]{};
};

static constexpr uint32_t kBlockCacheSize = 16384;
static constexpr uint32_t kBlockCacheMask = kBlockCacheSize - 1;
static constexpr uint64_t kHotBlockThreshold = 1000;

struct BlockCacheEntry {
    GuestAddress key = 0;
    BasicBlock   block{};
};

struct HotPath {
    GuestAddress entryPoint = 0;
    uint64_t     totalExecutions = 0;
    uint32_t     blockCount = 0;
    float        executionShare = 0.0f;
    bool         isLoop = false;
    uint32_t     loopIterations = 0;
};

struct OpcodeProfile {
    uint64_t frequency[256]{};
    uint64_t twoByteFreq[256]{};
    uint64_t threeByteFreq38[256]{};
    uint64_t threeByteFreq3A[256]{};
    uint8_t  topOpcodes[16]{};
};

struct MemoryProfile {
    uint64_t totalReads = 0;
    uint64_t totalWrites = 0;
    uint64_t stackAccesses = 0;
    uint64_t heapAccesses = 0;
    uint64_t codeRegionReads = 0;
    uint64_t crossPageAccesses = 0;
    uint32_t uniquePagesAccessed = 0;
    uint32_t writableExecAccesses = 0;
};

struct PhaseTimings {
    uint64_t decodingNs = 0;
    uint64_t executionNs = 0;
    uint64_t memoryNs = 0;
    uint64_t apiDispatchNs = 0;
    uint64_t analysisNs = 0;
    uint64_t blockCacheLookupNs = 0;
    uint64_t blockCacheHits = 0;
    uint64_t blockCacheMisses = 0;
    double   cacheHitRate = 0.0;
};

class PerformanceProfiler {
public:
    explicit PerformanceProfiler() noexcept;
    ~PerformanceProfiler() noexcept;

    PerformanceProfiler(const PerformanceProfiler&) = delete;
    PerformanceProfiler& operator=(const PerformanceProfiler&) = delete;
    PerformanceProfiler(PerformanceProfiler&&) noexcept;
    PerformanceProfiler& operator=(PerformanceProfiler&&) noexcept;

    void OnInstructionStart(GuestAddress rip) noexcept;
    void OnInstructionEnd(GuestAddress rip, uint8_t opcodeMap, uint8_t opcode) noexcept;
    void OnBlockEntry(GuestAddress blockStart) noexcept;
    void OnBlockExit(GuestAddress blockEnd, uint32_t instrCount) noexcept;
    void OnMemoryAccess(GuestAddress addr, uint32_t size, bool isWrite) noexcept;
    void OnAPICall(const char* funcName, uint64_t durationNs) noexcept;
    void OnDecodeComplete(uint64_t durationNs) noexcept;

    [[nodiscard]] BasicBlock* LookupBlock(GuestAddress address) noexcept;
    void CacheBlock(const BasicBlock& block) noexcept;
    void InvalidateBlock(GuestAddress address) noexcept;
    void InvalidateRange(GuestAddress start, GuestSize size) noexcept;

    [[nodiscard]] ThroughputStats GetThroughput() const noexcept;
    [[nodiscard]] OpcodeProfile GetOpcodeProfile() const noexcept;
    [[nodiscard]] MemoryProfile GetMemoryProfile() const noexcept;
    [[nodiscard]] PhaseTimings GetPhaseTimings() const noexcept;
    [[nodiscard]] std::vector<HotPath> GetHotPaths(uint32_t maxResults = 32) const noexcept;

    void Reset() noexcept;
    void SetEnabled(bool enabled) noexcept;
    [[nodiscard]] bool IsEnabled() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
