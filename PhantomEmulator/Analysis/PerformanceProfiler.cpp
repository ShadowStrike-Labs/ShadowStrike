/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * PerformanceProfiler.cpp — Emulation throughput tracking, hot-path
 * detection, and basic-block profiling for performance optimization
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "PerformanceProfiler.hpp"

#include "../Common/Constants.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <exception>
#include <limits>
#include <mutex>
#include <new>
#include <shared_mutex>
#include <thread>
#include <utility>

#if defined(_WIN32) || defined(_WIN64)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#endif

namespace Phantom {

namespace {

[[nodiscard]] uint64_t ReadHighResolutionTicks() noexcept {
#if defined(_WIN32) || defined(_WIN64)
    LARGE_INTEGER counter{};
    if (::QueryPerformanceCounter(&counter) == 0) {
        return 0;
    }
    return static_cast<uint64_t>(counter.QuadPart);
#else
    return static_cast<uint64_t>(
        std::chrono::high_resolution_clock::now().time_since_epoch().count());
#endif
}

[[nodiscard]] uint64_t ReadHighResolutionFrequency() noexcept {
#if defined(_WIN32) || defined(_WIN64)
    LARGE_INTEGER frequency{};
    if (::QueryPerformanceFrequency(&frequency) == 0 || frequency.QuadPart <= 0) {
        return 1;
    }
    return static_cast<uint64_t>(frequency.QuadPart);
#else
    return 1'000'000'000ULL;
#endif
}

[[nodiscard]] uint64_t TicksToNs(uint64_t ticks, uint64_t frequency) noexcept {
    if (ticks == 0 || frequency == 0) {
        return 0;
    }

    constexpr uint64_t kNsPerSecond = 1'000'000'000ULL;
    const long double ns =
        (static_cast<long double>(ticks) * static_cast<long double>(kNsPerSecond)) /
        static_cast<long double>(frequency);
    return (ns >= static_cast<long double>(std::numeric_limits<uint64_t>::max()))
        ? std::numeric_limits<uint64_t>::max()
        : static_cast<uint64_t>(ns);
}

[[nodiscard]] uint64_t ElapsedTicks(uint64_t nowTicks, uint64_t startTicks) noexcept {
    return (nowTicks > startTicks) ? (nowTicks - startTicks) : 0;
}

void SaturatingAdd(uint64_t& target, uint64_t value) noexcept {
    target = (value > std::numeric_limits<uint64_t>::max() - target)
        ? std::numeric_limits<uint64_t>::max()
        : (target + value);
}

void SaturatingIncrement(uint64_t& target) noexcept {
    SaturatingAdd(target, 1);
}

uint64_t SaturatingAtomicIncrement(std::atomic<uint64_t>& value) noexcept {
    uint64_t current = value.load(std::memory_order_relaxed);
    while (current != std::numeric_limits<uint64_t>::max()) {
        const uint64_t desired = current + 1;
        if (value.compare_exchange_weak(
                current,
                desired,
                std::memory_order_relaxed,
                std::memory_order_relaxed)) {
            return desired;
        }
    }
    return current;
}

template <size_t Capacity>
struct FixedPageSet {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be a power of two");

    std::array<GuestAddress, Capacity> slots{};
    uint32_t uniqueCount = 0;

    void Reset() noexcept {
        slots.fill(0);
        uniqueCount = 0;
    }

    [[nodiscard]] bool Contains(GuestAddress page) const noexcept {
        if (page == 0) {
            return false;
        }

        uint32_t index = static_cast<uint32_t>((page >> kPageShift) & (Capacity - 1));
        for (uint32_t probe = 0; probe < Capacity; ++probe) {
            const auto current = slots[(index + probe) & (Capacity - 1)];
            if (current == 0) {
                return false;
            }
            if (current == page) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] bool Insert(GuestAddress page) noexcept {
        if (page == 0) {
            return false;
        }

        uint32_t index = static_cast<uint32_t>((page >> kPageShift) & (Capacity - 1));
        for (uint32_t probe = 0; probe < Capacity; ++probe) {
            auto& slot = slots[(index + probe) & (Capacity - 1)];
            if (slot == page) {
                return false;
            }
            if (slot == 0) {
                slot = page;
                if (uniqueCount < Capacity) {
                    ++uniqueCount;
                }
                return true;
            }
        }
        return false;
    }
};

} // namespace

struct PerformanceProfiler::Impl {
    static constexpr uint32_t kMaxTrackedThreads = 32;
    static constexpr uint32_t kRecentBlockRingSize = 64;
    static constexpr uint32_t kHotPathTableSize = 4096;
    static constexpr uint32_t kMaxHotPathBlocks = 8;
    static constexpr uint32_t kTrackedPageSetSize = 8192;
    static constexpr uint64_t kOneSecondNs = 1'000'000'000ULL;
    static constexpr GuestAddress kStackBase32 = 0x00F00000ULL;
    static constexpr GuestAddress kHeapBase32 = 0x00200000ULL;

    struct ThreadContext {
        std::thread::id id{};
        bool inUse = false;
        bool instructionActive = false;
        GuestAddress currentRip = 0;
        GuestAddress currentBlock = 0;
        uint64_t instructionStartTicks = 0;
        uint64_t lastPhaseTicks = 0;
    };

    struct HotPathEntry {
        uint64_t signature = 0;
        HotPath  path{};
    };

    mutable std::shared_mutex mutex;
    bool enabled = true;

    uint64_t tickFrequency = ReadHighResolutionFrequency();
    uint64_t startTicks = ReadHighResolutionTicks();
    uint64_t lastWindowTicks = startTicks;
    uint64_t lastWindowInstructionCount = 0;

    std::atomic<uint64_t> totalInstructions{ 0 };
    double peakIPS = 0.0;

    ThroughputStats throughput{};
    OpcodeProfile opcodeProfile{};
    MemoryProfile memoryProfile{};
    PhaseTimings phaseTimings{};

    std::unique_ptr<BlockCacheEntry[]> blockCache;
    std::array<ThreadContext, kMaxTrackedThreads> threadContexts{};
    std::array<GuestAddress, kRecentBlockRingSize> recentBlocks{};
    uint32_t recentBlockCount = 0;
    uint32_t recentBlockHead = 0;
    std::array<HotPathEntry, kHotPathTableSize> hotPaths{};
    FixedPageSet<kTrackedPageSetSize> uniquePages;
    FixedPageSet<kTrackedPageSetSize> executedPages;
    FixedPageSet<kTrackedPageSetSize> writtenExecutablePages;

    Impl()
        : blockCache(std::make_unique<BlockCacheEntry[]>(kBlockCacheSize))
    {
        ResetState();
    }

    [[nodiscard]] ThreadContext* GetThreadContext() noexcept {
        const auto currentId = std::this_thread::get_id();

        for (auto& entry : threadContexts) {
            if (entry.inUse && entry.id == currentId) {
                return &entry;
            }
        }

        for (auto& entry : threadContexts) {
            if (!entry.inUse) {
                entry = ThreadContext{};
                entry.id = currentId;
                entry.inUse = true;
                return &entry;
            }
        }

        threadContexts[0] = ThreadContext{};
        threadContexts[0].id = currentId;
        threadContexts[0].inUse = true;
        return &threadContexts[0];
    }

    [[nodiscard]] BlockCacheEntry* FindBlockEntry(GuestAddress address) noexcept {
        if (address == 0 || !blockCache) {
            return nullptr;
        }

        uint32_t index = static_cast<uint32_t>((address >> 2) & kBlockCacheMask);
        for (uint32_t probe = 0; probe < kBlockCacheSize; ++probe) {
            auto& entry = blockCache[(index + probe) & kBlockCacheMask];
            if (entry.key == 0) {
                return nullptr;
            }
            if (entry.key == address) {
                return &entry;
            }
        }

        return nullptr;
    }

    [[nodiscard]] const BlockCacheEntry* FindBlockEntry(GuestAddress address) const noexcept {
        return const_cast<Impl*>(this)->FindBlockEntry(address);
    }

    void EraseBlockEntry(GuestAddress address) noexcept {
        if (address == 0 || !blockCache) {
            return;
        }

        uint32_t index = static_cast<uint32_t>((address >> 2) & kBlockCacheMask);
        for (uint32_t probe = 0; probe < kBlockCacheSize; ++probe) {
            const uint32_t slotIndex = (index + probe) & kBlockCacheMask;
            if (blockCache[slotIndex].key == 0) {
                return;
            }

            if (blockCache[slotIndex].key == address) {
                blockCache[slotIndex] = BlockCacheEntry{};
                uint32_t next = (slotIndex + 1) & kBlockCacheMask;
                while (blockCache[next].key != 0) {
                    BlockCacheEntry displaced = blockCache[next];
                    blockCache[next] = BlockCacheEntry{};

                    uint32_t reinsertion = static_cast<uint32_t>(
                        (displaced.key >> 2) & kBlockCacheMask);
                    for (uint32_t reProbe = 0; reProbe < kBlockCacheSize; ++reProbe) {
                        auto& destination = blockCache[(reinsertion + reProbe) & kBlockCacheMask];
                        if (destination.key == 0) {
                            destination = displaced;
                            break;
                        }
                    }
                    next = (next + 1) & kBlockCacheMask;
                }
                return;
            }
        }
    }

    [[nodiscard]] uint64_t ComputeSequenceSignature(
        const GuestAddress* sequence,
        uint32_t count) const noexcept
    {
        uint64_t hash = 1469598103934665603ULL;
        for (uint32_t i = 0; i < count; ++i) {
            hash ^= sequence[i];
            hash *= 1099511628211ULL;
        }
        hash ^= count;
        hash *= 1099511628211ULL;
        return hash == 0 ? 1 : hash;
    }

    [[nodiscard]] uint32_t EstimateLoopIterations(uint32_t length) const noexcept {
        if (length == 0 || recentBlockCount < length) {
            return 0;
        }

        std::array<GuestAddress, kMaxHotPathBlocks> pattern{};
        for (uint32_t i = 0; i < length; ++i) {
            const uint32_t sourceIndex =
                (recentBlockHead + kRecentBlockRingSize - length + i) % kRecentBlockRingSize;
            pattern[i] = recentBlocks[sourceIndex];
        }

        uint32_t iterations = 1;
        uint32_t available = recentBlockCount;
        while (available >= (iterations + 1) * length) {
            bool matches = true;
            for (uint32_t i = 0; i < length; ++i) {
                const uint32_t sourceIndex =
                    (recentBlockHead + kRecentBlockRingSize - ((iterations + 1) * length) + i)
                    % kRecentBlockRingSize;
                if (recentBlocks[sourceIndex] != pattern[i]) {
                    matches = false;
                    break;
                }
            }

            if (!matches) {
                break;
            }
            ++iterations;
        }

        return iterations;
    }

    void UpdatePeakIPS(uint64_t nowTicks) noexcept {
        const uint64_t currentInstructions = totalInstructions.load(std::memory_order_relaxed);
        const uint64_t elapsedTicks = ElapsedTicks(nowTicks, lastWindowTicks);
        if (elapsedTicks == 0 || tickFrequency == 0) {
            return;
        }

        const uint64_t elapsedNs = TicksToNs(elapsedTicks, tickFrequency);
        if (elapsedNs < kOneSecondNs) {
            return;
        }

        const uint64_t deltaInstructions =
            currentInstructions >= lastWindowInstructionCount
                ? currentInstructions - lastWindowInstructionCount
                : 0;
        const double ips = static_cast<double>(deltaInstructions) * static_cast<double>(tickFrequency)
            / static_cast<double>(elapsedTicks);
        if (ips > peakIPS) {
            peakIPS = ips;
        }

        lastWindowTicks = nowTicks;
        lastWindowInstructionCount = currentInstructions;
    }

    void TrackHotPath(GuestAddress blockStart) noexcept {
        recentBlocks[recentBlockHead] = blockStart;
        recentBlockHead = (recentBlockHead + 1) % kRecentBlockRingSize;
        if (recentBlockCount < kRecentBlockRingSize) {
            ++recentBlockCount;
        }

        const uint32_t maxBlocks = std::min<uint32_t>(recentBlockCount, kMaxHotPathBlocks);
        std::array<GuestAddress, kMaxHotPathBlocks> sequence{};

        for (uint32_t length = 1; length <= maxBlocks; ++length) {
            for (uint32_t i = 0; i < length; ++i) {
                const uint32_t sourceIndex =
                    (recentBlockHead + kRecentBlockRingSize - length + i) % kRecentBlockRingSize;
                sequence[i] = recentBlocks[sourceIndex];
            }

            const uint64_t signature = ComputeSequenceSignature(sequence.data(), length);
            const uint32_t baseIndex = static_cast<uint32_t>(signature & (kHotPathTableSize - 1));

            for (uint32_t probe = 0; probe < kHotPathTableSize; ++probe) {
                auto& slot = hotPaths[(baseIndex + probe) & (kHotPathTableSize - 1)];
                if (slot.signature == 0 || slot.signature == signature) {
                    if (slot.signature == 0) {
                        slot.signature = signature;
                        slot.path.entryPoint = sequence[0];
                        slot.path.blockCount = length;
                    }

                    SaturatingIncrement(slot.path.totalExecutions);
                    const uint32_t loopIterations = EstimateLoopIterations(length);
                    if (loopIterations > 1) {
                        slot.path.isLoop = true;
                        slot.path.loopIterations = std::max(slot.path.loopIterations, loopIterations);
                    }
                    break;
                }
            }
        }
    }

    [[nodiscard]] bool IsStackAddress(GuestAddress addr) const noexcept {
        const GuestAddress page = PageBase(addr);
        return (page >= WinConst::kStackBase64
                && page < WinConst::kStackBase64 + static_cast<GuestAddress>(kStackSize))
            || (page >= kStackBase32 && page < kStackBase32 + static_cast<GuestAddress>(kStackSize));
    }

    [[nodiscard]] bool IsHeapAddress(GuestAddress addr) const noexcept {
        const GuestAddress page = PageBase(addr);
        return (page >= WinConst::kProcessHeapBase64
                && page < WinConst::kProcessHeapBase64 + static_cast<GuestAddress>(kHeapInitial))
            || (page >= kHeapBase32 && page < kHeapBase32 + static_cast<GuestAddress>(kHeapInitial));
    }

    void ResetState() noexcept {
        totalInstructions.store(0, std::memory_order_relaxed);
        throughput = ThroughputStats{};
        opcodeProfile = OpcodeProfile{};
        memoryProfile = MemoryProfile{};
        phaseTimings = PhaseTimings{};
        peakIPS = 0.0;
        if (blockCache) {
            for (uint32_t i = 0; i < kBlockCacheSize; ++i) {
                blockCache[i] = BlockCacheEntry{};
            }
        }
        recentBlocks.fill(0);
        recentBlockCount = 0;
        recentBlockHead = 0;
        hotPaths.fill(HotPathEntry{});
        uniquePages.Reset();
        executedPages.Reset();
        writtenExecutablePages.Reset();
        for (auto& ctx : threadContexts) {
            ctx = ThreadContext{};
        }
        tickFrequency = ReadHighResolutionFrequency();
        startTicks = ReadHighResolutionTicks();
        lastWindowTicks = startTicks;
        lastWindowInstructionCount = 0;
    }
};

PerformanceProfiler::PerformanceProfiler() noexcept {
    try {
        m_impl = std::make_unique<Impl>();
    } catch (const std::bad_alloc&) {
        m_impl.reset();
    } catch (const std::exception&) {
        m_impl.reset();
    }
}

PerformanceProfiler::~PerformanceProfiler() noexcept = default;
PerformanceProfiler::PerformanceProfiler(PerformanceProfiler&&) noexcept = default;
PerformanceProfiler& PerformanceProfiler::operator=(PerformanceProfiler&&) noexcept = default;

void PerformanceProfiler::OnInstructionStart(GuestAddress rip) noexcept {
    if (!m_impl) {
        return;
    }

    const uint64_t nowTicks = ReadHighResolutionTicks();
    std::unique_lock lock(m_impl->mutex);
    if (!m_impl->enabled) {
        return;
    }

    auto* threadCtx = m_impl->GetThreadContext();
    threadCtx->instructionActive = true;
    threadCtx->currentRip = rip;
    threadCtx->instructionStartTicks = nowTicks;
    threadCtx->lastPhaseTicks = nowTicks;
    (void)m_impl->executedPages.Insert(PageBase(rip));
}

void PerformanceProfiler::OnInstructionEnd(
    [[maybe_unused]] GuestAddress rip,
    uint8_t opcodeMap,
    uint8_t opcode) noexcept
{
    if (!m_impl) {
        return;
    }

    const uint64_t nowTicks = ReadHighResolutionTicks();
    std::unique_lock lock(m_impl->mutex);
    if (!m_impl->enabled) {
        return;
    }

    auto* threadCtx = m_impl->GetThreadContext();
    if (threadCtx->instructionActive && nowTicks > threadCtx->lastPhaseTicks) {
        const uint64_t deltaNs =
            TicksToNs(ElapsedTicks(nowTicks, threadCtx->lastPhaseTicks), m_impl->tickFrequency);
        SaturatingAdd(m_impl->phaseTimings.executionNs, deltaNs);
        SaturatingAdd(m_impl->throughput.executeTimeNs, deltaNs);
    }

    threadCtx->instructionActive = false;
    threadCtx->lastPhaseTicks = nowTicks;

    const uint64_t currentCount = SaturatingAtomicIncrement(m_impl->totalInstructions);

    switch (static_cast<OpcodeMap>(opcodeMap)) {
        case OpcodeMap::OneByte:
            SaturatingIncrement(m_impl->opcodeProfile.frequency[opcode]);
            break;
        case OpcodeMap::TwoByte:
            SaturatingIncrement(m_impl->opcodeProfile.twoByteFreq[opcode]);
            break;
        case OpcodeMap::ThreeByte38:
            SaturatingIncrement(m_impl->opcodeProfile.threeByteFreq38[opcode]);
            break;
        case OpcodeMap::ThreeByte3A:
            SaturatingIncrement(m_impl->opcodeProfile.threeByteFreq3A[opcode]);
            break;
        default:
            break;
    }

    m_impl->throughput.totalInstructions = currentCount;
    m_impl->UpdatePeakIPS(nowTicks);
}

void PerformanceProfiler::OnBlockEntry(GuestAddress blockStart) noexcept {
    if (!m_impl || blockStart == 0) {
        return;
    }

    std::unique_lock lock(m_impl->mutex);
    if (!m_impl->enabled) {
        return;
    }

    auto* threadCtx = m_impl->GetThreadContext();
    threadCtx->currentBlock = blockStart;
    (void)m_impl->executedPages.Insert(PageBase(blockStart));

    if (auto* entry = m_impl->FindBlockEntry(blockStart); entry != nullptr) {
        SaturatingIncrement(entry->block.executionCount);
        entry->block.lastExecuted = m_impl->totalInstructions.load(std::memory_order_relaxed);
        entry->block.isHot = entry->block.executionCount >= kHotBlockThreshold;
    }

    m_impl->TrackHotPath(blockStart);
}

void PerformanceProfiler::OnBlockExit(
    GuestAddress blockEnd,
    uint32_t instrCount) noexcept
{
    if (!m_impl) {
        return;
    }

    std::unique_lock lock(m_impl->mutex);
    if (!m_impl->enabled) {
        return;
    }

    auto* threadCtx = m_impl->GetThreadContext();
    if (threadCtx->currentBlock != 0) {
        if (auto* entry = m_impl->FindBlockEntry(threadCtx->currentBlock); entry != nullptr) {
            if (entry->block.byteLength == 0 && blockEnd >= threadCtx->currentBlock) {
                const uint64_t length = blockEnd - threadCtx->currentBlock;
                entry->block.byteLength = static_cast<uint32_t>(
                    std::min<uint64_t>(length, std::numeric_limits<uint32_t>::max()));
            }
            if (entry->block.instructionCount == 0 && instrCount != 0) {
                entry->block.instructionCount = instrCount;
            }
        }
    }

    threadCtx->currentBlock = 0;
}

void PerformanceProfiler::OnMemoryAccess(
    GuestAddress addr,
    uint32_t size,
    bool isWrite) noexcept
{
    if (!m_impl || size == 0) {
        return;
    }

    const uint64_t nowTicks = ReadHighResolutionTicks();
    std::unique_lock lock(m_impl->mutex);
    if (!m_impl->enabled) {
        return;
    }

    auto* threadCtx = m_impl->GetThreadContext();
    if (threadCtx->instructionActive && nowTicks > threadCtx->lastPhaseTicks) {
        const uint64_t deltaNs =
            TicksToNs(ElapsedTicks(nowTicks, threadCtx->lastPhaseTicks), m_impl->tickFrequency);
        SaturatingAdd(m_impl->phaseTimings.memoryNs, deltaNs);
        SaturatingAdd(m_impl->throughput.memoryAccessTimeNs, deltaNs);
        threadCtx->lastPhaseTicks = nowTicks;
    }

    if (isWrite) {
        SaturatingIncrement(m_impl->memoryProfile.totalWrites);
    } else {
        SaturatingIncrement(m_impl->memoryProfile.totalReads);
    }

    if (m_impl->IsStackAddress(addr)) {
        SaturatingIncrement(m_impl->memoryProfile.stackAccesses);
    }

    if (m_impl->IsHeapAddress(addr)) {
        SaturatingIncrement(m_impl->memoryProfile.heapAccesses);
    }

    const GuestAddress startPage = PageBase(addr);
    const GuestAddress endAddr =
        (std::numeric_limits<GuestAddress>::max() - addr < static_cast<GuestAddress>(size - 1))
        ? std::numeric_limits<GuestAddress>::max()
        : addr + static_cast<GuestAddress>(size - 1);
    const GuestAddress endPage = PageBase(endAddr);
    if (startPage != endPage) {
        SaturatingIncrement(m_impl->memoryProfile.crossPageAccesses);
    }

    if (m_impl->uniquePages.Insert(startPage)) {
        m_impl->memoryProfile.uniquePagesAccessed = m_impl->uniquePages.uniqueCount;
    }
    if (endPage != startPage && m_impl->uniquePages.Insert(endPage)) {
        m_impl->memoryProfile.uniquePagesAccessed = m_impl->uniquePages.uniqueCount;
    }

    if (!isWrite && m_impl->executedPages.Contains(startPage)) {
        SaturatingIncrement(m_impl->memoryProfile.codeRegionReads);
    }

    if (isWrite && m_impl->executedPages.Contains(startPage)) {
        if (m_impl->writtenExecutablePages.Insert(startPage)) {
            if (m_impl->memoryProfile.writableExecAccesses < std::numeric_limits<uint32_t>::max()) {
                ++m_impl->memoryProfile.writableExecAccesses;
            }
        }
    }
}

void PerformanceProfiler::OnAPICall(
    [[maybe_unused]] const char* funcName,
    uint64_t durationNs) noexcept
{
    if (!m_impl) {
        return;
    }

    std::unique_lock lock(m_impl->mutex);
    if (!m_impl->enabled) {
        return;
    }

    SaturatingAdd(m_impl->phaseTimings.apiDispatchNs, durationNs);
    SaturatingAdd(m_impl->throughput.apiDispatchTimeNs, durationNs);
    auto* threadCtx = m_impl->GetThreadContext();
    if (threadCtx->instructionActive) {
        threadCtx->lastPhaseTicks = ReadHighResolutionTicks();
    }
}

void PerformanceProfiler::OnDecodeComplete(uint64_t durationNs) noexcept {
    if (!m_impl) {
        return;
    }

    std::unique_lock lock(m_impl->mutex);
    if (!m_impl->enabled) {
        return;
    }

    SaturatingAdd(m_impl->phaseTimings.decodingNs, durationNs);
    SaturatingAdd(m_impl->throughput.decodeTimeNs, durationNs);

    auto* threadCtx = m_impl->GetThreadContext();
    if (threadCtx->instructionActive) {
        threadCtx->lastPhaseTicks = ReadHighResolutionTicks();
    }
}

BasicBlock* PerformanceProfiler::LookupBlock(GuestAddress address) noexcept {
    if (!m_impl || address == 0) {
        return nullptr;
    }

    const uint64_t startTicks = ReadHighResolutionTicks();
    std::unique_lock lock(m_impl->mutex);
    if (!m_impl->enabled) {
        return nullptr;
    }

    const auto elapsedTicks = ElapsedTicks(ReadHighResolutionTicks(), startTicks);
    SaturatingAdd(m_impl->phaseTimings.blockCacheLookupNs,
                  TicksToNs(elapsedTicks, m_impl->tickFrequency));

    if (auto* entry = m_impl->FindBlockEntry(address); entry != nullptr) {
        SaturatingIncrement(m_impl->phaseTimings.blockCacheHits);
        thread_local BasicBlock snapshot;
        snapshot = entry->block;
        return &snapshot;
    }

    SaturatingIncrement(m_impl->phaseTimings.blockCacheMisses);
    return nullptr;
}

void PerformanceProfiler::CacheBlock(const BasicBlock& block) noexcept {
    if (!m_impl || !m_impl->blockCache || block.startAddress == 0) {
        return;
    }

    std::unique_lock lock(m_impl->mutex);
    if (!m_impl->enabled) {
        return;
    }

    uint32_t index = static_cast<uint32_t>((block.startAddress >> 2) & kBlockCacheMask);
    for (uint32_t probe = 0; probe < kBlockCacheSize; ++probe) {
        auto& entry = m_impl->blockCache[(index + probe) & kBlockCacheMask];
        if (entry.key == 0 || entry.key == block.startAddress) {
            entry.key = block.startAddress;
            entry.block = block;
            entry.block.instructionCount = std::min(
                block.instructionCount, BasicBlock::kMaxBlockInstructions);
            entry.block.isHot = entry.block.executionCount >= kHotBlockThreshold;
            return;
        }
    }

    auto& victim = m_impl->blockCache[index];
    victim.key = block.startAddress;
    victim.block = block;
    victim.block.instructionCount = std::min(
        block.instructionCount, BasicBlock::kMaxBlockInstructions);
    victim.block.isHot = victim.block.executionCount >= kHotBlockThreshold;
}

void PerformanceProfiler::InvalidateBlock(GuestAddress address) noexcept {
    if (!m_impl || address == 0) {
        return;
    }

    std::unique_lock lock(m_impl->mutex);
    if (auto* entry = m_impl->FindBlockEntry(address); entry != nullptr) {
        m_impl->EraseBlockEntry(address);
    }
}

void PerformanceProfiler::InvalidateRange(GuestAddress start, GuestSize size) noexcept {
    if (!m_impl || !m_impl->blockCache || size == 0) {
        return;
    }

    std::unique_lock lock(m_impl->mutex);
    const GuestAddress end =
        (std::numeric_limits<GuestAddress>::max() - start < size)
        ? std::numeric_limits<GuestAddress>::max()
        : start + size;
    bool removed = true;
    while (removed) {
        removed = false;
        for (uint32_t slot = 0; slot < kBlockCacheSize; ++slot) {
            const auto& entry = m_impl->blockCache[slot];
            if (entry.key == 0) {
                continue;
            }

            const GuestAddress blockStart = entry.block.startAddress;
            const GuestAddress blockLength = entry.block.byteLength == 0
                ? 1
                : static_cast<GuestAddress>(entry.block.byteLength);
            const GuestAddress blockEnd =
                (std::numeric_limits<GuestAddress>::max() - blockStart < blockLength)
                ? std::numeric_limits<GuestAddress>::max()
                : blockStart + blockLength;
            if (blockStart < end && start < blockEnd) {
                m_impl->EraseBlockEntry(entry.block.startAddress);
                removed = true;
                break;
            }
        }
    }
}

ThroughputStats PerformanceProfiler::GetThroughput() const noexcept {
    ThroughputStats snapshot{};
    if (!m_impl) {
        return snapshot;
    }

    std::shared_lock lock(m_impl->mutex);
    snapshot = m_impl->throughput;
    snapshot.totalInstructions = m_impl->totalInstructions.load(std::memory_order_relaxed);
    snapshot.totalCycles = ElapsedTicks(ReadHighResolutionTicks(), m_impl->startTicks);

    if (snapshot.totalCycles != 0 && m_impl->tickFrequency != 0) {
        snapshot.instructionsPerSecond =
            static_cast<double>(snapshot.totalInstructions) * static_cast<double>(m_impl->tickFrequency)
            / static_cast<double>(snapshot.totalCycles);
    }

    if (snapshot.totalInstructions != 0) {
        const uint64_t totalNs = TicksToNs(snapshot.totalCycles, m_impl->tickFrequency);
        snapshot.avgNanosPerInstruction =
            static_cast<double>(totalNs) / static_cast<double>(snapshot.totalInstructions);
    }

    snapshot.peakIPS = m_impl->peakIPS;
    return snapshot;
}

OpcodeProfile PerformanceProfiler::GetOpcodeProfile() const noexcept {
    OpcodeProfile snapshot{};
    if (!m_impl) {
        return snapshot;
    }

    std::shared_lock lock(m_impl->mutex);
    snapshot = m_impl->opcodeProfile;

    std::array<std::pair<uint64_t, uint8_t>, 256> ranked{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint64_t total = snapshot.frequency[i];
        SaturatingAdd(total, snapshot.twoByteFreq[i]);
        SaturatingAdd(total, snapshot.threeByteFreq38[i]);
        SaturatingAdd(total, snapshot.threeByteFreq3A[i]);
        ranked[i] = {
            total,
            static_cast<uint8_t>(i)
        };
    }

    std::partial_sort(
        ranked.begin(),
        ranked.begin() + 16,
        ranked.end(),
        [](const auto& lhs, const auto& rhs) {
            return lhs.first > rhs.first;
        });

    for (size_t i = 0; i < 16; ++i) {
        snapshot.topOpcodes[i] = ranked[i].second;
    }

    return snapshot;
}

MemoryProfile PerformanceProfiler::GetMemoryProfile() const noexcept {
    if (!m_impl) {
        return {};
    }

    std::shared_lock lock(m_impl->mutex);
    return m_impl->memoryProfile;
}

PhaseTimings PerformanceProfiler::GetPhaseTimings() const noexcept {
    PhaseTimings snapshot{};
    if (!m_impl) {
        return snapshot;
    }

    std::shared_lock lock(m_impl->mutex);
    snapshot = m_impl->phaseTimings;
    uint64_t lookups = snapshot.blockCacheHits;
    SaturatingAdd(lookups, snapshot.blockCacheMisses);
    if (lookups != 0) {
        snapshot.cacheHitRate =
            static_cast<double>(snapshot.blockCacheHits) / static_cast<double>(lookups);
    }

    return snapshot;
}

std::vector<HotPath> PerformanceProfiler::GetHotPaths(uint32_t maxResults) const noexcept {
    std::vector<HotPath> results;
    if (!m_impl || maxResults == 0) {
        return results;
    }

    try {
        std::shared_lock lock(m_impl->mutex);
        results.reserve(std::min<uint32_t>(maxResults, Impl::kHotPathTableSize));

        const double totalInstructions =
            static_cast<double>(m_impl->totalInstructions.load(std::memory_order_relaxed));

        for (const auto& entry : m_impl->hotPaths) {
            if (entry.signature == 0 || entry.path.totalExecutions < kHotBlockThreshold) {
                continue;
            }

            HotPath path = entry.path;
            if (totalInstructions > 0.0) {
                const double estimatedInstructions =
                    static_cast<double>(path.totalExecutions) * static_cast<double>(path.blockCount);
                const double share = (estimatedInstructions / totalInstructions) * 100.0;
                path.executionShare = static_cast<float>(std::min(share, 100.0));
            }
            results.push_back(path);
        }
    } catch (const std::bad_alloc&) {
        return {};
    } catch (const std::exception&) {
        return {};
    }

    std::sort(
        results.begin(),
        results.end(),
        [](const HotPath& lhs, const HotPath& rhs) {
            if (lhs.totalExecutions != rhs.totalExecutions) {
                return lhs.totalExecutions > rhs.totalExecutions;
            }
            return lhs.executionShare > rhs.executionShare;
        });

    if (results.size() > maxResults) {
        results.resize(maxResults);
    }

    return results;
}

void PerformanceProfiler::Reset() noexcept {
    if (!m_impl) {
        return;
    }

    std::unique_lock lock(m_impl->mutex);
    m_impl->ResetState();
}

void PerformanceProfiler::SetEnabled(bool enabled) noexcept {
    if (!m_impl) {
        return;
    }

    std::unique_lock lock(m_impl->mutex);
    m_impl->enabled = enabled;
}

bool PerformanceProfiler::IsEnabled() const noexcept {
    if (!m_impl) {
        return false;
    }

    std::shared_lock lock(m_impl->mutex);
    return m_impl->enabled;
}

} // namespace Phantom
