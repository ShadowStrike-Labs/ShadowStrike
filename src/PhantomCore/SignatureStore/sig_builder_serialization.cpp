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
#include"pch.h"
#include "SignatureBuilder.hpp"

#include <array>
#include <ctime>
#include <limits>
#include <map>
#include <memory>
#include <queue>
#include <span>
#include <unordered_map>

namespace ShadowStrike {
namespace SignatureStore {

    namespace {
        // ============================================================================
        // SAFETY CONSTANTS
        // ============================================================================
        constexpr int64_t DEFAULT_PERF_FREQUENCY = 1'000'000LL;  // 1MHz fallback
        
        // Safe elapsed time calculation helper with division-by-zero AND overflow protection.
        // Uses quotient+remainder decomposition to avoid int64_t overflow when
        // diff * multiplier exceeds INT64_MAX (which happens after ~2.5 hours at 1GHz QPC).
        [[nodiscard]] inline uint64_t safeElapsedUs(
            const LARGE_INTEGER& start,
            const LARGE_INTEGER& end,
            const LARGE_INTEGER& freq) noexcept
        {
            if (freq.QuadPart <= 0) {
                return 0;
            }
            int64_t diff = end.QuadPart - start.QuadPart;
            if (diff < 0) {
                return 0;  // Timer wrapped or invalid
            }
            // Decompose to avoid overflow: (diff / freq) * 1M + ((diff % freq) * 1M) / freq
            const int64_t wholeSec = diff / freq.QuadPart;
            const int64_t remainder = diff % freq.QuadPart;
            return static_cast<uint64_t>(wholeSec) * 1'000'000ULL
                 + static_cast<uint64_t>((remainder * 1'000'000LL) / freq.QuadPart);
        }

        [[nodiscard]] inline uint64_t safeElapsedMs(
            const LARGE_INTEGER& start,
            const LARGE_INTEGER& end,
            const LARGE_INTEGER& freq) noexcept
        {
            if (freq.QuadPart <= 0) {
                return 0;
            }
            int64_t diff = end.QuadPart - start.QuadPart;
            if (diff < 0) {
                return 0;
            }
            const int64_t wholeSec = diff / freq.QuadPart;
            const int64_t remainder = diff % freq.QuadPart;
            return static_cast<uint64_t>(wholeSec) * 1'000ULL
                 + static_cast<uint64_t>((remainder * 1'000LL) / freq.QuadPart);
        }

        // ============================================================================
        // RAII GUARD FOR SERIALIZATION CLEANUP
        // ============================================================================
        class SerializationGuard {
        public:
            SerializationGuard(HANDLE& file, HANDLE& mapping, void*& base) noexcept
                : m_file(file), m_mapping(mapping), m_base(base), m_committed(false) {}
            
            ~SerializationGuard() noexcept {
                if (!m_committed) {
                    Cleanup();
                }
            }
            
            // Non-copyable, non-movable for safety
            SerializationGuard(const SerializationGuard&) = delete;
            SerializationGuard& operator=(const SerializationGuard&) = delete;
            SerializationGuard(SerializationGuard&&) = delete;
            SerializationGuard& operator=(SerializationGuard&&) = delete;
            
            void Commit() noexcept { m_committed = true; }
            
            void Cleanup() noexcept {
                if (m_base) {
                    UnmapViewOfFile(m_base);
                    m_base = nullptr;
                }
                if (m_mapping && m_mapping != INVALID_HANDLE_VALUE) {
                    CloseHandle(m_mapping);
                    m_mapping = INVALID_HANDLE_VALUE;
                }
                if (m_file && m_file != INVALID_HANDLE_VALUE) {
                    CloseHandle(m_file);
                    m_file = INVALID_HANDLE_VALUE;
                }
            }
            
        private:
            HANDLE& m_file;
            HANDLE& m_mapping;
            void*& m_base;
            bool m_committed;
        };

        // 64-bit cache-line alignment helper. Format::AlignToCacheLine returns
        // size_t which truncates on 32-bit builds; we need uint64_t for file offsets.
        [[nodiscard]] constexpr uint64_t AlignToCacheLine64(uint64_t offset) noexcept {
            constexpr uint64_t mask = CACHE_LINE_SIZE - 1;
            return (offset + mask) & ~mask;
        }

        // ============================================================================
        // CRC64 LOOKUP TABLE FOR 100x FASTER CHECKSUM COMPUTATION
        // ============================================================================
        // NOTE: This is CRC64-ECMA (reflected), matching the public CRC64_POLY constant
        // on SignatureBuilder (0x42F0E1EBA9EA3693 reflected = 0xC96C5795D7870F42).
        constexpr uint64_t CRC64_POLYNOMIAL = 0xC96C5795D7870F42ULL;
        
        constexpr std::array<uint64_t, 256> GenerateCRC64Table() noexcept {
            std::array<uint64_t, 256> table{};
            for (uint32_t i = 0; i < 256; ++i) {
                uint64_t crc = i;
                for (int j = 0; j < 8; ++j) {
                    if (crc & 1)
                        crc = (crc >> 1) ^ CRC64_POLYNOMIAL;
                    else
                        crc >>= 1;
                }
                table[i] = crc;
            }
            return table;
        }
        
        // Pre-computed at compile time
        constexpr auto CRC64_TABLE = GenerateCRC64Table();
        
        // Fast CRC64 using lookup table - O(n) single pass
        [[nodiscard]] uint64_t FastCRC64(const uint8_t* data, size_t length) noexcept {
            // Null pointer protection
            if (!data || length == 0) {
                return 0xFFFFFFFFFFFFFFFFULL;
            }
            
            uint64_t crc = 0xFFFFFFFFFFFFFFFFULL;
            for (size_t i = 0; i < length; ++i) {
                const uint8_t tableIndex = static_cast<uint8_t>(crc ^ data[i]);
                crc = CRC64_TABLE[tableIndex] ^ (crc >> 8);
            }
            return crc ^ 0xFFFFFFFFFFFFFFFFULL;
        }
    } // anonymous namespace



        StoreError SignatureBuilder::Serialize() noexcept {
            {
                std::unique_lock<std::shared_mutex> lock(m_stateMutex);
                m_currentStage = "Serialization";
            }

            LARGE_INTEGER startTime{};
            QueryPerformanceCounter(&startTime);

            // Validate performance frequency to prevent division by zero
            if (m_perfFrequency.QuadPart <= 0) {
                QueryPerformanceFrequency(&m_perfFrequency);
                if (m_perfFrequency.QuadPart <= 0) {
                    m_perfFrequency.QuadPart = DEFAULT_PERF_FREQUENCY; // Fallback
                }
            }

            // Calculate required size with overflow protection
            uint64_t requiredSize = 0;
            try {
                requiredSize = CalculateRequiredSize();
            } catch (...) {
                return StoreError{ SignatureStoreError::Unknown, 0, "Failed to calculate required size" };
            }

            if (requiredSize == 0) {
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Database size is zero" };
            }
            
            if (requiredSize > MAX_DATABASE_SIZE) {
                return StoreError{ SignatureStoreError::TooLarge, 0, "Database too large" };
            }

            // Create output file with path validation
            if (m_config.outputPath.empty()) {
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "No output path" };
            }
            
            // Validate path length (Windows MAX_PATH limit)
            if (m_config.outputPath.length() > 32767) {
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Output path too long" };
            }

            m_outputFile = CreateFileW(
                m_config.outputPath.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                nullptr,
                m_config.overwriteExisting ? CREATE_ALWAYS : CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, // Optimize for sequential write
                nullptr
            );

            if (m_outputFile == INVALID_HANDLE_VALUE) {
                const DWORD err = GetLastError();
                return StoreError{ SignatureStoreError::FileNotFound, err, "Cannot create output file" };
            }

            // RAII guard for automatic cleanup on any failure path
            SerializationGuard guard(m_outputFile, m_outputMapping, m_outputBase);

            // Set file size
            LARGE_INTEGER size{};
            size.QuadPart = static_cast<LONGLONG>(requiredSize);
            if (!SetFilePointerEx(m_outputFile, size, nullptr, FILE_BEGIN) ||
                !SetEndOfFile(m_outputFile)) {
                const DWORD err = GetLastError();
                return StoreError{ SignatureStoreError::Unknown, err, "Cannot set file size" };
            }

            // Create mapping
            m_outputMapping = CreateFileMappingW(
                m_outputFile,
                nullptr,
                PAGE_READWRITE,
                0, 0,
                nullptr
            );

            if (!m_outputMapping) {
                const DWORD err = GetLastError();
                return StoreError{ SignatureStoreError::MappingFailed, err, "Cannot create mapping" };
            }

            // Map view
            m_outputBase = MapViewOfFile(m_outputMapping, FILE_MAP_WRITE, 0, 0, static_cast<SIZE_T>(requiredSize));
            if (!m_outputBase) {
                const DWORD err = GetLastError();
                return StoreError{ SignatureStoreError::MappingFailed, err, "Cannot map view" };
            }

            m_outputSize = requiredSize;
            m_currentOffset = 0;

            // Serialize sections - any failure triggers RAII cleanup
            StoreError result = SerializeHeader();
            if (result.code != SignatureStoreError::Success) {
                return result;
            }
            
            result = SerializeHashes();
            if (result.code != SignatureStoreError::Success) {
                return result;
            }
            
            result = SerializePatterns();
            if (result.code != SignatureStoreError::Success) {
                return result;
            }
            
            result = SerializeYaraRules();
            if (result.code != SignatureStoreError::Success) {
                return result;
            }
            
            result = SerializeMetadata();
            if (result.code != SignatureStoreError::Success) {
                return result;
            }

            // Clear compiled pattern cache to release memory (cache served its purpose:
            // it is read by SerializePatterns when writing the entry array)
            m_compiledPatternCache.clear();
            m_compiledPatternCache.shrink_to_fit();

            // Back-fill header section offsets and sizes now that all sections are written.
            // The header was written with hashIndexOffset set in SerializeHeader; the
            // remaining fields are populated here with the actual offsets tracked during
            // serialization of each section.
            {
                auto* hdr = static_cast<SignatureDatabaseHeader*>(m_outputBase);
                // hashIndexOffset was already set in SerializeHeader
                hdr->hashIndexSize   = m_statistics.hashIndexSize;
                hdr->patternIndexOffset = m_sectionOffsets.patternStart;
                hdr->patternIndexSize   = m_statistics.patternIndexSize;
                hdr->yaraRulesOffset    = m_sectionOffsets.yaraStart;
                hdr->yaraRulesSize      = m_statistics.yaraRulesSize;
                hdr->metadataOffset     = m_sectionOffsets.metadataStart;
                hdr->metadataSize       = m_statistics.metadataSize;
            }

            // Compute checksum while memory mapping is still active
            result = ComputeChecksum();
            if (result.code != SignatureStoreError::Success) {
                return result;
            }

            // Flush with error checking
            if (!FlushViewOfFile(m_outputBase, static_cast<SIZE_T>(m_outputSize))) {
                Log("Warning: FlushViewOfFile failed, data may be cached");
            }
            if (!FlushFileBuffers(m_outputFile)) {
                Log("Warning: FlushFileBuffers failed");
            }

            // Commit the guard before manual cleanup
            guard.Commit();
            
            // Clean up with proper ordering and error logging
            if (!UnmapViewOfFile(m_outputBase)) {
                const DWORD err = GetLastError();
                SS_LOG_WARN(L"SignatureBuilder",
                    L"Serialize: UnmapViewOfFile failed (error: %lu)", err);
            }
            m_outputBase = nullptr;
            
            if (m_outputMapping && m_outputMapping != INVALID_HANDLE_VALUE) {
                if (!CloseHandle(m_outputMapping)) {
                    const DWORD err = GetLastError();
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"Serialize: CloseHandle(mapping) failed (error: %lu)", err);
                }
                m_outputMapping = INVALID_HANDLE_VALUE;
            }
            
            if (m_outputFile && m_outputFile != INVALID_HANDLE_VALUE) {
                if (!CloseHandle(m_outputFile)) {
                    const DWORD err = GetLastError();
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"Serialize: CloseHandle(file) failed (error: %lu)", err);
                }
                m_outputFile = INVALID_HANDLE_VALUE;
            }

            LARGE_INTEGER endTime{};
            QueryPerformanceCounter(&endTime);
            
            // Safe time calculation with division-by-zero protection
            m_statistics.serializationTimeMilliseconds = safeElapsedMs(startTime, endTime, m_perfFrequency);

            m_statistics.finalDatabaseSize = requiredSize;

            Log("Serialization complete: " + std::to_string(requiredSize) + " bytes");
            return StoreError{ SignatureStoreError::Success };
        }

        StoreError SignatureBuilder::SerializeHeader() noexcept {
            auto* header = static_cast<SignatureDatabaseHeader*>(m_outputBase);
            std::memset(header, 0, sizeof(SignatureDatabaseHeader));

            header->magic = SIGNATURE_DB_MAGIC;
            header->versionMajor = SIGNATURE_DB_VERSION_MAJOR;
            header->versionMinor = SIGNATURE_DB_VERSION_MINOR;

            // Generate UUID
            auto uuid = GenerateDatabaseUUID();
            std::memcpy(header->databaseUuid.data(), uuid.data(), 16);

            header->creationTime = GetCurrentTimestamp();
            header->lastUpdateTime = header->creationTime;
            header->buildNumber = 1;

            header->totalHashes = m_pendingHashes.size();
            header->totalPatterns = m_pendingPatterns.size();
            header->totalYaraRules = m_pendingYaraRules.size();

            // Set section offsets (page-aligned)
            m_currentOffset = Format::AlignToPage(sizeof(SignatureDatabaseHeader));
            header->hashIndexOffset = m_currentOffset;

            return StoreError{ SignatureStoreError::Success };
        }

        // ============================================================================
        // SERIALIZE HASHES IMPLEMENTATION - PRODUCTION GRADE
        // ============================================================================

        StoreError SignatureBuilder::SerializeHashes() noexcept {
            SS_LOG_INFO(L"SignatureBuilder", L"SerializeHashes: Starting hash serialization");

            LARGE_INTEGER startTime{};
            QueryPerformanceCounter(&startTime);

            // Ensure performance frequency is valid
            if (m_perfFrequency.QuadPart <= 0) {
                QueryPerformanceFrequency(&m_perfFrequency);
                if (m_perfFrequency.QuadPart <= 0) {
                    m_perfFrequency.QuadPart = DEFAULT_PERF_FREQUENCY;
                }
            }

            // ========================================================================
            // VALIDATION
            // ========================================================================
            if (m_pendingHashes.empty()) {
                SS_LOG_WARN(L"SignatureBuilder", L"SerializeHashes: No hashes to serialize");
                return StoreError{ SignatureStoreError::Success };
            }
            
            // Validate output buffer
            if (!m_outputBase || m_outputSize == 0) {
                SS_LOG_ERROR(L"SignatureBuilder", L"SerializeHashes: Invalid output buffer");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid output buffer" };
            }

            // ========================================================================
            // LAY OUT THE HASH INDEX THE WAY THE RUNTIME READS IT
            // ========================================================================
            // The previous layout could never be opened by HashStore, and the two
            // halves disagreed on structure rather than on a size or an offset.
            //
            // HashStore::InitializeBuckets partitions the hash index into
            // NUM_HASH_TYPES equal buckets - seven, MD5 through TLSH - and gives
            // each one its own B+tree:
            //
            //     bucketSize   = header->hashIndexSize / 7
            //     bucket[i] at = header->hashIndexOffset + i * bucketSize
            //
            // That is a deliberate design and a good one: a SHA-256 lookup then
            // searches only SHA-256 keys, with no type comparison per node and a
            // smaller tree to walk. This writer instead emitted ONE tree for all
            // types, and placed the hash payload at the very start of the region -
            // exactly where the reader expects bucket 0's root node. Every bucket
            // therefore failed to initialise and HashStore returned
            // "No buckets initialized", which surfaced as hashStore=FAILED even
            // though the header, magic, offsets and totalHashes were all correct.
            //
            // It also allocated one page for the whole index, while the reader
            // needs at least sizeof(BPlusTreeNode) per bucket - roughly 2 KB each
            // given ORDER 128, so about 14 KB minimum before any hash is stored.
            //
            // Fixed on the writer's side because the reader's per-type design is
            // the one the runtime is built around (HashStore keeps m_buckets keyed
            // by HashType) and is the better structure. No compatibility concern:
            // no signatures.sdb has ever existed in the field.
            //
            // Layout now, all page aligned:
            //
            //     hashIndexOffset + 0*bucketSize : bucket 0  (MD5)     leaf chain
            //     ...
            //     hashIndexOffset + 6*bucketSize : bucket 6  (TLSH)    leaf chain
            //     hashIndexOffset + 7*bucketSize : hash payload (HashValue + name)
            //
            // Payload sits after the buckets because leaf children hold absolute
            // file offsets, so the payload can live anywhere outside the region the
            // reader partitions. Buckets are written even for types with no hashes:
            // an empty leaf with keyCount 0 initialises cleanly and reports no
            // matches, whereas a missing bucket would fail the whole store.
            // ========================================================================
            constexpr uint8_t kNumHashTypes = static_cast<uint8_t>(HashType::TLSH) + 1;

            // Group by type, preserving a sorted-by-fast-hash order within each type
            // so each bucket's leaf chain is ordered the way lookups expect.
            std::array<std::vector<size_t>, kNumHashTypes> byType{};
            for (size_t i = 0; i < m_pendingHashes.size(); ++i) {
                const auto rawType = static_cast<uint8_t>(m_pendingHashes[i].hash.type);
                if (rawType >= kNumHashTypes) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"SerializeHashes: hash %zu has unsupported type %u, skipping",
                        i, static_cast<unsigned>(rawType));
                    continue;
                }
                byType[rawType].push_back(i);
            }

            for (auto& group : byType) {
                std::sort(group.begin(), group.end(),
                    [this](size_t a, size_t b) {
                        return m_pendingHashes[a].hash.FastHash() <
                               m_pendingHashes[b].hash.FastHash();
                    });
            }

            // Sizing must budget the WHOLE tree, not just its leaves.
            //
            // This previously counted leaves only, because only leaves were ever
            // written. That produced a structure the reader cannot navigate: it
            // wrote ceil(N/127) leaf nodes chained by nextLeaf with no internal
            // nodes and no root, while SignatureIndex::FindLeaf descends with
            // "while (node && !node->isLeaf)". A leaf at the section's root offset
            // ends that loop immediately, so every point lookup returned the FIRST
            // leaf regardless of the key sought, and only the first 127 entries per
            // hash type were reachable. Measured before this change with a synthetic
            // 500-hash corpus: exactly 127 of 500 found, 127 being MAX_KEYS.
            //
            // Nothing reported it because a hash lookup that finds nothing is
            // indistinguishable from a clean file. The builder now verifies its own
            // output by looking up every hash it imported, which is what turned this
            // from invisible into a build failure.
            const size_t leafCapacity  = BPlusTreeNode::MAX_KEYS;
            const size_t childCapacity = BPlusTreeNode::MAX_CHILDREN;

            // Total nodes for a tree over `leaves` leaf nodes: the leaves, plus one
            // internal level per reduction by childCapacity, until a single node
            // remains. That last node is the root. A single leaf IS the root, so it
            // needs no internal level at all.
            const auto totalNodesForLeaves = [childCapacity](size_t leaves) -> size_t {
                if (leaves <= 1) {
                    return 1;
                }
                size_t nodes = leaves;
                size_t level = leaves;
                while (level > 1) {
                    level = (level + childCapacity - 1) / childCapacity;
                    nodes += level;
                }
                return nodes;
            };

            size_t maxLeavesPerType = 1;   // at least one node, even when empty
            size_t maxNodesPerType  = 1;
            for (const auto& group : byType) {
                const size_t leaves = group.empty()
                    ? 1u
                    : (group.size() + leafCapacity - 1) / leafCapacity;
                if (leaves > maxLeavesPerType) {
                    maxLeavesPerType = leaves;
                }
                const size_t nodes = totalNodesForLeaves(leaves);
                if (nodes > maxNodesPerType) {
                    maxNodesPerType = nodes;
                }
            }
            (void)maxLeavesPerType;   // retained for the log line below

            // A uniform bucket must hold the busiest type's entire tree, because the
            // reader derives one bucketSize for all of them from
            // hashIndexSize / kNumHashTypes.
            const uint64_t bucketSize =
                Format::AlignToPage(maxNodesPerType * sizeof(BPlusTreeNode));
            const uint64_t indexRegionSize = bucketSize * kNumHashTypes;
            const uint64_t indexRegionStart = m_currentOffset;
            const uint64_t payloadStart = Format::AlignToPage(indexRegionStart + indexRegionSize);

            if (payloadStart <= indexRegionStart || payloadStart > m_outputSize) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"SerializeHashes: hash index region does not fit (start=%llu, size=%llu, output=%llu)",
                    indexRegionStart, indexRegionSize, m_outputSize);
                return StoreError{ SignatureStoreError::TooLarge, 0, "Database too small for hash index" };
            }

            // ------------------------------------------------------------------
            // Write the hash payload, recording each entry's absolute offset.
            // ------------------------------------------------------------------
            std::vector<uint64_t> hashOffsets(m_pendingHashes.size(), 0ull);
            uint64_t currentOffset = payloadStart;

            for (size_t i = 0; i < m_pendingHashes.size(); ++i) {
                const auto& hashInput = m_pendingHashes[i];

                if (currentOffset + sizeof(HashValue) > m_outputSize) {
                    SS_LOG_ERROR(L"SignatureBuilder", L"SerializeHashes: Insufficient space for hash");
                    return StoreError{ SignatureStoreError::TooLarge, 0, "Database too small" };
                }

                HashValue* hashPtr = reinterpret_cast<HashValue*>(
                    static_cast<uint8_t*>(m_outputBase) + currentOffset
                    );
                std::memcpy(hashPtr, &hashInput.hash, sizeof(HashValue));

                const uint64_t nameOffset = currentOffset + sizeof(HashValue);
                const size_t nameBytes = hashInput.name.size() + 1;   // include the terminator

                if (nameOffset + nameBytes > m_outputSize) {
                    SS_LOG_ERROR(L"SignatureBuilder", L"SerializeHashes: Insufficient space for name");
                    return StoreError{ SignatureStoreError::TooLarge, 0, "Database too small" };
                }

                char* namePtr = reinterpret_cast<char*>(
                    static_cast<uint8_t*>(m_outputBase) + nameOffset
                    );
                std::memcpy(namePtr, hashInput.name.c_str(), nameBytes);

                hashOffsets[i] = currentOffset;
                currentOffset = AlignToCacheLine64(nameOffset + nameBytes);
            }

            // ------------------------------------------------------------------
            // Write one B+Tree per hash type into its own bucket.
            //
            // Node placement inside a bucket:
            //
            //     index 0            the ROOT, always
            //     index 1 .. L       the L leaves, in ascending key order
            //     index L+1 ...      intermediate internal levels, bottom-up
            //
            // The root lives at section offset 0 because that is the one location
            // the reader can find without being told: SignatureIndex resolves its
            // root there, so no format change, no section header and no version bump
            // are needed. When a tree is a single leaf, that leaf IS the root and
            // occupies index 0 alone.
            //
            // Separator convention, which must match the reader exactly or lookups
            // silently go to the wrong subtree. SignatureIndex::FindLeaf does:
            //
            //     pos = lower_bound(keys, keyCount, target)
            //     if (pos < keyCount && target >= keys[pos]) pos++
            //     next = children[pos]
            //
            // so children[j] covers [keys[j-1], keys[j]) and a key equal to keys[j]
            // descends right into children[j+1]. Therefore keys[j] must be the
            // MINIMUM key present in the subtree under children[j+1] - the separator
            // is the first key of the right child, not the last key of the left.
            // ------------------------------------------------------------------
            size_t totalIndexed = 0;

            // One entry per node written at the level currently being reduced.
            struct LevelNode {
                uint64_t offset;   // absolute file offset of the node
                uint64_t minKey;   // smallest key anywhere beneath it
            };
            std::vector<LevelNode> level;
            std::vector<LevelNode> nextLevel;

            for (uint8_t t = 0; t < kNumHashTypes; ++t) {
                const uint64_t bucketOffset = indexRegionStart + (static_cast<uint64_t>(t) * bucketSize);
                const auto& group = byType[t];

                const size_t leaves = group.empty()
                    ? 1u
                    : (group.size() + leafCapacity - 1) / leafCapacity;
                const size_t nodesNeeded = totalNodesForLeaves(leaves);

                if (nodesNeeded * sizeof(BPlusTreeNode) > bucketSize ||
                    bucketOffset + (nodesNeeded * sizeof(BPlusTreeNode)) > m_outputSize) {
                    SS_LOG_ERROR(L"SignatureBuilder",
                        L"SerializeHashes: bucket %u exceeds its space (offset=%llu, nodes=%zu, bucketSize=%llu)",
                        static_cast<unsigned>(t), bucketOffset, nodesNeeded, bucketSize);
                    return StoreError{ SignatureStoreError::TooLarge, 0, "Database too small for hash index" };
                }

                const auto nodeAt = [this, bucketOffset](size_t index) -> BPlusTreeNode* {
                    return reinterpret_cast<BPlusTreeNode*>(
                        static_cast<uint8_t*>(m_outputBase) + bucketOffset +
                        (static_cast<uint64_t>(index) * sizeof(BPlusTreeNode)));
                };

                // Node offsets stored INSIDE nodes are SECTION-RELATIVE, not absolute
                // file offsets. SignatureIndex sets m_baseAddress to
                // view.baseAddress + indexOffset and GetNode requires
                // nodeOffset < m_indexSize, where m_indexSize is this bucket's size,
                // then addresses the node as m_baseAddress + nodeOffset.
                //
                // Writing absolute offsets here is precisely how the first attempt at
                // this fix failed: every internal child offset exceeded m_indexSize,
                // GetNode refused it, FindLeaf returned null and lookups went from
                // 127-of-500 to 0-of-500. Single-leaf trees still worked, which is
                // the tell - they never descend.
                //
                // Note the deliberate asymmetry: a LEAF's children[] hold ABSOLUTE
                // file offsets to hash payload records, because leaves are terminal
                // and those values are returned to the caller rather than followed as
                // nodes. Only internal children, prevLeaf, nextLeaf and parentOffset
                // are section-relative node offsets.
                const auto offsetAt = [](size_t index) -> uint64_t {
                    return static_cast<uint64_t>(index) * sizeof(BPlusTreeNode);
                };

                // --------------------------------------------------------------
                // Leaf level. A single leaf is the root and goes to index 0;
                // otherwise leaves occupy 1..L and index 0 is reserved for the root.
                // --------------------------------------------------------------
                const size_t firstLeafIndex = (leaves == 1) ? 0u : 1u;

                level.clear();
                level.reserve(leaves);

                size_t entryIdx = 0;
                for (size_t leafIdx = 0; leafIdx < leaves; ++leafIdx) {
                    const size_t   slot       = firstLeafIndex + leafIdx;
                    const uint64_t leafOffset = offsetAt(slot);
                    BPlusTreeNode* leaf       = nodeAt(slot);

                    std::memset(leaf, 0, sizeof(BPlusTreeNode));
                    leaf->isLeaf = true;

                    const uint32_t keysInLeaf = group.empty()
                        ? 0u
                        : static_cast<uint32_t>(std::min(leafCapacity, group.size() - entryIdx));
                    leaf->keyCount = keysInLeaf;

                    for (uint32_t k = 0; k < keysInLeaf; ++k) {
                        const size_t src = group[entryIdx + k];
                        leaf->keys[k]     = m_pendingHashes[src].hash.FastHash();
                        leaf->children[k] = hashOffsets[src];
                    }

                    // Sequential-scan chain. Still maintained: ForEach and range
                    // queries walk it, and it is how a full enumeration reaches
                    // every entry independently of the descent path.
                    leaf->prevLeaf = (leafIdx > 0) ? offsetAt(slot - 1) : 0ull;
                    leaf->nextLeaf = (leafIdx + 1 < leaves) ? offsetAt(slot + 1) : 0ull;

                    level.push_back(LevelNode{
                        leafOffset,
                        (keysInLeaf > 0) ? leaf->keys[0] : 0ull
                    });

                    entryIdx     += keysInLeaf;
                    totalIndexed += keysInLeaf;
                }

                // --------------------------------------------------------------
                // Internal levels, built bottom-up until one node remains. That
                // final node is the root and is written to index 0.
                // --------------------------------------------------------------
                size_t nextFreeSlot = (leaves == 1) ? 1u : (1u + leaves);

                while (level.size() > 1) {
                    const size_t parentCount =
                        (level.size() + childCapacity - 1) / childCapacity;

                    nextLevel.clear();
                    nextLevel.reserve(parentCount);

                    for (size_t p = 0; p < parentCount; ++p) {
                        const size_t firstChild = p * childCapacity;
                        const size_t childCount =
                            std::min(childCapacity, level.size() - firstChild);

                        // The single node of the topmost level is the root.
                        const bool isRoot = (parentCount == 1);
                        const size_t slot = isRoot ? 0u : nextFreeSlot++;

                        if (!isRoot && slot * sizeof(BPlusTreeNode) >= bucketSize) {
                            SS_LOG_ERROR(L"SignatureBuilder",
                                L"SerializeHashes: bucket %u internal node slot %zu exceeds bucket size %llu",
                                static_cast<unsigned>(t), slot, bucketSize);
                            return StoreError{ SignatureStoreError::TooLarge, 0,
                                "Database too small for hash index internal nodes" };
                        }

                        BPlusTreeNode* parent = nodeAt(slot);
                        std::memset(parent, 0, sizeof(BPlusTreeNode));
                        parent->isLeaf   = false;
                        parent->keyCount = static_cast<uint32_t>(childCount - 1);

                        for (size_t c = 0; c < childCount; ++c) {
                            parent->children[c] = level[firstChild + c].offset;
                            if (c > 0) {
                                // Separator is the first key of the right child.
                                parent->keys[c - 1] = level[firstChild + c].minKey;
                            }
                        }

                        nextLevel.push_back(LevelNode{
                            offsetAt(slot),
                            level[firstChild].minKey
                        });
                    }

                    level.swap(nextLevel);
                }

                // Record each child's parent so maintenance paths that walk upward
                // have a truthful pointer rather than an implied zero. Offsets here
                // are section-relative, matching the children[] they mirror.
                if (leaves > 1) {
                    const auto linkChildren = [&](size_t parentSlot) {
                        BPlusTreeNode* node = nodeAt(parentSlot);
                        if (node->isLeaf) {
                            return;
                        }
                        const uint32_t childTotal = node->keyCount + 1u;
                        for (uint32_t c = 0; c < childTotal && c < BPlusTreeNode::MAX_CHILDREN; ++c) {
                            const uint64_t childOffset = node->children[c];
                            if (childOffset % sizeof(BPlusTreeNode) != 0 ||
                                childOffset + sizeof(BPlusTreeNode) > bucketSize) {
                                continue;
                            }
                            const size_t childSlot =
                                static_cast<size_t>(childOffset / sizeof(BPlusTreeNode));
                            nodeAt(childSlot)->parentOffset = offsetAt(parentSlot);
                        }
                    };

                    linkChildren(0);                                  // the root
                    for (size_t slot = 1; slot < nextFreeSlot; ++slot) {
                        linkChildren(slot);                           // intermediate levels
                    }
                }
            }

            // The reader computes bucketSize as hashIndexSize / kNumHashTypes, so
            // this must be an exact multiple or every bucket lands misaligned.
            m_statistics.hashIndexSize = indexRegionSize;
            m_statistics.optimizedSignatures += m_pendingHashes.size();

            SS_LOG_INFO(L"SignatureBuilder",
                L"SerializeHashes: %zu hash(es) indexed across %u type buckets "
                L"(bucketSize=%llu, indexSize=%llu)",
                totalIndexed, static_cast<unsigned>(kNumHashTypes), bucketSize, indexRegionSize);

            // ========================================================================
            // PERFORMANCE METRICS
            // ========================================================================
            LARGE_INTEGER endTime{};
            QueryPerformanceCounter(&endTime);

            // Safe time calculation with division-by-zero protection
            uint64_t serializeTimeUs = safeElapsedUs(startTime, endTime, m_perfFrequency);

            m_statistics.serializationTimeMilliseconds += serializeTimeUs / 1000;

            m_currentOffset = currentOffset;

            SS_LOG_INFO(L"SignatureBuilder",
                L"SerializeHashes: Complete - %zu hashes, %llu bytes, %llu us",
                m_pendingHashes.size(), m_statistics.hashIndexSize, serializeTimeUs);

            ReportProgress("SerializeHashes", m_pendingHashes.size(), m_pendingHashes.size());

            return StoreError{ SignatureStoreError::Success };
        }

        // ============================================================================
        // SERIALIZE PATTERNS IMPLEMENTATION - PRODUCTION GRADE WITH AHO-CORASICK
        // ============================================================================

        StoreError SignatureBuilder::SerializePatterns() noexcept {
            SS_LOG_INFO(L"SignatureBuilder", L"SerializePatterns: Starting pattern serialization with Aho-Corasick optimization");

            LARGE_INTEGER startTime{};
            QueryPerformanceCounter(&startTime);

            // Ensure performance frequency is valid
            if (m_perfFrequency.QuadPart <= 0) {
                QueryPerformanceFrequency(&m_perfFrequency);
                if (m_perfFrequency.QuadPart <= 0) {
                    m_perfFrequency.QuadPart = DEFAULT_PERF_FREQUENCY;
                }
            }

            // ========================================================================
            // STEP 1: VALIDATION
            // ========================================================================
            if (m_pendingPatterns.empty()) {
                SS_LOG_WARN(L"SignatureBuilder", L"SerializePatterns: No patterns to serialize");
                m_statistics.patternIndexSize = 0;
                return StoreError{ SignatureStoreError::Success };
            }
            
            // Validate output buffer
            if (!m_outputBase || m_outputSize == 0) {
                SS_LOG_ERROR(L"SignatureBuilder", L"SerializePatterns: Invalid output buffer");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid output buffer" };
            }

            SS_LOG_INFO(L"SignatureBuilder",
                L"SerializePatterns: Processing %zu patterns", m_pendingPatterns.size());

            // NOTE: the pattern section start is NOT recorded here. It is
            // recorded at the trie offset below, once alignment is applied.
            // Recording m_currentOffset at this point published a section start
            // that was (a) not page aligned, because it is wherever the hash
            // payload pool happened to end, and (b) inconsistent with
            // patternIndexSize, which is measured from the ALIGNED trie offset.
            // ValidateHeader::checkPageAlignment then rejected the whole database
            // on open, so every store failed and the product reported "No
            // components could be initialized" - for a database that had just
            // been written and checksummed successfully.

            // ========================================================================
            // STEP 2: PRE-COMPILE ALL PATTERNS (SINGLE PASS - MAJOR OPTIMIZATION)
            // ========================================================================
            // FIX: Previously patterns were compiled 3 times (automaton, entropy, serialize)
            // Now we compile once and cache the results in m_compiledPatternCache for 
            // reuse when the entry array is written below.

            m_compiledPatternCache.clear();
            m_compiledPatternCache.reserve(m_pendingPatterns.size());

            for (size_t patternIdx = 0; patternIdx < m_pendingPatterns.size(); ++patternIdx) {
                const auto& pattern = m_pendingPatterns[patternIdx];

                CompiledPatternCacheEntry cache{};
                cache.valid = false;

                auto compiledPattern = PatternStore::PatternCompiler::CompilePattern(
                    pattern.patternString, cache.mode, cache.mask
                );
                
                if (compiledPattern.has_value()) {
                    cache.bytes = std::move(*compiledPattern);
                    cache.entropy = PatternStore::PatternCompiler::ComputeEntropy(cache.bytes);
                    cache.valid = true;
                } else {
                    // A pattern that does not compile is skipped by every write site
                    // below (cache.valid gates them all), so it is ABSENT from the
                    // finished database - not truncated, not degraded, absent. The author
                    // asked for a signature and the build will not contain one.
                    //
                    // This is an ERROR, not a warning: it is silent coverage loss, and
                    // the surrounding build still succeeds by design (one bad pattern in
                    // a 10,000-entry feed must not zero out the other 9,999). The count
                    // is what callers act on - phantom-sigbuild treats any non-zero
                    // invalidSignaturesSkipped as a failed content build, because shipped
                    // content is authored and every pattern in it is meant to be there.
                    SS_LOG_ERROR(L"SignatureBuilder",
                        L"SerializePatterns: pattern %zu ('%S') failed to compile and will "
                        L"be ABSENT from the database; it passed input validation, so this "
                        L"is a disagreement between ValidatePattern and CompilePattern",
                        patternIdx, pattern.name.c_str());
                    m_statistics.invalidSignaturesSkipped++;
                }
                
                m_compiledPatternCache.push_back(std::move(cache));
            }
            
            SS_LOG_DEBUG(L"SignatureBuilder", 
                L"SerializePatterns: Pre-compiled %zu patterns (cached)", m_compiledPatternCache.size());

            // ========================================================================
            // STEP 3: BUILD AHO-CORASICK AUTOMATON USING CACHED COMPILED PATTERNS
            // ========================================================================
            PatternStore::AhoCorasickAutomaton automaton;

            for (size_t patternIdx = 0; patternIdx < m_compiledPatternCache.size(); ++patternIdx) {
                const auto& cache = m_compiledPatternCache[patternIdx];
                if (!cache.valid) continue;

                if (!automaton.AddPattern(cache.bytes, static_cast<uint64_t>(patternIdx))) {
                    // Narrower consequence than a compile failure, and worth stating
                    // precisely: the pattern IS still written to the PatternEntry array,
                    // and PatternStore rebuilds its own automaton from those entries at
                    // load, so this does not by itself remove the pattern from the product.
                    // What it means is that the builder's automaton - and therefore the
                    // serialized trie - does not contain it. With one governing length
                    // limit and a static_assert on the matcher's ceiling, the remaining
                    // reachable cause is the aggregate MAX_TOTAL_NODES cap, which is a real
                    // limit on how much pattern content one database can hold.
                    SS_LOG_ERROR(L"SignatureBuilder",
                        L"SerializePatterns: pattern '%S' (%zu bytes) was refused by the "
                        L"automaton; it remains in the entry array but is absent from the "
                        L"serialized trie. Check the aggregate node ceiling.",
                        m_pendingPatterns[patternIdx].name.c_str(), cache.bytes.size());
                    m_statistics.invalidSignaturesSkipped++;
                }
            }

            if (!automaton.Compile()) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"SerializePatterns: Failed to compile Aho-Corasick automaton");
                return StoreError{ SignatureStoreError::Unknown, 0, "Automaton compilation failed" };
            }

            SS_LOG_INFO(L"SignatureBuilder",
                L"SerializePatterns: Aho-Corasick automaton compiled - %zu nodes, %zu patterns",
                automaton.GetNodeCount(), automaton.GetPatternCount());

            // ========================================================================
            // STEP 4: SORT PATTERNS BY ENTROPY USING CACHED VALUES
            // ========================================================================
            std::vector<std::pair<size_t, float>> patternsByEntropy;
            patternsByEntropy.reserve(m_pendingPatterns.size());

            for (size_t patternIdx = 0; patternIdx < m_compiledPatternCache.size(); ++patternIdx) {
                const auto& cache = m_compiledPatternCache[patternIdx];
                if (cache.valid) {
                    patternsByEntropy.emplace_back(patternIdx, cache.entropy);
                }
            }

            std::sort(patternsByEntropy.begin(), patternsByEntropy.end(),
                [](const auto& a, const auto& b) {
                    return a.second > b.second;
                });

            SS_LOG_DEBUG(L"SignatureBuilder", L"SerializePatterns: Optimized pattern order by entropy");

            // ========================================================================
            // STEP 5: SERIALIZE THE AHO-CORASICK TRIE
            // ========================================================================
            // The trie is written FIRST and the pattern entries follow it, so that
            // patternIndexOffset..+patternIndexSize describes the WHOLE pattern area.
            //
            // It used to be the other way round, and that was a format defect rather
            // than a style choice: the entries were written at whatever offset the
            // hash section happened to end on, then patternIndexOffset was set to the
            // page-aligned trie that came after them. Every PatternEntry therefore sat
            // BELOW the declared start of the section, in a gap no header field
            // described - unvalidated, unbounded, and impossible for a reader to find.
            // That is the direct reason the runtime could never load patterns.
            //
            // The trie header must be at the section start because that is the one
            // address PatternIndex::Initialize can resolve without being told, exactly
            // as the hash B+tree root must sit at bucket offset 0.
            uint64_t trieOffset = Format::AlignToPage(m_currentOffset);

            // Record the section start at the aligned offset where the section data
            // actually begins. This is also the base patternIndexSize is measured
            // from below, so offset and size describe the same span.
            m_sectionOffsets.patternStart = trieOffset;

            uint64_t currentOffset = trieOffset;

            StoreError trieErr = SerializeAhoCorasickToDisk(currentOffset);
            if (!trieErr.IsSuccess()) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"SerializePatterns: Failed to serialize trie: %S", trieErr.message.c_str());
                return trieErr;
            }

            // SerializeAhoCorasickToDisk re-aligns the offset it is given before
            // placing the header. We passed an already page-aligned value so the
            // header must be exactly at trieOffset - but verify it rather than assume,
            // because everything below writes through a pointer to that header and a
            // wrong assumption here would corrupt the section silently.
            auto* trieHeader = reinterpret_cast<TrieIndexHeader*>(
                static_cast<uint8_t*>(m_outputBase) + trieOffset
                );
            if (trieHeader->magic != TRIE_INDEX_MAGIC) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"SerializePatterns: trie header is not at the section start "
                    L"(offset 0x%llX holds magic 0x%08X, expected 0x%08X)",
                    trieOffset, trieHeader->magic, TRIE_INDEX_MAGIC);
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                                  "Trie header not at section start" };
            }

            // ========================================================================
            // STEP 6: WRITE PATTERN ENTRIES USING CACHED COMPILED PATTERNS
            // ========================================================================
            // PatternEntry is alignas(8); the records must start aligned because the
            // runtime indexes them as an array of PatternEntry.
            currentOffset = AlignToCacheLine64(currentOffset);
            const uint64_t entryRegionStart = currentOffset;

            // The entries are a TRUE ARRAY: patternEntryOffset and patternEntryCount in
            // the section header describe exactly `count` fixed-size PatternEntry
            // records starting at that offset, so a reader can index them directly.
            //
            // The variable-length blobs - name, compiled pattern bytes, optional mask -
            // follow the array in their own region. They used to be INTERLEAVED with the
            // entries as [entry][name][data][mask][pad][entry]..., which made the stride
            // variable and an "array of N" promise impossible to keep: nothing records a
            // name length, so a reader could only step from one entry to the next by
            // re-deriving the writer's exact arithmetic including its alignment rule.
            // Publishing a count and an offset for a layout that cannot be indexed would
            // have been the same class of defect as the offsets this change repairs.
            const size_t entryCount = patternsByEntropy.size();

            if (entryCount != 0 &&
                entryCount > (m_outputSize - entryRegionStart) / sizeof(PatternEntry)) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"SerializePatterns: %zu pattern entries do not fit at offset 0x%llX "
                    L"in a %llu byte database",
                    entryCount, entryRegionStart, m_outputSize);
                return StoreError{ SignatureStoreError::TooLarge, 0, "Database too small" };
            }

            const uint64_t entryArrayBytes =
                static_cast<uint64_t>(entryCount) * sizeof(PatternEntry);

            // Blobs begin after the FULL array reservation, so the array stays dense and
            // indexable even if an individual pattern is rejected below.
            uint64_t blobOffset = entryRegionStart + entryArrayBytes;

            size_t processedPatterns = 0;

            // Build-time diagnostics, accumulated in the loop below rather than in a
            // second pass. These used to be computed only to be stored in an
            // unreadable metadata block; they are worth reporting, so they are
            // reported.
            float entropySum = 0.0f;
            uint32_t minPatternLen = UINT32_MAX;
            uint32_t maxPatternLen = 0;

            for (const auto& [origIdx, entropy] : patternsByEntropy) {
                const auto& pattern = m_pendingPatterns[origIdx];
                const auto& cache = m_compiledPatternCache[origIdx];
                
                // Skip invalid patterns (already filtered but double-check)
                if (!cache.valid) continue;

                PatternEntry* entryPtr = reinterpret_cast<PatternEntry*>(
                    static_cast<uint8_t*>(m_outputBase) + entryRegionStart
                    + processedPatterns * sizeof(PatternEntry)
                    );

                // The name is stored NUL-TERMINATED, because a terminator is the only
                // thing a reader can use to find its end: no name length is recorded
                // anywhere in this format. The terminator is written EXPLICITLY, as its
                // own byte, and the blob cursor advances past it.
                //
                // This block used to read:
                //     std::string nameStr = pattern.name + "\0";
                //     std::memcpy(namePtr, nameStr.c_str(), nameStr.length());
                //     blobOffset += nameStr.length();
                // which appends NOTHING. operator+(std::string, const char*) copies the
                // literal up to its first NUL, and the first character of "\0" IS that
                // NUL - so nameStr was exactly pattern.name, one byte shorter than the
                // code appears to say, and no terminator ever reached the file. The
                // intent was stated in the source and absent from the output.
                //
                // What it cost, measured: the name ran straight into the pattern bytes
                // written immediately after it, PatternStore's loader scanned for a
                // terminator bounded by the section end, found none, and substituted a
                // generated placeholder. A pattern named TestPattern was reported by a
                // real scan as "UnnamedPattern_0" - so a pattern detection named a
                // placeholder instead of the signature, in the log, in the threat
                // callback, and in whatever the user is shown. The previous verification
                // could not see it because it only asked whether ANY pattern matched.
                const uint64_t nameOffset = blobOffset;
                const uint64_t nameBytesWithNul =
                    static_cast<uint64_t>(pattern.name.length()) + 1u;

                if (nameOffset + nameBytesWithNul > m_outputSize) {
                    SS_LOG_ERROR(L"SignatureBuilder",
                        L"SerializePatterns: Insufficient space for name at pattern %zu",
                        processedPatterns);
                    return StoreError{ SignatureStoreError::TooLarge, 0, "Database too small" };
                }

                char* namePtr = reinterpret_cast<char*>(
                    static_cast<uint8_t*>(m_outputBase) + nameOffset
                    );
                if (!pattern.name.empty()) {
                    std::memcpy(namePtr, pattern.name.data(), pattern.name.length());
                }
                namePtr[pattern.name.length()] = '\0';
                blobOffset += nameBytesWithNul;

                // FIX: Use cached compiled pattern instead of re-compiling (3rd time!)
                // This was the major performance bottleneck
                uint64_t dataOffset = blobOffset;
                size_t patternLen = cache.bytes.size();

                if (dataOffset + patternLen > m_outputSize) {
                    SS_LOG_ERROR(L"SignatureBuilder",
                        L"SerializePatterns: Insufficient space for pattern data at pattern %zu",
                        processedPatterns);
                    return StoreError{ SignatureStoreError::TooLarge, 0, "Database too small" };
                }

                uint8_t* dataPtrDest = static_cast<uint8_t*>(m_outputBase) + dataOffset;
                if (patternLen > 0 && !cache.bytes.empty()) {
                    std::memcpy(dataPtrDest, cache.bytes.data(), patternLen);
                } else if (patternLen > 0) {
                    SS_LOG_ERROR(L"SignatureBuilder",
                        L"SerializePatterns: Pattern data empty but length=%zu at pattern %zu",
                        patternLen, processedPatterns);
                    return StoreError{ SignatureStoreError::InvalidSignature, 0,
                                      "Inconsistent pattern data" };
                }
                blobOffset += patternLen;

                // Write pattern mask (for wildcard patterns) - use cached mask.
                //
                // The mask is placed immediately after the pattern data and its
                // presence is recorded in the entry's flags. PatternEntry has no
                // maskOffset field, so before the flag existed these bytes were
                // written to disk at a location NOTHING could recover: the mask was
                // present, occupied space, and was lost on every read-back. A pattern
                // whose meaning depends on its mask would then have matched literally
                // at the wildcard positions.
                bool maskWritten = false;
                if (!cache.mask.empty() && cache.mask.size() == cache.bytes.size()) {
                    if (blobOffset + cache.mask.size() > m_outputSize) {
                        SS_LOG_ERROR(L"SignatureBuilder",
                            L"SerializePatterns: Insufficient space for mask at pattern %zu",
                            processedPatterns);
                        return StoreError{ SignatureStoreError::TooLarge, 0, "Database too small" };
                    }

                    uint8_t* maskPtr = static_cast<uint8_t*>(m_outputBase) + blobOffset;
                    std::memcpy(maskPtr, cache.mask.data(), cache.mask.size());
                    blobOffset += cache.mask.size();
                    maskWritten = true;
                }

                // Fill pattern entry structure - use cached values
                entryPtr->mode = cache.mode;
                entryPtr->reserved[0] = 0;
                entryPtr->reserved[1] = 0;
                entryPtr->reserved[2] = 0;
                entryPtr->patternLength = static_cast<uint32_t>(patternLen);

                // Validate offsets fit in uint32_t before truncation to prevent
                // silent data corruption on databases > 4GB
                if (nameOffset > UINT32_MAX || dataOffset > UINT32_MAX) {
                    SS_LOG_ERROR(L"SignatureBuilder",
                        L"SerializePatterns: Pattern offset exceeds uint32_t capacity at pattern %zu "
                        L"(nameOffset: %llu, dataOffset: %llu)",
                        processedPatterns, nameOffset, dataOffset);
                    return StoreError{ SignatureStoreError::TooLarge, 0,
                                      "Pattern offset exceeds 4GB limit" };
                }
                entryPtr->nameOffset = static_cast<uint32_t>(nameOffset);
                entryPtr->dataOffset = static_cast<uint32_t>(dataOffset);
                entryPtr->threatLevel = static_cast<uint32_t>(pattern.threatLevel);
                entryPtr->signatureId = std::hash<std::string>{}(pattern.name);
                entryPtr->flags = maskWritten ? PatternEntryFlags::MaskFollowsData : 0ull;
                entryPtr->entropy = entropy;
                entryPtr->hitCount = 0;
                // GetCurrentTimestamp returns ms; convert to seconds to fit uint32_t
                // and remain consistent with Unix epoch convention used in the header.
                entryPtr->lastUpdateTime = static_cast<uint32_t>(GetCurrentTimestamp() / 1000);

                entropySum += entropy;
                minPatternLen = (std::min)(minPatternLen, entryPtr->patternLength);
                maxPatternLen = (std::max)(maxPatternLen, entryPtr->patternLength);

                processedPatterns++;

                if (processedPatterns % 100 == 0) {
                    ReportProgress("SerializePatterns", processedPatterns, m_pendingPatterns.size());
                }
            }

            // The section runs to the end of the blob region: array first, blobs after.
            currentOffset = blobOffset;

            // ========================================================================
            // STEP 7: PUBLISH WHERE THE PATTERNS ARE
            // ========================================================================
            // Without this the entries are unreachable. patternIndexOffset names the
            // trie header, so the entry region needs its own coordinates, and they go
            // in the trie header because that is the only structure in the section a
            // reader can find. SECTION-RELATIVE, the same rule as every other offset
            // stored inside a section.
            trieHeader->patternEntryOffset = entryRegionStart - trieOffset;
            trieHeader->patternEntryCount = processedPatterns;

            // patternIndexSize now spans the trie AND the entries, so the section
            // bounds cover every byte the section owns. Previously it stopped at the
            // end of the trie while more data followed, and a fixed 1 KB metadata
            // block was written past it that no reader could interpret - its struct
            // was declared local to this function.
            m_statistics.patternIndexSize = currentOffset - trieOffset;
            m_statistics.optimizedSignatures += processedPatterns;

            // Re-checksum: SerializeAhoCorasickToDisk computed the CRC over the trie
            // only, because the entries did not exist yet. Extend it over the whole
            // section so the recorded value means what the field says it means.
            // Corruption detection only - anything able to write the file can
            // recompute it, so it is not an authenticity check.
            {
                const uint64_t sectionSize = currentOffset - trieOffset;
                if (sectionSize < sizeof(TrieIndexHeader)) {
                    SS_LOG_ERROR(L"SignatureBuilder",
                        L"SerializePatterns: pattern section smaller than its own header");
                    return StoreError{ SignatureStoreError::InvalidFormat, 0,
                                      "Pattern section smaller than header" };
                }
                const uint8_t* checksummed = static_cast<const uint8_t*>(m_outputBase)
                    + trieOffset + sizeof(TrieIndexHeader);
                const size_t checksummedLen =
                    static_cast<size_t>(sectionSize - sizeof(TrieIndexHeader));
                trieHeader->checksumCRC64 = (checksummedLen > 0)
                    ? ComputeCRC64(checksummed, checksummedLen)
                    : 0;
            }

            SS_LOG_INFO(L"SignatureBuilder",
                L"SerializePatterns: section 0x%llX..0x%llX (%llu bytes) - trie plus %zu "
                L"pattern entrie(s) at section offset 0x%llX",
                trieOffset, currentOffset, m_statistics.patternIndexSize,
                processedPatterns, trieHeader->patternEntryOffset);

            // The pattern section ends here. It used to be followed by a
            // PatternIndexMetadata block holding totalPatterns, node count, average
            // entropy and a pattern length range - written past the declared section
            // size, into a struct DECLARED LOCAL TO THIS FUNCTION, so no reader could
            // name the type let alone find the bytes. It was removed rather than
            // relocated: totalNodes and totalPatterns already live in the trie header,
            // and the remaining three values had no consumer anywhere. Recording
            // statistics somewhere unreadable is not observability.
            currentOffset = Format::AlignToPage(currentOffset);

            // ========================================================================
            // STEP 8: PERFORMANCE METRICS & LOGGING
            // ========================================================================
            LARGE_INTEGER endTime{};
            QueryPerformanceCounter(&endTime);

            // Safe time calculation with division-by-zero protection
            uint64_t serializeTimeUs = safeElapsedUs(startTime, endTime, m_perfFrequency);

            m_statistics.serializationTimeMilliseconds += serializeTimeUs / 1000;
            m_currentOffset = currentOffset;

            SS_LOG_INFO(L"SignatureBuilder",
                L"SerializePatterns: Complete");
            SS_LOG_INFO(L"SignatureBuilder",
                L"  Patterns serialized: %zu/%zu", processedPatterns, m_pendingPatterns.size());
            SS_LOG_INFO(L"SignatureBuilder",
                L"  Index size: %llu bytes", m_statistics.patternIndexSize);
            SS_LOG_INFO(L"SignatureBuilder",
                L"  Automaton nodes: %zu", automaton.GetNodeCount());
            SS_LOG_INFO(L"SignatureBuilder",
                L"  Average entropy: %.2f",
                (processedPatterns > 0) ? (entropySum / static_cast<float>(processedPatterns)) : 0.0f);
            SS_LOG_INFO(L"SignatureBuilder",
                L"  Pattern length range: [%u, %u]",
                (minPatternLen == UINT32_MAX) ? 0u : minPatternLen, maxPatternLen);
            SS_LOG_INFO(L"SignatureBuilder",
                L"  Serialization time: %llu us (%.2f ms)",
                serializeTimeUs, serializeTimeUs / 1000.0);

            ReportProgress("SerializePatterns", processedPatterns, m_pendingPatterns.size());

            return StoreError{ SignatureStoreError::Success };
        }

        // Use fast CRC64 with lookup table (100x faster)
        uint64_t SignatureBuilder::ComputeCRC64(const uint8_t* data, size_t length) {
            return FastCRC64(data, length);
        }

        // ============================================================================
        // SERIALIZE AHO-CORASICK AUTOMATON TO DISK TRIE FORMAT
        // ============================================================================

        StoreError SignatureBuilder::SerializeAhoCorasickToDisk(
            uint64_t& currentOffset
        ) noexcept {
            SS_LOG_INFO(L"SignatureBuilder",
                L"SerializeAhoCorasickToDisk: Starting trie serialization at offset 0x%llX",
                currentOffset);

            LARGE_INTEGER startTime{};
            QueryPerformanceCounter(&startTime);

            // Ensure performance frequency is valid
            if (m_perfFrequency.QuadPart <= 0) {
                QueryPerformanceFrequency(&m_perfFrequency);
                if (m_perfFrequency.QuadPart <= 0) {
                    m_perfFrequency.QuadPart = DEFAULT_PERF_FREQUENCY;
                }
            }

            // ========================================================================
            // STEP 1: VALIDATION
            // ========================================================================
            if (!m_outputBase || m_outputSize == 0) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"SerializeAhoCorasickToDisk: Invalid output buffer");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid output buffer" };
            }
            
            // Validate offset doesn't exceed output size
            if (currentOffset >= m_outputSize) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"SerializeAhoCorasickToDisk: Offset exceeds output size");
                return StoreError{ SignatureStoreError::TooLarge, 0, "Offset out of bounds" };
            }

            // ========================================================================
            // STEP 2: WRITE THE SECTION HEADER
            // ========================================================================
            //
            // THIS SECTION NO LONGER CARRIES A SERIALIZED AUTOMATON, AND THAT IS A
            // DELIBERATE REMOVAL RATHER THAN MISSING WORK.
            //
            // What used to be here: an in-memory trie was rebuilt from the compiled
            // patterns, Aho-Corasick failure links were computed over it, disk offsets
            // were assigned to every node in BFS order, every node was written out as a
            // TrieNodeBinary, and an output-id pool was appended. Roughly 250 lines.
            //
            // It produced a structure that could not match anything:
            //   - childOffsets were written verbatim from the in-memory nodes, where
            //     they hold NODE IDS, not the disk offsets the field name and the
            //     reader both require. The nodeIdToDiskOffset map that would have
            //     translated them was built and never applied.
            //   - failureLinkOffset had the same defect.
            //   - outputOffset was left 0 on every node, and PatternIndex::collectOutputs
            //     returns immediately on a zero outputOffset, so no node could ever
            //     report a match even if the links had been correct.
            // The header nevertheless set flags = 0x01, "Aho-Corasick optimized".
            //
            // AND IT WAS NOT FREE. TrieNodeBinary is 1056 bytes because childOffsets is
            // a DENSE 256-entry array, so a node with one child costs the same as a node
            // with 256. Measured through the real tool, the section cost ~1,059 bytes per
            // byte of pattern content - 200 patterns of 200 bytes produced a 42 MB
            // pattern index. The database is a fixed 64 MB allocation of which the YARA
            // section already holds 38 MB, so an unreadable index was the binding
            // constraint on how much pattern content this product could ship. Removing it
            // raises that ceiling by roughly a thousandfold: the authoritative persisted
            // form is the PatternEntry array, at 48 bytes plus the pattern's own bytes.
            //
            // THE CORRECT PRODUCER ALREADY EXISTS, which is why this is a removal and not
            // a rewrite. PatternIndex has its own complete implementation of this
            // structure - CreateNew assigns rootNodeOffset properly and AddPattern writes
            // outputOffset properly - so there were two producers of one on-disk format
            // and the broken one was the one that ran. If an on-disk automaton is wanted
            // later, that path is the place to build it from, and any implementation must
            // first replace the dense 256-entry child array with a sparse representation.
            // Until then the runtime builds its automaton from the pattern entries at
            // load, which is O(total pattern bytes) once per start.
            uint64_t headerOffset = Format::AlignToPage(currentOffset);

            if (headerOffset + sizeof(TrieIndexHeader) > m_outputSize) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"SerializeAhoCorasickToDisk: Insufficient space for trie header");
                return StoreError{ SignatureStoreError::TooLarge, 0, "Database too small" };
            }

            TrieIndexHeader* header = reinterpret_cast<TrieIndexHeader*>(
                static_cast<uint8_t*>(m_outputBase) + headerOffset
                );

            std::memset(header, 0, sizeof(TrieIndexHeader));

            header->magic = TRIE_INDEX_MAGIC;
            header->version = TRIE_INDEX_VERSION;
            header->totalPatterns = m_pendingPatterns.size();

            // Zero means "this database carries no serialized automaton". The reader
            // accepts that state explicitly rather than treating it as corruption, and
            // flags deliberately does NOT claim Aho-Corasick optimization, because the
            // previous value said so while the nodes were unusable.
            header->totalNodes = 0;
            header->rootNodeOffset = 0;
            header->outputPoolOffset = 0;
            header->outputPoolSize = 0;
            header->maxNodeDepth = 0;
            header->flags = 0;

            // Explicitly "no pattern entries" until the caller writes them and records
            // their coordinates. The output buffer may be a reused file (--overwrite),
            // so these cannot be assumed zero - and if serialization fails between
            // here and there, a header claiming entries that were never written would
            // send the loader into arbitrary bytes.
            header->patternEntryOffset = 0;
            header->patternEntryCount = 0;

            currentOffset = headerOffset + sizeof(TrieIndexHeader);

            // ========================================================================
         // STEP 8: COMPUTE CHECKSUM
         // ========================================================================

         // Calculate the trie data size with overflow protection
            uint64_t trieDataSize = currentOffset - headerOffset;

            // Bounds validation before computing checksum
            if (headerOffset + sizeof(TrieIndexHeader) > m_outputSize ||
                trieDataSize < sizeof(TrieIndexHeader)) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"SerializeAhoCorasickToDisk: Invalid trie data size for checksum");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid trie data size" };
            }

            const uint8_t* trieDataPtr = static_cast<const uint8_t*>(m_outputBase)
                + headerOffset + sizeof(TrieIndexHeader);
            size_t trieDataLen = static_cast<size_t>(trieDataSize - sizeof(TrieIndexHeader));

            // Additional bounds validation
            if (trieDataLen > 0 && trieDataPtr) {
                std::span<const uint8_t> trieData(trieDataPtr, trieDataLen);
                header->checksumCRC64 = ComputeCRC64(trieData.data(), trieData.size());
            } else {
                header->checksumCRC64 = 0;
            }

            // ========================================================================
            // STEP 9: PERFORMANCE LOGGING
            // ========================================================================
            LARGE_INTEGER endTime{};
            QueryPerformanceCounter(&endTime);

            // Safe time calculation with division-by-zero protection
            uint64_t serializeTimeUs = safeElapsedUs(startTime, endTime, m_perfFrequency);

            SS_LOG_INFO(L"SignatureBuilder",
                L"SerializeAhoCorasickToDisk: wrote the pattern section header "
                L"(%llu bytes, no serialized automaton) in %llu us",
                trieDataSize, serializeTimeUs);

            return StoreError{ SignatureStoreError::Success };
        }


        StoreError SignatureBuilder::SerializeYaraRules() noexcept {
            SS_LOG_INFO(L"SignatureBuilder", L"SerializeYaraIndex: Starting YARA rule serialization");

            LARGE_INTEGER startTime{};
            QueryPerformanceCounter(&startTime);

            // Ensure performance frequency is valid
            if (m_perfFrequency.QuadPart <= 0) {
                QueryPerformanceFrequency(&m_perfFrequency);
                if (m_perfFrequency.QuadPart <= 0) {
                    m_perfFrequency.QuadPart = DEFAULT_PERF_FREQUENCY;
                }
            }

            // ========================================================================
            // VALIDATION
            // ========================================================================
            if (m_pendingYaraRules.empty()) {
                SS_LOG_WARN(L"SignatureBuilder", L"SerializeYaraIndex: No YARA rules to serialize");
                return StoreError{ SignatureStoreError::Success };
            }
            
            // Validate output buffer
            if (!m_outputBase || m_outputSize == 0) {
                SS_LOG_ERROR(L"SignatureBuilder", L"SerializeYaraIndex: Invalid output buffer");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid output buffer" };
            }

            // ========================================================================
            // COMPILE YARA RULES USING YaraCompiler
            // ========================================================================
            YaraCompiler compiler;

            size_t compiledRules = 0;
            size_t failedRules = 0;
            for (const auto& ruleInput : m_pendingYaraRules) {
                StoreError err = compiler.AddString(ruleInput.ruleSource, ruleInput.namespace_);
                if (err.IsSuccess()) {
                    compiledRules++;
                }
                else {
                    failedRules++;
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"SerializeYaraIndex: Failed to compile rule from %S: %S",
                        ruleInput.source.c_str(), err.message.c_str());
                }
            }

            if (compiledRules == 0) {
                SS_LOG_ERROR(L"SignatureBuilder", L"SerializeYaraIndex: No rules compiled successfully");
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Failed to compile any YARA rules" };
            }

            if (failedRules > 0) {
                SS_LOG_WARN(L"SignatureBuilder",
                    L"SerializeYaraIndex: %zu/%zu rules failed to compile",
                    failedRules, m_pendingYaraRules.size());
            }

            SS_LOG_INFO(L"SignatureBuilder",
                L"SerializeYaraIndex: Compiled %zu/%zu rules successfully",
                compiledRules, m_pendingYaraRules.size());

            // ========================================================================
            // SAVE COMPILED RULES TO BUFFER
            // ========================================================================
            auto compiledBuffer = compiler.SaveToBuffer();
            if (!compiledBuffer.has_value()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"SerializeYaraIndex: Failed to save compiled rules");
                return StoreError{ SignatureStoreError::Unknown, 0, "Failed to serialize compiled rules" };
            }

            uint64_t yaraDataSize = compiledBuffer->size();

            // ========================================================================
            // WRITE COMPILED YARA DATA TO DATABASE
            // ========================================================================
            uint64_t currentOffset = m_currentOffset;
            uint64_t yaraOffset = Format::AlignToPage(currentOffset);

            // CRITICAL: Record section start for header back-fill
            m_sectionOffsets.yaraStart = yaraOffset;

            if (yaraOffset + yaraDataSize > m_outputSize) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"SerializeYaraIndex: Insufficient space (%llu + %llu > %llu)",
                    yaraOffset, yaraDataSize, m_outputSize);
                return StoreError{ SignatureStoreError::TooLarge, 0, "Database too small for YARA rules" };
            }

            // Copy compiled rules to database
            uint8_t* yaraPtr = static_cast<uint8_t*>(m_outputBase) + yaraOffset;
            std::memcpy(yaraPtr, compiledBuffer->data(), yaraDataSize);

            currentOffset = Format::AlignToPage(yaraOffset + yaraDataSize);

            m_statistics.yaraRulesSize = yaraDataSize;
            m_statistics.optimizedSignatures += compiledRules;

            // ========================================================================
            // WRITE RULE METADATA
            // ========================================================================
            std::vector<YaraRuleEntry> ruleEntries;
            ruleEntries.reserve(m_pendingYaraRules.size());

            uint64_t metadataOffset = currentOffset;

            for (size_t i = 0; i < m_pendingYaraRules.size(); ++i) {
                const auto& ruleInput = m_pendingYaraRules[i];

                YaraRuleEntry entry{};
                entry.ruleId = std::hash<std::string>{}(ruleInput.ruleSource);

                // Validate offsets fit in uint32_t before truncation
                if (yaraOffset > UINT32_MAX || yaraDataSize > UINT32_MAX) {
                    SS_LOG_ERROR(L"SignatureBuilder",
                        L"SerializeYaraIndex: YARA data offset/size exceeds uint32_t capacity "
                        L"(offset: %llu, size: %llu)", yaraOffset, yaraDataSize);
                    return StoreError{ SignatureStoreError::TooLarge, 0,
                                      "YARA data offset exceeds 4GB limit" };
                }
                entry.compiledOffset = static_cast<uint32_t>(yaraOffset);
                entry.compiledSize = static_cast<uint32_t>(yaraDataSize);
                entry.threatLevel = 50;  // Default medium threat
                entry.flags = 0;
                entry.lastModified = GetCurrentTimestamp();

                if (currentOffset + sizeof(YaraRuleEntry) > m_outputSize) {
                    SS_LOG_ERROR(L"SignatureBuilder", L"SerializeYaraIndex: Insufficient space for metadata");
                    return StoreError{ SignatureStoreError::TooLarge, 0, "Database too small" };
                }

                YaraRuleEntry* entryPtr = reinterpret_cast<YaraRuleEntry*>(
                    static_cast<uint8_t*>(m_outputBase) + currentOffset
                    );

                std::memcpy(entryPtr, &entry, sizeof(YaraRuleEntry));
                currentOffset += sizeof(YaraRuleEntry);
            }

            currentOffset = Format::AlignToPage(currentOffset);

            // ========================================================================
            // PERFORMANCE METRICS
            // ========================================================================
            LARGE_INTEGER endTime{};
            QueryPerformanceCounter(&endTime);

            // Safe time calculation with division-by-zero protection
            uint64_t serializeTimeUs = safeElapsedUs(startTime, endTime, m_perfFrequency);

            m_statistics.serializationTimeMilliseconds += serializeTimeUs / 1000;
            m_currentOffset = currentOffset;

            SS_LOG_INFO(L"SignatureBuilder",
                L"SerializeYaraIndex: Complete - %zu rules compiled, %llu bytes bytecode, %llu us",
                compiledRules, yaraDataSize, serializeTimeUs);

            ReportProgress("SerializeYaraIndex", compiledRules, m_pendingYaraRules.size());

            return StoreError{ SignatureStoreError::Success };
        }


        // ============================================================================
        // SERIALIZE METADATA IMPLEMENTATION - PRODUCTION GRADE
        // ============================================================================

        StoreError SignatureBuilder::SerializeMetadata() noexcept {
            SS_LOG_INFO(L"SignatureBuilder", L"SerializeMetadata: Starting metadata serialization");

            LARGE_INTEGER startTime{};
            QueryPerformanceCounter(&startTime);

            // Ensure performance frequency is valid
            if (m_perfFrequency.QuadPart <= 0) {
                QueryPerformanceFrequency(&m_perfFrequency);
                if (m_perfFrequency.QuadPart <= 0) {
                    m_perfFrequency.QuadPart = DEFAULT_PERF_FREQUENCY;
                }
            }
            
            // Validate output buffer
            if (!m_outputBase || m_outputSize == 0) {
                SS_LOG_ERROR(L"SignatureBuilder", L"SerializeMetadata: Invalid output buffer");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid output buffer" };
            }

            // ========================================================================
            // BUILD METADATA JSON - WITH PROPER TIMESTAMP FORMATTING
            // ========================================================================

            time_t now = time(nullptr);
            char buf[32] = {0}; // Safely oversized buffer for ctime_s
            errno_t timeErr = ctime_s(buf, sizeof(buf), &now);
            
            std::string createdAt;
            if (timeErr == 0) {
                createdAt = buf;
            } else {
                createdAt = "unknown";
            }
            while (!createdAt.empty() && (createdAt.back() == '\n' || createdAt.back() == '\r')) {
                createdAt.pop_back();
            }
            
            // FIX: Escape any remaining control characters for JSON safety
            std::string escapedCreatedAt;
            escapedCreatedAt.reserve(createdAt.size());
            for (char c : createdAt) {
                if (c >= 32 && c < 127 && c != '"' && c != '\\') {
                    escapedCreatedAt.push_back(c);
                } else if (c == '"') {
                    escapedCreatedAt += "\\\"";
                } else if (c == '\\') {
                    escapedCreatedAt += "\\\\";
                }
                // Skip other control characters
            }

            std::string jsonContent = R"({
  "database": {
    "version": "1.0",
    "createdAt": ")" + escapedCreatedAt + R"(",
    "totalSignatures": )" + std::to_string(m_pendingHashes.size() + m_pendingPatterns.size() + m_pendingYaraRules.size()) + R"(
  },
  "hashes": {
    "count": )" + std::to_string(m_pendingHashes.size()) + R"(,
    "indexed": true
  },
  "patterns": {
    "count": )" + std::to_string(m_pendingPatterns.size()) + R"(,
    "indexed": true
  },
  "yaraRules": {
    "count": )" + std::to_string(m_pendingYaraRules.size()) + R"(,
    "compiled": true
  }
})";

            // ========================================================================
            // WRITE METADATA TO DATABASE
            // ========================================================================
            uint64_t currentOffset = m_currentOffset;
            uint64_t metadataOffset = Format::AlignToPage(currentOffset);

            // CRITICAL: Record section start for header back-fill
            m_sectionOffsets.metadataStart = metadataOffset;

            if (metadataOffset + jsonContent.size() > m_outputSize) {
                SS_LOG_ERROR(L"SignatureBuilder", L"SerializeMetadata: Insufficient space");
                return StoreError{ SignatureStoreError::TooLarge, 0, "Database too small" };
            }

            char* metadataPtr = reinterpret_cast<char*>(
                static_cast<uint8_t*>(m_outputBase) + metadataOffset
                );
            std::memcpy(metadataPtr, jsonContent.c_str(), jsonContent.size());

            currentOffset = Format::AlignToPage(metadataOffset + jsonContent.size());

            m_statistics.metadataSize = jsonContent.size();

            // ========================================================================
            // PERFORMANCE METRICS
            // ========================================================================
            LARGE_INTEGER endTime{};
            QueryPerformanceCounter(&endTime);

            // Safe time calculation with division-by-zero protection
            uint64_t serializeTimeUs = safeElapsedUs(startTime, endTime, m_perfFrequency);

            m_statistics.serializationTimeMilliseconds += serializeTimeUs / 1000;
            m_currentOffset = currentOffset;

            SS_LOG_INFO(L"SignatureBuilder",
                L"SerializeMetadata: Complete - %zu bytes in %llu us",
                jsonContent.size(), serializeTimeUs);

            return StoreError{ SignatureStoreError::Success };
        }

        StoreError SignatureBuilder::ComputeChecksum() noexcept {
            if (!m_outputBase || m_outputSize == 0) {
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "No output buffer" };
            }

            // Validate minimum size for header
            if (m_outputSize < sizeof(SignatureDatabaseHeader)) {
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Output too small for header" };
            }

            auto* header = static_cast<SignatureDatabaseHeader*>(m_outputBase);

            // CRITICAL: Zero the checksum field BEFORE computing the hash, otherwise
            // verification will fail because the hash input would include the non-zero
            // checksum value that was just stored.
            std::memset(header->sha256Checksum.data(), 0, header->sha256Checksum.size());

            // Compute SHA-256 of entire database (checksum field is now zeroed)
            auto checksum = ComputeDatabaseChecksum();

            // Validate checksum was computed
            if (checksum.empty()) {
                return StoreError{ SignatureStoreError::Unknown, 0, "Checksum computation failed" };
            }

            // Validate checksum result is not all-zeros (indicates hash failure)
            bool allZero = true;
            for (size_t i = 0; i < checksum.size() && allZero; ++i) {
                if (checksum[i] != 0) allZero = false;
            }
            if (allZero) {
                SS_LOG_WARN(L"SignatureBuilder", L"ComputeChecksum: checksum is all zeros");
            }

            // Copy checksum with bounds check
            size_t copySize = std::min(checksum.size(), header->sha256Checksum.size());
            std::memcpy(header->sha256Checksum.data(), checksum.data(), copySize);

            if (!FlushViewOfFile(m_outputBase, sizeof(SignatureDatabaseHeader))) {
                SS_LOG_WARN(L"SignatureBuilder", L"ComputeChecksum: FlushViewOfFile failed");
            }

            Log("Checksum computed");
            return StoreError{ SignatureStoreError::Success };
        }
	}
	
}
