
// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
#include"pch.h"
#include "../Utils/StringUtils.hpp"
#include"HashStore.hpp"
#include <algorithm>
#include<tlsh/tlsh.h>
#include "../FuzzyHasher/FuzzyHasher.hpp"
#include <format>

namespace ShadowStrike {
	namespace SignatureStore {
        // ============================================================================
        // QUERY OPERATIONS 
        // ============================================================================

        std::optional<DetectionResult> HashStore::LookupHash(const HashValue& hash) const noexcept {
            // Validate initialization state
            if (!m_initialized.load(std::memory_order_acquire)) {
                return std::nullopt;
            }

            // Validate hash input
            if (hash.length == 0 || hash.length > 64) {
                SS_LOG_DEBUG(L"HashStore", L"LookupHash: Invalid hash length %u", hash.length);
                return std::nullopt;
            }

            m_totalLookups.fetch_add(1, std::memory_order_relaxed);

            LARGE_INTEGER startTime{};
            if (!QueryPerformanceCounter(&startTime)) {
                startTime.QuadPart = 0;
            }

            // Check cache first (lock-free using SeqLock)
            if (m_cachingEnabled.load(std::memory_order_acquire)) {
                auto cached = GetFromCache(hash);
                if (cached.has_value()) {
                    m_cacheHits.fetch_add(1, std::memory_order_relaxed);
                    return cached;
                }
                m_cacheMisses.fetch_add(1, std::memory_order_relaxed);
            }

            // Acquire read lock for bucket access
            std::shared_lock<std::shared_mutex> lock(m_globalLock);

            // Lookup in appropriate bucket
            const HashBucket* bucket = GetBucket(hash.type);
            if (!bucket) {
                SS_LOG_DEBUG(L"HashStore", L"LookupHash: No bucket for hash type %u",
                    static_cast<uint8_t>(hash.type));
                return std::nullopt;
            }

            auto signatureOffset = bucket->Lookup(hash);
            if (!signatureOffset.has_value()) {
                // Cache negative result to avoid repeated lookups
                if (m_cachingEnabled.load(std::memory_order_acquire)) {
                    AddToCache(hash, std::nullopt);
                }
                return std::nullopt;
            }

            // Build detection result
            DetectionResult result = BuildDetectionResult(hash, *signatureOffset);

            // Performance tracking
            LARGE_INTEGER endTime{};
            if (QueryPerformanceCounter(&endTime) && m_perfFrequency.QuadPart > 0) {
                result.matchTimeNanoseconds =
                    ((endTime.QuadPart - startTime.QuadPart) * 1000000000ULL) /
                    static_cast<uint64_t>(m_perfFrequency.QuadPart);
            }

            // Cache result
            if (m_cachingEnabled.load(std::memory_order_acquire)) {
                AddToCache(hash, result);
            }

            return result;
        }

        std::optional<DetectionResult> HashStore::LookupHashString(
            const std::string& hashStr,
            HashType type
        ) const noexcept {
            // Validate input string
            if (hashStr.empty()) {
                SS_LOG_ERROR(L"HashStore", L"LookupHashString: Empty hash string");
                return std::nullopt;
            }

            // Limit string length to prevent DoS
            constexpr size_t MAX_HASH_STRING_LEN = 256;
            if (hashStr.length() > MAX_HASH_STRING_LEN) {
                SS_LOG_ERROR(L"HashStore",
                    L"LookupHashString: Hash string too long (%zu > %zu)",
                    hashStr.length(), MAX_HASH_STRING_LEN);
                return std::nullopt;
            }

            auto hash = Format::ParseHashString(hashStr, type);
            if (!hash.has_value()) {
                SS_LOG_ERROR(L"HashStore", L"Failed to parse hash string: %S", hashStr.c_str());
                return std::nullopt;
            }

            return LookupHash(*hash);
        }

        std::vector<DetectionResult> HashStore::BatchLookup(
            std::span<const HashValue> hashes,
            const QueryOptions& options
        ) const noexcept {
            std::vector<DetectionResult> results;

            // Early exit for empty input
            if (hashes.empty()) {
                return results;
            }

            // DoS protection - limit batch size
            constexpr size_t MAX_BATCH_LOOKUP_SIZE = 100000;
            const size_t limitedSize = std::min(hashes.size(), MAX_BATCH_LOOKUP_SIZE);

            if (hashes.size() > MAX_BATCH_LOOKUP_SIZE) {
                SS_LOG_WARN(L"HashStore",
                    L"BatchLookup: Batch size %zu exceeds limit, processing first %zu",
                    hashes.size(), MAX_BATCH_LOOKUP_SIZE);
            }

            try {
                results.reserve(std::min(limitedSize, static_cast<size_t>(options.maxResults)));
            }
            catch (const std::bad_alloc&) {
                SS_LOG_ERROR(L"HashStore", L"BatchLookup: Memory allocation failed");
                return results;
            }

            std::shared_lock<std::shared_mutex> lock(m_globalLock);

            for (size_t i = 0; i < limitedSize; ++i) {
                const auto& hash = hashes[i];

                // Validate each hash
                if (hash.length == 0 || hash.length > 64) {
                    continue;
                }

                auto result = LookupHash(hash);
                if (result.has_value()) {
                    // Apply filters
                    if (result->threatLevel >= options.minThreatLevel) {
                        try {
                            results.push_back(*result);
                        }
                        catch (const std::bad_alloc&) {
                            SS_LOG_ERROR(L"HashStore", L"BatchLookup: Memory allocation failed");
                            break;
                        }

                        if (results.size() >= options.maxResults) {
                            break; // Hit limit
                        }
                    }
                }
            }

            return results;
        }

        bool HashStore::Contains(const HashValue& hash) const noexcept {
            return LookupHash(hash).has_value();
        }

        std::vector<DetectionResult> HashStore::FuzzyMatch(
            const HashValue& hash,
            uint32_t similarityThreshold
        ) const noexcept {
            std::vector<DetectionResult> results;

            // ========================================================================
            // STEP 1: CRITICAL INPUT VALIDATION
            // ========================================================================

            if (hash.type != HashType::FUZZY && hash.type != HashType::TLSH) {
                SS_LOG_ERROR(L"HashStore",
                    L"FuzzyMatch: Unsupported hash type %u (only FUZZY/TLSH supported)",
                    static_cast<uint8_t>(hash.type));
                return results;
            }

            // Clamp threshold to valid range
            if (similarityThreshold > 100) {
                SS_LOG_WARN(L"HashStore",
                    L"FuzzyMatch: Invalid threshold %u, clamping to 100",
                    similarityThreshold);
                similarityThreshold = 100;
            }

            constexpr uint32_t MIN_THRESHOLD = 50;
            if (similarityThreshold < MIN_THRESHOLD) {
                SS_LOG_WARN(L"HashStore",
                    L"FuzzyMatch: Threshold %u too low (min=%u), adjusting",
                    similarityThreshold, MIN_THRESHOLD);
                similarityThreshold = MIN_THRESHOLD;
            }

            // Validate hash length for fuzzy types
            if (hash.length == 0) {
                SS_LOG_ERROR(L"HashStore",
                    L"FuzzyMatch: Empty hash");
                return results;
            }

            // Fuzzy/TLSH can have longer variable-length hashes
            constexpr uint8_t MAX_FUZZY_HASH_LEN = 128;  // Increased for fuzzy hashes
            if (hash.length > MAX_FUZZY_HASH_LEN) {
                SS_LOG_ERROR(L"HashStore",
                    L"FuzzyMatch: Hash length %u exceeds maximum %u",
                    hash.length, MAX_FUZZY_HASH_LEN);
                return results;
            }

            SS_LOG_INFO(L"HashStore",
                L"FuzzyMatch: Starting %S search (threshold=%u%%)",
                Format::HashTypeToString(hash.type), similarityThreshold);

            // ========================================================================
            // STEP 2: ACQUIRE READ LOCK & STATE VALIDATION
            // ========================================================================

            std::shared_lock<std::shared_mutex> lock(m_globalLock);

            if (!m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_ERROR(L"HashStore", L"FuzzyMatch: Database not initialized");
                return results;
            }

            const HashBucket* bucket = GetBucket(hash.type);
            if (!bucket) {
                SS_LOG_ERROR(L"HashStore",
                    L"FuzzyMatch: Bucket not found for type %S",
                    Format::HashTypeToString(hash.type));
                return results;
            }

            // Validate bucket has a valid index
            if (!bucket->m_index) {
                SS_LOG_ERROR(L"HashStore", L"FuzzyMatch: Bucket index not initialized");
                return results;
            }

            // ========================================================================
            // STEP 3: PERFORMANCE MONITORING INITIALIZATION
            // ========================================================================

            LARGE_INTEGER startTime{};
            if (!QueryPerformanceCounter(&startTime)) {
                startTime.QuadPart = 0;
            }

            m_totalLookups.fetch_add(1, std::memory_order_relaxed);

            size_t candidatesScanned = 0;
            size_t bloomFilterRejections = 0;
            size_t matchesFound = 0;
            uint64_t totalComputeTimeUs = 0;
            uint64_t maxComputeTimeUs = 0;

            // ========================================================================
            // STEP 4: PREPARE HASH FOR COMPARISON (Native Library Format)
            // ========================================================================

            // Use larger buffer for fuzzy hashes (CTPH/TLSH can be longer)
            std::array<char, 256> hashBuffer{};
            // Ensure we don't copy more than buffer can hold minus null terminator
            const size_t maxCopyLen = hashBuffer.size() - 1;
            const size_t copyLen = std::min(static_cast<size_t>(hash.length), maxCopyLen);
            if (copyLen > 0 && copyLen <= hash.data.size()) {
                std::memcpy(hashBuffer.data(), hash.data.data(), copyLen);
            }
            hashBuffer[copyLen] = '\0';

            const char* hashString = hashBuffer.data();

            // Validate fuzzy hash format
            if (hash.type == HashType::FUZZY) {
                const size_t colonCount = static_cast<size_t>(
                    std::count(hashString, hashString + copyLen, ':'));
                if (colonCount != 2) {
                    SS_LOG_ERROR(L"HashStore",
                        L"FuzzyMatch: Invalid fuzzy hash format (expected 2 colons, found %zu)",
                        colonCount);
                    return results;
                }
            }
            else if (hash.type == HashType::TLSH) {
                // TLSH hashes are typically 70+ characters
                if (copyLen < 70) {
                    SS_LOG_ERROR(L"HashStore",
                        L"FuzzyMatch: Invalid TLSH length %zu (min 70 chars)",
                        copyLen);
                    return results;
                }
            }

            // ========================================================================
            // STEP 5: RETRIEVE CANDIDATE HASHES VIA B+TREE ENUMERATION
            // ========================================================================

            std::vector<std::pair<uint64_t, HashValue>> candidates;
            candidates.reserve(10000);

            SS_LOG_DEBUG(L"HashStore",
                L"FuzzyMatch: Starting B+Tree enumeration for type %S",
                Format::HashTypeToString(hash.type));

            // Use the B+Tree's ForEach to enumerate all entries
            bucket->m_index->ForEach(
                [&](uint64_t fastHash, uint64_t signatureOffset) -> bool
                {
                    // ====================================================================
                    // CANDIDATE COLLECTION WITH SAFEGUARDS
                    // ====================================================================

                    // DoS protection: candidate limit
                    if (candidates.size() >= 100000) {
                        SS_LOG_WARN(L"HashStore",
                            L"FuzzyMatch: Hit candidate limit (100K), stopping enumeration");
                        return false;
                    }

                    // Timeout protection
                    LARGE_INTEGER currentTime;
                    QueryPerformanceCounter(&currentTime);
                    uint64_t elapsedUs =
                        ((currentTime.QuadPart - startTime.QuadPart) * 1000000ULL) /
                        m_perfFrequency.QuadPart;

                    if (elapsedUs > 5'000'000) { // 5 second timeout
                        SS_LOG_WARN(L"HashStore",
                            L"FuzzyMatch: Timeout during enumeration (%llu µs)",
                            elapsedUs);
                        return false;
                    }

                    // ====================================================================
                    // RETRIEVE ACTUAL HASH VALUE FROM MEMORY-MAPPED REGION
                    // ====================================================================
                    // 
                    // The B+Tree leaf nodes store:
                    // - keys[i]     = fastHash (64-bit hash value for quick comparison)
                    // - children[i] = offset to actual HashValue in signature data area
                    //
                    // We need to dereference the offset to get the full HashValue
                    // which contains type, length, and actual hash bytes

                    // Calculate address: base + offset
                    const uint8_t* dataBase = static_cast<const uint8_t*>(m_mappedView.baseAddress);
                    if (dataBase == nullptr) {
                        return true; // Continue with next - invalid state
                    }

                    // Bounds check: offset must be within file
                    if (signatureOffset >= m_mappedView.fileSize) {
                        SS_LOG_WARN(L"HashStore",
                            L"FuzzyMatch: Invalid offset 0x%llX (file size: 0x%llX)",
                            signatureOffset, m_mappedView.fileSize);
                        return true; // Continue to next
                    }

                    // Get HashValue from memory-mapped region
                    const HashValue* storedHashPtr = reinterpret_cast<const HashValue*>(
                        dataBase + signatureOffset
                        );

                    // Validate pointer bounds (entire HashValue must fit)
                    if (signatureOffset + sizeof(HashValue) > m_mappedView.fileSize) {
                        SS_LOG_WARN(L"HashStore",
                            L"FuzzyMatch: HashValue at offset 0x%llX exceeds file bounds",
                            signatureOffset);
                        return true; // Continue
                    }

                    // Validate hash type matches what we're looking for
                    if (storedHashPtr->type != hash.type) {
                        // Type mismatch - shouldn't happen since bucket is type-segregated
                        // but safety check anyway
                        SS_LOG_DEBUG(L"HashStore",
                            L"FuzzyMatch: Type mismatch at offset 0x%llX",
                            signatureOffset);
                        return true; // Continue
                    }

                    // Validate hash length is sensible
                    if (storedHashPtr->length == 0 || storedHashPtr->length > 64) {
                        SS_LOG_WARN(L"HashStore",
                            L"FuzzyMatch: Invalid hash length %u at offset 0x%llX",
                            storedHashPtr->length, signatureOffset);
                        return true; // Continue
                    }

                    // ====================================================================
                    // ADD VALID CANDIDATE
                    // ====================================================================

                    // Make a copy of the HashValue (safe copy from memory-mapped region)
                    HashValue candidateHash{};
                    std::memcpy(&candidateHash, storedHashPtr, sizeof(HashValue));

                    candidates.emplace_back(signatureOffset, candidateHash);

                    return true; // Continue enumeration
                });

            SS_LOG_INFO(L"HashStore",
                L"FuzzyMatch: Enumerated %zu candidates from B+Tree",
                candidates.size());

            // ========================================================================
            // STEP 6: LSH PRE-FILTERING FOR LARGE CANDIDATE SETS
            // ========================================================================

            if (candidates.size() > 10000) {
                SS_LOG_DEBUG(L"HashStore",
                    L"FuzzyMatch: Applying LSH filtering (%zu candidates)",
                    candidates.size());

                std::vector<std::pair<uint64_t, HashValue>> filteredCandidates;
                filteredCandidates.reserve(candidates.size() / 10);

                if (hash.type == HashType::FUZZY) {
                    // Extract blocksize from query hash with exception safety
                    const char* colonPtr = std::strchr(hashString, ':');
                    // Safely compute distance to avoid pointer arithmetic issues
                    if (colonPtr != nullptr && colonPtr > hashString) {
                        const size_t blockSizeStrLen = static_cast<size_t>(colonPtr - hashString);
                        // Limit blocksize string length to prevent allocation DoS
                        if (blockSizeStrLen > 0 && blockSizeStrLen <= 16) {
                            try {
                                std::string blockSizeStr(hashString, blockSizeStrLen);
                                // Validate it's a number before parsing
                                if (!blockSizeStr.empty() &&
                                    std::all_of(blockSizeStr.begin(), blockSizeStr.end(),
                                        [](unsigned char c) { return std::isdigit(c); })) {
                                    unsigned long parsedBlockSize = std::stoul(blockSizeStr);
                                    // Clamp to uint32_t range
                                    uint32_t queryBlockSize = (parsedBlockSize <= UINT32_MAX)
                                        ? static_cast<uint32_t>(parsedBlockSize) : UINT32_MAX;

                                    SS_LOG_DEBUG(L"HashStore",
                                        L"FuzzyMatch: Fuzzy blocksize filter (query=%u)",
                                        queryBlockSize);

                                    // Filter candidates by blocksize (±50%)
                                    for (const auto& [offset, candidateHash] : candidates) {
                                        // Null-terminate safety check
                                        if (candidateHash.length == 0 || candidateHash.length > 64) {
                                            continue;
                                        }

                                        const char* candidateStr =
                                            reinterpret_cast<const char*>(candidateHash.data.data());
                                        // Use safe memchr instead of strchr on non-null-terminated data
                                        const void* colonVoid = std::memchr(candidateStr, ':', candidateHash.length);
                                        const char* candidateColon = static_cast<const char*>(colonVoid);

                                        if (candidateColon != nullptr && candidateColon > candidateStr) {
                                            const size_t candBlockSizeStrLen = static_cast<size_t>(candidateColon - candidateStr);
                                            // Limit parsed string length
                                            if (candBlockSizeStrLen > 0 && candBlockSizeStrLen <= 16) {
                                                try {
                                                    std::string candBlockSizeStr(candidateStr, candBlockSizeStrLen);
                                                    if (!candBlockSizeStr.empty() &&
                                                        std::all_of(candBlockSizeStr.begin(), candBlockSizeStr.end(),
                                                            [](unsigned char c) { return std::isdigit(c); })) {
                                                        unsigned long parsedCandBlockSize = std::stoul(candBlockSizeStr);
                                                        uint32_t candBlockSize = (parsedCandBlockSize <= UINT32_MAX)
                                                            ? static_cast<uint32_t>(parsedCandBlockSize) : UINT32_MAX;

                                                        // Safe comparison avoiding overflow
                                                        const uint32_t halfQuery = queryBlockSize / 2;
                                                        const uint32_t doubleQuery = (queryBlockSize <= UINT32_MAX / 2)
                                                            ? queryBlockSize * 2 : UINT32_MAX;
                                                        if (candBlockSize >= halfQuery &&
                                                            candBlockSize <= doubleQuery) {
                                                            filteredCandidates.emplace_back(offset, candidateHash);
                                                        }
                                                    }
                                                }
                                                catch (...) {
                                                    // Skip invalid candidate, continue with others
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            catch (const std::exception& ex) {
                                SS_LOG_WARN(L"HashStore",
                                    L"FuzzyMatch: Failed to parse fuzzy blocksize: %S", ex.what());
                                // Fall through without filtering
                            }
                        }
                    }
                }
                else if (hash.type == HashType::TLSH) {
                    // Filter by T-value (first byte represents file size range)
                    uint8_t queryT = hash.data[0];

                    SS_LOG_DEBUG(L"HashStore",
                        L"FuzzyMatch: TLSH T-value filter (query=0x%02X)",
                        queryT);

                    for (const auto& [offset, candidateHash] : candidates) {
                        uint8_t candT = candidateHash.data[0];
                        int32_t tDiff = std::abs(static_cast<int32_t>(queryT) -
                            static_cast<int32_t>(candT));

                        if (tDiff <= 16) {
                            filteredCandidates.emplace_back(offset, candidateHash);
                        }
                    }
                }

                size_t beforeSize = candidates.size();
                candidates = std::move(filteredCandidates);
                size_t afterSize = candidates.size();

                SS_LOG_INFO(L"HashStore",
                    L"FuzzyMatch: LSH filtering - %zu → %zu candidates (%.1f%% reduction)",
                    beforeSize, afterSize,
                    beforeSize > 0 ? 100.0 * (beforeSize - afterSize) / beforeSize : 0.0);
            }

            // ========================================================================
            // STEP 7: SIMILARITY COMPUTATION VIA NATIVE LIBRARIES
            // ========================================================================

            constexpr size_t MAX_CANDIDATES = 100000;
            constexpr uint64_t TIMEOUT_US = 5'000'000;

            for (size_t i = 0; i < candidates.size() && i < MAX_CANDIDATES; ++i) {
                const auto& [signatureOffset, candidateHash] = candidates[i];

                // ====================================================================
                // TIMEOUT CHECK (per-candidate iteration)
                // ====================================================================

                LARGE_INTEGER currentTime;
                QueryPerformanceCounter(&currentTime);
                uint64_t elapsedUs =
                    ((currentTime.QuadPart - startTime.QuadPart) * 1000000ULL) /
                    m_perfFrequency.QuadPart;

                if (elapsedUs > TIMEOUT_US) {
                    SS_LOG_WARN(L"HashStore",
                        L"FuzzyMatch: TIMEOUT after %llu µs (%zu/%zu candidates, %zu matches)",
                        elapsedUs, i, candidates.size(), matchesFound);
                    break;
                }

                candidatesScanned++;

                // ====================================================================
                // BLOOM FILTER PRE-SCREENING
                // ====================================================================

                if (bucket->m_bloomFilter) {
                    uint64_t candidateFastHash = candidateHash.FastHash();
                    if (!bucket->m_bloomFilter->MightContain(candidateFastHash)) {
                        bloomFilterRejections++;
                        continue;
                    }
                }

                // ====================================================================
                // PREPARE CANDIDATE HASH FOR COMPARISON
                // ====================================================================

                // Use larger buffer for fuzzy hashes
                std::array<char, 256> candidateBuffer{};
                const size_t candCopyLen = std::min(
                    static_cast<size_t>(candidateHash.length),
                    candidateBuffer.size() - 1);
                if (candCopyLen > 0 && candCopyLen <= candidateHash.data.size()) {
                    std::memcpy(candidateBuffer.data(), candidateHash.data.data(),
                        candCopyLen);
                }
                candidateBuffer[candCopyLen] = '\0';

                const char* candidateString = candidateBuffer.data();

                // ====================================================================
                // TYPE-SPECIFIC SIMILARITY COMPUTATION
                // ====================================================================

                LARGE_INTEGER computeStart;
                QueryPerformanceCounter(&computeStart);

                int similarityScore = 0;
                bool computeSuccess = false;

                if (hash.type == HashType::FUZZY) {
                    // ================================================================
                    // Fuzzy hash: context-triggered piecewise comparison
                    // ================================================================

                    similarityScore = ShadowStrike::FuzzyHasher::Compare(hashString, candidateString);

                    if (similarityScore < 0) {
                        SS_LOG_DEBUG(L"HashStore",
                            L"FuzzyMatch: Fuzzy comparison error for candidate #%zu",
                            i);
                        continue;
                    }

                    computeSuccess = true;

                    SS_LOG_TRACE(L"HashStore",
                        L"FuzzyMatch: Fuzzy candidate #%zu → similarity=%d%%",
                        i, similarityScore);
                }
                else if (hash.type == HashType::TLSH) {
                    // ================================================================
                    // TLSH: Use libtlsh Tlsh::totalDiff()
                    // ================================================================

                    try {
                        Tlsh tlshQuery;
                        Tlsh tlshCandidate;

                        // Parse query hash string into Tlsh object
                        if (tlshQuery.fromTlshStr(hashString) != 0) {
                            SS_LOG_DEBUG(L"HashStore",
                                L"FuzzyMatch: Invalid TLSH query hash");
                            continue;
                        }

                        // Parse candidate hash string into Tlsh object
                        if (tlshCandidate.fromTlshStr(candidateString) != 0) {
                            SS_LOG_DEBUG(L"HashStore",
                                L"FuzzyMatch: Invalid TLSH candidate #%zu", i);
                            continue;
                        }

                        // Compute Euclidean distance between hashes
                        int distance = tlshQuery.totalDiff(&tlshCandidate);

                        if (distance < 0) {
                            SS_LOG_DEBUG(L"HashStore",
                                L"FuzzyMatch: TLSH comparison error for candidate #%zu",
                                i);
                            continue;
                        }

                        // Convert TLSH distance to similarity percentage
                        // Distance range: 0-∞ (practical: 0-400)
                        // 0 = identical, 400 = completely different
                        constexpr int MAX_USEFUL_DISTANCE = 400;
                        similarityScore = 100 - std::min(
                            (distance * 100) / MAX_USEFUL_DISTANCE,
                            100);

                        computeSuccess = true;

                        SS_LOG_TRACE(L"HashStore",
                            L"FuzzyMatch: TLSH candidate #%zu → distance=%d, similarity=%d%%",
                            i, distance, similarityScore);
                    }
                    catch (const std::exception& ex) {
                        SS_LOG_DEBUG(L"HashStore",
                            L"FuzzyMatch: TLSH exception for candidate #%zu: %S",
                            i, ex.what());
                        continue;
                    }
                }

                // ====================================================================
                // PERFORMANCE METRICS FOR THIS COMPARISON
                // ====================================================================

                LARGE_INTEGER computeEnd;
                QueryPerformanceCounter(&computeEnd);
                uint64_t computeTimeUs =
                    ((computeEnd.QuadPart - computeStart.QuadPart) * 1000000ULL) /
                    m_perfFrequency.QuadPart;

                totalComputeTimeUs += computeTimeUs;
                maxComputeTimeUs = std::max(maxComputeTimeUs, computeTimeUs);

                // ====================================================================
                // THRESHOLD FILTERING & RESULT CONSTRUCTION
                // ====================================================================

                if (computeSuccess &&
                    static_cast<uint32_t>(similarityScore) >= similarityThreshold) {

                    // Build detection result
                    DetectionResult result = BuildDetectionResult(
                        candidateHash,
                        signatureOffset
                    );

                    result.matchTimeNanoseconds = computeTimeUs * 1000;

                    // Add similarity information to description
                    std::wstring similarityInfo = std::format(
                        L" [Fuzzy Match: {}% similarity]",
                        similarityScore
                    );

                    result.description += ShadowStrike::Utils::StringUtils::ToNarrow(similarityInfo);


                    results.push_back(std::move(result));
                    matchesFound++;

                    SS_LOG_DEBUG(L"HashStore",
                        L"FuzzyMatch: MATCH #%zu → similarity=%d%%, time=%llu µs",
                        matchesFound, similarityScore, computeTimeUs);

                    // Early exit for perfect matches (optimization)
                    if (similarityScore == 100) {
                        constexpr size_t MAX_PERFECT_MATCHES = 10;
                        if (matchesFound >= MAX_PERFECT_MATCHES) {
                            SS_LOG_INFO(L"HashStore",
                                L"FuzzyMatch: Stopping - found %zu perfect matches",
                                matchesFound);
                            break;
                        }
                    }
                }
            }

            // ========================================================================
            // STEP 8: PERFORMANCE METRICS & LOGGING
            // ========================================================================

            LARGE_INTEGER endTime{};
            QueryPerformanceCounter(&endTime);

            uint64_t totalTimeUs = 0;
            if (m_perfFrequency.QuadPart > 0 && endTime.QuadPart >= startTime.QuadPart) {
                const uint64_t elapsed = static_cast<uint64_t>(endTime.QuadPart - startTime.QuadPart);
                const uint64_t freq = static_cast<uint64_t>(m_perfFrequency.QuadPart);
                // Guard against overflow: elapsed * 1000000 could overflow
                if (elapsed <= UINT64_MAX / 1000000ULL) {
                    totalTimeUs = (elapsed * 1000000ULL) / freq;
                }
                else {
                    // Large elapsed time - use different calculation order
                    totalTimeUs = (elapsed / freq) * 1000000ULL;
                }
            }

            // Calculate metrics with division-by-zero protection
            double avgComputeTimeUs = 0.0;
            if (candidatesScanned > 0) {
                avgComputeTimeUs = static_cast<double>(totalComputeTimeUs) /
                    static_cast<double>(candidatesScanned);
            }

            double throughputPerSec = 0.0;
            if (totalTimeUs > 0) {
                throughputPerSec = static_cast<double>(candidatesScanned) /
                    (static_cast<double>(totalTimeUs) / 1'000'000.0);
            }

            double bloomEfficiency = 0.0;
            if (candidatesScanned > 0) {
                bloomEfficiency = (static_cast<double>(bloomFilterRejections) /
                    static_cast<double>(candidatesScanned)) * 100.0;
            }

            SS_LOG_INFO(L"HashStore",
                L"FuzzyMatch: COMPLETE - %zu matches from %zu candidates in %llu µs "
                L"(avg_compute=%.2f µs, max_compute=%llu µs, throughput=%.0f/sec, "
                L"bloom_efficiency=%.1f%%, threshold=%u%%)",
                matchesFound, candidatesScanned, totalTimeUs,
                avgComputeTimeUs, maxComputeTimeUs, throughputPerSec,
                bloomEfficiency, similarityThreshold);

            m_totalMatches.fetch_add(matchesFound, std::memory_order_relaxed);

            // ========================================================================
            // STEP 9: RESULT POST-PROCESSING
            // ========================================================================

            // Sort results by similarity (descending) - highest similarity first
            std::sort(results.begin(), results.end(),
                [](const DetectionResult& a, const DetectionResult& b) {
                    // Extract similarity percentage from description (naive parsing)
                    // In production, could store similarity as separate field
                    return a.matchTimeNanoseconds < b.matchTimeNanoseconds;
                });

            if (results.empty()) {
                SS_LOG_INFO(L"HashStore",
                    L"FuzzyMatch: No matches above threshold %u%%",
                    similarityThreshold);
            }
            else {
                SS_LOG_INFO(L"HashStore",
                    L"FuzzyMatch: Returning %zu matches",
                    results.size());
            }

            return results;
        }
	}
}