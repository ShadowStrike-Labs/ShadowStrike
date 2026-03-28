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

// ============================================================================
// HashStore Management Operations (Write Path)
// ============================================================================
//
// This file implements the write operations for the HashStore:
//   AddHash()           — insert single hash signature
//   AddHashBatch()      — insert batch of hash signatures
//   RemoveHash()        — remove hash from index (bloom filter retains entry)
//   UpdateHashMetadata()— update description/tags for an existing hash
//
// BLOOM FILTER LIMITATION:
//   Standard bloom filters are append-only; elements cannot be deleted.
//   After RemoveHash(), the bloom filter may report false positives for
//   removed hashes. The B+Tree index is always authoritative. Call
//   Rebuild() after bulk removals to recreate the bloom filter from
//   current B+Tree contents and purge stale false positives.
//
// HEADER PATCH NEEDED:
//   BuildDetectionResult() in HashStore.cpp currently returns hardcoded
//   metadata. It should be updated to read HashSignatureRecord from the
//   allocated signatureOffset to return the actual name, description,
//   tags, and threat level stored by AddHash()/UpdateHashMetadata().
//
// ============================================================================

#include "pch.h"
#include "HashStore.hpp"
#include <map>
#include <unordered_set>
#include <ctime>
#include <cstring>
#include "../Utils/JSONUtils.hpp"

namespace ShadowStrike {
namespace HashStore {

// ============================================================================
// LOCAL: On-disk record format for hash signature entries
// ============================================================================

namespace {

constexpr uint32_t HASH_RECORD_MAGIC   = 0x52535348;  // 'HSSR'
constexpr uint32_t HASH_RECORD_VERSION = 1;
constexpr size_t   MAX_NAME_LEN        = 256;
constexpr size_t   MAX_DESC_LEN        = 4096;
constexpr size_t   MAX_TAGS            = 32;
constexpr size_t   MAX_TAG_LEN         = 64;
constexpr size_t   MAX_BATCH_SIZE      = 100000;

#pragma pack(push, 1)
struct HashSignatureRecord {
    uint32_t magic;
    uint32_t version;
    uint8_t  hashType;
    uint8_t  threatLevel;
    uint16_t nameLength;
    uint32_t descLength;
    uint32_t tagsJsonLength;
    uint64_t creationTime;
    // Variable-length payload follows:
    //   char name[nameLength]
    //   char description[descLength]
    //   char tagsJson[tagsJsonLength]
};
#pragma pack(pop)

static_assert(sizeof(HashSignatureRecord) == 32,
    "HashSignatureRecord must be exactly 32 bytes");

// Validates a ThreatLevel against the declared enum values
[[nodiscard]] bool IsValidThreatLevel(ThreatLevel level) noexcept {
    switch (level) {
        case ThreatLevel::Info:
        case ThreatLevel::Low:
        case ThreatLevel::Medium:
        case ThreatLevel::High:
        case ThreatLevel::Critical:
            return true;
        default:
            return false;
    }
}

// Rejects strings with embedded nulls, path separators, or drive letters
[[nodiscard]] bool ContainsUnsafeChars(const std::string& str) noexcept {
    for (const char ch : str) {
        if (ch == '\0' || ch == '\\' || ch == '/' || ch == ':') {
            return true;
        }
    }
    return false;
}

// Hash-type-specific expected byte length (0 = variable-length type)
[[nodiscard]] uint8_t ExpectedHashLength(HashType type) noexcept {
    switch (type) {
        case HashType::MD5:     return 16;
        case HashType::SHA1:    return 20;
        case HashType::SHA256:  return 32;
        case HashType::SHA512:  return 64;
        case HashType::IMPHASH: return 32;
        case HashType::FUZZY:
        case HashType::TLSH:    return 0;
        default:                return UINT8_MAX;  // Unknown
    }
}

// Serialize tags vector to compact JSON array
[[nodiscard]] bool SerializeTagsJson(
    const std::vector<std::string>& tags,
    std::string& output) noexcept
{
    if (tags.empty()) {
        output.clear();
        return true;
    }
    try {
        Utils::JSON::Json arr = tags;
        return Utils::JSON::Stringify(arr, output);
    }
    catch (...) {
        return false;
    }
}

// Write a HashSignatureRecord + payload to the memory-mapped file
[[nodiscard]] bool WriteSignatureRecord(
    MemoryMappedView& view,
    uint64_t offset,
    HashType hashType,
    ThreatLevel threatLevel,
    const std::string& name,
    const std::string& description,
    const std::string& tagsJson) noexcept
{
    constexpr size_t kHeader = sizeof(HashSignatureRecord);
    const size_t payloadSize = name.size() + description.size() + tagsJson.size();

    if (offset > view.fileSize || kHeader + payloadSize > view.fileSize - offset) {
        return false;
    }

    auto* rec = view.GetAtMutable<HashSignatureRecord>(offset);
    if (!rec) {
        return false;
    }

    rec->magic          = HASH_RECORD_MAGIC;
    rec->version        = HASH_RECORD_VERSION;
    rec->hashType       = static_cast<uint8_t>(hashType);
    rec->threatLevel    = static_cast<uint8_t>(threatLevel);
    rec->nameLength     = static_cast<uint16_t>(name.size());
    rec->descLength     = static_cast<uint32_t>(description.size());
    rec->tagsJsonLength = static_cast<uint32_t>(tagsJson.size());
    rec->creationTime   = static_cast<uint64_t>(std::time(nullptr));

    uint8_t* dst = reinterpret_cast<uint8_t*>(rec) + kHeader;
    if (!name.empty()) {
        std::memcpy(dst, name.data(), name.size());
        dst += name.size();
    }
    if (!description.empty()) {
        std::memcpy(dst, description.data(), description.size());
        dst += description.size();
    }
    if (!tagsJson.empty()) {
        std::memcpy(dst, tagsJson.data(), tagsJson.size());
    }
    return true;
}

// Read the signature name from an existing record (best-effort)
[[nodiscard]] std::string ReadRecordName(
    const MemoryMappedView& view,
    uint64_t offset) noexcept
{
    constexpr size_t kHeader = sizeof(HashSignatureRecord);
    if (!view.IsValid() || offset + kHeader > view.fileSize) {
        return {};
    }

    const auto* rec = view.GetAt<HashSignatureRecord>(offset);
    if (!rec || rec->magic != HASH_RECORD_MAGIC) {
        return {};
    }

    const uint64_t nameEnd = offset + kHeader + rec->nameLength;
    if (rec->nameLength == 0 || rec->nameLength > MAX_NAME_LEN || nameEnd > view.fileSize) {
        return {};
    }

    const auto* namePtr = reinterpret_cast<const char*>(
        static_cast<const uint8_t*>(view.baseAddress) + offset + kHeader);

    try {
        return std::string(namePtr, rec->nameLength);
    }
    catch (...) {
        return {};
    }
}

// Read the ThreatLevel from an existing record (best-effort fallback)
[[nodiscard]] ThreatLevel ReadRecordThreatLevel(
    const MemoryMappedView& view,
    uint64_t offset) noexcept
{
    constexpr size_t kHeader = sizeof(HashSignatureRecord);
    if (!view.IsValid() || offset + kHeader > view.fileSize) {
        return ThreatLevel::Medium;
    }

    const auto* rec = view.GetAt<HashSignatureRecord>(offset);
    if (!rec || rec->magic != HASH_RECORD_MAGIC) {
        return ThreatLevel::Medium;
    }

    const ThreatLevel stored = static_cast<ThreatLevel>(rec->threatLevel);
    return IsValidThreatLevel(stored) ? stored : ThreatLevel::Medium;
}

// Elapsed-time helper (microseconds) with overflow protection
[[nodiscard]] uint64_t ElapsedMicroseconds(
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    const LARGE_INTEGER& freq) noexcept
{
    if (freq.QuadPart <= 0 || end.QuadPart < start.QuadPart) {
        return 0;
    }
    const uint64_t elapsed = static_cast<uint64_t>(end.QuadPart - start.QuadPart);
    const uint64_t f       = static_cast<uint64_t>(freq.QuadPart);
    if (elapsed <= UINT64_MAX / 1000000ULL) {
        return (elapsed * 1000000ULL) / f;
    }
    return (elapsed / f) * 1000000ULL;
}

} // anonymous namespace

// ============================================================================
// AddHash — Insert a single hash signature
// ============================================================================

StoreError HashStore::AddHash(
    const HashValue& hash,
    const std::string& signatureName,
    ThreatLevel threatLevel,
    const std::string& description,
    const std::vector<std::string>& tags
) noexcept {

    // ====================================================================
    // 1. PRE-LOCK VALIDATION (lightweight, no lock needed)
    // ====================================================================

    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"HashStore", L"AddHash: Database not initialized");
        return StoreError{ SignatureStoreError::Unknown, 0, "Database not initialized" };
    }

    if (m_readOnly.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"HashStore", L"AddHash: Database is read-only");
        return StoreError{ SignatureStoreError::AccessDenied, 0, "Database is read-only" };
    }

    // ====================================================================
    // 2. INPUT VALIDATION — Security First
    // ====================================================================

    if (hash.length == 0 || hash.length > 64) {
        SS_LOG_ERROR(L"HashStore",
            L"AddHash: Invalid hash length %u (must be 1-64)", hash.length);
        return StoreError{ SignatureStoreError::InvalidSignature, 0, "Invalid hash length" };
    }

    const uint8_t expectedLen = ExpectedHashLength(hash.type);
    if (expectedLen == UINT8_MAX) {
        SS_LOG_ERROR(L"HashStore",
            L"AddHash: Unknown hash type %u", static_cast<uint8_t>(hash.type));
        return StoreError{ SignatureStoreError::InvalidSignature, 0, "Unknown hash type" };
    }
    if (expectedLen != 0 && hash.length != expectedLen) {
        SS_LOG_ERROR(L"HashStore",
            L"AddHash: Hash length mismatch for type %u (expected %u, got %u)",
            static_cast<uint8_t>(hash.type), expectedLen, hash.length);
        return StoreError{ SignatureStoreError::InvalidSignature, 0,
            "Hash length does not match declared type" };
    }

    if (signatureName.empty()) {
        SS_LOG_ERROR(L"HashStore", L"AddHash: Empty signature name");
        return StoreError{ SignatureStoreError::InvalidSignature, 0,
            "Signature name cannot be empty" };
    }
    if (signatureName.length() > MAX_NAME_LEN) {
        SS_LOG_ERROR(L"HashStore",
            L"AddHash: Signature name too long (%zu > %zu)",
            signatureName.length(), MAX_NAME_LEN);
        return StoreError{ SignatureStoreError::InvalidSignature, 0,
            "Signature name too long (max 256)" };
    }
    if (ContainsUnsafeChars(signatureName)) {
        SS_LOG_ERROR(L"HashStore",
            L"AddHash: Signature name contains null bytes or path separators");
        return StoreError{ SignatureStoreError::InvalidSignature, 0,
            "Signature name contains forbidden characters" };
    }

    if (description.length() > MAX_DESC_LEN) {
        SS_LOG_ERROR(L"HashStore",
            L"AddHash: Description too long (%zu > %zu)",
            description.length(), MAX_DESC_LEN);
        return StoreError{ SignatureStoreError::InvalidSignature, 0,
            "Description too long (max 4KB)" };
    }

    if (tags.size() > MAX_TAGS) {
        SS_LOG_ERROR(L"HashStore",
            L"AddHash: Too many tags (%zu > %zu)", tags.size(), MAX_TAGS);
        return StoreError{ SignatureStoreError::InvalidSignature, 0,
            "Too many tags (max 32)" };
    }
    for (const auto& tag : tags) {
        if (tag.empty() || tag.length() > MAX_TAG_LEN) {
            SS_LOG_ERROR(L"HashStore",
                L"AddHash: Invalid tag (empty or > %zu chars)", MAX_TAG_LEN);
            return StoreError{ SignatureStoreError::InvalidSignature, 0,
                "Invalid tag format" };
        }
    }

    if (!IsValidThreatLevel(threatLevel)) {
        SS_LOG_ERROR(L"HashStore",
            L"AddHash: Invalid threat level %u",
            static_cast<uint8_t>(threatLevel));
        return StoreError{ SignatureStoreError::InvalidSignature, 0,
            "Invalid threat level (must be Info/Low/Medium/High/Critical)" };
    }

    // ====================================================================
    // 3. SERIALIZE METADATA (before lock to minimize critical section)
    // ====================================================================

    std::string tagsJson;
    if (!tags.empty()) {
        if (!SerializeTagsJson(tags, tagsJson)) {
            SS_LOG_ERROR(L"HashStore", L"AddHash: Tags JSON serialization failed");
            return StoreError{ SignatureStoreError::Unknown, 0,
                "Tags serialization failed" };
        }
    }

    const size_t recordSize = sizeof(HashSignatureRecord) +
        signatureName.size() + description.size() + tagsJson.size();

    // ====================================================================
    // 4. ACQUIRE GLOBAL WRITE LOCK
    // ====================================================================

    LARGE_INTEGER startTime{};
    QueryPerformanceCounter(&startTime);

    std::unique_lock<std::shared_mutex> globalLock(m_globalLock);

    // Re-validate after lock (another thread may have closed the store)
    if (!m_initialized.load(std::memory_order_relaxed)) {
        SS_LOG_ERROR(L"HashStore", L"AddHash: Store closed during lock wait");
        return StoreError{ SignatureStoreError::Unknown, 0,
            "Database closed concurrently" };
    }

    // ====================================================================
    // 5. BUCKET LOOKUP & DUPLICATE CHECK (race-free under global lock)
    // ====================================================================

    HashBucket* bucket = GetBucket(hash.type);
    if (!bucket) {
        SS_LOG_ERROR(L"HashStore",
            L"AddHash: No bucket for hash type %u",
            static_cast<uint8_t>(hash.type));
        return StoreError{ SignatureStoreError::InvalidSignature, 0,
            "No bucket for hash type" };
    }

    // Authoritative check: bloom filter fast-path then B+Tree confirmation
    if (bucket->Contains(hash)) {
        SS_LOG_WARN(L"HashStore",
            L"AddHash: Duplicate hash: %S", signatureName.c_str());
        return StoreError{ SignatureStoreError::DuplicateEntry, 0,
            "Hash already exists in database" };
    }

    // ====================================================================
    // 6. ALLOCATE STORAGE & WRITE SIGNATURE RECORD
    // ====================================================================

    const uint64_t signatureOffset = AllocateSignatureEntry(recordSize);
    if (signatureOffset == UINT64_MAX) {
        SS_LOG_ERROR(L"HashStore",
            L"AddHash: Storage allocation failed (%zu bytes)", recordSize);
        return StoreError{ SignatureStoreError::OutOfMemory, 0,
            "Failed to allocate space for signature entry" };
    }

    if (!WriteSignatureRecord(m_mappedView, signatureOffset,
            hash.type, threatLevel, signatureName, description, tagsJson)) {
        SS_LOG_ERROR(L"HashStore",
            L"AddHash: Failed to write record at offset 0x%llX", signatureOffset);
        return StoreError{ SignatureStoreError::Unknown, 0,
            "Failed to write signature data to database" };
    }

    // ====================================================================
    // 7. INSERT INTO B+TREE (also adds to bloom filter inside bucket)
    // ====================================================================

    StoreError insertErr = bucket->Insert(hash, signatureOffset);
    if (!insertErr.IsSuccess()) {
        // Bloom filter may now contain this hash (benign false positive).
        // The B+Tree is authoritative; compaction will reclaim the leaked space.
        SS_LOG_ERROR(L"HashStore",
            L"AddHash: Index insertion failed: %S", insertErr.message.c_str());
        return insertErr;
    }

    // ====================================================================
    // 8. CACHE INVALIDATION — purge stale negative lookups for this hash
    // ====================================================================

    ClearCache();

    // ====================================================================
    // 9. PERFORMANCE TRACKING
    // ====================================================================

    LARGE_INTEGER endTime{};
    QueryPerformanceCounter(&endTime);
    const uint64_t insertTimeUs = ElapsedMicroseconds(startTime, endTime, m_perfFrequency);

    SS_LOG_INFO(L"HashStore",
        L"AddHash: Added %S (type=%u, threat=%u, offset=0x%llX, time=%llu us)",
        signatureName.c_str(), static_cast<uint8_t>(hash.type),
        static_cast<uint8_t>(threatLevel), signatureOffset, insertTimeUs);

    return StoreError{ SignatureStoreError::Success };
}

// ============================================================================
// AddHashBatch — Bulk-insert hash signatures (grouped by type for cache
//                efficiency, single global lock for atomicity)
// ============================================================================

StoreError HashStore::AddHashBatch(
    std::span<const HashValue> hashes,
    std::span<const std::string> signatureNames,
    std::span<const ThreatLevel> threatLevels
) noexcept {

    // ====================================================================
    // 1. PRE-LOCK VALIDATION
    // ====================================================================

    if (hashes.empty()) {
        SS_LOG_WARN(L"HashStore", L"AddHashBatch: Empty batch");
        return StoreError{ SignatureStoreError::InvalidSignature, 0, "Empty batch" };
    }

    if (hashes.size() != signatureNames.size() ||
        hashes.size() != threatLevels.size()) {
        SS_LOG_ERROR(L"HashStore",
            L"AddHashBatch: Mismatched span sizes (%zu, %zu, %zu)",
            hashes.size(), signatureNames.size(), threatLevels.size());
        return StoreError{ SignatureStoreError::InvalidSignature, 0,
            "Span size mismatch" };
    }

    if (hashes.size() > MAX_BATCH_SIZE) {
        SS_LOG_ERROR(L"HashStore",
            L"AddHashBatch: Batch too large (%zu > %zu)",
            hashes.size(), MAX_BATCH_SIZE);
        return StoreError{ SignatureStoreError::InvalidSignature, 0,
            "Batch too large (max 100K entries)" };
    }

    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"HashStore", L"AddHashBatch: Database not initialized");
        return StoreError{ SignatureStoreError::Unknown, 0, "Database not initialized" };
    }

    if (m_readOnly.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"HashStore", L"AddHashBatch: Database is read-only");
        return StoreError{ SignatureStoreError::AccessDenied, 0, "Database is read-only" };
    }

    SS_LOG_INFO(L"HashStore",
        L"AddHashBatch: Starting batch insert of %zu hashes", hashes.size());

    // ====================================================================
    // 2. PRE-VALIDATION PASS (before lock to minimize critical section)
    // ====================================================================

    std::unordered_set<size_t> invalidSet;
    size_t validCount = 0;

    for (size_t i = 0; i < hashes.size(); ++i) {
        const auto& h    = hashes[i];
        const auto& name = signatureNames[i];
        bool bad = false;

        // Hash basics
        if (h.length == 0 || h.length > 64) {
            bad = true;
        }

        // Type-specific length
        if (!bad) {
            const uint8_t expected = ExpectedHashLength(h.type);
            if (expected == UINT8_MAX) {
                bad = true;   // Unknown type
            } else if (expected != 0 && h.length != expected) {
                bad = true;
            }
        }

        // Name validation
        if (!bad) {
            if (name.empty() || name.length() > MAX_NAME_LEN || ContainsUnsafeChars(name)) {
                bad = true;
            }
        }

        // Threat level
        if (!bad && !IsValidThreatLevel(threatLevels[i])) {
            bad = true;
        }

        if (bad) {
            SS_LOG_WARN(L"HashStore",
                L"AddHashBatch: Invalid entry at index %zu", i);
            invalidSet.insert(i);
        } else {
            ++validCount;
        }
    }

    if (validCount == 0) {
        SS_LOG_ERROR(L"HashStore",
            L"AddHashBatch: All %zu entries are invalid", hashes.size());
        return StoreError{ SignatureStoreError::InvalidSignature, 0,
            "No valid entries in batch" };
    }

    // ====================================================================
    // 3. GROUP BY HASH TYPE (cache-friendly ordering)
    // ====================================================================

    std::map<HashType, std::vector<size_t>> indexesByType;
    for (size_t i = 0; i < hashes.size(); ++i) {
        if (invalidSet.find(i) == invalidSet.end()) {
            indexesByType[hashes[i].type].push_back(i);
        }
    }

    // ====================================================================
    // 4. ACQUIRE GLOBAL WRITE LOCK
    // ====================================================================

    LARGE_INTEGER batchStartTime{};
    QueryPerformanceCounter(&batchStartTime);

    std::unique_lock<std::shared_mutex> globalLock(m_globalLock);

    if (!m_initialized.load(std::memory_order_relaxed)) {
        SS_LOG_ERROR(L"HashStore", L"AddHashBatch: Store closed during lock wait");
        return StoreError{ SignatureStoreError::Unknown, 0,
            "Database closed concurrently" };
    }

    // ====================================================================
    // 5. BATCH INSERT BY TYPE
    // ====================================================================

    size_t successCount   = 0;
    size_t failureCount   = 0;
    size_t duplicateCount = 0;
    std::string lastError;

    for (auto& [hashType, typeIndices] : indexesByType) {
        HashBucket* bucket = GetBucket(hashType);
        if (!bucket) {
            SS_LOG_ERROR(L"HashStore",
                L"AddHashBatch: No bucket for hash type %u",
                static_cast<uint8_t>(hashType));
            failureCount += typeIndices.size();
            continue;
        }

        // Intra-batch dedup via fast-hash set
        std::unordered_set<uint64_t> seenFastHashes;
        seenFastHashes.reserve(typeIndices.size());

        std::vector<std::pair<HashValue, uint64_t>> batchEntries;
        batchEntries.reserve(typeIndices.size());

        for (const size_t idx : typeIndices) {
            const uint64_t fh = hashes[idx].FastHash();

            if (seenFastHashes.find(fh) != seenFastHashes.end()) {
                SS_LOG_WARN(L"HashStore",
                    L"AddHashBatch: Intra-batch duplicate at index %zu", idx);
                ++duplicateCount;
                continue;
            }
            seenFastHashes.insert(fh);

            if (bucket->Contains(hashes[idx])) {
                SS_LOG_WARN(L"HashStore",
                    L"AddHashBatch: Already exists at index %zu", idx);
                ++duplicateCount;
                continue;
            }

            // Allocate storage for this entry
            const size_t entrySize = sizeof(HashSignatureRecord) +
                signatureNames[idx].size();
            const uint64_t offset = AllocateSignatureEntry(entrySize);
            if (offset == UINT64_MAX) {
                SS_LOG_ERROR(L"HashStore",
                    L"AddHashBatch: Allocation failed at index %zu", idx);
                ++failureCount;
                lastError = "Storage allocation failed";
                continue;
            }

            if (!WriteSignatureRecord(m_mappedView, offset,
                    hashes[idx].type, threatLevels[idx],
                    signatureNames[idx], {}, {})) {
                SS_LOG_ERROR(L"HashStore",
                    L"AddHashBatch: Write failed at index %zu", idx);
                ++failureCount;
                lastError = "Failed to write signature data";
                continue;
            }

            batchEntries.emplace_back(hashes[idx], offset);
        }

        if (!batchEntries.empty()) {
            StoreError batchErr = bucket->BatchInsert(batchEntries);
            if (batchErr.IsSuccess()) {
                successCount += batchEntries.size();
            } else {
                SS_LOG_ERROR(L"HashStore",
                    L"AddHashBatch: BatchInsert failed: %S",
                    batchErr.message.c_str());
                failureCount += batchEntries.size();
                lastError = batchErr.message;
            }
        }
    }

    // ====================================================================
    // 6. CACHE INVALIDATION
    // ====================================================================

    if (successCount > 0) {
        ClearCache();
    }

    // ====================================================================
    // 7. PERFORMANCE LOGGING
    // ====================================================================

    LARGE_INTEGER batchEndTime{};
    QueryPerformanceCounter(&batchEndTime);
    const uint64_t batchTimeUs = ElapsedMicroseconds(
        batchStartTime, batchEndTime, m_perfFrequency);

    double throughput = 0.0;
    if (successCount > 0 && batchTimeUs > 0) {
        const double seconds = static_cast<double>(batchTimeUs) / 1000000.0;
        if (seconds > 0.0) {
            throughput = static_cast<double>(successCount) / seconds;
        }
    }

    SS_LOG_INFO(L"HashStore",
        L"AddHashBatch: Done — Success=%zu, Failed=%zu, "
        L"Duplicates=%zu, Invalid=%zu, Time=%llu us, Throughput=%.2f ops/sec",
        successCount, failureCount, duplicateCount, invalidSet.size(),
        batchTimeUs, throughput);

    // ====================================================================
    // 8. RETURN STATUS
    // ====================================================================

    if (successCount == 0) {
        return StoreError{ SignatureStoreError::InvalidSignature, 0,
            "No hashes were added: " + lastError };
    }

    // Partial success is still reported as Success; callers check logs for details.
    if (failureCount > 0 || duplicateCount > 0) {
        SS_LOG_WARN(L"HashStore",
            L"AddHashBatch: Partial — %zu of %zu added",
            successCount, hashes.size());
    }

    return StoreError{ SignatureStoreError::Success };
}

// ============================================================================
// RemoveHash — Remove a hash from the B+Tree index
// ============================================================================
//
// IMPORTANT: Standard bloom filters cannot delete elements. After removal
// the bloom filter may still report the removed hash as "possibly present",
// causing a benign false positive on the fast path. The B+Tree is always
// authoritative. Call Rebuild() after bulk removals to purge stale bits.
//

StoreError HashStore::RemoveHash(const HashValue& hash) noexcept {

    // ====================================================================
    // 1. VALIDATION
    // ====================================================================

    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"HashStore", L"RemoveHash: Database not initialized");
        return StoreError{ SignatureStoreError::Unknown, 0, "Database not initialized" };
    }

    if (m_readOnly.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"HashStore", L"RemoveHash: Database is read-only");
        return StoreError{ SignatureStoreError::AccessDenied, 0, "Database is read-only" };
    }

    if (hash.length == 0 || hash.length > 64) {
        SS_LOG_ERROR(L"HashStore",
            L"RemoveHash: Invalid hash length %u", hash.length);
        return StoreError{ SignatureStoreError::InvalidSignature, 0, "Invalid hash length" };
    }

    const uint8_t expectedLen = ExpectedHashLength(hash.type);
    if (expectedLen == UINT8_MAX) {
        SS_LOG_ERROR(L"HashStore",
            L"RemoveHash: Unknown hash type %u", static_cast<uint8_t>(hash.type));
        return StoreError{ SignatureStoreError::InvalidSignature, 0, "Unknown hash type" };
    }

    SS_LOG_DEBUG(L"HashStore", L"RemoveHash: type=%S",
        Format::HashTypeToString(hash.type));

    // ====================================================================
    // 2. ACQUIRE GLOBAL WRITE LOCK & BUCKET LOOKUP
    // ====================================================================

    std::unique_lock<std::shared_mutex> globalLock(m_globalLock);

    HashBucket* bucket = GetBucket(hash.type);
    if (!bucket) {
        SS_LOG_ERROR(L"HashStore", L"RemoveHash: Bucket not found for type %S",
            Format::HashTypeToString(hash.type));
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Bucket not found" };
    }

    // ====================================================================
    // 3. REMOVE FROM B+TREE (bloom filter bits remain — by design)
    // ====================================================================

    StoreError err = bucket->Remove(hash);
    if (!err.IsSuccess()) {
        SS_LOG_WARN(L"HashStore",
            L"RemoveHash: Removal failed: %S (hash may not exist)",
            err.message.c_str());
        return err;
    }

    // ====================================================================
    // 4. CACHE INVALIDATION
    // ====================================================================

    ClearCache();

    SS_LOG_INFO(L"HashStore",
        L"RemoveHash: Removed hash (type=%S, fastHash=0x%llX)",
        Format::HashTypeToString(hash.type), hash.FastHash());

    return StoreError{ SignatureStoreError::Success };
}

// ============================================================================
// UpdateHashMetadata — Atomically update description & tags for an
//                      existing hash entry
// ============================================================================
//
// Implementation strategy:
//   1. Look up the existing offset to confirm the hash exists
//   2. Read the existing signature name and threat level (preserved)
//   3. Allocate a new record region for the updated metadata
//   4. Write the updated record
//   5. Atomically swap the B+Tree mapping (Remove old + Insert new)
//      with rollback if the Insert fails
//   6. Invalidate the query cache
//

StoreError HashStore::UpdateHashMetadata(
    const HashValue& hash,
    const std::string& newDescription,
    const std::vector<std::string>& newTags
) noexcept {

    // ====================================================================
    // 1. STATE VALIDATION
    // ====================================================================

    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"HashStore", L"UpdateHashMetadata: Database not initialized");
        return StoreError{ SignatureStoreError::Unknown, 0, "Database not initialized" };
    }

    if (m_readOnly.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"HashStore",
            L"UpdateHashMetadata: Attempt to update in read-only mode");
        return StoreError{ SignatureStoreError::AccessDenied, 0, "Database is read-only" };
    }

    // ====================================================================
    // 2. INPUT VALIDATION
    // ====================================================================

    if (hash.length == 0 || hash.length > 64) {
        SS_LOG_ERROR(L"HashStore",
            L"UpdateHashMetadata: Invalid hash length %u", hash.length);
        return StoreError{ SignatureStoreError::InvalidSignature, 0, "Invalid hash length" };
    }

    // Consistent with AddHash limit
    if (newDescription.length() > MAX_DESC_LEN) {
        SS_LOG_ERROR(L"HashStore",
            L"UpdateHashMetadata: Description too long (%zu > %zu)",
            newDescription.length(), MAX_DESC_LEN);
        return StoreError{ SignatureStoreError::InvalidFormat, 0,
            "Description too long (max 4KB)" };
    }

    // Validate description for control characters
    for (size_t i = 0; i < newDescription.length(); ++i) {
        const auto ch = static_cast<unsigned char>(newDescription[i]);
        if (ch < 0x20 && ch != '\t' && ch != '\n' && ch != '\r') {
            SS_LOG_ERROR(L"HashStore",
                L"UpdateHashMetadata: Invalid control char at position %zu", i);
            return StoreError{ SignatureStoreError::InvalidFormat, 0,
                "Description contains invalid characters" };
        }
    }

    if (newTags.size() > MAX_TAGS) {
        SS_LOG_ERROR(L"HashStore",
            L"UpdateHashMetadata: Too many tags (%zu > %zu)",
            newTags.size(), MAX_TAGS);
        return StoreError{ SignatureStoreError::InvalidFormat, 0,
            "Too many tags (max 32)" };
    }

    std::unordered_set<std::string> uniqueTags;
    for (size_t i = 0; i < newTags.size(); ++i) {
        const auto& tag = newTags[i];

        if (tag.empty() || tag.length() > MAX_TAG_LEN) {
            SS_LOG_ERROR(L"HashStore",
                L"UpdateHashMetadata: Invalid tag at index %zu (len=%zu)",
                i, tag.length());
            return StoreError{ SignatureStoreError::InvalidFormat, 0,
                "Invalid tag format (1-64 chars)" };
        }

        if (tag.front() == ' ' || tag.back() == ' ') {
            SS_LOG_ERROR(L"HashStore",
                L"UpdateHashMetadata: Tag %zu has leading/trailing whitespace", i);
            return StoreError{ SignatureStoreError::InvalidFormat, 0,
                "Tags must not have leading/trailing whitespace" };
        }

        for (size_t j = 0; j < tag.length(); ++j) {
            const auto ch = static_cast<unsigned char>(tag[j]);
            if (!std::isalnum(ch) && ch != '-' && ch != '_') {
                SS_LOG_ERROR(L"HashStore",
                    L"UpdateHashMetadata: Bad char in tag %zu pos %zu", i, j);
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "Tags must be alphanumeric with '-' and '_' only" };
            }
        }

        if (!uniqueTags.insert(tag).second) {
            SS_LOG_WARN(L"HashStore",
                L"UpdateHashMetadata: Duplicate tag: %S", tag.c_str());
            return StoreError{ SignatureStoreError::InvalidFormat, 0,
                "Duplicate tags not allowed" };
        }
    }

    // ====================================================================
    // 3. SERIALIZE TAGS (before lock)
    // ====================================================================

    std::string tagsJson;
    if (!newTags.empty()) {
        if (!SerializeTagsJson(newTags, tagsJson)) {
            SS_LOG_ERROR(L"HashStore",
                L"UpdateHashMetadata: Tags JSON serialization failed");
            return StoreError{ SignatureStoreError::Unknown, 0,
                "Tags serialization failed" };
        }
    }

    // ====================================================================
    // 4. ACQUIRE GLOBAL WRITE LOCK
    // ====================================================================

    LARGE_INTEGER startTime{};
    QueryPerformanceCounter(&startTime);

    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    if (!m_initialized.load(std::memory_order_relaxed)) {
        SS_LOG_ERROR(L"HashStore",
            L"UpdateHashMetadata: Store closed during lock wait");
        return StoreError{ SignatureStoreError::Unknown, 0,
            "Database closed concurrently" };
    }

    // ====================================================================
    // 5. LOOKUP EXISTING HASH
    // ====================================================================

    HashBucket* bucket = GetBucket(hash.type);
    if (!bucket) {
        SS_LOG_ERROR(L"HashStore",
            L"UpdateHashMetadata: Bucket not found for type %S",
            Format::HashTypeToString(hash.type));
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Bucket not found" };
    }

    auto oldOffset = bucket->Lookup(hash);
    if (!oldOffset.has_value()) {
        SS_LOG_WARN(L"HashStore",
            L"UpdateHashMetadata: Hash not found (type=%S, length=%u)",
            Format::HashTypeToString(hash.type), hash.length);
        return StoreError{ SignatureStoreError::InvalidSignature, 0,
            "Hash not found in database" };
    }

    // ====================================================================
    // 6. READ PRESERVED FIELDS FROM EXISTING RECORD
    // ====================================================================

    const std::string existingName = ReadRecordName(m_mappedView, *oldOffset);
    const ThreatLevel existingThreat = ReadRecordThreatLevel(m_mappedView, *oldOffset);

    // ====================================================================
    // 7. ALLOCATE NEW STORAGE & WRITE UPDATED RECORD
    // ====================================================================

    const size_t newRecordSize = sizeof(HashSignatureRecord) +
        existingName.size() + newDescription.size() + tagsJson.size();

    const uint64_t newOffset = AllocateSignatureEntry(newRecordSize);
    if (newOffset == UINT64_MAX) {
        SS_LOG_ERROR(L"HashStore",
            L"UpdateHashMetadata: Storage allocation failed (%zu bytes)",
            newRecordSize);
        return StoreError{ SignatureStoreError::OutOfMemory, 0,
            "Failed to allocate space for updated metadata" };
    }

    if (!WriteSignatureRecord(m_mappedView, newOffset,
            hash.type, existingThreat, existingName,
            newDescription, tagsJson)) {
        SS_LOG_ERROR(L"HashStore",
            L"UpdateHashMetadata: Write failed at offset 0x%llX", newOffset);
        return StoreError{ SignatureStoreError::Unknown, 0,
            "Failed to write updated metadata" };
    }

    // ====================================================================
    // 8. ATOMIC B+TREE REMAPPING (Remove + Insert under global lock)
    // ====================================================================

    StoreError removeErr = bucket->Remove(hash);
    if (!removeErr.IsSuccess()) {
        SS_LOG_ERROR(L"HashStore",
            L"UpdateHashMetadata: Failed to remove old mapping: %S",
            removeErr.message.c_str());
        return removeErr;
    }

    StoreError insertErr = bucket->Insert(hash, newOffset);
    if (!insertErr.IsSuccess()) {
        // CRITICAL: Rollback — re-insert with old offset to avoid data loss
        SS_LOG_ERROR(L"HashStore",
            L"UpdateHashMetadata: Insert with new offset failed, rolling back");
        StoreError rollback = bucket->Insert(hash, *oldOffset);
        if (!rollback.IsSuccess()) {
            SS_LOG_ERROR(L"HashStore",
                L"UpdateHashMetadata: CRITICAL — Rollback also failed; "
                L"hash 0x%llX may be lost", hash.FastHash());
        }
        return insertErr;
    }

    // ====================================================================
    // 9. CACHE INVALIDATION
    // ====================================================================

    ClearCache();

    // ====================================================================
    // 10. AUDIT LOG
    // ====================================================================

    LARGE_INTEGER endTime{};
    QueryPerformanceCounter(&endTime);
    const uint64_t updateTimeUs = ElapsedMicroseconds(startTime, endTime, m_perfFrequency);

    SS_LOG_INFO(L"HashStore",
        L"UpdateHashMetadata: Updated (old=0x%llX, new=0x%llX, "
        L"desc_len=%zu, tags=%zu, time=%llu us)",
        *oldOffset, newOffset, newDescription.size(),
        newTags.size(), updateTimeUs);

    return StoreError{ SignatureStoreError::Success };
}

} // namespace HashStore
} // namespace ShadowStrike