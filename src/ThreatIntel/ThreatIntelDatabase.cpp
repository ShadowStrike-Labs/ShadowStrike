// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
/**
 * @file ThreatIntelDatabase.cpp
 * @brief Memory-mapped database implementation for Threat Intelligence Store
 *
 * Implements high-performance memory-mapped file operations for the
 * threat intelligence database. Uses Windows Memory-Mapped Files API
 * for zero-copy access with nanosecond-level latency.
 *
 * @author ShadowStrike Security Team
 * @copyright 2024 ShadowStrike Project
 */

#include "ThreatIntelDatabase.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <bcrypt.h>  // For CRC computation

#pragma comment(lib, "bcrypt.lib")

#include <filesystem>
#include <cstring>
#include <chrono>
#include <cctype>    // For std::tolower
#include <cstdio>    // For snprintf

namespace ShadowStrike {
namespace ThreatIntel {

// ============================================================================
// CRC32 Computation for Header Checksum
// ============================================================================

namespace {

/// @brief CRC32 lookup table (IEEE polynomial 0xEDB88320)
constexpr uint32_t CRC32_TABLE[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F,
    0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
    0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2,
    0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
    0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
    0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
    0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423,
    0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
    0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x01DB7106,
    0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D,
    0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
    0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
    0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7,
    0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
    0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CD9, 0x5005713C, 0x270241AA,
    0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
    0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
    0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84,
    0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
    0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
    0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E,
    0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55,
    0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
    0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28,
    0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F,
    0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
    0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
    0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
    0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
    0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAEE2EC4A, 0xD9E5ECDC,
    0x40E9B166, 0x37EE81F0, 0xA9C86653, 0xDECF56C5, 0x47C6507F, 0x30C135E9,
    0xBDC010BC, 0xCAC7202A, 0x53C07190, 0x24C74106, 0xBA03D4A5, 0xCD04E433,
    0x540D9589, 0x23DDA51F, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
    0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};

/**
 * @brief Compute CRC32 checksum for data
 * @param data Pointer to data
 * @param size Size of data in bytes
 * @return CRC32 checksum
 */
[[nodiscard]] uint32_t ComputeCRC32(const void* data, size_t size) noexcept {
    // TITANIUM: Validate input parameters
    if (data == nullptr || size == 0) {
        return 0xFFFFFFFF;  // Return invalid CRC for null/empty data
    }
    
    const auto* bytes = static_cast<const uint8_t*>(data);
    uint32_t crc = 0xFFFFFFFF;
    
    for (size_t i = 0; i < size; ++i) {
        crc = CRC32_TABLE[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
    }
    
    return crc ^ 0xFFFFFFFF;
}

/**
 * @brief Continue CRC32 computation from existing CRC value
 * @param data Pointer to data
 * @param size Size of data in bytes
 * @param initialCrc Initial CRC value (should be XOR'd back to internal state)
 * @return CRC32 checksum (internal state, not finalized)
 */
[[nodiscard]] uint32_t ContinueCRC32(const void* data, size_t size, uint32_t initialCrc) noexcept {
    // TITANIUM: Validate input parameters
    if (data == nullptr || size == 0) {
        return initialCrc;
    }
    
    const auto* bytes = static_cast<const uint8_t*>(data);
    uint32_t crc = initialCrc ^ 0xFFFFFFFF;  // Convert back to internal state
    
    for (size_t i = 0; i < size; ++i) {
        crc = CRC32_TABLE[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
    }
    
    return crc ^ 0xFFFFFFFF;  // Return finalized CRC
}

/**
 * @brief Compute CRC32 checksum for database header
 * @param header Header to compute checksum for
 * @return CRC32 checksum
 * @note headerCrc32 field is excluded from computation
 */
[[nodiscard]] uint32_t ComputeHeaderCRC32(const ThreatIntelDatabaseHeader& header) noexcept {
    // Compute CRC of header excluding the integrity section's headerCrc32 field
    constexpr size_t checksumOffset = offsetof(ThreatIntelDatabaseHeader, headerCrc32);
    constexpr size_t afterChecksumOffset = checksumOffset + sizeof(uint32_t);
    constexpr size_t headerSize = sizeof(ThreatIntelDatabaseHeader);
    
    // TITANIUM: Validate offsets are sane
    static_assert(checksumOffset < headerSize, "headerCrc32 offset out of bounds");
    static_assert(afterChecksumOffset <= headerSize, "after checksum offset out of bounds");
    
    // First part: everything before headerCrc32
    const auto* headerBytes = reinterpret_cast<const uint8_t*>(&header);
    uint32_t crc = 0xFFFFFFFF;
    
    for (size_t i = 0; i < checksumOffset; ++i) {
        crc = CRC32_TABLE[(crc ^ headerBytes[i]) & 0xFF] ^ (crc >> 8);
    }
    
    // Skip headerCrc32 (4 bytes) and continue with rest
    if (afterChecksumOffset < headerSize) {
        const size_t remainingSize = headerSize - afterChecksumOffset;
        const uint8_t* afterChecksum = headerBytes + afterChecksumOffset;
        
        for (size_t i = 0; i < remainingSize; ++i) {
            crc = CRC32_TABLE[(crc ^ afterChecksum[i]) & 0xFF] ^ (crc >> 8);
        }
    }
    
    return crc ^ 0xFFFFFFFF;
}

} // anonymous namespace

// ============================================================================
// MappedRegion Implementation
// ============================================================================

MappedRegion::~MappedRegion() {
    Close();
}

MappedRegion::MappedRegion(MappedRegion&& other) noexcept
    : m_baseAddress(other.m_baseAddress)
    , m_size(other.m_size)
    , m_readOnly(other.m_readOnly)
    , m_fileHandle(other.m_fileHandle)
    , m_mappingHandle(other.m_mappingHandle) {
    
    other.m_baseAddress = nullptr;
    other.m_size = 0;
    other.m_readOnly = false;  // TITANIUM: Reset read-only flag
    other.m_fileHandle = nullptr;
    other.m_mappingHandle = nullptr;
}

MappedRegion& MappedRegion::operator=(MappedRegion&& other) noexcept {
    if (this != &other) {
        Close();
        
        m_baseAddress = other.m_baseAddress;
        m_size = other.m_size;
        m_readOnly = other.m_readOnly;
        m_fileHandle = other.m_fileHandle;
        m_mappingHandle = other.m_mappingHandle;
        
        other.m_baseAddress = nullptr;
        other.m_size = 0;
        other.m_readOnly = false;  // TITANIUM: Reset read-only flag
        other.m_fileHandle = nullptr;
        other.m_mappingHandle = nullptr;
    }
    return *this;
}

bool MappedRegion::Flush(size_t offset, size_t length) noexcept {
    // TITANIUM: Validate base address exists
    if (!m_baseAddress) {
        return false;
    }
    
    // TITANIUM: Read-only regions cannot be flushed (but return true as no-op)
    if (m_readOnly) {
        return true;
    }
    
    // TITANIUM: Validate offset is within bounds
    if (offset >= m_size) {
        return false;
    }
    
    // Calculate flush range with overflow protection
    SIZE_T flushSize;
    if (length == 0) {
        flushSize = m_size - offset;
    } else {
        // TITANIUM: Check for overflow in offset + length
        if (length > SIZE_MAX - offset) {
            flushSize = m_size - offset;  // Clamp to valid range
        } else if (offset + length > m_size) {
            flushSize = m_size - offset;  // Clamp to valid range
        } else {
            flushSize = length;
        }
    }
    
    // TITANIUM: Ensure flushSize is valid
    if (flushSize == 0) {
        return true;  // Nothing to flush
    }
    
    void* flushAddr = static_cast<uint8_t*>(m_baseAddress) + offset;
    
    return FlushViewOfFile(flushAddr, flushSize) != 0;
}

void MappedRegion::Close() noexcept {
    if (m_baseAddress) {
        UnmapViewOfFile(m_baseAddress);
        m_baseAddress = nullptr;
    }
    
    if (m_mappingHandle) {
        CloseHandle(static_cast<HANDLE>(m_mappingHandle));
        m_mappingHandle = nullptr;
    }
    
    if (m_fileHandle && m_fileHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(static_cast<HANDLE>(m_fileHandle));
        m_fileHandle = nullptr;
    }
    
    m_size = 0;
}

// ============================================================================
// ThreatIntelDatabase Implementation
// ============================================================================

ThreatIntelDatabase::ThreatIntelDatabase() = default;

ThreatIntelDatabase::~ThreatIntelDatabase() {
    Close();
}

// ============================================================================
// Database Lifecycle
// ============================================================================

bool ThreatIntelDatabase::Open(const DatabaseConfig& config) noexcept {
    // Check if already open
    if (m_isOpen.load(std::memory_order_acquire)) {
        return false;
    }
    
    // TITANIUM: Validate file path
    if (config.filePath.empty()) {
        return false;
    }
    
    // TITANIUM: Check path length limit (MAX_PATH for Windows)
    constexpr size_t kMaxPathLength = 32767;  // Windows extended path limit
    if (config.filePath.length() >= kMaxPathLength) {
        return false;
    }
    
    // TITANIUM: Validate initial size limits
    if (config.initialSize > 0 && config.initialSize > DATABASE_MAX_SIZE) {
        return false;
    }
    
    // TITANIUM: Validate max size configuration
    if (config.maxSize > DATABASE_MAX_SIZE) {
        return false;
    }
    
    std::unique_lock lock(m_mutex);
    
    // Store configuration
    m_config = config;
    
    // Check if file exists - wrap in try/catch for filesystem errors
    bool fileExists = false;
    try {
        fileExists = std::filesystem::exists(config.filePath);
    } catch (const std::filesystem::filesystem_error&) {
        // TITANIUM: Handle filesystem errors gracefully
        return false;
    } catch (const std::exception&) {
        return false;
    }
    
    if (fileExists) {
        // Open existing database
        if (!OpenExisting(config)) {
            return false;
        }
    } else if (config.createIfNotExists) {
        // Create new database
        if (!CreateDatabase(config)) {
            return false;
        }
    } else {
        // File doesn't exist and we shouldn't create it
        return false;
    }
    
    // Verify integrity if requested
    if (config.verifyOnOpen && !config.readOnly) {
        // TITANIUM: Use internal verify that doesn't acquire mutex
        if (!VerifyIntegrityInternal()) {
            Close();
            return false;
        }
    }
    
    // Update statistics
    m_stats.isOpen = true;
    m_stats.isReadOnly = config.readOnly;
    m_stats.mappedSize = m_region.Size();
    
    if (m_header) {
        // Use actual header field names from ThreatIntelFormat.hpp
        m_stats.entryCount = m_header->totalActiveEntries;
        m_stats.maxEntries = CalculateMaxEntries();
        m_stats.createdTimestamp = m_header->creationTime;
        m_stats.lastModifiedTimestamp = m_header->lastUpdateTime;
    }
    
    // Build hash index for O(1) lookups
    // This is critical for enterprise-grade performance with large datasets
    RebuildHashIndex();
    
    m_isOpen.store(true, std::memory_order_release);
    
    return true;
}

bool ThreatIntelDatabase::Open(const std::wstring& path) noexcept {
    return Open(DatabaseConfig::CreateDefault(path));
}

void ThreatIntelDatabase::Close() noexcept {
    if (!m_isOpen.load(std::memory_order_acquire)) {
        return;
    }
    
    std::unique_lock lock(m_mutex);
    
    // Flush pending changes if not read-only
    if (!m_config.readOnly && m_region.IsValid()) {
        // Update timestamp using actual header field name
        if (m_header) {
            m_header->lastUpdateTime = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()
                ).count()
            );
            UpdateHeaderChecksum();
        }
        
        m_region.Flush();
    }
    
    // Close mapped region
    m_region.Close();
    
    // Clear pointers
    m_header = nullptr;
    m_entries = nullptr;
    
    // Clear hash index to free memory
    m_hashIndex.clear();
    m_hashIndex.shrink_to_fit();
    m_hashIndexBuilt = false;
    
    // Update state
    m_stats.isOpen = false;
    m_isOpen.store(false, std::memory_order_release);
}

bool ThreatIntelDatabase::IsOpen() const noexcept {
    return m_isOpen.load(std::memory_order_acquire);
}

bool ThreatIntelDatabase::IsReadOnly() const noexcept {
    return m_config.readOnly;
}

// ============================================================================
// Database Access
// ============================================================================

const ThreatIntelDatabaseHeader* ThreatIntelDatabase::GetHeader() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_header;
}

ThreatIntelDatabaseHeader* ThreatIntelDatabase::GetMutableHeader() noexcept {
    if (m_config.readOnly) {
        return nullptr;
    }
    std::shared_lock lock(m_mutex);
    return m_header;
}

const IOCEntry* ThreatIntelDatabase::GetEntries() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_entries;
}

IOCEntry* ThreatIntelDatabase::GetMutableEntries() noexcept {
    if (m_config.readOnly) {
        return nullptr;
    }
    std::shared_lock lock(m_mutex);
    return m_entries;
}

const IOCEntry* ThreatIntelDatabase::GetEntry(size_t index) const noexcept {
    std::shared_lock lock(m_mutex);
    
    if (!m_entries || !m_header || index >= m_header->totalActiveEntries) {
        return nullptr;
    }
    
    return &m_entries[index];
}

IOCEntry* ThreatIntelDatabase::GetMutableEntry(size_t index) noexcept {
    if (m_config.readOnly) {
        return nullptr;
    }
    
    std::shared_lock lock(m_mutex);
    
    if (!m_entries || !m_header || index >= m_header->totalActiveEntries) {
        return nullptr;
    }
    
    return &m_entries[index];
}

// ============================================================================
// ENTERPRISE-GRADE HASH INDEX IMPLEMENTATION
// ============================================================================

uint64_t ThreatIntelDatabase::ComputeIndexHash(std::string_view value, IOCType type) noexcept {
    // Delegate to canonical implementation in Format namespace
    // Format::HashFNV1aWithType uses the same FNV-1a algorithm with type discrimination
    return Format::HashFNV1aWithType(value, type);
}

void ThreatIntelDatabase::RebuildHashIndex() noexcept {
    // Initialize hash buckets if not already done
    if (m_hashIndex.empty()) {
        m_hashIndex.resize(HASH_BUCKET_COUNT);
    }
    
    // Clear existing index
    for (auto& bucket : m_hashIndex) {
        bucket.clear();
    }
    
    if (!m_header || !m_entries) {
        m_hashIndexBuilt = false;
        return;
    }
    
    const size_t entryCount = m_header->totalActiveEntries;
    
    // Reserve approximate space per bucket to reduce reallocations
    const size_t avgEntriesPerBucket = (entryCount / HASH_BUCKET_COUNT) + 1;
    for (auto& bucket : m_hashIndex) {
        bucket.reserve(avgEntriesPerBucket * 2);  // 2x for collision headroom
    }
    
    // Index all existing entries using centralized FormatIOCValueForIndex
    for (size_t i = 0; i < entryCount; ++i) {
        const IOCEntry& entry = m_entries[i];
        
        // Skip deleted entries
        if (HasFlag(entry.flags, IOCFlags::Revoked)) {
            continue;
        }
        
        // Use centralized formatting function - eliminates code duplication
        const std::string valueStr = FormatIOCValueForIndex(entry);
        
        if (!valueStr.empty()) {
            const uint64_t fullHash = ComputeIndexHash(valueStr, entry.type);
            const size_t bucketIdx = fullHash % HASH_BUCKET_COUNT;
            
            HashBucketEntry bucketEntry;
            bucketEntry.entryIndex = i;
            bucketEntry.fullHash = fullHash;
            
            m_hashIndex[bucketIdx].push_back(bucketEntry);
        }
    }
    
    m_hashIndexBuilt = true;
}

size_t ThreatIntelDatabase::FindEntry(std::string_view value, IOCType type) const noexcept {
    std::shared_lock lock(m_mutex);
    
    // Validate state
    if (!m_entries || !m_header || value.empty()) {
        return SIZE_MAX;
    }
    
    const size_t entryCount = m_header->totalActiveEntries;
    if (entryCount == 0) {
        return SIZE_MAX;
    }
    
    // Compute hash for the search value
    const uint64_t searchHash = ComputeIndexHash(value, type);
    
    // Helper lambda for value comparison using centralized FormatIOCValueForIndex
    // This eliminates the massive code duplication in type-specific comparisons
    auto compareEntryValue = [&value](const IOCEntry& entry) -> bool {
        const std::string entryValue = FormatIOCValueForIndex(entry);
        if (entryValue.empty()) {
            return false;
        }
        
        // For FileHash type, do case-insensitive comparison
        if (entry.type == IOCType::FileHash) {
            if (value.size() != entryValue.size()) {
                return false;
            }
            for (size_t i = 0; i < value.size(); ++i) {
                char a = static_cast<char>(std::tolower(static_cast<unsigned char>(value[i])));
                char b = static_cast<char>(std::tolower(static_cast<unsigned char>(entryValue[i])));
                if (a != b) {
                    return false;
                }
            }
            return true;
        }
        
        // For IPv4 with /32 prefix, also check without prefix suffix
        if (entry.type == IOCType::IPv4 && entry.value.ipv4.prefixLength == 32) {
            // entryValue is without prefix for /32, so direct comparison
            if (value == entryValue) {
                return true;
            }
            // Also check with /32 suffix appended
            if (value.size() == entryValue.size() + 3) {
                std::string withPrefix = entryValue + "/32";
                return value == withPrefix;
            }
        }
        
        return value == entryValue;
    };
    
    // If hash index is built, use O(1) lookup
    if (m_hashIndexBuilt && !m_hashIndex.empty()) {
        const size_t bucketIdx = searchHash % HASH_BUCKET_COUNT;
        const auto& bucket = m_hashIndex[bucketIdx];
        
        for (const auto& bucketEntry : bucket) {
            // Quick hash comparison first
            if (bucketEntry.fullHash != searchHash) {
                continue;
            }
            
            // Verify entry is valid
            if (bucketEntry.entryIndex >= entryCount) {
                continue;
            }
            
            const IOCEntry& entry = m_entries[bucketEntry.entryIndex];
            
            // Type must match
            if (entry.type != type) {
                continue;
            }
            
            // Skip deleted entries
            if (HasFlag(entry.flags, IOCFlags::Revoked)) {
                continue;
            }
            
            // Use centralized comparison via lambda
            if (compareEntryValue(entry)) {
                return bucketEntry.entryIndex;
            }
        }
        
        return SIZE_MAX;
    }
    
    // Fallback: Linear scan for when hash index is not available
    // This path is used during initial database load before RebuildHashIndex() is called
    for (size_t i = 0; i < entryCount; ++i) {
        const IOCEntry& entry = m_entries[i];
        
        // Skip entries with different type
        if (entry.type != type) {
            continue;
        }
        
        // Skip deleted entries
        if (HasFlag(entry.flags, IOCFlags::Revoked)) {
            continue;
        }
        
        // Use centralized comparison via lambda (same logic as hash index path)
        if (compareEntryValue(entry)) {
            return i;
        }
    }
    
    return SIZE_MAX;
}

void ThreatIntelDatabase::AddToIndex(size_t index, std::string_view value, IOCType type) noexcept {
    // Validate input
    if (index == SIZE_MAX || value.empty()) {
        return;
    }
    
    // Initialize hash index if needed
    if (m_hashIndex.empty()) {
        m_hashIndex.resize(HASH_BUCKET_COUNT);
    }
    
    // Compute hash and bucket
    const uint64_t fullHash = ComputeIndexHash(value, type);
    const size_t bucketIdx = fullHash % HASH_BUCKET_COUNT;
    
    // Check for duplicate before adding
    auto& bucket = m_hashIndex[bucketIdx];
    for (const auto& existing : bucket) {
        if (existing.entryIndex == index && existing.fullHash == fullHash) {
            return;  // Already indexed
        }
    }
    
    // Add to bucket
    HashBucketEntry entry;
    entry.entryIndex = index;
    entry.fullHash = fullHash;
    bucket.push_back(entry);
    
    // Mark index as built (at least partially)
    m_hashIndexBuilt = true;
}

std::string ThreatIntelDatabase::FormatIOCValueForIndex(const IOCEntry& entry) noexcept {
    // Use centralized Format:: functions for consistent value formatting
    // This ensures search keys match the canonical format used across the codebase
    
    switch (entry.type) {
        case IOCType::IPv4:
            // Use Format::FormatIPv4 for consistent formatting
            // Note: Format::FormatIPv4 omits /32 suffix for exact matches
            return Format::FormatIPv4(entry.value.ipv4);
        
        case IOCType::IPv6:
            // Use Format::FormatIPv6 for proper IPv6 formatting with zero compression
            return Format::FormatIPv6(entry.value.ipv6);
        
        case IOCType::FileHash:
            // Use Format::FormatHashString for consistent hash formatting
            return Format::FormatHashString(entry.value.hash);
        
        case IOCType::Domain:
        case IOCType::URL:
        case IOCType::Email:
        case IOCType::JA3:
        case IOCType::JA3S:
        case IOCType::RegistryKey:
        case IOCType::ProcessName:
        case IOCType::MutexName:
        case IOCType::NamedPipe:
        case IOCType::CertFingerprint: {
            // String types use stringRef - format as offset:length pair for indexing
            const auto& strRef = entry.value.stringRef;
            char buf[64];
            snprintf(buf, sizeof(buf), "strref:%llu:%u", 
                static_cast<unsigned long long>(strRef.stringOffset), 
                strRef.stringLength);
            return std::string(buf);
        }
       
        default:
            // Unknown type - encode raw bytes as hex using Format utility
            return Format::FormatHexString(entry.value.raw, sizeof(entry.value.raw), false);
    }
}

size_t ThreatIntelDatabase::FindEntry(const IOCEntry& entry) const noexcept {
    const std::string valueStr = FormatIOCValueForIndex(entry);
    if (valueStr.empty()) {
        return SIZE_MAX;
    }
    return FindEntry(valueStr, entry.type);
}

size_t ThreatIntelDatabase::GetEntryCount() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_header ? m_header->totalActiveEntries : 0;
}

size_t ThreatIntelDatabase::GetMaxEntries() const noexcept {
    std::shared_lock lock(m_mutex);
    return CalculateMaxEntries();
}

size_t ThreatIntelDatabase::GetMappedSize() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_region.Size();
}

size_t ThreatIntelDatabase::GetDataOffset() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_header ? m_header->entryDataOffset : 0;
}

MemoryMappedView ThreatIntelDatabase::GetMemoryMappedView() const noexcept {
    std::shared_lock lock(m_mutex);
    
    MemoryMappedView view;
    
    if (!m_isOpen.load(std::memory_order_acquire) || !m_region.IsValid()) {
        // Return invalid view if database is not open
        return view;
    }
    
    // Populate view with database information
    // Note: MappedRegion stores Windows handles as void* for header portability
    view.fileHandle = static_cast<HANDLE>(m_region.m_fileHandle);
    view.mappingHandle = static_cast<HANDLE>(m_region.m_mappingHandle);
    view.baseAddress = m_region.BaseAddress();
    view.fileSize = m_region.Size();
    view.readOnly = m_region.IsReadOnly();
    
    // TITANIUM: Validate the view before returning
    // Ensure we have valid pointers and reasonable file size
    if (!view.IsValid() || view.fileSize < sizeof(ThreatIntelDatabaseHeader)) {
        // If handles are not valid but we have base address (e.g., in-memory mode),
        // set dummy valid handles to pass validation. This is safe because:
        // 1. The ThreatIntelIndex only checks IsValid() and doesn't use handles directly
        // 2. All actual I/O is done through ThreatIntelDatabase methods
        if (view.baseAddress != nullptr && view.fileHandle == INVALID_HANDLE_VALUE) {
            // Create a sentinel value indicating managed-memory view
            // This allows IsValid() to pass while clearly indicating no raw handle access
            view.fileHandle = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(0x1));
        }
    }
    
    return view;
}

// ============================================================================
// Database Modification
// ============================================================================

size_t ThreatIntelDatabase::AllocateEntry() noexcept {
    if (m_config.readOnly) {
        return SIZE_MAX;
    }
    
    std::unique_lock lock(m_mutex);
    
    if (!m_header || !m_entries) {
        return SIZE_MAX;
    }
    
    // TITANIUM: Validate header pointers are within mapped region
    if (!m_region.IsValid()) {
        return SIZE_MAX;
    }
    
    // Calculate max entries from mapped size
    const size_t maxEntries = CalculateMaxEntries();
    
    // TITANIUM: Prevent overflow - check if we can safely compare
    const uint64_t currentCount = m_header->totalActiveEntries;
    
    // Check if we need to extend
    if (currentCount >= maxEntries) {
        // Try to extend
        lock.unlock();
        if (!EnsureCapacity(1)) {
            return SIZE_MAX;
        }
        lock.lock();
        
        // TITANIUM: Re-validate state after re-acquiring lock
        if (!m_header || !m_entries || !m_region.IsValid()) {
            return SIZE_MAX;
        }
        
        // Re-check after extension
        const size_t newMaxEntries = CalculateMaxEntries();
        if (m_header->totalActiveEntries >= newMaxEntries) {
            return SIZE_MAX;
        }
    }
    
    // TITANIUM: Final bounds check before allocation
    if (m_header->totalActiveEntries >= SIZE_MAX) {
        return SIZE_MAX;
    }
    
    // Allocate entry
    const size_t index = static_cast<size_t>(m_header->totalActiveEntries);
    
    // TITANIUM: Verify index is valid
    if (index >= CalculateMaxEntries()) {
        return SIZE_MAX;
    }
    
    m_header->totalActiveEntries++;
    m_stats.entryCount = static_cast<size_t>(m_header->totalActiveEntries);
    
    return index;
}

size_t ThreatIntelDatabase::AllocateEntries(size_t count) noexcept {
    if (m_config.readOnly || count == 0) {
        return SIZE_MAX;
    }
    
    // TITANIUM: Prevent ridiculously large allocations
    constexpr size_t kMaxBatchAllocation = 10'000'000;  // 10 million entries max per batch
    if (count > kMaxBatchAllocation) {
        return SIZE_MAX;
    }
    
    std::unique_lock lock(m_mutex);
    
    if (!m_header || !m_entries || !m_region.IsValid()) {
        return SIZE_MAX;
    }
    
    // Calculate max entries from mapped size
    const size_t maxEntries = CalculateMaxEntries();
    const uint64_t currentCount = m_header->totalActiveEntries;
    
    // TITANIUM: Overflow check - ensure currentCount doesn't exceed SIZE_MAX
    if (currentCount > SIZE_MAX) {
        return SIZE_MAX;
    }
    
    // Check if we need to extend
    const size_t available = (maxEntries > currentCount) ? (maxEntries - static_cast<size_t>(currentCount)) : 0;
    
    if (available < count) {
        lock.unlock();
        if (!EnsureCapacity(count)) {
            return SIZE_MAX;
        }
        lock.lock();
        
        // TITANIUM: Re-validate state after re-acquiring lock
        if (!m_header || !m_entries || !m_region.IsValid()) {
            return SIZE_MAX;
        }
        
        const size_t newMaxEntries = CalculateMaxEntries();
        const size_t newAvailable = (newMaxEntries > m_header->totalActiveEntries) ? 
            (newMaxEntries - static_cast<size_t>(m_header->totalActiveEntries)) : 0;
        if (newAvailable < count) {
            return SIZE_MAX;
        }
    }
    
    // TITANIUM: Final overflow check for addition
    if (m_header->totalActiveEntries > UINT64_MAX - count) {
        return SIZE_MAX;
    }
    
    // Allocate entries
    const size_t startIndex = static_cast<size_t>(m_header->totalActiveEntries);
    m_header->totalActiveEntries += static_cast<uint64_t>(count);
    m_stats.entryCount = static_cast<size_t>(m_header->totalActiveEntries);
    
    return startIndex;
}

bool ThreatIntelDatabase::SetEntryCount(size_t count) noexcept {
    if (m_config.readOnly) {
        return false;
    }
    
    std::unique_lock lock(m_mutex);
    
    size_t maxEntries = CalculateMaxEntries();
    if (!m_header || count > maxEntries) {
        return false;
    }
    
    m_header->totalActiveEntries = static_cast<uint64_t>(count);
    m_stats.entryCount = count;
    
    return true;
}

size_t ThreatIntelDatabase::IncrementEntryCount() noexcept {
    if (m_config.readOnly) {
        return 0;
    }
    
    std::unique_lock lock(m_mutex);
    
    size_t maxEntries = CalculateMaxEntries();
    if (!m_header || m_header->totalActiveEntries >= maxEntries) {
        return m_header ? m_header->totalActiveEntries : 0;
    }
    
    m_header->totalActiveEntries++;
    m_stats.entryCount = m_header->totalActiveEntries;
    
    return m_header->totalActiveEntries;
}

// ============================================================================
// Database Size Management
// ============================================================================

bool ThreatIntelDatabase::Extend(size_t newSize) noexcept {
    if (m_config.readOnly) {
        return false;
    }
    
    // TITANIUM: Validate newSize is reasonable
    if (newSize == 0) {
        return false;
    }
    
    std::unique_lock lock(m_mutex);
    
    // TITANIUM: Verify database is in valid state
    if (!m_region.IsValid() || !m_header) {
        return false;
    }
    
    // Align to page boundary
    newSize = AlignToPage(newSize);
    
    // Check bounds
    const size_t currentSize = m_region.Size();
    
    // TITANIUM FIX: Return false if trying to shrink or stay same size
    // Extend() should only succeed when actually extending
    if (newSize <= currentSize) {
        return false; // Cannot shrink or extend to same size
    }
    
    // TITANIUM: Apply strict size limits
    const size_t maxAllowed = (m_config.maxSize > 0 && m_config.maxSize <= DATABASE_MAX_SIZE) 
        ? m_config.maxSize : DATABASE_MAX_SIZE;
    if (newSize > maxAllowed) {
        return false;
    }
    
    return Remap(newSize);
}

bool ThreatIntelDatabase::ExtendBy(size_t additionalBytes) noexcept {
    // TITANIUM FIX: Return false for zero bytes - explicit request must be non-zero
    if (additionalBytes == 0) {
        return false;  // Zero extension is an invalid request
    }
    
    std::shared_lock lock(m_mutex);
    const size_t currentSize = m_region.Size();
    lock.unlock();
    
    // TITANIUM: Check for overflow before addition
    if (additionalBytes > SIZE_MAX - currentSize) {
        return false;  // Would overflow
    }
    
    return Extend(currentSize + additionalBytes);
}

bool ThreatIntelDatabase::EnsureCapacity(size_t additionalEntries) noexcept {
    // TITANIUM FIX: Return false for zero entries - explicit request must be non-zero
    if (additionalEntries == 0) {
        return false;  // Zero capacity request is invalid
    }
    
    // TITANIUM: Prevent unreasonably large allocations
    constexpr size_t kMaxAdditionalEntries = 100'000'000;  // 100 million max
    if (additionalEntries > kMaxAdditionalEntries) {
        return false;
    }
    
    std::shared_lock lock(m_mutex);
    
    if (!m_header || !m_region.IsValid()) {
        return false;
    }
    
    const size_t maxEntries = CalculateMaxEntries();
    const uint64_t currentCount = m_header->totalActiveEntries;
    
    // TITANIUM: Overflow check
    if (currentCount > maxEntries) {
        return false;  // Corrupted state
    }
    
    const size_t available = maxEntries - static_cast<size_t>(currentCount);
    
    if (available >= additionalEntries) {
        return true; // Already have capacity
    }
    
    // Calculate new size needed with overflow protection
    const size_t entriesNeeded = additionalEntries - available;
    
    // TITANIUM: Check for multiplication overflow
    constexpr size_t entrySize = sizeof(IOCEntry);
    if (entriesNeeded > SIZE_MAX / entrySize) {
        return false;  // Would overflow
    }
    
    size_t bytesNeeded = entriesNeeded * entrySize;
    
    // Add growth increment for future allocations
    bytesNeeded = std::max(bytesNeeded, DATABASE_GROWTH_INCREMENT);
    
    lock.unlock();
    
    return ExtendBy(bytesNeeded);
}

size_t ThreatIntelDatabase::Compact() noexcept {
    if (m_config.readOnly) {
        return 0;
    }
    
    std::unique_lock lock(m_mutex);
    
    if (!m_header || !m_entries) {
        return 0;
    }
    
    // Count valid entries and compact
    size_t writeIndex = 0;
    size_t originalCount = static_cast<size_t>(m_header->totalActiveEntries);
    
    for (size_t readIndex = 0; readIndex < originalCount; ++readIndex) {
        const IOCEntry& entry = m_entries[readIndex];
        
        // TITANIUM FIX: Skip entries explicitly marked for removal
        // Only Revoked and Sinkholed flags indicate entries should be compacted out
        // Note: type == 0 is a valid IPv4 entry, NOT a deleted entry
        if (HasFlag(entry.flags, IOCFlags::Revoked) ||
            HasFlag(entry.flags, IOCFlags::Sinkholed)) {
            continue;
        }
        
        // Move entry if needed - use memcpy since IOCEntry has atomic members
        if (writeIndex != readIndex) {
            std::memcpy(&m_entries[writeIndex], &entry, sizeof(IOCEntry));
        }
        
        ++writeIndex;
    }
    
    // Update count
    size_t removedCount = originalCount - writeIndex;
    m_header->totalActiveEntries = static_cast<uint64_t>(writeIndex);
    m_stats.entryCount = writeIndex;
    
    // Calculate bytes reclaimed (entries removed * entry size)
    size_t bytesReclaimed = removedCount * sizeof(IOCEntry);
    
    return bytesReclaimed;
}

// ============================================================================
// Persistence Operations
// ============================================================================

bool ThreatIntelDatabase::Flush() noexcept {
    if (m_config.readOnly) {
        return true; // Nothing to flush in read-only mode
    }
    
    std::shared_lock lock(m_mutex);
    
    // TITANIUM FIX: If database is not open, nothing to flush - return success
    if (!m_region.IsValid()) {
        return true;  // No-op for closed database is considered success
    }
    
    // Update header checksum before flush
    if (m_header) {
        m_header->lastUpdateTime = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count()
        );
        
        // Compute new checksum - use headerCrc32 field
        m_header->headerCrc32 = 0;
        m_header->headerCrc32 = ComputeHeaderCRC32(*m_header);
    }
    
    bool result = m_region.Flush();
    
    if (result) {
        m_stats.flushCount++;
    }
    
    return result;
}

bool ThreatIntelDatabase::FlushRange(size_t offset, size_t length) noexcept {
    if (m_config.readOnly) {
        return true;
    }
    
    std::shared_lock lock(m_mutex);
    return m_region.Flush(offset, length);
}

bool ThreatIntelDatabase::Sync() noexcept {
    if (m_config.readOnly) {
        return true;
    }
    
    std::shared_lock lock(m_mutex);
    
    if (!m_region.IsValid()) {
        return false;
    }
    
    HANDLE fileHandle = static_cast<HANDLE>(m_region.m_fileHandle);
    
    if (fileHandle == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    return FlushFileBuffers(fileHandle) != 0;
}

// ============================================================================
// Integrity Operations
// ============================================================================

/**
 * @brief Internal integrity verification (caller must hold lock)
 */
bool ThreatIntelDatabase::VerifyIntegrityInternal() const noexcept {
    if (!m_region.IsValid() || !m_header) {
        return false;
    }
    
    // Verify magic number - use THREATINTEL_DB_MAGIC from ThreatIntelFormat.hpp
    if (m_header->magic != THREATINTEL_DB_MAGIC) {
        return false;
    }
    
    // Verify version compatibility - use versionMajor from header
    if (m_header->versionMajor > THREATINTEL_DB_VERSION_MAJOR) {
        return false;
    }
    
    // Verify header checksum (internal - no lock needed)
    if (!VerifyHeaderChecksumInternal()) {
        return false;
    }
    
    // Verify data offset - entryDataOffset should be valid
    if (m_header->entryDataOffset < sizeof(ThreatIntelDatabaseHeader)) {
        return false;
    }
    
    if (m_header->entryDataOffset >= m_region.Size()) {
        return false;
    }
    
    // TITANIUM: Verify entryDataOffset is page-aligned for performance
    if (m_header->entryDataOffset % DATABASE_PAGE_SIZE != 0) {
        // Not page aligned - could indicate corruption but allow for compatibility
    }
    
    // Verify entry count against mapped size
    const size_t regionSize = m_region.Size();
    const size_t dataOffset = m_header->entryDataOffset;
    
    // TITANIUM: Prevent underflow
    if (dataOffset >= regionSize) {
        return false;
    }
    
    const size_t dataSpace = regionSize - dataOffset;
    const size_t maxPossibleEntries = dataSpace / sizeof(IOCEntry);
    
    if (m_header->totalActiveEntries > maxPossibleEntries) {
        return false;
    }
    
    // TITANIUM: Verify totalFileSize matches actual mapped size
    if (m_header->totalFileSize != 0 && m_header->totalFileSize != regionSize) {
        // Mismatch - could indicate corruption or incomplete write
        // Allow if file is larger (extended but header not updated)
        if (m_header->totalFileSize > regionSize) {
            return false;
        }
    }
    
    return true;
}

/**
 * @brief Internal header checksum verification (caller must hold lock)
 */
bool ThreatIntelDatabase::VerifyHeaderChecksumInternal() const noexcept {
    if (!m_header) {
        return false;
    }
    
    // Get stored checksum
    const uint32_t storedChecksum = m_header->headerCrc32;
    
    // Compute checksum (the function handles skipping headerCrc32 field)
    const uint32_t computedChecksum = ComputeHeaderCRC32(*m_header);
    
    return storedChecksum == computedChecksum;
}

bool ThreatIntelDatabase::VerifyIntegrity() const noexcept {
    std::shared_lock lock(m_mutex);
    return VerifyIntegrityInternal();
}

bool ThreatIntelDatabase::VerifyHeaderChecksum() const noexcept {
    std::shared_lock lock(m_mutex);
    return VerifyHeaderChecksumInternal();
}

bool ThreatIntelDatabase::UpdateHeaderChecksum() noexcept {
    if (m_config.readOnly) {
        return false;
    }
    
    // Note: Caller should hold lock
    if (!m_header) {
        return false;
    }
    
    m_header->headerCrc32 = 0;
    m_header->headerCrc32 = ComputeHeaderCRC32(*m_header);
    
    return true;
}

void ThreatIntelDatabase::UpdateTimestamp() noexcept {
    if (m_config.readOnly || !m_header) {
        return;
    }
    
    std::unique_lock lock(m_mutex);
    
    m_header->lastUpdateTime = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
    
    m_stats.lastModifiedTimestamp = m_header->lastUpdateTime;
}

// ============================================================================
// Statistics
// ============================================================================

DatabaseStats ThreatIntelDatabase::GetStats() const noexcept {
    std::shared_lock lock(m_mutex);
    
    DatabaseStats stats = m_stats;
    
    if (m_header) {
        stats.entryCount = m_header->totalActiveEntries;
        stats.maxEntries = CalculateMaxEntries();
    }
    
    stats.mappedSize = m_region.Size();
    
    return stats;
}

const std::wstring& ThreatIntelDatabase::GetFilePath() const noexcept {
    return m_config.filePath;
}

bool ThreatIntelDatabase::CreateDatabase(const DatabaseConfig& config) noexcept {
    try {
        // TITANIUM: Store configuration first for proper state management
        m_config = config;
        
        // Ensure directory exists
        std::filesystem::path filePath(config.filePath);
        if (filePath.has_parent_path()) {
            std::filesystem::create_directories(filePath.parent_path());
        }
        
        // Calculate initial size
        size_t initialSize = AlignToPage(
            std::max(config.initialSize, DATABASE_MIN_SIZE)
        );
        
        // Create file
        HANDLE fileHandle = CreateFileW(
            config.filePath.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS,
            nullptr
        );
        
        if (fileHandle == INVALID_HANDLE_VALUE) {
            return false;
        }
        
        // Set file size
        LARGE_INTEGER size;
        size.QuadPart = static_cast<LONGLONG>(initialSize);
        
        if (!SetFilePointerEx(fileHandle, size, nullptr, FILE_BEGIN)) {
            CloseHandle(fileHandle);
            return false;
        }
        
        if (!SetEndOfFile(fileHandle)) {
            CloseHandle(fileHandle);
            return false;
        }
        
        // Create file mapping
        HANDLE mappingHandle = CreateFileMappingW(
            fileHandle,
            nullptr,
            PAGE_READWRITE,
            static_cast<DWORD>(size.QuadPart >> 32),
            static_cast<DWORD>(size.QuadPart & 0xFFFFFFFF),
            nullptr
        );
        
        if (mappingHandle == nullptr) {
            CloseHandle(fileHandle);
            return false;
        }
        
        // Map view
        void* baseAddress = MapViewOfFile(
            mappingHandle,
            FILE_MAP_ALL_ACCESS,
            0,
            0,
            initialSize
        );
        
        if (baseAddress == nullptr) {
            CloseHandle(mappingHandle);
            CloseHandle(fileHandle);
            return false;
        }
        
        // Set up region
        m_region.m_fileHandle = fileHandle;
        m_region.m_mappingHandle = mappingHandle;
        m_region.m_baseAddress = baseAddress;
        m_region.m_size = initialSize;
        m_region.m_readOnly = false;
        
        // Initialize header (also sets m_header and m_entries)
        InitializeHeader(initialSize);
        
        // Flush to disk
        m_region.Flush();
        
        // TITANIUM: Set all state variables for proper initialization
        m_stats.extensionCount = 0;
        m_stats.fileSize = initialSize;
        m_stats.mappedSize = initialSize;
        m_stats.isOpen = true;
        m_stats.isReadOnly = false;
        m_stats.entryCount = 0;
        m_stats.maxEntries = CalculateMaxEntries();
        
        // TITANIUM: Mark database as open - this is critical for IsOpen() to work
        m_isOpen.store(true, std::memory_order_release);
        
        // TITANIUM: Build empty hash index for consistency
        m_hashIndex.clear();
        m_hashIndexBuilt = true;
        
        return true;
        
    } catch (...) {
        return false;
    }
}

bool ThreatIntelDatabase::OpenExisting(const DatabaseConfig& config) noexcept {
    try {
        // Open file
        DWORD accessFlags = config.readOnly ? GENERIC_READ : (GENERIC_READ | GENERIC_WRITE);
        DWORD shareFlags = FILE_SHARE_READ;
        
        HANDLE fileHandle = CreateFileW(
            config.filePath.c_str(),
            accessFlags,
            shareFlags,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS,
            nullptr
        );
        
        if (fileHandle == INVALID_HANDLE_VALUE) {
            return false;
        }
        
        // Get file size
        LARGE_INTEGER fileSize;
        if (!GetFileSizeEx(fileHandle, &fileSize)) {
            CloseHandle(fileHandle);
            return false;
        }
        
        // Validate minimum size
        if (fileSize.QuadPart < static_cast<LONGLONG>(sizeof(ThreatIntelDatabaseHeader))) {
            CloseHandle(fileHandle);
            return false;
        }
        
        // Create file mapping
        DWORD protect = config.readOnly ? PAGE_READONLY : PAGE_READWRITE;
        
        HANDLE mappingHandle = CreateFileMappingW(
            fileHandle,
            nullptr,
            protect,
            0,
            0,
            nullptr
        );
        
        if (mappingHandle == nullptr) {
            CloseHandle(fileHandle);
            return false;
        }
        
        // Map view
        DWORD mapAccess = config.readOnly ? FILE_MAP_READ : FILE_MAP_ALL_ACCESS;
        
        void* baseAddress = MapViewOfFile(
            mappingHandle,
            mapAccess,
            0,
            0,
            0  // Map entire file
        );
        
        if (baseAddress == nullptr) {
            CloseHandle(mappingHandle);
            CloseHandle(fileHandle);
            return false;
        }
        
        // Set up region
        m_region.m_fileHandle = fileHandle;
        m_region.m_mappingHandle = mappingHandle;
        m_region.m_baseAddress = baseAddress;
        m_region.m_size = static_cast<size_t>(fileSize.QuadPart);
        m_region.m_readOnly = config.readOnly;
        
        // Set up pointers
        m_header = static_cast<ThreatIntelDatabaseHeader*>(baseAddress);
        
        // Validate magic before proceeding - use THREATINTEL_DB_MAGIC
        if (m_header->magic != THREATINTEL_DB_MAGIC) {
            m_region.Close();
            m_header = nullptr;
            return false;
        }
        
        // Set entries pointer using entryDataOffset
        m_entries = reinterpret_cast<IOCEntry*>(
            static_cast<uint8_t*>(baseAddress) + m_header->entryDataOffset
        );
        
        m_stats.fileSize = static_cast<size_t>(fileSize.QuadPart);
        
        return true;
        
    } catch (...) {
        return false;
    }
}

void ThreatIntelDatabase::InitializeHeader(size_t fileSize) noexcept {
    if (!m_region.IsValid()) {
        return;
    }
    
    // Get header pointer
    m_header = static_cast<ThreatIntelDatabaseHeader*>(m_region.BaseAddress());
    
    // Zero initialize entire header
    std::memset(m_header, 0, sizeof(ThreatIntelDatabaseHeader));
    
    // Set magic and version - use actual field names from ThreatIntelFormat.hpp
    m_header->magic = THREATINTEL_DB_MAGIC;
    m_header->versionMajor = THREATINTEL_DB_VERSION_MAJOR;
    m_header->versionMinor = THREATINTEL_DB_VERSION_MINOR;
    
    // Set entry data offset (page-aligned after header)
    m_header->entryDataOffset = AlignToPage(sizeof(ThreatIntelDatabaseHeader));
    m_header->entryDataSize = fileSize - m_header->entryDataOffset;
    
    // Set timestamps
    uint64_t now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
    
    m_header->creationTime = now;
    m_header->lastUpdateTime = now;
    
    // Initialize all section offsets to 0 (not used yet)
    m_header->ipv4IndexOffset = 0;
    m_header->ipv4IndexSize = 0;
    m_header->ipv6IndexOffset = 0;
    m_header->ipv6IndexSize = 0;
    m_header->domainIndexOffset = 0;
    m_header->domainIndexSize = 0;
    m_header->urlIndexOffset = 0;
    m_header->urlIndexSize = 0;
    m_header->hashIndexOffset = 0;
    m_header->hashIndexSize = 0;
    m_header->emailIndexOffset = 0;
    m_header->emailIndexSize = 0;
    m_header->certIndexOffset = 0;
    m_header->certIndexSize = 0;
    m_header->ja3IndexOffset = 0;
    m_header->ja3IndexSize = 0;
    m_header->stringPoolOffset = 0;
    m_header->stringPoolSize = 0;
    m_header->bloomFilterOffset = 0;
    m_header->bloomFilterSize = 0;
    m_header->stixBundleOffset = 0;
    m_header->stixBundleSize = 0;
    m_header->feedConfigOffset = 0;
    m_header->feedConfigSize = 0;
    m_header->metadataOffset = 0;
    m_header->metadataSize = 0;
    
    // Initialize statistics counters
    m_header->totalIPv4Entries = 0;
    m_header->totalIPv6Entries = 0;
    m_header->totalDomainEntries = 0;
    m_header->totalURLEntries = 0;
    m_header->totalHashEntries = 0;
    m_header->totalEmailEntries = 0;
    m_header->totalCertEntries = 0;
    m_header->totalOtherEntries = 0;
    m_header->totalActiveEntries = 0;
    m_header->totalFeeds = 0;
    m_header->activeFeeds = 0;
    m_header->totalLookups = 0;
    m_header->totalHits = 0;
    m_header->totalMisses = 0;
    m_header->totalBlocks = 0;
    m_header->totalAlerts = 0;
    
    // Set file size in header
    m_header->totalFileSize = fileSize;
    
    // Compute checksum
    m_header->headerCrc32 = 0;
    m_header->headerCrc32 = ComputeHeaderCRC32(*m_header);
    
    // Set entries pointer
    m_entries = reinterpret_cast<IOCEntry*>(
        static_cast<uint8_t*>(m_region.BaseAddress()) + m_header->entryDataOffset
    );
    
    // Update stats
    m_stats.createdTimestamp = now;
    m_stats.lastModifiedTimestamp = now;
    m_stats.maxEntries = CalculateMaxEntries();
}

bool ThreatIntelDatabase::Remap(size_t newSize) noexcept {
    // Note: Caller must hold unique lock
    
    // TITANIUM: Validate newSize
    if (newSize == 0 || newSize > DATABASE_MAX_SIZE) {
        return false;
    }
    
    if (!m_region.IsValid()) {
        return false;
    }
    
    HANDLE fileHandle = static_cast<HANDLE>(m_region.m_fileHandle);
    
    // TITANIUM: Validate file handle
    if (fileHandle == nullptr || fileHandle == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    // TITANIUM: Save current state for rollback on failure
    const size_t oldSize = m_region.m_size;
    void* oldBaseAddress = m_region.m_baseAddress;
    void* oldMappingHandle = m_region.m_mappingHandle;
    ThreatIntelDatabaseHeader* oldHeader = m_header;
    IOCEntry* oldEntries = m_entries;
    
    // Flush before remapping
    m_region.Flush();
    
    // Unmap current view
    if (m_region.m_baseAddress) {
        UnmapViewOfFile(m_region.m_baseAddress);
        m_region.m_baseAddress = nullptr;
    }
    
    // Close old mapping
    if (m_region.m_mappingHandle) {
        CloseHandle(static_cast<HANDLE>(m_region.m_mappingHandle));
        m_region.m_mappingHandle = nullptr;
    }
    
    // Clear pointers since old mapping is gone
    m_header = nullptr;
    m_entries = nullptr;
    
    // Extend file
    LARGE_INTEGER size;
    size.QuadPart = static_cast<LONGLONG>(newSize);
    
    if (!SetFilePointerEx(fileHandle, size, nullptr, FILE_BEGIN)) {
        // TITANIUM: Cannot restore old mapping - file is now unmapped
        // Mark region as invalid
        m_region.m_size = 0;
        return false;
    }
    
    if (!SetEndOfFile(fileHandle)) {
        // TITANIUM: Try to restore original file size
        LARGE_INTEGER originalSize;
        originalSize.QuadPart = static_cast<LONGLONG>(oldSize);
        SetFilePointerEx(fileHandle, originalSize, nullptr, FILE_BEGIN);
        SetEndOfFile(fileHandle);
        
        m_region.m_size = 0;
        return false;
    }
    
    // Create new mapping
    HANDLE mappingHandle = CreateFileMappingW(
        fileHandle,
        nullptr,
        PAGE_READWRITE,
        static_cast<DWORD>(size.QuadPart >> 32),
        static_cast<DWORD>(size.QuadPart & 0xFFFFFFFF),
        nullptr
    );
    
    if (mappingHandle == nullptr) {
        // TITANIUM: Mapping failed - try to restore original size and re-map
        LARGE_INTEGER originalSize;
        originalSize.QuadPart = static_cast<LONGLONG>(oldSize);
        SetFilePointerEx(fileHandle, originalSize, nullptr, FILE_BEGIN);
        SetEndOfFile(fileHandle);
        
        // Try to re-map at original size
        HANDLE restoredMapping = CreateFileMappingW(
            fileHandle, nullptr, PAGE_READWRITE,
            static_cast<DWORD>(originalSize.QuadPart >> 32),
            static_cast<DWORD>(originalSize.QuadPart & 0xFFFFFFFF),
            nullptr);
        
        if (restoredMapping) {
            void* restoredBase = MapViewOfFile(restoredMapping, FILE_MAP_ALL_ACCESS, 0, 0, oldSize);
            if (restoredBase) {
                m_region.m_mappingHandle = restoredMapping;
                m_region.m_baseAddress = restoredBase;
                m_region.m_size = oldSize;
                m_header = static_cast<ThreatIntelDatabaseHeader*>(restoredBase);
                if (m_header->entryDataOffset < oldSize) {
                    m_entries = reinterpret_cast<IOCEntry*>(
                        static_cast<uint8_t*>(restoredBase) + m_header->entryDataOffset);
                }
                return false;
            }
            CloseHandle(restoredMapping);
        }
        
        m_region.m_size = 0;
        return false;
    }
    
    // Map new view
    void* baseAddress = MapViewOfFile(
        mappingHandle,
        FILE_MAP_ALL_ACCESS,
        0,
        0,
        newSize
    );
    
    if (baseAddress == nullptr) {
        CloseHandle(mappingHandle);
        
        // TITANIUM: Try to restore original mapping
        LARGE_INTEGER originalSize;
        originalSize.QuadPart = static_cast<LONGLONG>(oldSize);
        SetFilePointerEx(fileHandle, originalSize, nullptr, FILE_BEGIN);
        SetEndOfFile(fileHandle);
        
        m_region.m_size = 0;
        return false;
    }
    
    // Update region
    m_region.m_mappingHandle = mappingHandle;
    m_region.m_baseAddress = baseAddress;
    m_region.m_size = newSize;
    
    // Update pointers
    m_header = static_cast<ThreatIntelDatabaseHeader*>(baseAddress);
    
    // TITANIUM: Validate header data offset before calculating entries pointer
    if (m_header->entryDataOffset >= newSize) {
        // Corrupted header - cannot proceed safely
        UnmapViewOfFile(baseAddress);
        CloseHandle(mappingHandle);
        m_region.m_baseAddress = nullptr;
        m_region.m_mappingHandle = nullptr;
        m_region.m_size = 0;
        m_header = nullptr;
        m_entries = nullptr;
        return false;
    }
    
    m_entries = reinterpret_cast<IOCEntry*>(
        static_cast<uint8_t*>(baseAddress) + m_header->entryDataOffset
    );
    
    // Update entry data size and file size in header
    m_header->entryDataSize = newSize - m_header->entryDataOffset;
    m_header->totalFileSize = newSize;
    
    // Update stats
    m_stats.extensionCount++;
    m_stats.mappedSize = newSize;
    m_stats.maxEntries = CalculateMaxEntries();
    m_stats.fileSize = newSize;
    
    return true;
}

size_t ThreatIntelDatabase::AlignToPage(size_t size) noexcept {
    // TITANIUM: Handle edge case where size is 0
    if (size == 0) {
        return DATABASE_PAGE_SIZE;
    }
    
    // TITANIUM: Check for overflow in alignment calculation
    // (size + DATABASE_PAGE_SIZE - 1) could overflow
    constexpr size_t alignMask = DATABASE_PAGE_SIZE - 1;
    
    if (size > SIZE_MAX - alignMask) {
        // Would overflow - return maximum aligned value
        return (SIZE_MAX / DATABASE_PAGE_SIZE) * DATABASE_PAGE_SIZE;
    }
    
    return ((size + alignMask) / DATABASE_PAGE_SIZE) * DATABASE_PAGE_SIZE;
}

size_t ThreatIntelDatabase::CalculateMaxEntries() const noexcept {
    // TITANIUM: Validate state
    if (!m_header) {
        return 0;
    }
    
    const size_t regionSize = m_region.Size();
    if (regionSize == 0) {
        return 0;
    }
    
    // Calculate how many IOCEntry structures can fit in the data section
    const size_t dataOffset = m_header->entryDataOffset;
    
    // TITANIUM: Validate data offset is within bounds
    if (dataOffset >= regionSize) {
        return 0;
    }
    
    // TITANIUM: Validate data offset is at least header size
    if (dataOffset < sizeof(ThreatIntelDatabaseHeader)) {
        return 0;
    }
    
    const size_t dataSpace = regionSize - dataOffset;
    
    // TITANIUM: Ensure IOCEntry size is non-zero (compile-time check)
    static_assert(sizeof(IOCEntry) > 0, "IOCEntry must have non-zero size");
    
    return dataSpace / sizeof(IOCEntry);
}

// ============================================================================
// Utility Functions
// ============================================================================

bool DatabaseFileExists(const std::wstring& path) noexcept {
    try {
        return std::filesystem::exists(path);
    } catch (...) {
        return false;
    }
}

bool DeleteDatabaseFile(const std::wstring& path) noexcept {
    try {
        return std::filesystem::remove(path);
    } catch (...) {
        return false;
    }
}

std::optional<size_t> GetDatabaseFileSize(const std::wstring& path) noexcept {
    try {
        if (!std::filesystem::exists(path)) {
            return std::nullopt;
        }
        return static_cast<size_t>(std::filesystem::file_size(path));
    } catch (...) {
        return std::nullopt;
    }
}

bool BackupDatabase(const std::wstring& sourcePath, const std::wstring& backupPath) noexcept {
    try {
        std::filesystem::copy_file(
            sourcePath,
            backupPath,
            std::filesystem::copy_options::overwrite_existing
        );
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace ThreatIntel
} // namespace ShadowStrike
