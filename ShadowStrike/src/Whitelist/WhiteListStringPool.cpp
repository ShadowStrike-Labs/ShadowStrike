


/**
 * ============================================================================
 * ShadowStrike WhitelistStore - STRING POOL IMPLEMENTATION
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * High-performance deduplicated string storage for whitelist database.
 * Uses FNV-1a hash-based deduplication and supports both UTF-8 and UTF-16.
 *
 * Thread Safety:
 * - All public methods use reader-writer locks
 * - GetString/GetWideString use shared_lock (concurrent reads)
 * - AddString/AddWideString use unique_lock (exclusive write)
 *
 * Memory Layout:
 * - Header: 32 bytes (usedSize, stringCount, reserved)
 * - Data: Contiguous string storage with null terminators
 *
 * ============================================================================
 */

#include "WhiteListStore.hpp"
#include "WhiteListFormat.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/JSONUtils.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <limits>
#include <climits>
#include <type_traits>

namespace ShadowStrike::Whitelist {

// ============================================================================
// INTERNAL HELPER FUNCTIONS (LOCAL TO THIS TRANSLATION UNIT)
// ============================================================================

namespace {

/**
 * @brief Safely add two sizes with overflow check
 * @param a First operand
 * @param b Second operand
 * @param result Output result (only modified on success)
 * @return True if addition succeeded, false if overflow would occur
 */
template<typename T>
[[nodiscard]] inline bool SafeAdd(T a, T b, T& result) noexcept {
    static_assert(std::is_unsigned_v<T>, "SafeAdd requires unsigned type");
    if (a > std::numeric_limits<T>::max() - b) {
        return false;  // Would overflow
    }
    result = a + b;
    return true;
}

/**
 * @brief Safely multiply two sizes with overflow check
 * @param a First operand
 * @param b Second operand
 * @param result Output result (only modified on success)
 * @return True if multiplication succeeded, false if overflow would occur
 */
template<typename T>
[[nodiscard]] inline bool SafeMul(T a, T b, T& result) noexcept {
    static_assert(std::is_unsigned_v<T>, "SafeMul requires unsigned type");
    if (a == 0 || b == 0) {
        result = 0;
        return true;
    }
    if (a > std::numeric_limits<T>::max() / b) {
        return false;  // Would overflow
    }
    result = a * b;
    return true;
}

/// @brief FNV-1a offset basis constant
constexpr uint64_t FNV_OFFSET_BASIS = 14695981039346656037ULL;

/// @brief FNV-1a prime constant
constexpr uint64_t FNV_PRIME = 1099511628211ULL;

/// @brief Maximum string length for narrow strings (uint16_t max)
constexpr size_t MAX_NARROW_STRING_LENGTH = 65535;

/// @brief Maximum string length for wide strings (chars, not bytes)
constexpr size_t MAX_WIDE_STRING_LENGTH = 32767;

/// @brief Header size in bytes
constexpr uint64_t STRING_POOL_HEADER_SIZE = 32;

} // anonymous namespace

// ============================================================================
// STRING POOL IMPLEMENTATION
// ============================================================================

StringPool::StringPool() = default;
StringPool::~StringPool() = default;

/**
 * @brief Initialize string pool from memory-mapped region (read-only mode)
 * 
 * @param view Valid memory-mapped view to read from
 * @param offset Byte offset within view to pool data
 * @param size Total size of pool region in bytes
 * @return StoreError Success or error code with descriptive message
 * 
 * @note Does NOT take ownership of the memory-mapped view
 * @note Pool becomes read-only after this initialization
 */
StoreError StringPool::Initialize(
    const MemoryMappedView& view,
    uint64_t offset,
    uint64_t size
) noexcept {
    std::unique_lock lock(m_rwLock);
    
    // Clear any previous state first (defensive)
    m_view = nullptr;
    m_baseAddress = nullptr;
    m_poolOffset = 0;
    m_totalSize = 0;
    m_usedSize.store(0, std::memory_order_relaxed);
    m_stringCount.store(0, std::memory_order_relaxed);
    m_deduplicationMap.clear();
    
    // Validate view is usable
    if (!view.IsValid()) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Invalid memory-mapped view"
        );
    }
    
    // Validate offset and size don't overflow
    uint64_t endOffset = 0;
    if (!SafeAdd(offset, size, endOffset)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "String pool section offset + size overflow"
        );
    }
    
    // Validate minimum size for header (usedSize + stringCount = 16 bytes minimum)
    if (size < STRING_POOL_HEADER_SIZE) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "String pool section too small for header"
        );
    }
    
    // Validate offset is within view bounds
    if (offset >= view.fileSize || endOffset > view.fileSize) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "String pool section exceeds view bounds"
        );
    }
    
    // Set up pool parameters (after all validation passes)
    m_view = &view;
    m_poolOffset = offset;
    m_totalSize = size;
    
    // Read used size from first 8 bytes with validation
    const auto* usedPtr = view.GetAt<uint64_t>(offset);
    if (usedPtr) {
        const uint64_t usedValue = *usedPtr;
        // Validate used size is within pool bounds and at least header size
        if (usedValue >= STRING_POOL_HEADER_SIZE && usedValue <= size) {
            m_usedSize.store(usedValue, std::memory_order_relaxed);
        } else {
            SS_LOG_WARN(L"Whitelist", L"StringPool: corrupt usedSize %llu (valid range: %llu - %llu)",
                usedValue, STRING_POOL_HEADER_SIZE, size);
            // Reset to header size - pool is effectively empty
            m_usedSize.store(STRING_POOL_HEADER_SIZE, std::memory_order_relaxed);
        }
    } else {
        // Failed to read header - pool may be corrupt
        SS_LOG_WARN(L"Whitelist", L"StringPool: failed to read usedSize from header");
        m_usedSize.store(STRING_POOL_HEADER_SIZE, std::memory_order_relaxed);
    }
    
    // Read string count from bytes 8-15 with validation
    const auto* countPtr = view.GetAt<uint64_t>(offset + 8);
    if (countPtr) {
        const uint64_t countValue = *countPtr;
        // Sanity check: string count should be reasonable for the pool size
        // At minimum, each string is 1 byte + null terminator
        const uint64_t maxPossibleStrings = (size - STRING_POOL_HEADER_SIZE) / 2;
        if (countValue <= maxPossibleStrings) {
            m_stringCount.store(countValue, std::memory_order_relaxed);
        } else {
            SS_LOG_WARN(L"Whitelist", L"StringPool: suspicious stringCount %llu (max possible: %llu)",
                countValue, maxPossibleStrings);
            m_stringCount.store(0, std::memory_order_relaxed);
        }
    } else {
        SS_LOG_WARN(L"Whitelist", L"StringPool: failed to read stringCount from header");
        m_stringCount.store(0, std::memory_order_relaxed);
    }
    
    SS_LOG_DEBUG(L"Whitelist",
        L"StringPool initialized (read-only): %llu bytes used, %llu strings, total size %llu",
        m_usedSize.load(std::memory_order_relaxed),
        m_stringCount.load(std::memory_order_relaxed),
        m_totalSize);
    
    return StoreError::Success();
}

/**
 * @brief Create new string pool in writable memory
 * 
 * @param baseAddress Writable memory base address (must remain valid)
 * @param availableSize Available space in bytes
 * @param usedSize Output: actual bytes used after creation
 * @return StoreError Success or error code
 * 
 * @note Does NOT take ownership of the memory
 * @note Pool becomes writable after this initialization
 */
StoreError StringPool::CreateNew(
    void* baseAddress,
    uint64_t availableSize,
    uint64_t& usedSize
) noexcept {
    std::unique_lock lock(m_rwLock);
    
    // Initialize output to safe value
    usedSize = 0;
    
    // Clear any previous state
    m_view = nullptr;
    m_baseAddress = nullptr;
    m_poolOffset = 0;
    m_totalSize = 0;
    m_usedSize.store(0, std::memory_order_relaxed);
    m_stringCount.store(0, std::memory_order_relaxed);
    m_deduplicationMap.clear();
    
    // Validate base address
    if (!baseAddress) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Null base address for string pool"
        );
    }
    
    // Validate minimum size for header + at least some data space
    if (availableSize < STRING_POOL_HEADER_SIZE) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Insufficient space for string pool header"
        );
    }
    
    // Validate available size is reasonable (max 4GB for string pool)
    constexpr uint64_t MAX_POOL_SIZE = 4ULL * 1024 * 1024 * 1024;
    if (availableSize > MAX_POOL_SIZE) {
        SS_LOG_WARN(L"Whitelist", L"StringPool: capping size from %llu to %llu",
            availableSize, MAX_POOL_SIZE);
        availableSize = MAX_POOL_SIZE;
    }
    
    // Set up pool parameters
    m_baseAddress = baseAddress;
    m_poolOffset = 0;
    m_totalSize = availableSize;
    
    // Initialize header (zero-fill for security - prevents info leak)
    auto* header = static_cast<uint8_t*>(baseAddress);
    std::memset(header, 0, static_cast<size_t>(STRING_POOL_HEADER_SIZE));
    
    // Set initial used size to header size
    m_usedSize.store(STRING_POOL_HEADER_SIZE, std::memory_order_relaxed);
    m_stringCount.store(0, std::memory_order_relaxed);
    
    // Write initial header values to memory
    auto* usedPtr = reinterpret_cast<uint64_t*>(header);
    *usedPtr = STRING_POOL_HEADER_SIZE;
    
    auto* countPtr = reinterpret_cast<uint64_t*>(header + 8);
    *countPtr = 0;
    
    usedSize = STRING_POOL_HEADER_SIZE;
    
    SS_LOG_DEBUG(L"Whitelist", L"StringPool created: %llu bytes available", availableSize);
    
    return StoreError::Success();
}

/**
 * @brief Retrieve a narrow (UTF-8) string from the pool
 * 
 * @param offset Byte offset within pool data section
 * @param length Length of string in bytes (excluding null terminator)
 * @return String view to the data, or empty view on bounds error
 * 
 * @note Thread-safe (uses shared_lock)
 * @note Returns empty view for invalid parameters, never throws
 */
std::string_view StringPool::GetString(uint32_t offset, uint16_t length) const noexcept {
    std::shared_lock lock(m_rwLock);
    
    // Validate length - zero length is valid but returns empty
    if (length == 0) {
        return {};
    }
    
    // Validate offset is within data section (after header)
    if (offset < STRING_POOL_HEADER_SIZE) {
        return {};  // Offset points into header - invalid
    }
    
    // Bounds check: offset + length must not overflow and must be within pool
    uint64_t endPos = 0;
    if (!SafeAdd(static_cast<uint64_t>(offset), static_cast<uint64_t>(length), endPos)) {
        return {};  // Arithmetic overflow
    }
    
    if (m_view) {
        // Memory-mapped mode - validate within view bounds
        uint64_t absoluteOffset = 0;
        uint64_t absoluteEnd = 0;
        if (!SafeAdd(m_poolOffset, static_cast<uint64_t>(offset), absoluteOffset) ||
            !SafeAdd(m_poolOffset, endPos, absoluteEnd)) {
            return {};  // Arithmetic overflow
        }
        
        // Validate against view size
        if (absoluteEnd > m_view->fileSize) {
            return {};  // Would read past view end
        }
        
        return m_view->GetString(absoluteOffset, length);
    } else if (m_baseAddress) {
        // Writable mode - validate within pool bounds
        if (endPos > m_totalSize) {
            return {};  // Would read past pool end
        }
        
        const char* ptr = reinterpret_cast<const char*>(
            static_cast<const uint8_t*>(m_baseAddress) + offset
        );
        return std::string_view(ptr, length);
    }
    
    // No storage configured
    return {};
}

/**
 * @brief Retrieve a wide (UTF-16) string from the pool
 * 
 * @param offset Byte offset within pool data section
 * @param length Length in BYTES (not characters)
 * @return Wide string view to the data, or empty view on bounds error
 * 
 * @note Thread-safe (uses shared_lock)
 * @note Returns empty view for invalid parameters, never throws
 * @note Length must be even (wide chars are 2 bytes each)
 */
std::wstring_view StringPool::GetWideString(uint32_t offset, uint16_t length) const noexcept {
    std::shared_lock lock(m_rwLock);
    
    // Validate length - must be non-zero and even (wchar_t alignment)
    if (length == 0) {
        return {};
    }
    
    if (length % sizeof(wchar_t) != 0) {
        return {};  // Invalid: not aligned to wchar_t boundary
    }
    
    // Validate offset is within data section and aligned
    if (offset < STRING_POOL_HEADER_SIZE) {
        return {};  // Offset points into header - invalid
    }
    
    if (offset % sizeof(wchar_t) != 0) {
        return {};  // Misaligned access
    }
    
    // Bounds check with overflow protection
    uint64_t endPos = 0;
    if (!SafeAdd(static_cast<uint64_t>(offset), static_cast<uint64_t>(length), endPos)) {
        return {};
    }
    
    const wchar_t* ptr = nullptr;
    
    if (m_view) {
        // Memory-mapped mode - validate within view bounds
        uint64_t absoluteOffset = 0;
        uint64_t absoluteEnd = 0;
        if (!SafeAdd(m_poolOffset, static_cast<uint64_t>(offset), absoluteOffset) ||
            !SafeAdd(m_poolOffset, endPos, absoluteEnd)) {
            return {};
        }
        
        if (absoluteEnd > m_view->fileSize) {
            return {};
        }
        
        ptr = m_view->GetAt<wchar_t>(absoluteOffset);
    } else if (m_baseAddress) {
        // Writable mode - validate within pool bounds
        if (endPos > m_totalSize) {
            return {};
        }
        
        ptr = reinterpret_cast<const wchar_t*>(
            static_cast<const uint8_t*>(m_baseAddress) + offset
        );
    }
    
    if (ptr) {
        // Safe division for character count
        const size_t charCount = length / sizeof(wchar_t);
        return std::wstring_view(ptr, charCount);
    }
    
    return {};
}

/**
 * @brief Add a narrow (UTF-8) string to the pool with deduplication
 * 
 * @param str String to add (must be non-empty)
 * @return Offset of string in pool, or nullopt on failure
 * 
 * @note Thread-safe (uses unique_lock)
 * @note Uses FNV-1a hash for deduplication - returns existing offset if found
 * @note Strings are null-terminated in the pool
 */
std::optional<uint32_t> StringPool::AddString(std::string_view str) noexcept {
    std::unique_lock lock(m_rwLock);
    
    // Validate writable state - pool must be in writable mode
    if (!m_baseAddress) {
        SS_LOG_DEBUG(L"Whitelist", L"StringPool::AddString: pool is read-only");
        return std::nullopt;
    }
    
    // Validate input - empty strings not allowed
    if (str.empty()) {
        return std::nullopt;
    }
    
    // Validate string length within uint16_t range
    if (str.size() > MAX_NARROW_STRING_LENGTH) {
        SS_LOG_WARN(L"Whitelist", L"StringPool: string too long (%zu bytes, max %zu)",
            str.size(), MAX_NARROW_STRING_LENGTH);
        return std::nullopt;
    }
    
    // Compute FNV-1a hash for deduplication
    uint64_t strHash = FNV_OFFSET_BASIS;
    for (const char c : str) {
        strHash ^= static_cast<uint8_t>(c);
        strHash *= FNV_PRIME;
    }
    
    // Check for existing duplicate (hash collision is extremely rare with 64-bit FNV-1a)
    try {
        auto it = m_deduplicationMap.find(strHash);
        if (it != m_deduplicationMap.end()) {
            // Found existing string - return its offset
            return it->second;
        }
    } catch (const std::exception& e) {
        // Map access failed (OOM?) - log and continue with insertion
        SS_LOG_WARN(L"Whitelist", L"StringPool: dedup map lookup failed: %S", e.what());
    }
    
    // Calculate required space with overflow check (+1 for null terminator)
    size_t strSize = 0;
    if (!SafeAdd(str.size(), static_cast<size_t>(1), strSize)) {
        SS_LOG_ERROR(L"Whitelist", L"StringPool: size overflow");
        return std::nullopt;
    }
    
    const uint64_t currentUsed = m_usedSize.load(std::memory_order_acquire);
    
    // Check if we have space (with overflow protection)
    uint64_t newUsed = 0;
    if (!SafeAdd(currentUsed, static_cast<uint64_t>(strSize), newUsed)) {
        SS_LOG_ERROR(L"Whitelist", L"StringPool: offset overflow");
        return std::nullopt;
    }
    
    if (newUsed > m_totalSize) {
        SS_LOG_WARN(L"Whitelist", L"StringPool: no space for string (%zu bytes, %llu/%llu used)",
            strSize, currentUsed, m_totalSize);
        return std::nullopt;
    }
    
    // Validate offset fits in uint32_t for return value
    if (currentUsed > UINT32_MAX) {
        SS_LOG_ERROR(L"Whitelist", L"StringPool: offset exceeds 32-bit limit (%llu)", currentUsed);
        return std::nullopt;
    }
    
    // Write string to pool
    const uint32_t offset = static_cast<uint32_t>(currentUsed);
    char* dest = reinterpret_cast<char*>(
        static_cast<uint8_t*>(m_baseAddress) + offset
    );
    std::memcpy(dest, str.data(), str.size());
    dest[str.size()] = '\0';  // Null terminate for safety
    
    // Update tracking atomically (release to ensure string is visible)
    m_usedSize.store(newUsed, std::memory_order_release);
    m_stringCount.fetch_add(1, std::memory_order_relaxed);
    
    // Add to deduplication map (best effort - failure doesn't affect correctness)
    try {
        m_deduplicationMap.emplace(strHash, offset);
    } catch (const std::exception& e) {
        SS_LOG_DEBUG(L"Whitelist", L"StringPool: dedup map insert failed: %S", e.what());
        // String still added successfully, just won't be deduplicated in future
    }
    
    // Update persistent header in memory
    auto* usedPtr = reinterpret_cast<uint64_t*>(m_baseAddress);
    *usedPtr = newUsed;
    
    auto* countPtr = reinterpret_cast<uint64_t*>(
        static_cast<uint8_t*>(m_baseAddress) + 8
    );
    *countPtr = m_stringCount.load(std::memory_order_relaxed);
    
    return offset;
}

/**
 * @brief Add a wide (UTF-16) string to the pool with deduplication
 * 
 * @param str Wide string to add (must be non-empty)
 * @return Offset of string in pool, or nullopt on failure
 * 
 * @note Thread-safe (uses unique_lock)
 * @note Uses FNV-1a hash for deduplication
 * @note Strings are aligned to 2-byte boundary and null-terminated
 */
std::optional<uint32_t> StringPool::AddWideString(std::wstring_view str) noexcept {
    std::unique_lock lock(m_rwLock);
    
    // Validate writable state
    if (!m_baseAddress) {
        SS_LOG_DEBUG(L"Whitelist", L"StringPool::AddWideString: pool is read-only");
        return std::nullopt;
    }
    
    // Validate input - empty strings not allowed
    if (str.empty()) {
        return std::nullopt;
    }
    
    // Validate string length (in characters)
    if (str.size() > MAX_WIDE_STRING_LENGTH) {
        SS_LOG_WARN(L"Whitelist", L"StringPool: wide string too long (%zu chars, max %zu)",
            str.size(), MAX_WIDE_STRING_LENGTH);
        return std::nullopt;
    }
    
    // Compute FNV-1a hash for deduplication (process each wchar_t)
    uint64_t strHash = FNV_OFFSET_BASIS;
    for (const wchar_t c : str) {
        // Hash both bytes of wide char for better distribution
        strHash ^= static_cast<uint8_t>(c & 0xFF);
        strHash *= FNV_PRIME;
        strHash ^= static_cast<uint8_t>((c >> 8) & 0xFF);
        strHash *= FNV_PRIME;
    }
    
    // Check for existing duplicate
    try {
        auto it = m_deduplicationMap.find(strHash);
        if (it != m_deduplicationMap.end()) {
            return it->second;  // Return existing offset
        }
    } catch (const std::exception& e) {
        SS_LOG_WARN(L"Whitelist", L"StringPool: dedup map lookup failed: %S", e.what());
    }
    
    // Calculate required space with overflow check (+1 for null terminator)
    size_t charCount = 0;
    if (!SafeAdd(str.size(), static_cast<size_t>(1), charCount)) {
        SS_LOG_ERROR(L"Whitelist", L"StringPool: char count overflow");
        return std::nullopt;
    }
    
    size_t charBytes = 0;
    if (!SafeMul(charCount, sizeof(wchar_t), charBytes)) {
        SS_LOG_ERROR(L"Whitelist", L"StringPool: byte size overflow");
        return std::nullopt;
    }
    
    uint64_t currentUsed = m_usedSize.load(std::memory_order_acquire);
    
    // Align to 2-byte boundary for wchar_t (round up safely)
    // Use mask to align: (x + align - 1) & ~(align - 1)
    const uint64_t alignedUsed = (currentUsed + (sizeof(wchar_t) - 1)) & ~(sizeof(wchar_t) - 1);
    
    // Verify alignment didn't overflow
    if (alignedUsed < currentUsed) {
        SS_LOG_ERROR(L"Whitelist", L"StringPool: alignment overflow");
        return std::nullopt;
    }
    
    // Check if we have space (with overflow protection)
    uint64_t newUsed = 0;
    if (!SafeAdd(alignedUsed, static_cast<uint64_t>(charBytes), newUsed)) {
        SS_LOG_ERROR(L"Whitelist", L"StringPool: offset overflow");
        return std::nullopt;
    }
    
    if (newUsed > m_totalSize) {
        SS_LOG_WARN(L"Whitelist", L"StringPool: no space for wide string (%zu bytes, %llu/%llu used)",
            charBytes, alignedUsed, m_totalSize);
        return std::nullopt;
    }
    
    // Validate offset fits in uint32_t
    if (alignedUsed > UINT32_MAX) {
        SS_LOG_ERROR(L"Whitelist", L"StringPool: offset exceeds 32-bit limit (%llu)", alignedUsed);
        return std::nullopt;
    }
    
    // Write string to pool (at aligned offset)
    const uint32_t offset = static_cast<uint32_t>(alignedUsed);
    wchar_t* dest = reinterpret_cast<wchar_t*>(
        static_cast<uint8_t*>(m_baseAddress) + offset
    );
    std::memcpy(dest, str.data(), str.size() * sizeof(wchar_t));
    dest[str.size()] = L'\0';  // Null terminate
    
    // Update tracking atomically
    m_usedSize.store(newUsed, std::memory_order_release);
    m_stringCount.fetch_add(1, std::memory_order_relaxed);
    
    // Add to deduplication map (best effort)
    try {
        m_deduplicationMap.emplace(strHash, offset);
    } catch (const std::exception& e) {
        SS_LOG_DEBUG(L"Whitelist", L"StringPool: dedup map insert failed: %S", e.what());
    }
    
    // Update persistent header in memory
    auto* usedPtr = reinterpret_cast<uint64_t*>(m_baseAddress);
    *usedPtr = newUsed;
    
    auto* countPtr = reinterpret_cast<uint64_t*>(
        static_cast<uint8_t*>(m_baseAddress) + 8
    );
    *countPtr = m_stringCount.load(std::memory_order_relaxed);
    
    return offset;
}

} // namespace ShadowStrike::Whitelist