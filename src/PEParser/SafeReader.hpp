#pragma once
/**
 * @file SafeReader.hpp
 * @brief Bounds-checked memory reader for safe PE parsing.
 *
 * Provides a defensive interface for reading binary data with:
 * - All reads bounds-checked before access
 * - Integer overflow protection on all arithmetic
 * - No raw pointer arithmetic exposed
 * - Immutable after construction
 *
 * This is the foundation of security for PE parsing - every byte
 * read from a PE file goes through this class.
 *
 * @copyright ShadowStrike Security Suite
 */

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <optional>
#include <span>
#include <limits>
#include <type_traits>

namespace ShadowStrike {
namespace PEParser {

/**
 * @brief Safe arithmetic operations with overflow detection.
 */
class SafeMath {
public:
    /**
     * @brief Safe addition with overflow check.
     * @param a First operand.
     * @param b Second operand.
     * @param result Output for result if no overflow.
     * @return true if addition succeeded without overflow.
     */
    template<typename T>
    [[nodiscard]] static constexpr bool SafeAdd(T a, T b, T& result) noexcept {
        static_assert(std::is_unsigned_v<T>, "SafeAdd requires unsigned types");
        if (a > std::numeric_limits<T>::max() - b) {
            return false;
        }
        result = a + b;
        return true;
    }

    /**
     * @brief Safe multiplication with overflow check.
     * @param a First operand.
     * @param b Second operand.
     * @param result Output for result if no overflow.
     * @return true if multiplication succeeded without overflow.
     */
    template<typename T>
    [[nodiscard]] static constexpr bool SafeMul(T a, T b, T& result) noexcept {
        static_assert(std::is_unsigned_v<T>, "SafeMul requires unsigned types");
        if (a != 0 && b > std::numeric_limits<T>::max() / a) {
            return false;
        }
        result = a * b;
        return true;
    }

    /**
     * @brief Safe subtraction with underflow check.
     * @param a First operand (minuend).
     * @param b Second operand (subtrahend).
     * @param result Output for result if no underflow.
     * @return true if subtraction succeeded without underflow.
     */
    template<typename T>
    [[nodiscard]] static constexpr bool SafeSub(T a, T b, T& result) noexcept {
        static_assert(std::is_unsigned_v<T>, "SafeSub requires unsigned types");
        if (b > a) {
            return false;
        }
        result = a - b;
        return true;
    }

    /**
     * @brief Safe type cast with range checking.
     * @tparam To Target type.
     * @tparam From Source type.
     * @param value Value to cast.
     * @return Optional containing casted value, or nullopt on range error.
     */
    template<typename To, typename From>
    [[nodiscard]] static constexpr std::optional<To> SafeCast(From value) noexcept {
        // Handle signed to unsigned conversion
        if constexpr (std::is_signed_v<From> && std::is_unsigned_v<To>) {
            if (value < 0) {
                return std::nullopt;
            }
        }

        // Check upper bound
        if constexpr (sizeof(From) > sizeof(To) ||
                      (sizeof(From) == sizeof(To) && std::is_unsigned_v<From> && std::is_signed_v<To>)) {
            if (static_cast<std::make_unsigned_t<From>>(value) >
                static_cast<std::make_unsigned_t<To>>(std::numeric_limits<To>::max())) {
                return std::nullopt;
            }
        }

        // Check lower bound for signed target
        if constexpr (std::is_signed_v<To> && std::is_signed_v<From>) {
            if (value < std::numeric_limits<To>::min()) {
                return std::nullopt;
            }
        }

        return static_cast<To>(value);
    }
};

/**
 * @brief Bounds-checked memory reader for binary data.
 *
 * This class provides safe access to raw memory with automatic
 * bounds checking and overflow protection. It is immutable after
 * construction and all operations are noexcept.
 *
 * Usage:
 * @code
 *   SafeReader reader(data, size);
 *   DosHeader dos;
 *   if (reader.Read(0, dos)) {
 *       // Use dos safely
 *   }
 * @endcode
 */
class SafeReader {
public:
    /**
     * @brief Construct from raw pointer and size.
     * @param data Pointer to data buffer.
     * @param size Size of data buffer in bytes.
     */
    SafeReader(const uint8_t* data, size_t size) noexcept
        : m_data(data)
        , m_size(data ? size : 0)
    {}

    /**
     * @brief Construct from span.
     * @param data Span of bytes.
     */
    explicit SafeReader(std::span<const uint8_t> data) noexcept
        : m_data(data.data())
        , m_size(data.size())
    {}

    /**
     * @brief Default constructor creates empty reader.
     */
    SafeReader() noexcept : m_data(nullptr), m_size(0) {}

    // Default copy/move
    SafeReader(const SafeReader&) = default;
    SafeReader& operator=(const SafeReader&) = default;
    SafeReader(SafeReader&&) = default;
    SafeReader& operator=(SafeReader&&) = default;

    // ========================================================================
    // Basic Properties
    // ========================================================================

    /**
     * @brief Get size of data buffer.
     * @return Size in bytes.
     */
    [[nodiscard]] size_t Size() const noexcept { return m_size; }

    /**
     * @brief Check if reader has any data.
     * @return true if size > 0.
     */
    [[nodiscard]] bool HasData() const noexcept { return m_size > 0; }

    /**
     * @brief Check if reader is valid (has data pointer).
     * @return true if data pointer is not null.
     */
    [[nodiscard]] bool IsValid() const noexcept { return m_data != nullptr; }

    /**
     * @brief Get raw data pointer (use with caution).
     * @return Pointer to data, or nullptr if invalid.
     */
    [[nodiscard]] const uint8_t* Data() const noexcept { return m_data; }

    // ========================================================================
    // Range Validation
    // ========================================================================

    /**
     * @brief Validate that a range [offset, offset+size) is within bounds.
     * @param offset Starting offset.
     * @param size Size of range.
     * @return true if range is valid and within bounds.
     */
    [[nodiscard]] bool ValidateRange(size_t offset, size_t size) const noexcept {
        size_t end;
        if (!SafeMath::SafeAdd(offset, size, end)) {
            return false;  // Overflow
        }
        return end <= m_size;
    }

    /**
     * @brief Check if an offset is within bounds.
     * @param offset Offset to check.
     * @return true if offset < size.
     */
    [[nodiscard]] bool ValidateOffset(size_t offset) const noexcept {
        return offset < m_size;
    }

    // ========================================================================
    // Reading Primitives
    // ========================================================================

    /**
     * @brief Read a value at offset.
     * @tparam T Type to read (must be trivially copyable).
     * @param offset Offset in buffer.
     * @param out Output for read value.
     * @return true if read succeeded.
     */
    template<typename T>
    [[nodiscard]] bool Read(size_t offset, T& out) const noexcept {
        static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");

        if (!ValidateRange(offset, sizeof(T))) {
            return false;
        }

        std::memcpy(&out, m_data + offset, sizeof(T));
        return true;
    }

    /**
     * @brief Read a value at offset, returning optional.
     * @tparam T Type to read.
     * @param offset Offset in buffer.
     * @return Optional containing value, or nullopt on failure.
     */
    template<typename T>
    [[nodiscard]] std::optional<T> ReadOpt(size_t offset) const noexcept {
        T value;
        if (Read(offset, value)) {
            return value;
        }
        return std::nullopt;
    }

    /**
     * @brief Read a single byte at offset.
     * @param offset Offset in buffer.
     * @param out Output byte.
     * @return true if read succeeded.
     */
    [[nodiscard]] bool ReadByte(size_t offset, uint8_t& out) const noexcept {
        if (offset >= m_size) {
            return false;
        }
        out = m_data[offset];
        return true;
    }

    /**
     * @brief Read a 16-bit little-endian value.
     * @param offset Offset in buffer.
     * @param out Output value.
     * @return true if read succeeded.
     */
    [[nodiscard]] bool ReadU16LE(size_t offset, uint16_t& out) const noexcept {
        return Read(offset, out);
    }

    /**
     * @brief Read a 32-bit little-endian value.
     * @param offset Offset in buffer.
     * @param out Output value.
     * @return true if read succeeded.
     */
    [[nodiscard]] bool ReadU32LE(size_t offset, uint32_t& out) const noexcept {
        return Read(offset, out);
    }

    /**
     * @brief Read a 64-bit little-endian value.
     * @param offset Offset in buffer.
     * @param out Output value.
     * @return true if read succeeded.
     */
    [[nodiscard]] bool ReadU64LE(size_t offset, uint64_t& out) const noexcept {
        return Read(offset, out);
    }

    // ========================================================================
    // Array Reading
    // ========================================================================

    /**
     * @brief Get a span view of an array at offset.
     * @tparam T Element type.
     * @param offset Offset in buffer.
     * @param count Number of elements.
     * @param out Output span.
     * @return true if range is valid.
     */
    template<typename T>
    [[nodiscard]] bool ReadArray(size_t offset, size_t count,
                                  std::span<const T>& out) const noexcept {
        static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");

        // Check for multiplication overflow
        size_t totalSize;
        if (!SafeMath::SafeMul(count, sizeof(T), totalSize)) {
            return false;
        }

        if (!ValidateRange(offset, totalSize)) {
            return false;
        }

        out = std::span<const T>(
            reinterpret_cast<const T*>(m_data + offset),
            count
        );
        return true;
    }

    /**
     * @brief Read bytes into a buffer.
     * @param offset Offset in source.
     * @param dest Destination buffer.
     * @param count Number of bytes to read.
     * @return true if read succeeded.
     */
    [[nodiscard]] bool ReadBytes(size_t offset, void* dest, size_t count) const noexcept {
        if (!dest || !ValidateRange(offset, count)) {
            return false;
        }
        std::memcpy(dest, m_data + offset, count);
        return true;
    }

    // ========================================================================
    // String Reading
    // ========================================================================

    /**
     * @brief Read a null-terminated string with maximum length.
     * @param offset Offset in buffer.
     * @param maxLen Maximum length to read (including null terminator search).
     * @param out Output string view (valid only while reader is valid).
     * @return true if a null terminator was found within maxLen.
     */
    [[nodiscard]] bool ReadString(size_t offset, size_t maxLen,
                                   std::string_view& out) const noexcept {
        if (offset >= m_size) {
            return false;
        }

        // Calculate maximum bytes we can examine
        size_t remaining = m_size - offset;
        size_t searchLen = (maxLen < remaining) ? maxLen : remaining;

        const char* start = reinterpret_cast<const char*>(m_data + offset);
        const char* end = static_cast<const char*>(
            std::memchr(start, '\0', searchLen)
        );

        if (end == nullptr) {
            return false;  // No null terminator found
        }

        out = std::string_view(start, end - start);
        return true;
    }

    /**
     * @brief Read a fixed-length string (may not be null-terminated).
     * @param offset Offset in buffer.
     * @param length Exact length to read.
     * @param out Output string (trimmed at first null if present).
     * @return true if read succeeded.
     */
    [[nodiscard]] bool ReadFixedString(size_t offset, size_t length,
                                        std::string& out) const noexcept {
        if (!ValidateRange(offset, length)) {
            return false;
        }

        const char* start = reinterpret_cast<const char*>(m_data + offset);

        // Find null terminator within fixed length
        const char* nullPos = static_cast<const char*>(
            std::memchr(start, '\0', length)
        );

        size_t strLen = nullPos ? (nullPos - start) : length;
        out.assign(start, strLen);
        return true;
    }

    // ========================================================================
    // Sub-Reader Creation
    // ========================================================================

    /**
     * @brief Create a sub-reader for a portion of the data.
     * @param offset Starting offset.
     * @param size Size of sub-region.
     * @return Optional containing sub-reader, or nullopt if range invalid.
     */
    [[nodiscard]] std::optional<SafeReader> SubReader(size_t offset,
                                                       size_t size) const noexcept {
        if (!ValidateRange(offset, size)) {
            return std::nullopt;
        }
        return SafeReader(m_data + offset, size);
    }

    /**
     * @brief Create a sub-reader from offset to end.
     * @param offset Starting offset.
     * @return Optional containing sub-reader, or nullopt if offset invalid.
     */
    [[nodiscard]] std::optional<SafeReader> SubReaderFrom(size_t offset) const noexcept {
        if (offset > m_size) {
            return std::nullopt;
        }
        return SafeReader(m_data + offset, m_size - offset);
    }

    // ========================================================================
    // Comparison
    // ========================================================================

    /**
     * @brief Compare bytes at offset with expected data.
     * @param offset Offset in buffer.
     * @param expected Expected bytes.
     * @param length Length to compare.
     * @return true if bytes match.
     */
    [[nodiscard]] bool CompareBytes(size_t offset, const void* expected,
                                     size_t length) const noexcept {
        if (!expected || !ValidateRange(offset, length)) {
            return false;
        }
        return std::memcmp(m_data + offset, expected, length) == 0;
    }

private:
    const uint8_t* m_data;  ///< Pointer to data buffer
    size_t m_size;          ///< Size of data buffer
};

} // namespace PEParser
} // namespace ShadowStrike
