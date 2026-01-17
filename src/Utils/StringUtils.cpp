// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
/**
 * @file StringUtils.cpp
 * @brief Implementation of string manipulation utilities for ShadowStrike.
 * 
 * @author ShadowStrike Security Team
 * @copyright (c) 2025 ShadowStrike. All rights reserved.
 */

#include "StringUtils.hpp"

#include <limits>
#include <algorithm>
#include <cstdarg>
#include <cwctype>
#include <stdexcept>
#include <type_traits>

namespace ShadowStrike {
    namespace Utils {
        namespace StringUtils {

            // ============================================================================
            // Internal Constants
            // ============================================================================

            namespace {
                /// Maximum size for conversion operations (prevents DoS)
                constexpr size_t kMaxConversionSize = 128 * 1024 * 1024; // 128 MB
                
                /// Maximum number of split/replace operations (prevents DoS)
                constexpr size_t kMaxOperationCount = 1000000;
                
                /// Maximum format output size
                constexpr int kMaxFormatSize = 1048576; // 1 MB
                
                /// Whitespace characters for trimming
                constexpr wchar_t kWhitespace[] = L" \t\n\r\f\v";
            }

            // ============================================================================
            // Character Encoding Conversions
            // ============================================================================

            std::wstring ToWide(std::string_view narrow) noexcept {
                // Handle empty input
                if (narrow.empty()) {
                    return std::wstring{};
                }

                // Validate input size (INT_MAX is the limit for Windows API)
                if (narrow.size() > static_cast<size_t>(INT_MAX)) {
                    return std::wstring{};
                }

                // Security: prevent excessive memory allocation
                if (narrow.size() > kMaxConversionSize) {
                    return std::wstring{};
                }

                // First call: determine required buffer size
                // Note: When cbMultiByte > 0, the function does NOT include null terminator
                const int sizeNeeded = MultiByteToWideChar(
                    CP_UTF8, 
                    MB_ERR_INVALID_CHARS,  // Fail on invalid UTF-8
                    narrow.data(),
                    static_cast<int>(narrow.size()), 
                    nullptr, 
                    0
                );

                if (sizeNeeded <= 0) {
                    // Conversion failed or invalid UTF-8
                    return std::wstring{};
                }

                // Validate output size won't overflow
                constexpr size_t maxWstringSize = std::numeric_limits<size_t>::max() / sizeof(wchar_t);
                if (static_cast<size_t>(sizeNeeded) > maxWstringSize) {
                    return std::wstring{};
                }

                // Allocate buffer with exception safety
                std::wstring result;
                try {
                    result.resize(static_cast<size_t>(sizeNeeded));
                }
                catch (const std::bad_alloc&) {
                    return std::wstring{};
                }
                catch (...) {
                    return std::wstring{};
                }

                // Second call: perform actual conversion
                const int converted = MultiByteToWideChar(
                    CP_UTF8,
                    MB_ERR_INVALID_CHARS,
                    narrow.data(),
                    static_cast<int>(narrow.size()),
                    result.data(),
                    sizeNeeded
                );

                if (converted != sizeNeeded) {
                    // Conversion failed
                    return std::wstring{};
                }

                return result;
            }

            std::string ToNarrow(std::wstring_view wide) noexcept {
                // Handle empty input
                if (wide.empty()) {
                    return std::string{};
                }

                // Validate input size
                if (wide.size() > static_cast<size_t>(INT_MAX)) {
                    return std::string{};
                }

                // Security: prevent excessive memory allocation
                if (wide.size() > kMaxConversionSize / sizeof(wchar_t)) {
                    return std::string{};
                }

                // First call: determine required buffer size
                // Note: When cchWideChar > 0, the function does NOT include null terminator
                const int sizeNeeded = WideCharToMultiByte(
                    CP_UTF8,
                    WC_ERR_INVALID_CHARS,  // Fail on invalid characters
                    wide.data(),
                    static_cast<int>(wide.size()),
                    nullptr,
                    0,
                    nullptr,
                    nullptr
                );

                if (sizeNeeded <= 0) {
                    // Conversion failed
                    return std::string{};
                }

                // Validate output size
                if (static_cast<size_t>(sizeNeeded) > std::numeric_limits<size_t>::max()) {
                    return std::string{};
                }

                // Allocate buffer with exception safety
                std::string result;
                try {
                    result.resize(static_cast<size_t>(sizeNeeded));
                }
                catch (const std::bad_alloc&) {
                    return std::string{};
                }
                catch (...) {
                    return std::string{};
                }

                // Second call: perform actual conversion
                const int converted = WideCharToMultiByte(
                    CP_UTF8,
                    WC_ERR_INVALID_CHARS,
                    wide.data(),
                    static_cast<int>(wide.size()),
                    result.data(),
                    sizeNeeded,
                    nullptr,
                    nullptr
                );

                if (converted != sizeNeeded) {
                    // Conversion failed
                    return std::string{};
                }

                return result;
            }

            std::wstring utf8_to_wstring(const char* utf8) noexcept {
                // Handle null or empty input
                if (!utf8 || *utf8 == '\0') {
                    return std::wstring{};
                }

                // First call: determine required buffer size
                // Using -1 for null-terminated string (includes null in count)
                const int sizeNeeded = MultiByteToWideChar(
                    CP_UTF8, 
                    MB_ERR_INVALID_CHARS,
                    utf8, 
                    -1, 
                    nullptr, 
                    0
                );

                if (sizeNeeded <= 0) {
                    return std::wstring{};
                }

                // sizeNeeded includes null terminator, so actual string length is sizeNeeded - 1
                if (sizeNeeded <= 1) {
                    return std::wstring{};  // Empty string (just null terminator)
                }

                // Allocate buffer (without null terminator since std::wstring manages it)
                std::wstring result;
                try {
                    result.resize(static_cast<size_t>(sizeNeeded - 1));
                }
                catch (...) {
                    return std::wstring{};
                }

                // Second call: perform conversion
                // Allocate +1 for the null terminator that MultiByteToWideChar writes
                std::vector<wchar_t> buffer;
                try {
                    buffer.resize(static_cast<size_t>(sizeNeeded));
                }
                catch (...) {
                    return std::wstring{};
                }

                const int converted = MultiByteToWideChar(
                    CP_UTF8, 
                    MB_ERR_INVALID_CHARS,
                    utf8, 
                    -1, 
                    buffer.data(), 
                    sizeNeeded
                );

                if (converted <= 0) {
                    return std::wstring{};
                }

                // Copy to result (excluding null terminator)
                return std::wstring(buffer.data(), static_cast<size_t>(converted - 1));
            }

            // ============================================================================
            // Case Transformations
            // ============================================================================

            void ToLower(std::wstring& str) noexcept {
                if (str.empty()) {
                    return;
                }

                // Handle strings larger than MAXDWORD by processing in chunks
                if (str.size() > static_cast<size_t>(MAXDWORD)) {
                    constexpr size_t kChunkSize = MAXDWORD / 2;
                    for (size_t offset = 0; offset < str.size(); offset += kChunkSize) {
                        const size_t remaining = str.size() - offset;
                        const size_t chunkLen = (remaining < kChunkSize) ? remaining : kChunkSize;
                        CharLowerBuffW(&str[offset], static_cast<DWORD>(chunkLen));
                    }
                }
                else {
                    CharLowerBuffW(str.data(), static_cast<DWORD>(str.size()));
                }
            }

            std::wstring ToLowerCopy(std::wstring_view str) {
                std::wstring result;
                try {
                    result = str;
                }
                catch (const std::bad_alloc&) {
                    return std::wstring{};
                }
                ToLower(result);
                return result;
            }

            void ToUpper(std::wstring& str) noexcept {
                if (str.empty()) {
                    return;
                }

                // Handle strings larger than MAXDWORD by processing in chunks
                if (str.size() > static_cast<size_t>(MAXDWORD)) {
                    constexpr size_t kChunkSize = MAXDWORD / 2;
                    for (size_t offset = 0; offset < str.size(); offset += kChunkSize) {
                        const size_t remaining = str.size() - offset;
                        const size_t chunkLen = (remaining < kChunkSize) ? remaining : kChunkSize;
                        CharUpperBuffW(&str[offset], static_cast<DWORD>(chunkLen));
                    }
                }
                else {
                    CharUpperBuffW(str.data(), static_cast<DWORD>(str.size()));
                }
            }

            std::wstring ToUpperCopy(std::wstring_view str) {
                std::wstring result;
                try {
                    result = str;
                }
                catch (const std::bad_alloc&) {
                    return std::wstring{};
                }
                ToUpper(result);
                return result;
            }

            // ============================================================================
            // Trimming Functions
            // ============================================================================

            void TrimLeft(std::wstring& str) noexcept {
                if (str.empty()) {
                    return;
                }

                const size_t pos = str.find_first_not_of(kWhitespace);

                if (pos == std::wstring::npos) {
                    str.clear();
                }
                else if (pos > 0) {
                    str.erase(0, pos);
                }
            }

            void TrimRight(std::wstring& str) noexcept {
                if (str.empty()) {
                    return;
                }

                const size_t pos = str.find_last_not_of(kWhitespace);

                if (pos == std::wstring::npos) {
                    str.clear();
                }
                else if (pos + 1 < str.size()) {
                    str.erase(pos + 1);
                }
            }

            void Trim(std::wstring& str) noexcept {
                TrimRight(str);
                TrimLeft(str);
            }

            std::wstring TrimCopy(std::wstring_view str) {
                std::wstring result;
                try {
                    result = str;
                }
                catch (const std::bad_alloc&) {
                    return std::wstring{};
                }
                Trim(result);
                return result;
            }

            std::wstring TrimLeftCopy(std::wstring_view str) {
                std::wstring result;
                try {
                    result = str;
                }
                catch (const std::bad_alloc&) {
                    return std::wstring{};
                }
                TrimLeft(result);
                return result;
            }

            std::wstring TrimRightCopy(std::wstring_view str) {
                std::wstring result;
                try {
                    result = str;
                }
                catch (const std::bad_alloc&) {
                    return std::wstring{};
                }
                TrimRight(result);
                return result;
            }

            // ============================================================================
            // String Comparison
            // ============================================================================

            bool IEquals(std::wstring_view s1, std::wstring_view s2) noexcept {
                // Handle size limit for Windows API
                if (s1.size() > static_cast<size_t>(INT_MAX) ||
                    s2.size() > static_cast<size_t>(INT_MAX)) {
                    return false;
                }

                // Both empty = equal
                if (s1.empty() && s2.empty()) {
                    return true;
                }
                
                // One empty, one not = not equal
                if (s1.empty() || s2.empty()) {
                    return false;
                }

                // Use Windows API for consistent locale-independent comparison
                const int result = CompareStringOrdinal(
                    s1.data(), static_cast<int>(s1.length()),
                    s2.data(), static_cast<int>(s2.length()),
                    TRUE  // Ignore case
                );

                return result == CSTR_EQUAL;
            }

            bool StartsWith(std::wstring_view str, std::wstring_view prefix) noexcept {
                if (prefix.empty()) {
                    return true;  // Empty prefix matches everything
                }
                if (str.size() < prefix.size()) {
                    return false;
                }
                return str.substr(0, prefix.size()) == prefix;
            }

            bool EndsWith(std::wstring_view str, std::wstring_view suffix) noexcept {
                if (suffix.empty()) {
                    return true;  // Empty suffix matches everything
                }
                if (str.size() < suffix.size()) {
                    return false;
                }
                return str.substr(str.size() - suffix.size()) == suffix;
            }

            bool Contains(std::wstring_view str, std::wstring_view substr) noexcept {
                if (substr.empty()) {
                    return true;  // Empty substring is always found
                }
                return str.find(substr) != std::wstring_view::npos;
            }

            bool IContains(std::wstring_view str, std::wstring_view substr) noexcept {
                // Empty substring is always found
                if (substr.empty()) {
                    return true;
                }
                
                // If substring is longer than string, can't be found
                if (str.empty() || substr.size() > str.size()) {
                    return false;
                }

                // Use STL search with case-insensitive comparison
                const auto it = std::search(
                    str.begin(), str.end(),
                    substr.begin(), substr.end(),
                    [](wchar_t ch1, wchar_t ch2) noexcept {
                        return std::towupper(static_cast<std::wint_t>(ch1)) == 
                               std::towupper(static_cast<std::wint_t>(ch2));
                    }
                );

                return it != str.end();
            }

            // ============================================================================
            // Splitting and Joining
            // ============================================================================

            std::vector<std::wstring> Split(std::wstring_view str, std::wstring_view delimiter) {
                std::vector<std::wstring> result;

                // Handle empty input
                if (str.empty()) {
                    return result;
                }

                // Empty delimiter: return entire string as single element
                if (delimiter.empty()) {
                    try {
                        result.emplace_back(str);
                    }
                    catch (const std::bad_alloc&) {
                        return std::vector<std::wstring>{};
                    }
                    return result;
                }

                // Estimate result size for pre-allocation
                const size_t estimate = str.size() / delimiter.size() + 1;
                const size_t reserveSize = (estimate < 32) ? estimate : 32;
                
                try {
                    result.reserve(reserveSize);
                }
                catch (const std::bad_alloc&) {
                    // Continue without reservation
                }

                size_t last = 0;
                size_t next = 0;
                size_t splitCount = 0;

                while ((next = str.find(delimiter, last)) != std::wstring_view::npos) {
                    try {
                        result.emplace_back(str.substr(last, next - last));
                    }
                    catch (const std::bad_alloc&) {
                        return result;  // Return partial result
                    }
                    
                    last = next + delimiter.length();

                    // DoS protection: limit number of splits
                    if (++splitCount > kMaxOperationCount) {
                        break;
                    }
                }

                // Add final segment
                try {
                    result.emplace_back(str.substr(last));
                }
                catch (const std::bad_alloc&) {
                    // Return partial result
                }

                return result;
            }

            std::wstring Join(const std::vector<std::wstring>& elements, std::wstring_view delimiter) {
                // Handle empty input
                if (elements.empty()) {
                    return std::wstring{};
                }

                // Calculate total size with overflow protection
                size_t totalSize = 0;
                constexpr size_t maxSize = std::numeric_limits<size_t>::max() / sizeof(wchar_t);

                for (const auto& elem : elements) {
                    // Check for overflow
                    if (totalSize > maxSize - elem.size()) {
                        return std::wstring{};  // Overflow would occur
                    }
                    totalSize += elem.size();
                }

                // Add delimiter sizes (only between elements)
                if (elements.size() > 1) {
                    const size_t delimCount = elements.size() - 1;
                    const size_t delimTotalSize = delimCount * delimiter.size();
                    
                    // Check for overflow
                    if (totalSize > maxSize - delimTotalSize) {
                        return std::wstring{};
                    }
                    totalSize += delimTotalSize;
                }

                // Allocate result
                std::wstring result;
                try {
                    result.reserve(totalSize);
                }
                catch (const std::bad_alloc&) {
                    return std::wstring{};
                }

                // Build result
                result += elements[0];

                for (size_t i = 1; i < elements.size(); ++i) {
                    result += delimiter;
                    result += elements[i];
                }

                return result;
            }

            // ============================================================================
            // String Replacement
            // ============================================================================

            void ReplaceAll(std::wstring& str, std::wstring_view from, std::wstring_view to) {
                // Nothing to replace if 'from' is empty or string is empty
                if (from.empty() || str.empty()) {
                    return;
                }

                // Check if 'to' contains 'from' (would cause infinite loop with naive approach)
                const bool toContainsFrom = (to.find(from) != std::wstring_view::npos);

                // Use copy-based approach if:
                // 1. 'to' contains 'from' (avoid infinite loop)
                // 2. 'to' is larger than 'from' (may need more space)
                if (toContainsFrom || to.size() > from.size()) {
                    std::wstring result;

                    // Estimate result size
                    size_t estimatedSize = str.size();
                    if (to.size() > from.size()) {
                        const size_t diff = to.size() - from.size();
                        estimatedSize += (str.size() / from.size()) * diff / 10;  // Conservative estimate
                    }
                    
                    const size_t reserveSize = (estimatedSize < str.size() * 2) ? estimatedSize : (str.size() * 2);
                    
                    try {
                        result.reserve(reserveSize);
                    }
                    catch (const std::bad_alloc&) {
                        // Continue without reservation
                    }

                    size_t lastPos = 0;
                    size_t findPos = 0;
                    size_t replacementCount = 0;

                    while ((findPos = str.find(from, lastPos)) != std::wstring::npos) {
                        // Append text before the match
                        result.append(str, lastPos, findPos - lastPos);
                        
                        // Append replacement
                        result.append(to);
                        
                        lastPos = findPos + from.length();

                        // DoS protection
                        if (++replacementCount > kMaxOperationCount) {
                            result.append(str, lastPos, std::wstring::npos);
                            break;
                        }
                    }

                    // Append remaining text
                    result.append(str, lastPos, std::wstring::npos);
                    str = std::move(result);
                }
                else {
                    // In-place replacement (safe when 'to' is shorter or equal to 'from')
                    size_t startPos = 0;
                    size_t replacementCount = 0;

                    while ((startPos = str.find(from, startPos)) != std::wstring::npos) {
                        str.replace(startPos, from.length(), to);
                        startPos += to.length();

                        // DoS protection
                        if (++replacementCount > kMaxOperationCount) {
                            break;
                        }
                    }
                }
            }

            std::wstring ReplaceAllCopy(std::wstring str, std::wstring_view from, std::wstring_view to) {
                ReplaceAll(str, from, to);
                return str;
            }

            // ============================================================================
            // String Formatting
            // ============================================================================

            std::wstring FormatV(const wchar_t* fmt, va_list args) {
                // Handle null or empty format string
                if (!fmt || *fmt == L'\0') {
                    return std::wstring{};
                }

                // Make a copy of args for the sizing call
                va_list argsCopy;
                va_copy(argsCopy, args);

                // Determine required buffer size
                const int needed = _vscwprintf(fmt, argsCopy);
                va_end(argsCopy);

                // Check for encoding error
                if (needed < 0) {
                    return L"[StringUtils::FormatV] Encoding error";
                }

                // Security: limit output size to prevent DoS
                if (needed > kMaxFormatSize) {
                    return L"[StringUtils::FormatV] Result too large";
                }

                // Handle empty result
                if (needed == 0) {
                    return std::wstring{};
                }

                // Allocate buffer with exception safety
                std::wstring result;
                try {
                    result.resize(static_cast<size_t>(needed));
                }
                catch (const std::bad_alloc&) {
                    return L"[StringUtils::FormatV] Memory allocation failed";
                }

                // Format the string
                // Note: _vsnwprintf_s requires buffer size including null terminator
                const int written = _vsnwprintf_s(
                    result.data(), 
                    result.size() + 1,  // Buffer size including null terminator
                    static_cast<size_t>(needed),  // Max characters to write (excluding null)
                    fmt, 
                    args
                );

                // Check for write error
                if (written < 0) {
                    return L"[StringUtils::FormatV] Write error";
                }

                // Resize if less was written (shouldn't happen normally)
                if (static_cast<size_t>(written) < result.size()) {
                    result.resize(static_cast<size_t>(written));
                }

                return result;
            }

            std::wstring Format(const wchar_t* fmt, ...) {
                va_list args;
                va_start(args, fmt);
                std::wstring result = FormatV(fmt, args);
                va_end(args);
                return result;
            }

        } // namespace StringUtils
    } // namespace Utils
} // namespace ShadowStrike