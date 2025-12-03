/**
 * @file StringUtils.hpp
 * @brief Comprehensive string manipulation utilities for ShadowStrike.
 * 
 * Provides thread-safe, locale-aware string operations including:
 * - UTF-8 / UTF-16 conversion
 * - Case transformation (locale-independent)
 * - Trimming and whitespace handling
 * - String comparison (case-sensitive and insensitive)
 * - Splitting, joining, and replacement
 * - Safe formatting with variadic arguments
 * 
 * All functions are designed for Windows platforms and use Windows API
 * for consistent behavior across locales.
 * 
 * @author ShadowStrike Security Team
 * @copyright (c) 2025 ShadowStrike. All rights reserved.
 */

#pragma once

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif // Prevent Windows.h from defining min/max macros

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif // Exclude rarely-used stuff from Windows headers

#include <Windows.h>

#endif // _WIN32

#include <string>
#include <string_view>
#include <vector>
#include <cstdarg>


namespace ShadowStrike {

    namespace Utils {

        namespace StringUtils {

            // ============================================================================
            // Character Encoding Conversions
            // ============================================================================

            /**
             * @brief Converts UTF-8 string to UTF-16 (wide) string.
             * @param narrow UTF-8 encoded string view.
             * @return UTF-16 encoded wide string, or empty string on failure.
             * @note Thread-safe. Returns empty string for invalid UTF-8 or on error.
             */
            [[nodiscard]] std::wstring ToWide(std::string_view narrow) noexcept;

            /**
             * @brief Converts UTF-16 (wide) string to UTF-8 string.
             * @param wide UTF-16 encoded wide string view.
             * @return UTF-8 encoded string, or empty string on failure.
             * @note Thread-safe. Returns empty string for invalid input or on error.
             */
            [[nodiscard]] std::string ToNarrow(std::wstring_view wide) noexcept;

            /**
             * @brief Converts null-terminated UTF-8 C-string to wide string.
             * @param utf8str Null-terminated UTF-8 string (can be nullptr).
             * @return UTF-16 encoded wide string, or empty string on failure.
             * @note Thread-safe. Validates UTF-8 encoding.
             */
            [[nodiscard]] std::wstring utf8_to_wstring(const char* utf8str) noexcept;

            // ============================================================================
            // Case Transformations (Locale-Independent)
            // ============================================================================

            /**
             * @brief Converts string to lowercase in-place.
             * @param str String to modify.
             * @note Uses Windows CharLowerBuffW for locale-independent conversion.
             */
            void ToLower(std::wstring& str) noexcept;

            /**
             * @brief Returns a lowercase copy of the string.
             * @param str Source string.
             * @return Lowercase copy of the string.
             */
            [[nodiscard]] std::wstring ToLowerCopy(std::wstring_view str);

            /**
             * @brief Converts string to uppercase in-place.
             * @param str String to modify.
             * @note Uses Windows CharUpperBuffW for locale-independent conversion.
             */
            void ToUpper(std::wstring& str) noexcept;

            /**
             * @brief Returns an uppercase copy of the string.
             * @param str Source string.
             * @return Uppercase copy of the string.
             */
            [[nodiscard]] std::wstring ToUpperCopy(std::wstring_view str);

            // ============================================================================
            // Trimming Functions
            // ============================================================================

            /**
             * @brief Trims whitespace from both ends of string in-place.
             * @param str String to modify.
             * @note Whitespace includes: space, tab, newline, carriage return, form feed, vertical tab.
             */
            void Trim(std::wstring& str) noexcept;

            /**
             * @brief Trims whitespace from the left (beginning) of string in-place.
             * @param str String to modify.
             */
            void TrimLeft(std::wstring& str) noexcept;

            /**
             * @brief Trims whitespace from the right (end) of string in-place.
             * @param str String to modify.
             */
            void TrimRight(std::wstring& str) noexcept;

            /**
             * @brief Returns a copy with whitespace trimmed from both ends.
             * @param str Source string.
             * @return Trimmed copy.
             */
            [[nodiscard]] std::wstring TrimCopy(std::wstring_view str);

            /**
             * @brief Returns a copy with whitespace trimmed from the left.
             * @param str Source string.
             * @return Left-trimmed copy.
             */
            [[nodiscard]] std::wstring TrimLeftCopy(std::wstring_view str);

            /**
             * @brief Returns a copy with whitespace trimmed from the right.
             * @param str Source string.
             * @return Right-trimmed copy.
             */
            [[nodiscard]] std::wstring TrimRightCopy(std::wstring_view str);

            // ============================================================================
            // String Comparison
            // ============================================================================

            /**
             * @brief Case-insensitive string equality comparison.
             * @param s1 First string.
             * @param s2 Second string.
             * @return true if strings are equal (ignoring case), false otherwise.
             * @note Uses Windows CompareStringOrdinal for consistent behavior.
             */
            [[nodiscard]] bool IEquals(std::wstring_view s1, std::wstring_view s2) noexcept;

            /**
             * @brief Checks if string starts with the given prefix (case-sensitive).
             * @param str String to check.
             * @param prefix Prefix to look for.
             * @return true if str starts with prefix.
             */
            [[nodiscard]] bool StartsWith(std::wstring_view str, std::wstring_view prefix) noexcept;

            /**
             * @brief Checks if string ends with the given suffix (case-sensitive).
             * @param str String to check.
             * @param suffix Suffix to look for.
             * @return true if str ends with suffix.
             */
            [[nodiscard]] bool EndsWith(std::wstring_view str, std::wstring_view suffix) noexcept;

            /**
             * @brief Checks if string contains substring (case-sensitive).
             * @param str String to search in.
             * @param substr Substring to find.
             * @return true if substr is found in str.
             */
            [[nodiscard]] bool Contains(std::wstring_view str, std::wstring_view substr) noexcept;

            /**
             * @brief Checks if string contains substring (case-insensitive).
             * @param str String to search in.
             * @param substr Substring to find.
             * @return true if substr is found in str (ignoring case).
             */
            [[nodiscard]] bool IContains(std::wstring_view str, std::wstring_view substr) noexcept;

            // ============================================================================
            // Splitting and Joining
            // ============================================================================

            /**
             * @brief Splits string by delimiter into vector of substrings.
             * @param str String to split.
             * @param delimiter Delimiter string.
             * @return Vector of substrings.
             * @note Returns single-element vector with original string if delimiter is empty.
             * @note Limited to 1,000,000 splits for DoS protection.
             */
            [[nodiscard]] std::vector<std::wstring> Split(std::wstring_view str, std::wstring_view delimiter);

            /**
             * @brief Joins vector of strings with delimiter.
             * @param elements Strings to join.
             * @param delimiter Delimiter to insert between elements.
             * @return Joined string, or empty string on overflow.
             */
            [[nodiscard]] std::wstring Join(const std::vector<std::wstring>& elements, std::wstring_view delimiter);

            // ============================================================================
            // String Replacement
            // ============================================================================

            /**
             * @brief Replaces all occurrences of substring in-place.
             * @param str String to modify.
             * @param from Substring to find.
             * @param to Replacement string.
             * @note Limited to 1,000,000 replacements for DoS protection.
             * @note Safe even when 'to' contains 'from'.
             */
            void ReplaceAll(std::wstring& str, std::wstring_view from, std::wstring_view to);

            /**
             * @brief Returns copy with all occurrences of substring replaced.
             * @param str Source string.
             * @param from Substring to find.
             * @param to Replacement string.
             * @return String with replacements applied.
             */
            [[nodiscard]] std::wstring ReplaceAllCopy(std::wstring str, std::wstring_view from, std::wstring_view to);

            // ============================================================================
            // String Formatting
            // ============================================================================

            /**
             * @brief Printf-style string formatting.
             * @param fmt Format string (printf-style).
             * @param ... Format arguments.
             * @return Formatted string, or error message on failure.
             * @note Limited to 1MB output for safety.
             */
            [[nodiscard]] std::wstring Format(const wchar_t* fmt, ...);

            /**
             * @brief Printf-style formatting with va_list.
             * @param fmt Format string (printf-style).
             * @param args Variable argument list.
             * @return Formatted string, or error message on failure.
             * @note Limited to 1MB output for safety.
             */
            [[nodiscard]] std::wstring FormatV(const wchar_t* fmt, va_list args);

        } // namespace StringUtils

    } // namespace Utils

} // namespace ShadowStrike