#include "StringUtils.hpp"
#include <limits>
#include <algorithm>
#include <cstdarg>
#include <cwctype>
#include <stdexcept>

namespace ShadowStrike {
    namespace Utils {
        namespace StringUtils {

            // Character code conversions
            std::wstring ToWide(std::string_view narrow) {
                if (narrow.empty()) {
                    return L"";
                }

                if (narrow.size() > static_cast<size_t>(INT_MAX)) {
                    return L"";
                }

                int size_needed = MultiByteToWideChar(CP_UTF8, 0, narrow.data(),
                    static_cast<int>(narrow.size()), nullptr, 0);

                if (size_needed <= 0) {
                    return L"";
                }

                constexpr size_t MAX_WSTRING_SIZE = std::numeric_limits<size_t>::max() / sizeof(wchar_t);
                if (static_cast<size_t>(size_needed) > MAX_WSTRING_SIZE) {
                    return L"";
                }

                // -1 because MultiByteToWideChar includes null terminator in count
                std::wstring wide_str(static_cast<size_t>(size_needed - 1), L'\0');

                int result = MultiByteToWideChar(CP_UTF8, 0, narrow.data(),
                    static_cast<int>(narrow.size()), wide_str.data(), size_needed);

                if (result != size_needed) {
                    return L"";
                }

                return wide_str;
            }

            std::string ToNarrow(std::wstring_view wide) {
                if (wide.empty()) {
                    return "";
                }

                if (wide.size() > static_cast<size_t>(INT_MAX)) {
                    return "";
                }

                int size_needed = WideCharToMultiByte(CP_UTF8, 0, wide.data(),
                    static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);

                if (size_needed <= 0) {
                    return "";
                }

                constexpr size_t MAX_STRING_SIZE = std::numeric_limits<size_t>::max();
                if (static_cast<size_t>(size_needed) > MAX_STRING_SIZE) {
                    return "";
                }

                // -1 because WideCharToMultiByte includes null terminator in count
                std::string narrow_str(static_cast<size_t>(size_needed - 1), '\0');

                int result = WideCharToMultiByte(CP_UTF8, 0, wide.data(),
                    static_cast<int>(wide.size()), narrow_str.data(), size_needed, nullptr, nullptr);

                if (result != size_needed) {
                    return "";
                }

                return narrow_str;
            }

            // Lower case upper case transformations
            void ToLower(std::wstring& str) {
                if (str.empty()) return;

                if (str.size() > static_cast<size_t>(MAXDWORD)) {
                    constexpr size_t CHUNK_SIZE = MAXDWORD / 2;
                    for (size_t offset = 0; offset < str.size(); offset += CHUNK_SIZE) {
                        size_t remaining = str.size() - offset;
                        size_t chunk_len = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;
                        CharLowerBuffW(&str[offset], static_cast<DWORD>(chunk_len));
                    }
                }
                else {
                    CharLowerBuffW(str.data(), static_cast<DWORD>(str.size()));
                }
            }

            std::wstring ToLowerCopy(std::wstring_view str) {
                std::wstring result(str);
                ToLower(result);
                return result;
            }

            void ToUpper(std::wstring& str) {
                if (str.empty()) return;

                if (str.size() > static_cast<size_t>(MAXDWORD)) {
                    constexpr size_t CHUNK_SIZE = MAXDWORD / 2;
                    for (size_t offset = 0; offset < str.size(); offset += CHUNK_SIZE) {
                        size_t remaining = str.size() - offset;
                        size_t chunk_len = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;
                        CharUpperBuffW(&str[offset], static_cast<DWORD>(chunk_len));
                    }
                }
                else {
                    CharUpperBuffW(str.data(), static_cast<DWORD>(str.size()));
                }
            }

            std::wstring ToUpperCopy(std::wstring_view str) {
                std::wstring result(str);
                ToUpper(result);
                return result;
            }

            // Trimming functions
            const wchar_t* WHITESPACE = L" \t\n\r\f\v";

            void TrimLeft(std::wstring& str) {
                if (str.empty()) return;

                size_t pos = str.find_first_not_of(WHITESPACE);

                if (pos == std::wstring::npos) {
                    str.clear();
                }
                else if (pos > 0) {
                    str.erase(0, pos);
                }
            }

            void TrimRight(std::wstring& str) {
                if (str.empty()) return;

                size_t pos = str.find_last_not_of(WHITESPACE);

                if (pos == std::wstring::npos) {
                    str.clear();
                }
                else if (pos + 1 < str.size()) {
                    str.erase(pos + 1);
                }
            }

            void Trim(std::wstring& str) {
                TrimRight(str);
                TrimLeft(str);
            }

            std::wstring TrimCopy(std::wstring_view str) {
                std::wstring s(str);
                Trim(s);
                return s;
            }

            std::wstring TrimLeftCopy(std::wstring_view str) {
                std::wstring s(str);
                TrimLeft(s);
                return s;
            }

            std::wstring TrimRightCopy(std::wstring_view str) {
                std::wstring s(str);
                TrimRight(s);
                return s;
            }

            std::wstring utf8_to_wstring(const char* utf8) noexcept {
                if (!utf8 || *utf8 == '\0') {
                    return L"";
                }

                int size_needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                    utf8, -1, nullptr, 0);

                if (size_needed <= 0) {
                    return L"";
                }

                std::wstring wstr(static_cast<size_t>(size_needed - 1), L'\0');

                int result = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                    utf8, -1, wstr.data(), size_needed);

                if (result <= 0) {
                    return L"";
                }

                return wstr;
            }

            // Comparing
            bool IEquals(std::wstring_view s1, std::wstring_view s2) {
                if (s1.size() > static_cast<size_t>(INT_MAX) ||
                    s2.size() > static_cast<size_t>(INT_MAX)) {
                    return false;
                }

                if (s1.empty() && s2.empty()) return true;
                if (s1.empty() || s2.empty()) return false;

                return CompareStringOrdinal(s1.data(), static_cast<int>(s1.length()),
                    s2.data(), static_cast<int>(s2.length()),
                    TRUE) == CSTR_EQUAL;
            }

            bool StartsWith(std::wstring_view str, std::wstring_view prefix) {
                return str.size() >= prefix.size() &&
                    str.substr(0, prefix.size()) == prefix;
            }

            bool EndsWith(std::wstring_view str, std::wstring_view suffix) {
                return str.size() >= suffix.size() &&
                    str.substr(str.size() - suffix.size()) == suffix;
            }

            bool Contains(std::wstring_view str, std::wstring_view substr) {
                return str.find(substr) != std::wstring_view::npos;
            }

            bool IContains(std::wstring_view str, std::wstring_view substr) {
                if (substr.empty()) return true;
                if (str.empty() || substr.size() > str.size()) return false;

                // Use STL search for efficiency
                auto it = std::search(
                    str.begin(), str.end(),
                    substr.begin(), substr.end(),
                    [](wchar_t ch1, wchar_t ch2) {
                        return std::towupper(ch1) == std::towupper(ch2);
                    }
                );

                return it != str.end();
            }

            // Splitting and joining
            std::vector<std::wstring> Split(std::wstring_view str, std::wstring_view delimiter) {
                std::vector<std::wstring> result;

                if (str.empty()) {
                    return result;
                }

                if (delimiter.empty()) {
                    result.emplace_back(str);
                    return result;
                }

                size_t estimate = str.size() / delimiter.size() + 1;
                size_t reserve_size = (estimate < 32) ? estimate : 32;
                result.reserve(reserve_size);

                size_t last = 0;
                size_t next = 0;

                while ((next = str.find(delimiter, last)) != std::wstring_view::npos) {
                    result.emplace_back(str.substr(last, next - last));
                    last = next + delimiter.length();

                    if (result.size() > 1000000) {
                        break;
                    }
                }

                result.emplace_back(str.substr(last));
                return result;
            }

            std::wstring Join(const std::vector<std::wstring>& elements, std::wstring_view delimiter) {
                std::wstring result;

                if (elements.empty()) {
                    return result;
                }

                size_t total_size = 0;
                constexpr size_t MAX_WSTRING_SIZE = std::numeric_limits<size_t>::max() / sizeof(wchar_t);

                for (const auto& s : elements) {
                    if (total_size > MAX_WSTRING_SIZE - s.size()) {
                        return L"";
                    }
                    total_size += s.size();
                }

                if (elements.size() > 1) {
                    size_t delim_count = elements.size() - 1;
                    if (total_size > MAX_WSTRING_SIZE - (delim_count * delimiter.size())) {
                        return L"";
                    }
                    total_size += delim_count * delimiter.size();
                }

                result.reserve(total_size);
                result += elements[0];

                for (size_t i = 1; i < elements.size(); ++i) {
                    result += delimiter;
                    result += elements[i];
                }

                return result;
            }

            // Changing
            void ReplaceAll(std::wstring& str, std::wstring_view from, std::wstring_view to) {
                if (from.empty() || str.empty()) {
                    return;
                }

                bool to_contains_from = (to.find(from) != std::wstring_view::npos);

                if (to_contains_from || to.size() > from.size()) {
                    std::wstring result;

                    size_t estimated_size = str.size();
                    if (to.size() > from.size()) {
                        size_t diff = to.size() - from.size();
                        estimated_size += (str.size() / from.size()) * diff / 10;
                    }
                    size_t reserve_size = (estimated_size < str.size() * 2) ? estimated_size : (str.size() * 2);
                    result.reserve(reserve_size);

                    size_t last_pos = 0;
                    size_t find_pos = 0;
                    size_t replacement_count = 0;

                    while ((find_pos = str.find(from, last_pos)) != std::wstring::npos) {
                        result.append(str, last_pos, find_pos - last_pos);
                        result.append(to);
                        last_pos = find_pos + from.length();

                        if (++replacement_count > 1000000) {
                            result.append(str, last_pos, std::wstring::npos);
                            break;
                        }
                    }

                    result.append(str, last_pos, std::wstring::npos);
                    str = std::move(result);

                }
                else {
                    size_t start_pos = 0;
                    size_t replacement_count = 0;

                    while ((start_pos = str.find(from, start_pos)) != std::wstring::npos) {
                        str.replace(start_pos, from.length(), to);
                        start_pos += to.length();

                        if (++replacement_count > 1000000) {
                            break;
                        }
                    }
                }
            }

            std::wstring ReplaceAllCopy(std::wstring str, std::wstring_view from, std::wstring_view to) {
                ReplaceAll(str, from, to);
                return str;
            }

            std::wstring FormatV(const wchar_t* fmt, va_list args) {
                if (!fmt || *fmt == L'\0') {
                    return L"";
                }

                va_list args_copy;
                va_copy(args_copy, args);

                int needed = _vscwprintf(fmt, args_copy);
                va_end(args_copy);

                if (needed < 0) {
                    return L"[StringUtils::FormatV] Encoding error";
                }

                if (needed > 1048576) {
                    return L"[StringUtils::FormatV] Result too large";
                }

                std::wstring result(static_cast<size_t>(needed), L'\0');

                int written = _vsnwprintf_s(result.data(), result.size() + 1, needed, fmt, args);

                if (written < 0) {
                    return L"[StringUtils::FormatV] Write error";
                }

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