#include "StringUtils.hpp"
#include <algorithm>
#include <cstdarg>
#include <cwctype>

namespace ShadowStrike {
	namespace Utils {
		namespace StringUtils {


			//Character code conversions
            std::wstring ToWide(std::string_view narrow) {
                if (narrow.empty()) {
                    //Return empty string on failure
                    return L"";
                }
                
                // ? FIX #5: Validate size doesn't exceed INT_MAX
                if (narrow.size() > static_cast<size_t>(INT_MAX)) {
                    // String too large for Win32 API
                    return L"";
                }
                
                int size_needed = MultiByteToWideChar(CP_UTF8, 0, narrow.data(), static_cast<int>(narrow.size()), NULL, 0);
                if (size_needed <= 0) {
					//Return empty string on failure
                    return L"";
                }
                std::wstring wide_str(size_needed, 0);
                MultiByteToWideChar(CP_UTF8, 0, narrow.data(), static_cast<int>(narrow.size()), &wide_str[0], size_needed);
                return wide_str;
            }

            std::string ToNarrow(std::wstring_view wide) {
                if (wide.empty()) {
                    //Return empty string on failure
                    return "";
                }
                
                // ? FIX #5: Validate size doesn't exceed INT_MAX
                if (wide.size() > static_cast<size_t>(INT_MAX)) {
                    // String too large for Win32 API
                    return "";
                }
                
                int size_needed = WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), NULL, 0, NULL, NULL);
                if (size_needed <= 0) {
                    //Return empty string on failure
                    return "";
                }
                std::string narrow_str(size_needed, 0);
                WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), &narrow_str[0], size_needed, NULL, NULL);
                return narrow_str;
            }


            //lower case upper case transformations
            void ToLower(std::wstring& str) {
                if (str.empty()) return;
                
                // ? FIX #6: Ensure null-termination for CharLowerW (it expects null-terminated string)
                // CharLowerW operates on null-terminated strings, not raw buffers
                // Use CharLowerBuffW for in-place transformation on buffer
                CharLowerBuffW(&str[0], static_cast<DWORD>(str.size()));
            }

            std::wstring ToLowerCopy(std::wstring_view str) {
                std::wstring result(str);
                ToLower(result);
                return result;
            }

            void ToUpper(std::wstring& str) {
                if (str.empty()) return;
                
                // ? FIX #6: Use CharUpperBuffW for in-place transformation
                CharUpperBuffW(&str[0], static_cast<DWORD>(str.size()));
            }

            std::wstring ToUpperCopy(std::wstring_view str) {
                std::wstring result(str);
                ToUpper(result);
                return result;
            }

			//Trimming functions
            const wchar_t* WHITESPACE = L" \t\n\r\f\v";

            void TrimLeft(std::wstring& str) {
                // ? FIX #7: Handle npos case (all whitespace or empty string)
                size_t pos = str.find_first_not_of(WHITESPACE);
                if (pos == std::wstring::npos) {
                    // String is all whitespace - clear it
                    str.clear();
                } else {
                    str.erase(0, pos);
                }
            }

            void TrimRight(std::wstring& str) {
                // ? FIX #8: Handle npos case (all whitespace or empty string)
                size_t pos = str.find_last_not_of(WHITESPACE);
                if (pos == std::wstring::npos) {
                    // String is all whitespace - clear it
                    str.clear();
                } else {
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


            //Comparing
            bool IEquals(std::wstring_view s1, std::wstring_view s2) {
				//CompareStringOrdinal is locale independent and fast.
                return CompareStringOrdinal(s1.data(), (int)s1.length(), s2.data(), (int)s2.length(), TRUE) == CSTR_EQUAL;
            }

            bool StartsWith(std::wstring_view str, std::wstring_view prefix) {
                return str.size() >= prefix.size() && str.substr(0, prefix.size()) == prefix;
            }

            bool EndsWith(std::wstring_view str, std::wstring_view suffix) {
                return str.size() >= suffix.size() && str.substr(str.size() - suffix.size()) == suffix;
            }

            bool Contains(std::wstring_view str, std::wstring_view substr) {
                return str.find(substr) != std::wstring_view::npos;
            }

            bool IContains(std::wstring_view str, std::wstring_view substr) {
                if (substr.empty()) return true;
                if (str.empty()) return false;
                
                // ? FIX #9: Use more efficient algorithm with pre-converted strings
                // Instead of calling towupper on every character comparison repeatedly,
                // convert both strings once and use standard find
                
                // For very short strings, keep old algorithm (faster for small inputs)
                if (str.size() < 50 && substr.size() < 20) {
                    auto it = std::search(
                        str.begin(), str.end(),
                        substr.begin(), substr.end(),
                        [](wchar_t ch1, wchar_t ch2) { return std::towupper(ch1) == std::towupper(ch2); }
                    );
                    return (it != str.end());
                }
                
                // For larger strings, use CompareStringOrdinal in chunks
                if (substr.size() > str.size()) return false;
                
                for (size_t i = 0; i <= str.size() - substr.size(); ++i) {
                    if (CompareStringOrdinal(
                        str.data() + i, static_cast<int>(substr.size()),
                        substr.data(), static_cast<int>(substr.size()),
                        TRUE) == CSTR_EQUAL) {
                        return true;
                    }
                }
                
                return false;
            }


			//splitting and joining
            std::vector<std::wstring> Split(std::wstring_view str, std::wstring_view delimiter) {
                std::vector<std::wstring> result;
                if (str.empty()) {
                    return result;
                }
                size_t last = 0;
                size_t next = 0;
                while ((next = str.find(delimiter, last)) != std::wstring_view::npos) {
                    result.emplace_back(str.substr(last, next - last));
                    last = next + delimiter.length();
                }
                result.emplace_back(str.substr(last));
                return result;
            }

            std::wstring Join(const std::vector<std::wstring>& elements, std::wstring_view delimiter) {
                std::wstring result;
                if (elements.empty()) {
                    return result;
                }
                size_t total_size = (elements.size() - 1) * delimiter.size();
                for (const auto& s : elements) {
                    total_size += s.size();
                }
                result.reserve(total_size);
                result += elements[0];
                for (size_t i = 1; i < elements.size(); ++i) {
                    result += delimiter;
                    result += elements[i];
                }
                return result;
            }

            //Changing
            void ReplaceAll(std::wstring& str, std::wstring_view from, std::wstring_view to) {
                if (from.empty()) {
                    return;
                }
                
                // ? FIX #11: Prevent infinite loop when 'to' contains 'from'
                // Example: ReplaceAll(str, "a", "aa") would loop forever
                // Strategy: If 'to' contains 'from', use a temporary string to avoid re-matching
                
                bool to_contains_from = (to.find(from) != std::wstring_view::npos);
                
                if (to_contains_from) {
                    // Use temporary string to avoid infinite loop
                    std::wstring result;
                    result.reserve(str.size()); // Reserve at least original size
                    
                    size_t last_pos = 0;
                    size_t find_pos = 0;
                    
                    while ((find_pos = str.find(from, last_pos)) != std::wstring::npos) {
                        result.append(str, last_pos, find_pos - last_pos);
                        result.append(to);
                        last_pos = find_pos + from.length();
                    }
                    result.append(str, last_pos, std::wstring::npos);
                    
                    str = std::move(result);
                } else {
                    // Safe to do in-place replacement
                    size_t start_pos = 0;
                    while ((start_pos = str.find(from, start_pos)) != std::wstring::npos) {
                        str.replace(start_pos, from.length(), to);
                        start_pos += to.length();
                    }
                }
            }

            std::wstring ReplaceAllCopy(std::wstring str, std::wstring_view from, std::wstring_view to) {
                ReplaceAll(str, from, to);
                return str;
            }


            std::wstring FormatV(const wchar_t* fmt, va_list args) {
                if (!fmt) return L"";

                va_list args_copy;
                va_copy(args_copy, args);

                int needed = _vscwprintf(fmt, args_copy);
                va_end(args_copy);

                if (needed < 0) {
                    return L"[StringUtils::FormatV] Encoding error.";
                }

                // ? FIX #10: Allocate exact size needed (not +1) and use _TRUNCATE safely
                std::wstring result(needed, L'\0');

                // Use _vsnwprintf_s with exact buffer size (result.size() is already correct)
                int written = _vsnwprintf_s(&result[0], result.size() + 1, result.size(), fmt, args);
                
                if (written < 0) {
                    return L"[StringUtils::FormatV] Write error.";
                }
                
                // Resize to actual written length (in case of truncation, though shouldn't happen)
                if (static_cast<size_t>(written) < result.size()) {
                    result.resize(written);
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

		}//namespace StringUtils
	}//namespace Utils
}//namespace ShadowStrike