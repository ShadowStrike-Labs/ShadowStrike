#include "StringUtils.hpp"
#include <limits>
#include <algorithm>
#include <cstdarg>
#include <cwctype>
#include<stdexcept>

namespace ShadowStrike {
	namespace Utils {
		namespace StringUtils {


			//Character code conversions
            std::wstring ToWide(std::string_view narrow) {
                if (narrow.empty()) {
                    return L"";
                }
                
                // Validate size doesn't exceed INT_MAX (Win32 API limit)
                if (narrow.size() > static_cast<size_t>(INT_MAX)) {
                    return L""; // String too large
                }
                
                int size_needed = MultiByteToWideChar(CP_UTF8, 0, narrow.data(), 
                    static_cast<int>(narrow.size()), nullptr, 0);
                
                if (size_needed <= 0) {
                    return L""; // Conversion failed
                }
                
                // Use numeric_limits instead of max_size()
                constexpr size_t MAX_WSTRING_SIZE = std::numeric_limits<size_t>::max() / sizeof(wchar_t);
                if (static_cast<size_t>(size_needed) > MAX_WSTRING_SIZE) {
                    return L""; // Would exceed max string size
                }
                
                std::wstring wide_str(static_cast<size_t>(size_needed), L'\0');
                
                int result = MultiByteToWideChar(CP_UTF8, 0, narrow.data(), 
                    static_cast<int>(narrow.size()), wide_str.data(), size_needed);
                
                // Verify actual conversion succeeded
                if (result != size_needed) {
                    return L""; // Partial conversion failure
                }
                
                return wide_str;
            }

            std::string ToNarrow(std::wstring_view wide) {
                if (wide.empty()) {
                    return "";
                }
                
                // Validate size doesn't exceed INT_MAX
                if (wide.size() > static_cast<size_t>(INT_MAX)) {
                    return ""; // String too large
                }
                
                int size_needed = WideCharToMultiByte(CP_UTF8, 0, wide.data(), 
                    static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
                
                if (size_needed <= 0) {
                    return ""; // Conversion failed
                }
                
                // Use numeric_limits
                constexpr size_t MAX_STRING_SIZE = std::numeric_limits<size_t>::max();
                if (static_cast<size_t>(size_needed) > MAX_STRING_SIZE) {
                    return ""; // Would exceed max string size
                }
                
                std::string narrow_str(static_cast<size_t>(size_needed), '\0');
                
                int result = WideCharToMultiByte(CP_UTF8, 0, wide.data(), 
                    static_cast<int>(wide.size()), narrow_str.data(), size_needed, nullptr, nullptr);
                
                // Verify actual conversion succeeded
                if (result != size_needed) {
                    return ""; // Partial conversion failure
                }
                
                return narrow_str;
            }


            //lower case upper case transformations
            void ToLower(std::wstring& str) {
                if (str.empty()) return;
                
                // Validate size doesn't exceed DWORD max
                if (str.size() > static_cast<size_t>(MAXDWORD)) {
                    // For very large strings, process in chunks
                    constexpr size_t CHUNK_SIZE = MAXDWORD / 2;
                    for (size_t offset = 0; offset < str.size(); offset += CHUNK_SIZE) {
                        size_t remaining = str.size() - offset;
                        size_t chunk_len = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;
                        CharLowerBuffW(&str[offset], static_cast<DWORD>(chunk_len));
                    }
                } else {
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
                
                // Validate size doesn't exceed DWORD max
                if (str.size() > static_cast<size_t>(MAXDWORD)) {
                    // Process in chunks for very large strings
                    constexpr size_t CHUNK_SIZE = MAXDWORD / 2;
                    for (size_t offset = 0; offset < str.size(); offset += CHUNK_SIZE) {
                        size_t remaining = str.size() - offset;
                        size_t chunk_len = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;
                        CharUpperBuffW(&str[offset], static_cast<DWORD>(chunk_len));
                    }
                } else {
                    CharUpperBuffW(str.data(), static_cast<DWORD>(str.size()));
                }
            }

            std::wstring ToUpperCopy(std::wstring_view str) {
                std::wstring result(str);
                ToUpper(result);
                return result;
            }

			//Trimming functions
            const wchar_t* WHITESPACE = L" \t\n\r\f\v";

            void TrimLeft(std::wstring& str) {
                if (str.empty()) return;
                
                size_t pos = str.find_first_not_of(WHITESPACE);
                
                // Handle all-whitespace case
                if (pos == std::wstring::npos) {
                    str.clear(); // String is all whitespace
                } else if (pos > 0) {
                    str.erase(0, pos);
                }
            }

            void TrimRight(std::wstring& str) {
                if (str.empty()) return;
                
                size_t pos = str.find_last_not_of(WHITESPACE);
                
                // Handle all-whitespace case
                if (pos == std::wstring::npos) {
                    str.clear(); // String is all whitespace
                } else if (pos + 1 < str.size()) {
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

            std::wstring utf8_to_wstring(const char* utf8)
            {
                if (!utf8)
                    return L"";

                int size_needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                    utf8, -1, nullptr, 0);
                if (size_needed == 0)
                    throw std::runtime_error("MultiByteToWideChar failed");

                std::wstring wstr(size_needed, 0);

                int result = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                    utf8, -1,
                    &wstr[0], size_needed);

                if (result == 0)
                    throw std::runtime_error("MultiByteToWideChar failed");

                //it came with null terminator, remove it
                wstr.pop_back();

                return wstr;
            }
            //Comparing
            bool IEquals(std::wstring_view s1, std::wstring_view s2) {
                // Validate sizes don't exceed INT_MAX
                if (s1.size() > static_cast<size_t>(INT_MAX) || 
                    s2.size() > static_cast<size_t>(INT_MAX)) {
                    return false; // Sizes too large for API
                }
                
                // Handle nullptr data() case (shouldn't happen with string_view, but be safe)
                if (s1.empty() && s2.empty()) return true;
                if (s1.empty() || s2.empty()) return false;
                
				// CompareStringOrdinal is locale independent and fast
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
                if (str.empty()) return false;
                if (substr.size() > str.size()) return false;
                
                // Optimized case-insensitive search with size validation
                
                // For very short strings, use simple algorithm
                if (str.size() < 50 && substr.size() < 20) {
                    auto it = std::search(
                        str.begin(), str.end(),
                        substr.begin(), substr.end(),
                        [](wchar_t ch1, wchar_t ch2) { 
                            return std::towupper(ch1) == std::towupper(ch2); 
                        }
                    );
                    return (it != str.end());
                }
                
                // For larger strings, use CompareStringOrdinal (but validate sizes)
                if (str.size() > static_cast<size_t>(INT_MAX) || 
                    substr.size() > static_cast<size_t>(INT_MAX)) {
                    // Fallback to STL for huge strings
                    auto it = std::search(
                        str.begin(), str.end(),
                        substr.begin(), substr.end(),
                        [](wchar_t ch1, wchar_t ch2) { 
                            return std::towupper(ch1) == std::towupper(ch2); 
                        }
                    );
                    return (it != str.end());
                }
                
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
                
                // Handle empty delimiter (would cause infinite loop)
                if (delimiter.empty()) {
                    result.emplace_back(str); // Return whole string as single element
                    return result;
                }
                
                // Reserve capacity to avoid reallocations (estimate)
                size_t estimate = str.size() / delimiter.size() + 1;
                size_t reserve_size = (estimate < 32) ? estimate : 32;
                result.reserve(reserve_size);
                
                size_t last = 0;
                size_t next = 0;
                
                while ((next = str.find(delimiter, last)) != std::wstring_view::npos) {
                    result.emplace_back(str.substr(last, next - last));
                    last = next + delimiter.length();
                    
                    //  Prevent excessive memory allocation (DoS protection)
                    if (result.size() > 1000000) { // 1M elements limit
                        break; // Abort to prevent memory exhaustion
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
                
                //  Check for size_t overflow when calculating total size
                size_t total_size = 0;
                constexpr size_t MAX_WSTRING_SIZE = std::numeric_limits<size_t>::max() / sizeof(wchar_t);
                
                // Calculate total size with overflow protection
                for (const auto& s : elements) {
                    if (total_size > MAX_WSTRING_SIZE - s.size()) {
                        return L""; // Would overflow, abort
                    }
                    total_size += s.size();
                }
                
                // Add delimiter sizes
                if (elements.size() > 1) {
                    size_t delim_count = elements.size() - 1;
                    if (total_size > MAX_WSTRING_SIZE - (delim_count * delimiter.size())) {
                        return L""; // Would overflow, abort
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

            //Changing
            void ReplaceAll(std::wstring& str, std::wstring_view from, std::wstring_view to) {
                if (from.empty() || str.empty()) {
                    return;
                }
                
                // Prevent infinite loop when 'to' contains 'from'
                // Example: ReplaceAll(str, "a", "aa") would loop forever without this
                
                bool to_contains_from = (to.find(from) != std::wstring_view::npos);
                
                if (to_contains_from || to.size() > from.size()) {
                    // Use temporary string to avoid infinite loop or performance issues
                    std::wstring result;
                    
                    // Estimate result size to avoid reallocations
                    size_t estimated_size = str.size();
                    if (to.size() > from.size()) {
                        // Rough estimate: assume 10% of string matches
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
                        
                        // Prevent excessive replacements (DoS protection)
                        if (++replacement_count > 1000000) { // 1M replacements limit
                            result.append(str, last_pos, std::wstring::npos);
                            break;
                        }
                    }
                    
                    result.append(str, last_pos, std::wstring::npos);
                    str = std::move(result);
                    
                } else {
                    // Safe to do in-place replacement (to.size() <= from.size() and no overlap)
                    size_t start_pos = 0;
                    size_t replacement_count = 0;
                    
                    while ((start_pos = str.find(from, start_pos)) != std::wstring::npos) {
                        str.replace(start_pos, from.length(), to);
                        start_pos += to.length();
                        
                        //  Prevent excessive replacements (DoS protection)
                        if (++replacement_count > 1000000) { // 1M replacements limit
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
                //  Validate fmt is not null
                if (!fmt || *fmt == L'\0') {
                    return L"";
                }

                va_list args_copy;
                va_copy(args_copy, args);

                int needed = _vscwprintf(fmt, args_copy);
                va_end(args_copy);

                // Handle encoding error
                if (needed < 0) {
                    return L"[StringUtils::FormatV] Encoding error";
                }
                
                // Prevent excessive allocation (DoS protection)
                if (needed > 1048576) { // 1MB limit for formatted strings
                    return L"[StringUtils::FormatV] Result too large";
                }

                //  Allocate exact size and handle write errors
                std::wstring result(static_cast<size_t>(needed), L'\0');

                int written = _vsnwprintf_s(result.data(), result.size() + 1, result.size(), fmt, args);
                
                //  Handle write failure
                if (written < 0) {
                    return L"[StringUtils::FormatV] Write error";
                }
                
                // Resize to actual written length (shouldn't differ, but be safe)
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

		}//namespace StringUtils
	}//namespace Utils
}//namespace ShadowStrike