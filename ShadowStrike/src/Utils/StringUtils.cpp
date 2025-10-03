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
                int size_needed = MultiByteToWideChar(CP_UTF8, 0, narrow.data(), (int)narrow.size(), NULL, 0);
                if (size_needed <= 0) {
					//Return empty string on failure
                    return L"";
                }
                std::wstring wide_str(size_needed, 0);
                MultiByteToWideChar(CP_UTF8, 0, narrow.data(), (int)narrow.size(), &wide_str[0], size_needed);
                return wide_str;
            }

            std::string ToNarrow(std::wstring_view wide) {
                if (wide.empty()) {
                    //Return empty string on failure
                    return "";
                }
                int size_needed = WideCharToMultiByte(CP_UTF8, 0, wide.data(), (int)wide.size(), NULL, 0, NULL, NULL);
                if (size_needed <= 0) {
                    //Return empty string on failure
                    return "";
                }
                std::string narrow_str(size_needed, 0);
                WideCharToMultiByte(CP_UTF8, 0, wide.data(), (int)wide.size(), &narrow_str[0], size_needed, NULL, NULL);
                return narrow_str;
            }


            //lower case upper case transformations
            void ToLower(std::wstring& str) {
                if (str.empty()) return;
                // CharLowerW,Could be locale dependent but it is enough in most cases.
                CharLowerW(&str[0]);
            }

            std::wstring ToLowerCopy(std::wstring_view str) {
                std::wstring result(str);
                ToLower(result);
                return result;
            }

            void ToUpper(std::wstring& str) {
                if (str.empty()) return;
                CharUpperW(&str[0]);
            }

            std::wstring ToUpperCopy(std::wstring_view str) {
                std::wstring result(str);
                ToUpper(result);
                return result;
            }

			//Trimming functions
            const wchar_t* WHITESPACE = L" \t\n\r\f\v";

            void TrimLeft(std::wstring& str) {
                str.erase(0, str.find_first_not_of(WHITESPACE));
            }

            void TrimRight(std::wstring& str) {
                str.erase(str.find_last_not_of(WHITESPACE) + 1);
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

                auto it = std::search(
                    str.begin(), str.end(),
                    substr.begin(), substr.end(),
                    [](wchar_t ch1, wchar_t ch2) { return std::towupper(ch1) == std::towupper(ch2); }
                );
                return (it != str.end());
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
                size_t start_pos = 0;
                while ((start_pos = str.find(from, start_pos)) != std::wstring::npos) {
                    str.replace(start_pos, from.length(), to);
                    start_pos += to.length();
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

				int needed = _vscwprintf(fmt, args_copy); // Only calculates the size needed
                va_end(args_copy);

                if (needed < 0) {
                    return L"[StringUtils::FormatV] Encoding error.";
                }

				std::wstring result(needed, L'\0'); //Not need +1 for null terminator, because _vsnwprintf_s handles it.

                int written = _vsnwprintf_s(&result[0], result.size() + 1, _TRUNCATE, fmt, args);
                if (written < 0) {
                    return L"[StringUtils::FormatV] Write error.";
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