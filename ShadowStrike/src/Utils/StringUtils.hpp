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


namespace ShadowStrike {

	namespace Utils {

		namespace StringUtils {

			//Character code conversions

			//UTF-8(std::string) to UTF-16(std::wstring)
			std::wstring ToWide(std::string_view narrow);

			//UTF-16(std::wstring) to UTF-8(std::string)
			std::string ToNarrow(std::wstring_view wide);

			//LOWER/UPPER case conversions (Locale independent)

			void ToLower(std::wstring& str);

			std::wstring ToLowerCopy(std::wstring_view str);

			void ToUpper(std::wstring& str);

			std::wstring ToUpperCopy(std::wstring_view str);

			std::wstring utf8_to_wstring(const char* utf8str);
			//Trimming functions

			void Trim(std::wstring& str);

			void TrimLeft(std::wstring& str);

			void TrimRight(std::wstring& str);

			std::wstring TrimCopy(std::wstring_view str);

			std::wstring TrimLeftCopy(std::wstring_view str);

			std::wstring TrimRightCopy(std::wstring_view str);

			//Comparing

			
			bool IEquals(std::wstring_view s1, std::wstring_view s2);


			bool StartsWith(std::wstring_view str, std::wstring_view prefix);

			bool EndsWith(std::wstring_view str, std::wstring_view suffix);

			bool Contains(std::wstring_view str, std::wstring_view substr);

			bool IContains(std::wstring_view str, std::wstring_view substr);

			//splitting and joining
			std::vector<std::wstring> Split(std::wstring_view str, std::wstring_view delimiter);

			std::wstring Join(const std::vector<std::wstring>& elements, std::wstring_view delimiter);

			//Changing
			// Splits the string by the specified separator and returns it as a vector.
			void ReplaceAll(std::wstring& str, std::wstring_view from, std::wstring_view to);

			// Returns a new copy by replacing all specified substrings in the string with the new one.
			std::wstring ReplaceAllCopy(std::wstring str, std::wstring_view from, std::wstring_view to);

			//Formatting
			std::wstring Format(const wchar_t* fmt, ...);
			std::wstring FormatV(const wchar_t* fmt, va_list args);
		}
	}
}