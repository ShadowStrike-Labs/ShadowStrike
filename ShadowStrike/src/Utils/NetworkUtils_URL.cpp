// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

#include"pch.h"
#include"NetworkUtils.hpp"

namespace ShadowStrike {
	namespace Utils {
		namespace NetworkUtils {


			// ============================================================================
			// Internal Helper Functions
			// ============================================================================

			namespace Internal {

				inline void SetError(Error* err, DWORD win32, std::wstring_view msg, std::wstring_view ctx = L"") {
					if (err) {
						err->win32 = win32;
						err->message = msg;
						err->context = ctx;
					}
				}

				inline void SetWsaError(Error* err, int wsaErr, std::wstring_view ctx = L"") {
					if (err) {
						err->wsaError = wsaErr;
						err->win32 = wsaErr;
						err->message = FormatWsaError(wsaErr);
						err->context = ctx;
					}
				}

				inline bool IsWhitespace(wchar_t c) noexcept {
					return c == L' ' || c == L'\t' || c == L'\r' || c == L'\n';
				}

				inline std::wstring_view TrimWhitespace(std::wstring_view str) noexcept {
					size_t start = 0;
					while (start < str.size() && IsWhitespace(str[start])) ++start;
					size_t end = str.size();
					while (end > start && IsWhitespace(str[end - 1])) --end;
					return str.substr(start, end - start);
				}

				inline bool EqualsIgnoreCase(std::wstring_view a, std::wstring_view b) noexcept {
					if (a.size() != b.size()) return false;
					return std::equal(a.begin(), a.end(), b.begin(), b.end(),
						[](wchar_t ca, wchar_t cb) {
							return ::towlower(ca) == ::towlower(cb);
						});
				}

				inline uint16_t NetworkToHost16(uint16_t net) noexcept {
					return ntohs(net);
				}

				inline uint32_t NetworkToHost32(uint32_t net) noexcept {
					return ntohl(net);
				}

				inline uint16_t HostToNetwork16(uint16_t host) noexcept {
					return htons(host);
				}

				inline uint32_t HostToNetwork32(uint32_t host) noexcept {
					return htonl(host);
				}

			} // namespace Internal


			// ============================================================================
			// URL Manipulation
			// ============================================================================

			bool ParseUrl(std::wstring_view url, UrlComponents& components, Error* err) noexcept {
				try {
					components = UrlComponents{};

					URL_COMPONENTS urlComp{};
					urlComp.dwStructSize = sizeof(urlComp);

					wchar_t scheme[32] = {};
					wchar_t host[256] = {};
					wchar_t user[128] = {};
					wchar_t pass[128] = {};
					wchar_t path[2048] = {}
					;					wchar_t query[2048] = {};
					wchar_t fragment[128] = {};

					urlComp.lpszScheme = scheme;
					urlComp.dwSchemeLength = _countof(scheme);
					urlComp.lpszHostName = host;
					urlComp.dwHostNameLength = _countof(host);
					urlComp.lpszUserName = user;
					urlComp.dwUserNameLength = _countof(user);
					urlComp.lpszPassword = pass;
					urlComp.dwPasswordLength = _countof(pass);
					urlComp.lpszUrlPath = path;
					urlComp.dwUrlPathLength = _countof(path);
					urlComp.lpszExtraInfo = query;
					urlComp.dwExtraInfoLength = _countof(query);

					std::wstring urlCopy(url);
					if (!::WinHttpCrackUrl(urlCopy.c_str(), 0, 0, &urlComp)) {
						Internal::SetError(err, ::GetLastError(), L"WinHttpCrackUrl failed");
						return false;
					}

					components.scheme = scheme;
					components.host = host;
					components.username = user;
					components.password = pass;
					components.path = path;
					components.query = query;
					components.port = urlComp.nPort;

					return true;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in ParseUrl");
					return false;
				}
			}

			std::wstring BuildUrl(const UrlComponents& components) noexcept {
				std::wostringstream oss;

				if (!components.scheme.empty()) {
					oss << components.scheme << L"://";
				}

				if (!components.username.empty()) {
					oss << components.username;
					if (!components.password.empty()) {
						oss << L':' << components.password;
					}
					oss << L'@';
				}

				oss << components.host;

				if (components.port != 0 && components.port != 80 && components.port != 443) {
					oss << L':' << components.port;
				}

				oss << components.path;

				if (!components.query.empty()) {
					if (components.query[0] != L'?') {
						oss << L'?';
					}
					oss << components.query;
				}

				if (!components.fragment.empty()) {
					if (components.fragment[0] != L'#') {
						oss << L'#';
					}
					oss << components.fragment;
				}

				return oss.str();
			}

			std::wstring UrlEncode(std::wstring_view str) noexcept {
				try {
					if (str.empty()) {
						return std::wstring();
					}

					// First convert to UTF-8 for proper encoding
					std::string utf8;
					{
						int utf8Len = WideCharToMultiByte(CP_UTF8, 0, str.data(),
							static_cast<int>(str.size()), nullptr, 0, nullptr, nullptr);
						if (utf8Len <= 0) {
							return std::wstring();
						}
						utf8.resize(static_cast<size_t>(utf8Len));
						WideCharToMultiByte(CP_UTF8, 0, str.data(),
							static_cast<int>(str.size()), utf8.data(), utf8Len, nullptr, nullptr);
					}

					std::wostringstream oss;
					oss << std::hex << std::uppercase;

					for (unsigned char c : utf8) {
						if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
							oss << static_cast<wchar_t>(c);
						}
						else if (c == ' ') {
							oss << L'+';
						}
						else {
							oss << L'%' << std::setw(2) << std::setfill(L'0') << static_cast<int>(c);
						}
					}

					return oss.str();
				}
				catch (...) {
					return std::wstring();
				}
			}

			std::wstring UrlDecode(std::wstring_view str) noexcept {
				try {
					if (str.empty()) {
						return std::wstring();
					}

					// Decode to UTF-8 bytes first
					std::vector<char> utf8;
					utf8.reserve(str.length());

					for (size_t i = 0; i < str.length(); ++i) {
						wchar_t wc = str[i];

						if (wc == L'%' && i + 2 < str.length()) {
							// Validate hex characters
							wchar_t h1 = str[i + 1];
							wchar_t h2 = str[i + 2];

							auto isHexChar = [](wchar_t c) -> bool {
								return (c >= L'0' && c <= L'9') ||
									(c >= L'A' && c <= L'F') ||
									(c >= L'a' && c <= L'f');
								};

							if (isHexChar(h1) && isHexChar(h2)) {
								auto hexToInt = [](wchar_t c) -> int {
									if (c >= L'0' && c <= L'9') return c - L'0';
									if (c >= L'A' && c <= L'F') return c - L'A' + 10;
									if (c >= L'a' && c <= L'f') return c - L'a' + 10;
									return 0;
									};

								int value = (hexToInt(h1) << 4) | hexToInt(h2);
								utf8.push_back(static_cast<char>(value));
								i += 2;
							}
							else {
								// Invalid percent encoding, keep literal
								utf8.push_back('%');
							}
						}
						else if (wc == L'+') {
							utf8.push_back(' ');
						}
						else if (wc < 128) {
							utf8.push_back(static_cast<char>(wc));
						}
						else {
							// Non-ASCII in URL - encode as UTF-8
							wchar_t wcBuf[2] = { wc, L'\0' };
							char utf8Buf[4] = {};
							int len = WideCharToMultiByte(CP_UTF8, 0, wcBuf, 1, utf8Buf, 4, nullptr, nullptr);
							for (int j = 0; j < len; ++j) {
								utf8.push_back(utf8Buf[j]);
							}
						}
					}

					// Convert UTF-8 back to wide string
					if (utf8.empty()) {
						return std::wstring();
					}

					int wideLen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
						utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
					if (wideLen <= 0) {
						// Fallback to ACP
						wideLen = MultiByteToWideChar(CP_ACP, 0, utf8.data(),
							static_cast<int>(utf8.size()), nullptr, 0);
						if (wideLen <= 0) {
							return std::wstring();
						}
						std::wstring result(static_cast<size_t>(wideLen), L'\0');
						MultiByteToWideChar(CP_ACP, 0, utf8.data(),
							static_cast<int>(utf8.size()), result.data(), wideLen);
						return result;
					}

					std::wstring result(static_cast<size_t>(wideLen), L'\0');
					MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
						utf8.data(), static_cast<int>(utf8.size()), result.data(), wideLen);
					return result;

				}
				catch (...) {
					return std::wstring();
				}
			}

			std::wstring ExtractDomain(std::wstring_view url) noexcept {
				UrlComponents components;
				if (ParseUrl(url, components, nullptr)) {
					return components.host;
				}
				return L"";
			}

			std::wstring ExtractHostname(std::wstring_view url) noexcept {
				return ExtractDomain(url);
			}

			bool IsValidUrl(std::wstring_view url) noexcept {
				UrlComponents components;
				return ParseUrl(url, components, nullptr);
			}

			// ============================================================================
			// Domain and Host Validation
			// ============================================================================

			bool IsValidDomain(std::wstring_view domain) noexcept {
				if (domain.empty() || domain.length() > 253) {
					return false;
				}

				size_t pos = 0;
				while (pos < domain.length()) {
					size_t dotPos = domain.find(L'.', pos);
					size_t labelLen = (dotPos == std::wstring_view::npos) ? (domain.length() - pos) : (dotPos - pos);

					if (labelLen == 0 || labelLen > 63) {
						return false;
					}

					std::wstring_view label = domain.substr(pos, labelLen);
					for (wchar_t c : label) {
						if (!std::isalnum(static_cast<unsigned char>(c)) && c != L'-') {
							return false;
						}
					}

					if (label[0] == L'-' || label[labelLen - 1] == L'-') {
						return false;
					}

					if (dotPos == std::wstring_view::npos) break;
					pos = dotPos + 1;
				}

				return true;
			}

			bool IsValidHostname(std::wstring_view hostname) noexcept {
				return IsValidDomain(hostname);
			}

			bool IsInternationalDomain(std::wstring_view domain) noexcept {
				for (wchar_t c : domain) {
					if (c > 127) {
						return true;
					}
				}
				return false;
			}

			// RFC 3492 compliant Punycode implementation
			namespace PunycodeConstants {
				constexpr uint32_t BASE = 36;
				constexpr uint32_t TMIN = 1;
				constexpr uint32_t TMAX = 26;
				constexpr uint32_t SKEW = 38;
				constexpr uint32_t DAMP = 700;
				constexpr uint32_t INITIAL_BIAS = 72;
				constexpr uint32_t INITIAL_N = 0x80;
				constexpr wchar_t DELIMITER = L'-';
				constexpr std::wstring_view PREFIX = L"xn--";
			}

			namespace {
				inline uint32_t AdaptBias(uint32_t delta, uint32_t numpoints, bool firsttime) noexcept {
					if (numpoints == 0) return 0;

					delta = firsttime ? delta / PunycodeConstants::DAMP : delta >> 1;
					delta += delta / numpoints;

					uint32_t k = 0;
					while (delta > ((PunycodeConstants::BASE - PunycodeConstants::TMIN) * PunycodeConstants::TMAX) / 2) {
						delta /= PunycodeConstants::BASE - PunycodeConstants::TMIN;
						k += PunycodeConstants::BASE;
					}

					return k + (((PunycodeConstants::BASE - PunycodeConstants::TMIN + 1) * delta) /
						(delta + PunycodeConstants::SKEW));
				}

				inline wchar_t EncodeDigit(uint32_t d) noexcept {
					return static_cast<wchar_t>(d + 22 + 75 * (d < 26));
				}

				inline uint32_t DecodeDigit(wchar_t c) noexcept {
					if (c >= L'0' && c <= L'9') return c - L'0' + 26;
					if (c >= L'A' && c <= L'Z') return c - L'A';
					if (c >= L'a' && c <= L'z') return c - L'a';
					return PunycodeConstants::BASE;
				}

				inline bool IsBasicCodePoint(wchar_t c) noexcept {
					return c < 0x80;
				}
			}

			std::wstring PunycodeEncode(std::wstring_view domain) noexcept {
				try {
					// Quick check - if all ASCII, no encoding needed
					if (!IsInternationalDomain(domain)) {
						return std::wstring(domain);
					}

					std::wstring result;
					result.reserve(domain.length() * 2);

					// Extract and copy basic code points
					size_t basicCount = 0;
					for (wchar_t c : domain) {
						if (IsBasicCodePoint(c)) {
							result += c;
							++basicCount;
						}
					}

					size_t handledCount = basicCount;

					// Add delimiter if we have basic characters
					if (handledCount > 0) {
						result += PunycodeConstants::DELIMITER;
					}

					uint32_t n = PunycodeConstants::INITIAL_N;
					uint32_t delta = 0;
					uint32_t bias = PunycodeConstants::INITIAL_BIAS;

					// Process non-basic code points
					while (handledCount < domain.length()) {
						// Find next code point to encode
						uint32_t m = 0x10FFFF;
						for (wchar_t c : domain) {
							uint32_t codepoint = static_cast<uint32_t>(c);
							if (codepoint >= n && codepoint < m) {
								m = codepoint;
							}
						}

						// Increase delta
						delta += (m - n) * (handledCount + 1);
						n = m;

						// Encode all occurrences of this code point
						for (wchar_t c : domain) {
							uint32_t codepoint = static_cast<uint32_t>(c);

							if (codepoint < n) {
								++delta;
							}
							else if (codepoint == n) {
								uint32_t q = delta;

								for (uint32_t k = PunycodeConstants::BASE; ; k += PunycodeConstants::BASE) {
									uint32_t t;
									if (k <= bias) {
										t = PunycodeConstants::TMIN;
									}
									else if (k >= bias + PunycodeConstants::TMAX) {
										t = PunycodeConstants::TMAX;
									}
									else {
										t = k - bias;
									}

									if (q < t) break;

									result += EncodeDigit(t + (q - t) % (PunycodeConstants::BASE - t));
									q = (q - t) / (PunycodeConstants::BASE - t);
								}

								result += EncodeDigit(q);
								bias = AdaptBias(delta, handledCount + 1, handledCount == basicCount);
								delta = 0;
								++handledCount;
							}
						}

						++delta;
						++n;
					}

					return std::wstring(PunycodeConstants::PREFIX) + result;

				}
				catch (...) {
					// Fallback on error
					return std::wstring(domain);
				}
			}

			std::wstring PunycodeDecode(std::wstring_view punycode) noexcept {
				try {
					// Check for punycode prefix
					if (punycode.substr(0, PunycodeConstants::PREFIX.length()) != PunycodeConstants::PREFIX) {
						return std::wstring(punycode);
					}

					// Remove prefix
					std::wstring_view encoded = punycode.substr(PunycodeConstants::PREFIX.length());

					std::wstring result;
					result.reserve(encoded.length());

					// Find delimiter position
					size_t delimiterPos = encoded.rfind(PunycodeConstants::DELIMITER);

					// Copy basic code points
					if (delimiterPos != std::wstring_view::npos) {
						result.append(encoded.substr(0, delimiterPos));
						encoded = encoded.substr(delimiterPos + 1);
					}

					uint32_t n = PunycodeConstants::INITIAL_N;
					uint32_t i = 0;
					uint32_t bias = PunycodeConstants::INITIAL_BIAS;

					// Decode non-basic code points
					for (size_t pos = 0; pos < encoded.length(); ) {
						uint32_t oldi = i;
						uint32_t w = 1;

						for (uint32_t k = PunycodeConstants::BASE; ; k += PunycodeConstants::BASE) {
							if (pos >= encoded.length()) {
								return std::wstring(punycode); // Invalid encoding
							}

							uint32_t digit = DecodeDigit(encoded[pos++]);
							if (digit >= PunycodeConstants::BASE) {
								return std::wstring(punycode); // Invalid digit
							}

							i += digit * w;

							uint32_t t;
							if (k <= bias) {
								t = PunycodeConstants::TMIN;
							}
							else if (k >= bias + PunycodeConstants::TMAX) {
								t = PunycodeConstants::TMAX;
							}
							else {
								t = k - bias;
							}

							if (digit < t) break;

							w *= (PunycodeConstants::BASE - t);
						}

						bias = AdaptBias(i - oldi, result.length() + 1, oldi == 0);
						n += i / (result.length() + 1);
						i %= (result.length() + 1);

						// Insert decoded character
						if (n > 0x10FFFF) {
							return std::wstring(punycode); // Invalid code point
						}

						result.insert(result.begin() + i, static_cast<wchar_t>(n));
						++i;
					}

					return result;

				}
				catch (...) {
					// Fallback on error
					return std::wstring(punycode);
				}
			}
		}
	}
}