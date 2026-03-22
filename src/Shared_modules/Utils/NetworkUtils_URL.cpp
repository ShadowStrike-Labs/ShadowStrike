/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
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

					// Input length validation — reject excessively long URLs
					constexpr size_t MAX_URL_LENGTH = 65536;
					if (url.empty() || url.size() > MAX_URL_LENGTH) {
						SS_LOG_ERROR(L"NetworkUtils: ParseUrl invalid URL length=%zu", url.size());
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"URL empty or exceeds maximum length");
						return false;
					}

					URL_COMPONENTS urlComp{};
					urlComp.dwStructSize = sizeof(urlComp);

					wchar_t scheme[32] = {};
					wchar_t host[256] = {};
					wchar_t user[128] = {};
					wchar_t pass[128] = {};
					wchar_t path[2048] = {};
					wchar_t extraInfo[4096] = {};

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
					urlComp.lpszExtraInfo = extraInfo;
					urlComp.dwExtraInfoLength = _countof(extraInfo);

					std::wstring urlCopy(url);
					if (!::WinHttpCrackUrl(urlCopy.c_str(), 0, 0, &urlComp)) {
						DWORD lastErr = ::GetLastError();
						SS_LOG_WARN(L"NetworkUtils: WinHttpCrackUrl failed err=%lu", lastErr);
						Internal::SetError(err, lastErr, L"WinHttpCrackUrl failed");
						return false;
					}

					// Detect silent truncation by WinHttpCrackUrl
					if (urlComp.dwSchemeLength >= _countof(scheme) - 1 ||
						urlComp.dwHostNameLength >= _countof(host) - 1 ||
						urlComp.dwUrlPathLength >= _countof(path) - 1) {
						SS_LOG_WARN(L"NetworkUtils: URL component truncated by fixed buffer");
						Internal::SetError(err, ERROR_BUFFER_OVERFLOW, L"URL component exceeds buffer size");
						return false;
					}

					components.scheme = scheme;
					components.host = host;
					components.username = user;
					components.password = pass;
					components.path = path;
					components.port = urlComp.nPort;

					// Parse query and fragment from ExtraInfo (WinHttpCrackUrl combines them)
					std::wstring_view extra(extraInfo);
					size_t hashPos = extra.find(L'#');
					if (hashPos != std::wstring_view::npos) {
						components.query = extra.substr(0, hashPos);
						components.fragment = extra.substr(hashPos + 1);
					}
					else {
						components.query = extra;
					}

					// Wipe password buffer from stack
					::SecureZeroMemory(pass, sizeof(pass));

					return true;

				}
				catch (...) {
					SS_LOG_ERROR(L"NetworkUtils: Exception in ParseUrl");
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in ParseUrl");
					return false;
				}
			}

			std::wstring BuildUrl(const UrlComponents& components) noexcept {
				try {
					std::wstring result;
					result.reserve(components.scheme.size() + components.host.size() +
						components.path.size() + components.query.size() +
						components.fragment.size() + 32);

					if (!components.scheme.empty()) {
						result += components.scheme;
						result += L"://";
					}

					if (!components.username.empty()) {
						result += components.username;
						if (!components.password.empty()) {
							result += L':';
							result += L"****";
						}
						result += L'@';
					}

					result += components.host;

					// Scheme-aware default port suppression
					bool suppressPort = false;
					if (components.port == 0) {
						suppressPort = true;
					}
					else if (Internal::EqualsIgnoreCase(components.scheme, L"http") && components.port == 80) {
						suppressPort = true;
					}
					else if (Internal::EqualsIgnoreCase(components.scheme, L"https") && components.port == 443) {
						suppressPort = true;
					}
					else if (Internal::EqualsIgnoreCase(components.scheme, L"ftp") && components.port == 21) {
						suppressPort = true;
					}

					if (!suppressPort) {
						result += L':';
						result += std::to_wstring(components.port);
					}

					result += components.path;

					if (!components.query.empty()) {
						if (components.query[0] != L'?') {
							result += L'?';
						}
						result += components.query;
					}

					if (!components.fragment.empty()) {
						if (components.fragment[0] != L'#') {
							result += L'#';
						}
						result += components.fragment;
					}

					return result;
				}
				catch (...) {
					SS_LOG_ERROR(L"NetworkUtils: Exception in BuildUrl");
					return std::wstring();
				}
			}

			std::wstring UrlEncode(std::wstring_view str) noexcept {
				try {
					if (str.empty()) {
						return std::wstring();
					}

					// Reject excessively large input to prevent DoS
					if (str.size() > 65536 || str.size() > static_cast<size_t>(INT_MAX)) {
						SS_LOG_ERROR(L"NetworkUtils: UrlEncode input too large length=%zu", str.size());
						return std::wstring();
					}

					// Convert to UTF-8 for proper percent-encoding
					std::string utf8;
					{
						int utf8Len = WideCharToMultiByte(CP_UTF8, 0, str.data(),
							static_cast<int>(str.size()), nullptr, 0, nullptr, nullptr);
						if (utf8Len <= 0) {
							SS_LOG_WARN(L"NetworkUtils: UrlEncode WideCharToMultiByte failed");
							return std::wstring();
						}
						utf8.resize(static_cast<size_t>(utf8Len));
						WideCharToMultiByte(CP_UTF8, 0, str.data(),
							static_cast<int>(str.size()), utf8.data(), utf8Len, nullptr, nullptr);
					}

					// RFC 3986 percent-encoding (not form-encoding)
					static constexpr wchar_t hexChars[] = L"0123456789ABCDEF";
					std::wstring result;
					result.reserve(utf8.size() * 2);

					for (unsigned char c : utf8) {
						if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
							result += static_cast<wchar_t>(c);
						}
						else {
							result += L'%';
							result += hexChars[(c >> 4) & 0x0F];
							result += hexChars[c & 0x0F];
						}
					}

					return result;
				}
				catch (...) {
					SS_LOG_ERROR(L"NetworkUtils: Exception in UrlEncode");
					return std::wstring();
				}
			}

			std::wstring UrlDecode(std::wstring_view str) noexcept {
				try {
					if (str.empty()) {
						return std::wstring();
					}

					// Reject excessively large input
					if (str.size() > 65536) {
						SS_LOG_ERROR(L"NetworkUtils: UrlDecode input too large length=%zu", str.size());
						return std::wstring();
					}

					auto isHexChar = [](wchar_t c) -> bool {
						return (c >= L'0' && c <= L'9') ||
							(c >= L'A' && c <= L'F') ||
							(c >= L'a' && c <= L'f');
					};

					auto hexToInt = [](wchar_t c) -> int {
						if (c >= L'0' && c <= L'9') return c - L'0';
						if (c >= L'A' && c <= L'F') return c - L'A' + 10;
						if (c >= L'a' && c <= L'f') return c - L'a' + 10;
						return 0;
					};

					// Decode to UTF-8 bytes first
					std::vector<char> utf8;
					utf8.reserve(str.length());

					for (size_t i = 0; i < str.length(); ++i) {
						wchar_t wc = str[i];

						if (wc == L'%' && i + 2 < str.length()) {
							wchar_t h1 = str[i + 1];
							wchar_t h2 = str[i + 2];

							if (isHexChar(h1) && isHexChar(h2)) {
								int value = (hexToInt(h1) << 4) | hexToInt(h2);
								utf8.push_back(static_cast<char>(value));
								i += 2;
							}
							else {
								utf8.push_back('%');
							}
						}
						else if (wc == L'+') {
							utf8.push_back(' ');
						}
						else if (wc < 128) {
							utf8.push_back(static_cast<char>(wc));
						}
						else if (wc >= 0xD800 && wc <= 0xDBFF && i + 1 < str.length()) {
							// UTF-16 surrogate pair — validate low surrogate before combining
							wchar_t next = str[i + 1];
							if (next >= 0xDC00 && next <= 0xDFFF) {
								wchar_t wcBuf[2] = { wc, next };
								char utf8Buf[4] = {};
								int len = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
									wcBuf, 2, utf8Buf, 4, nullptr, nullptr);
								if (len > 0) {
									for (int j = 0; j < len; ++j) utf8.push_back(utf8Buf[j]);
									++i;
								}
							}
							// else: orphan high surrogate — skip silently
						}
						else {
							// Non-ASCII single wchar_t — encode as UTF-8
							wchar_t wcBuf[2] = { wc, L'\0' };
							char utf8Buf[4] = {};
							int len = WideCharToMultiByte(CP_UTF8, 0, wcBuf, 1, utf8Buf, 4, nullptr, nullptr);
							for (int j = 0; j < len; ++j) utf8.push_back(utf8Buf[j]);
						}
					}

					if (utf8.empty()) {
						return std::wstring();
					}

					// Convert UTF-8 back to wide string — strict UTF-8, no fallback
					int wideLen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
						utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
					if (wideLen <= 0) {
						SS_LOG_WARN(L"NetworkUtils: UrlDecode invalid UTF-8 sequence in URL");
						return std::wstring();
					}

					std::wstring result(static_cast<size_t>(wideLen), L'\0');
					MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
						utf8.data(), static_cast<int>(utf8.size()), result.data(), wideLen);
					return result;

				}
				catch (...) {
					SS_LOG_ERROR(L"NetworkUtils: Exception in UrlDecode");
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

				// Accept trailing dot (FQDN notation per RFC 1035)
				std::wstring_view d = domain;
				if (d.size() > 1 && d.back() == L'.') {
					d = d.substr(0, d.size() - 1);
				}

				size_t pos = 0;
				while (pos < d.length()) {
					size_t dotPos = d.find(L'.', pos);
					size_t labelLen = (dotPos == std::wstring_view::npos) ? (d.length() - pos) : (dotPos - pos);

					if (labelLen == 0 || labelLen > 63) {
						return false;
					}

					std::wstring_view label = d.substr(pos, labelLen);
					for (wchar_t c : label) {
						// ASCII alphanumeric + hyphen for LDH labels (RFC 5890)
						// Non-ASCII chars allowed for IDN, but reject invalid codepoints
						if (c > 127) {
							// Reject surrogates, C1 controls, and non-characters
							if ((c >= 0xD800 && c <= 0xDFFF) ||
								(c >= 0x80 && c <= 0x9F) ||
								c == 0xFFFE || c == 0xFFFF) {
								return false;
							}
							continue; // Valid IDN codepoint
						}
						if (!((c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') ||
							(c >= L'0' && c <= L'9') || c == L'-')) {
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
					if (!IsInternationalDomain(domain)) {
						return std::wstring(domain);
					}

					// Cap input length
					if (domain.size() > 4096) {
						SS_LOG_WARN(L"NetworkUtils: PunycodeEncode domain too long length=%zu", domain.size());
						return std::wstring(domain);
					}

					// Convert UTF-16 to UTF-32 codepoints (handle surrogate pairs)
					std::vector<uint32_t> codepoints;
					codepoints.reserve(domain.size());
					for (size_t i = 0; i < domain.size(); ++i) {
						uint32_t cp = static_cast<uint32_t>(domain[i]);
						if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < domain.size()) {
							uint32_t low = static_cast<uint32_t>(domain[i + 1]);
							if (low >= 0xDC00 && low <= 0xDFFF) {
								cp = 0x10000 + ((cp & 0x3FF) << 10) + (low & 0x3FF);
								++i;
							}
						}
						codepoints.push_back(cp);
					}

					std::wstring result;
					result.reserve(codepoints.size() * 2);

					size_t basicCount = 0;
					for (uint32_t cp : codepoints) {
						if (cp < 0x80) {
							result += static_cast<wchar_t>(cp);
							++basicCount;
						}
					}

					size_t handledCount = basicCount;
					if (handledCount > 0) {
						result += PunycodeConstants::DELIMITER;
					}

					uint32_t n = PunycodeConstants::INITIAL_N;
					uint32_t delta = 0;
					uint32_t bias = PunycodeConstants::INITIAL_BIAS;
					const size_t totalCount = codepoints.size();

					while (handledCount < totalCount) {
						uint32_t m = 0x10FFFF;
						for (uint32_t cp : codepoints) {
							if (cp >= n && cp < m) m = cp;
						}

						// Overflow guard
						if (m - n > (UINT32_MAX - delta) / (handledCount + 1)) {
							SS_LOG_ERROR(L"NetworkUtils: PunycodeEncode overflow in delta computation");
							return std::wstring(domain);
						}
						delta += (m - n) * static_cast<uint32_t>(handledCount + 1);
						n = m;

						for (uint32_t cp : codepoints) {
							if (cp < n) {
								if (++delta == 0) {
									return std::wstring(domain); // Overflow
								}
							}
							else if (cp == n) {
								uint32_t q = delta;

								for (uint32_t k = PunycodeConstants::BASE; ; k += PunycodeConstants::BASE) {
									uint32_t t;
									if (k <= bias) t = PunycodeConstants::TMIN;
									else if (k >= bias + PunycodeConstants::TMAX) t = PunycodeConstants::TMAX;
									else t = k - bias;

									if (q < t) break;

									result += EncodeDigit(t + (q - t) % (PunycodeConstants::BASE - t));
									q = (q - t) / (PunycodeConstants::BASE - t);

									if (result.size() > 16384) {
										SS_LOG_ERROR(L"NetworkUtils: PunycodeEncode output too large");
										return std::wstring(domain);
									}
								}

								result += EncodeDigit(q);
								bias = AdaptBias(delta, static_cast<uint32_t>(handledCount + 1),
									handledCount == basicCount);
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
					SS_LOG_ERROR(L"NetworkUtils: Exception in PunycodeEncode");
					return std::wstring(domain);
				}
			}

			std::wstring PunycodeDecode(std::wstring_view punycode) noexcept {
				try {
					if (punycode.substr(0, PunycodeConstants::PREFIX.length()) != PunycodeConstants::PREFIX) {
						return std::wstring(punycode);
					}

					// Cap input length
					if (punycode.size() > 4096) {
						SS_LOG_WARN(L"NetworkUtils: PunycodeDecode input too long length=%zu", punycode.size());
						return std::wstring(punycode);
					}

					std::wstring_view encoded = punycode.substr(PunycodeConstants::PREFIX.length());

					// Decode into UTF-32 codepoints, then convert to UTF-16
					std::vector<uint32_t> output;
					output.reserve(encoded.length());

					size_t delimiterPos = encoded.rfind(PunycodeConstants::DELIMITER);
					if (delimiterPos != std::wstring_view::npos) {
						for (size_t j = 0; j < delimiterPos; ++j) {
							output.push_back(static_cast<uint32_t>(encoded[j]));
						}
						encoded = encoded.substr(delimiterPos + 1);
					}

					uint32_t n = PunycodeConstants::INITIAL_N;
					uint32_t i = 0;
					uint32_t bias = PunycodeConstants::INITIAL_BIAS;

					for (size_t pos = 0; pos < encoded.length(); ) {
						uint32_t oldi = i;
						uint32_t w = 1;

						for (uint32_t k = PunycodeConstants::BASE; ; k += PunycodeConstants::BASE) {
							if (pos >= encoded.length()) {
								return std::wstring(punycode);
							}

							uint32_t digit = DecodeDigit(encoded[pos++]);
							if (digit >= PunycodeConstants::BASE) {
								return std::wstring(punycode);
							}

							// Overflow guard: i += digit * w
							if (digit > (UINT32_MAX - i) / w) {
								SS_LOG_ERROR(L"NetworkUtils: PunycodeDecode overflow in i+=digit*w");
								return std::wstring(punycode);
							}
							i += digit * w;

							uint32_t t;
							if (k <= bias) t = PunycodeConstants::TMIN;
							else if (k >= bias + PunycodeConstants::TMAX) t = PunycodeConstants::TMAX;
							else t = k - bias;

							if (digit < t) break;

							// Overflow guard: w *= (BASE - t)
							uint32_t factor = PunycodeConstants::BASE - t;
							if (w > UINT32_MAX / factor) {
								SS_LOG_ERROR(L"NetworkUtils: PunycodeDecode overflow in w*=factor");
								return std::wstring(punycode);
							}
							w *= factor;
						}

						uint32_t outLen = static_cast<uint32_t>(output.size()) + 1;
						bias = AdaptBias(i - oldi, outLen, oldi == 0);
						n += i / outLen;
						i %= outLen;

						if (n > 0x10FFFF) {
							return std::wstring(punycode);
						}

						// Output length cap
						if (output.size() > 4096) {
							SS_LOG_ERROR(L"NetworkUtils: PunycodeDecode output too large");
							return std::wstring(punycode);
						}

						// Insert decoded codepoint (bounds check i)
						if (i > output.size()) {
							return std::wstring(punycode);
						}
						output.insert(output.begin() + i, n);
						++i;
					}

					// Convert UTF-32 codepoints to UTF-16 wstring (with surrogate pairs)
					std::wstring result;
					result.reserve(output.size() * 2);
					for (uint32_t cp : output) {
						if (cp <= 0xFFFF) {
							result += static_cast<wchar_t>(cp);
						}
						else {
							// Emit UTF-16 surrogate pair
							uint32_t adj = cp - 0x10000;
							result += static_cast<wchar_t>(0xD800 + (adj >> 10));
							result += static_cast<wchar_t>(0xDC00 + (adj & 0x3FF));
						}
					}

					return result;

				}
				catch (...) {
					SS_LOG_ERROR(L"NetworkUtils: Exception in PunycodeDecode");
					return std::wstring(punycode);
				}
			}
		}
	}
}