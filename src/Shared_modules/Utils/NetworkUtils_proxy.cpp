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
#include <WinInet.h>


#pragma comment(lib, "WinInet.lib")

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
		// Proxy Detection and Configuration
		// ============================================================================

			bool GetSystemProxySettings(ProxyInfo& proxy, Error* err) noexcept {
				try {
					SS_LOG_DEBUG(L"NetworkUtils", L"GetSystemProxySettings querying IE proxy config");
					proxy = ProxyInfo{};

					WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyConfig{};

					if (!::WinHttpGetIEProxyConfigForCurrentUser(&proxyConfig)) {
						SS_LOG_ERROR(L"NetworkUtils", L"WinHttpGetIEProxyConfigForCurrentUser failed err=%lu", ::GetLastError());
					Internal::SetError(err, ::GetLastError(), L"WinHttpGetIEProxyConfigForCurrentUser failed");
						return false;
					}

					// RAII cleanup for allocated strings
					struct ProxyConfigCleanup {
						WINHTTP_CURRENT_USER_IE_PROXY_CONFIG* config;
						~ProxyConfigCleanup() {
							if (config->lpszProxy) ::GlobalFree(config->lpszProxy);
							if (config->lpszProxyBypass) ::GlobalFree(config->lpszProxyBypass);
							if (config->lpszAutoConfigUrl) ::GlobalFree(config->lpszAutoConfigUrl);
						}
					};
					ProxyConfigCleanup cleanup{ &proxyConfig };

					proxy.enabled = (proxyConfig.lpszProxy != nullptr);
					proxy.autoDetect = proxyConfig.fAutoDetect;

					if (proxyConfig.lpszProxy) {
						proxy.server = proxyConfig.lpszProxy;
					}

					if (proxyConfig.lpszProxyBypass) {
						proxy.bypass = proxyConfig.lpszProxyBypass;
					}

					if (proxyConfig.lpszAutoConfigUrl) {
						proxy.autoConfigUrl = proxyConfig.lpszAutoConfigUrl;
					}

					return true;

				}
				catch (...) {
					SS_LOG_ERROR(L"NetworkUtils", L"Exception in GetSystemProxySettings");
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in GetSystemProxySettings");
					return false;
				}
			}

			bool SetSystemProxySettings(const ProxyInfo& proxy, Error* err) noexcept {
				try {
					SS_LOG_WARN(L"NetworkUtils", L"SetSystemProxySettings modifying system proxy — enabled=%d server=%ls",
						proxy.enabled ? 1 : 0, proxy.server.c_str());

					// Internet Settings registry path
					constexpr wchar_t REG_PATH[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

					HKEY hKey = nullptr;
					LONG result = ::RegOpenKeyExW(HKEY_CURRENT_USER, REG_PATH, 0, KEY_WRITE, &hKey);

					if (result != ERROR_SUCCESS) {
						Internal::SetError(err, result, L"Failed to open Internet Settings registry key");
						return false;
					}

					// RAII wrapper for registry key
					struct RegKeyDeleter {
						void operator()(HKEY h) const {
							if (h) ::RegCloseKey(h);
						}
					};
					std::unique_ptr<std::remove_pointer_t<HKEY>, RegKeyDeleter> keyGuard(hKey);

					// Set ProxyEnable
					DWORD proxyEnable = proxy.enabled ? 1 : 0;
					result = ::RegSetValueExW(hKey, L"ProxyEnable", 0, REG_DWORD,
						reinterpret_cast<const BYTE*>(&proxyEnable), sizeof(DWORD));

					if (result != ERROR_SUCCESS) {
						Internal::SetError(err, result, L"Failed to set ProxyEnable");
						return false;
					}

					// Set ProxyServer
					if (proxy.enabled && !proxy.server.empty()) {
						result = ::RegSetValueExW(hKey, L"ProxyServer", 0, REG_SZ,
							reinterpret_cast<const BYTE*>(proxy.server.c_str()),
							static_cast<DWORD>((proxy.server.length() + 1) * sizeof(wchar_t)));

						if (result != ERROR_SUCCESS) {
							Internal::SetError(err, result, L"Failed to set ProxyServer");
							return false;
						}
					}
					else {
						// Delete ProxyServer if proxy is disabled
						::RegDeleteValueW(hKey, L"ProxyServer");
					}

					// Set ProxyOverride (bypass list)
					if (!proxy.bypass.empty()) {
						result = ::RegSetValueExW(hKey, L"ProxyOverride", 0, REG_SZ,
							reinterpret_cast<const BYTE*>(proxy.bypass.c_str()),
							static_cast<DWORD>((proxy.bypass.length() + 1) * sizeof(wchar_t)));

						if (result != ERROR_SUCCESS) {
							Internal::SetError(err, result, L"Failed to set ProxyOverride");
							return false;
						}
					}
					else {
						::RegDeleteValueW(hKey, L"ProxyOverride");
					}

					// Set AutoConfigURL
					if (!proxy.autoConfigUrl.empty()) {
						result = ::RegSetValueExW(hKey, L"AutoConfigURL", 0, REG_SZ,
							reinterpret_cast<const BYTE*>(proxy.autoConfigUrl.c_str()),
							static_cast<DWORD>((proxy.autoConfigUrl.length() + 1) * sizeof(wchar_t)));

						if (result != ERROR_SUCCESS) {
							Internal::SetError(err, result, L"Failed to set AutoConfigURL");
							return false;
						}
					}
					else {
						::RegDeleteValueW(hKey, L"AutoConfigURL");
					}

					// Notify system about proxy changes
					::InternetSetOptionW(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0);
					::InternetSetOptionW(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0);

					return true;

				}
				catch (...) {
					SS_LOG_ERROR(L"NetworkUtils", L"Exception in SetSystemProxySettings");
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in SetSystemProxySettings");
					return false;
				}
			}

			bool DetectProxyForUrl(std::wstring_view url, ProxyInfo& proxy, Error* err) noexcept {
				try {
					SS_LOG_DEBUG(L"NetworkUtils", L"DetectProxyForUrl starting");
					proxy = ProxyInfo{};

					// Validate URL before passing to WinHTTP PAC engine
					if (url.empty() || url.size() > 8192) {
						SS_LOG_ERROR(L"NetworkUtils", L"DetectProxyForUrl invalid URL length=%zu", url.size());
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid URL for proxy detection");
						return false;
					}

					// Open WinHTTP session
					HINTERNET hSession = ::WinHttpOpen(L"AntivirusProxyDetection/1.0",
						WINHTTP_ACCESS_TYPE_NO_PROXY,
						WINHTTP_NO_PROXY_NAME,
						WINHTTP_NO_PROXY_BYPASS,
						0);

					if (!hSession) {
						Internal::SetError(err, ::GetLastError(), L"WinHttpOpen failed");
						return false;
					}

					struct HandleDeleter {
						void operator()(HINTERNET h) const {
							if (h) ::WinHttpCloseHandle(h);
						}
					};
					std::unique_ptr<std::remove_pointer_t<HINTERNET>, HandleDeleter> sessionGuard(hSession);

					// Get autoproxy options
					WINHTTP_AUTOPROXY_OPTIONS autoProxyOptions = {};
					autoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
					autoProxyOptions.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
					autoProxyOptions.fAutoLogonIfChallenged = TRUE;

					// Check for PAC file - RAII guard for IE proxy config
					WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ieProxyConfig{};
					struct IeProxyConfigCleanup {
						WINHTTP_CURRENT_USER_IE_PROXY_CONFIG* config;
						~IeProxyConfigCleanup() {
							if (config) {
								if (config->lpszProxy) ::GlobalFree(config->lpszProxy);
								if (config->lpszProxyBypass) ::GlobalFree(config->lpszProxyBypass);
								if (config->lpszAutoConfigUrl) ::GlobalFree(config->lpszAutoConfigUrl);
							}
						}
					};
					IeProxyConfigCleanup ieConfigGuard{ &ieProxyConfig };

					if (::WinHttpGetIEProxyConfigForCurrentUser(&ieProxyConfig)) {
						if (ieProxyConfig.lpszAutoConfigUrl) {
							autoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
							autoProxyOptions.lpszAutoConfigUrl = ieProxyConfig.lpszAutoConfigUrl;
						}
					}

					WINHTTP_PROXY_INFO proxyInfo = {};

					std::wstring urlStr(url);
					BOOL result = ::WinHttpGetProxyForUrl(hSession, urlStr.c_str(), &autoProxyOptions, &proxyInfo);

					// RAII guard for proxyInfo strings (only set if WinHttpGetProxyForUrl succeeds)
					struct ProxyInfoCleanup {
						WINHTTP_PROXY_INFO* info;
						~ProxyInfoCleanup() {
							if (info) {
								if (info->lpszProxy) ::GlobalFree(info->lpszProxy);
								if (info->lpszProxyBypass) ::GlobalFree(info->lpszProxyBypass);
							}
						}
					};
					ProxyInfoCleanup proxyInfoGuard{ result ? &proxyInfo : nullptr };

					if (!result) {
						// Fall back to system proxy settings
						return GetSystemProxySettings(proxy, err);
					}

					// Process proxy info - strings are managed by proxyInfoGuard
					if (proxyInfo.lpszProxy) {
						proxy.enabled = true;
						proxy.server = proxyInfo.lpszProxy;
					}

					if (proxyInfo.lpszProxyBypass) {
						proxy.bypass = proxyInfo.lpszProxyBypass;
					}

					return true;

				}
				catch (...) {
					SS_LOG_ERROR(L"NetworkUtils", L"Exception in DetectProxyForUrl");
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in DetectProxyForUrl");
					return false;
				}
			}

			//Proxy Bypass check
			bool ShouldBypassProxy(std::wstring_view url, const ProxyInfo& proxy, Error* err) noexcept {
				try {
					if (proxy.bypass.empty()) {
						return false;
					}

					// Extract hostname from URL for matching (scheme://[user:pass@]hostname:port/path)
					std::wstring urlStr(url);
					std::wstring hostname;
					{
						size_t schemeEnd = urlStr.find(L"://");
						size_t hostStart = (schemeEnd != std::wstring::npos) ? schemeEnd + 3 : 0;

						// Skip userinfo (user:pass@) if present
						size_t atPos = urlStr.find(L'@', hostStart);
						if (atPos != std::wstring::npos) {
							size_t nextSlash = urlStr.find(L'/', hostStart);
							if (nextSlash == std::wstring::npos || atPos < nextSlash) {
								hostStart = atPos + 1;
							}
						}

						// Handle IPv6 literal addresses [2001:db8::1]
						size_t hostEnd;
						if (hostStart < urlStr.size() && urlStr[hostStart] == L'[') {
							hostEnd = urlStr.find(L']', hostStart);
							if (hostEnd != std::wstring::npos) hostEnd++;
						}
						else {
							hostEnd = urlStr.find_first_of(L":/?", hostStart);
						}
						if (hostEnd == std::wstring::npos) hostEnd = urlStr.size();
						hostname = urlStr.substr(hostStart, hostEnd - hostStart);
					}
					std::transform(hostname.begin(), hostname.end(), hostname.begin(), ::towlower);

					// Parse bypass list (semicolon or space separated)
					std::wstring bypassList = proxy.bypass;

					size_t pos = 0;
					while (pos < bypassList.length()) {
						size_t nextPos = bypassList.find_first_of(L"; ", pos);
						if (nextPos == std::wstring::npos) {
							nextPos = bypassList.length();
						}

						std::wstring pattern = bypassList.substr(pos, nextPos - pos);
						pattern.erase(std::remove_if(pattern.begin(), pattern.end(), ::iswspace), pattern.end());
						std::transform(pattern.begin(), pattern.end(), pattern.begin(), ::towlower);

						if (pattern.empty()) {
							pos = (nextPos < bypassList.length()) ? nextPos + 1 : bypassList.length();
							continue;
						}

						// Special case: <local> — match hostnames with no dots (intranet names)
						if (pattern == L"<local>") {
							if (!hostname.empty() && hostname.find(L'.') == std::wstring::npos) {
								return true;
							}
						}
						// Wildcard matching — anchored to hostname suffix
						else if (pattern.front() == L'*') {
							// Pattern like "*.example.com" → suffix = ".example.com"
							std::wstring suffix = pattern.substr(1);
							if (suffix.empty()) {
								return true; // "*" matches everything
							}
							// Hostname ends with suffix, or hostname equals suffix without leading dot
							if (hostname.size() >= suffix.size() &&
								hostname.compare(hostname.size() - suffix.size(), suffix.size(), suffix) == 0) {
								return true;
							}
						}
						// Direct hostname match
						else if (hostname == pattern) {
							return true;
						}

						pos = (nextPos < bypassList.length()) ? nextPos + 1 : bypassList.length();
					}

					return false;

				}
				catch (...) {
					SS_LOG_ERROR(L"NetworkUtils", L"Exception in ShouldBypassProxy");
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in ShouldBypassProxy");
					return false;
				}
			}

			//Proxy authentication test — sends actual HTTP HEAD to verify proxy + auth
			bool TestProxyConnection(const ProxyInfo& proxy, Error* err) noexcept {
				try {
					SS_LOG_DEBUG(L"NetworkUtils", L"TestProxyConnection starting");

					if (!proxy.enabled || proxy.server.empty()) {
						return true; // No proxy, connection is direct
					}

					struct HandleDeleter {
						void operator()(HINTERNET h) const {
							if (h) ::WinHttpCloseHandle(h);
						}
					};

					HINTERNET hSession = ::WinHttpOpen(L"ShadowStrike-AntiVirus/1.0",
						WINHTTP_ACCESS_TYPE_NAMED_PROXY,
						proxy.server.c_str(),
						proxy.bypass.empty() ? WINHTTP_NO_PROXY_BYPASS : proxy.bypass.c_str(),
						0);

					if (!hSession) {
						SS_LOG_ERROR(L"NetworkUtils", L"TestProxyConnection WinHttpOpen failed err=%lu", ::GetLastError());
						Internal::SetError(err, ::GetLastError(), L"WinHttpOpen failed");
						return false;
					}
					std::unique_ptr<std::remove_pointer_t<HINTERNET>, HandleDeleter> sessionGuard(hSession);

					// Set timeouts to avoid blocking indefinitely
					::WinHttpSetTimeouts(hSession, 10000, 10000, 10000, 10000);

					// Connect to a well-known endpoint and send HEAD to verify proxy + auth
					HINTERNET hConnect = ::WinHttpConnect(hSession, L"www.msftconnecttest.com",
						INTERNET_DEFAULT_HTTP_PORT, 0);
					if (!hConnect) {
						SS_LOG_ERROR(L"NetworkUtils", L"TestProxyConnection WinHttpConnect failed err=%lu", ::GetLastError());
						Internal::SetError(err, ::GetLastError(), L"Proxy connection test failed");
						return false;
					}
					std::unique_ptr<std::remove_pointer_t<HINTERNET>, HandleDeleter> connectGuard(hConnect);

					// Send HEAD request to actually test proxy authentication
					HINTERNET hRequest = ::WinHttpOpenRequest(hConnect, L"HEAD", L"/connecttest.txt",
						nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
					if (!hRequest) {
						SS_LOG_ERROR(L"NetworkUtils", L"TestProxyConnection WinHttpOpenRequest failed");
						Internal::SetError(err, ::GetLastError(), L"WinHttpOpenRequest failed");
						return false;
					}
					std::unique_ptr<std::remove_pointer_t<HINTERNET>, HandleDeleter> requestGuard(hRequest);

					if (!::WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
						WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
						DWORD lastErr = ::GetLastError();
						SS_LOG_ERROR(L"NetworkUtils", L"TestProxyConnection send failed err=%lu", lastErr);
						Internal::SetError(err, lastErr, L"Proxy test request failed");
						return false;
					}

					if (!::WinHttpReceiveResponse(hRequest, nullptr)) {
						DWORD lastErr = ::GetLastError();
						SS_LOG_ERROR(L"NetworkUtils", L"TestProxyConnection receive failed err=%lu", lastErr);
						Internal::SetError(err, lastErr, L"Proxy test response failed");
						return false;
					}

					// Check for 407 Proxy Auth Required
					DWORD statusCode = 0;
					DWORD statusSize = sizeof(statusCode);
					if (!::WinHttpQueryHeaders(hRequest,
						WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
						nullptr, &statusCode, &statusSize, nullptr)) {
						SS_LOG_WARN(L"NetworkUtils", L"Could not query HTTP status code, assuming proxy reachable");
						return true;
					}

					if (statusCode == 407) {
						SS_LOG_WARN(L"NetworkUtils", L"Proxy requires authentication (407)");
						Internal::SetError(err, ERROR_ACCESS_DENIED, L"Proxy requires authentication");
						return false;
					}

					SS_LOG_INFO(L"NetworkUtils", L"TestProxyConnection succeeded status=%lu", statusCode);
					return true;

				}
				catch (...) {
					SS_LOG_ERROR(L"NetworkUtils", L"Exception in TestProxyConnection");
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in TestProxyConnection");
					return false;
				}
			}


		}//namespace NetworkUtils
	}//namespace Utils 
}//namespace ShadowStrike