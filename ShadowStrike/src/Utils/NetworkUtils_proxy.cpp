
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
					proxy = ProxyInfo{};

					WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyConfig{};

					if (!::WinHttpGetIEProxyConfigForCurrentUser(&proxyConfig)) {
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
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in GetSystemProxySettings");
					return false;
				}
			}

			bool SetSystemProxySettings(const ProxyInfo& proxy, Error* err) noexcept {
				try {
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
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in SetSystemProxySettings");
					return false;
				}
			}

			bool DetectProxyForUrl(std::wstring_view url, ProxyInfo& proxy, Error* err) noexcept {
				try {
					proxy = ProxyInfo{};

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

					// Parse bypass list (semicolon or space separated)
					std::wstring bypassList = proxy.bypass;
					std::wstring urlLower(url);
					std::transform(urlLower.begin(), urlLower.end(), urlLower.begin(), ::towlower);

					size_t pos = 0;
					while (pos < bypassList.length()) {
						size_t nextPos = bypassList.find_first_of(L"; ", pos);
						if (nextPos == std::wstring::npos) {
							nextPos = bypassList.length();
						}

						std::wstring pattern = bypassList.substr(pos, nextPos - pos);
						std::transform(pattern.begin(), pattern.end(), pattern.begin(), ::towlower);

						// Remove whitespace
						pattern.erase(std::remove_if(pattern.begin(), pattern.end(), ::iswspace), pattern.end());

						if (pattern.empty()) {
							pos = nextPos + 1;
							continue;
						}

						// Special case: <local>
						if (pattern == L"<local>") {
							if (urlLower.find(L'.') == std::wstring::npos) {
								return true;
							}
						}
						// Wildcard matching
						else if (pattern.find(L'*') != std::wstring::npos) {
							// Simple wildcard implementation
							size_t starPos = pattern.find(L'*');
							std::wstring prefix = pattern.substr(0, starPos);
							std::wstring suffix = pattern.substr(starPos + 1);

							if (urlLower.find(prefix) != std::wstring::npos &&
								(suffix.empty() || urlLower.find(suffix) != std::wstring::npos)) {
								return true;
							}
						}
						// Direct match
						else if (urlLower.find(pattern) != std::wstring::npos) {
							return true;
						}

						pos = nextPos + 1;
					}

					return false;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in ShouldBypassProxy");
					return false;
				}
			}

			//Proxy authentication test
			bool TestProxyConnection(const ProxyInfo& proxy, Error* err) noexcept {
				try {
					if (!proxy.enabled || proxy.server.empty()) {
						return true; // No proxy, connection is direct
					}

					HINTERNET hSession = ::WinHttpOpen(L"AntivirusProxyTest/1.0",
						WINHTTP_ACCESS_TYPE_NAMED_PROXY,
						proxy.server.c_str(),
						proxy.bypass.empty() ? WINHTTP_NO_PROXY_BYPASS : proxy.bypass.c_str(),
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

					// Try to connect to a known endpoint
					HINTERNET hConnect = ::WinHttpConnect(hSession, L"www.microsoft.com", INTERNET_DEFAULT_HTTPS_PORT, 0);

					if (!hConnect) {
						Internal::SetError(err, ::GetLastError(), L"Proxy connection test failed");
						return false;
					}

					// Use RAII to ensure hConnect is always closed
					std::unique_ptr<std::remove_pointer_t<HINTERNET>, HandleDeleter> connectGuard(hConnect);

					return true;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in TestProxyConnection");
					return false;
				}
			}


		}//namespace NetworkUtils
	}//namespace Utils 
}//namespace ShadowStrike