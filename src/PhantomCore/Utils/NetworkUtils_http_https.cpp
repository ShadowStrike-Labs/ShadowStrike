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
#include "NetworkUtils.hpp"
#include <fstream>
#include <WinInet.h>
#include <unordered_set>
#include <dhcpcsdk.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "WinInet.lib")
#pragma comment(lib, "dhcpcsvc.lib")

namespace ShadowStrike {
	namespace Utils {
		namespace NetworkUtils {

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
			// HTTP/HTTPS Operations
			// ============================================================================

			bool HttpRequest(std::wstring_view url, HttpResponse& response, const HttpRequestOptions& options, Error* err) noexcept {
				try {
					SS_LOG_DEBUG(L"NetworkUtils", L"HttpRequest starting method=%d timeout=%u",
						static_cast<int>(options.method), options.timeoutMs);
					response = HttpResponse{};

					// Validate URL length to prevent buffer overflow
					if (url.empty() || url.size() > 8192) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid URL length");
						return false;
					}

					// Reject embedded NUL/CR/LF/control characters in the URL.  WinHttpCrackUrl
					// is generally tolerant, but a payload containing CRLF can be smuggled
					// past length validation and used for request-smuggling against poorly
					// behaved upstreams, while embedded NUL silently truncates the host when
					// the URL is later copied through C string interfaces.
					for (wchar_t ch : url) {
						if (ch == L'\0' || ch == L'\r' || ch == L'\n' || (ch > 0 && ch < 0x20)) {
							Internal::SetError(err, ERROR_INVALID_PARAMETER, L"URL contains NUL or control characters");
							return false;
						}
					}

					WinHttpSession session;
					if (!session.Open(options.userAgent, err)) {
						return false;
					}

					// RAII wrapper for WinHTTP handles
					struct WinHttpHandleGuard {
						HINTERNET handle = nullptr;
						~WinHttpHandleGuard() {
							if (handle) {
								::WinHttpCloseHandle(handle);
							}
						}
					};

					URL_COMPONENTS urlComp{};
					urlComp.dwStructSize = sizeof(urlComp);

					wchar_t hostName[256] = {};
					wchar_t urlPath[2048] = {};

					urlComp.lpszHostName = hostName;
					urlComp.dwHostNameLength = _countof(hostName);
					urlComp.lpszUrlPath = urlPath;
					urlComp.dwUrlPathLength = _countof(urlPath);

					std::wstring urlCopy(url);
					if (!::WinHttpCrackUrl(urlCopy.c_str(), 0, 0, &urlComp)) {
						SS_LOG_ERROR(L"NetworkUtils", L"WinHttpCrackUrl failed err=%lu", ::GetLastError());
						Internal::SetError(err, ::GetLastError(), L"WinHttpCrackUrl failed");
						return false;
					}

					// Validate hostname was extracted
					if (hostName[0] == L'\0') {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Empty hostname in URL");
						return false;
					}

					WinHttpHandleGuard connectGuard;
					connectGuard.handle = ::WinHttpConnect(session.Handle(), hostName, urlComp.nPort, 0);
					if (!connectGuard.handle) {
						Internal::SetError(err, ::GetLastError(), L"WinHttpConnect failed");
						return false;
					}

					const wchar_t* method = L"GET";
					switch (options.method) {
					case HttpMethod::POST: method = L"POST"; break;
					case HttpMethod::PUT: method = L"PUT"; break;
#pragma push_macro("DELETE")
#undef DELETE
					case HttpMethod::DELETE: method = L"DELETE"; break;
#pragma pop_macro("DELETE")
					case HttpMethod::HEAD: method = L"HEAD"; break;
					case HttpMethod::PATCH: method = L"PATCH"; break;
					case HttpMethod::OPTIONS: method = L"OPTIONS"; break;
					case HttpMethod::TRACE: method = L"TRACE"; break;
					default: break;
					}

					DWORD secureFlags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;

					WinHttpHandleGuard requestGuard;
					requestGuard.handle = ::WinHttpOpenRequest(connectGuard.handle, method, urlPath, nullptr,
						WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, secureFlags);

					if (!requestGuard.handle) {
						Internal::SetError(err, ::GetLastError(), L"WinHttpOpenRequest failed");
						return false;
					}

					// Configure SSL/TLS options if requested to skip verification
					if (!options.verifySSL && (urlComp.nScheme == INTERNET_SCHEME_HTTPS)) {
						SS_LOG_WARN(L"NetworkUtils", L"SSL verification DISABLED for HTTPS request to %ls", hostName);
						DWORD sslFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
							SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
							SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
							SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
						::WinHttpSetOption(requestGuard.handle, WINHTTP_OPTION_SECURITY_FLAGS,
							&sslFlags, sizeof(sslFlags));
					}

					// Configure redirect policy
					if (!options.allowRedirects) {
						DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
						::WinHttpSetOption(requestGuard.handle, WINHTTP_OPTION_REDIRECT_POLICY,
							&redirectPolicy, sizeof(redirectPolicy));
					}

					// Set timeout with validation
					DWORD timeoutMs = (options.timeoutMs > 0 && options.timeoutMs <= 300000)
						? options.timeoutMs : 30000;
					::WinHttpSetTimeouts(requestGuard.handle, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

					// Add custom headers with validation
					// SECURITY: Sanitize headers to prevent CRLF injection (HTTP Header Injection)
					// CRLF sequences (\r\n) are interpreted as header separators by WinHttpAddRequestHeaders,
					// allowing attackers to inject arbitrary headers if they control header values.
					auto sanitizeHeaderValue = [](const std::wstring& value) -> std::wstring {
						std::wstring result;
						result.reserve(value.size());
						for (wchar_t ch : value) {
							// Strip CR (0x0D), LF (0x0A) and NUL to prevent header injection
							// and silent truncation by length-counted WinHTTP APIs.
							if (ch != L'\r' && ch != L'\n' && ch != L'\0') {
								result.push_back(ch);
							}
						}
						return result;
					};
					
					auto sanitizeHeaderName = [](const std::wstring& name) -> std::wstring {
						std::wstring result;
						result.reserve(name.size());
						for (wchar_t ch : name) {
							// Header names: strip CR/LF, NUL, the colon separator, and any
							// surrounding whitespace would terminate the field-name token.
							if (ch != L'\r' && ch != L'\n' && ch != L'\0' &&
								ch != L':' && ch != L' ' && ch != L'\t') {
								result.push_back(ch);
							}
						}
						return result;
					};
					
					for (const auto& header : options.headers) {
						if (!header.name.empty() && header.name.size() < 256 && header.value.size() < 8192) {
							std::wstring safeName = sanitizeHeaderName(header.name);
							std::wstring safeValue = sanitizeHeaderValue(header.value);
							
							// Skip if sanitization resulted in empty name
							if (safeName.empty()) {
								continue;
							}
							
							std::wstring headerStr = safeName + L": " + safeValue;
							::WinHttpAddRequestHeaders(requestGuard.handle, headerStr.c_str(),
								static_cast<DWORD>(headerStr.length()), WINHTTP_ADDREQ_FLAG_ADD);
						}
					}

					// Validate body size
					constexpr size_t MAX_BODY_SIZE = 100 * 1024 * 1024; // 100MB max
					if (options.body.size() > MAX_BODY_SIZE) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Request body too large");
						return false;
					}

					// Send request
					BOOL result = ::WinHttpSendRequest(requestGuard.handle,
						WINHTTP_NO_ADDITIONAL_HEADERS, 0,
						options.body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<void*>(static_cast<const void*>(options.body.data())),
						static_cast<DWORD>(options.body.size()),
						static_cast<DWORD>(options.body.size()), 0);

					if (!result) {
						SS_LOG_ERROR(L"NetworkUtils", L"WinHttpSendRequest failed err=%lu", ::GetLastError());
						Internal::SetError(err, ::GetLastError(), L"WinHttpSendRequest failed");
						return false;
					}

					// Receive response
					if (!::WinHttpReceiveResponse(requestGuard.handle, nullptr)) {
						SS_LOG_ERROR(L"NetworkUtils", L"WinHttpReceiveResponse failed err=%lu", ::GetLastError());
						Internal::SetError(err, ::GetLastError(), L"WinHttpReceiveResponse failed");
						return false;
					}

					// Get status code
					DWORD statusCode = 0;
					DWORD statusCodeSize = sizeof(statusCode);
					::WinHttpQueryHeaders(requestGuard.handle, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
						nullptr, &statusCode, &statusCodeSize, nullptr);
					response.statusCode = statusCode;

					// Parse status text
					wchar_t statusTextBuf[256] = {};
					DWORD statusTextSize = sizeof(statusTextBuf);
					if (::WinHttpQueryHeaders(requestGuard.handle, WINHTTP_QUERY_STATUS_TEXT,
						nullptr, statusTextBuf, &statusTextSize, nullptr)) {
						response.statusText = statusTextBuf;
					}

					// Parse Content-Type
					wchar_t ctBuf[512] = {};
					DWORD ctSize = sizeof(ctBuf);
					if (::WinHttpQueryHeaders(requestGuard.handle, WINHTTP_QUERY_CONTENT_TYPE,
						nullptr, ctBuf, &ctSize, nullptr)) {
						response.contentType = ctBuf;
					}

					// Parse Location header for redirects
					if (statusCode >= 300 && statusCode < 400) {
						wchar_t locBuf[2048] = {};
						DWORD locSize = sizeof(locBuf);
						if (::WinHttpQueryHeaders(requestGuard.handle, WINHTTP_QUERY_LOCATION,
							nullptr, locBuf, &locSize, nullptr)) {
							response.redirectUrl = locBuf;
						}
					}

					// Parse all response headers
					DWORD rawSize = 0;
					::WinHttpQueryHeaders(requestGuard.handle, WINHTTP_QUERY_RAW_HEADERS_CRLF,
						WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &rawSize, WINHTTP_NO_HEADER_INDEX);
					if (rawSize > 0 && rawSize < 256 * 1024) {
						std::wstring rawHeaders(rawSize / sizeof(wchar_t), L'\0');
						if (::WinHttpQueryHeaders(requestGuard.handle, WINHTTP_QUERY_RAW_HEADERS_CRLF,
							WINHTTP_HEADER_NAME_BY_INDEX, rawHeaders.data(), &rawSize, WINHTTP_NO_HEADER_INDEX)) {
							size_t pos = 0;
							while (pos < rawHeaders.size()) {
								auto lineEnd = rawHeaders.find(L"\r\n", pos);
								if (lineEnd == std::wstring::npos) break;
								auto line = rawHeaders.substr(pos, lineEnd - pos);
								auto colon = line.find(L':');
								if (colon != std::wstring::npos) {
									HttpHeader hdr;
									hdr.name = std::wstring(Internal::TrimWhitespace(line.substr(0, colon)));
									hdr.value = std::wstring(Internal::TrimWhitespace(line.substr(colon + 1)));
									response.headers.push_back(std::move(hdr));
								}
								pos = lineEnd + 2;
							}
						}
					}

					// Read response body with size limit
					constexpr size_t MAX_RESPONSE_SIZE = 100 * 1024 * 1024; // 100MB max

					// HT7: Pre-allocate using Content-Length if available
					DWORD clValue = 0;
					DWORD clSize = sizeof(clValue);
					if (::WinHttpQueryHeaders(requestGuard.handle,
						WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
						nullptr, &clValue, &clSize, nullptr)) {
						if (clValue > 0 && clValue <= MAX_RESPONSE_SIZE) {
							response.body.reserve(static_cast<size_t>(clValue));
						} else if (clValue > MAX_RESPONSE_SIZE) {
							SS_LOG_WARN(L"NetworkUtils", L"Content-Length %lu exceeds limit", clValue);
							Internal::SetError(err, ERROR_BUFFER_OVERFLOW, L"Content-Length exceeds response size limit");
							return false;
						}
					}

					std::vector<uint8_t> buffer(8192);
					DWORD bytesRead = 0;

					while (::WinHttpReadData(requestGuard.handle, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead) && bytesRead > 0) {
						// Check response size limit
						if (response.body.size() + bytesRead > MAX_RESPONSE_SIZE) {
							Internal::SetError(err, ERROR_BUFFER_OVERFLOW, L"Response body too large");
							return false;
						}
						response.body.insert(response.body.end(), buffer.begin(), buffer.begin() + bytesRead);
					}

					response.contentLength = response.body.size();

					SS_LOG_INFO(L"NetworkUtils", L"HttpRequest completed status=%u bodySize=%zu",
						response.statusCode, response.body.size());
					// Handles are closed by RAII guards
					return true;

				}
				catch (...) {
					SS_LOG_ERROR(L"NetworkUtils", L"Exception in HttpRequest");
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in HttpRequest");
					return false;
				}
			}

			bool HttpGet(std::wstring_view url, std::vector<uint8_t>& data, const HttpRequestOptions& options, Error* err) noexcept {
				HttpResponse response;
				HttpRequestOptions getOptions = options;
				getOptions.method = HttpMethod::GET;

				if (!HttpRequest(url, response, getOptions, err)) {
					return false;
				}

				data = std::move(response.body);
				return response.statusCode >= 200 && response.statusCode < 300;
			}

			bool HttpPost(std::wstring_view url, const std::vector<uint8_t>& postData, std::vector<uint8_t>& response, const HttpRequestOptions& options, Error* err) noexcept {
				HttpResponse httpResponse;
				HttpRequestOptions postOptions = options;
				postOptions.method = HttpMethod::POST;
				postOptions.body = postData;

				if (!HttpRequest(url, httpResponse, postOptions, err)) {
					return false;
				}

				response = std::move(httpResponse.body);
				return httpResponse.statusCode >= 200 && httpResponse.statusCode < 300;
			}

			bool HttpDownloadFile(std::wstring_view url, const std::filesystem::path& destPath, const HttpRequestOptions& options, ProgressCallback callback, Error* err) noexcept {
				try {
					SS_LOG_DEBUG(L"NetworkUtils", L"HttpDownloadFile starting");

					// Validate destination path
					if (destPath.empty()) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Empty destination path");
						return false;
					}

					// Reject path traversal sequences
					std::wstring destStr = destPath.wstring();
					if (destStr.find(L"..") != std::wstring::npos) {
						SS_LOG_ERROR(L"NetworkUtils", L"Path traversal detected in download destination");
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Path traversal in destination path");
						return false;
					}

					// Reject pre-existing symlinks at the destination.  If an attacker can
					// pre-create a symlink in a writable directory pointing to a sensitive
					// file, an unprivileged downloader would otherwise overwrite the link
					// target.  We require the destination to either not exist or to be a
					// regular file.
					std::error_code destSymEc;
					if (std::filesystem::is_symlink(destPath, destSymEc)) {
						SS_LOG_ERROR(L"NetworkUtils", L"Symlink detected at download destination");
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Symlinks not allowed for download destination");
						return false;
					}
					std::error_code destExistsEc;
					if (std::filesystem::exists(destPath, destExistsEc) &&
						!std::filesystem::is_regular_file(destPath, destExistsEc)) {
						SS_LOG_ERROR(L"NetworkUtils", L"Download destination exists and is not a regular file");
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Download destination must be a regular file");
						return false;
					}

					HttpResponse response;
					if (!HttpRequest(url, response, options, err)) {
						return false;
					}

					// Check HTTP status code
					if (response.statusCode < 200 || response.statusCode >= 300) {
						Internal::SetError(err, ERROR_INTERNET_OPERATION_CANCELLED,
							L"HTTP request failed with status " + std::to_wstring(response.statusCode));
						return false;
					}

					// Create parent directory if it doesn't exist
					std::error_code ec;
					auto parentPath = destPath.parent_path();
					if (!parentPath.empty() && !std::filesystem::exists(parentPath, ec)) {
						std::filesystem::create_directories(parentPath, ec);
						if (ec) {
							Internal::SetError(err, ec.value(), L"Failed to create directory");
							return false;
						}
					}

					std::ofstream outFile(destPath, std::ios::binary | std::ios::trunc);
					if (!outFile) {
						Internal::SetError(err, ERROR_CANNOT_MAKE, L"Failed to create output file");
						return false;
					}

					if (!response.body.empty()) {
						outFile.write(reinterpret_cast<const char*>(response.body.data()),
							static_cast<std::streamsize>(response.body.size()));

						if (!outFile.good()) {
							Internal::SetError(err, ERROR_WRITE_FAULT, L"Failed to write output file");
							outFile.close();
							// Attempt to delete partial file
							std::filesystem::remove(destPath, ec);
							return false;
						}
					}

					outFile.close();
					return true;

				}
				catch (const std::filesystem::filesystem_error& e) {
					SS_LOG_ERROR(L"NetworkUtils", L"Filesystem error in HttpDownloadFile");
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Filesystem error in HttpDownloadFile");
					return false;
				}
				catch (...) {
					SS_LOG_ERROR(L"NetworkUtils", L"Exception in HttpDownloadFile");
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in HttpDownloadFile");
					return false;
				}
			}

			bool HttpUploadFile(std::wstring_view url, const std::filesystem::path& filePath, std::vector<uint8_t>& response, const HttpRequestOptions& options, ProgressCallback callback, Error* err) noexcept {
				try {
					SS_LOG_DEBUG(L"NetworkUtils", L"HttpUploadFile starting");

					// Validate file path
					if (filePath.empty()) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Empty file path");
						return false;
					}

					// Reject path traversal sequences
					std::wstring filePathStr = filePath.wstring();
					if (filePathStr.find(L"..") != std::wstring::npos) {
						SS_LOG_ERROR(L"NetworkUtils", L"Path traversal detected in upload source");
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Path traversal in upload path");
						return false;
					}

					// Reject symlinks to prevent exfiltration via symlink attacks
					std::error_code symEc;
					if (std::filesystem::is_symlink(filePath, symEc)) {
						SS_LOG_ERROR(L"NetworkUtils", L"Symlink detected in upload path");
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Symlinks not allowed for upload");
						return false;
					}

					// Check file exists
					std::error_code ec;
					if (!std::filesystem::exists(filePath, ec) || ec) {
						Internal::SetError(err, ERROR_FILE_NOT_FOUND, L"Input file does not exist");
						return false;
					}

					// Get file size safely
					auto fileSize = std::filesystem::file_size(filePath, ec);
					if (ec) {
						Internal::SetError(err, ec.value(), L"Failed to get file size");
						return false;
					}

					// Validate file size limits
					constexpr uintmax_t MAX_UPLOAD_SIZE = 1024ULL * 1024ULL * 1024ULL; // 1GB
					if (fileSize > MAX_UPLOAD_SIZE) {
						Internal::SetError(err, ERROR_FILE_TOO_LARGE, L"File too large to upload");
						return false;
					}

					std::ifstream inFile(filePath, std::ios::binary);
					if (!inFile) {
						Internal::SetError(err, ERROR_FILE_NOT_FOUND, L"Failed to open input file");
						return false;
					}

					std::vector<uint8_t> fileData;
					fileData.resize(static_cast<size_t>(fileSize));

					if (!inFile.read(reinterpret_cast<char*>(fileData.data()), static_cast<std::streamsize>(fileSize))) {
						Internal::SetError(err, ERROR_READ_FAULT, L"Failed to read input file");
						return false;
					}

					return HttpPost(url, fileData, response, options, err);

				}
				catch (...) {
					SS_LOG_ERROR(L"NetworkUtils", L"Exception in HttpUploadFile");
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in HttpUploadFile");
					return false;
				}
			}

			// ============================================================================
			// Connection and Port Information
			// ============================================================================
			bool GetActiveConnections(std::vector<ConnectionInfo>& connections, ProtocolType protocol, Error* err) noexcept {
				try {
					connections.clear();

					if (protocol == ProtocolType::TCP) {
						// IPv4 TCP Connections (with TOCTOU retry)
						for (int retry = 0; retry < 3; ++retry) {
							ULONG size4 = 0;
#pragma warning(suppress: 6387)
							::GetExtendedTcpTable(nullptr, &size4, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
							if (size4 == 0) break;
							std::vector<uint8_t> buf4(size4);
							DWORD rc4 = ::GetExtendedTcpTable(buf4.data(), &size4, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
							if (rc4 == ERROR_INSUFFICIENT_BUFFER) continue;
							if (rc4 != NO_ERROR) break;
							auto* pTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buf4.data());
							for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
								ConnectionInfo conn;
								conn.protocol = ProtocolType::TCP;
								conn.localAddress = IpAddress(IPv4Address(Internal::NetworkToHost32(pTable->table[i].dwLocalAddr)));
								conn.localPort = Internal::NetworkToHost16(static_cast<uint16_t>(pTable->table[i].dwLocalPort));
								conn.remoteAddress = IpAddress(IPv4Address(Internal::NetworkToHost32(pTable->table[i].dwRemoteAddr)));
								conn.remotePort = Internal::NetworkToHost16(static_cast<uint16_t>(pTable->table[i].dwRemotePort));
								conn.state = static_cast<TcpState>(pTable->table[i].dwState);
								conn.processId = pTable->table[i].dwOwningPid;
								connections.push_back(std::move(conn));
							}
							break;
						}

						// IPv6 TCP Connections (separate buffer to prevent stale data)
						for (int retry = 0; retry < 3; ++retry) {
							ULONG size6 = 0;
#pragma warning(suppress: 6387)
							::GetExtendedTcpTable(nullptr, &size6, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
							if (size6 == 0) break;
							std::vector<uint8_t> buf6(size6);
							DWORD rc6 = ::GetExtendedTcpTable(buf6.data(), &size6, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
							if (rc6 == ERROR_INSUFFICIENT_BUFFER) continue;
							if (rc6 != NO_ERROR) break;
							auto* pTable6 = reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(buf6.data());
							for (DWORD i = 0; i < pTable6->dwNumEntries; ++i) {
								ConnectionInfo conn;
								conn.protocol = ProtocolType::TCP;
								std::array<uint8_t, 16> localBytes, remoteBytes;
								std::memcpy(localBytes.data(), pTable6->table[i].ucLocalAddr, 16);
								std::memcpy(remoteBytes.data(), pTable6->table[i].ucRemoteAddr, 16);
								conn.localAddress = IpAddress(IPv6Address(localBytes));
								conn.localPort = Internal::NetworkToHost16(static_cast<uint16_t>(pTable6->table[i].dwLocalPort));
								conn.remoteAddress = IpAddress(IPv6Address(remoteBytes));
								conn.remotePort = Internal::NetworkToHost16(static_cast<uint16_t>(pTable6->table[i].dwRemotePort));
								conn.state = static_cast<TcpState>(pTable6->table[i].dwState);
								conn.processId = pTable6->table[i].dwOwningPid;
								connections.push_back(std::move(conn));
							}
							break;
						}
					}
					else if (protocol == ProtocolType::UDP) {
						// IPv4 UDP Connections (with TOCTOU retry)
						for (int retry = 0; retry < 3; ++retry) {
							ULONG usize4 = 0;
#pragma warning(suppress: 6387)
							::GetExtendedUdpTable(nullptr, &usize4, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
							if (usize4 == 0) break;
							std::vector<uint8_t> ubuf4(usize4);
							DWORD urc4 = ::GetExtendedUdpTable(ubuf4.data(), &usize4, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
							if (urc4 == ERROR_INSUFFICIENT_BUFFER) continue;
							if (urc4 != NO_ERROR) break;
							auto* pTable = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(ubuf4.data());
							for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
								ConnectionInfo conn;
								conn.protocol = ProtocolType::UDP;
								conn.localAddress = IpAddress(IPv4Address(Internal::NetworkToHost32(pTable->table[i].dwLocalAddr)));
								conn.localPort = Internal::NetworkToHost16(static_cast<uint16_t>(pTable->table[i].dwLocalPort));
								conn.processId = pTable->table[i].dwOwningPid;
								connections.push_back(std::move(conn));
							}
							break;
						}

						// IPv6 UDP Connections (separate buffer)
						for (int retry = 0; retry < 3; ++retry) {
							ULONG usize6 = 0;
#pragma warning(suppress: 6387)
							::GetExtendedUdpTable(nullptr, &usize6, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
							if (usize6 == 0) break;
							std::vector<uint8_t> ubuf6(usize6);
							DWORD urc6 = ::GetExtendedUdpTable(ubuf6.data(), &usize6, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
							if (urc6 == ERROR_INSUFFICIENT_BUFFER) continue;
							if (urc6 != NO_ERROR) break;
							auto* pTable6 = reinterpret_cast<PMIB_UDP6TABLE_OWNER_PID>(ubuf6.data());
							for (DWORD i = 0; i < pTable6->dwNumEntries; ++i) {
								ConnectionInfo conn;
								conn.protocol = ProtocolType::UDP;
								std::array<uint8_t, 16> localBytes;
								std::memcpy(localBytes.data(), pTable6->table[i].ucLocalAddr, 16);
								conn.localAddress = IpAddress(IPv6Address(localBytes));
								conn.localPort = Internal::NetworkToHost16(static_cast<uint16_t>(pTable6->table[i].dwLocalPort));
								conn.processId = pTable6->table[i].dwOwningPid;
								connections.push_back(std::move(conn));
							}
							break;
						}
					}

					return true;
				}
				catch (...) {
					SS_LOG_ERROR(L"NetworkUtils", L"Exception in GetActiveConnections");
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in GetActiveConnections");
					return false;
				}
			}
			bool GetConnectionsByProcess(uint32_t processId, std::vector<ConnectionInfo>& connections, Error* err) noexcept {
				std::vector<ConnectionInfo> allConnections;
				if (!GetActiveConnections(allConnections, ProtocolType::TCP, err)) {
					return false;
				}

				// Also fetch UDP connections — malware may use UDP C2, DNS tunneling, QUIC
				std::vector<ConnectionInfo> udpConnections;
				if (GetActiveConnections(udpConnections, ProtocolType::UDP, nullptr)) {
					allConnections.insert(allConnections.end(),
						std::make_move_iterator(udpConnections.begin()),
						std::make_move_iterator(udpConnections.end()));
				}

				connections.clear();
				for (const auto& conn : allConnections) {
					if (conn.processId == processId) {
						connections.push_back(conn);
					}
				}

				return true;
			}

			bool IsPortInUse(uint16_t port, ProtocolType protocol) noexcept {
				std::vector<ConnectionInfo> connections;
				if (!GetActiveConnections(connections, protocol, nullptr)) {
					return false;
				}

				for (const auto& conn : connections) {
					if (conn.localPort == port) {
						return true;
					}
				}

				return false;
			}

			bool GetPortsInUse(std::vector<uint16_t>& ports, ProtocolType protocol, Error* err) noexcept {
				std::vector<ConnectionInfo> connections;
				if (!GetActiveConnections(connections, protocol, err)) {
					return false;
				}

				// Use set for O(n) dedup instead of O(n²) linear search
				std::unordered_set<uint16_t> portSet;
				portSet.reserve(connections.size());
				for (const auto& conn : connections) {
					portSet.insert(conn.localPort);
				}
				ports.assign(portSet.begin(), portSet.end());
				std::sort(ports.begin(), ports.end());
				return true;
			}
		}
	}
}