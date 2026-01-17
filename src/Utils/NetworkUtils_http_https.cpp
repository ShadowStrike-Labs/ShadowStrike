// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

#include"pch.h"
#include "NetworkUtils.hpp"
#include <fstream>
#include <WinInet.h>
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
					response = HttpResponse{};

					// Validate URL length to prevent buffer overflow
					if (url.empty() || url.size() > 8192) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid URL length");
						return false;
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
						DWORD sslFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
							SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
							SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
							SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
						::WinHttpSetOption(requestGuard.handle, WINHTTP_OPTION_SECURITY_FLAGS,
							&sslFlags, sizeof(sslFlags));
					}

					// Set timeout with validation
					DWORD timeoutMs = (options.timeoutMs > 0 && options.timeoutMs <= 300000)
						? options.timeoutMs : 30000;
					::WinHttpSetTimeouts(requestGuard.handle, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

					// Add custom headers with validation
					for (const auto& header : options.headers) {
						if (!header.name.empty() && header.name.size() < 256 && header.value.size() < 8192) {
							std::wstring headerStr = header.name + L": " + header.value;
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
						Internal::SetError(err, ::GetLastError(), L"WinHttpSendRequest failed");
						return false;
					}

					// Receive response
					if (!::WinHttpReceiveResponse(requestGuard.handle, nullptr)) {
						Internal::SetError(err, ::GetLastError(), L"WinHttpReceiveResponse failed");
						return false;
					}

					// Get status code
					DWORD statusCode = 0;
					DWORD statusCodeSize = sizeof(statusCode);
					::WinHttpQueryHeaders(requestGuard.handle, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
						nullptr, &statusCode, &statusCodeSize, nullptr);
					response.statusCode = statusCode;

					// Read response body with size limit
					constexpr size_t MAX_RESPONSE_SIZE = 100 * 1024 * 1024; // 100MB max
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

					// Handles are closed by RAII guards
					return true;

				}
				catch (...) {
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
					// Validate destination path
					if (destPath.empty()) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Empty destination path");
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
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Filesystem error in HttpDownloadFile");
					return false;
				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in HttpDownloadFile");
					return false;
				}
			}

			bool HttpUploadFile(std::wstring_view url, const std::filesystem::path& filePath, std::vector<uint8_t>& response, const HttpRequestOptions& options, ProgressCallback callback, Error* err) noexcept {
				try {
					// Validate file path
					if (filePath.empty()) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Empty file path");
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
						// IPv4 TCP Connections
						ULONG size = 0;
#pragma warning(suppress: 6387)
						::GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

						std::vector<uint8_t> buffer(size);
						if (::GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
							auto* pTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());

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
						}

						// IPv6 TCP Connections
						size = 0;
#pragma warning(suppress: 6387)
						::GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
						buffer.resize(size);

						if (::GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
							auto* pTable6 = reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(buffer.data());

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
						}
					}
					else if (protocol == ProtocolType::UDP) {
						// IPv4 UDP Connections
						ULONG size = 0;
#pragma warning(suppress: 6387)
						::GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);

						std::vector<uint8_t> buffer(size);
						if (::GetExtendedUdpTable(buffer.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
							auto* pTable = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(buffer.data());

							for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
								ConnectionInfo conn;
								conn.protocol = ProtocolType::UDP;
								conn.localAddress = IpAddress(IPv4Address(Internal::NetworkToHost32(pTable->table[i].dwLocalAddr)));
								conn.localPort = Internal::NetworkToHost16(static_cast<uint16_t>(pTable->table[i].dwLocalPort));
								conn.processId = pTable->table[i].dwOwningPid;

								connections.push_back(std::move(conn));
							}
						}

						// IPv6 UDP Connections
						size = 0;
#pragma warning(suppress: 6387)
						::GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
						buffer.resize(size);

						if (::GetExtendedUdpTable(buffer.data(), &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
							auto* pTable6 = reinterpret_cast<PMIB_UDP6TABLE_OWNER_PID>(buffer.data());

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
						}
					}

					return true;
				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in GetActiveConnections");
					return false;
				}
			}
			bool GetConnectionsByProcess(uint32_t processId, std::vector<ConnectionInfo>& connections, Error* err) noexcept {
				std::vector<ConnectionInfo> allConnections;
				if (!GetActiveConnections(allConnections, ProtocolType::TCP, err)) {
					return false;
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

				ports.clear();
				for (const auto& conn : connections) {
					if (std::find(ports.begin(), ports.end(), conn.localPort) == ports.end()) {
						ports.push_back(conn.localPort);
					}
				}

				std::sort(ports.begin(), ports.end());
				return true;
			}
		}
	}
}