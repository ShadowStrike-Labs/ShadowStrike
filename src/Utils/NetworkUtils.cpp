// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

#include"pch.h"
#include "NetworkUtils.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cctype>
#include <cstring>
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
			// RAII Helpers Implementation
			// ============================================================================

			bool WinHttpSession::Open(std::wstring_view userAgent, Error* err) noexcept {
				Close();
				m_session = ::WinHttpOpen(userAgent.data(), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
					WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
				
				if (!m_session) {
					Internal::SetError(err, ::GetLastError(), L"WinHttpOpen failed");
					return false;
				}
				return true;
			}

			void WinHttpSession::Close() noexcept {
				if (m_session) {
					::WinHttpCloseHandle(m_session);
					m_session = nullptr;
				}
			}

			WsaInitializer::WsaInitializer() noexcept {
				WSADATA wsaData;
				m_error = ::WSAStartup(MAKEWORD(2, 2), &wsaData);
				m_initialized = (m_error == 0);
			}

			WsaInitializer::~WsaInitializer() noexcept {
				if (m_initialized) {
					::WSACleanup();
				}
			}


			// ============================================================================
			// Ping and Network Testing
			// ============================================================================

			bool Ping(const IpAddress& address, PingResult& result, const PingOptions& options, Error* err) noexcept {
				try {
					result = PingResult{};
					result.address = address;

					// Validate IP address
					if (!address.IsValid()) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid IP address");
						return false;
					}

					// RAII wrapper for ICMP handles
					struct IcmpHandleGuard {
						HANDLE handle = INVALID_HANDLE_VALUE;
						~IcmpHandleGuard() {
							if (handle != INVALID_HANDLE_VALUE) {
								::IcmpCloseHandle(handle);
							}
						}
					};

					// Validate timeout
					DWORD timeoutMs = (options.timeoutMs > 0 && options.timeoutMs <= 60000) 
						? options.timeoutMs : 4000;

					if (address.version == IpVersion::IPv4) {
						auto* ipv4 = address.AsIPv4();
						if (!ipv4) {
							Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid IPv4 address");
							return false;
						}

						IcmpHandleGuard icmpGuard;
						icmpGuard.handle = ::IcmpCreateFile();
						if (icmpGuard.handle == INVALID_HANDLE_VALUE) {
							Internal::SetError(err, ::GetLastError(), L"IcmpCreateFile failed");
							return false;
						}

						// Prepare send data with size limit
						std::vector<uint8_t> sendData = options.data;
						if (sendData.empty()) {
							sendData.resize(32, 0xAA);
						} else if (sendData.size() > 65500) {
							sendData.resize(65500); // Max ICMP payload size
						}

						// Calculate reply buffer size with overflow check
						size_t replyBufferSize = sizeof(ICMP_ECHO_REPLY) + sendData.size() + 8;
						if (replyBufferSize > 65535) {
							replyBufferSize = 65535;
						}
						std::vector<uint8_t> replyBuffer(replyBufferSize);
						
						DWORD replyCount = ::IcmpSendEcho(icmpGuard.handle,
							Internal::HostToNetwork32(ipv4->ToUInt32()),
							sendData.data(), static_cast<WORD>(sendData.size()),
							nullptr,
							replyBuffer.data(), static_cast<DWORD>(replyBuffer.size()),
							timeoutMs);

						// IcmpSendEcho returns the NUMBER of ICMP_ECHO_REPLY structures, not size
						if (replyCount > 0) {
							auto* pReply = reinterpret_cast<PICMP_ECHO_REPLY>(replyBuffer.data());
							result.success = (pReply->Status == IP_SUCCESS);
							if (!result.success) {
								result.errorMessage = L"ICMP Status: " + std::to_wstring(pReply->Status);
							}
							result.roundTripTimeMs = pReply->RoundTripTime;
							result.ttl = pReply->Options.Ttl;
							result.dataSize = pReply->DataSize;
						} else {
							result.success = false;
							DWORD lastErr = ::GetLastError();
							result.errorMessage = L"Ping failed: " + FormatNetworkError(lastErr);
						}

						return true;
					}
					else if (address.version == IpVersion::IPv6) {
						auto* ipv6 = address.AsIPv6();
						if (!ipv6) {
							Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid IPv6 address");
							return false;
						}

						IcmpHandleGuard icmpGuard;
						icmpGuard.handle = ::Icmp6CreateFile();
						if (icmpGuard.handle == INVALID_HANDLE_VALUE) {
							Internal::SetError(err, ::GetLastError(), L"Icmp6CreateFile failed");
							return false;
						}

						sockaddr_in6 sourceAddr{};
						sourceAddr.sin6_family = AF_INET6;

						sockaddr_in6 destAddr{};
						destAddr.sin6_family = AF_INET6;
						std::memcpy(&destAddr.sin6_addr, ipv6->bytes.data(), 16);

						// Prepare send data with size limit
						std::vector<uint8_t> sendData = options.data;
						if (sendData.empty()) {
							sendData.resize(32, 0xAA);
						} else if (sendData.size() > 65500) {
							sendData.resize(65500);
						}

						// Calculate reply buffer size with overflow check
						size_t replyBufferSize = sizeof(ICMPV6_ECHO_REPLY) + sendData.size() + 8;
						if (replyBufferSize > 65535) {
							replyBufferSize = 65535;
						}
						std::vector<uint8_t> replyBuffer(replyBufferSize);
						
						DWORD replyCount = ::Icmp6SendEcho2(icmpGuard.handle, nullptr, nullptr, nullptr,
							&sourceAddr, &destAddr,
							sendData.data(), static_cast<WORD>(sendData.size()),
							nullptr,
							replyBuffer.data(), static_cast<DWORD>(replyBuffer.size()),
							timeoutMs);

						// Icmp6SendEcho2 returns the NUMBER of ICMPV6_ECHO_REPLY structures, not size
						if (replyCount > 0) {
							auto* pReply = reinterpret_cast<PICMPV6_ECHO_REPLY>(replyBuffer.data());
							result.success = (pReply->Status == IP_SUCCESS);
							if (!result.success) {
								result.errorMessage = L"ICMPv6 Status: " + std::to_wstring(pReply->Status);
							}
							result.roundTripTimeMs = pReply->RoundTripTime;
						} else {
							result.success = false;
							DWORD lastErr = ::GetLastError();
							result.errorMessage = L"Ping failed: " + FormatNetworkError(lastErr);
						}

						return true;
					}

					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid IP version");
					return false;

				} catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in Ping");
					return false;
				}
			}

			bool Ping(std::wstring_view hostname, PingResult& result, const PingOptions& options, Error* err) noexcept {
				std::vector<IpAddress> addresses;
				if (!ResolveHostname(hostname, addresses, AddressFamily::Unspecified, err)) {
					return false;
				}

				if (addresses.empty()) {
					Internal::SetError(err, ERROR_HOST_UNREACHABLE, L"No addresses resolved");
					return false;
				}

				return Ping(addresses[0], result, options, err);
			}

			bool TraceRoute(const IpAddress& address, std::vector<TraceRouteHop>& hops, uint32_t maxHops, uint32_t timeoutMs, Error* err) noexcept {
				try {
					hops.clear();

					for (uint32_t ttl = 1; ttl <= maxHops; ++ttl) {
						PingOptions pingOpts;
						pingOpts.ttl = ttl;
						pingOpts.timeoutMs = timeoutMs;

						PingResult pingResult;
						if (Ping(address, pingResult, pingOpts, nullptr)) {
							TraceRouteHop hop;
							hop.hopNumber = ttl;
							hop.address = pingResult.address;
							hop.roundTripTimeMs = pingResult.roundTripTimeMs;
							hop.timedOut = !pingResult.success;

							// Try reverse lookup
							std::wstring hostname;
							if (ReverseLookup(pingResult.address, hostname, nullptr)) {
								hop.hostname = hostname;
							}

							hops.push_back(std::move(hop));

							if (pingResult.success && pingResult.address == address) {
								break; // Reached destination
							}
						} else {
							TraceRouteHop hop;
							hop.hopNumber = ttl;
							hop.timedOut = true;
							hops.push_back(std::move(hop));
						}
					}

					return true;

				} catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in TraceRoute");
					return false;
				}
			}

			bool TraceRoute(std::wstring_view hostname, std::vector<TraceRouteHop>& hops, uint32_t maxHops, uint32_t timeoutMs, Error* err) noexcept {
				std::vector<IpAddress> addresses;
				if (!ResolveHostname(hostname, addresses, AddressFamily::Unspecified, err)) {
					return false;
				}

				if (addresses.empty()) {
					Internal::SetError(err, ERROR_HOST_UNREACHABLE, L"No addresses resolved");
					return false;
				}

				return TraceRoute(addresses[0], hops, maxHops, timeoutMs, err);
			}

			// ============================================================================
			// Port Scanning
			// ============================================================================

			bool ScanPort(const IpAddress& address, uint16_t port, PortScanResult& result, uint32_t timeoutMs, Error* err) noexcept {
				try {
					result = PortScanResult{};
					result.port = port;

					// Validate address
					if (!address.IsValid()) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid IP address");
						return false;
					}

					// Validate timeout
					if (timeoutMs == 0 || timeoutMs > 60000) {
						timeoutMs = 1000;
					}

					WsaInitializer wsa;
					if (!wsa.IsInitialized()) {
						Internal::SetWsaError(err, wsa.GetError(), L"WSA initialization failed");
						return false;
					}

					// RAII socket wrapper
					struct SocketGuard {
						SOCKET sock = INVALID_SOCKET;
						~SocketGuard() {
							if (sock != INVALID_SOCKET) {
								::closesocket(sock);
							}
						}
					} socketGuard;

					socketGuard.sock = ::socket(address.IsIPv4() ? AF_INET : AF_INET6, SOCK_STREAM, IPPROTO_TCP);
					if (socketGuard.sock == INVALID_SOCKET) {
						Internal::SetWsaError(err, ::WSAGetLastError(), L"socket creation failed");
						return false;
					}

					// Set non-blocking mode
					u_long mode = 1;
					if (::ioctlsocket(socketGuard.sock, FIONBIO, &mode) == SOCKET_ERROR) {
						Internal::SetWsaError(err, ::WSAGetLastError(), L"Failed to set non-blocking mode");
						return false;
					}

					// Set timeout options
					DWORD dwTimeout = timeoutMs;
					::setsockopt(socketGuard.sock, SOL_SOCKET, SO_RCVTIMEO, 
						reinterpret_cast<const char*>(&dwTimeout), sizeof(dwTimeout));
					::setsockopt(socketGuard.sock, SOL_SOCKET, SO_SNDTIMEO, 
						reinterpret_cast<const char*>(&dwTimeout), sizeof(dwTimeout));

					auto startTime = std::chrono::steady_clock::now();

					int connectResult = -1;
					if (address.IsIPv4()) {
						auto* ipv4 = address.AsIPv4();
						if (!ipv4) {
							Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid IPv4 address");
							return false;
						}
						sockaddr_in sa{};
						sa.sin_family = AF_INET;
						sa.sin_port = Internal::HostToNetwork16(port);
						sa.sin_addr.s_addr = Internal::HostToNetwork32(ipv4->ToUInt32());
						connectResult = ::connect(socketGuard.sock, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
					} else {
						auto* ipv6 = address.AsIPv6();
						if (!ipv6) {
							Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid IPv6 address");
							return false;
						}
						sockaddr_in6 sa6{};
						sa6.sin6_family = AF_INET6;
						sa6.sin6_port = Internal::HostToNetwork16(port);
						std::memcpy(&sa6.sin6_addr, ipv6->bytes.data(), 16);
						connectResult = ::connect(socketGuard.sock, reinterpret_cast<sockaddr*>(&sa6), sizeof(sa6));
					}

					int wsaErr = ::WSAGetLastError();
					if (connectResult == 0 || wsaErr == WSAEWOULDBLOCK || wsaErr == WSAEINPROGRESS) {
						fd_set writeSet;
						FD_ZERO(&writeSet);
						FD_SET(socketGuard.sock, &writeSet);

						struct timeval tv;
						tv.tv_sec = static_cast<long>(timeoutMs / 1000);
						tv.tv_usec = static_cast<long>((timeoutMs % 1000) * 1000);

						int selectResult = ::select(0, nullptr, &writeSet, nullptr, &tv);
						if (selectResult > 0 && FD_ISSET(socketGuard.sock, &writeSet)) {
							// Check if connection succeeded
							int optVal = 0;
							int optLen = sizeof(optVal);
							if (::getsockopt(socketGuard.sock, SOL_SOCKET, SO_ERROR, 
									reinterpret_cast<char*>(&optVal), &optLen) == 0 && optVal == 0) {
								result.isOpen = true;
							}
							
							auto endTime = std::chrono::steady_clock::now();
							result.responseTimeMs = static_cast<uint32_t>(
								std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count()
							);
						}
					}

					// Socket is closed by RAII guard
					return true;

				} catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in ScanPort");
					return false;
				}
			}

			bool ScanPorts(const IpAddress& address, const std::vector<uint16_t>& ports, std::vector<PortScanResult>& results, uint32_t timeoutMs, Error* err) noexcept {
				results.clear();
				results.reserve(ports.size());

				for (uint16_t port : ports) {
					PortScanResult result;
					if (ScanPort(address, port, result, timeoutMs, nullptr)) {
						results.push_back(result);
					}
				}

				return true;
			}

			// ============================================================================
			// Network Statistics
			// ============================================================================

		//Total statistics for all adapters
			bool GetNetworkStatistics(NetworkStatistics& stats, Error* err) noexcept {
				try {
					stats = NetworkStatistics{};
					stats.timestamp = std::chrono::system_clock::now();

					//Get all adapters
					ULONG bufferSize = 0;
					if (::GetIfTable(nullptr, &bufferSize, FALSE) != ERROR_INSUFFICIENT_BUFFER) {
						Internal::SetError(err, ::GetLastError(), L"Failed to get interface table size");
						return false;
					}

					std::vector<uint8_t> buffer(bufferSize);
					auto* pIfTable = reinterpret_cast<PMIB_IFTABLE>(buffer.data());

					if (::GetIfTable(pIfTable, &bufferSize, FALSE) != NO_ERROR) {
						Internal::SetError(err, ::GetLastError(), L"Failed to get interface table");
						return false;
					}

					//Collect the all statistics of all adapters
					for (DWORD i = 0; i < pIfTable->dwNumEntries; ++i) {
						const auto& ifRow = pIfTable->table[i];

						stats.bytesSent += ifRow.dwOutOctets;
						stats.bytesReceived += ifRow.dwInOctets;
						stats.packetsSent += ifRow.dwOutUcastPkts + ifRow.dwOutNUcastPkts;
						stats.packetsReceived += ifRow.dwInUcastPkts + ifRow.dwInNUcastPkts;
						stats.errorsSent += ifRow.dwOutErrors;
						stats.errorsReceived += ifRow.dwInErrors;
						stats.droppedPackets += ifRow.dwInDiscards + ifRow.dwOutDiscards;
					}

					return true;
				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in GetNetworkStatistics");
					return false;
				}
			}

			//Statistics for a specific adapter by name
			bool GetNetworkStatistics(const std::wstring& adapterName, NetworkStatistics& stats, Error* err) noexcept {
				try {
					stats = NetworkStatistics{};
					stats.timestamp = std::chrono::system_clock::now();

					//Get the adapters and find the one matching the name
					std::vector<NetworkAdapterInfo> adapters;
					if (!GetNetworkAdapters(adapters, err)) {
						return false;
					}

					DWORD targetIndex = 0;
					bool found = false;

					for (const auto& adapter : adapters) {
						if (adapter.friendlyName == adapterName) {
							targetIndex = adapter.interfaceIndex; // Assuming interfaceIndex is the same as dwIndex in MIB_IFROW
							found = true;
							break;
						}
					}

					if (!found) {
						Internal::SetError(err, ERROR_NOT_FOUND, L"Adapter not found");
						return false;
					}

					//Get statistics for the specific adapter
					MIB_IFROW ifRow{};
					ifRow.dwIndex = targetIndex;

					if (::GetIfEntry(&ifRow) != NO_ERROR) {
						Internal::SetError(err, ::GetLastError(), L"Failed to get interface entry");
						return false;
					}

					stats.bytesSent = ifRow.dwOutOctets;
					stats.bytesReceived = ifRow.dwInOctets;
					stats.packetsSent = ifRow.dwOutUcastPkts + ifRow.dwOutNUcastPkts;
					stats.packetsReceived = ifRow.dwInUcastPkts + ifRow.dwInNUcastPkts;
					stats.errorsSent = ifRow.dwOutErrors;
					stats.errorsReceived = ifRow.dwInErrors;
					stats.droppedPackets = ifRow.dwInDiscards + ifRow.dwOutDiscards;

					return true;
				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in GetNetworkStatistics");
					return false;
				}
			}

			bool CalculateBandwidth(const NetworkStatistics& previous, const NetworkStatistics& current, BandwidthInfo& bandwidth) noexcept {
				auto duration = std::chrono::duration_cast<std::chrono::seconds>(current.timestamp - previous.timestamp).count();
				if (duration <= 0) {
					return false;
				}

				bandwidth.currentDownloadBps = (current.bytesReceived - previous.bytesReceived) / duration;
				bandwidth.currentUploadBps = (current.bytesSent - previous.bytesSent) / duration;

				return true;
			}


		

			// ============================================================================
			// Network Connectivity Tests
			// ============================================================================

			bool IsInternetAvailable(uint32_t timeoutMs) noexcept {
				DWORD flags = 0;
				if (::InternetGetConnectedState(&flags, 0)) {
					return true;
				}

				// Try pinging a known server
				PingResult result;
				IPv4Address googleDns(std::array<uint8_t, 4>{8, 8, 8, 8});
				return Ping(IpAddress(googleDns), result, PingOptions{timeoutMs}, nullptr) && result.success;
			}

			bool IsHostReachable(std::wstring_view hostname, uint32_t timeoutMs) noexcept {
				PingResult result;
				return Ping(hostname, result, PingOptions{timeoutMs}, nullptr) && result.success;
			}

			bool IsHostReachable(const IpAddress& address, uint32_t timeoutMs) noexcept {
				PingResult result;
				return Ping(address, result, PingOptions{timeoutMs}, nullptr) && result.success;
			}

			bool TestDnsResolution(uint32_t timeoutMs) noexcept {
				std::vector<IpAddress> addresses;
				return ResolveHostname(L"www.google.com", addresses, AddressFamily::Unspecified, nullptr) && !addresses.empty();
			}


			// ============================================================================
            // Network Protocol Detection
            // Implementation based on RFC specifications:
            // - RFC 959 (FTP), RFC 4253 (SSH), RFC 5321 (SMTP), RFC 3501 (IMAP)
            // - RFC 1939 (POP3), RFC 854 (Telnet), ITU-T T.123 (RDP)
            // Protocol magic numbers and signatures are standardized, not copyrightable.
            // ============================================================================
			bool DetectProtocol(const std::vector<uint8_t>& data, std::wstring& protocol) noexcept {
				if (data.empty()) {
					protocol = L"Unknown";
					return false;
				}

				// Check protocols in order of likelihood
				if (IsHttpTraffic(data)) {
					protocol = L"HTTP";
					return true;
				}
				if (IsHttpsTraffic(data)) {
					protocol = L"HTTPS/TLS";
					return true;
				}
				if (IsSshTraffic(data)) {
					protocol = L"SSH";
					return true;
				}
				if (IsFtpTraffic(data)) {
					protocol = L"FTP";
					return true;
				}
				if (IsSmtpTraffic(data)) {
					protocol = L"SMTP";
					return true;
				}
				if (IsImapTraffic(data)) {
					protocol = L"IMAP";
					return true;
				}
				if (IsPop3Traffic(data)) {
					protocol = L"POP3";
					return true;
				}
				if (IsDnsTraffic(data)) {
					protocol = L"DNS";
					return true;
				}
				if (IsTelnetTraffic(data)) {
					protocol = L"TELNET";
					return true;
				}
				if (IsRdpTraffic(data)) {
					protocol = L"RDP";
					return true;
				}
				if (IsSmbTraffic(data)) {
					protocol = L"SMB";
					return true;
				}

				protocol = L"Unknown";
				return false;
			}

			/**
            * Detects if the provided data buffer corresponds to common HTTP traffic patterns.
            * Optimized to satisfy PVS-Studio V814 by avoiding redundant strlen calls.
            * * @param data The raw byte buffer to analyze.
            * @return True if a known HTTP method or response header is detected at the start of the buffer.
            */
			bool IsHttpTraffic(const std::vector<uint8_t>& data) noexcept {
				// Minimum length requirement for the shortest HTTP method pattern (e.g., "GET ")
				if (data.size() < 4) {
					return false;
				}

				// Known HTTP methods and protocol markers
				// Note: Patterns include trailing spaces where applicable to increase precision
				const char* httpMethods[] = {
					"GET ", "POST", "PUT ", "DELE", "HEAD", "PATC", "OPTI", "TRAC",
					"HTTP" // Matches HTTP response headers (e.g., HTTP/1.1)
				};

				for (const char* method : httpMethods) {
					// Optimization: Cache string length to prevent O(n^2) behavior in the loop (Fixes V814)
					const size_t methodLen = std::strlen(method);

					// Safety check: Ensure the buffer is large enough to contain the current method pattern
					if (data.size() >= methodLen) {
						// High-performance memory comparison using intrinsic-optimized memcmp
						// memcmp returns 0 when the memory blocks are identical
						if (std::memcmp(data.data(), method, methodLen) == 0) {
							return true;
						}
					}
				}

				return false;
			}

			bool IsHttpsTraffic(const std::vector<uint8_t>& data) noexcept {
				if (data.size() < 5) return false;

				// TLS/SSL Handshake patterns
				// TLS Record: [Content Type (1 byte)][Version (2 bytes)][Length (2 bytes)]
				// Content Type: 0x16 = Handshake, 0x17 = Application Data
				// Version: 0x0301 = TLS 1.0, 0x0302 = TLS 1.1, 0x0303 = TLS 1.2, 0x0304 = TLS 1.3

				uint8_t contentType = data[0];
				uint16_t version = (static_cast<uint16_t>(data[1]) << 8) | data[2];

				// Check for TLS/SSL content types
				if (contentType == 0x16 || contentType == 0x17 || contentType == 0x14 ||
					contentType == 0x15 || contentType == 0x18) {

					// Check for valid TLS/SSL versions
					if (version == 0x0301 || // TLS 1.0
						version == 0x0302 || // TLS 1.1
						version == 0x0303 || // TLS 1.2
						version == 0x0304 || // TLS 1.3
						version == 0x0300) { // SSL 3.0
						return true;
					}
				}

				// Additional check for Client Hello (Handshake Type 0x01)
				if (data.size() >= 6 &&
					data[0] == 0x16 && // Handshake
					data[5] == 0x01) { // Client Hello
					return true;
				}

				return false;
			}


			bool IsDnsTraffic(const std::vector<uint8_t>& data) noexcept {
				if (data.size() < 12) return false; // DNS header minimum 12 bytes

				// DNS Header structure:
				// [Transaction ID (2)][Flags (2)][Questions (2)][Answers (2)][Authority (2)][Additional (2)]

				// Get flags (bytes 2-3)
				uint16_t flags = (static_cast<uint16_t>(data[2]) << 8) | data[3];

				// Check QR bit (bit 15): 0 = Query, 1 = Response
				// Check Opcode (bits 11-14): 0 = Standard Query, 1 = Inverse Query, 2 = Status Request
				uint8_t qr = (flags >> 15) & 0x01;
				uint8_t opcode = (flags >> 11) & 0x0F;

				// Valid DNS opcodes: 0 (Standard), 1 (Inverse - deprecated), 2 (Status), 4 (Notify), 5 (Update)
				if (opcode > 5 && opcode != 0) return false;

				// Get question count (bytes 4-5)
				uint16_t questions = (static_cast<uint16_t>(data[4]) << 8) | data[5];

				// DNS query should have at least 1 question, DNS response can have 0 questions
				if (qr == 0 && questions == 0) return false; // Query with no questions is invalid

				// Sanity check: questions count should be reasonable (< 100 for most cases)
				if (questions > 100) return false;

				// Additional validation: check if data length is reasonable for DNS packet
				// DNS over UDP: max 512 bytes (traditionally), DNS over TCP can be larger
				if (data.size() > 4096) return false; // Too large for typical DNS

				return true;
			}

			/**
            * Detects if the provided data buffer corresponds to FTP traffic patterns.
            * Identifies both FTP server response codes and common FTP client commands.
            * * @param data The raw byte buffer to analyze.
            * @return True if FTP-specific patterns are detected at the start of the buffer.
            */
			bool IsFtpTraffic(const std::vector<uint8_t>& data) noexcept {
				// Basic length requirement for the shortest possible FTP pattern
				if (data.size() < 3) {
					return false;
				}

				// 1. Check for FTP server response codes (3-digit codes, e.g., "220 ", "331-")
				// FTP status codes are defined in RFC 959.
				if (data.size() >= 4 &&
					std::isdigit(data[0]) && std::isdigit(data[1]) && std::isdigit(data[2]) &&
					(data[3] == ' ' || data[3] == '-')) {
					return true;
				}

				// 2. Check for common FTP client commands
				// Optimized list for memory comparison
				const char* ftpCommands[] = {
					"USER", "PASS", "ACCT", "CWD ", "CDUP", "SMNT", "QUIT",
					"REIN", "PORT", "PASV", "TYPE", "STRU", "MODE", "RETR",
					"STOR", "STOU", "APPE", "ALLO", "REST", "RNFR", "RNTO",
					"ABOR", "DELE", "RMD ", "MKD ", "PWD ", "LIST", "NLST",
					"SITE", "SYST", "STAT", "HELP", "NOOP"
				};

				for (const char* cmd : ftpCommands) {
					// Optimization: Pre-calculate command length to fix PVS-Studio V814
					const size_t cmdLen = std::strlen(cmd);

					// Ensure buffer contains enough data for comparison
					if (data.size() >= cmdLen) {
						// High-performance block memory comparison
						if (std::memcmp(data.data(), cmd, cmdLen) == 0) {
							return true;
						}
					}
				}

				return false;
			}

			bool IsSshTraffic(const std::vector<uint8_t>& data) noexcept {
				if (data.size() < 4) return false;

				// SSH protocol identification string: "SSH-"
				// Format: SSH-protoversion-softwareversion
				// Examples: "SSH-2.0-OpenSSH_7.4", "SSH-1.99-Cisco-1.25"
				if (data.size() >= 8) {
					if (std::memcmp(data.data(), "SSH-", 4) == 0) {
						// Check version format: SSH-X.Y
						if (data.size() >= 7) {
							if (std::isdigit(data[4]) && data[5] == '.' && std::isdigit(data[6])) {
								return true;
							}
						}
					}
				}

				// SSH binary packet structure (after key exchange)
				// First 4 bytes: packet length (big-endian, excluding MAC and length itself)
				// Next byte: padding length
				// Packet length should be reasonable (not too large)
				if (data.size() >= 6) {
					uint32_t packetLen = (static_cast<uint32_t>(data[0]) << 24) |
						(static_cast<uint32_t>(data[1]) << 16) |
						(static_cast<uint32_t>(data[2]) << 8) |
						static_cast<uint32_t>(data[3]);

					// SSH packets are typically < 256KB
					if (packetLen > 0 && packetLen < 262144) {
						uint8_t paddingLen = data[4];
						// Padding length should be 4-255 bytes per SSH spec
						if (paddingLen >= 4 && paddingLen < 256) {
							// Message code (byte 5) should be valid SSH message type
							uint8_t msgCode = data[5];
							// SSH message types: 1-99 = Transport layer, 20-49 = Key exchange, etc.
							if (msgCode >= 1 && msgCode <= 99) {
								return true;
							}
						}
					}
				}

				return false;
			}

			/**
 * Analyzes network data to detect SMTP/ESMTP protocol patterns.
 * Optimized for high-throughput scanning by avoiding heap allocations.
 */
			bool IsSmtpTraffic(const std::vector<uint8_t>& data) noexcept {
				if (data.size() < 4) return false;

				// 1. Analyze Server Responses (3-digit code + ' ' or '-')
				// Example: "220 ", "250-"
				if (std::isdigit(data[0]) && std::isdigit(data[1]) && std::isdigit(data[2]) &&
					(data[3] == ' ' || data[3] == '-'))
				{
					// Extract numeric code without using atoi/string
					int codeNum = (data[0] - '0') * 100 + (data[1] - '0') * 10 + (data[2] - '0');

					// Common SMTP response codes per RFC 5321
					static const int smtpCodes[] = {
						220, 221, 250, 251, 252, 354, 421, 450, 451, 452,
						500, 501, 502, 503, 504, 550, 551, 552, 553, 554
					};

					for (int validCode : smtpCodes) {
						if (codeNum == validCode) {
							// Check if it's a 220 Greeting containing "SMTP"
							if (codeNum == 220 && data.size() >= 10) {
								// Search for "SMTP" in the greeting banner (case-insensitive not required for protocol keywords)
								// We avoid PVS-Studio V734 by searching for "SMTP" only, which covers "ESMTP"
								const char* rawData = reinterpret_cast<const char*>(data.data());
								if (std::strstr(rawData, "SMTP") != nullptr) {
									return true;
								}
							}
							return true;
						}
					}
				}

				// 2. Analyze Client Commands (Case-Insensitive Triage)
				// We check the first 4 characters for known SMTP verbs
				if (data.size() >= 4) {
					char cmd[5] = { 0 };
					for (int i = 0; i < 4; ++i) cmd[i] = static_cast<char>(::toupper(data[i]));

					// Check for common SMTP verbs
					static const char* smtpVerbs[] = {
						"HELO", "EHLO", "MAIL", "RCPT", "DATA", "RSET", "QUIT", "AUTH"
					};

					for (const char* verb : smtpVerbs) {
						if (std::memcmp(cmd, verb, 4) == 0) {
							return true;
						}
					}
				}

				return false;
			}

			bool IsImapTraffic(const std::vector<uint8_t>& data) noexcept {
				if (data.size() < 4) return false;

				// IMAP commands start with a tag (alphanumeric string)
				// followed by space and command
				// Examples: "A001 LOGIN", "* OK IMAP4", "a1 SELECT INBOX"

				// Check for IMAP server greeting: "* OK" or "* BYE"
				if (data.size() >= 4) {
					if (data[0] == '*' && data[1] == ' ') {
						if (data.size() >= 6) {
							std::string prefix(reinterpret_cast<const char*>(data.data() + 2),
								std::min(size_t(4), data.size() - 2));
							std::transform(prefix.begin(), prefix.end(), prefix.begin(), ::toupper);

							if (prefix.find("OK") == 0 || prefix.find("BYE") == 0 ||
								prefix.find("NO") == 0 || prefix.find("BAD") == 0) {
								// Look for "IMAP" in greeting to confirm
								if (data.size() >= 15) {
									std::string greeting(reinterpret_cast<const char*>(data.data()),
										std::min(size_t(40), data.size()));
									std::transform(greeting.begin(), greeting.end(), greeting.begin(), ::toupper);
									if (greeting.find("IMAP") != std::string::npos) {
										return true;
									}
								}
								return true; // OK/BYE/NO/BAD with * prefix is strong indicator
							}
						}
					}
				}

				// IMAP client commands (come after tag, so search in string)
				static const char* imapCommands[] = {
					"LOGIN", "SELECT", "EXAMINE", "CREATE", "DELETE", "RENAME",
					"SUBSCRIBE", "UNSUBSCRIBE", "LIST", "LSUB", "STATUS", "APPEND",
					"CHECK", "CLOSE", "EXPUNGE", "SEARCH", "FETCH", "STORE",
					"COPY", "UID", "LOGOUT", "NOOP", "CAPABILITY", "STARTTLS", "AUTHENTICATE"
				};

				std::string dataStr;
				if (data.size() >= 5) {
					dataStr.assign(reinterpret_cast<const char*>(data.data()),
						std::min(size_t(50), data.size()));
					std::transform(dataStr.begin(), dataStr.end(), dataStr.begin(), ::toupper);

					for (const auto* cmd : imapCommands) {
						if (dataStr.find(cmd) != std::string::npos) {
							return true;
						}
					}
				}

				return false;
			}

			bool IsPop3Traffic(const std::vector<uint8_t>& data) noexcept {
				if (data.size() < 3) return false;

				// POP3 server responses start with "+OK" or "-ERR"
				if (data.size() >= 3) {
					if (data[0] == '+') {
						if (data.size() >= 4 && data[1] == 'O' && data[2] == 'K') {
							return true;
						}
					}
					if (data[0] == '-') {
						if (data.size() >= 4 && data[1] == 'E' && data[2] == 'R' && data[3] == 'R') {
							return true;
						}
					}
				}

				// POP3 client commands
				static const char* pop3Commands[] = {
					"USER ", "PASS ", "STAT", "LIST", "RETR ", "DELE ", "NOOP",
					"RSET", "QUIT", "TOP ", "UIDL", "APOP ", "AUTH "
				};

				std::string dataStr;
				if (data.size() >= 4) {
					dataStr.assign(reinterpret_cast<const char*>(data.data()),
						std::min(size_t(8), data.size()));
					std::transform(dataStr.begin(), dataStr.end(), dataStr.begin(), ::toupper);

					for (const auto* cmd : pop3Commands) {
						if (dataStr.find(cmd) == 0) {
							return true;
						}
					}
				}

				// Check for POP3 greeting
				if (data.size() >= 20) {
					std::string greeting(reinterpret_cast<const char*>(data.data()),
						std::min(size_t(40), data.size()));
					std::transform(greeting.begin(), greeting.end(), greeting.begin(), ::toupper);
					if (greeting.find("+OK POP3") != std::string::npos) {
						return true;
					}
				}

				return false;
			}

			bool IsTelnetTraffic(const std::vector<uint8_t>& data) noexcept {
				if (data.size() < 3) return false;

				// Telnet uses IAC (Interpret As Command) = 0xFF
				// Followed by command byte and option byte
				// Common sequences: IAC WILL, IAC WONT, IAC DO, IAC DONT

				for (size_t i = 0; i < data.size() - 2; ++i) {
					if (data[i] == 0xFF) { // IAC
						uint8_t cmd = data[i + 1];
						// Telnet commands: 240-255
						// 251=WILL, 252=WONT, 253=DO, 254=DONT, 250=SB, 240=SE
						if (cmd >= 240 && cmd <= 255) {
							return true;
						}
					}
				}

				// Check for telnet option negotiation patterns
				if (data.size() >= 3) {
					// Count IAC sequences
					int iacCount = 0;
					for (size_t i = 0; i < data.size(); ++i) {
						if (data[i] == 0xFF) iacCount++;
					}
					// If more than 2 IAC bytes in small packet, likely telnet
					if (iacCount >= 2 && data.size() < 100) {
						return true;
					}
				}

				return false;
			}

			bool IsRdpTraffic(const std::vector<uint8_t>& data) noexcept {
				if (data.size() < 11) return false;

				// RDP uses TPKT header (RFC 1006)
				// TPKT version: 0x03
				// Reserved: 0x00
				// Length: 2 bytes (big-endian)
				if (data[0] == 0x03 && data[1] == 0x00) {
					uint16_t tpktLen = (static_cast<uint16_t>(data[2]) << 8) | data[3];

					// TPKT length should match or be close to actual data length
					if (tpktLen >= 11 && tpktLen <= data.size() + 100) {
						// Check for X.224 connection request/confirm (RDP's transport layer)
						// X.224 header starts at byte 4
						if (data.size() > 5) {
							uint8_t x224Len = data[4];
							uint8_t x224Type = data[5];

							// X.224 Connection Request = 0xE0, Connection Confirm = 0xD0
							// Data = 0xF0
							if (x224Type == 0xE0 || x224Type == 0xD0 || x224Type == 0xF0) {
								return true;
							}
						}
					}
				}

				// Check for RDP negotiation request (Cookie: mstshash=)
				if (data.size() >= 15) {
					std::string dataStr(reinterpret_cast<const char*>(data.data()),
						std::min(size_t(80), data.size()));
					if (dataStr.find("Cookie: mstshash=") != std::string::npos ||
						dataStr.find("rdpdr") != std::string::npos ||
						dataStr.find("cliprdr") != std::string::npos) {
						return true;
					}
				}

				// Check for CredSSP (RDP with NLA - Network Level Authentication)
				// CredSSP uses SPNEGO which starts with specific ASN.1 structures
				if (data.size() >= 10) {
					// SPNEGO typically starts with 0x60 (SEQUENCE tag)
					if (data[0] == 0x60 && data.size() >= 20) {
						// Look for NTLM or Kerberos OIDs
						std::string dataStr(reinterpret_cast<const char*>(data.data()),
							std::min(size_t(100), data.size()));
						// NTLMSSP signature
						if (dataStr.find("NTLMSSP") != std::string::npos) {
							return true;
						}
					}
				}

				return false;
			}

			bool IsSmbTraffic(const std::vector<uint8_t>& data) noexcept {
				if (data.size() < 4) return false;

				// SMB1 (CIFS) signature: 0xFF 'S' 'M' 'B'
				if (data.size() >= 4) {
					if (data[0] == 0xFF && data[1] == 'S' && data[2] == 'M' && data[3] == 'B') {
						return true;
					}
				}

				// SMB2/SMB3 signature: 0xFE 'S' 'M' 'B'
				if (data.size() >= 4) {
					if (data[0] == 0xFE && data[1] == 'S' && data[2] == 'M' && data[3] == 'B') {
						return true;
					}
				}

				// NetBIOS Session Service header (used for SMB over NetBIOS)
				// Type: 0x00 (Session Message), Length: 3 bytes
				if (data.size() >= 8) {
					if (data[0] == 0x00) {
						// Next 3 bytes are length (big-endian, but only lower 17 bits used)
						uint32_t nbLen = ((static_cast<uint32_t>(data[1]) & 0x01) << 16) |
							(static_cast<uint32_t>(data[2]) << 8) |
							static_cast<uint32_t>(data[3]);

						// Check if SMB signature follows NetBIOS header
						if (nbLen > 0 && nbLen < 0x20000 && data.size() >= 8) {
							if ((data[4] == 0xFF || data[4] == 0xFE) &&
								data[5] == 'S' && data[6] == 'M' && data[7] == 'B') {
								return true;
							}
						}
					}
				}

				// SMB Direct (SMB over RDMA)
				// Uses different framing but still contains SMB signature
				if (data.size() >= 64) {
					for (size_t i = 0; i < data.size() - 4; ++i) {
						if ((data[i] == 0xFF || data[i] == 0xFE) &&
							data[i + 1] == 'S' && data[i + 2] == 'M' && data[i + 3] == 'B') {
							return true;
						}
					}
				}

				return false;
			}

		
			// ============================================================================
			// Utility Functions
			// ============================================================================

			std::wstring GetProtocolName(ProtocolType protocol) noexcept {
				switch (protocol) {
				case ProtocolType::TCP: return L"TCP";
				case ProtocolType::UDP: return L"UDP";
				case ProtocolType::ICMP: return L"ICMP";
				case ProtocolType::ICMPv6: return L"ICMPv6";
				case ProtocolType::RAW: return L"RAW";
				default: return L"Unknown";
				}
			}

			std::wstring GetTcpStateName(TcpState state) noexcept {
				switch (state) {
				case TcpState::Closed: return L"CLOSED";
				case TcpState::Listen: return L"LISTEN";
				case TcpState::SynSent: return L"SYN_SENT";
				case TcpState::SynRcvd: return L"SYN_RCVD";
				case TcpState::Established: return L"ESTABLISHED";
				case TcpState::FinWait1: return L"FIN_WAIT1";
				case TcpState::FinWait2: return L"FIN_WAIT2";
				case TcpState::CloseWait: return L"CLOSE_WAIT";
				case TcpState::Closing: return L"CLOSING";
				case TcpState::LastAck: return L"LAST_ACK";
				case TcpState::TimeWait: return L"TIME_WAIT";
				case TcpState::DeleteTcb: return L"DELETE_TCB";
				default: return L"UNKNOWN";
				}
			}

			std::wstring GetAdapterTypeName(AdapterType type) noexcept {
				switch (type) {
				case AdapterType::Ethernet: return L"Ethernet";
				case AdapterType::Wireless80211: return L"Wireless 802.11";
				case AdapterType::Loopback: return L"Loopback";
				case AdapterType::Tunnel: return L"Tunnel";
				case AdapterType::PPP: return L"PPP";
				case AdapterType::Virtual: return L"Virtual";
				default: return L"Unknown";
				}
			}

			std::wstring GetOperationalStatusName(OperationalStatus status) noexcept {
				switch (status) {
				case OperationalStatus::Up: return L"Up";
				case OperationalStatus::Down: return L"Down";
				case OperationalStatus::Testing: return L"Testing";
				case OperationalStatus::Dormant: return L"Dormant";
				case OperationalStatus::NotPresent: return L"Not Present";
				case OperationalStatus::LowerLayerDown: return L"Lower Layer Down";
				default: return L"Unknown";
				}
			}

			std::wstring FormatBytes(uint64_t bytes) noexcept {
				const wchar_t* units[] = { L"B", L"KB", L"MB", L"GB", L"TB" };
				int unitIndex = 0;
				double size = static_cast<double>(bytes);

				while (size >= 1024.0 && unitIndex < 4) {
					size /= 1024.0;
					++unitIndex;
				}

				wchar_t buffer[64];
				swprintf_s(buffer, L"%.2f %s", size, units[unitIndex]);
				return buffer;
			}

			std::wstring FormatBytesPerSecond(uint64_t bytesPerSec) noexcept {
				return FormatBytes(bytesPerSec) + L"/s";
			}

			// ============================================================================
			// Error Helpers
			// ============================================================================

			std::wstring FormatNetworkError(DWORD errorCode) noexcept {
				wchar_t* messageBuffer = nullptr;
				size_t size = ::FormatMessageW(
					FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
					nullptr, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
					reinterpret_cast<LPWSTR>(&messageBuffer), 0, nullptr);

				std::wstring message;
				if (size > 0 && messageBuffer) {
					message = messageBuffer;
					::LocalFree(messageBuffer);
				} else {
					message = L"Unknown error code: " + std::to_wstring(errorCode);
				}

				return message;
			}

			std::wstring FormatWinHttpError(DWORD errorCode) noexcept {
				return FormatNetworkError(errorCode);
			}

			std::wstring FormatWsaError(int wsaError) noexcept {
				switch (wsaError) {
				case WSAEACCES: return L"Permission denied";
				case WSAEADDRINUSE: return L"Address already in use";
				case WSAEADDRNOTAVAIL: return L"Cannot assign requested address";
				case WSAEAFNOSUPPORT: return L"Address family not supported";
				case WSAEALREADY: return L"Operation already in progress";
				case WSAECONNABORTED: return L"Software caused connection abort";
				case WSAECONNREFUSED: return L"Connection refused";
				case WSAECONNRESET: return L"Connection reset by peer";
				case WSAEDESTADDRREQ: return L"Destination address required";
				case WSAEHOSTDOWN: return L"Host is down";
				case WSAEHOSTUNREACH: return L"No route to host";
				case WSAEINPROGRESS: return L"Operation now in progress";
				case WSAEINTR: return L"Interrupted function call";
				case WSAEINVAL: return L"Invalid argument";
				case WSAEISCONN: return L"Socket is already connected";
				case WSAEMFILE: return L"Too many open files";
				case WSAEMSGSIZE: return L"Message too long";
				case WSAENETDOWN: return L"Network is down";
				case WSAENETRESET: return L"Network dropped connection on reset";
				case WSAENETUNREACH: return L"Network is unreachable";
				case WSAENOBUFS: return L"No buffer space available";
				case WSAENOPROTOOPT: return L"Bad protocol option";
				case WSAENOTCONN: return L"Socket is not connected";
				case WSAENOTSOCK: return L"Socket operation on non-socket";
				case WSAEOPNOTSUPP: return L"Operation not supported";
				case WSAEPFNOSUPPORT: return L"Protocol family not supported";
				case WSAEPROTONOSUPPORT: return L"Protocol not supported";
				case WSAEPROTOTYPE: return L"Protocol wrong type for socket";
				case WSAESHUTDOWN: return L"Cannot send after socket shutdown";
				case WSAESOCKTNOSUPPORT: return L"Socket type not supported";
				case WSAETIMEDOUT: return L"Connection timed out";
				case WSAEWOULDBLOCK: return L"Resource temporarily unavailable";
				case WSAHOST_NOT_FOUND: return L"Host not found";
				case WSANO_DATA: return L"Valid name, no data record of requested type";
				case WSANO_RECOVERY: return L"This is a non-recoverable error";
				case WSATRY_AGAIN: return L"Non-authoritative host not found";
				default: return L"Unknown WSA error: " + std::to_wstring(wsaError);
				}
			}

		} // namespace NetworkUtils
	} // namespace Utils
} // namespace ShadowStrike
