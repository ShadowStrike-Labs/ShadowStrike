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
			// IPv4Address Implementation
			// ============================================================================

			std::wstring IPv4Address::ToString() const {
				wchar_t buffer[16];
				swprintf_s(buffer, L"%u.%u.%u.%u", octets[0], octets[1], octets[2], octets[3]);
				return buffer;
			}

			bool IPv4Address::IsLoopback() const noexcept {
				return octets[0] == 127;
			}

			bool IPv4Address::IsPrivate() const noexcept {
				// 10.0.0.0/8
				if (octets[0] == 10) return true;
				// 172.16.0.0/12
				if (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) return true;
				// 192.168.0.0/16
				if (octets[0] == 192 && octets[1] == 168) return true;
				return false;
			}

			bool IPv4Address::IsMulticast() const noexcept {
				// 224.0.0.0/4
				return octets[0] >= 224 && octets[0] <= 239;
			}

			bool IPv4Address::IsBroadcast() const noexcept {
				return octets[0] == 255 && octets[1] == 255 && octets[2] == 255 && octets[3] == 255;
			}

			bool IPv4Address::IsLinkLocal() const noexcept {
				// 169.254.0.0/16
				return octets[0] == 169 && octets[1] == 254;
			}

			// ============================================================================
			// IPv6Address Implementation
			// ============================================================================

			std::wstring IPv6Address::ToString() const {
				wchar_t buffer[40];
				swprintf_s(buffer, L"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
					bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
					bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
				return buffer;
			}

			std::wstring IPv6Address::ToStringCompressed() const {
				// Find longest sequence of zeros for compression
				int maxZeroStart = -1, maxZeroLen = 0;
				int currentZeroStart = -1, currentZeroLen = 0;

				for (int i = 0; i < 8; ++i) {
					uint16_t word = (static_cast<uint16_t>(bytes[i * 2]) << 8) | bytes[i * 2 + 1];
					if (word == 0) {
						if (currentZeroStart == -1) {
							currentZeroStart = i;
							currentZeroLen = 1;
						} else {
							++currentZeroLen;
						}
					} else {
						if (currentZeroLen > maxZeroLen) {
							maxZeroStart = currentZeroStart;
							maxZeroLen = currentZeroLen;
						}
						currentZeroStart = -1;
						currentZeroLen = 0;
					}
				}
				if (currentZeroLen > maxZeroLen) {
					maxZeroStart = currentZeroStart;
					maxZeroLen = currentZeroLen;
				}

				std::wostringstream oss;
				bool compressed = false;
				for (int i = 0; i < 8; ++i) {
					if (maxZeroLen > 1 && i >= maxZeroStart && i < maxZeroStart + maxZeroLen) {
						if (!compressed) {
							oss << L"::";
							compressed = true;
						}
						continue;
					}
					if (i > 0 && !(compressed && i == maxZeroStart + maxZeroLen)) {
						oss << L':';
					}
					uint16_t word = (static_cast<uint16_t>(bytes[i * 2]) << 8) | bytes[i * 2 + 1];
					oss << std::hex << word;
				}

				return oss.str();
			}

			bool IPv6Address::IsLoopback() const noexcept {
				for (int i = 0; i < 15; ++i) {
					if (bytes[i] != 0) return false;
				}
				return bytes[15] == 1;
			}

			bool IPv6Address::IsPrivate() const noexcept {
				return IsUniqueLocal();
			}

			bool IPv6Address::IsMulticast() const noexcept {
				return bytes[0] == 0xFF;
			}

			bool IPv6Address::IsLinkLocal() const noexcept {
				return bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80;
			}

			bool IPv6Address::IsSiteLocal() const noexcept {
				return bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0xC0;
			}

			bool IPv6Address::IsUniqueLocal() const noexcept {
				return (bytes[0] & 0xFE) == 0xFC;
			}

			// ============================================================================
			// IpAddress Implementation
			// ============================================================================

			std::wstring IpAddress::ToString() const {
				if (version == IpVersion::IPv4) {
					if (auto* ipv4 = AsIPv4()) {
						return ipv4->ToString();
					}
				} else if (version == IpVersion::IPv6) {
					if (auto* ipv6 = AsIPv6()) {
						return ipv6->ToStringCompressed();
					}
				}
				return L"<invalid>";
			}

			bool IpAddress::IsLoopback() const noexcept {
				if (version == IpVersion::IPv4) {
					if (auto* ipv4 = AsIPv4()) return ipv4->IsLoopback();
				} else if (version == IpVersion::IPv6) {
					if (auto* ipv6 = AsIPv6()) return ipv6->IsLoopback();
				}
				return false;
			}

			bool IpAddress::IsPrivate() const noexcept {
				if (version == IpVersion::IPv4) {
					if (auto* ipv4 = AsIPv4()) return ipv4->IsPrivate();
				} else if (version == IpVersion::IPv6) {
					if (auto* ipv6 = AsIPv6()) return ipv6->IsPrivate();
				}
				return false;
			}

			bool IpAddress::IsMulticast() const noexcept {
				if (version == IpVersion::IPv4) {
					if (auto* ipv4 = AsIPv4()) return ipv4->IsMulticast();
				} else if (version == IpVersion::IPv6) {
					if (auto* ipv6 = AsIPv6()) return ipv6->IsMulticast();
				}
				return false;
			}

			bool IpAddress::operator==(const IpAddress& other) const noexcept {
				if (version != other.version) return false;
				if (version == IpVersion::IPv4) {
					auto* a = AsIPv4();
					auto* b = other.AsIPv4();
					return a && b && (*a == *b);
				} else if (version == IpVersion::IPv6) {
					auto* a = AsIPv6();
					auto* b = other.AsIPv6();
					return a && b && (*a == *b);
				}
				return false;
			}

			// ============================================================================
			// MacAddress Implementation
			// ============================================================================

			std::wstring MacAddress::ToString() const {
				wchar_t buffer[18];
				swprintf_s(buffer, L"%02X-%02X-%02X-%02X-%02X-%02X",
					bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
				return buffer;
			}

			bool MacAddress::IsValid() const noexcept {
				// Check if not all zeros and not broadcast
				bool allZero = true, allFF = true;
				for (auto b : bytes) {
					if (b != 0) allZero = false;
					if (b != 0xFF) allFF = false;
				}
				return !allZero && !allFF;
			}

			bool MacAddress::IsBroadcast() const noexcept {
				for (auto b : bytes) {
					if (b != 0xFF) return false;
				}
				return true;
			}

			bool MacAddress::IsMulticast() const noexcept {
				return (bytes[0] & 0x01) != 0;
			}

			// ============================================================================
			// IP Address Parsing
			// ============================================================================

			bool ParseIPv4(std::wstring_view str, IPv4Address& out, Error* err) noexcept {
				try {
					str = Internal::TrimWhitespace(str);
					if (str.empty()) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Empty IPv4 string");
						return false;
					}

					std::array<uint8_t, 4> octets{};
					size_t octetIndex = 0;
					size_t pos = 0;

					while (pos < str.size() && octetIndex < 4) {
						size_t dotPos = str.find(L'.', pos);
						std::wstring_view octetStr = str.substr(pos, dotPos == std::wstring_view::npos ? std::wstring_view::npos : dotPos - pos);

						if (octetStr.empty()) {
							Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Empty octet in IPv4");
							return false;
						}

						int value = 0;
						for (wchar_t c : octetStr) {
							if (c < L'0' || c > L'9') {
								Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid character in IPv4");
								return false;
							}
							value = value * 10 + (c - L'0');
							if (value > 255) {
								Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Octet value exceeds 255");
								return false;
							}
						}

						octets[octetIndex++] = static_cast<uint8_t>(value);

						if (dotPos == std::wstring_view::npos) break;
						pos = dotPos + 1;
					}

					if (octetIndex != 4) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"IPv4 must have exactly 4 octets");
						return false;
					}

					out = IPv4Address(octets);
					return true;

				} catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception parsing IPv4");
					return false;
				}
			}

			bool ParseIPv6(std::wstring_view str, IPv6Address& out, Error* err) noexcept {
				try {
					str = Internal::TrimWhitespace(str);
					if (str.empty()) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Empty IPv6 string");
						return false;
					}

					std::array<uint8_t, 16> bytes{};
					std::fill(bytes.begin(), bytes.end(), 0);

					// Handle IPv6 with scope ID (e.g., fe80::1%eth0)
					size_t percentPos = str.find(L'%');
					if (percentPos != std::wstring_view::npos) {
						str = str.substr(0, percentPos);
					}

					// Use Windows API for robust parsing
					sockaddr_in6 sa6{};
					sa6.sin6_family = AF_INET6;
					int len = sizeof(sa6);

					std::wstring strCopy(str);
					if (WSAStringToAddressW(strCopy.data(), AF_INET6, nullptr,
						reinterpret_cast<SOCKADDR*>(&sa6), &len) == 0) {
						std::memcpy(bytes.data(), &sa6.sin6_addr, 16);
						out = IPv6Address(bytes);
						return true;
					}

					Internal::SetWsaError(err, WSAGetLastError(), L"ParseIPv6");
					return false;

				} catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception parsing IPv6");
					return false;
				}
			}

			bool ParseIpAddress(std::wstring_view str, IpAddress& out, Error* err) noexcept {
				IPv4Address ipv4;
				if (ParseIPv4(str, ipv4, nullptr)) {
					out = IpAddress(ipv4);
					return true;
				}

				IPv6Address ipv6;
				if (ParseIPv6(str, ipv6, err)) {
					out = IpAddress(ipv6);
					return true;
				}

				if (err && err->message.empty()) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid IP address format");
				}
				return false;
			}

			bool IsValidIPv4(std::wstring_view str) noexcept {
				IPv4Address temp;
				return ParseIPv4(str, temp, nullptr);
			}

			bool IsValidIPv6(std::wstring_view str) noexcept {
				IPv6Address temp;
				return ParseIPv6(str, temp, nullptr);
			}

			bool IsValidIpAddress(std::wstring_view str) noexcept {
				return IsValidIPv4(str) || IsValidIPv6(str);
			}

			// ============================================================================
			// IP Network Calculations
			// ============================================================================

			bool IsInSubnet(const IpAddress& address, const IpAddress& subnet, uint8_t prefixLength) noexcept {
				if (address.version != subnet.version) return false;

				if (address.version == IpVersion::IPv4) {
					if (prefixLength > 32) return false;
					auto* addr = address.AsIPv4();
					auto* net = subnet.AsIPv4();
					if (!addr || !net) return false;

					uint32_t mask = (prefixLength == 0) ? 0 : (~0U << (32 - prefixLength));
					return (addr->ToUInt32() & mask) == (net->ToUInt32() & mask);

				} else if (address.version == IpVersion::IPv6) {
					if (prefixLength > 128) return false;
					auto* addr = address.AsIPv6();
					auto* net = subnet.AsIPv6();
					if (!addr || !net) return false;

					for (size_t i = 0; i < 16; ++i) {
						uint8_t bitsInByte = (i < prefixLength / 8) ? 8 : (i == prefixLength / 8 ? prefixLength % 8 : 0);
						if (bitsInByte == 0) break;

						uint8_t mask = (bitsInByte == 8) ? 0xFF : (0xFF << (8 - bitsInByte));
						if ((addr->bytes[i] & mask) != (net->bytes[i] & mask)) return false;
					}
					return true;
				}

				return false;
			}

			std::optional<IpAddress> GetNetworkAddress(const IpAddress& address, uint8_t prefixLength) noexcept {
				if (address.version == IpVersion::IPv4) {
					if (prefixLength > 32) return std::nullopt;
					auto* addr = address.AsIPv4();
					if (!addr) return std::nullopt;

					uint32_t mask = (prefixLength == 0) ? 0 : (~0U << (32 - prefixLength));
					uint32_t network = addr->ToUInt32() & mask;
					return IpAddress(IPv4Address(network));

				} else if (address.version == IpVersion::IPv6) {
					if (prefixLength > 128) return std::nullopt;
					auto* addr = address.AsIPv6();
					if (!addr) return std::nullopt;

					std::array<uint8_t, 16> networkBytes = addr->bytes;
					for (size_t i = 0; i < 16; ++i) {
						uint8_t bitsInByte = (i < prefixLength / 8) ? 8 : (i == prefixLength / 8 ? prefixLength % 8 : 0);
						uint8_t mask = (bitsInByte == 8) ? 0xFF : (bitsInByte == 0 ? 0 : (0xFF << (8 - bitsInByte)));
						networkBytes[i] &= mask;
					}
					return IpAddress(IPv6Address(networkBytes));
				}

				return std::nullopt;
			}

			std::optional<IpAddress> GetBroadcastAddress(const IPv4Address& network, uint8_t prefixLength) noexcept {
				if (prefixLength > 32) return std::nullopt;

				uint32_t mask = (prefixLength == 0) ? 0 : (~0U << (32 - prefixLength));
				uint32_t broadcast = network.ToUInt32() | ~mask;
				return IpAddress(IPv4Address(broadcast));
			}

			uint64_t GetAddressCount(uint8_t prefixLength, IpVersion version) noexcept {
				if (version == IpVersion::IPv4) {
					if (prefixLength > 32) return 0;
					return 1ULL << (32 - prefixLength);
				} else if (version == IpVersion::IPv6) {
					if (prefixLength > 128) return 0;
					if (prefixLength < 64) return UINT64_MAX; // Too large
					return 1ULL << (128 - prefixLength);
				}
				return 0;
			}

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
			// Hostname Resolution
			// ============================================================================

			bool ResolveHostname(std::wstring_view hostname, std::vector<IpAddress>& addresses, AddressFamily family, Error* err) noexcept {
				try {
					addresses.clear();

					WsaInitializer wsa;
					if (!wsa.IsInitialized()) {
						Internal::SetWsaError(err, wsa.GetError(), L"WSA initialization failed");
						return false;
					}

					std::string hostnameA(hostname.begin(), hostname.end());

					addrinfo hints{};
					hints.ai_family = static_cast<int>(family);
					hints.ai_socktype = SOCK_STREAM;
					hints.ai_protocol = IPPROTO_TCP;

					addrinfo* result = nullptr;
					int ret = ::getaddrinfo(hostnameA.c_str(), nullptr, &hints, &result);
					if (ret != 0) {
						Internal::SetWsaError(err, WSAGetLastError(), L"getaddrinfo");
						return false;
					}

					for (addrinfo* ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
						if (ptr->ai_family == AF_INET) {
							auto* sa = reinterpret_cast<sockaddr_in*>(ptr->ai_addr);
							uint32_t addr = Internal::NetworkToHost32(sa->sin_addr.s_addr);
							addresses.emplace_back(IPv4Address(addr));
						} else if (ptr->ai_family == AF_INET6) {
							auto* sa6 = reinterpret_cast<sockaddr_in6*>(ptr->ai_addr);
							std::array<uint8_t, 16> bytes;
							std::memcpy(bytes.data(), &sa6->sin6_addr, 16);
							addresses.emplace_back(IPv6Address(bytes));
						}
					}

					::freeaddrinfo(result);
					return !addresses.empty();

				} catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in ResolveHostname");
					return false;
				}
			}

			bool ResolveHostnameIPv4(std::wstring_view hostname, std::vector<IPv4Address>& addresses, Error* err) noexcept {
				std::vector<IpAddress> allAddresses;
				if (!ResolveHostname(hostname, allAddresses, AddressFamily::IPv4, err)) {
					return false;
				}

				addresses.clear();
				for (const auto& addr : allAddresses) {
					if (auto* ipv4 = addr.AsIPv4()) {
						addresses.push_back(*ipv4);
					}
				}

				return !addresses.empty();
			}

			bool ResolveHostnameIPv6(std::wstring_view hostname, std::vector<IPv6Address>& addresses, Error* err) noexcept {
				std::vector<IpAddress> allAddresses;
				if (!ResolveHostname(hostname, allAddresses, AddressFamily::IPv6, err)) {
					return false;
				}

				addresses.clear();
				for (const auto& addr : allAddresses) {
					if (auto* ipv6 = addr.AsIPv6()) {
						addresses.push_back(*ipv6);
					}
				}

				return !addresses.empty();
			}

			// ============================================================================
			// Reverse DNS Lookup
			// ============================================================================

			bool ReverseLookup(const IpAddress& address, std::wstring& hostname, Error* err) noexcept {
				try {
					WsaInitializer wsa;
					if (!wsa.IsInitialized()) {
						Internal::SetWsaError(err, wsa.GetError(), L"WSA initialization failed");
						return false;
					}

					if (address.version == IpVersion::IPv4) {
						auto* ipv4 = address.AsIPv4();
						if (!ipv4) {
							Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid IPv4 address");
							return false;
						}

						sockaddr_in sa{};
						sa.sin_family = AF_INET;
						sa.sin_addr.s_addr = Internal::HostToNetwork32(ipv4->ToUInt32());

						char hostBuffer[NI_MAXHOST];
						int ret = ::getnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof(sa),
							hostBuffer, sizeof(hostBuffer), nullptr, 0, NI_NAMEREQD);

						if (ret == 0) {
							hostname = std::wstring(hostBuffer, hostBuffer + std::strlen(hostBuffer));
							return true;
						}

					} else if (address.version == IpVersion::IPv6) {
						auto* ipv6 = address.AsIPv6();
						if (!ipv6) {
							Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid IPv6 address");
							return false;
						}

						sockaddr_in6 sa6{};
						sa6.sin6_family = AF_INET6;
						std::memcpy(&sa6.sin6_addr, ipv6->bytes.data(), 16);

						char hostBuffer[NI_MAXHOST];
						int ret = ::getnameinfo(reinterpret_cast<sockaddr*>(&sa6), sizeof(sa6),
							hostBuffer, sizeof(hostBuffer), nullptr, 0, NI_NAMEREQD);

						if (ret == 0) {
							hostname = std::wstring(hostBuffer, hostBuffer + std::strlen(hostBuffer));
							return true;
						}
					}

					Internal::SetWsaError(err, WSAGetLastError(), L"getnameinfo");
					return false;

				} catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in ReverseLookup");
					return false;
				}
			}

			// ============================================================================
			// DNS Queries
			// ============================================================================

			bool QueryDns(std::wstring_view hostname, DnsRecordType type, std::vector<DnsRecord>& records, const DnsQueryOptions& options, Error* err) noexcept {
				try {
					records.clear();

					std::wstring hostStr(hostname);
					PDNS_RECORD pDnsRecord = nullptr;

					DWORD flags = DNS_QUERY_STANDARD;

					if(!options.recursionDesired) {
						flags |= DNS_QUERY_NO_RECURSION;
					}
					if (options.dnssec) {
						flags |= DNS_QUERY_DNSSEC_OK;
					}
					if (!options.useSystemDns && !options.customDnsServers.empty()) {
						flags |= DNS_QUERY_NO_HOSTS_FILE;
					}

					// Prepare custom DNS servers if specified
					PIP4_ARRAY pDnsServers = nullptr;
					std::vector<IP4_ADDRESS> dnsServerAddresses;
					
					if (!options.customDnsServers.empty() && !options.useSystemDns) {
						for (const auto& dnsServer : options.customDnsServers) {
							if (dnsServer.IsIPv4()) {
								auto* ipv4 = dnsServer.AsIPv4();
								if (ipv4) {
									dnsServerAddresses.push_back(Internal::HostToNetwork32(ipv4->ToUInt32()));
								}
							}
						}

						if (!dnsServerAddresses.empty()) {
							size_t structSize = sizeof(IP4_ARRAY) + (dnsServerAddresses.size() - 1) * sizeof(IP4_ADDRESS);
							pDnsServers = reinterpret_cast<PIP4_ARRAY>(malloc(structSize));
							if (pDnsServers) {
								pDnsServers->AddrCount = static_cast<DWORD>(dnsServerAddresses.size());
								for (size_t i = 0; i < dnsServerAddresses.size(); ++i) {
									pDnsServers->AddrArray[i] = dnsServerAddresses[i];
								}
							}
						}
					}

					DNS_STATUS status = ::DnsQuery_W(
						hostStr.c_str(),
						static_cast<WORD>(type),
						flags,
						pDnsServers,
						&pDnsRecord,
						nullptr
					);

					// Cleanup custom DNS servers
					if (pDnsServers) {
						free(pDnsServers);
					}

					if (status != 0) {
						Internal::SetError(err, status, L"DnsQuery_W failed");
						return false;
					}

					for (PDNS_RECORD pRec = pDnsRecord; pRec != nullptr; pRec = pRec->pNext) {
						DnsRecord rec;
						rec.name = pRec->pName ? pRec->pName : L"";
						rec.type = static_cast<DnsRecordType>(pRec->wType);
						rec.ttl = pRec->dwTtl;

						switch (pRec->wType) {
						case DNS_TYPE_A:
							if (pRec->wDataLength >= sizeof(DNS_A_DATA)) {
								IPv4Address ipv4(Internal::NetworkToHost32(pRec->Data.A.IpAddress));
								rec.data = ipv4.ToString();
							}
							break;

						case DNS_TYPE_AAAA:
							if (pRec->wDataLength >= sizeof(DNS_AAAA_DATA)) {
								std::array<uint8_t, 16> bytes;
								std::memcpy(bytes.data(), &pRec->Data.AAAA.Ip6Address, 16);
								IPv6Address ipv6(bytes);
								rec.data = ipv6.ToStringCompressed();
							}
							break;

						case DNS_TYPE_CNAME:
							rec.data = pRec->Data.CNAME.pNameHost ? pRec->Data.CNAME.pNameHost : L"";
							break;

						case DNS_TYPE_MX:
							rec.data = pRec->Data.MX.pNameExchange ? pRec->Data.MX.pNameExchange : L"";
							rec.priority = pRec->Data.MX.wPreference;
							break;

						case DNS_TYPE_TEXT:
							for (DWORD i = 0; i < pRec->Data.TXT.dwStringCount; ++i) {
								if (pRec->Data.TXT.pStringArray[i]) {
									if (!rec.data.empty()) rec.data += L" ";
									rec.data += pRec->Data.TXT.pStringArray[i];
								}
							}
							break;

						case DNS_TYPE_PTR:
							rec.data = pRec->Data.PTR.pNameHost ? pRec->Data.PTR.pNameHost : L"";
							break;

						case DNS_TYPE_NS:
							rec.data = pRec->Data.NS.pNameHost ? pRec->Data.NS.pNameHost : L"";
							break;

						case DNS_TYPE_SRV:
							rec.data = pRec->Data.SRV.pNameTarget ? pRec->Data.SRV.pNameTarget : L"";
							rec.priority = pRec->Data.SRV.wPriority;
							break;

						default:
							rec.data = L"<unsupported record type>";
							break;
						}

						records.push_back(std::move(rec));
					}

					::DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
					return true;

				} catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in QueryDns");
					return false;
				}
			}

			bool QueryDnsA(std::wstring_view hostname, std::vector<IPv4Address>& addresses, const DnsQueryOptions& options, Error* err) noexcept {
				std::vector<DnsRecord> records;
				if (!QueryDns(hostname, DnsRecordType::A, records, options, err)) {
					return false;
				}

				addresses.clear();
				for (const auto& rec : records) {
					IPv4Address ipv4;
					if (ParseIPv4(rec.data, ipv4, nullptr)) {
						addresses.push_back(ipv4);
					}
				}

				return !addresses.empty();
			}

			bool QueryDnsAAAA(std::wstring_view hostname, std::vector<IPv6Address>& addresses, const DnsQueryOptions& options, Error* err) noexcept {
				std::vector<DnsRecord> records;
				if (!QueryDns(hostname, DnsRecordType::AAAA, records, options, err)) {
					return false;
				}

				addresses.clear();
				for (const auto& rec : records) {
					IPv6Address ipv6;
					if (ParseIPv6(rec.data, ipv6, nullptr)) {
						addresses.push_back(ipv6);
					}
				}

				return !addresses.empty();
			}

			bool QueryDnsMX(std::wstring_view domain, std::vector<DnsRecord>& mxRecords, const DnsQueryOptions& options, Error* err) noexcept {
				return QueryDns(domain, DnsRecordType::MX, mxRecords, options, err);
			}

			bool QueryDnsTXT(std::wstring_view domain, std::vector<std::wstring>& txtRecords, const DnsQueryOptions& options, Error* err) noexcept {
				std::vector<DnsRecord> records;
				if (!QueryDns(domain, DnsRecordType::TXT, records, options, err)) {
					return false;
				}

				txtRecords.clear();
				for (const auto& rec : records) {
					txtRecords.push_back(rec.data);
				}

				return !txtRecords.empty();
			}

			// ============================================================================
			// Network Adapter Information
			// ============================================================================

			bool GetNetworkAdapters(std::vector<NetworkAdapterInfo>& adapters, Error* err) noexcept {
				try {
					adapters.clear();

					ULONG bufferSize = 15000;
					std::vector<uint8_t> buffer(bufferSize);

					ULONG ret = ::GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS,
						nullptr, reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()), &bufferSize);

					if (ret == ERROR_BUFFER_OVERFLOW) {
						buffer.resize(bufferSize);
						ret = ::GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS,
							nullptr, reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()), &bufferSize);
					}

					if (ret != NO_ERROR) {
						Internal::SetError(err, ret, L"GetAdaptersAddresses failed");
						return false;
					}

					for (PIP_ADAPTER_ADDRESSES pAdapter = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
						pAdapter != nullptr; pAdapter = pAdapter->Next) {

						NetworkAdapterInfo info;
						info.friendlyName = pAdapter->FriendlyName ? pAdapter->FriendlyName : L"";
						info.description = pAdapter->Description ? pAdapter->Description : L"";
						info.interfaceIndex = pAdapter->IfIndex;
						info.mtu = pAdapter->Mtu;
						info.speed = pAdapter->TransmitLinkSpeed;
						info.type = static_cast<AdapterType>(pAdapter->IfType);
						info.status = static_cast<OperationalStatus>(pAdapter->OperStatus);
						info.dhcpEnabled = (pAdapter->Flags & IP_ADAPTER_DHCP_ENABLED) != 0;
						info.ipv4Enabled = (pAdapter->Flags & IP_ADAPTER_IPV4_ENABLED) != 0;
						info.ipv6Enabled = (pAdapter->Flags & IP_ADAPTER_IPV6_ENABLED) != 0;

						// MAC Address
						if (pAdapter->PhysicalAddressLength == 6) {
							std::array<uint8_t, 6> macBytes;
							std::memcpy(macBytes.data(), pAdapter->PhysicalAddress, 6);
							info.macAddress = MacAddress(macBytes);
						}

						// IP Addresses
						for (PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pAdapter->FirstUnicastAddress;
							pUnicast != nullptr; pUnicast = pUnicast->Next) {
							
							if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
								auto* sa = reinterpret_cast<sockaddr_in*>(pUnicast->Address.lpSockaddr);
								uint32_t addr = Internal::NetworkToHost32(sa->sin_addr.s_addr);
								info.ipAddresses.emplace_back(IPv4Address(addr));
							} else if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6) {
								auto* sa6 = reinterpret_cast<sockaddr_in6*>(pUnicast->Address.lpSockaddr);
								std::array<uint8_t, 16> bytes;
								std::memcpy(bytes.data(), &sa6->sin6_addr, 16);
								info.ipAddresses.emplace_back(IPv6Address(bytes));
							}
						}

						// Gateway Addresses
						for (PIP_ADAPTER_GATEWAY_ADDRESS pGateway = pAdapter->FirstGatewayAddress;
							pGateway != nullptr; pGateway = pGateway->Next) {
							
							if (pGateway->Address.lpSockaddr->sa_family == AF_INET) {
								auto* sa = reinterpret_cast<sockaddr_in*>(pGateway->Address.lpSockaddr);
								uint32_t addr = Internal::NetworkToHost32(sa->sin_addr.s_addr);
								info.gatewayAddresses.emplace_back(IPv4Address(addr));
							} else if (pGateway->Address.lpSockaddr->sa_family == AF_INET6) {
								auto* sa6 = reinterpret_cast<sockaddr_in6*>(pGateway->Address.lpSockaddr);
								std::array<uint8_t, 16> bytes;
								std::memcpy(bytes.data(), &sa6->sin6_addr, 16);
								info.gatewayAddresses.emplace_back(IPv6Address(bytes));
							}
						}

						// DNS Servers
						for (PIP_ADAPTER_DNS_SERVER_ADDRESS pDns = pAdapter->FirstDnsServerAddress;
							pDns != nullptr; pDns = pDns->Next) {
							
							if (pDns->Address.lpSockaddr->sa_family == AF_INET) {
								auto* sa = reinterpret_cast<sockaddr_in*>(pDns->Address.lpSockaddr);
								uint32_t addr = Internal::NetworkToHost32(sa->sin_addr.s_addr);
								info.dnsServers.emplace_back(IPv4Address(addr));
							} else if (pDns->Address.lpSockaddr->sa_family == AF_INET6) {
								auto* sa6 = reinterpret_cast<sockaddr_in6*>(pDns->Address.lpSockaddr);
								std::array<uint8_t, 16> bytes;
								std::memcpy(bytes.data(), &sa6->sin6_addr, 16);
								info.dnsServers.emplace_back(IPv6Address(bytes));
							}
						}

						adapters.push_back(std::move(info));
					}

					return true;

				} catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in GetNetworkAdapters");
					return false;
				}
			}

			bool GetDefaultGateway(IpAddress& gateway, Error* err) noexcept {
				std::vector<NetworkAdapterInfo> adapters;
				if (!GetNetworkAdapters(adapters, err)) {
					return false;
				}

				for (const auto& adapter : adapters) {
					if (adapter.status == OperationalStatus::Up && !adapter.gatewayAddresses.empty()) {
						gateway = adapter.gatewayAddresses[0];
						return true;
					}
				}

				Internal::SetError(err, ERROR_NOT_FOUND, L"No default gateway found");
				return false;
			}

			bool GetDnsServers(std::vector<IpAddress>& dnsServers, Error* err) noexcept {
				std::vector<NetworkAdapterInfo> adapters;
				if (!GetNetworkAdapters(adapters, err)) {
					return false;
				}

				dnsServers.clear();
				for (const auto& adapter : adapters) {
					if (adapter.status == OperationalStatus::Up) {
						for (const auto& dns : adapter.dnsServers) {
							dnsServers.push_back(dns);
						}
					}
				}

				return !dnsServers.empty();
			}

			bool GetLocalIpAddresses(std::vector<IpAddress>& addresses, bool includeLoopback, Error* err) noexcept {
				std::vector<NetworkAdapterInfo> adapters;
				if (!GetNetworkAdapters(adapters, err)) {
					return false;
				}

				addresses.clear();
				for (const auto& adapter : adapters) {
					if (adapter.status == OperationalStatus::Up) {
						for (const auto& ip : adapter.ipAddresses) {
							if (includeLoopback || !ip.IsLoopback()) {
								addresses.push_back(ip);
							}
						}
					}
				}

				return !addresses.empty();
			}

			// ============================================================================
			// HTTP/HTTPS Operations
			// ============================================================================

			bool HttpRequest(std::wstring_view url, HttpResponse& response, const HttpRequestOptions& options, Error* err) noexcept {
				try {
					response = HttpResponse{};

					WinHttpSession session;
					if (!session.Open(options.userAgent, err)) {
						return false;
					}

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

					HINTERNET hConnect = ::WinHttpConnect(session.Handle(), hostName, urlComp.nPort, 0);
					if (!hConnect) {
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

					DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
					HINTERNET hRequest = ::WinHttpOpenRequest(hConnect, method, urlPath, nullptr,
						WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
					
					if (!hRequest) {
						::WinHttpCloseHandle(hConnect);
						Internal::SetError(err, ::GetLastError(), L"WinHttpOpenRequest failed");
						return false;
					}

					// Set timeout
					::WinHttpSetTimeouts(hRequest, options.timeoutMs, options.timeoutMs, options.timeoutMs, options.timeoutMs);

					// Add custom headers
					for (const auto& header : options.headers) {
						std::wstring headerStr = header.name + L": " + header.value;
						::WinHttpAddRequestHeaders(hRequest, headerStr.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);
					}

					// Send request
					BOOL result = ::WinHttpSendRequest(hRequest,
						WINHTTP_NO_ADDITIONAL_HEADERS, 0,
						options.body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<void*>(static_cast<const void*>(options.body.data())),
						static_cast<DWORD>(options.body.size()),
						static_cast<DWORD>(options.body.size()), 0);

					if (!result) {
						::WinHttpCloseHandle(hRequest);
						::WinHttpCloseHandle(hConnect);
						Internal::SetError(err, ::GetLastError(), L"WinHttpSendRequest failed");
						return false;
					}

					// Receive response
					if (!::WinHttpReceiveResponse(hRequest, nullptr)) {
						::WinHttpCloseHandle(hRequest);
						::WinHttpCloseHandle(hConnect);
						Internal::SetError(err, ::GetLastError(), L"WinHttpReceiveResponse failed");
						return false;
					}

					// Get status code
					DWORD statusCode = 0;
					DWORD statusCodeSize = sizeof(statusCode);
					::WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
						nullptr, &statusCode, &statusCodeSize, nullptr);
					response.statusCode = statusCode;

					// Read response body
					std::vector<uint8_t> buffer(8192);
					DWORD bytesRead = 0;
					while (::WinHttpReadData(hRequest, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead) && bytesRead > 0) {
						response.body.insert(response.body.end(), buffer.begin(), buffer.begin() + bytesRead);
					}

					response.contentLength = response.body.size();

					::WinHttpCloseHandle(hRequest);
					::WinHttpCloseHandle(hConnect);

					return true;

				} catch (...) {
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
					HttpResponse response;
					if (!HttpRequest(url, response, options, err)) {
						return false;
					}

					std::ofstream outFile(destPath, std::ios::binary);
					if (!outFile) {
						Internal::SetError(err, ERROR_CANNOT_MAKE, L"Failed to create output file");
						return false;
					}

					outFile.write(reinterpret_cast<const char*>(response.body.data()), response.body.size());
					outFile.close();

					return true;

				} catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in HttpDownloadFile");
					return false;
				}
			}

			bool HttpUploadFile(std::wstring_view url, const std::filesystem::path& filePath, std::vector<uint8_t>& response, const HttpRequestOptions& options, ProgressCallback callback, Error* err) noexcept {
				try {
					std::ifstream inFile(filePath, std::ios::binary | std::ios::ate);
					if (!inFile) {
						Internal::SetError(err, ERROR_FILE_NOT_FOUND, L"Failed to open input file");
						return false;
					}

					std::streamsize fileSize = inFile.tellg();
					inFile.seekg(0, std::ios::beg);

					std::vector<uint8_t> fileData(fileSize);
					if (!inFile.read(reinterpret_cast<char*>(fileData.data()), fileSize)) {
						Internal::SetError(err, ERROR_READ_FAULT, L"Failed to read input file");
						return false;
					}

					return HttpPost(url, fileData, response, options, err);

				} catch (...) {
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

			// ============================================================================
			// Ping and Network Testing
			// ============================================================================

			bool Ping(const IpAddress& address, PingResult& result, const PingOptions& options, Error* err) noexcept {
				try {
					result = PingResult{};
					result.address = address;

					if (address.version == IpVersion::IPv4) {
						auto* ipv4 = address.AsIPv4();
						if (!ipv4) {
							Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid IPv4 address");
							return false;
						}

						HANDLE hIcmp = ::IcmpCreateFile();
						if (hIcmp == INVALID_HANDLE_VALUE) {
							Internal::SetError(err, ::GetLastError(), L"IcmpCreateFile failed");
							return false;
						}

						std::vector<uint8_t> sendData = options.data;
						if (sendData.empty()) {
							sendData.resize(32, 0xAA);
						}

						std::vector<uint8_t> replyBuffer(sizeof(ICMP_ECHO_REPLY) + sendData.size() + 8);
						
						DWORD replySize = ::IcmpSendEcho(hIcmp,
							Internal::HostToNetwork32(ipv4->ToUInt32()),
							sendData.data(), static_cast<WORD>(sendData.size()),
							nullptr,
							replyBuffer.data(), static_cast<DWORD>(replyBuffer.size()),
							options.timeoutMs);

						::IcmpCloseHandle(hIcmp);

						if (replySize > 0) {
							auto* pReply = reinterpret_cast<PICMP_ECHO_REPLY>(replyBuffer.data());
							result.success = (pReply->Status == IP_SUCCESS);
							result.roundTripTimeMs = pReply->RoundTripTime;
							result.ttl = pReply->Options.Ttl;
							result.dataSize = pReply->DataSize;
						} else {
							result.success = false;
							result.errorMessage = L"Ping timeout or failed";
						}

						return true;
					}
					else if (address.version == IpVersion::IPv6) {
						auto* ipv6 = address.AsIPv6();
						if (!ipv6) {
							Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid IPv6 address");
							return false;
						}

						HANDLE hIcmp6 = ::Icmp6CreateFile();
						if (hIcmp6 == INVALID_HANDLE_VALUE) {
							Internal::SetError(err, ::GetLastError(), L"Icmp6CreateFile failed");
							return false;
						}

						sockaddr_in6 sourceAddr{};
						sourceAddr.sin6_family = AF_INET6;

						sockaddr_in6 destAddr{};
						destAddr.sin6_family = AF_INET6;
						std::memcpy(&destAddr.sin6_addr, ipv6->bytes.data(), 16);

						std::vector<uint8_t> sendData = options.data;
						if (sendData.empty()) {
							sendData.resize(32, 0xAA);
						}

						std::vector<uint8_t> replyBuffer(sizeof(ICMPV6_ECHO_REPLY) + sendData.size() + 8);
						
						DWORD replySize = ::Icmp6SendEcho2(hIcmp6, nullptr, nullptr, nullptr,
							&sourceAddr, &destAddr,
							sendData.data(), static_cast<WORD>(sendData.size()),
							nullptr,
							replyBuffer.data(), static_cast<DWORD>(replyBuffer.size()),
							options.timeoutMs);

						::IcmpCloseHandle(hIcmp6);

						if (replySize > 0) {
							auto* pReply = reinterpret_cast<PICMPV6_ECHO_REPLY>(replyBuffer.data());
							result.success = (pReply->Status == IP_SUCCESS);
							result.roundTripTimeMs = pReply->RoundTripTime;
						} else {
							result.success = false;
							result.errorMessage = L"Ping timeout or failed";
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

					WsaInitializer wsa;
					if (!wsa.IsInitialized()) {
						Internal::SetWsaError(err, wsa.GetError(), L"WSA initialization failed");
						return false;
					}

					SOCKET sock = ::socket(address.IsIPv4() ? AF_INET : AF_INET6, SOCK_STREAM, IPPROTO_TCP);
					if (sock == INVALID_SOCKET) {
						Internal::SetWsaError(err, ::WSAGetLastError(), L"socket creation failed");
						return false;
					}

					// Set non-blocking mode
					u_long mode = 1;
					::ioctlsocket(sock, FIONBIO, &mode);

					// Set timeout
					struct timeval tv;
					tv.tv_sec = timeoutMs / 1000;
					tv.tv_usec = (timeoutMs % 1000) * 1000;
					::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
					::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));

					auto startTime = std::chrono::steady_clock::now();

					int connectResult = -1;
					if (address.IsIPv4()) {
						auto* ipv4 = address.AsIPv4();
						sockaddr_in sa{};
						sa.sin_family = AF_INET;
						sa.sin_port = Internal::HostToNetwork16(port);
						sa.sin_addr.s_addr = Internal::HostToNetwork32(ipv4->ToUInt32());
						connectResult = ::connect(sock, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
					} else {
						auto* ipv6 = address.AsIPv6();
						sockaddr_in6 sa6{};
						sa6.sin6_family = AF_INET6;
						sa6.sin6_port = Internal::HostToNetwork16(port);
						std::memcpy(&sa6.sin6_addr, ipv6->bytes.data(), 16);
						connectResult = ::connect(sock, reinterpret_cast<sockaddr*>(&sa6), sizeof(sa6));
					}

					if (connectResult == 0 || ::WSAGetLastError() == WSAEWOULDBLOCK) {
						fd_set writeSet;
						FD_ZERO(&writeSet);
						FD_SET(sock, &writeSet);

						if (::select(0, nullptr, &writeSet, nullptr, &tv) > 0) {
							result.isOpen = true;
							
							auto endTime = std::chrono::steady_clock::now();
							result.responseTimeMs = static_cast<uint32_t>(
								std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count()
							);
						}
					}

					::closesocket(sock);
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

				} catch (...) {
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
				std::wostringstream oss;
				oss << std::hex << std::uppercase;

				for (wchar_t c : str) {
					if (std::isalnum(static_cast<unsigned char>(c)) || c == L'-' || c == L'_' || c == L'.' || c == L'~') {
						oss << static_cast<char>(c);
					} else if (c == L' ') {
						oss << L'+';
					} else {
						oss << L'%' << std::setw(2) << std::setfill(L'0') << static_cast<int>(static_cast<unsigned char>(c));
					}
				}

				return oss.str();
			}

			std::wstring UrlDecode(std::wstring_view str) noexcept {
				std::wostringstream oss;

				for (size_t i = 0; i < str.length(); ++i) {
					if (str[i] == L'%' && i + 2 < str.length()) {
						int value = 0;
						std::wistringstream(std::wstring(str.substr(i + 1, 2))) >> std::hex >> value;
						oss << static_cast<wchar_t>(value);
						i += 2;
					} else if (str[i] == L'+') {
						oss << L' ';
					} else {
						oss << str[i];
					}
				}

				return oss.str();
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

			// ============================================================================
			// MAC Address Utilities
			// ============================================================================

			bool ParseMacAddress(std::wstring_view str, MacAddress& mac, Error* err) noexcept {
				try {
					str = Internal::TrimWhitespace(str);
					std::array<uint8_t, 6> bytes{};
					int byteIndex = 0;
					size_t pos = 0;

					while (pos < str.length() && byteIndex < 6) {
						// Find separator (- or :)
						size_t sepPos = str.find_first_of(L"-:", pos);
						size_t byteLen = (sepPos == std::wstring_view::npos) ? (str.length() - pos) : (sepPos - pos);

						if (byteLen != 2) {
							Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid MAC address format");
							return false;
						}

						std::wstring byteStr(str.substr(pos, 2));
						bytes[byteIndex++] = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));

						if (sepPos == std::wstring_view::npos) break;
						pos = sepPos + 1;
					}

					if (byteIndex != 6) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"MAC address must have 6 bytes");
						return false;
					}

					mac = MacAddress(bytes);
					return true;

				} catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception parsing MAC address");
					return false;
				}
			}

			bool GetMacAddress(const IpAddress& ipAddress, MacAddress& mac, Error* err) noexcept {
				try {
					if (ipAddress.IsIPv4()) {
						// IPv4 - Use SendARP
						auto* ipv4 = ipAddress.AsIPv4();
						ULONG macAddr[2] = {};
						ULONG macAddrLen = 6;

						DWORD result = ::SendARP(Internal::HostToNetwork32(ipv4->ToUInt32()), 0, macAddr, &macAddrLen);
						if (result != NO_ERROR) {
							Internal::SetError(err, result, L"SendARP failed");
							return false;
						}

						if (macAddrLen != 6) {
							Internal::SetError(err, ERROR_INVALID_DATA, L"Invalid MAC address length");
							return false;
						}

						std::array<uint8_t, 6> bytes;
						std::memcpy(bytes.data(), macAddr, 6);
						mac = MacAddress(bytes);
						return true;
					}
					else if (ipAddress.IsIPv6()) {
						// IPv6 - Use GetIpNetTable2
						PMIB_IPNET_TABLE2 pTable = nullptr;

						DWORD result = ::GetIpNetTable2(AF_INET6, &pTable);
						if (result != NO_ERROR) {
							Internal::SetError(err, result, L"GetIpNetTable2 failed");
							return false;
						}

						// RAII wrapper for cleanup
						struct TableDeleter {
							void operator()(PMIB_IPNET_TABLE2 p) const {
								if (p) ::FreeMibTable(p);
							}
						};
						std::unique_ptr<MIB_IPNET_TABLE2, TableDeleter> tableGuard(pTable);

						// Get IPv6 bytes for comparison
						auto* ipv6 = ipAddress.AsIPv6();
						std::array<uint8_t, 16> targetBytes = ipv6->bytes;

						// Search for matching IPv6 address
						for (ULONG i = 0; i < pTable->NumEntries; ++i) {
							const auto& row = pTable->Table[i];

							// Compare IPv6 addresses
							if (std::memcmp(row.Address.Ipv6.sin6_addr.u.Byte, targetBytes.data(), 16) == 0) {
								// Check if physical address is valid
								if (row.PhysicalAddressLength != 6) {
									continue; // Skip non-Ethernet entries
								}

								// Check if entry is reachable
								if (row.State != NlnsReachable && row.State != NlnsStale && row.State != NlnsPermanent) {
									continue; // Skip unreachable entries
								}

								std::array<uint8_t, 6> bytes;
								std::memcpy(bytes.data(), row.PhysicalAddress, 6);
								mac = MacAddress(bytes);
								return true;
							}
						}

						Internal::SetError(err, ERROR_NOT_FOUND, L"MAC address not found in neighbor table");
						return false;
					}

					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid IP address type");
					return false;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in GetMacAddress");
					return false;
				}
			}

			//Helper to refresh neighbor cache by sending a ping
			bool RefreshNeighborCache(const IpAddress& ipAddress, Error* err) noexcept {
				try {
					if (ipAddress.IsIPv6()) {
						//We can fill the neighbor cache by sending an ICMPv6 echo request
						HANDLE hIcmpFile = ::Icmp6CreateFile();
						if (hIcmpFile == INVALID_HANDLE_VALUE) {
							Internal::SetError(err, ::GetLastError(), L"Failed to create ICMPv6 handle");
							return false;
						}

						struct IcmpDeleter {
							void operator()(HANDLE h) const {
								if (h != INVALID_HANDLE_VALUE) ::IcmpCloseHandle(h);
							}
						};
						std::unique_ptr<std::remove_pointer_t<HANDLE>, IcmpDeleter> icmpGuard(hIcmpFile);

						auto* ipv6 = ipAddress.AsIPv6();
						std::array<uint8_t, 16> targetBytes = ipv6->bytes;

						sockaddr_in6 sourceAddr{};
						sourceAddr.sin6_family = AF_INET6;

						sockaddr_in6 destAddr{};
						destAddr.sin6_family = AF_INET6;
						std::memcpy(&destAddr.sin6_addr, targetBytes.data(), 16);

						constexpr size_t REPLY_BUFFER_SIZE = sizeof(ICMPV6_ECHO_REPLY) + 32;
						uint8_t replyBuffer[REPLY_BUFFER_SIZE] = {};

						uint8_t sendData[32] = {};

						// Send ping to populate neighbor cache
						::Icmp6SendEcho2(hIcmpFile, nullptr, nullptr, nullptr,
							&sourceAddr, &destAddr,
							sendData, sizeof(sendData),
							nullptr, replyBuffer, REPLY_BUFFER_SIZE, 1000);

						// Give system time to update neighbor table
						::Sleep(100);
					}
					else if (ipAddress.IsIPv4()) {
						//for ipv4 sendarp already updates the neighbor cache
						auto* ipv4 = ipAddress.AsIPv4();
						ULONG macAddr[2] = {};
						ULONG macAddrLen = 6;
						::SendARP(Internal::HostToNetwork32(ipv4->ToUInt32()), 0, macAddr, &macAddrLen);
					}

					return true;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in RefreshNeighborCache");
					return false;
				}
			}

			bool GetLocalMacAddresses(std::vector<MacAddress>& addresses, Error* err) noexcept {
				std::vector<NetworkAdapterInfo> adapters;
				if (!GetNetworkAdapters(adapters, err)) {
					return false;
				}

				addresses.clear();
				for (const auto& adapter : adapters) {
					if (adapter.macAddress.IsValid()) {
						addresses.push_back(adapter.macAddress);
					}
				}

				return !addresses.empty();
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
			// Network Interface Control
			// ============================================================================

			//***************************************************************************
			//Maybe we can use in the future
			bool EnableNetworkAdapter(const std::wstring& adapterName, Error* err) noexcept {
				Internal::SetError(err, ERROR_NOT_SUPPORTED, L"Function requires elevated privileges");
				return false; // Requires admin rights and netsh or WMI
			}

			bool DisableNetworkAdapter(const std::wstring& adapterName, Error* err) noexcept {
				Internal::SetError(err, ERROR_NOT_SUPPORTED, L"Function requires elevated privileges");
				return false; // Requires admin rights and netsh or WMI
			}
			//***************************************************************************

			bool FlushDnsCache(Error* err) noexcept {
				// DnsFlushResolverCache may not be available on all Windows versions
				// Use ipconfig /flushdns via system command as fallback
				HMODULE hDnsapi = ::LoadLibraryW(L"dnsapi.dll");
				if (hDnsapi) {
					typedef BOOL(WINAPI* DnsFlushResolverCacheFunc)();
					auto pDnsFlushResolverCache = reinterpret_cast<DnsFlushResolverCacheFunc>(
						::GetProcAddress(hDnsapi, "DnsFlushResolverCache"));
					
					if (pDnsFlushResolverCache) {
						BOOL result = pDnsFlushResolverCache();
						::FreeLibrary(hDnsapi);
						if (result) {
							return true;
						}
					}
					::FreeLibrary(hDnsapi);
				}
				
				// Fallback: use system command
				int result = ::_wsystem(L"ipconfig /flushdns >nul 2>&1");
				if (result == 0) {
					return true;
				}

				Internal::SetError(err, ::GetLastError(), L"Failed to flush DNS cache");
				return false;
			}

			bool RenewDhcpLease(const std::wstring& adapterName, Error* err) noexcept {
				Internal::SetError(err, ERROR_NOT_SUPPORTED, L"Function requires elevated privileges");
				return false; // Requires admin rights
			}

			bool ReleaseDhcpLease(const std::wstring& adapterName, Error* err) noexcept {
				Internal::SetError(err, ERROR_NOT_SUPPORTED, L"Function requires elevated privileges");
				return false; // Requires admin rights
			}

			// ============================================================================
			// Routing Table
			// ============================================================================

			bool GetRoutingTable(std::vector<RouteEntry>& routes, Error* err) noexcept {
				try {
					routes.clear();

					// IPv4 Routing Table
					ULONG size = 0;
#pragma warning(suppress: 6387)
					::GetIpForwardTable(nullptr, &size, FALSE);

					std::vector<uint8_t> buffer(size);
					DWORD result = ::GetIpForwardTable(reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data()), &size, FALSE);

					if (result == NO_ERROR) {
						auto* pTable = reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data());

						for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
							const auto& row = pTable->table[i];

							RouteEntry entry;
							entry.destination = IpAddress(IPv4Address(Internal::NetworkToHost32(row.dwForwardDest)));
							entry.netmask = IpAddress(IPv4Address(Internal::NetworkToHost32(row.dwForwardMask)));
							entry.gateway = IpAddress(IPv4Address(Internal::NetworkToHost32(row.dwForwardNextHop)));
							entry.interfaceIndex = row.dwForwardIfIndex;
							entry.metric = row.dwForwardMetric1;

							routes.push_back(std::move(entry));
						}
					}

					// IPv6 Routing Table
					PMIB_IPFORWARD_TABLE2 pTable6 = nullptr;
					result = ::GetIpForwardTable2(AF_INET6, &pTable6);

					if (result != NO_ERROR) {
						// IPv4 routes varsa onlarý döndür, IPv6 hata veriyorsa sorun deðil
						return !routes.empty();
					}

					// RAII wrapper for cleanup
					struct TableDeleter {
						void operator()(PMIB_IPFORWARD_TABLE2 p) const {
							if (p) ::FreeMibTable(p);
						}
					};
					std::unique_ptr<MIB_IPFORWARD_TABLE2, TableDeleter> tableGuard(pTable6);

					for (ULONG i = 0; i < pTable6->NumEntries; ++i) {
						const auto& row = pTable6->Table[i];

						RouteEntry entry;

						// Destination IPv6 address
						std::array<uint8_t, 16> destBytes;
						std::memcpy(destBytes.data(), row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte, 16);
						entry.destination = IpAddress(IPv6Address(destBytes));

						// IPv6 uses prefix length instead of netmask
						// Convert prefix length to netmask representation
						uint8_t prefixLen = row.DestinationPrefix.PrefixLength;
						std::array<uint8_t, 16> maskBytes = {};
						for (uint8_t j = 0; j < prefixLen / 8; ++j) {
							maskBytes[j] = 0xFF;
						}
						if (prefixLen % 8) {
							maskBytes[prefixLen / 8] = static_cast<uint8_t>(0xFF << (8 - (prefixLen % 8)));
						}
						entry.netmask = IpAddress(IPv6Address(maskBytes));

						// Gateway (NextHop) IPv6 address
						std::array<uint8_t, 16> gwBytes;
						std::memcpy(gwBytes.data(), row.NextHop.Ipv6.sin6_addr.u.Byte, 16);
						entry.gateway = IpAddress(IPv6Address(gwBytes));

						entry.interfaceIndex = row.InterfaceIndex;
						entry.metric = row.Metric;

						routes.push_back(std::move(entry));
					}

					return true;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in GetRoutingTable");
					return false;
				}
			}

			//routing table for specific family
			bool GetRoutingTable(std::vector<RouteEntry>& routes, ADDRESS_FAMILY family, Error* err) noexcept {
				try {
					routes.clear();

					if (family == AF_INET) {
						// IPv4 only
						ULONG size = 0;
#pragma warning(suppress: 6387)
						::GetIpForwardTable(nullptr, &size, FALSE);

						std::vector<uint8_t> buffer(size);
						DWORD result = ::GetIpForwardTable(reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data()), &size, FALSE);

						if (result != NO_ERROR) {
							Internal::SetError(err, result, L"GetIpForwardTable failed");
							return false;
						}

						auto* pTable = reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data());

						for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
							const auto& row = pTable->table[i];

							RouteEntry entry;
							entry.destination = IpAddress(IPv4Address(Internal::NetworkToHost32(row.dwForwardDest)));
							entry.netmask = IpAddress(IPv4Address(Internal::NetworkToHost32(row.dwForwardMask)));
							entry.gateway = IpAddress(IPv4Address(Internal::NetworkToHost32(row.dwForwardNextHop)));
							entry.interfaceIndex = row.dwForwardIfIndex;
							entry.metric = row.dwForwardMetric1;

							routes.push_back(std::move(entry));
						}
					}
					else if (family == AF_INET6) {
						// IPv6 only
						PMIB_IPFORWARD_TABLE2 pTable6 = nullptr;
						DWORD result = ::GetIpForwardTable2(AF_INET6, &pTable6);

						if (result != NO_ERROR) {
							Internal::SetError(err, result, L"GetIpForwardTable2 failed");
							return false;
						}

						struct TableDeleter {
							void operator()(PMIB_IPFORWARD_TABLE2 p) const {
								if (p) ::FreeMibTable(p);
							}
						};
						std::unique_ptr<MIB_IPFORWARD_TABLE2, TableDeleter> tableGuard(pTable6);

						for (ULONG i = 0; i < pTable6->NumEntries; ++i) {
							const auto& row = pTable6->Table[i];

							RouteEntry entry;

							std::array<uint8_t, 16> destBytes;
							std::memcpy(destBytes.data(), row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte, 16);
							entry.destination = IpAddress(IPv6Address(destBytes));

							uint8_t prefixLen = row.DestinationPrefix.PrefixLength;
							std::array<uint8_t, 16> maskBytes = {};
							for (uint8_t j = 0; j < prefixLen / 8; ++j) {
								maskBytes[j] = 0xFF;
							}
							if (prefixLen % 8) {
								maskBytes[prefixLen / 8] = static_cast<uint8_t>(0xFF << (8 - (prefixLen % 8)));
							}
							entry.netmask = IpAddress(IPv6Address(maskBytes));

							std::array<uint8_t, 16> gwBytes;
							std::memcpy(gwBytes.data(), row.NextHop.Ipv6.sin6_addr.u.Byte, 16);
							entry.gateway = IpAddress(IPv6Address(gwBytes));

							entry.interfaceIndex = row.InterfaceIndex;
							entry.metric = row.Metric;

							routes.push_back(std::move(entry));
						}
					}
					else {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid address family");
						return false;
					}

					return true;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in GetRoutingTable");
					return false;
				}
			}

			bool AddRoute(const IpAddress& destination, uint8_t prefixLength, const IpAddress& gateway, Error* err) noexcept {
				try {
					// Check if both addresses are same IP version
					if (destination.IsIPv4() != gateway.IsIPv4()) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Destination and gateway must be same IP version");
						return false;
					}

					if (destination.IsIPv4()) {
						// IPv4 Route Addition
						MIB_IPFORWARDROW route = {};

						auto* destIpv4 = destination.AsIPv4();
						auto* gwIpv4 = gateway.AsIPv4();

						route.dwForwardDest = Internal::HostToNetwork32(destIpv4->ToUInt32());
						route.dwForwardNextHop = Internal::HostToNetwork32(gwIpv4->ToUInt32());

						// Convert prefix length to netmask
						if (prefixLength > 32) {
							Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid prefix length for IPv4");
							return false;
						}

						uint32_t mask = prefixLength == 0 ? 0 : (~0U << (32 - prefixLength));
						route.dwForwardMask = Internal::HostToNetwork32(mask);

						route.dwForwardPolicy = 0;
						route.dwForwardIfIndex = 0; // Let system choose interface
						route.dwForwardType = MIB_IPROUTE_TYPE_INDIRECT;
						route.dwForwardProto = MIB_IPPROTO_NETMGMT;
						route.dwForwardAge = 0;
						route.dwForwardNextHopAS = 0;
						route.dwForwardMetric1 = 1;
						route.dwForwardMetric2 = static_cast<DWORD>(-1);
						route.dwForwardMetric3 = static_cast<DWORD>(-1);
						route.dwForwardMetric4 = static_cast<DWORD>(-1);
						route.dwForwardMetric5 = static_cast<DWORD>(-1);

						DWORD result = ::CreateIpForwardEntry(&route);
						if (result != NO_ERROR) {
							Internal::SetError(err, result, L"CreateIpForwardEntry failed");
							return false;
						}

						return true;
					}
					else if (destination.IsIPv6()) {
						// IPv6 Route Addition
						MIB_IPFORWARD_ROW2 route = {};
						::InitializeIpForwardEntry(&route);

						auto* destIpv6 = destination.AsIPv6();
						auto* gwIpv6 = gateway.AsIPv6();

						// Destination prefix
						route.DestinationPrefix.Prefix.si_family = AF_INET6;
						const auto& destBytes = destIpv6->bytes;
						std::memcpy(route.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte, destBytes.data(), 16);
						route.DestinationPrefix.PrefixLength = prefixLength;

						if (prefixLength > 128) {
							Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid prefix length for IPv6");
							return false;
						}

						// Next hop (gateway)
						route.NextHop.si_family = AF_INET6;
						const auto& gwBytes = gwIpv6->bytes;
						std::memcpy(route.NextHop.Ipv6.sin6_addr.u.Byte, gwBytes.data(), 16);

						route.Protocol = MIB_IPPROTO_NETMGMT;
						route.Metric = 1;
						route.ValidLifetime = 0xFFFFFFFF; // Infinite
						route.PreferredLifetime = 0xFFFFFFFF; // Infinite

						DWORD result = ::CreateIpForwardEntry2(&route);
						if (result != NO_ERROR) {
							Internal::SetError(err, result, L"CreateIpForwardEntry2 failed");
							return false;
						}

						return true;
					}

					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid IP address type");
					return false;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in AddRoute");
					return false;
				}
			}

			bool DeleteRoute(const IpAddress& destination, uint8_t prefixLength, Error* err) noexcept {
				try {
					if (destination.IsIPv4()) {
						// IPv4 Route Deletion
						MIB_IPFORWARDROW route = {};

						auto* destIpv4 = destination.AsIPv4();
						route.dwForwardDest = Internal::HostToNetwork32(destIpv4->ToUInt32());

						// Convert prefix length to netmask
						if (prefixLength > 32) {
							Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid prefix length for IPv4");
							return false;
						}

						uint32_t mask = prefixLength == 0 ? 0 : (~0U << (32 - prefixLength));
						route.dwForwardMask = Internal::HostToNetwork32(mask);

						// Find matching route in table
						ULONG size = 0;
#pragma warning(suppress: 6387)
						::GetIpForwardTable(nullptr, &size, FALSE);

						std::vector<uint8_t> buffer(size);
						DWORD result = ::GetIpForwardTable(reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data()), &size, FALSE);

						if (result != NO_ERROR) {
							Internal::SetError(err, result, L"GetIpForwardTable failed");
							return false;
						}

						auto* pTable = reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data());
						bool found = false;

						for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
							const auto& row = pTable->table[i];

							if (row.dwForwardDest == route.dwForwardDest &&
								row.dwForwardMask == route.dwForwardMask) {

								result = ::DeleteIpForwardEntry(&pTable->table[i]);
								if (result != NO_ERROR) {
									Internal::SetError(err, result, L"DeleteIpForwardEntry failed");
									return false;
								}

								found = true;
								break;
							}
						}

						if (!found) {
							Internal::SetError(err, ERROR_NOT_FOUND, L"Route not found");
							return false;
						}

						return true;
					}
					else if (destination.IsIPv6()) {
						// IPv6 Route Deletion
						MIB_IPFORWARD_ROW2 route = {};
						::InitializeIpForwardEntry(&route);

						auto* destIpv6 = destination.AsIPv6();

						route.DestinationPrefix.Prefix.si_family = AF_INET6;
						const auto& destBytes = destIpv6->bytes;
						std::memcpy(route.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte, destBytes.data(), 16);
						route.DestinationPrefix.PrefixLength = prefixLength;

						if (prefixLength > 128) {
							Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid prefix length for IPv6");
							return false;
						}

						// Find and delete the route
						PMIB_IPFORWARD_TABLE2 pTable6 = nullptr;
						DWORD result = ::GetIpForwardTable2(AF_INET6, &pTable6);

						if (result != NO_ERROR) {
							Internal::SetError(err, result, L"GetIpForwardTable2 failed");
							return false;
						}

						struct TableDeleter {
							void operator()(PMIB_IPFORWARD_TABLE2 p) const {
								if (p) ::FreeMibTable(p);
							}
						};
						std::unique_ptr<MIB_IPFORWARD_TABLE2, TableDeleter> tableGuard(pTable6);

						bool found = false;

						for (ULONG i = 0; i < pTable6->NumEntries; ++i) {
							const auto& row = pTable6->Table[i];

							if (row.DestinationPrefix.PrefixLength == prefixLength &&
								std::memcmp(row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte,
									destBytes.data(), 16) == 0) {

								result = ::DeleteIpForwardEntry2(&pTable6->Table[i]);
								if (result != NO_ERROR) {
									Internal::SetError(err, result, L"DeleteIpForwardEntry2 failed");
									return false;
								}

								found = true;
								break;
							}
						}

						if (!found) {
							Internal::SetError(err, ERROR_NOT_FOUND, L"Route not found");
							return false;
						}

						return true;
					}

					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid IP address type");
					return false;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in DeleteRoute");
					return false;
				}
			}

			//Route modification
			bool ModifyRoute(const IpAddress& destination, uint8_t prefixLength,
				const IpAddress& newGateway, uint32_t newMetric, Error* err) noexcept {
				try {
					if (destination.IsIPv4() != newGateway.IsIPv4()) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"IP version mismatch");
						return false;
					}

					if (destination.IsIPv4()) {
						// IPv4 Route Modification
						ULONG size = 0;
#pragma warning(suppress: 6387)
						::GetIpForwardTable(nullptr, &size, FALSE);

						std::vector<uint8_t> buffer(size);
						DWORD result = ::GetIpForwardTable(reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data()), &size, FALSE);

						if (result != NO_ERROR) {
							Internal::SetError(err, result, L"GetIpForwardTable failed");
							return false;
						}

						auto* pTable = reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data());
						auto* destIpv4 = destination.AsIPv4();

						uint32_t destAddr = Internal::HostToNetwork32(destIpv4->ToUInt32());
						uint32_t mask = prefixLength == 0 ? 0 : (~0U << (32 - prefixLength));
						uint32_t netmask = Internal::HostToNetwork32(mask);

						for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
							auto& row = pTable->table[i];

							if (row.dwForwardDest == destAddr && row.dwForwardMask == netmask) {
								auto* gwIpv4 = newGateway.AsIPv4();
								row.dwForwardNextHop = Internal::HostToNetwork32(gwIpv4->ToUInt32());
								row.dwForwardMetric1 = newMetric;

								result = ::SetIpForwardEntry(&row);
								if (result != NO_ERROR) {
									Internal::SetError(err, result, L"SetIpForwardEntry failed");
									return false;
								}

								return true;
							}
						}

						Internal::SetError(err, ERROR_NOT_FOUND, L"Route not found");
						return false;
					}
					else if (destination.IsIPv6()) {
						// IPv6 Route Modification
						PMIB_IPFORWARD_TABLE2 pTable6 = nullptr;
						DWORD result = ::GetIpForwardTable2(AF_INET6, &pTable6);

						if (result != NO_ERROR) {
							Internal::SetError(err, result, L"GetIpForwardTable2 failed");
							return false;
						}

						struct TableDeleter {
							void operator()(PMIB_IPFORWARD_TABLE2 p) const {
								if (p) ::FreeMibTable(p);
							}
						};
						std::unique_ptr<MIB_IPFORWARD_TABLE2, TableDeleter> tableGuard(pTable6);

						auto* destIpv6 = destination.AsIPv6();
						const auto& destBytes = destIpv6->bytes;

						for (ULONG i = 0; i < pTable6->NumEntries; ++i) {
							auto& row = pTable6->Table[i];

							if (row.DestinationPrefix.PrefixLength == prefixLength &&
								std::memcmp(row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte,
									destBytes.data(), 16) == 0) {

								auto* gwIpv6 = newGateway.AsIPv6();
								const auto& gwBytes = gwIpv6->bytes;
								std::memcpy(row.NextHop.Ipv6.sin6_addr.u.Byte, gwBytes.data(), 16);
								row.Metric = newMetric;

								result = ::SetIpForwardEntry2(&row);
								if (result != NO_ERROR) {
									Internal::SetError(err, result, L"SetIpForwardEntry2 failed");
									return false;
								}

								return true;
							}
						}

						Internal::SetError(err, ERROR_NOT_FOUND, L"Route not found");
						return false;
					}

					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid IP address type");
					return false;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in ModifyRoute");
					return false;
				}
			}

			// ============================================================================
			// ARP Table
			// ============================================================================

			bool GetArpTable(std::vector<ArpEntry>& entries, Error* err) noexcept {
				try {
					entries.clear();

					// IPv4 ARP Table
					ULONG size = 0;
#pragma warning(suppress: 6387)
					::GetIpNetTable(nullptr, &size, FALSE);

					std::vector<uint8_t> buffer(size);
					DWORD result = ::GetIpNetTable(reinterpret_cast<PMIB_IPNETTABLE>(buffer.data()), &size, FALSE);

					if (result == NO_ERROR) {
						auto* pTable = reinterpret_cast<PMIB_IPNETTABLE>(buffer.data());

						for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
							const auto& row = pTable->table[i];

							ArpEntry entry;
							entry.ipAddress = IpAddress(IPv4Address(Internal::NetworkToHost32(row.dwAddr)));
							entry.interfaceIndex = row.dwIndex;
							entry.isStatic = (row.Type == MIB_IPNET_TYPE_STATIC);

							if (row.dwPhysAddrLen == 6) {
								std::array<uint8_t, 6> macBytes;
								std::memcpy(macBytes.data(), row.bPhysAddr, 6);
								entry.macAddress = MacAddress(macBytes);
							}

							entries.push_back(std::move(entry));
						}
					}

					// IPv6 NDP Table
					PMIB_IPNET_TABLE2 pTable6 = nullptr;
					result = ::GetIpNetTable2(AF_INET6, &pTable6);

					if (result != NO_ERROR) {
						// IPv4 entries varsa onlarý döndür, IPv6 yoksa sorun deðil
						return !entries.empty();
					}

					struct TableDeleter {
						void operator()(PMIB_IPNET_TABLE2 p) const {
							if (p) ::FreeMibTable(p);
						}
					};
					std::unique_ptr<MIB_IPNET_TABLE2, TableDeleter> tableGuard(pTable6);

					for (ULONG i = 0; i < pTable6->NumEntries; ++i) {
						const auto& row = pTable6->Table[i];

						ArpEntry entry;

						// IPv6 address
						std::array<uint8_t, 16> ipBytes;
						std::memcpy(ipBytes.data(), row.Address.Ipv6.sin6_addr.u.Byte, 16);
						entry.ipAddress = IpAddress(IPv6Address(ipBytes));

						entry.interfaceIndex = row.InterfaceIndex;
						entry.isStatic = (row.State == NlnsPermanent);

						// MAC address
						if (row.PhysicalAddressLength == 6) {
							std::array<uint8_t, 6> macBytes;
							std::memcpy(macBytes.data(), row.PhysicalAddress, 6);
							entry.macAddress = MacAddress(macBytes);
						}

						entries.push_back(std::move(entry));
					}

					return true;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in GetArpTable");
					return false;
				}
			}

			bool AddArpEntry(const IpAddress& ipAddress, const MacAddress& macAddress, Error* err) noexcept {
				try {
					const auto& macBytes = macAddress.bytes;

					if (macBytes.size() != 6) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid MAC address length");
						return false;
					}

					if (ipAddress.IsIPv4()) {
						// IPv4 ARP Entry
						MIB_IPNETROW row = {};

						auto* ipv4 = ipAddress.AsIPv4();
						row.dwAddr = Internal::HostToNetwork32(ipv4->ToUInt32());
						row.dwIndex = 0; // Will need to find appropriate interface
						row.dwPhysAddrLen = 6;
						std::memcpy(row.bPhysAddr, macBytes.data(), 6);
						row.Type = MIB_IPNET_TYPE_STATIC;

						// Find appropriate interface index
						ULONG tableSize = 0;
#pragma warning(suppress: 6387)
						::GetIpNetTable(nullptr, &tableSize, FALSE);

						std::vector<uint8_t> buffer(tableSize);
						if (::GetIpNetTable(reinterpret_cast<PMIB_IPNETTABLE>(buffer.data()), &tableSize, FALSE) == NO_ERROR) {
							auto* pTable = reinterpret_cast<PMIB_IPNETTABLE>(buffer.data());
							if (pTable->dwNumEntries > 0) {
								// Use first interface index as default
								row.dwIndex = pTable->table[0].dwIndex;
							}
						}

						if (row.dwIndex == 0) {
							Internal::SetError(err, ERROR_NOT_FOUND, L"No valid interface found");
							return false;
						}

						DWORD result = ::CreateIpNetEntry(&row);
						if (result != NO_ERROR) {
							Internal::SetError(err, result, L"CreateIpNetEntry failed");
							return false;
						}

						return true;
					}
					else if (ipAddress.IsIPv6()) {
						// IPv6 NDP Entry
						MIB_IPNET_ROW2 row = {};

						auto* ipv6 = ipAddress.AsIPv6();
						const auto& ipBytes = ipv6->bytes;

						row.Address.si_family = AF_INET6;
						std::memcpy(row.Address.Ipv6.sin6_addr.u.Byte, ipBytes.data(), 16);

						row.PhysicalAddressLength = 6;
						std::memcpy(row.PhysicalAddress, macBytes.data(), 6);

						row.State = NlnsPermanent;
						row.IsRouter = FALSE;
						row.IsUnreachable = FALSE;

						// Find appropriate interface
						PMIB_IPNET_TABLE2 pTable6 = nullptr;
						DWORD result = ::GetIpNetTable2(AF_INET6, &pTable6);

						if (result == NO_ERROR && pTable6 && pTable6->NumEntries > 0) {
							row.InterfaceIndex = pTable6->Table[0].InterfaceIndex;
							row.InterfaceLuid = pTable6->Table[0].InterfaceLuid;
							::FreeMibTable(pTable6);
						}
						else {
							if (pTable6) ::FreeMibTable(pTable6);
							Internal::SetError(err, ERROR_NOT_FOUND, L"No valid IPv6 interface found");
							return false;
						}

						result = ::CreateIpNetEntry2(&row);
						if (result != NO_ERROR) {
							Internal::SetError(err, result, L"CreateIpNetEntry2 failed");
							return false;
						}

						return true;
					}

					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid IP address type");
					return false;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in AddArpEntry");
					return false;
				}
			}

			bool DeleteArpEntry(const IpAddress& ipAddress, Error* err) noexcept {
				try {
					if (ipAddress.IsIPv4()) {
						// IPv4 ARP Entry Deletion
						ULONG size = 0;
#pragma warning(suppress: 6387)
						::GetIpNetTable(nullptr, &size, FALSE);

						std::vector<uint8_t> buffer(size);
						DWORD result = ::GetIpNetTable(reinterpret_cast<PMIB_IPNETTABLE>(buffer.data()), &size, FALSE);

						if (result != NO_ERROR) {
							Internal::SetError(err, result, L"GetIpNetTable failed");
							return false;
						}

						auto* pTable = reinterpret_cast<PMIB_IPNETTABLE>(buffer.data());
						auto* ipv4 = ipAddress.AsIPv4();
						uint32_t targetAddr = Internal::HostToNetwork32(ipv4->ToUInt32());

						bool found = false;

						for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
							if (pTable->table[i].dwAddr == targetAddr) {
								result = ::DeleteIpNetEntry(&pTable->table[i]);
								if (result != NO_ERROR) {
									Internal::SetError(err, result, L"DeleteIpNetEntry failed");
									return false;
								}
								found = true;
								break;
							}
						}

						if (!found) {
							Internal::SetError(err, ERROR_NOT_FOUND, L"ARP entry not found");
							return false;
						}

						return true;
					}
					else if (ipAddress.IsIPv6()) {
						// IPv6 NDP Entry Deletion
						PMIB_IPNET_TABLE2 pTable6 = nullptr;
						DWORD result = ::GetIpNetTable2(AF_INET6, &pTable6);

						if (result != NO_ERROR) {
							Internal::SetError(err, result, L"GetIpNetTable2 failed");
							return false;
						}

						struct TableDeleter {
							void operator()(PMIB_IPNET_TABLE2 p) const {
								if (p) ::FreeMibTable(p);
							}
						};
						std::unique_ptr<MIB_IPNET_TABLE2, TableDeleter> tableGuard(pTable6);

						auto* ipv6 = ipAddress.AsIPv6();
						const auto& targetBytes = ipv6->bytes;

						bool found = false;

						for (ULONG i = 0; i < pTable6->NumEntries; ++i) {
							if (std::memcmp(pTable6->Table[i].Address.Ipv6.sin6_addr.u.Byte,
								targetBytes.data(), 16) == 0) {

								result = ::DeleteIpNetEntry2(&pTable6->Table[i]);
								if (result != NO_ERROR) {
									Internal::SetError(err, result, L"DeleteIpNetEntry2 failed");
									return false;
								}
								found = true;
								break;
							}
						}

						if (!found) {
							Internal::SetError(err, ERROR_NOT_FOUND, L"NDP entry not found");
							return false;
						}

						return true;
					}

					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid IP address type");
					return false;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in DeleteArpEntry");
					return false;
				}
			}

			bool FlushArpCache(Error* err) noexcept {
				try {
					bool success = true;

					// Flush IPv4 ARP Cache
					ULONG size = 0;
#pragma warning(suppress: 6387)
					::GetIpNetTable(nullptr, &size, FALSE);

					std::vector<uint8_t> buffer(size);
					DWORD result = ::GetIpNetTable(reinterpret_cast<PMIB_IPNETTABLE>(buffer.data()), &size, FALSE);

					if (result == NO_ERROR) {
						auto* pTable = reinterpret_cast<PMIB_IPNETTABLE>(buffer.data());

						// Delete all dynamic entries (keep static ones)
						for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
							if (pTable->table[i].Type != MIB_IPNET_TYPE_STATIC) {
								result = ::DeleteIpNetEntry(&pTable->table[i]);
								if (result != NO_ERROR) {
									success = false;
								}
							}
						}
					}

					// Flush IPv6 NDP Cache
					PMIB_IPNET_TABLE2 pTable6 = nullptr;
					result = ::GetIpNetTable2(AF_INET6, &pTable6);

					if (result == NO_ERROR) {
						struct TableDeleter {
							void operator()(PMIB_IPNET_TABLE2 p) const {
								if (p) ::FreeMibTable(p);
							}
						};
						std::unique_ptr<MIB_IPNET_TABLE2, TableDeleter> tableGuard(pTable6);

						// Delete all non-permanent entries
						for (ULONG i = 0; i < pTable6->NumEntries; ++i) {
							if (pTable6->Table[i].State != NlnsPermanent) {
								result = ::DeleteIpNetEntry2(&pTable6->Table[i]);
								if (result != NO_ERROR) {
									success = false;
								}
							}
						}
					}

					if (!success) {
						Internal::SetError(err, ERROR_PARTIAL_COPY, L"Some entries could not be flushed");
						return false;
					}

					return true;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in FlushArpCache");
					return false;
				}
			}

			
			bool FlushArpCache(uint32_t interfaceIndex, Error* err) noexcept {
				try {
					bool success = true;

					// Flush IPv4 ARP Cache for specific interface
					ULONG size = 0;
#pragma warning(suppress: 6387)
					::GetIpNetTable(nullptr, &size, FALSE);

					std::vector<uint8_t> buffer(size);
					DWORD result = ::GetIpNetTable(reinterpret_cast<PMIB_IPNETTABLE>(buffer.data()), &size, FALSE);

					if (result == NO_ERROR) {
						auto* pTable = reinterpret_cast<PMIB_IPNETTABLE>(buffer.data());

						for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
							if (pTable->table[i].dwIndex == interfaceIndex &&
								pTable->table[i].Type != MIB_IPNET_TYPE_STATIC) {

								result = ::DeleteIpNetEntry(&pTable->table[i]);
								if (result != NO_ERROR) {
									success = false;
								}
							}
						}
					}

					// Flush IPv6 NDP Cache for specific interface
					PMIB_IPNET_TABLE2 pTable6 = nullptr;
					result = ::GetIpNetTable2(AF_INET6, &pTable6);

					if (result == NO_ERROR) {
						struct TableDeleter {
							void operator()(PMIB_IPNET_TABLE2 p) const {
								if (p) ::FreeMibTable(p);
							}
						};
						std::unique_ptr<MIB_IPNET_TABLE2, TableDeleter> tableGuard(pTable6);

						for (ULONG i = 0; i < pTable6->NumEntries; ++i) {
							if (pTable6->Table[i].InterfaceIndex == interfaceIndex &&
								pTable6->Table[i].State != NlnsPermanent) {

								result = ::DeleteIpNetEntry2(&pTable6->Table[i]);
								if (result != NO_ERROR) {
									success = false;
								}
							}
						}
					}

					if (!success) {
						Internal::SetError(err, ERROR_PARTIAL_COPY, L"Some entries could not be flushed");
						return false;
					}

					return true;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in FlushArpCache");
					return false;
				}
			}

			// ============================================================================
			// Network Security (SSL/TLS)
			// ============================================================================
			namespace {
				// Helper to convert FILETIME to system_clock::time_point
				inline std::chrono::system_clock::time_point FileTimeToTimePoint(const FILETIME& ft) noexcept {
					ULARGE_INTEGER uli;
					uli.LowPart = ft.dwLowDateTime;
					uli.HighPart = ft.dwHighDateTime;

					// FILETIME is 100-nanosecond intervals since January 1, 1601 UTC
					// Convert to system_clock epoch (January 1, 1970 UTC)
					constexpr uint64_t EPOCH_DIFFERENCE = 116444736000000000ULL;

					if (uli.QuadPart < EPOCH_DIFFERENCE) {
						return std::chrono::system_clock::time_point{};
					}

					uint64_t microseconds = (uli.QuadPart - EPOCH_DIFFERENCE) / 10;
					return std::chrono::system_clock::time_point{
						std::chrono::microseconds(microseconds)
					};
				}

				// Helper to extract Common Name from certificate subject
				inline std::wstring ExtractCommonName(const wchar_t* subject) noexcept {
					if (!subject) return L"";

					std::wstring str(subject);
					size_t cnPos = str.find(L"CN=");
					if (cnPos == std::wstring::npos) return L"";

					cnPos += 3; // Skip "CN="
					size_t endPos = str.find(L',', cnPos);

					if (endPos == std::wstring::npos) {
						return str.substr(cnPos);
					}

					return str.substr(cnPos, endPos - cnPos);
				}

				// Helper to check if hostname matches certificate CN or SAN
				inline bool MatchesHostname(std::wstring_view certName, std::wstring_view hostname) noexcept {
					// Exact match
					if (Internal::EqualsIgnoreCase(certName, hostname)) {
						return true;
					}

					// Wildcard match (e.g., *.example.com matches www.example.com)
					if (certName.size() >= 2 && certName[0] == L'*' && certName[1] == L'.') {
						std::wstring_view wildcardDomain = certName.substr(2);

						// Find first dot in hostname
						size_t dotPos = hostname.find(L'.');
						if (dotPos != std::wstring_view::npos && dotPos + 1 < hostname.size()) {
							std::wstring_view hostDomain = hostname.substr(dotPos + 1);
							return Internal::EqualsIgnoreCase(wildcardDomain, hostDomain);
						}
					}

					return false;
				}
			}

			bool GetSslCertificate(std::wstring_view hostname, uint16_t port, SslCertificateInfo& certInfo, Error* err) noexcept {
				try {
					certInfo = SslCertificateInfo{};

					// Open WinHTTP session
					HINTERNET hSession = ::WinHttpOpen(
						L"ShadowStrike-AntiVirus/1.0",
						WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
						WINHTTP_NO_PROXY_NAME,
						WINHTTP_NO_PROXY_BYPASS,
						0
					);

					if (!hSession) {
						Internal::SetError(err, ::GetLastError(), L"WinHttpOpen failed", L"GetSslCertificate");
						return false;
					}

					// RAII cleanup for session
					struct SessionDeleter {
						void operator()(HINTERNET h) const { if (h) ::WinHttpCloseHandle(h); }
					};
					std::unique_ptr<std::remove_pointer_t<HINTERNET>, SessionDeleter> sessionGuard(hSession);

					// Connect to server
					std::wstring hostStr(hostname);
					HINTERNET hConnect = ::WinHttpConnect(hSession, hostStr.c_str(), port, 0);

					if (!hConnect) {
						Internal::SetError(err, ::GetLastError(), L"WinHttpConnect failed", L"GetSslCertificate");
						return false;
					}

					std::unique_ptr<std::remove_pointer_t<HINTERNET>, SessionDeleter> connectGuard(hConnect);

					// Open HTTPS request
					HINTERNET hRequest = ::WinHttpOpenRequest(
						hConnect,
						L"HEAD",
						L"/",
						nullptr,
						WINHTTP_NO_REFERER,
						WINHTTP_DEFAULT_ACCEPT_TYPES,
						WINHTTP_FLAG_SECURE
					);

					if (!hRequest) {
						Internal::SetError(err, ::GetLastError(), L"WinHttpOpenRequest failed", L"GetSslCertificate");
						return false;
					}

					std::unique_ptr<std::remove_pointer_t<HINTERNET>, SessionDeleter> requestGuard(hRequest);

					// Configure security options
					DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
						SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
						SECURITY_FLAG_IGNORE_CERT_CN_INVALID;

					if (!::WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
						&securityFlags, sizeof(securityFlags))) {
						Internal::SetError(err, ::GetLastError(), L"Failed to set security flags", L"GetSslCertificate");
						return false;
					}

					// Set timeouts (5 seconds for each phase)
					::WinHttpSetTimeouts(hRequest, 5000, 5000, 5000, 5000);

					// Send request
					if (!::WinHttpSendRequest(hRequest,
						WINHTTP_NO_ADDITIONAL_HEADERS, 0,
						WINHTTP_NO_REQUEST_DATA, 0,
						0, 0)) {
						Internal::SetError(err, ::GetLastError(), L"WinHttpSendRequest failed", L"GetSslCertificate");
						return false;
					}

					// Receive response
					if (!::WinHttpReceiveResponse(hRequest, nullptr)) {
						Internal::SetError(err, ::GetLastError(), L"WinHttpReceiveResponse failed", L"GetSslCertificate");
						return false;
					}

					// Query certificate info
					PCCERT_CONTEXT pCertContext = nullptr;
					DWORD certSize = sizeof(pCertContext);

					if (!::WinHttpQueryOption(hRequest,
						WINHTTP_OPTION_SERVER_CERT_CONTEXT,
						&pCertContext,
						&certSize)) {
						Internal::SetError(err, ::GetLastError(), L"Failed to retrieve certificate", L"GetSslCertificate");
						return false;
					}

					if (!pCertContext) {
						Internal::SetError(err, ERROR_INVALID_DATA, L"Certificate context is null", L"GetSslCertificate");
						return false;
					}

					// RAII cleanup for certificate
					struct CertDeleter {
						void operator()(PCCERT_CONTEXT p) const { if (p) ::CertFreeCertificateContext(p); }
					};
					std::unique_ptr<const CERT_CONTEXT, CertDeleter> certGuard(pCertContext);

					// Extract subject
					DWORD subjectLen = ::CertGetNameStringW(
						pCertContext,
						CERT_NAME_SIMPLE_DISPLAY_TYPE,
						0,
						nullptr,
						nullptr,
						0
					);

					if (subjectLen > 1) {
						std::vector<wchar_t> subjectBuf(subjectLen);
						::CertGetNameStringW(
							pCertContext,
							CERT_NAME_SIMPLE_DISPLAY_TYPE,
							0,
							nullptr,
							subjectBuf.data(),
							subjectLen
						);
						certInfo.subject = subjectBuf.data();
					}

					// Extract issuer
					DWORD issuerLen = ::CertGetNameStringW(
						pCertContext,
						CERT_NAME_SIMPLE_DISPLAY_TYPE,
						CERT_NAME_ISSUER_FLAG,
						nullptr,
						nullptr,
						0
					);

					if (issuerLen > 1) {
						std::vector<wchar_t> issuerBuf(issuerLen);
						::CertGetNameStringW(
							pCertContext,
							CERT_NAME_SIMPLE_DISPLAY_TYPE,
							CERT_NAME_ISSUER_FLAG,
							nullptr,
							issuerBuf.data(),
							issuerLen
						);
						certInfo.issuer = issuerBuf.data();
					}

					// Extract serial number
					DWORD serialSize = pCertContext->pCertInfo->SerialNumber.cbData;
					if (serialSize > 0) {
						std::wostringstream oss;
						oss << std::hex << std::uppercase << std::setfill(L'0');

						// Serial number is stored in little-endian, display in big-endian
						for (DWORD i = serialSize; i > 0; --i) {
							oss << std::setw(2) << static_cast<int>(pCertContext->pCertInfo->SerialNumber.pbData[i - 1]);
							if (i > 1) oss << L':';
						}

						certInfo.serialNumber = oss.str();
					}

					// Extract validity dates
					certInfo.validFrom = FileTimeToTimePoint(pCertContext->pCertInfo->NotBefore);
					certInfo.validTo = FileTimeToTimePoint(pCertContext->pCertInfo->NotAfter);

					// Check if certificate is currently valid
					auto now = std::chrono::system_clock::now();
					certInfo.isValid = (now >= certInfo.validFrom && now <= certInfo.validTo);

					// Check if self-signed
					certInfo.isSelfSigned = Internal::EqualsIgnoreCase(certInfo.subject, certInfo.issuer);

					// Extract Subject Alternative Names (SAN)
					PCERT_EXTENSION pExtension = ::CertFindExtension(
						szOID_SUBJECT_ALT_NAME2,
						pCertContext->pCertInfo->cExtension,
						pCertContext->pCertInfo->rgExtension
					);

					if (pExtension) {
						DWORD sanSize = 0;
						if (::CryptDecodeObjectEx(
							X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
							X509_ALTERNATE_NAME,
							pExtension->Value.pbData,
							pExtension->Value.cbData,
							CRYPT_DECODE_ALLOC_FLAG,
							nullptr,
							nullptr,
							&sanSize)) {

							std::vector<uint8_t> sanBuf(sanSize);
							if (::CryptDecodeObjectEx(
								X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
								X509_ALTERNATE_NAME,
								pExtension->Value.pbData,
								pExtension->Value.cbData,
								CRYPT_DECODE_ALLOC_FLAG,
								nullptr,
								sanBuf.data(),
								&sanSize)) {

								auto* pAltNameInfo = reinterpret_cast<PCERT_ALT_NAME_INFO>(sanBuf.data());

								for (DWORD i = 0; i < pAltNameInfo->cAltEntry; ++i) {
									const auto& entry = pAltNameInfo->rgAltEntry[i];

									if (entry.dwAltNameChoice == CERT_ALT_NAME_DNS_NAME && entry.pwszDNSName) {
										certInfo.subjectAltNames.emplace_back(entry.pwszDNSName);
									}
									else if (entry.dwAltNameChoice == CERT_ALT_NAME_IP_ADDRESS) {
										// Handle IP address SANs if needed
										if (entry.IPAddress.cbData == 4) {
											// IPv4
											IPv4Address ipv4;
											std::memcpy(ipv4.octets.data(), entry.IPAddress.pbData, 4);
											certInfo.subjectAltNames.emplace_back(ipv4.ToString());
										}
										else if (entry.IPAddress.cbData == 16) {
											// IPv6
											std::array<uint8_t, 16> bytes;
											std::memcpy(bytes.data(), entry.IPAddress.pbData, 16);
											IPv6Address ipv6(bytes);
											certInfo.subjectAltNames.emplace_back(ipv6.ToStringCompressed());
										}
									}
								}
							}
						}
					}

					// Verify certificate chain (optional but recommended for enterprise AV)
					CERT_CHAIN_PARA chainPara = {};
					chainPara.cbSize = sizeof(chainPara);

					PCCERT_CHAIN_CONTEXT pChainContext = nullptr;

					if (::CertGetCertificateChain(
						nullptr,                    // Use default chain engine
						pCertContext,
						nullptr,                    // Use current time
						pCertContext->hCertStore,
						&chainPara,
						CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
						nullptr,
						&pChainContext)) {

						struct ChainDeleter {
							void operator()(PCCERT_CHAIN_CONTEXT p) const {
								if (p) ::CertFreeCertificateChain(p);
							}
						};
						std::unique_ptr<const CERT_CHAIN_CONTEXT, ChainDeleter> chainGuard(pChainContext);

						// Check chain status
						if (pChainContext->TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR) {
							// Certificate chain is valid
							certInfo.isValid = certInfo.isValid && true;
						}
						else {
							// Chain has errors - mark as potentially invalid
							if (pChainContext->TrustStatus.dwErrorStatus & CERT_TRUST_IS_NOT_TIME_VALID) {
								certInfo.isValid = false;
							}
							if (pChainContext->TrustStatus.dwErrorStatus & CERT_TRUST_IS_REVOKED) {
								certInfo.isValid = false;
							}
							if (pChainContext->TrustStatus.dwErrorStatus & CERT_TRUST_IS_NOT_SIGNATURE_VALID) {
								certInfo.isValid = false;
							}
							if (pChainContext->TrustStatus.dwErrorStatus & CERT_TRUST_IS_UNTRUSTED_ROOT) {
								// Self-signed or untrusted CA
								certInfo.isSelfSigned = true;
							}
						}
					}

					return true;

				}
				catch (const std::exception& ex) {
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER;
						err->message = L"Exception in GetSslCertificate: ";

						// Convert exception message to wstring
						std::string exMsg = ex.what();
						err->message += std::wstring(exMsg.begin(), exMsg.end());
					}
					return false;
				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Unknown exception in GetSslCertificate");
					return false;
				}
			}

			bool ValidateSslCertificate(const SslCertificateInfo& certInfo, std::wstring_view expectedHostname) noexcept {
				try {
					// 1. Check if certificate structure is valid
					if (!certInfo.isValid) {
						return false;
					}

					// 2. Reject self-signed certificates (enterprise policy)
					if (certInfo.isSelfSigned) {
						return false;
					}

					// 3. Check temporal validity
					auto now = std::chrono::system_clock::now();

					if (now < certInfo.validFrom) {
						// Certificate not yet valid
						return false;
					}

					if (now > certInfo.validTo) {
						// Certificate expired
						return false;
					}

					// 4. Validate hostname matching (RFC 6125)
					bool hostnameMatches = false;

					// 4a. Check Subject Alternative Names (SAN) first (modern standard)
					if (!certInfo.subjectAltNames.empty()) {
						for (const auto& san : certInfo.subjectAltNames) {
							if (MatchesHostname(san, expectedHostname)) {
								hostnameMatches = true;
								break;
							}
						}
					}

					// 4b. Fallback to Common Name (deprecated but still used)
					if (!hostnameMatches && !certInfo.subject.empty()) {
						std::wstring cn = ExtractCommonName(certInfo.subject.c_str());
						if (!cn.empty() && MatchesHostname(cn, expectedHostname)) {
							hostnameMatches = true;
						}
					}

					if (!hostnameMatches) {
						// Hostname doesn't match certificate
						return false;
					}

					// 5. Additional security checks

					// 5a. Check validity period length (suspicious if > 825 days as per CA/Browser Forum)
					auto validityPeriod = std::chrono::duration_cast<std::chrono::hours>(
						certInfo.validTo - certInfo.validFrom
					).count();

					constexpr int64_t MAX_VALIDITY_HOURS = 825 * 24; // 825 days
					if (validityPeriod > MAX_VALIDITY_HOURS) {
						// Suspiciously long validity period
						return false;
					}

					// 5b. Ensure issuer is not empty
					if (certInfo.issuer.empty()) {
						return false;
					}

					// 5c. Ensure serial number exists
					if (certInfo.serialNumber.empty()) {
						return false;
					}

					// All checks passed
					return true;

				}
				catch (...) {
					// Any exception during validation = failed validation
					return false;
				}
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

			bool IsFtpTraffic(const std::vector<uint8_t>& data) noexcept {
				if (data.size() < 3) return false;

				// FTP server responses start with 3-digit status codes
				// 220 = Service ready, 331 = User name okay, need password, etc.
				if (data.size() >= 4) {
					// Check for 3-digit code followed by space or dash
					if (std::isdigit(data[0]) && std::isdigit(data[1]) && std::isdigit(data[2])) {
						if (data[3] == ' ' || data[3] == '-') {
							// Common FTP response codes
							char code[4] = { static_cast<char>(data[0]), static_cast<char>(data[1]),
											static_cast<char>(data[2]), '\0' };
							int codeNum = std::atoi(code);
							// FTP codes are typically 1xx-5xx
							if (codeNum >= 100 && codeNum <= 599) {
								return true;
							}
						}
					}
				}

				// FTP client commands (always uppercase)
				static const char* ftpCommands[] = {
					"USER ", "PASS ", "ACCT ", "CWD ", "CDUP", "SMNT ", "QUIT",
					"REIN", "PORT ", "PASV", "TYPE ", "STRU ", "MODE ", "RETR ",
					"STOR ", "STOU ", "APPE ", "ALLO ", "REST ", "RNFR ", "RNTO ",
					"ABOR", "DELE ", "RMD ", "MKD ", "PWD", "LIST", "NLST",
					"SITE ", "SYST", "STAT", "HELP", "NOOP", "FEAT", "OPTS "
				};

				std::string dataStr;
				if (data.size() >= 4) {
					dataStr.assign(reinterpret_cast<const char*>(data.data()),
						std::min(size_t(8), data.size()));
					std::transform(dataStr.begin(), dataStr.end(), dataStr.begin(), ::toupper);

					for (const auto* cmd : ftpCommands) {
						if (dataStr.find(cmd) == 0) {
							return true;
						}
					}
				}

				// Check for FTP greeting (220 response with "FTP" in text)
				if (data.size() >= 20) {
					std::string greeting(reinterpret_cast<const char*>(data.data()),
						std::min(size_t(50), data.size()));
					if (greeting.find("220") == 0 && greeting.find("FTP") != std::string::npos) {
						return true;
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

			bool IsSmtpTraffic(const std::vector<uint8_t>& data) noexcept {
				if (data.size() < 4) return false;

				// SMTP server responses: 3-digit code followed by space or dash
				if (data.size() >= 4) {
					if (std::isdigit(data[0]) && std::isdigit(data[1]) && std::isdigit(data[2])) {
						if (data[3] == ' ' || data[3] == '-') {
							char code[4] = { static_cast<char>(data[0]), static_cast<char>(data[1]),
											static_cast<char>(data[2]), '\0' };
							int codeNum = std::atoi(code);

							// Common SMTP response codes
							static const int smtpCodes[] = {
								220, 221, 250, 251, 252, 354, 421, 450, 451, 452,
								500, 501, 502, 503, 504, 550, 551, 552, 553, 554
							};

							for (int validCode : smtpCodes) {
								if (codeNum == validCode) {
									return true;
								}
							}
						}
					}
				}

				// SMTP client commands
				static const char* smtpCommands[] = {
					"HELO ", "EHLO ", "MAIL FROM:", "RCPT TO:", "DATA", "RSET",
					"VRFY ", "EXPN ", "HELP", "NOOP", "QUIT", "AUTH ", "STARTTLS"
				};

				std::string dataStr;
				if (data.size() >= 4) {
					dataStr.assign(reinterpret_cast<const char*>(data.data()),
						std::min(size_t(12), data.size()));
					std::transform(dataStr.begin(), dataStr.end(), dataStr.begin(), ::toupper);

					for (const auto* cmd : smtpCommands) {
						if (dataStr.find(cmd) == 0) {
							return true;
						}
					}
				}

				// Check for SMTP greeting (220 with SMTP/ESMTP in message)
				if (data.size() >= 20) {
					std::string greeting(reinterpret_cast<const char*>(data.data()),
						std::min(size_t(40), data.size()));
					if (greeting.find("220") == 0) {
						if (greeting.find("SMTP") != std::string::npos ||
							greeting.find("ESMTP") != std::string::npos) {
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

					struct SessionDeleter {
						void operator()(HINTERNET h) const {
							if (h) ::WinHttpCloseHandle(h);
						}
					};
					std::unique_ptr<std::remove_pointer_t<HINTERNET>, SessionDeleter> sessionGuard(hSession);

					// Get autoproxy options
					WINHTTP_AUTOPROXY_OPTIONS autoProxyOptions = {};
					autoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
					autoProxyOptions.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
					autoProxyOptions.fAutoLogonIfChallenged = TRUE;

					// Check for PAC file
					WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ieProxyConfig{};
					if (::WinHttpGetIEProxyConfigForCurrentUser(&ieProxyConfig)) {
						if (ieProxyConfig.lpszAutoConfigUrl) {
							autoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
							autoProxyOptions.lpszAutoConfigUrl = ieProxyConfig.lpszAutoConfigUrl;
						}
					}

					WINHTTP_PROXY_INFO proxyInfo = {};

					std::wstring urlStr(url);
					BOOL result = ::WinHttpGetProxyForUrl(hSession, urlStr.c_str(), &autoProxyOptions, &proxyInfo);

					// Cleanup IE proxy config
					if (ieProxyConfig.lpszProxy) ::GlobalFree(ieProxyConfig.lpszProxy);
					if (ieProxyConfig.lpszProxyBypass) ::GlobalFree(ieProxyConfig.lpszProxyBypass);
					if (ieProxyConfig.lpszAutoConfigUrl) ::GlobalFree(ieProxyConfig.lpszAutoConfigUrl);

					if (!result) {
						// Fall back to system proxy settings
						return GetSystemProxySettings(proxy, err);
					}

					// Process proxy info
					if (proxyInfo.lpszProxy) {
						proxy.enabled = true;
						proxy.server = proxyInfo.lpszProxy;
						::GlobalFree(proxyInfo.lpszProxy);
					}

					if (proxyInfo.lpszProxyBypass) {
						proxy.bypass = proxyInfo.lpszProxyBypass;
						::GlobalFree(proxyInfo.lpszProxyBypass);
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

					struct SessionDeleter {
						void operator()(HINTERNET h) const {
							if (h) ::WinHttpCloseHandle(h);
						}
					};
					std::unique_ptr<std::remove_pointer_t<HINTERNET>, SessionDeleter> sessionGuard(hSession);

					// Try to connect to a known endpoint
					HINTERNET hConnect = ::WinHttpConnect(hSession, L"www.microsoft.com", INTERNET_DEFAULT_HTTPS_PORT, 0);

					if (!hConnect) {
						Internal::SetError(err, ::GetLastError(), L"Proxy connection test failed");
						return false;
					}

					::WinHttpCloseHandle(hConnect);
					return true;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in TestProxyConnection");
					return false;
				}
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
