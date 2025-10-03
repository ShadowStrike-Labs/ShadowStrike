#include "NetworkUtils.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cctype>
#include <cstring>
#include <fstream>
#include <WinInet.h>
#include <dhcpcsdk.h>

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

					DNS_STATUS status = ::DnsQuery_W(
						hostStr.c_str(),
						static_cast<WORD>(type),
						DNS_QUERY_STANDARD,
						nullptr,
						&pDnsRecord,
						nullptr
					);

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
						ULONG size = 0;
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

						// IPv6 connections
						size = 0;
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
						ULONG size = 0;
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
					}

					return true;

				} catch (...) {
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

			bool GetNetworkStatistics(NetworkStatistics& stats, Error* err) noexcept {
				try {
					stats = NetworkStatistics{};
					stats.timestamp = std::chrono::system_clock::now();

					MIB_IFROW ifRow{};
					ifRow.dwIndex = 0; // 0 = all interfaces

					if (::GetIfEntry(&ifRow) == NO_ERROR) {
						stats.bytesSent = ifRow.dwOutOctets;
						stats.bytesReceived = ifRow.dwInOctets;
						stats.packetsSent = ifRow.dwOutUcastPkts + ifRow.dwOutNUcastPkts;
						stats.packetsReceived = ifRow.dwInUcastPkts + ifRow.dwInNUcastPkts;
						stats.errorsSent = ifRow.dwOutErrors;
						stats.errorsReceived = ifRow.dwInErrors;
						stats.droppedPackets = ifRow.dwInDiscards + ifRow.dwOutDiscards;
					}

					return true;

				} catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in GetNetworkStatistics");
					return false;
				}
			}

			bool GetNetworkStatistics(const std::wstring& adapterName, NetworkStatistics& stats, Error* err) noexcept {
				// For specific adapter, enumerate and find matching name
				std::vector<NetworkAdapterInfo> adapters;
				if (!GetNetworkAdapters(adapters, err)) {
					return false;
				}

				for (const auto& adapter : adapters) {
					if (adapter.friendlyName == adapterName) {
						return GetNetworkStatistics(stats, err);
					}
				}

				Internal::SetError(err, ERROR_NOT_FOUND, L"Adapter not found");
				return false;
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

			std::wstring PunycodeEncode(std::wstring_view domain) noexcept {
				// Simplified punycode encoding - full implementation would be complex
				if (!IsInternationalDomain(domain)) {
					return std::wstring(domain);
				}
				return L"xn--" + std::wstring(domain);
			}

			std::wstring PunycodeDecode(std::wstring_view punycode) noexcept {
				if (punycode.substr(0, 4) == L"xn--") {
					return std::wstring(punycode.substr(4));
				}
				return std::wstring(punycode);
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
						auto* ipv4 = ipAddress.AsIPv4();
						ULONG macAddr[2] = {};
						ULONG macAddrLen = 6;

						if (::SendARP(Internal::HostToNetwork32(ipv4->ToUInt32()), 0, macAddr, &macAddrLen) == NO_ERROR) {
							std::array<uint8_t, 6> bytes;
							std::memcpy(bytes.data(), macAddr, 6);
							mac = MacAddress(bytes);
							return true;
						}
					}

					Internal::SetError(err, ERROR_NOT_FOUND, L"MAC address not found");
					return false;

				} catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in GetMacAddress");
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

			bool EnableNetworkAdapter(const std::wstring& adapterName, Error* err) noexcept {
				Internal::SetError(err, ERROR_NOT_SUPPORTED, L"Function requires elevated privileges");
				return false; // Requires admin rights and netsh or WMI
			}

			bool DisableNetworkAdapter(const std::wstring& adapterName, Error* err) noexcept {
				Internal::SetError(err, ERROR_NOT_SUPPORTED, L"Function requires elevated privileges");
				return false; // Requires admin rights and netsh or WMI
			}

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

					ULONG size = 0;
					::GetIpForwardTable(nullptr, &size, FALSE);

					std::vector<uint8_t> buffer(size);
					if (::GetIpForwardTable(reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data()), &size, FALSE) == NO_ERROR) {
						auto* pTable = reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data());

						for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
							RouteEntry entry;
							entry.destination = IpAddress(IPv4Address(Internal::NetworkToHost32(pTable->table[i].dwForwardDest)));
							entry.netmask = IpAddress(IPv4Address(Internal::NetworkToHost32(pTable->table[i].dwForwardMask)));
							entry.gateway = IpAddress(IPv4Address(Internal::NetworkToHost32(pTable->table[i].dwForwardNextHop)));
							entry.interfaceIndex = pTable->table[i].dwForwardIfIndex;
							entry.metric = pTable->table[i].dwForwardMetric1;

							routes.push_back(std::move(entry));
						}
					}

					return true;

				} catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in GetRoutingTable");
					return false;
				}
			}

			bool AddRoute(const IpAddress& destination, uint8_t prefixLength, const IpAddress& gateway, Error* err) noexcept {
				Internal::SetError(err, ERROR_NOT_SUPPORTED, L"Function requires elevated privileges");
				return false; // Requires admin rights
			}

			bool DeleteRoute(const IpAddress& destination, uint8_t prefixLength, Error* err) noexcept {
				Internal::SetError(err, ERROR_NOT_SUPPORTED, L"Function requires elevated privileges");
				return false; // Requires admin rights
			}

			// ============================================================================
			// ARP Table
			// ============================================================================

			bool GetArpTable(std::vector<ArpEntry>& entries, Error* err) noexcept {
				try {
					entries.clear();

					ULONG size = 0;
					::GetIpNetTable(nullptr, &size, FALSE);

					std::vector<uint8_t> buffer(size);
					if (::GetIpNetTable(reinterpret_cast<PMIB_IPNETTABLE>(buffer.data()), &size, FALSE) == NO_ERROR) {
						auto* pTable = reinterpret_cast<PMIB_IPNETTABLE>(buffer.data());

						for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
							ArpEntry entry;
							entry.ipAddress = IpAddress(IPv4Address(Internal::NetworkToHost32(pTable->table[i].dwAddr)));
							entry.interfaceIndex = pTable->table[i].dwIndex;
							entry.isStatic = (pTable->table[i].Type == MIB_IPNET_TYPE_STATIC);

							if (pTable->table[i].dwPhysAddrLen == 6) {
								std::array<uint8_t, 6> macBytes;
								std::memcpy(macBytes.data(), pTable->table[i].bPhysAddr, 6);
								entry.macAddress = MacAddress(macBytes);
							}

							entries.push_back(std::move(entry));
						}
					}

					return true;

				} catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in GetArpTable");
					return false;
				}
			}

			bool AddArpEntry(const IpAddress& ipAddress, const MacAddress& macAddress, Error* err) noexcept {
				Internal::SetError(err, ERROR_NOT_SUPPORTED, L"Function requires elevated privileges");
				return false; // Requires admin rights
			}

			bool DeleteArpEntry(const IpAddress& ipAddress, Error* err) noexcept {
				Internal::SetError(err, ERROR_NOT_SUPPORTED, L"Function requires elevated privileges");
				return false; // Requires admin rights
			}

			bool FlushArpCache(Error* err) noexcept {
				Internal::SetError(err, ERROR_NOT_SUPPORTED, L"Function requires elevated privileges");
				return false; // Requires admin rights
			}

			// ============================================================================
			// Network Security (SSL/TLS)
			// ============================================================================

			bool GetSslCertificate(std::wstring_view hostname, uint16_t port, SslCertificateInfo& certInfo, Error* err) noexcept {
				Internal::SetError(err, ERROR_NOT_SUPPORTED, L"SSL certificate retrieval not fully implemented");
				return false; // Would require OpenSSL or WinHTTP certificate APIs
			}

			bool ValidateSslCertificate(const SslCertificateInfo& certInfo, std::wstring_view expectedHostname) noexcept {
				if (!certInfo.isValid) return false;
				if (certInfo.isSelfSigned) return false;

				auto now = std::chrono::system_clock::now();
				if (now < certInfo.validFrom || now > certInfo.validTo) {
					return false;
				}

				// Check if hostname matches
				if (certInfo.subject.find(expectedHostname) != std::wstring::npos) {
					return true;
				}

				for (const auto& altName : certInfo.subjectAltNames) {
					if (altName == expectedHostname) {
						return true;
					}
				}

				return false;
			}

			// ============================================================================
			// Network Protocol Detection
			// ============================================================================

			bool DetectProtocol(const std::vector<uint8_t>& data, std::wstring& protocol) noexcept {
				if (IsHttpTraffic(data)) {
					protocol = L"HTTP";
					return true;
				}
				if (IsHttpsTraffic(data)) {
					protocol = L"HTTPS/TLS";
					return true;
				}
				if (IsDnsTraffic(data)) {
					protocol = L"DNS";
					return true;
				}

				protocol = L"Unknown";
				return false;
			}

			bool IsHttpTraffic(const std::vector<uint8_t>& data) noexcept {
				if (data.size() < 4) return false;
				
				std::string prefix(data.begin(), data.begin() + std::min(size_t(16), data.size()));
				return prefix.find("GET ") == 0 || prefix.find("POST ") == 0 || 
					   prefix.find("PUT ") == 0 || prefix.find("HTTP/") == 0;
			}

			bool IsHttpsTraffic(const std::vector<uint8_t>& data) noexcept {
				if (data.size() < 3) return false;
				
				// TLS handshake starts with 0x16, 0x03, 0x0X
				return data[0] == 0x16 && data[1] == 0x03 && (data[2] >= 0x00 && data[2] <= 0x03);
			}

			bool IsDnsTraffic(const std::vector<uint8_t>& data) noexcept {
				if (data.size() < 12) return false;
				
				// DNS header is 12 bytes, check flags
				return true; // Simplified check
			}

			// ============================================================================
			// Proxy Detection and Configuration
			// ============================================================================

			bool GetSystemProxySettings(ProxyInfo& proxy, Error* err) noexcept {
				try {
					proxy = ProxyInfo{};

					WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyConfig{};
					if (::WinHttpGetIEProxyConfigForCurrentUser(&proxyConfig)) {
						proxy.enabled = (proxyConfig.lpszProxy != nullptr);
						if (proxyConfig.lpszProxy) {
							proxy.server = proxyConfig.lpszProxy;
							::GlobalFree(proxyConfig.lpszProxy);
						}
						if (proxyConfig.lpszProxyBypass) {
							proxy.bypass = proxyConfig.lpszProxyBypass;
							::GlobalFree(proxyConfig.lpszProxyBypass);
						}
						if (proxyConfig.lpszAutoConfigUrl) {
							proxy.autoConfigUrl = proxyConfig.lpszAutoConfigUrl;
							::GlobalFree(proxyConfig.lpszAutoConfigUrl);
						}
						proxy.autoDetect = proxyConfig.fAutoDetect;

						return true;
					}

					Internal::SetError(err, ::GetLastError(), L"WinHttpGetIEProxyConfigForCurrentUser failed");
					return false;

				} catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in GetSystemProxySettings");
					return false;
				}
			}

			bool SetSystemProxySettings(const ProxyInfo& proxy, Error* err) noexcept {
				Internal::SetError(err, ERROR_NOT_SUPPORTED, L"Function requires elevated privileges and registry modification");
				return false; // Requires modifying IE/Windows proxy settings in registry
			}

			bool DetectProxyForUrl(std::wstring_view url, ProxyInfo& proxy, Error* err) noexcept {
				return GetSystemProxySettings(proxy, err);
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
