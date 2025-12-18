
#include "NetworkUtils.hpp"



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
						}
						else {
							++currentZeroLen;
						}
					}
					else {
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
				}
				else if (version == IpVersion::IPv6) {
					if (auto* ipv6 = AsIPv6()) {
						return ipv6->ToStringCompressed();
					}
				}
				return L"<invalid>";
			}

			bool IpAddress::IsLoopback() const noexcept {
				if (version == IpVersion::IPv4) {
					if (auto* ipv4 = AsIPv4()) return ipv4->IsLoopback();
				}
				else if (version == IpVersion::IPv6) {
					if (auto* ipv6 = AsIPv6()) return ipv6->IsLoopback();
				}
				return false;
			}

			bool IpAddress::IsPrivate() const noexcept {
				if (version == IpVersion::IPv4) {
					if (auto* ipv4 = AsIPv4()) return ipv4->IsPrivate();
				}
				else if (version == IpVersion::IPv6) {
					if (auto* ipv6 = AsIPv6()) return ipv6->IsPrivate();
				}
				return false;
			}

			bool IpAddress::IsMulticast() const noexcept {
				if (version == IpVersion::IPv4) {
					if (auto* ipv4 = AsIPv4()) return ipv4->IsMulticast();
				}
				else if (version == IpVersion::IPv6) {
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
				}
				else if (version == IpVersion::IPv6) {
					auto* a = AsIPv6();
					auto* b = other.AsIPv6();
					return a && b && (*a == *b);
				}
				return false;
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

				}
				catch (...) {
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

				}
				catch (...) {
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

				}
				else if (address.version == IpVersion::IPv6) {
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

				}
				else if (address.version == IpVersion::IPv6) {
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
				}
				else if (version == IpVersion::IPv6) {
					if (prefixLength > 128) return 0;
					if (prefixLength < 64) return UINT64_MAX; // Too large
					return 1ULL << (128 - prefixLength);
				}
				return 0;
			}

		}// namespace NetworkUtils
	}// namespace Utils
}// namespace ShadowStrike