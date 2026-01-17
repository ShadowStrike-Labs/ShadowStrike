
// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

/*
 * ============================================================================
 * ShadowStrike Network Utilities - IP Address Operations
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * Enterprise-grade IP address parsing, validation, and manipulation.
 * Supports IPv4, IPv6, CIDR notation, and network calculations.
 *
 * SECURITY NOTES:
 * - All parsing functions reject malformed input strictly
 * - Leading zeros in IPv4 octets are rejected (prevents octal confusion)
 * - Integer overflow protection in all arithmetic operations
 * - WSAStartup must be called before using IPv6 parsing functions
 *
 * ============================================================================
 */

#include "pch.h"
#include "NetworkUtils.hpp"

#include <limits>
#include <algorithm>
#include <sstream>
#include <iomanip>

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

				// Thread-safe error setting with null-safety
				inline void SetError(Error* err, DWORD win32, std::wstring_view msg, std::wstring_view ctx = L"") noexcept {
					if (err) {
						err->win32 = win32;
						err->wsaError = 0;
						// Use try-catch for string assignment which could theoretically throw
						try {
							err->message = msg;
							err->context = ctx;
						}
						catch (...) {
							// If string assignment fails, leave message empty
							err->message.clear();
							err->context.clear();
						}
					}
				}

				inline void SetWsaError(Error* err, int wsaErr, std::wstring_view ctx = L"") noexcept {
					if (err) {
						err->wsaError = wsaErr;
						err->win32 = static_cast<DWORD>(wsaErr);
						try {
							err->message = FormatWsaError(wsaErr);
							err->context = ctx;
						}
						catch (...) {
							err->message.clear();
							err->context.clear();
						}
					}
				}

				// Character classification (constexpr for compile-time optimization)
				[[nodiscard]] constexpr bool IsWhitespace(wchar_t c) noexcept {
					return c == L' ' || c == L'\t' || c == L'\r' || c == L'\n';
				}

				[[nodiscard]] constexpr bool IsDigit(wchar_t c) noexcept {
					return c >= L'0' && c <= L'9';
				}

				[[nodiscard]] constexpr bool IsHexDigit(wchar_t c) noexcept {
					return IsDigit(c) || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F');
				}

				// Safe string trimming (noexcept, no allocation)
				[[nodiscard]] inline std::wstring_view TrimWhitespace(std::wstring_view str) noexcept {
					if (str.empty()) return str;
					
					size_t start = 0;
					while (start < str.size() && IsWhitespace(str[start])) ++start;
					
					if (start == str.size()) return std::wstring_view{}; // All whitespace
					
					size_t end = str.size();
					while (end > start && IsWhitespace(str[end - 1])) --end;
					
					return str.substr(start, end - start);
				}

				[[nodiscard]] inline bool EqualsIgnoreCase(std::wstring_view a, std::wstring_view b) noexcept {
					if (a.size() != b.size()) return false;
					return std::equal(a.begin(), a.end(), b.begin(), b.end(),
						[](wchar_t ca, wchar_t cb) noexcept {
							return ::towlower(static_cast<wint_t>(ca)) == ::towlower(static_cast<wint_t>(cb));
						});
				}

				// Network byte order conversions (thin wrappers for clarity)
				// Note: Cannot be constexpr as ntohs/ntohl/htons/htonl are not constexpr
				[[nodiscard]] inline uint16_t NetworkToHost16(uint16_t net) noexcept {
					return ntohs(net);
				}

				[[nodiscard]] inline uint32_t NetworkToHost32(uint32_t net) noexcept {
					return ntohl(net);
				}

				[[nodiscard]] inline uint16_t HostToNetwork16(uint16_t host) noexcept {
					return htons(host);
				}

				[[nodiscard]] inline uint32_t HostToNetwork32(uint32_t host) noexcept {
					return htonl(host);
				}

				// ================================================================
				// Safe Arithmetic Helpers (overflow protection)
				// ================================================================

				// Safe multiplication with overflow check for octet parsing
				// Returns false if overflow would occur
				[[nodiscard]] constexpr bool SafeMultiplyAdd(int& result, int multiplier, int addend) noexcept {
					// Check if multiplication would overflow
					if (result > (std::numeric_limits<int>::max() - addend) / multiplier) {
						return false;
					}
					result = result * multiplier + addend;
					return true;
				}

				// Generate IPv4 netmask from prefix length (0-32)
				// Avoids undefined behavior from shifting by 32 bits
				[[nodiscard]] constexpr uint32_t IPv4MaskFromPrefix(uint8_t prefixLength) noexcept {
					if (prefixLength == 0) return 0;
					if (prefixLength >= 32) return 0xFFFFFFFF;
					// Shift is now guaranteed to be 1-31, which is safe for uint32_t
					return ~(0xFFFFFFFFU >> prefixLength);
				}

				// Generate byte mask for IPv6 prefix calculations (bits within a single byte)
				// bitsInByte: number of significant bits in this byte (0-8)
				[[nodiscard]] constexpr uint8_t IPv6ByteMask(uint8_t bitsInByte) noexcept {
					if (bitsInByte == 0) return 0x00;
					if (bitsInByte >= 8) return 0xFF;
					// bitsInByte is 1-7, shift by (8 - bitsInByte) is 1-7, safe for uint8_t
					return static_cast<uint8_t>(0xFF << (8 - bitsInByte));
				}

			} // namespace Internal

			// ============================================================================
			// IPv4Address Implementation
			// ============================================================================

			std::wstring IPv4Address::ToString() const {
				// IPv4 max: "255.255.255.255" = 15 chars + null terminator
				wchar_t buffer[16];
				const int result = swprintf_s(buffer, _countof(buffer), 
					L"%u.%u.%u.%u", 
					static_cast<unsigned>(octets[0]), 
					static_cast<unsigned>(octets[1]), 
					static_cast<unsigned>(octets[2]), 
					static_cast<unsigned>(octets[3]));
				
				// swprintf_s returns -1 on error, which should never happen with valid octets
				if (result < 0) {
					return L"0.0.0.0"; // Defensive fallback
				}
				return buffer;
			}

			bool IPv4Address::IsLoopback() const noexcept {
				// 127.0.0.0/8 - entire 127.x.x.x range is loopback (RFC 1122)
				return octets[0] == 127;
			}

			bool IPv4Address::IsPrivate() const noexcept {
				// RFC 1918 private address ranges:
				// 10.0.0.0/8 (Class A)
				if (octets[0] == 10) return true;
				// 172.16.0.0/12 (Class B)
				if (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) return true;
				// 192.168.0.0/16 (Class C)
				if (octets[0] == 192 && octets[1] == 168) return true;
				return false;
			}

			bool IPv4Address::IsMulticast() const noexcept {
				// 224.0.0.0/4 - Class D (RFC 5771)
				return octets[0] >= 224 && octets[0] <= 239;
			}

			bool IPv4Address::IsBroadcast() const noexcept {
				// Limited broadcast address (RFC 919)
				return octets[0] == 255 && octets[1] == 255 && 
				       octets[2] == 255 && octets[3] == 255;
			}

			bool IPv4Address::IsLinkLocal() const noexcept {
				// 169.254.0.0/16 - APIPA (RFC 3927)
				return octets[0] == 169 && octets[1] == 254;
			}

			// ============================================================================
			// IPv6Address Implementation
			// ============================================================================

			std::wstring IPv6Address::ToString() const {
				// Full IPv6 format: "xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx"
				// Each group: 4 hex chars, 7 colons, null = 32 + 7 + 1 = 40
				wchar_t buffer[40];
				const int result = swprintf_s(buffer, _countof(buffer),
					L"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
					static_cast<unsigned>(bytes[0]), static_cast<unsigned>(bytes[1]),
					static_cast<unsigned>(bytes[2]), static_cast<unsigned>(bytes[3]),
					static_cast<unsigned>(bytes[4]), static_cast<unsigned>(bytes[5]),
					static_cast<unsigned>(bytes[6]), static_cast<unsigned>(bytes[7]),
					static_cast<unsigned>(bytes[8]), static_cast<unsigned>(bytes[9]),
					static_cast<unsigned>(bytes[10]), static_cast<unsigned>(bytes[11]),
					static_cast<unsigned>(bytes[12]), static_cast<unsigned>(bytes[13]),
					static_cast<unsigned>(bytes[14]), static_cast<unsigned>(bytes[15]));
				
				if (result < 0) {
					return L"::"; // Defensive fallback (unspecified address)
				}
				return buffer;
			}

			std::wstring IPv6Address::ToStringCompressed() const {
				// Find the longest sequence of consecutive zero 16-bit words for :: compression
				// RFC 5952 specifies the rules for compressed notation
				
				int maxZeroStart = -1;
				int maxZeroLen = 0;
				int currentZeroStart = -1;
				int currentZeroLen = 0;

				// First pass: identify longest run of zero words
				for (int i = 0; i < 8; ++i) {
					const uint16_t word = (static_cast<uint16_t>(bytes[i * 2]) << 8) | 
					                       static_cast<uint16_t>(bytes[i * 2 + 1]);
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
				// Check if the run extends to the end
				if (currentZeroLen > maxZeroLen) {
					maxZeroStart = currentZeroStart;
					maxZeroLen = currentZeroLen;
				}

				// RFC 5952: :: MUST NOT be used for a single 16-bit 0 field
				if (maxZeroLen <= 1) {
					maxZeroStart = -1; // Don't compress single zeros
					maxZeroLen = 0;
				}

				// Build compressed string
				try {
					std::wostringstream oss;
					oss << std::hex;
					
					bool inCompression = false;
					bool needsColon = false;

					for (int i = 0; i < 8; ++i) {
						// Check if we're in the zero compression zone
						if (maxZeroLen > 0 && i >= maxZeroStart && i < maxZeroStart + maxZeroLen) {
							if (!inCompression) {
								// Start of compression - emit ::
								oss << L"::";
								inCompression = true;
							}
							// Skip this word entirely
							continue;
						}

						// Regular word output
						if (needsColon && !inCompression) {
							oss << L':';
						}
						
						const uint16_t word = (static_cast<uint16_t>(bytes[i * 2]) << 8) | 
						                       static_cast<uint16_t>(bytes[i * 2 + 1]);
						oss << word;
						
						needsColon = true;
						inCompression = false; // Reset after we've passed the compressed section
					}

					// Handle edge case: all zeros (::)
					// Already handled above, but ensure we have valid output
					std::wstring result = oss.str();
					if (result.empty()) {
						return L"::";
					}
					
					return result;
				}
				catch (const std::exception&) {
					// Fallback to uncompressed format on allocation failure
					return ToString();
				}
			}

			bool IPv6Address::IsLoopback() const noexcept {
				// ::1 (RFC 4291)
				for (size_t i = 0; i < 15; ++i) {
					if (bytes[i] != 0) return false;
				}
				return bytes[15] == 1;
			}

			bool IPv6Address::IsPrivate() const noexcept {
				return IsUniqueLocal();
			}

			bool IPv6Address::IsMulticast() const noexcept {
				// ff00::/8 (RFC 4291)
				return bytes[0] == 0xFF;
			}

			bool IPv6Address::IsLinkLocal() const noexcept {
				// fe80::/10 (RFC 4291)
				return bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80;
			}

			bool IPv6Address::IsSiteLocal() const noexcept {
				// fec0::/10 (deprecated by RFC 3879, but still check for compatibility)
				return bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0xC0;
			}

			bool IPv6Address::IsUniqueLocal() const noexcept {
				// fc00::/7 (RFC 4193)
				return (bytes[0] & 0xFE) == 0xFC;
			}

			// ============================================================================
			// IpAddress Implementation (Unified IPv4/IPv6 wrapper)
			// ============================================================================

			std::wstring IpAddress::ToString() const {
				if (version == IpVersion::IPv4) {
					if (const auto* ipv4 = AsIPv4()) {
						return ipv4->ToString();
					}
				}
				else if (version == IpVersion::IPv6) {
					if (const auto* ipv6 = AsIPv6()) {
						return ipv6->ToStringCompressed();
					}
				}
				return L"<invalid>";
			}

			bool IpAddress::IsLoopback() const noexcept {
				if (version == IpVersion::IPv4) {
					if (const auto* ipv4 = AsIPv4()) return ipv4->IsLoopback();
				}
				else if (version == IpVersion::IPv6) {
					if (const auto* ipv6 = AsIPv6()) return ipv6->IsLoopback();
				}
				return false;
			}

			bool IpAddress::IsPrivate() const noexcept {
				if (version == IpVersion::IPv4) {
					if (const auto* ipv4 = AsIPv4()) return ipv4->IsPrivate();
				}
				else if (version == IpVersion::IPv6) {
					if (const auto* ipv6 = AsIPv6()) return ipv6->IsPrivate();
				}
				return false;
			}

			bool IpAddress::IsMulticast() const noexcept {
				if (version == IpVersion::IPv4) {
					if (const auto* ipv4 = AsIPv4()) return ipv4->IsMulticast();
				}
				else if (version == IpVersion::IPv6) {
					if (const auto* ipv6 = AsIPv6()) return ipv6->IsMulticast();
				}
				return false;
			}

			bool IpAddress::operator==(const IpAddress& other) const noexcept {
				if (version != other.version) return false;
				if (version == IpVersion::IPv4) {
					const auto* a = AsIPv4();
					const auto* b = other.AsIPv4();
					return a && b && (*a == *b);
				}
				else if (version == IpVersion::IPv6) {
					const auto* a = AsIPv6();
					const auto* b = other.AsIPv6();
					return a && b && (*a == *b);
				}
				return false;
			}

			// ============================================================================
			// IP Address Parsing - Enterprise-Grade with Security Hardening
			// ============================================================================

			bool ParseIPv4(std::wstring_view str, IPv4Address& out, Error* err) noexcept {
				// Input sanitization
				str = Internal::TrimWhitespace(str);
				if (str.empty()) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Empty IPv4 string", L"ParseIPv4");
					return false;
				}

				// Limit input length to prevent DoS (max valid: "255.255.255.255" = 15 chars)
				constexpr size_t MAX_IPV4_LENGTH = 15;
				if (str.size() > MAX_IPV4_LENGTH) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"IPv4 string too long", L"ParseIPv4");
					return false;
				}

				std::array<uint8_t, 4> octets{};
				size_t octetIndex = 0;
				size_t pos = 0;

				while (pos < str.size() && octetIndex < 4) {
					// Find the next dot or end of string
					size_t dotPos = str.find(L'.', pos);
					const size_t octetEnd = (dotPos == std::wstring_view::npos) ? str.size() : dotPos;
					std::wstring_view octetStr = str.substr(pos, octetEnd - pos);

					// Validate octet string
					if (octetStr.empty()) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, 
							L"Empty octet in IPv4 address", L"ParseIPv4");
						return false;
					}

					// SECURITY: Reject leading zeros to prevent octal interpretation attacks
					// Valid: "0", "1", "12", "123", "255"
					// Invalid: "00", "01", "007", "0123"
					if (octetStr.size() > 1 && octetStr[0] == L'0') {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, 
							L"Leading zeros not allowed in IPv4 octets (security: prevents octal confusion)", 
							L"ParseIPv4");
						return false;
					}

					// Limit octet string length (max valid: "255" = 3 digits)
					if (octetStr.size() > 3) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, 
							L"IPv4 octet too long", L"ParseIPv4");
						return false;
					}

					// Parse octet value with overflow protection
					int value = 0;
					for (const wchar_t c : octetStr) {
						if (!Internal::IsDigit(c)) {
							Internal::SetError(err, ERROR_INVALID_PARAMETER, 
								L"Invalid character in IPv4 address (expected digit)", L"ParseIPv4");
							return false;
						}

						// SECURITY: Safe multiplication with overflow check
						// Since octetStr.size() <= 3 and digits are 0-9, max intermediate = 259
						// which fits in int, but we check anyway for defense in depth
						const int digit = c - L'0';
						if (!Internal::SafeMultiplyAdd(value, 10, digit)) {
							Internal::SetError(err, ERROR_INVALID_PARAMETER, 
								L"IPv4 octet value overflow", L"ParseIPv4");
							return false;
						}

						// Early exit if value exceeds byte range
						if (value > 255) {
							Internal::SetError(err, ERROR_INVALID_PARAMETER, 
								L"IPv4 octet exceeds 255", L"ParseIPv4");
							return false;
						}
					}

					octets[octetIndex++] = static_cast<uint8_t>(value);

					// Move past the dot
					if (dotPos == std::wstring_view::npos) {
						pos = str.size(); // End of string
					}
					else {
						pos = dotPos + 1;
						
						// Check for trailing dot
						if (pos == str.size()) {
							Internal::SetError(err, ERROR_INVALID_PARAMETER, 
								L"IPv4 address ends with dot", L"ParseIPv4");
							return false;
						}
					}
				}

				// Validate we have exactly 4 octets
				if (octetIndex != 4) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, 
						L"IPv4 must have exactly 4 octets", L"ParseIPv4");
					return false;
				}

				// SECURITY: Ensure no trailing content after the 4th octet
				if (pos < str.size()) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, 
						L"Unexpected content after IPv4 address", L"ParseIPv4");
					return false;
				}

				out = IPv4Address(octets);
				return true;
			}

			bool ParseIPv6(std::wstring_view str, IPv6Address& out, Error* err) noexcept {
				// Input sanitization
				str = Internal::TrimWhitespace(str);
				if (str.empty()) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Empty IPv6 string", L"ParseIPv6");
					return false;
				}

				// Limit input length to prevent DoS
				// Max valid: full form with scope ID could be quite long
				// "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%interfacename" 
				constexpr size_t MAX_IPV6_LENGTH = 64;
				if (str.size() > MAX_IPV6_LENGTH) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"IPv6 string too long", L"ParseIPv6");
					return false;
				}

				std::array<uint8_t, 16> bytes{};
				std::fill(bytes.begin(), bytes.end(), static_cast<uint8_t>(0));

				// Handle scope ID (e.g., fe80::1%eth0) - strip it for parsing
				size_t percentPos = str.find(L'%');
				if (percentPos != std::wstring_view::npos) {
					str = str.substr(0, percentPos);
					if (str.empty()) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, 
							L"IPv6 address empty before scope ID", L"ParseIPv6");
						return false;
					}
				}

				// Use Windows API for robust parsing
				// NOTE: WSAStartup must be called before this function works
				sockaddr_in6 sa6{};
				sa6.sin6_family = AF_INET6;
				int len = sizeof(sa6);

				// WSAStringToAddressW requires non-const string, so we must copy
				// Using a local buffer to avoid dynamic allocation in noexcept function
				constexpr size_t BUFFER_SIZE = 64;
				wchar_t strBuffer[BUFFER_SIZE];
				
				if (str.size() >= BUFFER_SIZE) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, 
						L"IPv6 string exceeds buffer size", L"ParseIPv6");
					return false;
				}

				// Safe copy
				std::wmemcpy(strBuffer, str.data(), str.size());
				strBuffer[str.size()] = L'\0';

				if (WSAStringToAddressW(strBuffer, AF_INET6, nullptr,
					reinterpret_cast<SOCKADDR*>(&sa6), &len) == 0) {//-V603
					// Successfully parsed - copy the address bytes
					static_assert(sizeof(sa6.sin6_addr) == 16, "IPv6 address must be 16 bytes");
					std::memcpy(bytes.data(), &sa6.sin6_addr, 16);
					out = IPv6Address(bytes);
					return true;
				}

				// Handle common error cases with better messages
				const int wsaErr = WSAGetLastError();
				if (wsaErr == WSANOTINITIALISED) {
					Internal::SetError(err, static_cast<DWORD>(wsaErr), 
						L"WSAStartup not called - Winsock must be initialized before parsing IPv6", 
						L"ParseIPv6");
				}
				else {
					Internal::SetWsaError(err, wsaErr, L"ParseIPv6");
				}
				return false;
			}

			bool ParseIpAddress(std::wstring_view str, IpAddress& out, Error* err) noexcept {
				// Try IPv4 first (more common and faster to parse)
				IPv4Address ipv4;
				if (ParseIPv4(str, ipv4, nullptr)) {
					out = IpAddress(ipv4);
					return true;
				}

				// Try IPv6
				IPv6Address ipv6;
				if (ParseIPv6(str, ipv6, err)) {
					out = IpAddress(ipv6);
					return true;
				}

				// Neither worked - set error if not already set
				if (err && err->message.empty()) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, 
						L"Invalid IP address format (not valid IPv4 or IPv6)", L"ParseIpAddress");
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
			// IP Network Calculations - Enterprise-Grade with UB Protection
			// ============================================================================

			/**
			 * @brief Check if an IP address is within a given subnet
			 * @param address The IP address to check
			 * @param subnet The subnet network address
			 * @param prefixLength The CIDR prefix length (0-32 for IPv4, 0-128 for IPv6)
			 * @return true if address is in subnet, false otherwise
			 * @note Both addresses must be the same IP version
			 */
			bool IsInSubnet(const IpAddress& address, const IpAddress& subnet, uint8_t prefixLength) noexcept {
				// IP version mismatch check
				if (address.version != subnet.version) {
					return false;
				}

				if (address.version == IpVersion::IPv4) {
					// Validate prefix length for IPv4 (0-32)
					if (prefixLength > 32) {
						return false;
					}

					const auto* addr = address.AsIPv4();
					const auto* net = subnet.AsIPv4();
					if (!addr || !net) {
						return false;
					}

					// Use helper function to avoid UB from shift by 32
					const uint32_t mask = Internal::IPv4MaskFromPrefix(prefixLength);
					return (addr->ToUInt32() & mask) == (net->ToUInt32() & mask);
				}
				else if (address.version == IpVersion::IPv6) {
					// Validate prefix length for IPv6 (0-128)
					if (prefixLength > 128) {
						return false;
					}

					const auto* addr = address.AsIPv6();
					const auto* net = subnet.AsIPv6();
					if (!addr || !net) {
						return false;
					}

					// Calculate which bytes are fully/partially masked
					const size_t fullBytes = static_cast<size_t>(prefixLength / 8);
					const uint8_t remainingBits = static_cast<uint8_t>(prefixLength % 8);

					// Compare fully-masked bytes (all bits significant)
					for (size_t i = 0; i < fullBytes; ++i) {
						if (addr->bytes[i] != net->bytes[i]) {
							return false;
						}
					}

					// Compare partially-masked byte if exists
					if (fullBytes < 16 && remainingBits > 0) {
						const uint8_t mask = Internal::IPv6ByteMask(remainingBits);
						if ((addr->bytes[fullBytes] & mask) != (net->bytes[fullBytes] & mask)) {
							return false;
						}
					}

					return true;
				}

				return false;
			}

			/**
			 * @brief Calculate the network address from an IP address and prefix length
			 * @param address The IP address
			 * @param prefixLength The CIDR prefix length
			 * @return The network address, or std::nullopt on invalid input
			 */
			std::optional<IpAddress> GetNetworkAddress(const IpAddress& address, uint8_t prefixLength) noexcept {
				if (address.version == IpVersion::IPv4) {
					if (prefixLength > 32) {
						return std::nullopt;
					}

					const auto* addr = address.AsIPv4();
					if (!addr) {
						return std::nullopt;
					}

					// Use helper to avoid UB
					const uint32_t mask = Internal::IPv4MaskFromPrefix(prefixLength);
					const uint32_t network = addr->ToUInt32() & mask;
					return IpAddress(IPv4Address(network));
				}
				else if (address.version == IpVersion::IPv6) {
					if (prefixLength > 128) {
						return std::nullopt;
					}

					const auto* addr = address.AsIPv6();
					if (!addr) {
						return std::nullopt;
					}

					std::array<uint8_t, 16> networkBytes = addr->bytes;
					const size_t fullBytes = static_cast<size_t>(prefixLength / 8);
					const uint8_t remainingBits = static_cast<uint8_t>(prefixLength % 8);

					// Keep full bytes as-is (they're already part of network)
					// Apply partial mask to the boundary byte
					if (fullBytes < 16) {
						if (remainingBits > 0) {
							const uint8_t mask = Internal::IPv6ByteMask(remainingBits);
							networkBytes[fullBytes] &= mask;
						}
						else {
							networkBytes[fullBytes] = 0;
						}
					}

					// Zero out remaining bytes
					for (size_t i = fullBytes + (remainingBits > 0 ? 1 : 0); i < 16; ++i) {
						networkBytes[i] = 0;
					}

					return IpAddress(IPv6Address(networkBytes));
				}

				return std::nullopt;
			}

			/**
			 * @brief Calculate the broadcast address for an IPv4 network
			 * @param network The network address
			 * @param prefixLength The CIDR prefix length (0-32)
			 * @return The broadcast address, or std::nullopt on invalid input
			 * @note IPv6 does not have broadcast addresses (uses multicast instead)
			 */
			std::optional<IpAddress> GetBroadcastAddress(const IPv4Address& network, uint8_t prefixLength) noexcept {
				if (prefixLength > 32) {
					return std::nullopt;
				}

				// Use helper to avoid UB, then invert for host mask
				const uint32_t netmask = Internal::IPv4MaskFromPrefix(prefixLength);
				const uint32_t hostmask = ~netmask;
				const uint32_t broadcast = network.ToUInt32() | hostmask;
				return IpAddress(IPv4Address(broadcast));
			}

			/**
			 * @brief Calculate the number of addresses in a subnet
			 * @param prefixLength The CIDR prefix length
			 * @param version The IP version
			 * @return Number of addresses, or 0 on invalid input, or UINT64_MAX if too large
			 * @note For IPv6 with prefix < 64, returns UINT64_MAX as actual count exceeds uint64_t
			 */
			uint64_t GetAddressCount(uint8_t prefixLength, IpVersion version) noexcept {
				if (version == IpVersion::IPv4) {
					if (prefixLength > 32) {
						return 0;
					}
					// Safe: shift amount is 0-32, and we use 64-bit type
					// When prefixLength == 0, result is 1 << 32 = 4,294,967,296 (fits in uint64_t)
					const uint64_t hostBits = 32ULL - static_cast<uint64_t>(prefixLength);
					return 1ULL << hostBits;
				}
				else if (version == IpVersion::IPv6) {
					if (prefixLength > 128) {
						return 0;
					}
					
					// For IPv6, if prefix < 64, the result would exceed uint64_t
					// 2^(128-63) = 2^65 > UINT64_MAX
					const uint64_t hostBits = 128ULL - static_cast<uint64_t>(prefixLength);
					if (hostBits > 63) {
						// Return max value to indicate "very large"
						// Callers should check: if (result == UINT64_MAX && prefix < 64) => overflow
						return UINT64_MAX;
					}
					
					return 1ULL << hostBits;
				}
				
				return 0;
			}

		}// namespace NetworkUtils
	}// namespace Utils
}// namespace ShadowStrike