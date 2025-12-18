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

				}
				catch (...) {
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
		}//namespace NetworkUtils
	}//namespace Utils
}//namespace ShadowStrike