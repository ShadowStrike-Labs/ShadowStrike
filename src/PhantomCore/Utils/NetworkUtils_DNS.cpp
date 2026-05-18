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

			namespace {
				// Reject hostnames carrying embedded NUL or ASCII control characters.
				// std::wstring built from a std::wstring_view preserves embedded NULs,
				// but DnsQuery_W / getaddrinfo consume a C string and would silently
				// truncate at the first NUL, hiding the rest of the payload from
				// validation.  Length cap is enforced separately by callers.
				[[nodiscard]] inline bool IsAcceptableHostname(std::wstring_view host) noexcept {
					for (wchar_t c : host) {
						if (c == L'\0') return false;
						if (c < 0x20 || c == 0x7F) return false;
					}
					return true;
				}
			} // anonymous namespace



			// ============================================================================
			// Hostname Resolution
			// ============================================================================

			bool ResolveHostname(std::wstring_view hostname, std::vector<IpAddress>& addresses, AddressFamily family, Error* err) noexcept {
				try {
					addresses.clear();
					SS_LOG_DEBUG(L"NetworkUtils", L"ResolveHostname called len=%zu family=%u", hostname.size(), static_cast<unsigned>(family));

					// Validate hostname length to prevent buffer overflow attacks
					if (hostname.empty() || hostname.size() > 255) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid hostname length");
						return false;
					}
					if (!IsAcceptableHostname(hostname)) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Hostname contains NUL or control characters");
						return false;
					}

					WsaInitializer wsa;
					if (!wsa.IsInitialized()) {
						Internal::SetWsaError(err, wsa.GetError(), L"WSA initialization failed");
						return false;
					}

					// Properly convert wide string to narrow string using UTF-8
					std::string hostnameA;
					{
						int narrowLen = WideCharToMultiByte(CP_UTF8, 0, hostname.data(),
							static_cast<int>(hostname.size()), nullptr, 0, nullptr, nullptr);
						if (narrowLen <= 0) {
							Internal::SetError(err, ::GetLastError(), L"Failed to convert hostname");
							return false;
						}
						hostnameA.resize(static_cast<size_t>(narrowLen));
						WideCharToMultiByte(CP_UTF8, 0, hostname.data(),
							static_cast<int>(hostname.size()), hostnameA.data(), narrowLen, nullptr, nullptr);
					}

					addrinfo hints{};
					hints.ai_family = static_cast<int>(family);
					hints.ai_socktype = SOCK_STREAM;
					hints.ai_protocol = IPPROTO_TCP;

					addrinfo* result = nullptr;
					int ret = ::getaddrinfo(hostnameA.c_str(), nullptr, &hints, &result);
					if (ret != 0) {
						SS_LOG_ERROR(L"NetworkUtils", L"getaddrinfo failed ret=%d", ret);
						Internal::SetWsaError(err, ret, L"getaddrinfo");
						return false;
					}

					// RAII guard ensures freeaddrinfo on all paths (including exception)
					struct AddrInfoGuard {
						addrinfo* p;
						~AddrInfoGuard() { if (p) ::freeaddrinfo(p); }
					} aiGuard{result};

					for (addrinfo* ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
						if (ptr->ai_addr == nullptr) continue;
						if (ptr->ai_family == AF_INET && ptr->ai_addrlen >= sizeof(sockaddr_in)) {
							auto* sa = reinterpret_cast<sockaddr_in*>(ptr->ai_addr);
							uint32_t addr = Internal::NetworkToHost32(sa->sin_addr.s_addr);
							addresses.emplace_back(IPv4Address(addr));
						}
						else if (ptr->ai_family == AF_INET6 && ptr->ai_addrlen >= sizeof(sockaddr_in6)) {
							auto* sa6 = reinterpret_cast<sockaddr_in6*>(ptr->ai_addr);
							std::array<uint8_t, 16> bytes;
							std::memcpy(bytes.data(), &sa6->sin6_addr, 16);
							addresses.emplace_back(IPv6Address(bytes));
						}
					}

					return !addresses.empty();

				}
				catch (...) {
					SS_LOG_ERROR(L"NetworkUtils", L"Exception in ResolveHostname");
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
					hostname.clear();
					SS_LOG_DEBUG(L"NetworkUtils", L"ReverseLookup called");

					WsaInitializer wsa;
					if (!wsa.IsInitialized()) {
						Internal::SetWsaError(err, wsa.GetError(), L"WSA initialization failed");
						return false;
					}

					// Validate IP address
					if (!address.IsValid()) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid IP address");
						return false;
					}

					// Helper lambda for proper UTF-8 to wide string conversion
					auto convertToWide = [](const char* narrowStr, std::wstring& wideStr) -> bool {
						if (!narrowStr || narrowStr[0] == '\0') return false;
						size_t narrowLen = std::strlen(narrowStr);
						if (narrowLen == 0 || narrowLen > NI_MAXHOST) return false;

						int wideLen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
							narrowStr, static_cast<int>(narrowLen), nullptr, 0);
						if (wideLen <= 0) {
							// Fallback to ACP if UTF-8 fails
							wideLen = MultiByteToWideChar(CP_ACP, 0, narrowStr,
								static_cast<int>(narrowLen), nullptr, 0);
							if (wideLen <= 0) return false;
							wideStr.resize(static_cast<size_t>(wideLen));
							MultiByteToWideChar(CP_ACP, 0, narrowStr,
								static_cast<int>(narrowLen), wideStr.data(), wideLen);
						}
						else {
							wideStr.resize(static_cast<size_t>(wideLen));
							MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
								narrowStr, static_cast<int>(narrowLen), wideStr.data(), wideLen);
						}
						return true;
						};

					int gnRet = -1;

					if (address.version == IpVersion::IPv4) {
						auto* ipv4 = address.AsIPv4();
						if (!ipv4) {
							Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid IPv4 address");
							return false;
						}

						sockaddr_in sa{};
						sa.sin_family = AF_INET;
						sa.sin_addr.s_addr = Internal::HostToNetwork32(ipv4->ToUInt32());

						char hostBuffer[NI_MAXHOST] = {};
						gnRet = ::getnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof(sa),
							hostBuffer, sizeof(hostBuffer), nullptr, 0, NI_NAMEREQD);

						if (gnRet == 0 && convertToWide(hostBuffer, hostname)) {
							return true;
						}

					}
					else if (address.version == IpVersion::IPv6) {
						auto* ipv6 = address.AsIPv6();
						if (!ipv6) {
							Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid IPv6 address");
							return false;
						}

						sockaddr_in6 sa6{};
						sa6.sin6_family = AF_INET6;
						std::memcpy(&sa6.sin6_addr, ipv6->bytes.data(), 16);

						char hostBuffer[NI_MAXHOST] = {};
						gnRet = ::getnameinfo(reinterpret_cast<sockaddr*>(&sa6), sizeof(sa6),
							hostBuffer, sizeof(hostBuffer), nullptr, 0, NI_NAMEREQD);

						if (gnRet == 0 && convertToWide(hostBuffer, hostname)) {
							return true;
						}
					}

					SS_LOG_ERROR(L"NetworkUtils", L"ReverseLookup getnameinfo failed (code=%d)", gnRet);
					Internal::SetWsaError(err, gnRet, L"Reverse DNS lookup failed — no PTR record");
					return false;

				}
				catch (...) {
					SS_LOG_ERROR(L"NetworkUtils", L"Exception in ReverseLookup");
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

					if (hostname.empty() || hostname.size() > 255) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid hostname length");
						return false;
					}
					if (!IsAcceptableHostname(hostname)) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Hostname contains NUL or control characters");
						return false;
					}

					SS_LOG_DEBUG(L"NetworkUtils", L"QueryDns type=%u host_len=%zu", static_cast<unsigned>(type), hostname.size());
					std::wstring hostStr(hostname);

					// RAII wrapper explicitly using PDNS_RECORDW to ensure Unicode compatibility
					struct DnsRecordGuard {
						PDNS_RECORDW ptr = nullptr;
						~DnsRecordGuard() {
							if (ptr) {
								::DnsFree(ptr, DnsFreeRecordList);
							}
						}
					} dnsRecordGuard;

					// Backing storage for custom DNS server array (replaces raw malloc)
					std::vector<uint8_t> dnsServerBacking;
					PIP4_ARRAY pDnsServers = nullptr;

					DWORD flags = DNS_QUERY_STANDARD;
					if (!options.recursionDesired) flags |= DNS_QUERY_NO_RECURSION;
					if (options.dnssec) flags |= DNS_QUERY_DNSSEC_OK;
					if (!options.useSystemDns && !options.customDnsServers.empty()) flags |= DNS_QUERY_NO_HOSTS_FILE;

					if (!options.customDnsServers.empty() && !options.useSystemDns) {
						std::vector<IP4_ADDRESS> dnsServerAddresses;
						dnsServerAddresses.reserve(options.customDnsServers.size());

						size_t ipv6Skipped = 0;
						for (const auto& dnsServer : options.customDnsServers) {
							if (dnsServer.IsIPv4()) {
								if (auto* ipv4 = dnsServer.AsIPv4()) {
									dnsServerAddresses.push_back(Internal::HostToNetwork32(ipv4->ToUInt32()));
								}
							} else {
								++ipv6Skipped;
							}
						}
						if (ipv6Skipped > 0) {
							SS_LOG_WARN(L"NetworkUtils", L"QueryDns skipped %zu IPv6-only custom DNS servers (DnsQuery_W only supports IPv4 server list)", ipv6Skipped);
						}

						if (dnsServerAddresses.empty() && ipv6Skipped > 0) {
							SS_LOG_WARN(L"NetworkUtils", L"All custom DNS servers were IPv6 — falling back to system DNS");
						}
						if (!dnsServerAddresses.empty()) {
							constexpr size_t maxDnsServers = 64;
							if (dnsServerAddresses.size() > maxDnsServers) dnsServerAddresses.resize(maxDnsServers);

							size_t structSize = sizeof(IP4_ARRAY) + (dnsServerAddresses.size() - 1) * sizeof(IP4_ADDRESS);
							dnsServerBacking.resize(structSize, 0);
							pDnsServers = reinterpret_cast<PIP4_ARRAY>(dnsServerBacking.data());
							pDnsServers->AddrCount = static_cast<DWORD>(dnsServerAddresses.size());
							for (size_t i = 0; i < dnsServerAddresses.size(); ++i) {
								pDnsServers->AddrArray[i] = dnsServerAddresses[i];
							}
						}
					}

					// Explicitly using PDNS_RECORDW cast to avoid macro-based type mismatches
					DNS_STATUS status = ::DnsQuery_W(
						hostStr.c_str(),
						static_cast<WORD>(type),
						flags,
						pDnsServers,
						reinterpret_cast<PDNS_RECORD*>(&dnsRecordGuard.ptr),
						nullptr
					);

					if (status != 0) {
						if (status == DNS_INFO_NO_RECORDS) {
							SS_LOG_DEBUG(L"NetworkUtils", L"DnsQuery_W returned no records");
							return true;
						}
						SS_LOG_ERROR(L"NetworkUtils", L"DnsQuery_W failed status=%lu", status);
						Internal::SetError(err, status, L"DnsQuery_W failed");
						return false;
					}

					// Cap record iteration to prevent malicious DNS responses from OOM
					constexpr DWORD kMaxDnsRecords = 2048;
					DWORD recordCount = 0;

					for (PDNS_RECORDW pRec = dnsRecordGuard.ptr; pRec != nullptr && recordCount < kMaxDnsRecords; pRec = pRec->pNext, ++recordCount) {
						// NOTE: DnsQuery_W with DNS_QUERY_DNSSEC_OK delegates validation
						// to the Windows DNS resolver, which returns DNS_INFO_NO_RECORDS
						// on validation failure (handled above).  Per-record filtering
						// against pRec->Flags.DW would require a user-mode "validated"
						// bit that Windows does not expose; the previous implementation
						// matched 0x0020, which is the Section bit-field, not a DNSSEC
						// status, and therefore silently discarded every record when
						// options.dnssec was set.  Trust the resolver here instead.

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
							// pNameHost is PWSTR in DNS_RECORDW
							rec.data = pRec->Data.CNAME.pNameHost ? pRec->Data.CNAME.pNameHost : L"";
							break;

						case DNS_TYPE_MX:
							rec.data = pRec->Data.MX.pNameExchange ? pRec->Data.MX.pNameExchange : L"";
							rec.priority = pRec->Data.MX.wPreference;
							break;

						case DNS_TYPE_TEXT:
							if (pRec->Data.TXT.dwStringCount > 0 && pRec->Data.TXT.dwStringCount < 256) {
								for (DWORD i = 0; i < pRec->Data.TXT.dwStringCount; ++i) {
									// pStringArray[i] is PWSTR in DNS_RECORDW
									if (pRec->Data.TXT.pStringArray[i]) {
										if (!rec.data.empty()) rec.data += L" ";
										rec.data += pRec->Data.TXT.pStringArray[i];
									}
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
							continue;
						}

						records.push_back(std::move(rec));
					}

					return true;
				}
				catch (const std::exception& e) {
					SS_LOG_ERROR(L"NetworkUtils", L"Exception in QueryDns");
					Internal::SetError(err, ERROR_GENERIC_NOT_MAPPED, L"Exception in QueryDns");
					return false;
				}
				catch (...) {
					SS_LOG_ERROR(L"NetworkUtils", L"Unknown exception in QueryDns");
					Internal::SetError(err, ERROR_GENERIC_NOT_MAPPED, L"Unknown exception in QueryDns");
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

		}
	}
}