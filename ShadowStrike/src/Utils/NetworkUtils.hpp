#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <functional>
#include <cstdint>
#include <filesystem>
#include <map>
#include <array>
#include <chrono>
#include <memory>
#include <variant>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#  include <WinSock2.h>
#  include <ws2tcpip.h>
#  include <iphlpapi.h>
#  include <icmpapi.h>
#  include <netioapi.h>
#  include <mstcpip.h>
#  include <winhttp.h>
#  include <windns.h>
#  pragma comment(lib, "ws2_32.lib")
#  pragma comment(lib, "iphlpapi.lib")
#  pragma comment(lib, "winhttp.lib")
#  pragma comment(lib, "dnsapi.lib")
#endif

#include "Logger.hpp"

namespace ShadowStrike {
	namespace Utils {
		namespace NetworkUtils {

			// ============================================================================
			// Error Structures
			// ============================================================================

			struct Error {
				DWORD win32 = ERROR_SUCCESS;
				DWORD httpStatus = 0;
				DWORD wsaError = 0;
				std::wstring message;
				std::wstring context;
			};

			// ============================================================================
			// IP Address Structures and Enums
			// ============================================================================

			enum class IpVersion : uint8_t {
				Unknown = 0,
				IPv4 = 4,
				IPv6 = 6
			};

			enum class AddressFamily : uint16_t {
				Unspecified = AF_UNSPEC,
				IPv4 = AF_INET,
				IPv6 = AF_INET6
			};

			struct IPv4Address {
				std::array<uint8_t, 4> octets = {};

				IPv4Address() = default;
				explicit IPv4Address(const std::array<uint8_t, 4>& bytes) : octets(bytes) {}
				explicit IPv4Address(uint32_t addr) {
					octets[0] = (addr >> 24) & 0xFF;
					octets[1] = (addr >> 16) & 0xFF;
					octets[2] = (addr >> 8) & 0xFF;
					octets[3] = addr & 0xFF;
				}

				uint32_t ToUInt32() const noexcept {
					return (static_cast<uint32_t>(octets[0]) << 24) |
						   (static_cast<uint32_t>(octets[1]) << 16) |
						   (static_cast<uint32_t>(octets[2]) << 8) |
						   static_cast<uint32_t>(octets[3]);
				}

				std::wstring ToString() const;
				bool IsLoopback() const noexcept;
				bool IsPrivate() const noexcept;
				bool IsMulticast() const noexcept;
				bool IsBroadcast() const noexcept;
				bool IsLinkLocal() const noexcept;

				bool operator==(const IPv4Address& other) const noexcept {
					return octets == other.octets;
				}
				bool operator!=(const IPv4Address& other) const noexcept {
					return !(*this == other);
				}
			};

			struct IPv6Address {
				std::array<uint8_t, 16> bytes = {};

				IPv6Address() = default;
				explicit IPv6Address(const std::array<uint8_t, 16>& b) : bytes(b) {}

				std::wstring ToString() const;
				std::wstring ToStringCompressed() const;
				bool IsLoopback() const noexcept;
				bool IsPrivate() const noexcept;
				bool IsMulticast() const noexcept;
				bool IsLinkLocal() const noexcept;
				bool IsSiteLocal() const noexcept;
				bool IsUniqueLocal() const noexcept;

				bool operator==(const IPv6Address& other) const noexcept {
					return bytes == other.bytes;
				}
				bool operator!=(const IPv6Address& other) const noexcept {
					return !(*this == other);
				}
			};

			struct IpAddress {
				IpVersion version = IpVersion::Unknown;
				std::variant<std::monostate, IPv4Address, IPv6Address> address;

				IpAddress() = default;
				explicit IpAddress(const IPv4Address& ipv4) : version(IpVersion::IPv4), address(ipv4) {}
				explicit IpAddress(const IPv6Address& ipv6) : version(IpVersion::IPv6), address(ipv6) {}

				bool IsValid() const noexcept { return version != IpVersion::Unknown; }
				bool IsIPv4() const noexcept { return version == IpVersion::IPv4; }
				bool IsIPv6() const noexcept { return version == IpVersion::IPv6; }

				const IPv4Address* AsIPv4() const noexcept {
					return std::get_if<IPv4Address>(&address);
				}
				const IPv6Address* AsIPv6() const noexcept {
					return std::get_if<IPv6Address>(&address);
				}

				std::wstring ToString() const;
				bool IsLoopback() const noexcept;
				bool IsPrivate() const noexcept;
				bool IsMulticast() const noexcept;

				bool operator==(const IpAddress& other) const noexcept;
				bool operator!=(const IpAddress& other) const noexcept {
					return !(*this == other);
				}
			};

			// ============================================================================
			// Network Adapter Information
			// ============================================================================

			enum class AdapterType : uint32_t {
				Unknown = 0,
				Ethernet = IF_TYPE_ETHERNET_CSMACD,
				Wireless80211 = IF_TYPE_IEEE80211,
				Loopback = IF_TYPE_SOFTWARE_LOOPBACK,
				Tunnel = IF_TYPE_TUNNEL,
				PPP = IF_TYPE_PPP,
				Virtual = 0xFFFF
			};

			enum class OperationalStatus : uint32_t {
				Up = IfOperStatusUp,
				Down = IfOperStatusDown,
				Testing = IfOperStatusTesting,
				Unknown = IfOperStatusUnknown,
				Dormant = IfOperStatusDormant,
				NotPresent = IfOperStatusNotPresent,
				LowerLayerDown = IfOperStatusLowerLayerDown
			};

			struct MacAddress {
				std::array<uint8_t, 6> bytes = {};

				MacAddress() = default;
				explicit MacAddress(const std::array<uint8_t, 6>& b) : bytes(b) {}

				std::wstring ToString() const;
				bool IsValid() const noexcept;
				bool IsBroadcast() const noexcept;
				bool IsMulticast() const noexcept;

				bool operator==(const MacAddress& other) const noexcept {
					return bytes == other.bytes;
				}
			};

			struct NetworkAdapterInfo {
				std::wstring friendlyName;
				std::wstring description;
				MacAddress macAddress;
				std::vector<IpAddress> ipAddresses;
				std::vector<IpAddress> gatewayAddresses;
				std::vector<IpAddress> dnsServers;
				uint32_t mtu = 0;
				uint64_t speed = 0; // bits per second
				AdapterType type = AdapterType::Unknown;
				OperationalStatus status = OperationalStatus::Unknown;
				uint32_t interfaceIndex = 0;
				bool dhcpEnabled = false;
				bool ipv4Enabled = false;
				bool ipv6Enabled = false;
			};

			// ============================================================================
			// HTTP/HTTPS Functionality
			// ============================================================================

#pragma push_macro("DELETE")
#undef DELETE
			enum class HttpMethod {
				GET,
				POST,
				PUT,
				DELETE,
				HEAD,
				PATCH,
				OPTIONS,
				TRACE
			};
#pragma pop_macro("DELETE")

			struct HttpHeader {
				std::wstring name;
				std::wstring value;
			};

			struct HttpRequestOptions {
				HttpMethod method = HttpMethod::GET;
				std::vector<HttpHeader> headers;
				std::vector<uint8_t> body;
				std::wstring contentType = L"application/octet-stream";
				uint32_t timeoutMs = 30000;
				bool allowRedirects = true;
				uint32_t maxRedirects = 10;
				bool verifySSL = true;
				std::wstring userAgent = L"ShadowStrike-AntiVirus/1.0";
				std::wstring proxy;
				std::wstring proxyUsername;
				std::wstring proxyPassword;
				bool useSystemProxy = true;
			};

			struct HttpResponse {
				uint32_t statusCode = 0;
				std::wstring statusText;
				std::vector<HttpHeader> headers;
				std::vector<uint8_t> body;
				std::wstring contentType;
				uint64_t contentLength = 0;
				std::wstring redirectUrl;
			};

			struct DownloadProgress {
				uint64_t bytesDownloaded = 0;
				uint64_t totalBytes = 0;
				double percentComplete = 0.0;
				uint64_t bytesPerSecond = 0;
				std::chrono::steady_clock::time_point startTime;
				std::chrono::steady_clock::time_point lastUpdate;
			};

			using ProgressCallback = std::function<bool(const DownloadProgress&)>;

			// ============================================================================
			// DNS Functionality
			// ============================================================================

			enum class DnsRecordType : uint16_t {
				A = DNS_TYPE_A,
				AAAA = DNS_TYPE_AAAA,
				CNAME = DNS_TYPE_CNAME,
				MX = DNS_TYPE_MX,
				TXT = DNS_TYPE_TEXT,
				PTR = DNS_TYPE_PTR,
				NS = DNS_TYPE_NS,
				SOA = DNS_TYPE_SOA,
				SRV = DNS_TYPE_SRV,
				ANY = DNS_TYPE_ALL
			};

			struct DnsRecord {
				std::wstring name;
				DnsRecordType type = DnsRecordType::A;
				uint32_t ttl = 0;
				std::wstring data;
				uint16_t priority = 0; // for MX/SRV records
			};

			struct DnsQueryOptions {
				std::vector<IpAddress> customDnsServers;
				uint32_t timeoutMs = 5000;
				bool useSystemDns = true;
				bool recursionDesired = true;
				bool dnssec = false;
			};

			// ============================================================================
			// Port and Socket Information
			// ============================================================================

			enum class ProtocolType : uint8_t {
				TCP = IPPROTO_TCP,
				UDP = IPPROTO_UDP,
				ICMP = IPPROTO_ICMP,
				ICMPv6 = IPPROTO_ICMPV6,
				RAW = IPPROTO_RAW
			};

			enum class TcpState : uint32_t {
				Closed = MIB_TCP_STATE_CLOSED,
				Listen = MIB_TCP_STATE_LISTEN,
				SynSent = MIB_TCP_STATE_SYN_SENT,
				SynRcvd = MIB_TCP_STATE_SYN_RCVD,
				Established = MIB_TCP_STATE_ESTAB,
				FinWait1 = MIB_TCP_STATE_FIN_WAIT1,
				FinWait2 = MIB_TCP_STATE_FIN_WAIT2,
				CloseWait = MIB_TCP_STATE_CLOSE_WAIT,
				Closing = MIB_TCP_STATE_CLOSING,
				LastAck = MIB_TCP_STATE_LAST_ACK,
				TimeWait = MIB_TCP_STATE_TIME_WAIT,
				DeleteTcb = MIB_TCP_STATE_DELETE_TCB
			};

			struct ConnectionInfo {
				ProtocolType protocol = ProtocolType::TCP;
				IpAddress localAddress;
				uint16_t localPort = 0;
				IpAddress remoteAddress;
				uint16_t remotePort = 0;
				TcpState state = TcpState::Closed;
				uint32_t processId = 0;
				std::wstring processName;
				std::chrono::system_clock::time_point createTime;
			};

			struct PortScanResult {
				uint16_t port = 0;
				bool isOpen = false;
				std::wstring serviceName;
				uint32_t responseTimeMs = 0;
			};

			// ============================================================================
			// Ping and Network Testing
			// ============================================================================

			struct PingResult {
				IpAddress address;
				bool success = false;
				uint32_t roundTripTimeMs = 0;
				uint32_t ttl = 0;
				uint32_t dataSize = 0;
				std::wstring errorMessage;
			};

			struct PingOptions {
				uint32_t timeoutMs = 4000;
				uint32_t ttl = 128;
				bool dontFragment = false;
				std::vector<uint8_t> data;
			};

			struct TraceRouteHop {
				uint32_t hopNumber = 0;
				IpAddress address;
				std::wstring hostname;
				uint32_t roundTripTimeMs = 0;
				bool timedOut = false;
			};

			// ============================================================================
			// Network Statistics
			// ============================================================================

			struct NetworkStatistics {
				uint64_t bytesSent = 0;
				uint64_t bytesReceived = 0;
				uint64_t packetsSent = 0;
				uint64_t packetsReceived = 0;
				uint64_t errorsSent = 0;
				uint64_t errorsReceived = 0;
				uint64_t droppedPackets = 0;
				std::chrono::system_clock::time_point timestamp;
			};

			struct BandwidthInfo {
				uint64_t currentDownloadBps = 0;
				uint64_t currentUploadBps = 0;
				uint64_t peakDownloadBps = 0;
				uint64_t peakUploadBps = 0;
				double utilizationPercent = 0.0;
			};

			// ============================================================================
			// URL and Domain Utilities
			// ============================================================================

			struct UrlComponents {
				std::wstring scheme;      // http, https, ftp, etc.
				std::wstring username;
				std::wstring password;
				std::wstring host;
				uint16_t port = 0;
				std::wstring path;
				std::wstring query;
				std::wstring fragment;
			};

			// ============================================================================
			// Routing Table
			// ============================================================================

			struct RouteEntry {
				IpAddress destination;
				IpAddress netmask;
				IpAddress gateway;
				uint32_t interfaceIndex = 0;
				uint32_t metric = 0;
			};

			// ============================================================================
			// ARP Table
			// ============================================================================

			struct ArpEntry {
				IpAddress ipAddress;
				MacAddress macAddress;
				uint32_t interfaceIndex = 0;
				bool isStatic = false;
			};

			// ============================================================================
			// SSL Certificate Information
			// ============================================================================

			struct SslCertificateInfo {
				std::wstring subject;
				std::wstring issuer;
				std::wstring serialNumber;
				std::chrono::system_clock::time_point validFrom;
				std::chrono::system_clock::time_point validTo;
				std::vector<std::wstring> subjectAltNames;
				bool isValid = false;
				bool isSelfSigned = false;
			};

			// ============================================================================
			// Proxy Configuration
			// ============================================================================

			struct ProxyInfo {
				bool enabled = false;
				std::wstring server;
				uint16_t port = 0;
				std::wstring username;
				std::wstring bypass;
				bool autoDetect = false;
				std::wstring autoConfigUrl;
			};

			// ============================================================================
			// Core Network Utility Functions
			// ============================================================================

			// --- IP Address Parsing and Validation ---
			bool ParseIPv4(std::wstring_view str, IPv4Address& out, Error* err = nullptr) noexcept;
			bool ParseIPv6(std::wstring_view str, IPv6Address& out, Error* err = nullptr) noexcept;
			bool ParseIpAddress(std::wstring_view str, IpAddress& out, Error* err = nullptr) noexcept;

			bool IsValidIPv4(std::wstring_view str) noexcept;
			bool IsValidIPv6(std::wstring_view str) noexcept;
			bool IsValidIpAddress(std::wstring_view str) noexcept;

			// --- IP Network Calculations ---
			bool IsInSubnet(const IpAddress& address, const IpAddress& subnet, uint8_t prefixLength) noexcept;
			std::optional<IpAddress> GetNetworkAddress(const IpAddress& address, uint8_t prefixLength) noexcept;
			std::optional<IpAddress> GetBroadcastAddress(const IPv4Address& network, uint8_t prefixLength) noexcept;
			uint64_t GetAddressCount(uint8_t prefixLength, IpVersion version) noexcept;

			// --- Hostname Resolution ---
			bool ResolveHostname(std::wstring_view hostname, std::vector<IpAddress>& addresses, AddressFamily family = AddressFamily::Unspecified, Error* err = nullptr) noexcept;
			bool ResolveHostnameIPv4(std::wstring_view hostname, std::vector<IPv4Address>& addresses, Error* err = nullptr) noexcept;
			bool ResolveHostnameIPv6(std::wstring_view hostname, std::vector<IPv6Address>& addresses, Error* err = nullptr) noexcept;

			// --- Reverse DNS Lookup ---
			bool ReverseLookup(const IpAddress& address, std::wstring& hostname, Error* err = nullptr) noexcept;

			// --- DNS Queries ---
			bool QueryDns(std::wstring_view hostname, DnsRecordType type, std::vector<DnsRecord>& records, const DnsQueryOptions& options = {}, Error* err = nullptr) noexcept;
			bool QueryDnsA(std::wstring_view hostname, std::vector<IPv4Address>& addresses, const DnsQueryOptions& options = {}, Error* err = nullptr) noexcept;
			bool QueryDnsAAAA(std::wstring_view hostname, std::vector<IPv6Address>& addresses, const DnsQueryOptions& options = {}, Error* err = nullptr) noexcept;
			bool QueryDnsMX(std::wstring_view domain, std::vector<DnsRecord>& mxRecords, const DnsQueryOptions& options = {}, Error* err = nullptr) noexcept;
			bool QueryDnsTXT(std::wstring_view domain, std::vector<std::wstring>& txtRecords, const DnsQueryOptions& options = {}, Error* err = nullptr) noexcept;

			// --- Network Adapter Information ---
			bool GetNetworkAdapters(std::vector<NetworkAdapterInfo>& adapters, Error* err = nullptr) noexcept;
			bool GetDefaultGateway(IpAddress& gateway, Error* err = nullptr) noexcept;
			bool GetDnsServers(std::vector<IpAddress>& dnsServers, Error* err = nullptr) noexcept;
			bool GetLocalIpAddresses(std::vector<IpAddress>& addresses, bool includeLoopback = false, Error* err = nullptr) noexcept;

			// --- HTTP/HTTPS Operations ---
			bool HttpRequest(std::wstring_view url, HttpResponse& response, const HttpRequestOptions& options = {}, Error* err = nullptr) noexcept;
			bool HttpGet(std::wstring_view url, std::vector<uint8_t>& data, const HttpRequestOptions& options = {}, Error* err = nullptr) noexcept;
			bool HttpPost(std::wstring_view url, const std::vector<uint8_t>& postData, std::vector<uint8_t>& response, const HttpRequestOptions& options = {}, Error* err = nullptr) noexcept;
			bool HttpDownloadFile(std::wstring_view url, const std::filesystem::path& destPath, const HttpRequestOptions& options = {}, ProgressCallback callback = nullptr, Error* err = nullptr) noexcept;
			bool HttpUploadFile(std::wstring_view url, const std::filesystem::path& filePath, std::vector<uint8_t>& response, const HttpRequestOptions& options = {}, ProgressCallback callback = nullptr, Error* err = nullptr) noexcept;

			// --- Connection and Port Information ---
			bool GetActiveConnections(std::vector<ConnectionInfo>& connections, ProtocolType protocol = ProtocolType::TCP, Error* err = nullptr) noexcept;
			bool GetConnectionsByProcess(uint32_t processId, std::vector<ConnectionInfo>& connections, Error* err = nullptr) noexcept;
			bool IsPortInUse(uint16_t port, ProtocolType protocol = ProtocolType::TCP) noexcept;
			bool GetPortsInUse(std::vector<uint16_t>& ports, ProtocolType protocol = ProtocolType::TCP, Error* err = nullptr) noexcept;

			// --- Ping and Network Testing ---
			bool Ping(const IpAddress& address, PingResult& result, const PingOptions& options = {}, Error* err = nullptr) noexcept;
			bool Ping(std::wstring_view hostname, PingResult& result, const PingOptions& options = {}, Error* err = nullptr) noexcept;
			bool TraceRoute(const IpAddress& address, std::vector<TraceRouteHop>& hops, uint32_t maxHops = 30, uint32_t timeoutMs = 5000, Error* err = nullptr) noexcept;
			bool TraceRoute(std::wstring_view hostname, std::vector<TraceRouteHop>& hops, uint32_t maxHops = 30, uint32_t timeoutMs = 5000, Error* err = nullptr) noexcept;

			// --- Port Scanning ---
			bool ScanPort(const IpAddress& address, uint16_t port, PortScanResult& result, uint32_t timeoutMs = 1000, Error* err = nullptr) noexcept;
			bool ScanPorts(const IpAddress& address, const std::vector<uint16_t>& ports, std::vector<PortScanResult>& results, uint32_t timeoutMs = 1000, Error* err = nullptr) noexcept;

			// --- Network Statistics ---
			bool GetNetworkStatistics(NetworkStatistics& stats, Error* err = nullptr) noexcept;
			bool GetNetworkStatistics(const std::wstring& adapterName, NetworkStatistics& stats, Error* err = nullptr) noexcept;
			bool CalculateBandwidth(const NetworkStatistics& previous, const NetworkStatistics& current, BandwidthInfo& bandwidth) noexcept;

			// --- URL Manipulation ---
			bool ParseUrl(std::wstring_view url, UrlComponents& components, Error* err = nullptr) noexcept;
			std::wstring BuildUrl(const UrlComponents& components) noexcept;
			std::wstring UrlEncode(std::wstring_view str) noexcept;
			std::wstring UrlDecode(std::wstring_view str) noexcept;
			std::wstring ExtractDomain(std::wstring_view url) noexcept;
			std::wstring ExtractHostname(std::wstring_view url) noexcept;
			bool IsValidUrl(std::wstring_view url) noexcept;

			// --- Domain and Host Validation ---
			bool IsValidDomain(std::wstring_view domain) noexcept;
			bool IsValidHostname(std::wstring_view hostname) noexcept;
			bool IsInternationalDomain(std::wstring_view domain) noexcept;
			std::wstring PunycodeEncode(std::wstring_view domain) noexcept;
			std::wstring PunycodeDecode(std::wstring_view punycode) noexcept;

			// --- MAC Address Utilities ---
			bool ParseMacAddress(std::wstring_view str, MacAddress& mac, Error* err = nullptr) noexcept;
			bool GetMacAddress(const IpAddress& ipAddress, MacAddress& mac, Error* err = nullptr) noexcept;
			bool GetLocalMacAddresses(std::vector<MacAddress>& addresses, Error* err = nullptr) noexcept;

			// --- Network Connectivity Tests ---
			bool IsInternetAvailable(uint32_t timeoutMs = 5000) noexcept;
			bool IsHostReachable(std::wstring_view hostname, uint32_t timeoutMs = 5000) noexcept;
			bool IsHostReachable(const IpAddress& address, uint32_t timeoutMs = 5000) noexcept;
			bool TestDnsResolution(uint32_t timeoutMs = 5000) noexcept;

			// --- Network Interface Control ---
			bool EnableNetworkAdapter(const std::wstring& adapterName, Error* err = nullptr) noexcept;
			bool DisableNetworkAdapter(const std::wstring& adapterName, Error* err = nullptr) noexcept;
			bool FlushDnsCache(Error* err = nullptr) noexcept;
			bool RenewDhcpLease(const std::wstring& adapterName, Error* err = nullptr) noexcept;
			bool ReleaseDhcpLease(const std::wstring& adapterName, Error* err = nullptr) noexcept;

			// --- Routing Table ---
			bool GetRoutingTable(std::vector<RouteEntry>& routes, Error* err = nullptr) noexcept;
			bool AddRoute(const IpAddress& destination, uint8_t prefixLength, const IpAddress& gateway, Error* err = nullptr) noexcept;
			bool DeleteRoute(const IpAddress& destination, uint8_t prefixLength, Error* err = nullptr) noexcept;

			// --- ARP Table ---
			bool GetArpTable(std::vector<ArpEntry>& entries, Error* err = nullptr) noexcept;
			bool AddArpEntry(const IpAddress& ipAddress, const MacAddress& macAddress, Error* err = nullptr) noexcept;
			bool DeleteArpEntry(const IpAddress& ipAddress, Error* err = nullptr) noexcept;
			bool FlushArpCache(Error* err = nullptr) noexcept;

			// --- Network Security ---
			bool GetSslCertificate(std::wstring_view hostname, uint16_t port, SslCertificateInfo& certInfo, Error* err = nullptr) noexcept;
			bool ValidateSslCertificate(const SslCertificateInfo& certInfo, std::wstring_view expectedHostname) noexcept;

			// --- Network Protocol Detection ---
			bool DetectProtocol(const std::vector<uint8_t>& data, std::wstring& protocol) noexcept;
			bool IsHttpTraffic(const std::vector<uint8_t>& data) noexcept;
			bool IsHttpsTraffic(const std::vector<uint8_t>& data) noexcept;
			bool IsDnsTraffic(const std::vector<uint8_t>& data) noexcept;
			bool IsFtpTraffic(const std::vector<uint8_t>& data) noexcept;
			bool IsSshTraffic(const std::vector<uint8_t>& data) noexcept;
			bool IsSmtpTraffic(const std::vector<uint8_t>& data) noexcept;
			bool IsImapTraffic(const std::vector<uint8_t>& data) noexcept;
			bool IsPop3Traffic(const std::vector<uint8_t>& data) noexcept;
			bool IsTelnetTraffic(const std::vector<uint8_t>& data) noexcept;
			bool IsRdpTraffic(const std::vector<uint8_t>& data) noexcept;
			bool IsSmbTraffic(const std::vector<uint8_t>& data) noexcept;

			// --- Proxy Detection and Configuration ---
			bool GetSystemProxySettings(ProxyInfo& proxy, Error* err = nullptr) noexcept;
			bool SetSystemProxySettings(const ProxyInfo& proxy, Error* err = nullptr) noexcept;
			bool DetectProxyForUrl(std::wstring_view url, ProxyInfo& proxy, Error* err = nullptr) noexcept;

			// --- Utility Functions ---
			std::wstring GetProtocolName(ProtocolType protocol) noexcept;
			std::wstring GetTcpStateName(TcpState state) noexcept;
			std::wstring GetAdapterTypeName(AdapterType type) noexcept;
			std::wstring GetOperationalStatusName(OperationalStatus status) noexcept;
			std::wstring FormatBytes(uint64_t bytes) noexcept;
			std::wstring FormatBytesPerSecond(uint64_t bytesPerSec) noexcept;

			// --- Error Helpers ---
			std::wstring FormatNetworkError(DWORD errorCode) noexcept;
			std::wstring FormatWinHttpError(DWORD errorCode) noexcept;
			std::wstring FormatWsaError(int wsaError) noexcept;

			// ============================================================================
			// RAII Helpers
			// ============================================================================

			class WinHttpSession {
			public:
				WinHttpSession() = default;
				~WinHttpSession() noexcept { Close(); }

				WinHttpSession(WinHttpSession&& other) noexcept : m_session(other.m_session) {
					other.m_session = nullptr;
				}
				WinHttpSession& operator=(WinHttpSession&& other) noexcept {
					if (this != &other) {
						Close();
						m_session = other.m_session;
						other.m_session = nullptr;
					}
					return *this;
				}

				WinHttpSession(const WinHttpSession&) = delete;
				WinHttpSession& operator=(const WinHttpSession&) = delete;

				bool Open(std::wstring_view userAgent, Error* err = nullptr) noexcept;
				void Close() noexcept;
				bool IsValid() const noexcept { return m_session != nullptr; }
				HINTERNET Handle() const noexcept { return m_session; }

			private:
				HINTERNET m_session = nullptr;
			};

			class WsaInitializer {
			public:
				WsaInitializer() noexcept;
				~WsaInitializer() noexcept;

				WsaInitializer(const WsaInitializer&) = delete;
				WsaInitializer& operator=(const WsaInitializer&) = delete;

				bool IsInitialized() const noexcept { return m_initialized; }
				int GetError() const noexcept { return m_error; }

			private:
				bool m_initialized = false;
				int m_error = 0;
			};

		} // namespace NetworkUtils
	} // namespace Utils
} // namespace ShadowStrike} // namespace ShadowStrike