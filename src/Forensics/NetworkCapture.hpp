/**
 * ============================================================================
 * ShadowStrike Forensics - NETWORK TRAFFIC CAPTURE ENGINE
 * ============================================================================
 *
 * @file NetworkCapture.hpp
 * @brief Enterprise-grade network traffic capture system for forensic analysis
 *        of malicious network communications and data exfiltration attempts.
 *
 * This module provides comprehensive network packet capture capabilities using
 * Windows Filtering Platform (WFP) and other capture mechanisms for selective
 * traffic acquisition during incident investigation.
 *
 * CAPTURE CAPABILITIES:
 * =====================
 *
 * 1. SELECTIVE CAPTURE
 *    - Per-process capture (PID-based)
 *    - IP address filtering
 *    - Port filtering
 *    - Protocol filtering
 *    - Domain filtering
 *
 * 2. WFP INTEGRATION
 *    - Callout driver integration
 *    - Stream layer inspection
 *    - Packet layer capture
 *    - Real-time filtering
 *    - Zero-copy capture
 *
 * 3. PROTOCOL ANALYSIS
 *    - TCP stream reassembly
 *    - HTTP/HTTPS parsing
 *    - DNS transaction logging
 *    - SMB session tracking
 *    - Custom protocol handlers
 *
 * 4. SSL/TLS INSPECTION
 *    - SSLKEYLOGFILE support
 *    - Master secret capture
 *    - Session key extraction
 *    - Certificate logging
 *    - Handshake analysis
 *
 * 5. CAPTURE FORMATS
 *    - PCAP/PCAPNG output
 *    - ShadowStrike format
 *    - Network flow records
 *    - SSL key log files
 *    - Evidence containers
 *
 * 6. ANALYSIS FEATURES
 *    - C2 communication detection
 *    - Data exfiltration detection
 *    - DNS tunneling detection
 *    - Beaconing detection
 *    - Protocol anomalies
 *
 * INTEGRATION:
 * ============
 * - WFP callout driver for kernel capture
 * - ETW for network event tracing
 * - Raw sockets for user-mode capture
 * - Wireshark-compatible output
 *
 * @note Full capture requires kernel driver or elevated privileges.
 * @note SSL inspection requires application-level hooks.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * COMPLIANCE: SOC2, ISO 27001, NIST
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <optional>
#include <variant>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <span>
#include <queue>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#  include <Winsock2.h>
#  include <Ws2tcpip.h>
#  include <fwpmu.h>
#  include <fwpmtypes.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/ProcessUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Forensics {
    class NetworkCaptureImpl;
    class EvidenceCollector;
}

namespace ShadowStrike {
namespace Forensics {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace NetworkCaptureConstants {

    // ========================================================================
    // VERSION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // PCAP CONSTANTS
    // ========================================================================
    
    /// @brief PCAP magic number
    inline constexpr uint32_t PCAP_MAGIC = 0xA1B2C3D4;
    
    /// @brief PCAPNG magic number
    inline constexpr uint32_t PCAPNG_MAGIC = 0x0A0D0D0A;
    
    /// @brief Default snapshot length
    inline constexpr uint32_t DEFAULT_SNAPLEN = 65535;
    
    /// @brief Ethernet link type
    inline constexpr uint32_t LINKTYPE_ETHERNET = 1;
    
    /// @brief Raw IP link type
    inline constexpr uint32_t LINKTYPE_RAW = 101;

    // ========================================================================
    // LIMITS
    // ========================================================================
    
    /// @brief Maximum capture file size (bytes)
    inline constexpr uint64_t MAX_CAPTURE_SIZE = 10ULL * 1024 * 1024 * 1024;  // 10GB
    
    /// @brief Maximum packets to buffer
    inline constexpr size_t MAX_PACKET_BUFFER = 100000;
    
    /// @brief Maximum concurrent captures
    inline constexpr size_t MAX_CONCURRENT_CAPTURES = 10;
    
    /// @brief Maximum filter rules
    inline constexpr size_t MAX_FILTER_RULES = 100;
    
    /// @brief Maximum SSL keys to store
    inline constexpr size_t MAX_SSL_KEYS = 10000;

    // ========================================================================
    // TIMEOUTS
    // ========================================================================
    
    /// @brief Capture timeout default (milliseconds)
    inline constexpr uint32_t DEFAULT_CAPTURE_TIMEOUT_MS = 300000;  // 5 minutes
    
    /// @brief Packet read timeout (milliseconds)
    inline constexpr uint32_t PACKET_READ_TIMEOUT_MS = 1000;
    
    /// @brief TCP reassembly timeout (seconds)
    inline constexpr uint32_t TCP_REASSEMBLY_TIMEOUT_SECS = 300;

    // ========================================================================
    // BUFFER SIZES
    // ========================================================================
    
    /// @brief Ring buffer size
    inline constexpr size_t RING_BUFFER_SIZE = 64 * 1024 * 1024;  // 64MB
    
    /// @brief Packet buffer size
    inline constexpr size_t PACKET_BUFFER_SIZE = 65536;

}  // namespace NetworkCaptureConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
using Hash256 = std::array<uint8_t, 32>;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Capture mode
 */
enum class CaptureMode : uint8_t {
    Passive     = 0,    ///< Passive capture only
    Active      = 1,    ///< Active inspection
    Inline      = 2,    ///< Inline (can modify)
    Mirror      = 3     ///< Port mirror/SPAN
};

/**
 * @brief Capture method
 */
enum class CaptureMethod : uint8_t {
    Auto        = 0,    ///< Automatic selection
    WFP         = 1,    ///< Windows Filtering Platform
    ETW         = 2,    ///< Event Tracing for Windows
    RawSocket   = 3,    ///< Raw sockets
    Npcap       = 4,    ///< Npcap/WinPcap
    Driver      = 5     ///< Custom driver
};

/**
 * @brief Protocol type
 */
enum class ProtocolType : uint8_t {
    Unknown     = 0,
    ICMP        = 1,
    TCP         = 6,
    UDP         = 17,
    ICMPv6      = 58,
    SCTP        = 132
};

/**
 * @brief Application protocol
 */
enum class AppProtocol : uint16_t {
    Unknown     = 0,
    HTTP        = 80,
    HTTPS       = 443,
    DNS         = 53,
    SMTP        = 25,
    SMB         = 445,
    SSH         = 22,
    FTP         = 21,
    RDP         = 3389,
    IRC         = 6667,
    Custom      = 65535
};

/**
 * @brief Capture format
 */
enum class CaptureFormat : uint8_t {
    PCAP        = 0,    ///< Classic PCAP
    PCAPNG      = 1,    ///< PCAP Next Generation
    ShadowStrike= 2,    ///< Encrypted SS format
    NetFlow     = 3,    ///< NetFlow records
    JSON        = 4     ///< JSON log format
};

/**
 * @brief Capture status
 */
enum class CaptureStatus : uint8_t {
    Idle        = 0,
    Starting    = 1,
    Running     = 2,
    Paused      = 3,
    Stopping    = 4,
    Stopped     = 5,
    Error       = 6
};

/**
 * @brief TCP stream state
 */
enum class TCPStreamState : uint8_t {
    Closed      = 0,
    SynSent     = 1,
    SynReceived = 2,
    Established = 3,
    FinWait1    = 4,
    FinWait2    = 5,
    CloseWait   = 6,
    Closing     = 7,
    LastAck     = 8,
    TimeWait    = 9
};

/**
 * @brief Filter action
 */
enum class FilterAction : uint8_t {
    Capture     = 0,    ///< Capture packet
    Ignore      = 1,    ///< Ignore packet
    Block       = 2,    ///< Block and capture
    Alert       = 3     ///< Alert and capture
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Degraded        = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief IP address (v4 or v6)
 */
struct IPAddress {
    /// @brief Address family (AF_INET or AF_INET6)
    uint16_t family = AF_INET;
    
    /// @brief IPv4 address
    uint32_t v4 = 0;
    
    /// @brief IPv6 address
    std::array<uint8_t, 16> v6{};
    
    /**
     * @brief Create from string
     */
    static std::optional<IPAddress> FromString(std::string_view str);
    
    /**
     * @brief Convert to string
     */
    [[nodiscard]] std::string ToString() const;
    
    /**
     * @brief Check if valid
     */
    [[nodiscard]] bool IsValid() const noexcept;
    
    /**
     * @brief Check if IPv4
     */
    [[nodiscard]] bool IsIPv4() const noexcept { return family == AF_INET; }
    
    /**
     * @brief Check if private address
     */
    [[nodiscard]] bool IsPrivate() const noexcept;
    
    /**
     * @brief Compare addresses
     */
    [[nodiscard]] bool operator==(const IPAddress& other) const noexcept;
};

/**
 * @brief Captured packet
 */
struct CapturedPacket {
    /// @brief Packet ID
    uint64_t packetId = 0;
    
    /// @brief Capture timestamp
    SystemTimePoint timestamp;
    
    /// @brief Source IP
    IPAddress sourceIP;
    
    /// @brief Destination IP
    IPAddress destIP;
    
    /// @brief Source port
    uint16_t sourcePort = 0;
    
    /// @brief Destination port
    uint16_t destPort = 0;
    
    /// @brief Protocol
    ProtocolType protocol = ProtocolType::Unknown;
    
    /// @brief Application protocol
    AppProtocol appProtocol = AppProtocol::Unknown;
    
    /// @brief Source process ID
    uint32_t processId = 0;
    
    /// @brief Packet length
    uint32_t packetLength = 0;
    
    /// @brief Captured length
    uint32_t capturedLength = 0;
    
    /// @brief Packet data
    std::vector<uint8_t> data;
    
    /// @brief Direction (true = outbound)
    bool isOutbound = false;
    
    /// @brief TCP sequence number
    uint32_t tcpSeq = 0;
    
    /// @brief TCP acknowledgment number
    uint32_t tcpAck = 0;
    
    /// @brief TCP flags
    uint8_t tcpFlags = 0;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief TCP stream
 */
struct TCPStream {
    /// @brief Stream ID
    uint64_t streamId = 0;
    
    /// @brief Source endpoint
    IPAddress sourceIP;
    uint16_t sourcePort = 0;
    
    /// @brief Destination endpoint
    IPAddress destIP;
    uint16_t destPort = 0;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Stream state
    TCPStreamState state = TCPStreamState::Closed;
    
    /// @brief Start time
    SystemTimePoint startTime;
    
    /// @brief End time
    SystemTimePoint endTime;
    
    /// @brief Bytes from client
    uint64_t bytesFromClient = 0;
    
    /// @brief Bytes from server
    uint64_t bytesToClient = 0;
    
    /// @brief Packets from client
    uint32_t packetsFromClient = 0;
    
    /// @brief Packets to client
    uint32_t packetsToClient = 0;
    
    /// @brief Reassembled client data
    std::vector<uint8_t> clientData;
    
    /// @brief Reassembled server data
    std::vector<uint8_t> serverData;
    
    /// @brief Application protocol
    AppProtocol appProtocol = AppProtocol::Unknown;
    
    /// @brief TLS SNI hostname
    std::string tlsSNI;
    
    /// @brief HTTP Host header
    std::string httpHost;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief DNS transaction
 */
struct DNSTransaction {
    /// @brief Transaction ID
    uint16_t transactionId = 0;
    
    /// @brief Query timestamp
    SystemTimePoint queryTime;
    
    /// @brief Response timestamp
    SystemTimePoint responseTime;
    
    /// @brief Query domain
    std::string queryDomain;
    
    /// @brief Query type (A, AAAA, etc.)
    uint16_t queryType = 0;
    
    /// @brief Resolved addresses
    std::vector<IPAddress> resolvedAddresses;
    
    /// @brief Source IP
    IPAddress sourceIP;
    
    /// @brief DNS server
    IPAddress dnsServer;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Response code
    uint8_t responseCode = 0;
    
    /// @brief Is suspicious
    bool isSuspicious = false;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Capture filter
 */
struct CaptureFilter {
    /// @brief Filter name
    std::string name;
    
    /// @brief Filter action
    FilterAction action = FilterAction::Capture;
    
    /// @brief Process IDs to capture
    std::vector<uint32_t> processIds;
    
    /// @brief Source IP addresses
    std::vector<IPAddress> sourceIPs;
    
    /// @brief Destination IP addresses
    std::vector<IPAddress> destIPs;
    
    /// @brief Source ports
    std::vector<uint16_t> sourcePorts;
    
    /// @brief Destination ports
    std::vector<uint16_t> destPorts;
    
    /// @brief Protocols
    std::vector<ProtocolType> protocols;
    
    /// @brief Domain patterns
    std::vector<std::string> domainPatterns;
    
    /// @brief BPF filter string (for pcap)
    std::string bpfFilter;
    
    /// @brief Is enabled
    bool isEnabled = true;
    
    /**
     * @brief Match packet against filter
     */
    [[nodiscard]] bool Matches(const CapturedPacket& packet) const;
};

/**
 * @brief SSL key log entry
 */
struct SSLKeyLogEntry {
    /// @brief Key type
    std::string keyType;  // CLIENT_RANDOM, etc.
    
    /// @brief Client random
    std::array<uint8_t, 32> clientRandom{};
    
    /// @brief Master secret or traffic secret
    std::vector<uint8_t> secret;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief Associated stream ID
    uint64_t streamId = 0;
    
    /**
     * @brief Format as SSLKEYLOGFILE line
     */
    [[nodiscard]] std::string ToKeyLogLine() const;
};

/**
 * @brief Capture session
 */
struct CaptureSession {
    /// @brief Session ID
    std::string sessionId;
    
    /// @brief Output path
    std::wstring outputPath;
    
    /// @brief Output format
    CaptureFormat format = CaptureFormat::PCAPNG;
    
    /// @brief Capture method
    CaptureMethod method = CaptureMethod::Auto;
    
    /// @brief Status
    CaptureStatus status = CaptureStatus::Idle;
    
    /// @brief Start time
    SystemTimePoint startTime;
    
    /// @brief End time
    SystemTimePoint endTime;
    
    /// @brief Target process ID (0 = all)
    uint32_t targetPid = 0;
    
    /// @brief Target process name
    std::wstring targetProcessName;
    
    /// @brief Filters
    std::vector<CaptureFilter> filters;
    
    /// @brief Packets captured
    uint64_t packetsCaptured = 0;
    
    /// @brief Bytes captured
    uint64_t bytesCaptured = 0;
    
    /// @brief Packets dropped
    uint64_t packetsDropped = 0;
    
    /// @brief File size
    uint64_t fileSize = 0;
    
    /// @brief Error message
    std::string errorMessage;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Capture configuration
 */
struct NetworkCaptureConfiguration {
    /// @brief Default capture method
    CaptureMethod defaultMethod = CaptureMethod::Auto;
    
    /// @brief Default capture format
    CaptureFormat defaultFormat = CaptureFormat::PCAPNG;
    
    /// @brief Output directory
    std::wstring outputDirectory;
    
    /// @brief Snapshot length
    uint32_t snaplen = NetworkCaptureConstants::DEFAULT_SNAPLEN;
    
    /// @brief Maximum capture file size
    uint64_t maxCaptureSize = NetworkCaptureConstants::MAX_CAPTURE_SIZE;
    
    /// @brief Enable TCP reassembly
    bool enableTCPReassembly = true;
    
    /// @brief Enable SSL key logging
    bool enableSSLKeyLog = false;
    
    /// @brief Enable DNS logging
    bool enableDNSLogging = true;
    
    /// @brief Ring buffer mode
    bool ringBufferMode = false;
    
    /// @brief Ring buffer size
    size_t ringBufferSize = NetworkCaptureConstants::RING_BUFFER_SIZE;
    
    /// @brief Auto-rotate files
    bool autoRotate = true;
    
    /// @brief Rotate size (bytes)
    uint64_t rotateSize = 100 * 1024 * 1024;  // 100MB
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Capture statistics
 */
struct CaptureStatistics {
    /// @brief Total packets captured
    std::atomic<uint64_t> totalPackets{0};
    
    /// @brief Total bytes captured
    std::atomic<uint64_t> totalBytes{0};
    
    /// @brief Packets dropped
    std::atomic<uint64_t> droppedPackets{0};
    
    /// @brief TCP streams tracked
    std::atomic<uint64_t> tcpStreams{0};
    
    /// @brief DNS transactions
    std::atomic<uint64_t> dnsTransactions{0};
    
    /// @brief SSL sessions
    std::atomic<uint64_t> sslSessions{0};
    
    /// @brief Active captures
    std::atomic<uint32_t> activeCaptures{0};
    
    /// @brief Start time
    TimePoint startTime = Clock::now();
    
    /**
     * @brief Reset statistics
     */
    void Reset() noexcept;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/// @brief Packet callback
using PacketCallback = std::function<void(const CapturedPacket&)>;

/// @brief Stream callback
using StreamCallback = std::function<void(const TCPStream&)>;

/// @brief DNS callback
using DNSCallback = std::function<void(const DNSTransaction&)>;

/// @brief Status callback
using CaptureStatusCallback = std::function<void(const CaptureSession&)>;

// ============================================================================
// NETWORK CAPTURE ENGINE CLASS
// ============================================================================

/**
 * @class NetworkCapture
 * @brief Enterprise-grade network traffic capture engine
 *
 * Provides comprehensive network capture capabilities for forensic analysis
 * of malicious network communications.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& capture = NetworkCapture::Instance();
 *     
 *     // Start capture for specific process
 *     if (capture.StartCapture(pid, L"C:\\Evidence\\malware.pcapng")) {
 *         // Capture running...
 *         capture.StopCapture();
 *     }
 * @endcode
 */
class NetworkCapture final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static NetworkCapture& Instance() noexcept;
    
    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    // Non-copyable, non-movable
    NetworkCapture(const NetworkCapture&) = delete;
    NetworkCapture& operator=(const NetworkCapture&) = delete;
    NetworkCapture(NetworkCapture&&) = delete;
    NetworkCapture& operator=(NetworkCapture&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initialize network capture
     */
    [[nodiscard]] bool Initialize(const NetworkCaptureConfiguration& config = {});
    
    /**
     * @brief Shutdown network capture
     */
    void Shutdown();
    
    /**
     * @brief Check if initialized
     */
    [[nodiscard]] bool IsInitialized() const noexcept;
    
    /**
     * @brief Get current status
     */
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    // ========================================================================
    // CAPTURE CONTROL
    // ========================================================================
    
    /**
     * @brief Start capturing traffic for a specific PID
     */
    [[nodiscard]] bool StartCapture(uint32_t pid, const std::wstring& outputPath);
    
    /**
     * @brief Start capture with options
     */
    [[nodiscard]] std::string StartCapture(uint32_t pid, std::wstring_view outputPath,
                                           CaptureFormat format = CaptureFormat::PCAPNG,
                                           const std::vector<CaptureFilter>& filters = {});
    
    /**
     * @brief Start capture for all traffic
     */
    [[nodiscard]] std::string StartCapture(std::wstring_view outputPath,
                                           const std::vector<CaptureFilter>& filters);
    
    /**
     * @brief Stop the capture
     */
    void StopCapture();
    
    /**
     * @brief Stop specific capture session
     */
    void StopCapture(const std::string& sessionId);
    
    /**
     * @brief Pause capture
     */
    void PauseCapture(const std::string& sessionId);
    
    /**
     * @brief Resume capture
     */
    void ResumeCapture(const std::string& sessionId);
    
    /**
     * @brief Get capture status
     */
    [[nodiscard]] CaptureStatus GetCaptureStatus(const std::string& sessionId) const;
    
    /**
     * @brief Get capture session info
     */
    [[nodiscard]] std::optional<CaptureSession> GetSession(const std::string& sessionId) const;
    
    /**
     * @brief Get all active sessions
     */
    [[nodiscard]] std::vector<CaptureSession> GetActiveSessions() const;
    
    // ========================================================================
    // FILTER MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Add capture filter
     */
    [[nodiscard]] bool AddFilter(const std::string& sessionId, const CaptureFilter& filter);
    
    /**
     * @brief Remove capture filter
     */
    [[nodiscard]] bool RemoveFilter(const std::string& sessionId, const std::string& filterName);
    
    /**
     * @brief Clear all filters
     */
    void ClearFilters(const std::string& sessionId);
    
    /**
     * @brief Get filters for session
     */
    [[nodiscard]] std::vector<CaptureFilter> GetFilters(const std::string& sessionId) const;
    
    // ========================================================================
    // STREAM TRACKING
    // ========================================================================
    
    /**
     * @brief Get TCP streams
     */
    [[nodiscard]] std::vector<TCPStream> GetTCPStreams(const std::string& sessionId) const;
    
    /**
     * @brief Get stream by ID
     */
    [[nodiscard]] std::optional<TCPStream> GetStream(uint64_t streamId) const;
    
    /**
     * @brief Get streams for process
     */
    [[nodiscard]] std::vector<TCPStream> GetStreamsForProcess(uint32_t pid) const;
    
    // ========================================================================
    // DNS LOGGING
    // ========================================================================
    
    /**
     * @brief Get DNS transactions
     */
    [[nodiscard]] std::vector<DNSTransaction> GetDNSTransactions(
        const std::string& sessionId) const;
    
    /**
     * @brief Get DNS transactions for domain
     */
    [[nodiscard]] std::vector<DNSTransaction> GetDNSForDomain(
        std::string_view domain) const;
    
    // ========================================================================
    // SSL KEY LOGGING
    // ========================================================================
    
    /**
     * @brief Get SSL key log entries
     */
    [[nodiscard]] std::vector<SSLKeyLogEntry> GetSSLKeyLog(
        const std::string& sessionId) const;
    
    /**
     * @brief Export SSL key log file
     */
    [[nodiscard]] bool ExportSSLKeyLog(const std::string& sessionId,
                                       std::wstring_view outputPath);
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Set packet callback
     */
    void SetPacketCallback(PacketCallback callback);
    
    /**
     * @brief Set stream callback
     */
    void SetStreamCallback(StreamCallback callback);
    
    /**
     * @brief Set DNS callback
     */
    void SetDNSCallback(DNSCallback callback);
    
    /**
     * @brief Set status callback
     */
    void SetStatusCallback(CaptureStatusCallback callback);
    
    // ========================================================================
    // ANALYSIS
    // ========================================================================
    
    /**
     * @brief Detect beaconing patterns
     */
    [[nodiscard]] std::vector<std::pair<IPAddress, double>> DetectBeaconing(
        const std::string& sessionId, uint32_t minIntervalMs = 1000);
    
    /**
     * @brief Detect DNS tunneling
     */
    [[nodiscard]] std::vector<std::string> DetectDNSTunneling(
        const std::string& sessionId);
    
    /**
     * @brief Get connection summary
     */
    [[nodiscard]] std::vector<std::tuple<IPAddress, uint16_t, uint64_t>> 
        GetConnectionSummary(const std::string& sessionId) const;
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    /**
     * @brief Get statistics
     */
    [[nodiscard]] CaptureStatistics GetStatistics() const;
    
    /**
     * @brief Get session statistics
     */
    [[nodiscard]] std::optional<CaptureStatistics> GetSessionStatistics(
        const std::string& sessionId) const;
    
    /**
     * @brief Reset statistics
     */
    void ResetStatistics();
    
    // ========================================================================
    // UTILITY
    // ========================================================================
    
    /**
     * @brief Check if WFP is available
     */
    [[nodiscard]] bool IsWFPAvailable() const;
    
    /**
     * @brief Check if Npcap is available
     */
    [[nodiscard]] bool IsNpcapAvailable() const;
    
    /**
     * @brief Get available interfaces
     */
    [[nodiscard]] std::vector<std::pair<std::string, std::wstring>> GetInterfaces() const;
    
    /**
     * @brief Self-test
     */
    [[nodiscard]] bool SelfTest();
    
    /**
     * @brief Get version string
     */
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR
    // ========================================================================
    
    NetworkCapture();
    ~NetworkCapture();
    
    // ========================================================================
    // PIMPL
    // ========================================================================
    
    std::unique_ptr<NetworkCaptureImpl> m_impl;
    
    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================
    
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get capture mode name
 */
[[nodiscard]] std::string_view GetCaptureModeName(CaptureMode mode) noexcept;

/**
 * @brief Get capture method name
 */
[[nodiscard]] std::string_view GetCaptureMethodName(CaptureMethod method) noexcept;

/**
 * @brief Get protocol name
 */
[[nodiscard]] std::string_view GetProtocolName(ProtocolType protocol) noexcept;

/**
 * @brief Get application protocol name
 */
[[nodiscard]] std::string_view GetAppProtocolName(AppProtocol protocol) noexcept;

/**
 * @brief Get capture format name
 */
[[nodiscard]] std::string_view GetCaptureFormatName(CaptureFormat format) noexcept;

/**
 * @brief Get capture format extension
 */
[[nodiscard]] std::wstring_view GetCaptureFormatExtension(CaptureFormat format) noexcept;

/**
 * @brief Get capture status name
 */
[[nodiscard]] std::string_view GetCaptureStatusName(CaptureStatus status) noexcept;

/**
 * @brief Get TCP state name
 */
[[nodiscard]] std::string_view GetTCPStateName(TCPStreamState state) noexcept;

}  // namespace Forensics
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

/**
 * @brief Start capture for process
 */
#define SS_START_CAPTURE(pid, path) \
    ::ShadowStrike::Forensics::NetworkCapture::Instance().StartCapture((pid), (path))

/**
 * @brief Stop capture
 */
#define SS_STOP_CAPTURE() \
    ::ShadowStrike::Forensics::NetworkCapture::Instance().StopCapture()
