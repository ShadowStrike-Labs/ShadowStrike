/**
 * ============================================================================
 * ShadowStrike Core Network - TRAFFIC ANALYZER (The Spectrometer)
 * ============================================================================
 *
 * @file TrafficAnalyzer.hpp
 * @brief Enterprise-grade deep packet inspection and protocol analysis engine.
 *
 * This module provides comprehensive network traffic analysis through Deep
 * Packet Inspection (DPI), protocol identification, payload analysis, and
 * threat detection in network streams.
 *
 * Key Capabilities:
 * =================
 * 1. PROTOCOL IDENTIFICATION
 *    - Automatic protocol detection (50+ protocols)
 *    - Port-independent identification
 *    - Protocol tunneling detection
 *    - Encrypted protocol fingerprinting
 *    - Custom protocol definitions
 *
 * 2. TLS/SSL INSPECTION
 *    - Certificate extraction and validation
 *    - JA3/JA3S fingerprinting
 *    - Server Name Indication (SNI) extraction
 *    - Cipher suite analysis
 *    - Certificate chain validation
 *    - ALPN protocol detection
 *
 * 3. PAYLOAD ANALYSIS
 *    - Shellcode detection
 *    - Encoded payload identification
 *    - File type detection in streams
 *    - Malware signature scanning
 *    - Data pattern recognition
 *    - Compression detection
 *
 * 4. ANOMALY DETECTION
 *    - Protocol anomalies
 *    - Traffic pattern anomalies
 *    - Timing anomalies
 *    - Size anomalies
 *    - Behavioral anomalies
 *
 * 5. METADATA EXTRACTION
 *    - HTTP headers and methods
 *    - SMTP envelope information
 *    - DNS query/response details
 *    - SMB file operations
 *    - RDP session info
 *
 * 6. STREAM REASSEMBLY
 *    - TCP stream reassembly
 *    - HTTP request/response pairing
 *    - Fragmented packet handling
 *    - Out-of-order packet handling
 *
 * DPI Architecture:
 * =================
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                       TrafficAnalyzer                               │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │PacketDecoder │  │StreamReassm  │  │    ProtocolParser        │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - L2/L3/L4   │  │ - TCP Streams│  │ - HTTP/HTTPS             │  │
 *   │  │ - Headers    │  │ - UDP Flows  │  │ - DNS/SMB/RDP            │  │
 *   │  │ - Checksums  │  │ - Fragments  │  │ - SSH/FTP/SMTP           │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │TLSInspector  │  │PayloadAnalyz │  │    AnomalyDetector       │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - JA3/JA3S   │  │ - Shellcode  │  │ - Protocol Anomaly       │  │
 *   │  │ - Certs      │  │ - Signatures │  │ - Pattern Anomaly        │  │
 *   │  │ - SNI        │  │ - FileType   │  │ - Timing Anomaly         │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * Supported Protocols:
 * ====================
 * Layer 7: HTTP, HTTPS, DNS, SMB, RDP, SSH, FTP, SMTP, IMAP, POP3,
 *          LDAP, Kerberos, NTP, SNMP, SIP, RTSP, MySQL, PostgreSQL,
 *          MSSQL, MongoDB, Redis, MQTT, AMQP, gRPC, WebSocket
 * Layer 4: TCP, UDP, SCTP
 * Layer 3: IPv4, IPv6, ICMP, ICMPv6
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1071: Application Layer Protocol
 * - T1573: Encrypted Channel
 * - T1572: Protocol Tunneling
 * - T1001: Data Obfuscation
 * - T1095: Non-Application Layer Protocol
 * - T1132: Data Encoding
 *
 * Thread Safety:
 * ==============
 * - All public methods are thread-safe
 * - Stream state is per-connection
 * - Concurrent packet processing supported
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see NetworkMonitor.hpp for packet capture
 * @see PatternStore for signature matching
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/NetworkUtils.hpp"       // Network utilities
#include "../../Utils/HashUtils.hpp"          // JA3 hash computation
#include "../../Utils/CertUtils.hpp"          // Certificate extraction
#include "../../PatternStore/PatternStore.hpp" // Protocol/shellcode patterns
#include "../../SignatureStore/SignatureStore.hpp" // Malware signatures
#include "../../ThreatIntel/ThreatIntelLookup.hpp"  // IP/domain reputation

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <set>
#include <queue>
#include <optional>
#include <variant>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <shared_mutex>
#include <span>

namespace ShadowStrike {
namespace Core {
namespace Network {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class TrafficAnalyzerImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace TrafficAnalyzerConstants {

    // Version
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Stream limits
    constexpr size_t MAX_STREAM_SIZE = 100ULL * 1024 * 1024;   // 100 MB max stream
    constexpr size_t MAX_PACKET_SIZE = 65535;                   // Max IP packet
    constexpr size_t MAX_ACTIVE_STREAMS = 100000;               // Concurrent streams
    constexpr size_t MAX_FRAGMENTS_PER_STREAM = 1000;
    constexpr uint32_t STREAM_TIMEOUT_MS = 300000;              // 5 minutes

    // Analysis limits
    constexpr size_t MAX_PAYLOAD_SCAN = 1024 * 1024;            // 1 MB payload scan
    constexpr size_t MIN_PROTOCOL_BYTES = 4;                    // Min for identification
    constexpr size_t MAX_HTTP_HEADER_SIZE = 64 * 1024;          // 64 KB headers
    constexpr size_t MAX_CERT_CHAIN_LENGTH = 10;

    // Detection thresholds
    constexpr double SHELLCODE_THRESHOLD = 0.8;
    constexpr size_t SHELLCODE_MIN_SIZE = 50;
    constexpr double ANOMALY_THRESHOLD = 3.0;                   // Standard deviations

    // JA3 constants
    constexpr size_t JA3_HASH_SIZE = 32;                        // MD5 hex string

}  // namespace TrafficAnalyzerConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum Protocol
 * @brief Identified network protocol.
 */
enum class Protocol : uint16_t {
    UNKNOWN = 0,

    // Core protocols
    TCP = 1,
    UDP = 2,
    ICMP = 3,
    ICMPv6 = 4,

    // Web protocols
    HTTP = 10,
    HTTPS = 11,
    HTTP2 = 12,
    HTTP3_QUIC = 13,
    WEBSOCKET = 14,
    WEBSOCKET_SECURE = 15,

    // Email protocols
    SMTP = 20,
    SMTPS = 21,
    POP3 = 22,
    POP3S = 23,
    IMAP = 24,
    IMAPS = 25,

    // File transfer
    FTP = 30,
    FTP_DATA = 31,
    FTPS = 32,
    SFTP = 33,
    SCP = 34,
    TFTP = 35,

    // Directory/Auth
    LDAP = 40,
    LDAPS = 41,
    KERBEROS = 42,
    RADIUS = 43,
    NTLM = 44,

    // Name services
    DNS = 50,
    DNS_OVER_TLS = 51,
    DNS_OVER_HTTPS = 52,
    MDNS = 53,
    LLMNR = 54,
    NETBIOS = 55,

    // Remote access
    SSH = 60,
    TELNET = 61,
    RDP = 62,
    VNC = 63,
    XDMCP = 64,

    // Windows protocols
    SMB = 70,
    SMB2 = 71,
    SMB3 = 72,
    MSRPC = 73,
    DCOM = 74,
    WINRM = 75,

    // Database protocols
    MYSQL = 80,
    POSTGRESQL = 81,
    MSSQL = 82,
    ORACLE_TNS = 83,
    MONGODB = 84,
    REDIS = 85,
    MEMCACHED = 86,
    ELASTICSEARCH = 87,
    CASSANDRA = 88,

    // Messaging
    MQTT = 90,
    AMQP = 91,
    KAFKA = 92,
    ZMTP = 93,  // ZeroMQ

    // Streaming
    RTSP = 100,
    RTP = 101,
    RTCP = 102,
    SIP = 103,
    H323 = 104,

    // Network management
    SNMP = 110,
    NTP = 111,
    SYSLOG = 112,
    DHCP = 113,
    BOOTP = 114,

    // VPN/Tunnel
    OPENVPN = 120,
    WIREGUARD = 121,
    IPSEC_IKE = 122,
    IPSEC_ESP = 123,
    GRE = 124,
    L2TP = 125,
    PPTP = 126,

    // P2P/Anonymous
    BITTORRENT = 130,
    TOR = 131,
    I2P = 132,

    // Cryptocurrency
    BITCOIN = 140,
    ETHEREUM = 141,
    STRATUM = 142,  // Mining

    // RPC
    GRPC = 150,
    THRIFT = 151,
    AVRO = 152,

    // Industrial
    MODBUS = 160,
    DNOP3 = 161,
    BACNET = 162,
    OPC_UA = 163,

    // Custom/Unknown encrypted
    TLS_UNKNOWN = 200,          // TLS with unknown application protocol
    ENCRYPTED_UNKNOWN = 201,
    CUSTOM = 255
};

/**
 * @enum TLSVersion
 * @brief TLS protocol version.
 */
enum class TLSVersion : uint16_t {
    UNKNOWN = 0,
    SSL_3_0 = 0x0300,
    TLS_1_0 = 0x0301,
    TLS_1_1 = 0x0302,
    TLS_1_2 = 0x0303,
    TLS_1_3 = 0x0304
};

/**
 * @enum PayloadType
 * @brief Type of payload detected.
 */
enum class PayloadType : uint8_t {
    UNKNOWN = 0,
    TEXT = 1,
    BINARY = 2,
    COMPRESSED = 3,
    ENCRYPTED = 4,
    EXECUTABLE = 5,
    SHELLCODE = 6,
    ENCODED_BASE64 = 7,
    ENCODED_HEX = 8,
    ENCODED_XOR = 9,
    FILE_ARCHIVE = 10,
    FILE_DOCUMENT = 11,
    FILE_IMAGE = 12,
    FILE_SCRIPT = 13,
    STRUCTURED_JSON = 14,
    STRUCTURED_XML = 15,
    STRUCTURED_PROTOBUF = 16
};

/**
 * @enum AnomalyType
 * @brief Type of traffic anomaly.
 */
enum class AnomalyType : uint8_t {
    NONE = 0,
    PROTOCOL_VIOLATION = 1,    // Protocol spec violation
    UNEXPECTED_PORT = 2,       // Protocol on unexpected port
    UNUSUAL_SIZE = 3,          // Abnormal packet/stream size
    TIMING_ANOMALY = 4,        // Suspicious timing patterns
    HEADER_ANOMALY = 5,        // Malformed/unusual headers
    ENCODING_ANOMALY = 6,      // Unusual encoding
    FRAGMENTATION = 7,         // Unusual fragmentation
    TUNNELING = 8,             // Protocol tunneling detected
    COVERT_CHANNEL = 9,        // Potential covert channel
    EXFILTRATION = 10          // Potential data exfiltration
};

/**
 * @enum ThreatIndicator
 * @brief Threat indicator from traffic analysis.
 */
enum class ThreatIndicator : uint8_t {
    NONE = 0,
    SHELLCODE_DETECTED = 1,
    MALWARE_SIGNATURE = 2,
    EXPLOIT_PATTERN = 3,
    C2_PATTERN = 4,
    EXFILTRATION_PATTERN = 5,
    BEACONING = 6,
    SUSPICIOUS_TLS = 7,
    KNOWN_BAD_JA3 = 8,
    CREDENTIAL_THEFT = 9,
    LATERAL_MOVEMENT = 10
};

/**
 * @enum HTTPMethod
 * @brief HTTP request methods.
 */
enum class HTTPMethod : uint8_t {
    UNKNOWN = 0,
    GET = 1,
    POST = 2,
    PUT = 3,
    DELETE = 4,
    HEAD = 5,
    OPTIONS = 6,
    PATCH = 7,
    CONNECT = 8,
    TRACE = 9
};

/**
 * @enum StreamState
 * @brief State of a TCP stream.
 */
enum class StreamState : uint8_t {
    NEW = 0,
    ESTABLISHING = 1,
    ESTABLISHED = 2,
    DATA_TRANSFER = 3,
    CLOSING = 4,
    CLOSED = 5,
    TIMEOUT = 6,
    ERROR = 7
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct PacketInfo
 * @brief Parsed packet information.
 */
struct alignas(64) PacketInfo {
    // Raw data
    std::span<const uint8_t> rawData;
    size_t captureLength{ 0 };
    size_t wireLength{ 0 };

    // Timing
    std::chrono::system_clock::time_point timestamp;

    // Layer 2
    std::array<uint8_t, 6> srcMac{ 0 };
    std::array<uint8_t, 6> dstMac{ 0 };
    uint16_t etherType{ 0 };
    uint16_t vlanId{ 0 };
    bool hasVlan{ false };

    // Layer 3
    bool isIPv6{ false };
    std::array<uint8_t, 16> srcIP{ 0 };
    std::array<uint8_t, 16> dstIP{ 0 };
    uint8_t ipVersion{ 0 };
    uint8_t ttl{ 0 };
    uint8_t protocol{ 0 };              // IP protocol number
    uint16_t ipId{ 0 };
    uint16_t fragmentOffset{ 0 };
    bool moreFragments{ false };
    bool dontFragment{ false };

    // Layer 4
    uint16_t srcPort{ 0 };
    uint16_t dstPort{ 0 };

    // TCP specific
    uint32_t tcpSeq{ 0 };
    uint32_t tcpAck{ 0 };
    uint16_t tcpWindow{ 0 };
    uint8_t tcpFlags{ 0 };
    bool tcpSyn{ false };
    bool tcpAck_flag{ false };
    bool tcpFin{ false };
    bool tcpRst{ false };
    bool tcpPsh{ false };
    bool tcpUrg{ false };

    // UDP specific
    uint16_t udpLength{ 0 };

    // Payload
    std::span<const uint8_t> payload;
    size_t payloadOffset{ 0 };
    size_t payloadLength{ 0 };

    // Validation
    bool isValid{ false };
    bool checksumValid{ false };
    std::string parseError;
};

/**
 * @struct StreamKey
 * @brief Key identifying a network stream.
 */
struct alignas(32) StreamKey {
    std::array<uint8_t, 16> srcIP{ 0 };
    std::array<uint8_t, 16> dstIP{ 0 };
    uint16_t srcPort{ 0 };
    uint16_t dstPort{ 0 };
    uint8_t protocol{ 0 };
    bool isIPv6{ false };

    bool operator==(const StreamKey& other) const noexcept;

    struct Hash {
        size_t operator()(const StreamKey& key) const noexcept;
    };
};

/**
 * @struct JA3Fingerprint
 * @brief TLS client fingerprint.
 */
struct alignas(64) JA3Fingerprint {
    std::string hash;                    // MD5 hash
    std::string rawString;               // Full fingerprint string

    // Components
    TLSVersion version{ TLSVersion::UNKNOWN };
    std::vector<uint16_t> cipherSuites;
    std::vector<uint16_t> extensions;
    std::vector<uint16_t> ellipticCurves;
    std::vector<uint8_t> ecPointFormats;

    // Identification
    std::string identifiedClient;        // If known
    bool isKnownMalicious{ false };
    std::string malwareFamily;
};

/**
 * @struct JA3SFingerprint
 * @brief TLS server fingerprint.
 */
struct alignas(64) JA3SFingerprint {
    std::string hash;
    std::string rawString;

    TLSVersion version{ TLSVersion::UNKNOWN };
    uint16_t selectedCipher{ 0 };
    std::vector<uint16_t> extensions;

    std::string identifiedServer;
    bool isKnownMalicious{ false };
};

/**
 * @struct CertificateInfo
 * @brief Extracted certificate information.
 */
struct alignas(128) CertificateInfo {
    // Subject
    std::string commonName;
    std::string organization;
    std::string organizationalUnit;
    std::string country;
    std::string state;
    std::string locality;

    // Issuer
    std::string issuerCN;
    std::string issuerOrg;

    // Validity
    std::chrono::system_clock::time_point notBefore;
    std::chrono::system_clock::time_point notAfter;
    bool isExpired{ false };
    bool isNotYetValid{ false };

    // Identifiers
    std::string serialNumber;
    std::string sha256Fingerprint;
    std::string sha1Fingerprint;

    // Extensions
    std::vector<std::string> subjectAltNames;
    std::string keyUsage;
    std::string extKeyUsage;
    bool isCA{ false };
    int32_t pathLength{ -1 };

    // Validation
    bool isSelfSigned{ false };
    bool isRevoked{ false };
    bool chainValid{ false };
    std::string validationError;
};

/**
 * @struct TLSInfo
 * @brief Complete TLS session information.
 */
struct alignas(256) TLSInfo {
    // Version and cipher
    TLSVersion version{ TLSVersion::UNKNOWN };
    uint16_t cipherSuite{ 0 };
    std::string cipherSuiteName;

    // Server Name Indication
    std::string sni;

    // ALPN
    std::string alpnProtocol;

    // Fingerprints
    JA3Fingerprint ja3;
    JA3SFingerprint ja3s;

    // Certificates
    std::vector<CertificateInfo> certificateChain;

    // Session info
    std::array<uint8_t, 32> sessionId{ 0 };
    bool isResumption{ false };
    bool hasEarlyData{ false };           // TLS 1.3 0-RTT

    // Security assessment
    bool isSecure{ true };
    std::vector<std::string> securityIssues;
    uint8_t securityScore{ 0 };           // 0-100
};

/**
 * @struct HTTPInfo
 * @brief HTTP request/response information.
 */
struct alignas(128) HTTPInfo {
    // Request
    HTTPMethod method{ HTTPMethod::UNKNOWN };
    std::string uri;
    std::string host;
    std::string userAgent;
    std::string referer;
    std::string contentType;
    uint64_t contentLength{ 0 };
    std::string httpVersion;

    // Headers
    std::unordered_map<std::string, std::string> headers;

    // Response
    uint16_t statusCode{ 0 };
    std::string statusText;
    std::string serverHeader;

    // Body info
    bool hasBody{ false };
    bool isChunked{ false };
    bool isCompressed{ false };
    std::string encoding;

    // Security
    bool hasXSSHeaders{ false };
    bool hasCSPHeader{ false };
    bool hasHSTSHeader{ false };
};

/**
 * @struct DNSInfo
 * @brief DNS query/response information.
 */
struct alignas(64) DNSInfo {
    uint16_t transactionId{ 0 };
    bool isQuery{ true };
    bool isRecursive{ false };
    uint8_t responseCode{ 0 };

    struct Question {
        std::string name;
        uint16_t type{ 0 };
        uint16_t qclass{ 0 };
    };
    std::vector<Question> questions;

    struct ResourceRecord {
        std::string name;
        uint16_t type{ 0 };
        uint16_t rclass{ 0 };
        uint32_t ttl{ 0 };
        std::string rdata;
    };
    std::vector<ResourceRecord> answers;
    std::vector<ResourceRecord> authorities;
    std::vector<ResourceRecord> additionals;
};

/**
 * @struct SMBInfo
 * @brief SMB/CIFS session information.
 */
struct alignas(64) SMBInfo {
    uint8_t version{ 0 };                 // 1, 2, or 3
    uint64_t sessionId{ 0 };
    uint32_t treeId{ 0 };
    uint32_t messageId{ 0 };

    std::string shareName;
    std::string fileName;
    std::string command;

    bool isRequest{ true };
    uint32_t status{ 0 };
};

/**
 * @struct PayloadAnalysis
 * @brief Analysis of packet payload.
 */
struct alignas(64) PayloadAnalysis {
    PayloadType type{ PayloadType::UNKNOWN };
    size_t size{ 0 };

    // Entropy
    double entropy{ 0.0 };
    bool isHighEntropy{ false };

    // File detection
    std::string detectedMimeType;
    std::string detectedFileType;
    std::array<uint8_t, 32> fileSha256{ 0 };

    // Pattern matches
    std::vector<std::string> matchedSignatures;
    bool hasShellcode{ false };
    double shellcodeScore{ 0.0 };

    // Encoding detection
    bool isBase64{ false };
    bool isHexEncoded{ false };
    bool isPossiblyXORed{ false };
    uint8_t likelyXORKey{ 0 };
};

/**
 * @struct StreamInfo
 * @brief Complete stream analysis.
 */
struct alignas(256) StreamInfo {
    // Identity
    uint64_t streamId{ 0 };
    StreamKey key;
    StreamState state{ StreamState::NEW };

    // Protocol
    Protocol identifiedProtocol{ Protocol::UNKNOWN };
    std::string protocolDetails;
    bool isEncrypted{ false };

    // Timing
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point lastActivity;
    std::chrono::milliseconds duration{ 0 };

    // Statistics
    uint64_t packetsClient{ 0 };
    uint64_t packetsServer{ 0 };
    uint64_t bytesClient{ 0 };
    uint64_t bytesServer{ 0 };
    uint32_t retransmissions{ 0 };

    // Protocol-specific info
    std::optional<TLSInfo> tlsInfo;
    std::optional<HTTPInfo> httpInfo;
    std::optional<DNSInfo> dnsInfo;
    std::optional<SMBInfo> smbInfo;

    // Payload analysis
    PayloadAnalysis payloadAnalysis;

    // Anomalies
    std::vector<AnomalyType> anomalies;
    std::vector<ThreatIndicator> threats;
    uint8_t riskScore{ 0 };               // 0-100

    // Metadata
    std::unordered_map<std::string, std::string> metadata;
};

/**
 * @struct AnalysisResult
 * @brief Result from packet analysis.
 */
struct alignas(128) AnalysisResult {
    // Packet info
    PacketInfo packet;
    uint64_t streamId{ 0 };

    // Protocol
    Protocol protocol{ Protocol::UNKNOWN };
    bool newProtocolIdentified{ false };

    // Threats
    std::vector<ThreatIndicator> threats;
    std::vector<std::string> signatures;
    uint8_t threatScore{ 0 };

    // Anomalies
    std::vector<AnomalyType> anomalies;

    // Extracted data
    std::optional<TLSInfo> tlsInfo;
    std::optional<HTTPInfo> httpInfo;
    std::optional<DNSInfo> dnsInfo;
    PayloadAnalysis payloadAnalysis;

    // Processing info
    std::chrono::microseconds analysisTime{ 0 };
    bool analysisComplete{ false };
};

/**
 * @struct TrafficAnalyzerConfig
 * @brief Configuration for traffic analyzer.
 */
struct alignas(64) TrafficAnalyzerConfig {
    // Feature toggles
    bool enabled{ true };
    bool enableProtocolDetection{ true };
    bool enableTLSInspection{ true };
    bool enablePayloadAnalysis{ true };
    bool enableAnomalyDetection{ true };
    bool enableStreamReassembly{ true };
    bool enableShellcodeDetection{ true };
    bool enableSignatureScanning{ true };

    // Limits
    size_t maxStreamSize{ TrafficAnalyzerConstants::MAX_STREAM_SIZE };
    size_t maxPayloadScan{ TrafficAnalyzerConstants::MAX_PAYLOAD_SCAN };
    uint32_t streamTimeoutMs{ TrafficAnalyzerConstants::STREAM_TIMEOUT_MS };
    size_t maxActiveStreams{ TrafficAnalyzerConstants::MAX_ACTIVE_STREAMS };

    // TLS settings
    bool extractCertificates{ true };
    bool validateCertChain{ true };
    bool checkJA3Reputation{ true };

    // Performance
    bool useThreadPool{ true };
    uint32_t workerThreads{ 4 };
    bool enableCaching{ true };

    // Logging
    bool logAllStreams{ false };
    bool logThreatsOnly{ true };
    bool logTLSInfo{ false };

    // Factory methods
    static TrafficAnalyzerConfig CreateDefault() noexcept;
    static TrafficAnalyzerConfig CreateHighSecurity() noexcept;
    static TrafficAnalyzerConfig CreatePerformance() noexcept;
    static TrafficAnalyzerConfig CreateForensic() noexcept;
};

/**
 * @struct TrafficAnalyzerStatistics
 * @brief Runtime statistics.
 */
struct alignas(128) TrafficAnalyzerStatistics {
    // Packet statistics
    std::atomic<uint64_t> totalPackets{ 0 };
    std::atomic<uint64_t> packetsAnalyzed{ 0 };
    std::atomic<uint64_t> packetsDropped{ 0 };
    std::atomic<uint64_t> bytesProcessed{ 0 };

    // Stream statistics
    std::atomic<uint64_t> totalStreams{ 0 };
    std::atomic<uint32_t> activeStreams{ 0 };
    std::atomic<uint64_t> streamsTimedOut{ 0 };

    // Protocol statistics
    std::atomic<uint64_t> httpStreams{ 0 };
    std::atomic<uint64_t> httpsStreams{ 0 };
    std::atomic<uint64_t> dnsPackets{ 0 };
    std::atomic<uint64_t> smbStreams{ 0 };
    std::atomic<uint64_t> unknownProtocols{ 0 };

    // Detection statistics
    std::atomic<uint64_t> threatsDetected{ 0 };
    std::atomic<uint64_t> anomaliesDetected{ 0 };
    std::atomic<uint64_t> shellcodeDetected{ 0 };
    std::atomic<uint64_t> signaturesMatched{ 0 };

    // TLS statistics
    std::atomic<uint64_t> tlsHandshakes{ 0 };
    std::atomic<uint64_t> certsExtracted{ 0 };
    std::atomic<uint64_t> ja3Fingerprints{ 0 };
    std::atomic<uint64_t> maliciousJA3{ 0 };

    // Performance
    std::atomic<uint64_t> avgAnalysisTimeUs{ 0 };
    std::atomic<uint64_t> maxAnalysisTimeUs{ 0 };

    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Callback for packet analysis.
 */
using PacketAnalysisCallback = std::function<void(const AnalysisResult& result)>;

/**
 * @brief Callback for stream events.
 */
using StreamCallback = std::function<void(const StreamInfo& stream, bool isNew)>;

/**
 * @brief Callback for protocol detection.
 */
using ProtocolDetectionCallback = std::function<void(
    uint64_t streamId,
    Protocol protocol,
    const StreamInfo& stream
)>;

/**
 * @brief Callback for threat detection.
 */
using ThreatCallback = std::function<void(
    uint64_t streamId,
    ThreatIndicator threat,
    const AnalysisResult& result
)>;

/**
 * @brief Callback for TLS events.
 */
using TLSCallback = std::function<void(
    uint64_t streamId,
    const TLSInfo& tlsInfo
)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class TrafficAnalyzer
 * @brief Enterprise-grade deep packet inspection and protocol analysis.
 *
 * Thread Safety:
 * All public methods are thread-safe. Concurrent packet processing supported.
 *
 * Usage Example:
 * @code
 * auto& analyzer = TrafficAnalyzer::Instance();
 * 
 * // Initialize
 * auto config = TrafficAnalyzerConfig::CreateHighSecurity();
 * analyzer.Initialize(config);
 * 
 * // Register threat callback
 * analyzer.RegisterThreatCallback(
 *     [](uint64_t streamId, ThreatIndicator threat, const auto& result) {
 *         HandleThreat(streamId, threat);
 *     }
 * );
 * 
 * // Analyze packets
 * analyzer.AnalyzePacket(packetData);
 * @endcode
 */
class TrafficAnalyzer {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    static TrafficAnalyzer& Instance();

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initializes the traffic analyzer.
     * @param config Configuration settings.
     * @return True if successful.
     */
    bool Initialize(const TrafficAnalyzerConfig& config);

    /**
     * @brief Starts analysis threads.
     * @return True if started.
     */
    bool Start();

    /**
     * @brief Stops analysis threads.
     */
    void Stop();

    /**
     * @brief Shuts down and releases resources.
     */
    void Shutdown() noexcept;

    /**
     * @brief Checks if running.
     * @return True if active.
     */
    [[nodiscard]] bool IsRunning() const noexcept;

    // ========================================================================
    // PACKET ANALYSIS
    // ========================================================================

    /**
     * @brief Analyze a raw network packet.
     * @param packet Raw packet data.
     */
    void AnalyzePacket(const std::vector<uint8_t>& packet);

    /**
     * @brief Analyze packet with timestamp.
     * @param packet Raw packet data.
     * @param timestamp Capture timestamp.
     * @return Analysis result.
     */
    [[nodiscard]] AnalysisResult AnalyzePacket(
        std::span<const uint8_t> packet,
        std::chrono::system_clock::time_point timestamp
    );

    /**
     * @brief Batch analyze packets.
     * @param packets Vector of raw packets.
     * @return Vector of results.
     */
    [[nodiscard]] std::vector<AnalysisResult> AnalyzePackets(
        const std::vector<std::vector<uint8_t>>& packets
    );

    // ========================================================================
    // STREAM MANAGEMENT
    // ========================================================================

    /**
     * @brief Gets stream information.
     * @param streamId Stream ID.
     * @return Stream info, or nullopt.
     */
    [[nodiscard]] std::optional<StreamInfo> GetStream(uint64_t streamId) const;

    /**
     * @brief Gets all active streams.
     * @return Vector of active streams.
     */
    [[nodiscard]] std::vector<StreamInfo> GetActiveStreams() const;

    /**
     * @brief Gets streams by protocol.
     * @param protocol Protocol to filter.
     * @return Matching streams.
     */
    [[nodiscard]] std::vector<StreamInfo> GetStreamsByProtocol(Protocol protocol) const;

    /**
     * @brief Terminates a stream.
     * @param streamId Stream to terminate.
     */
    void TerminateStream(uint64_t streamId);

    /**
     * @brief Clears all streams.
     */
    void ClearAllStreams();

    // ========================================================================
    // PROTOCOL DETECTION
    // ========================================================================

    /**
     * @brief Identifies protocol from payload.
     * @param payload Payload data.
     * @param srcPort Source port.
     * @param dstPort Destination port.
     * @return Identified protocol.
     */
    [[nodiscard]] Protocol IdentifyProtocol(
        std::span<const uint8_t> payload,
        uint16_t srcPort,
        uint16_t dstPort
    ) const;

    /**
     * @brief Gets protocol name.
     * @param protocol Protocol.
     * @return Protocol name.
     */
    [[nodiscard]] static std::string_view GetProtocolName(Protocol protocol) noexcept;

    // ========================================================================
    // TLS ANALYSIS
    // ========================================================================

    /**
     * @brief Extracts TLS information from stream.
     * @param streamId Stream ID.
     * @return TLS info, or nullopt.
     */
    [[nodiscard]] std::optional<TLSInfo> GetTLSInfo(uint64_t streamId) const;

    /**
     * @brief Calculates JA3 fingerprint.
     * @param clientHello Raw ClientHello data.
     * @return JA3 fingerprint.
     */
    [[nodiscard]] JA3Fingerprint CalculateJA3(std::span<const uint8_t> clientHello) const;

    /**
     * @brief Checks if JA3 is known malicious.
     * @param ja3Hash JA3 hash.
     * @return True if malicious.
     */
    [[nodiscard]] bool IsJA3Malicious(const std::string& ja3Hash) const;

    // ========================================================================
    // PAYLOAD ANALYSIS
    // ========================================================================

    /**
     * @brief Analyzes payload.
     * @param payload Payload data.
     * @return Payload analysis.
     */
    [[nodiscard]] PayloadAnalysis AnalyzePayload(std::span<const uint8_t> payload) const;

    /**
     * @brief Detects shellcode in payload.
     * @param payload Payload data.
     * @return Pair of (is_shellcode, confidence).
     */
    [[nodiscard]] std::pair<bool, double> DetectShellcode(
        std::span<const uint8_t> payload
    ) const;

    /**
     * @brief Detects file type from payload.
     * @param payload Payload data.
     * @return MIME type string.
     */
    [[nodiscard]] std::string DetectFileType(std::span<const uint8_t> payload) const;

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    [[nodiscard]] uint64_t RegisterPacketCallback(PacketAnalysisCallback callback);
    [[nodiscard]] uint64_t RegisterStreamCallback(StreamCallback callback);
    [[nodiscard]] uint64_t RegisterProtocolCallback(ProtocolDetectionCallback callback);
    [[nodiscard]] uint64_t RegisterThreatCallback(ThreatCallback callback);
    [[nodiscard]] uint64_t RegisterTLSCallback(TLSCallback callback);
    bool UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const TrafficAnalyzerStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    [[nodiscard]] bool PerformDiagnostics() const;
    bool ExportDiagnostics(const std::wstring& outputPath) const;

private:
    TrafficAnalyzer();
    ~TrafficAnalyzer();

    TrafficAnalyzer(const TrafficAnalyzer&) = delete;
    TrafficAnalyzer& operator=(const TrafficAnalyzer&) = delete;

    std::unique_ptr<TrafficAnalyzerImpl> m_impl;
};

}  // namespace Network
}  // namespace Core
}  // namespace ShadowStrike
