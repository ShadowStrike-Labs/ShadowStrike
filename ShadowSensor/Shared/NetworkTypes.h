/**
 * ============================================================================
 * ShadowStrike NGAV - NETWORK MONITORING TYPES
 * ============================================================================
 *
 * @file NetworkTypes.h
 * @brief Network monitoring data structures for kernel<->user communication.
 *
 * This file defines all data structures used for WFP network filtering,
 * C2 detection, DNS monitoring, and data exfiltration prevention
 * between the kernel driver and user-mode analysis engine.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_NETWORK_TYPES_H
#define SHADOWSTRIKE_NETWORK_TYPES_H

#ifdef _KERNEL_MODE
    #include <fltKernel.h>
#else
    #include <windows.h>
#endif

#include "SharedDefs.h"

// ============================================================================
// NETWORK CONSTANTS
// ============================================================================

#define MAX_HOSTNAME_LENGTH         256
#define MAX_URL_LENGTH              2048
#define MAX_DNS_NAME_LENGTH         256
#define MAX_JA3_FINGERPRINT_LENGTH  64
#define MAX_USER_AGENT_LENGTH       512
#define MAX_DNS_ANSWERS             16
#define MAX_HTTP_HEADER_LENGTH      4096

// Well-known ports
#define PORT_HTTP                   80
#define PORT_HTTPS                  443
#define PORT_DNS                    53
#define PORT_DNS_OVER_TLS           853
#define PORT_SMB                    445
#define PORT_RDP                    3389
#define PORT_SSH                    22
#define PORT_FTP                    21
#define PORT_TELNET                 23
#define PORT_SMTP                   25
#define PORT_POP3                   110
#define PORT_IMAP                   143
#define PORT_LDAP                   389
#define PORT_LDAPS                  636

// ============================================================================
// NETWORK EVENT TYPES
// ============================================================================

/**
 * @brief Network event types.
 */
typedef enum _NETWORK_EVENT_TYPE {
    NetworkEvent_None = 0,
    
    // Connection events
    NetworkEvent_Connect,                 // Outbound connection
    NetworkEvent_ConnectComplete,         // Connection established
    NetworkEvent_Listen,                  // Inbound listener created
    NetworkEvent_Accept,                  // Inbound connection accepted
    NetworkEvent_Disconnect,              // Connection closed
    
    // Data events
    NetworkEvent_DataSend,                // Data sent
    NetworkEvent_DataReceive,             // Data received
    
    // DNS events
    NetworkEvent_DnsQuery,                // DNS query
    NetworkEvent_DnsResponse,             // DNS response
    
    // Protocol events
    NetworkEvent_HttpRequest,             // HTTP request
    NetworkEvent_HttpResponse,            // HTTP response
    NetworkEvent_TlsHandshake,            // TLS handshake
    
    // Suspicious events
    NetworkEvent_PortScan,                // Port scan detected
    NetworkEvent_Beaconing,               // Beaconing detected
    NetworkEvent_DataExfiltration,        // Exfiltration detected
    NetworkEvent_C2Communication,         // C2 detected
    NetworkEvent_DNSTunneling,            // DNS tunneling detected
    
    // Administrative
    NetworkEvent_Block,                   // Connection blocked
    NetworkEvent_Allow,                   // Connection allowed (logged)
    
    NetworkEvent_Max
} NETWORK_EVENT_TYPE;

/**
 * @brief Network protocol types.
 */
typedef enum _NETWORK_PROTOCOL {
    NetworkProtocol_Unknown = 0,
    NetworkProtocol_TCP,
    NetworkProtocol_UDP,
    NetworkProtocol_ICMP,
    NetworkProtocol_ICMPv6,
    NetworkProtocol_SCTP,
    NetworkProtocol_Max
} NETWORK_PROTOCOL;

/**
 * @brief Network direction.
 */
typedef enum _NETWORK_DIRECTION {
    NetworkDirection_Unknown = 0,
    NetworkDirection_Inbound,
    NetworkDirection_Outbound,
    NetworkDirection_Max
} NETWORK_DIRECTION;

/**
 * @brief Connection state.
 */
typedef enum _CONNECTION_STATE {
    ConnectionState_Unknown = 0,
    ConnectionState_Connecting,
    ConnectionState_Connected,
    ConnectionState_Listening,
    ConnectionState_Closing,
    ConnectionState_Closed,
    ConnectionState_Blocked,
    ConnectionState_Max
} CONNECTION_STATE;

// ============================================================================
// NETWORK THREAT TYPES
// ============================================================================

/**
 * @brief Network threat indicators.
 */
typedef enum _NETWORK_THREAT_TYPE {
    NetworkThreat_None = 0,
    
    // C2 Communication
    NetworkThreat_C2_Generic,
    NetworkThreat_C2_CobaltStrike,
    NetworkThreat_C2_Meterpreter,
    NetworkThreat_C2_Empire,
    NetworkThreat_C2_Covenant,
    NetworkThreat_C2_PoshC2,
    
    // DNS-based threats
    NetworkThreat_DNS_Tunneling,
    NetworkThreat_DNS_DGA,                // Domain Generation Algorithm
    NetworkThreat_DNS_FastFlux,
    NetworkThreat_DNS_Exfiltration,
    
    // Protocol anomalies
    NetworkThreat_Protocol_Anomaly,
    NetworkThreat_Port_Scan,
    NetworkThreat_Lateral_Movement,
    NetworkThreat_Data_Exfiltration,
    
    // Connection anomalies
    NetworkThreat_Beaconing,
    NetworkThreat_LongConnection,
    NetworkThreat_HighFrequency,
    NetworkThreat_Tor_Exit,
    NetworkThreat_Proxy_Chain,
    
    // Reputation-based
    NetworkThreat_Bad_Reputation,
    NetworkThreat_Newly_Registered,       // NRD
    NetworkThreat_Known_Malicious,
    NetworkThreat_Suspicious_TLS,
    
    NetworkThreat_Max
} NETWORK_THREAT_TYPE;

// ============================================================================
// IP ADDRESS STRUCTURES
// ============================================================================

#pragma pack(push, 1)

/**
 * @brief IPv4 address structure.
 */
typedef struct _SS_IPV4_ADDRESS {
    union {
        UINT32 Address;
        UINT8 Bytes[4];
    };
} SS_IPV4_ADDRESS, *PSS_IPV4_ADDRESS;

/**
 * @brief IPv6 address structure.
 */
typedef struct _SS_IPV6_ADDRESS {
    union {
        UINT8 Bytes[16];
        UINT16 Words[8];
        UINT32 DWords[4];
    };
} SS_IPV6_ADDRESS, *PSS_IPV6_ADDRESS;

/**
 * @brief Generic IP address (v4 or v6).
 */
typedef struct _SS_IP_ADDRESS {
    UINT16 Family;                        // AF_INET or AF_INET6
    UINT16 Reserved;
    union {
        SS_IPV4_ADDRESS V4;
        SS_IPV6_ADDRESS V6;
    };
} SS_IP_ADDRESS, *PSS_IP_ADDRESS;

/**
 * @brief Socket address (IP + port).
 */
typedef struct _SS_SOCKET_ADDRESS {
    SS_IP_ADDRESS Address;
    UINT16 Port;
    UINT16 Reserved;
} SS_SOCKET_ADDRESS, *PSS_SOCKET_ADDRESS;

// ============================================================================
// NETWORK EVENT STRUCTURES
// ============================================================================

/**
 * @brief Base network event header.
 */
typedef struct _NETWORK_EVENT_HEADER {
    UINT32 Size;                          // Total structure size
    UINT32 Version;                       // Structure version
    UINT64 Timestamp;                     // Event timestamp
    UINT64 MessageId;                     // Unique message ID
    NETWORK_EVENT_TYPE EventType;         // Event type
    NETWORK_PROTOCOL Protocol;            // Protocol
    NETWORK_DIRECTION Direction;          // Direction
    UINT32 ProcessId;
    UINT32 ThreadId;
    UINT32 ParentProcessId;
    UINT32 Flags;
} NETWORK_EVENT_HEADER, *PNETWORK_EVENT_HEADER;

// Network event flags
#define NET_FLAG_BLOCKED                  0x00000001
#define NET_FLAG_ENCRYPTED                0x00000002
#define NET_FLAG_INTERNAL                 0x00000004  // Internal network
#define NET_FLAG_LOOPBACK                 0x00000008
#define NET_FLAG_MULTICAST                0x00000010
#define NET_FLAG_BROADCAST                0x00000020
#define NET_FLAG_HIGH_PRIORITY            0x00000040
#define NET_FLAG_REQUIRES_VERDICT         0x00000080
#define NET_FLAG_SUSPICIOUS               0x00000100
#define NET_FLAG_KNOWN_MALICIOUS          0x00000200

/**
 * @brief Network connection event.
 */
typedef struct _NETWORK_CONNECTION_EVENT {
    NETWORK_EVENT_HEADER Header;
    
    // Connection endpoints
    SS_SOCKET_ADDRESS LocalAddress;
    SS_SOCKET_ADDRESS RemoteAddress;
    
    // Connection state
    CONNECTION_STATE State;
    UINT32 ConnectionFlags;
    
    // Connection ID for correlation
    UINT64 ConnectionId;
    UINT64 FlowId;                        // WFP flow ID
    
    // Process info
    WCHAR ProcessImagePath[MAX_FILE_PATH_LENGTH];
    
    // Domain info (if resolved)
    WCHAR RemoteHostname[MAX_HOSTNAME_LENGTH];
    
    // Analysis
    UINT32 ThreatScore;
    NETWORK_THREAT_TYPE ThreatType;
    UINT32 ReputationScore;               // 0-100 (100 = trusted)
    UINT32 Reserved;
} NETWORK_CONNECTION_EVENT, *PNETWORK_CONNECTION_EVENT;

// Connection flags
#define CONN_FLAG_NEW_DOMAIN              0x00000001  // Newly registered domain
#define CONN_FLAG_RARE_PORT               0x00000002  // Unusual port
#define CONN_FLAG_FOREIGN_GEO             0x00000004  // Foreign country
#define CONN_FLAG_TOR_EXIT                0x00000008  // Tor exit node
#define CONN_FLAG_VPN_EXIT                0x00000010  // VPN exit
#define CONN_FLAG_CLOUD_PROVIDER          0x00000020  // Cloud hosting
#define CONN_FLAG_CDN                     0x00000040  // CDN network
#define CONN_FLAG_KNOWN_SERVICE           0x00000080  // Known service (Google, etc.)
#define CONN_FLAG_FIRST_CONTACT           0x00000100  // First time contacting
#define CONN_FLAG_LATE_NIGHT              0x00000200  // Outside business hours

/**
 * @brief DNS query/response event.
 */
typedef struct _NETWORK_DNS_EVENT {
    NETWORK_EVENT_HEADER Header;
    
    // DNS transaction
    UINT16 TransactionId;
    UINT16 QueryType;                     // A, AAAA, TXT, MX, etc.
    UINT16 QueryClass;
    UINT16 ResponseCode;                  // NOERROR, NXDOMAIN, etc.
    
    // Query details
    WCHAR QueryName[MAX_DNS_NAME_LENGTH];
    UINT32 QueryNameLength;
    UINT32 Flags;
    
    // Response details (if response)
    UINT32 AnswerCount;
    UINT32 TTL;
    
    // Resolved addresses (for A/AAAA)
    SS_IP_ADDRESS ResolvedAddresses[MAX_DNS_ANSWERS];
    UINT32 ResolvedAddressCount;
    
    // TXT record content (for TXT queries - potential tunneling)
    UINT8 TxtData[256];
    UINT32 TxtDataLength;
    
    // Analysis
    UINT32 ThreatScore;
    NETWORK_THREAT_TYPE ThreatType;
    UINT32 DGAScore;                      // DGA likelihood (0-100)
    UINT32 EntropyScore;                  // Domain entropy * 100
    BOOLEAN IsDGA;
    BOOLEAN IsNewlyRegistered;
    BOOLEAN IsFastFlux;
    BOOLEAN IsTunneling;
    
    // Process info
    WCHAR ProcessImagePath[MAX_FILE_PATH_LENGTH];
} NETWORK_DNS_EVENT, *PNETWORK_DNS_EVENT;

// DNS query types
#define DNS_TYPE_A                        1
#define DNS_TYPE_NS                       2
#define DNS_TYPE_CNAME                    5
#define DNS_TYPE_SOA                      6
#define DNS_TYPE_PTR                      12
#define DNS_TYPE_MX                       15
#define DNS_TYPE_TXT                      16
#define DNS_TYPE_AAAA                     28
#define DNS_TYPE_SRV                      33
#define DNS_TYPE_ANY                      255

// DNS flags
#define DNS_FLAG_RECURSIVE                0x00000001
#define DNS_FLAG_TRUNCATED                0x00000002
#define DNS_FLAG_AUTHORITATIVE            0x00000004
#define DNS_FLAG_CACHED                   0x00000008
#define DNS_FLAG_DNSSEC                   0x00000010
#define DNS_FLAG_DOH                      0x00000020  // DNS over HTTPS
#define DNS_FLAG_DOT                      0x00000040  // DNS over TLS

/**
 * @brief Data transfer event (send/receive).
 */
typedef struct _NETWORK_DATA_EVENT {
    NETWORK_EVENT_HEADER Header;
    
    // Connection info
    UINT64 ConnectionId;
    UINT64 FlowId;
    SS_SOCKET_ADDRESS LocalAddress;
    SS_SOCKET_ADDRESS RemoteAddress;
    
    // Data info
    UINT64 BytesTransferred;
    UINT64 TotalBytesInFlow;              // Cumulative
    UINT32 PacketCount;
    UINT32 Flags;
    
    // Data sample (first N bytes)
    UINT8 DataSample[256];
    UINT32 DataSampleSize;
    UINT32 DataEntropy;                   // Entropy * 1000
    
    // Content analysis
    BOOLEAN IsEncrypted;
    BOOLEAN IsCompressed;
    BOOLEAN HasPEHeader;
    BOOLEAN HasScriptContent;
    BOOLEAN HasEncodedContent;            // Base64, etc.
    UINT8 Reserved[3];
    
    // Analysis
    UINT32 ThreatScore;
    NETWORK_THREAT_TYPE ThreatType;
    
    WCHAR ProcessImagePath[MAX_FILE_PATH_LENGTH];
} NETWORK_DATA_EVENT, *PNETWORK_DATA_EVENT;

// Data event flags
#define DATA_FLAG_FIRST_PACKET            0x00000001
#define DATA_FLAG_LAST_PACKET             0x00000002
#define DATA_FLAG_LARGE_TRANSFER          0x00000004  // > threshold
#define DATA_FLAG_SENSITIVE_DATA          0x00000008  // DLP match
#define DATA_FLAG_ENCODED                 0x00000010  // Base64/hex encoded
#define DATA_FLAG_COMPRESSED              0x00000020
#define DATA_FLAG_ENCRYPTED               0x00000040
#define DATA_FLAG_BINARY                  0x00000080  // Binary content
#define DATA_FLAG_EXECUTABLE              0x00000100  // PE/ELF/Mach-O

/**
 * @brief TLS handshake event (for JA3 fingerprinting).
 */
typedef struct _NETWORK_TLS_EVENT {
    NETWORK_EVENT_HEADER Header;
    
    // Connection info
    UINT64 ConnectionId;
    SS_SOCKET_ADDRESS LocalAddress;
    SS_SOCKET_ADDRESS RemoteAddress;
    
    // TLS details
    UINT16 TLSVersion;                    // 0x0301=1.0, 0x0302=1.1, 0x0303=1.2, 0x0304=1.3
    UINT16 CipherSuite;
    UINT16 CompressionMethod;
    UINT16 Flags;
    
    // Extensions
    UINT16 ExtensionCount;
    UINT16 SupportedVersionsCount;
    UINT16 EllipticCurvesCount;
    UINT16 ECPointFormatsCount;
    
    // SNI (Server Name Indication)
    WCHAR ServerName[MAX_HOSTNAME_LENGTH];
    
    // JA3/JA3S fingerprints
    CHAR JA3Fingerprint[MAX_JA3_FINGERPRINT_LENGTH];    // Client fingerprint
    CHAR JA3SFingerprint[MAX_JA3_FINGERPRINT_LENGTH];   // Server fingerprint
    UINT8 JA3Hash[16];                    // MD5 of JA3
    UINT8 JA3SHash[16];                   // MD5 of JA3S
    
    // Certificate info (server)
    WCHAR CertSubject[256];
    WCHAR CertIssuer[256];
    UINT64 CertNotBefore;
    UINT64 CertNotAfter;
    BOOLEAN CertSelfSigned;
    BOOLEAN CertExpired;
    BOOLEAN CertRevoked;
    BOOLEAN CertMismatch;                 // Name mismatch
    
    // Analysis
    UINT32 ThreatScore;
    NETWORK_THREAT_TYPE ThreatType;
    BOOLEAN IsKnownMaliciousJA3;
    BOOLEAN IsSuspiciousCertificate;
    UINT16 Reserved2;
    
    WCHAR ProcessImagePath[MAX_FILE_PATH_LENGTH];
} NETWORK_TLS_EVENT, *PNETWORK_TLS_EVENT;

// TLS flags
#define TLS_FLAG_CLIENT_HELLO             0x0001
#define TLS_FLAG_SERVER_HELLO             0x0002
#define TLS_FLAG_CERTIFICATE              0x0004
#define TLS_FLAG_HANDSHAKE_COMPLETE       0x0008
#define TLS_FLAG_SESSION_RESUMED          0x0010
#define TLS_FLAG_EARLY_DATA               0x0020  // TLS 1.3 0-RTT
#define TLS_FLAG_ALPN_HTTP2               0x0040  // HTTP/2
#define TLS_FLAG_ALPN_HTTP3               0x0080  // HTTP/3

// ============================================================================
// C2 DETECTION STRUCTURES
// ============================================================================

/**
 * @brief Beaconing detection data.
 */
typedef struct _BEACONING_DATA {
    UINT64 ConnectionId;
    UINT64 FirstSeen;
    UINT64 LastSeen;
    UINT32 BeaconCount;
    UINT32 AverageIntervalMs;
    UINT32 IntervalStdDevMs;              // Standard deviation
    UINT32 JitterPercent;
    UINT32 AveragePayloadSize;
    UINT32 PayloadSizeVariance;
    BOOLEAN IsRegularInterval;
    BOOLEAN HasJitter;
    UINT16 Reserved;
} BEACONING_DATA, *PBEACONING_DATA;

/**
 * @brief C2 detection event.
 */
typedef struct _NETWORK_C2_EVENT {
    NETWORK_EVENT_HEADER Header;
    
    // Connection info
    UINT64 ConnectionId;
    SS_SOCKET_ADDRESS LocalAddress;
    SS_SOCKET_ADDRESS RemoteAddress;
    WCHAR RemoteHostname[MAX_HOSTNAME_LENGTH];
    
    // C2 indicators
    NETWORK_THREAT_TYPE C2Type;
    UINT32 ConfidenceScore;               // 0-100
    UINT32 ThreatScore;
    UINT32 IndicatorCount;
    
    // Beaconing analysis
    BEACONING_DATA BeaconingData;
    
    // Protocol analysis
    BOOLEAN UsesHTTP;
    BOOLEAN UsesHTTPS;
    BOOLEAN UsesDNS;
    BOOLEAN UsesCustomProtocol;
    BOOLEAN HasEncodedPayloads;
    BOOLEAN HasEncryptedPayloads;
    UINT16 Reserved;
    
    // JA3 match (if TLS)
    CHAR JA3Fingerprint[MAX_JA3_FINGERPRINT_LENGTH];
    BOOLEAN JA3MatchesKnownC2;
    UINT8 Reserved2[3];
    
    // Sample data
    UINT8 PayloadSample[256];
    UINT32 PayloadSampleSize;
    
    WCHAR ProcessImagePath[MAX_FILE_PATH_LENGTH];
    WCHAR CommandLine[MAX_COMMAND_LINE_LENGTH];
} NETWORK_C2_EVENT, *PNETWORK_C2_EVENT;

/**
 * @brief DNS tunneling detection event.
 */
typedef struct _NETWORK_DNS_TUNNEL_EVENT {
    NETWORK_EVENT_HEADER Header;
    
    // DNS server
    SS_IP_ADDRESS DnsServer;
    
    // Tunnel analysis
    UINT32 QueryCount;                    // Queries to this domain
    UINT32 TxtQueryCount;                 // TXT queries
    UINT32 AverageSubdomainLength;
    UINT32 MaxSubdomainLength;
    UINT32 EntropyScore;                  // Average entropy * 100
    UINT32 UniqueSubdomains;
    
    // Time analysis
    UINT64 FirstQueryTime;
    UINT64 LastQueryTime;
    UINT32 QueriesPerMinute;
    UINT32 Reserved;
    
    // Base domain
    WCHAR BaseDomain[MAX_DNS_NAME_LENGTH];
    
    // Sample queries
    WCHAR SampleQueries[4][MAX_DNS_NAME_LENGTH];
    UINT32 SampleQueryCount;
    
    // Analysis
    UINT32 ThreatScore;
    UINT32 ConfidenceScore;
    BOOLEAN IsConfirmedTunneling;
    UINT8 Reserved2[3];
    
    WCHAR ProcessImagePath[MAX_FILE_PATH_LENGTH];
} NETWORK_DNS_TUNNEL_EVENT, *PNETWORK_DNS_TUNNEL_EVENT;

// ============================================================================
// DATA EXFILTRATION STRUCTURES
// ============================================================================

/**
 * @brief Data exfiltration detection event.
 */
typedef struct _NETWORK_EXFIL_EVENT {
    NETWORK_EVENT_HEADER Header;
    
    // Connection info
    UINT64 ConnectionId;
    SS_SOCKET_ADDRESS LocalAddress;
    SS_SOCKET_ADDRESS RemoteAddress;
    WCHAR RemoteHostname[MAX_HOSTNAME_LENGTH];
    
    // Exfiltration analysis
    UINT64 TotalBytesSent;
    UINT64 TotalBytesReceived;
    UINT32 UploadDownloadRatio;           // Ratio * 100
    UINT64 DataRateBytes;                 // Bytes per second
    UINT32 Duration;                      // Connection duration (seconds)
    UINT32 Flags;
    
    // Content analysis
    BOOLEAN ContainsSensitiveData;
    BOOLEAN ContainsCredentials;
    BOOLEAN ContainsPII;
    BOOLEAN ContainsSourceCode;
    BOOLEAN IsCompressed;
    BOOLEAN IsEncrypted;
    BOOLEAN UsesEncoding;                 // Base64, etc.
    UINT8 Reserved;
    
    // DLP matches
    UINT32 DLPMatchCount;
    WCHAR DLPRuleNames[4][64];            // First 4 matched rules
    
    // Analysis
    UINT32 ThreatScore;
    UINT32 ConfidenceScore;
    
    WCHAR ProcessImagePath[MAX_FILE_PATH_LENGTH];
    WCHAR SourceFilePath[MAX_FILE_PATH_LENGTH];  // If file exfiltration
} NETWORK_EXFIL_EVENT, *PNETWORK_EXFIL_EVENT;

// Exfiltration flags
#define EXFIL_FLAG_HIGH_VOLUME            0x00000001
#define EXFIL_FLAG_UNUSUAL_DEST           0x00000002
#define EXFIL_FLAG_UNUSUAL_TIME           0x00000004
#define EXFIL_FLAG_UNUSUAL_PROTOCOL       0x00000008
#define EXFIL_FLAG_DLP_MATCH              0x00000010
#define EXFIL_FLAG_CLOUD_STORAGE          0x00000020
#define EXFIL_FLAG_FILE_SHARING           0x00000040
#define EXFIL_FLAG_EMAIL                  0x00000080
#define EXFIL_FLAG_USB_FOLLOWED           0x00000100  // Followed USB access

// ============================================================================
// NETWORK BLOCKING STRUCTURES
// ============================================================================

/**
 * @brief Network block event.
 */
typedef struct _NETWORK_BLOCK_EVENT {
    NETWORK_EVENT_HEADER Header;
    
    // Connection info
    SS_SOCKET_ADDRESS LocalAddress;
    SS_SOCKET_ADDRESS RemoteAddress;
    WCHAR RemoteHostname[MAX_HOSTNAME_LENGTH];
    
    // Block reason
    UINT32 BlockReason;                   // NETWORK_BLOCK_REASON
    UINT32 BlockRuleId;                   // Rule that triggered block
    WCHAR BlockRuleName[64];
    
    // Threat info
    UINT32 ThreatScore;
    NETWORK_THREAT_TYPE ThreatType;
    
    // Process info
    WCHAR ProcessImagePath[MAX_FILE_PATH_LENGTH];
    WCHAR CommandLine[MAX_COMMAND_LINE_LENGTH];
} NETWORK_BLOCK_EVENT, *PNETWORK_BLOCK_EVENT;

// Block reasons
typedef enum _NETWORK_BLOCK_REASON {
    BlockReason_None = 0,
    BlockReason_Reputation,               // Bad reputation
    BlockReason_C2Detection,              // C2 detected
    BlockReason_DNSTunneling,             // DNS tunneling
    BlockReason_Exfiltration,             // Data exfiltration
    BlockReason_MaliciousIP,              // Known malicious IP
    BlockReason_MaliciousDomain,          // Known malicious domain
    BlockReason_PolicyViolation,          // Policy rule
    BlockReason_RateLimiting,             // Rate limiting
    BlockReason_GeoBlock,                 // Geographic block
    BlockReason_PortBlock,                // Blocked port
    BlockReason_ProcessBlock,             // Process not allowed
    BlockReason_Max
} NETWORK_BLOCK_REASON;

#pragma pack(pop)

// ============================================================================
// NETWORK MONITORING CONFIGURATION
// ============================================================================

/**
 * @brief Network monitoring configuration.
 */
typedef struct _NETWORK_MONITOR_CONFIG {
    // Feature toggles
    BOOLEAN EnableConnectionMonitoring;
    BOOLEAN EnableDnsMonitoring;
    BOOLEAN EnableDataInspection;
    BOOLEAN EnableTlsInspection;
    BOOLEAN EnableC2Detection;
    BOOLEAN EnableExfiltrationDetection;
    BOOLEAN EnableDnsTunnelingDetection;
    BOOLEAN EnablePortScanDetection;
    
    // Thresholds
    UINT32 BeaconMinSamples;              // Min samples for beaconing
    UINT32 BeaconJitterThreshold;         // Max jitter %
    UINT32 ExfiltrationThresholdMB;       // Exfil threshold
    UINT32 DnsQueryRateThreshold;         // Queries per minute
    UINT32 PortScanThreshold;             // Unique ports per minute
    
    // Rate limiting
    UINT32 MaxEventsPerSecond;
    UINT32 MaxConnectionsPerProcess;
    
    // Sampling
    UINT32 DataSampleSize;                // Bytes to sample
    UINT32 DataSampleInterval;            // Sample every N packets
    
    UINT32 Reserved[4];
} NETWORK_MONITOR_CONFIG, *PNETWORK_MONITOR_CONFIG;

// ============================================================================
// HELPER MACROS AND FUNCTIONS
// ============================================================================

/**
 * @brief Check if IP is IPv4.
 */
#define SS_IS_IPV4(addr) ((addr)->Family == 2)  // AF_INET

/**
 * @brief Check if IP is IPv6.
 */
#define SS_IS_IPV6(addr) ((addr)->Family == 23) // AF_INET6

/**
 * @brief Check if IP is loopback.
 */
#define SS_IS_LOOPBACK_V4(addr) \
    (SS_IS_IPV4(addr) && (addr)->V4.Bytes[0] == 127)

/**
 * @brief Check if IP is private (RFC 1918).
 */
#define SS_IS_PRIVATE_V4(addr) \
    (SS_IS_IPV4(addr) && \
     ((addr)->V4.Bytes[0] == 10 || \
      ((addr)->V4.Bytes[0] == 172 && ((addr)->V4.Bytes[1] & 0xF0) == 16) || \
      ((addr)->V4.Bytes[0] == 192 && (addr)->V4.Bytes[1] == 168)))

/**
 * @brief Check if port is well-known.
 */
#define SS_IS_WELL_KNOWN_PORT(port) ((port) < 1024)

/**
 * @brief Check if threat is C2-related.
 */
#define SS_IS_C2_THREAT(type) \
    ((type) >= NetworkThreat_C2_Generic && (type) <= NetworkThreat_C2_PoshC2)

#endif // SHADOWSTRIKE_NETWORK_TYPES_H
