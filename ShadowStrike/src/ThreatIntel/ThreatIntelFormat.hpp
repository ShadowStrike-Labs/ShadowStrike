/*
 * ============================================================================
 * ShadowStrike ThreatIntelFormat - ENTERPRISE-GRADE BINARY FORMAT
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Ultra-high performance binary format definitions for threat intelligence database
 * Memory-mapped I/O with zero-copy reads for sub-microsecond lookups
 * 
 * Target Performance:
 * - IP reputation lookup: < 50ns average (nanosecond-level)
 * - Domain lookup: < 100ns with hash index
 * - URL lookup: < 200ns with Trie index
 * - Hash lookup: < 100ns with B+Tree
 * - Bloom filter pre-check: < 20ns
 * - Batch lookup (1000 items): < 50µs
 *
 * Supported Threat Intelligence Types:
 * - IPv4/IPv6 Addresses (with CIDR notation support)
 * - Domain Names (with subdomain matching)
 * - URLs (full URL and path patterns)
 * - File Hashes (MD5/SHA1/SHA256/SHA512)
 * - Email Addresses (sender reputation)
 * - SSL Certificate Fingerprints
 * - JA3/JA3S TLS Fingerprints
 * - Registry Keys (Windows-specific threats)
 * - MITRE ATT&CK TTPs
 *
 * Data Sources:
 * - VirusTotal (VT) API
 * - AlienVault OTX (Open Threat Exchange)
 * - AbuseIPDB
 * - MISP (Malware Information Sharing Platform)
 * - Shodan
 * - GreyNoise
 * - Pulsedive
 * - ThreatFox
 * - URLhaus
 * - Custom/Internal Feeds
 *
 * Industry Standard Formats:
 * - STIX 2.1 (Structured Threat Information Expression)
 * - TAXII 2.x (Trusted Automated Exchange of Intelligence Information)
 * - OpenIOC
 * - MISP Format
 *
 * File Format Architecture:
 * ┌────────────────────────────────────────────────────────────────────────┐
 * │ ThreatIntelDatabaseHeader (4KB aligned)                                │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │ IPv4 Index Section (Radix Tree, CIDR-aware, page-aligned)             │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │ IPv6 Index Section (Patricia Trie, 128-bit optimized)                 │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │ Domain Index Section (Suffix Trie for reverse DNS matching)           │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │ URL Index Section (Aho-Corasick for pattern matching)                 │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │ Hash Index Section (B+Tree, per hash type buckets)                    │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │ IOC Entry Data Section (Packed threat intel entries)                  │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │ STIX Bundle Section (Serialized STIX 2.1 objects)                     │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │ String Pool Section (Deduplicated string storage)                     │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │ Bloom Filter Section (Per-type bloom filters)                         │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │ Metadata Section (Feed info, update timestamps, API configs)          │
 * └────────────────────────────────────────────────────────────────────────┘
 *
 * Performance Standards: CrowdStrike Falcon / Microsoft Defender ATP quality
 *
 * ============================================================================
 */

#pragma once

#include <cstdint>
#include <cstring>
#include <array>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <span>
#include <chrono>
#include <atomic>
#include <bitset>
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
#  include <WS2tcpip.h>
#endif

namespace ShadowStrike {
namespace ThreatIntel {

// ============================================================================
// CORE CONSTANTS & CONFIGURATION
// ============================================================================

/// @brief Magic number for threat intel database: 'SSTI' = ShadowStrike Threat Intel
constexpr uint32_t THREATINTEL_DB_MAGIC = 0x49545353;  // 'SSTI' in little-endian

/// @brief Current database format version
constexpr uint16_t THREATINTEL_DB_VERSION_MAJOR = 1;
constexpr uint16_t THREATINTEL_DB_VERSION_MINOR = 0;

/// @brief Performance-critical alignment constants
constexpr size_t PAGE_SIZE = 4096;                      // Standard Windows page size
constexpr size_t CACHE_LINE_SIZE = 64;                  // CPU cache line (Intel/AMD x64)
constexpr size_t SECTOR_SIZE = 512;                     // Disk sector alignment
constexpr size_t HUGE_PAGE_SIZE = 2 * 1024 * 1024;     // 2MB huge page for large datasets

/// @brief Index configuration for optimal performance
constexpr size_t BTREE_ORDER = 128;                     // B+Tree node order (cache-optimized)
constexpr size_t RADIX_TREE_FANOUT = 256;              // Full byte range for IP radix tree
constexpr size_t HASH_BUCKET_COUNT = 65536;            // 64K hash table buckets (power of 2)
constexpr size_t BLOOM_FILTER_BITS_PER_ELEMENT = 10;   // ~1% false positive rate

/// @brief Size limits
constexpr size_t MAX_DOMAIN_LENGTH = 253;               // RFC 1035 maximum domain length
constexpr size_t MAX_URL_LENGTH = 2048;                 // Practical URL length limit
constexpr size_t MAX_EMAIL_LENGTH = 254;                // RFC 5321 maximum email length
constexpr size_t MAX_DESCRIPTION_LENGTH = 4096;         // IOC description max length
constexpr size_t MAX_TAGS_PER_IOC = 64;                // Maximum tags per IOC
constexpr size_t MAX_TAG_LENGTH = 64;                   // Individual tag max length
constexpr size_t MAX_FEED_NAME_LENGTH = 128;           // Feed source name max length
constexpr size_t MAX_API_KEY_LENGTH = 256;             // API key max length
constexpr uint64_t MAX_DATABASE_SIZE = 32ULL * 1024 * 1024 * 1024; // 32GB database limit
constexpr uint64_t MAX_IOC_ENTRIES = 1'000'000'000;    // 1 billion IOC entries max

/// @brief Cache configuration
constexpr size_t QUERY_CACHE_SIZE = 131072;             // 128K cache entries
constexpr size_t STRING_POOL_CHUNK_SIZE = 4 * 1024 * 1024; // 4MB string pool chunks
constexpr uint32_t DEFAULT_TTL_SECONDS = 86400;        // 24 hours default TTL
constexpr uint32_t MIN_TTL_SECONDS = 60;               // 1 minute minimum TTL
constexpr uint32_t MAX_TTL_SECONDS = 604800;           // 7 days maximum TTL

/// @brief API rate limiting defaults
constexpr uint32_t DEFAULT_API_RATE_LIMIT = 1000;      // Requests per minute
constexpr uint32_t DEFAULT_API_TIMEOUT_MS = 30000;     // 30 seconds API timeout

// ============================================================================
// IOC (INDICATOR OF COMPROMISE) TYPES
// ============================================================================

/// @brief Type of IOC - determines which index is used for lookup
enum class IOCType : uint8_t {
    /// @brief IPv4 address (with optional CIDR)
    IPv4 = 0,
    
    /// @brief IPv6 address (with optional CIDR prefix)
    IPv6 = 1,
    
    /// @brief Domain name (supports wildcard subdomains)
    Domain = 2,
    
    /// @brief Full URL (protocol + domain + path)
    URL = 3,
    
    /// @brief File hash (MD5/SHA1/SHA256/SHA512)
    FileHash = 4,
    
    /// @brief Email address (sender/recipient reputation)
    Email = 5,
    
    /// @brief SSL/TLS Certificate SHA256 fingerprint
    CertFingerprint = 6,
    
    /// @brief JA3 TLS client fingerprint
    JA3 = 7,
    
    /// @brief JA3S TLS server fingerprint
    JA3S = 8,
    
    /// @brief Windows Registry key/value
    RegistryKey = 9,
    
    /// @brief Process name pattern
    ProcessName = 10,
    
    /// @brief Mutex name (malware indicator)
    MutexName = 11,
    
    /// @brief Named pipe (C2 indicator)
    NamedPipe = 12,
    
    /// @brief User agent string
    UserAgent = 13,
    
    /// @brief ASN (Autonomous System Number)
    ASN = 14,
    
    /// @brief CIDR network range (IPv4)
    CIDRv4 = 15,
    
    /// @brief CIDR network range (IPv6)
    CIDRv6 = 16,
    
    /// @brief YARA rule reference
    YaraRule = 17,
    
    /// @brief Sigma rule reference
    SigmaRule = 18,
    
    /// @brief MITRE ATT&CK Technique ID
    MitreAttack = 19,
    
    /// @brief CVE identifier
    CVE = 20,
    
    /// @brief STIX pattern
    STIXPattern = 21,
    
    /// @brief Unknown or unrecognized IOC type
    /// Used for validation, error handling, and default initialization
    Unknown = 254,
    
    /// @brief Reserved for future use (binary compatibility)
    Reserved = 255
};

/// @brief Get string representation of IOC type
[[nodiscard]] constexpr const char* IOCTypeToString(IOCType type) noexcept {
    switch (type) {
        case IOCType::IPv4:           return "ipv4-addr";
        case IOCType::IPv6:           return "ipv6-addr";
        case IOCType::Domain:         return "domain-name";
        case IOCType::URL:            return "url";
        case IOCType::FileHash:       return "file-hash";
        case IOCType::Email:          return "email-addr";
        case IOCType::CertFingerprint: return "x509-certificate";
        case IOCType::JA3:            return "ja3-fingerprint";
        case IOCType::JA3S:           return "ja3s-fingerprint";
        case IOCType::RegistryKey:    return "windows-registry-key";
        case IOCType::ProcessName:    return "process-name";
        case IOCType::MutexName:      return "mutex";
        case IOCType::NamedPipe:      return "named-pipe";
        case IOCType::UserAgent:      return "user-agent";
        case IOCType::ASN:            return "autonomous-system";
        case IOCType::CIDRv4:         return "ipv4-network";
        case IOCType::CIDRv6:         return "ipv6-network";
        case IOCType::YaraRule:       return "yara-rule";
        case IOCType::SigmaRule:      return "sigma-rule";
        case IOCType::MitreAttack:    return "attack-pattern";
        case IOCType::CVE:            return "vulnerability";
        case IOCType::STIXPattern:    return "stix-pattern";
        case IOCType::Unknown:        return "unknown";
        case IOCType::Reserved:       return "reserved";
        default:                      return "unknown";
    }
}

// ============================================================================
// REPUTATION & THREAT LEVELS
// ============================================================================

/// @brief Reputation score (0-100 scale, higher = more malicious)
/// @note Aligned with industry standards: 0-20 safe, 21-40 suspicious, 41-60 likely malicious, 
///       61-80 malicious, 81-100 critical/confirmed malicious
enum class ReputationLevel : uint8_t {
    /// @brief Verified safe/benign (0-10)
    Safe = 0,
    
    /// @brief Known good but not explicitly verified (11-20)
    Trusted = 10,
    
    /// @brief Unknown reputation (21-30) - treat with caution
    Unknown = 25,
    
    /// @brief Low risk indicators present (31-40)
    LowRisk = 35,
    
    /// @brief Moderate suspicion (41-50)
    Suspicious = 45,
    
    /// @brief High suspicion, likely malicious (51-60)
    HighRisk = 55,
    
    /// @brief Confirmed malicious by multiple sources (61-80)
    Malicious = 70,
    
    /// @brief Critical threat, active exploitation (81-100)
    Critical = 90,
    
    /// @brief Maximum threat level
    Maximum = 100
};

/// @brief Confidence level of the threat intelligence
enum class ConfidenceLevel : uint8_t {
    /// @brief Unverified/raw data (< 20%)
    None = 0,
    
    /// @brief Low confidence (20-40%)
    Low = 25,
    
    /// @brief Medium confidence (40-60%)
    Medium = 50,
    
    /// @brief High confidence (60-80%)
    High = 75,
    
    /// @brief Confirmed by multiple trusted sources (80-100%)
    Confirmed = 95
};

/// @brief Threat category classification (STIX 2.1 compatible)
enum class ThreatCategory : uint16_t {
    /// @brief Unknown/Unclassified
    Unknown = 0,
    
    // Malware categories (1-99)
    Malware = 1,
    Ransomware = 2,
    Trojan = 3,
    Worm = 4,
    Virus = 5,
    Rootkit = 6,
    Bootkit = 7,
    Keylogger = 8,
    Spyware = 9,
    Adware = 10,
    Backdoor = 11,
    RAT = 12,           // Remote Access Trojan
    Dropper = 13,
    Downloader = 14,
    Cryptominer = 15,
    Botnet = 16,
    InfoStealer = 17,
    BankingTrojan = 18,
    Fileless = 19,
    
    // Network threats (100-199)
    C2Server = 100,     // Command & Control
    Phishing = 101,
    MaliciousURL = 102,
    DriveBydDownload = 103,
    Exploit = 104,
    Scanner = 105,
    BruteForce = 106,
    DDoS = 107,
    Spam = 108,
    Tor = 109,
    VPN = 110,
    Proxy = 111,
    
    // Actor categories (200-299)
    APT = 200,          // Advanced Persistent Threat
    Crimeware = 201,
    Hacktivist = 202,
    NationState = 203,
    InsiderThreat = 204,
    
    // Vulnerability exploitation (300-399)
    ExploitKit = 300,
    ZeroDay = 301,
    KnownVulnerability = 302,
    
    // Data exfiltration (400-499)
    DataTheft = 400,
    Exfiltration = 401,
    CredentialHarvesting = 402,
    
    // Evasion techniques (500-599)
    ObfuscatedMalware = 500,
    PackedMalware = 501,
    Polymorphic = 502,
    Metamorphic = 503,
    
    /// @brief Custom category (see description)
    Custom = 65534,
    
    /// @brief Reserved
    Reserved = 65535
};

/// @brief Get STIX 2.1 compatible threat category string
[[nodiscard]] constexpr const char* ThreatCategoryToString(ThreatCategory category) noexcept {
    switch (category) {
        case ThreatCategory::Malware:       return "malware";
        case ThreatCategory::Ransomware:    return "ransomware";
        case ThreatCategory::Trojan:        return "trojan";
        case ThreatCategory::Worm:          return "worm";
        case ThreatCategory::Virus:         return "virus";
        case ThreatCategory::Rootkit:       return "rootkit";
        case ThreatCategory::Backdoor:      return "backdoor";
        case ThreatCategory::RAT:           return "remote-access-trojan";
        case ThreatCategory::Cryptominer:   return "cryptominer";
        case ThreatCategory::Botnet:        return "botnet";
        case ThreatCategory::InfoStealer:   return "information-stealer";
        case ThreatCategory::C2Server:      return "command-and-control";
        case ThreatCategory::Phishing:      return "phishing";
        case ThreatCategory::APT:           return "advanced-persistent-threat";
        case ThreatCategory::ExploitKit:    return "exploit-kit";
        case ThreatCategory::ZeroDay:       return "zero-day";
        default:                            return "unknown";
    }
}

// ============================================================================
// THREAT INTEL SOURCE TYPES
// ============================================================================

/// @brief Source of threat intelligence data
enum class ThreatIntelSource : uint16_t {
    /// @brief Unknown/unspecified source
    Unknown = 0,
    
    // Commercial APIs (1-99)
    VirusTotal = 1,
    CrowdStrike = 2,
    RecordedFuture = 3,
    Mandiant = 4,
    Flashpoint = 5,
    IntelX = 6,
    Shodan = 7,
    Censys = 8,
    BinaryEdge = 9,
    RiskIQ = 10,
    DomainTools = 11,
    PassiveTotal = 12,
    ThreatConnect = 13,
    Anomali = 14,
    
    // Open Source Feeds (100-199)
    AlienVaultOTX = 100,
    AbuseIPDB = 101,
    MISP = 102,
    OpenCTI = 103,
    ThreatFox = 104,
    URLhaus = 105,
    MalwareBazaar = 106,
    Feodo = 107,
    SSLBlacklist = 108,
    EmergingThreats = 109,
    Spamhaus = 110,
    PhishTank = 111,
    OpenPhish = 112,
    Pulsedive = 113,
    GreyNoise = 114,
    BotScout = 115,
    HoneyDB = 116,
    
    // Government/CERT Sources (200-299)
    CISA = 200,
    NIST_NVD = 201,
    MITRE_ATT_CK = 202,
    US_CERT = 203,
    UK_NCSC = 204,
    AU_ACSC = 205,
    
    // Internal Sources (300-399)
    InternalAnalysis = 300,
    SandboxAnalysis = 301,
    MLClassification = 302,
    UserReport = 303,
    HoneypotCapture = 304,
    NetworkForensics = 305,
    EndpointForensics = 306,
    
    // Custom Sources (900-999)
    CustomFeed = 900,
    PartnerFeed = 901,
    CustomerSubmission = 902,
    
    /// @brief Reserved
    Reserved = 65535
};

/// @brief Get source name string
[[nodiscard]] constexpr const char* ThreatIntelSourceToString(ThreatIntelSource source) noexcept {
    switch (source) {
        case ThreatIntelSource::VirusTotal:     return "VirusTotal";
        case ThreatIntelSource::CrowdStrike:    return "CrowdStrike";
        case ThreatIntelSource::AlienVaultOTX:  return "AlienVault OTX";
        case ThreatIntelSource::AbuseIPDB:      return "AbuseIPDB";
        case ThreatIntelSource::MISP:           return "MISP";
        case ThreatIntelSource::ThreatFox:      return "ThreatFox";
        case ThreatIntelSource::URLhaus:        return "URLhaus";
        case ThreatIntelSource::MalwareBazaar:  return "MalwareBazaar";
        case ThreatIntelSource::GreyNoise:      return "GreyNoise";
        case ThreatIntelSource::Shodan:         return "Shodan";
        case ThreatIntelSource::Spamhaus:       return "Spamhaus";
        case ThreatIntelSource::CISA:           return "CISA";
        case ThreatIntelSource::MITRE_ATT_CK:   return "MITRE ATT&CK";
        case ThreatIntelSource::InternalAnalysis: return "Internal Analysis";
        case ThreatIntelSource::CustomFeed:     return "Custom Feed";
        default:                                return "Unknown";
    }
}

// ============================================================================
// INDEX VALUE STRUCTURE
// ============================================================================
/**
 * @brief Generic value stored in index structures.
 * Encapsulates the unique IOC entry ID and its absolute database offset
 * for nanosecond-level direct access. Designed for cache-line efficiency.
 */
struct IndexValue {
    uint64_t entryId{ 0 };      ///< Unique ID of the IOC entry
    uint64_t entryOffset{ 0 };  ///< File offset to the packed entry data

    constexpr IndexValue() noexcept = default;
    constexpr IndexValue(uint64_t id, uint64_t offset) noexcept
        : entryId(id), entryOffset(offset) {
    }

    /**
     * @brief Checks if the value points to a valid database entry.
     * @return true if entryId is non-zero.
     */
    [[nodiscard]] constexpr bool IsValid() const noexcept {
        return entryId != 0;
    }

    /**
     * @brief C++20 Three-way comparison operator (Spaceship operator).
     * Enables automatic generation of all relational operators for sorted containers.
     */
    auto operator<=>(const IndexValue&) const = default;
};
// ============================================================================
// HASH ALGORITHM TYPES
// ============================================================================

/// @brief Hash algorithm type for file hash IOCs
enum class HashAlgorithm : uint8_t {
    MD5 = 0,            ///< 16 bytes - legacy, still widely used
    SHA1 = 1,           ///< 20 bytes - legacy, being phased out
    SHA256 = 2,         ///< 32 bytes - RECOMMENDED standard
    SHA512 = 3,         ///< 64 bytes - high security
    SHA3_256 = 4,       ///< 32 bytes - NIST standard
    SHA3_512 = 5,       ///< 64 bytes - NIST standard
    SSDEEP = 6,         ///< Variable - fuzzy hash
    TLSH = 7,           ///< 70 bytes - locality sensitive
    ImpHash = 8,        ///< 16 bytes - PE import hash
    TypeHash = 9,       ///< 32 bytes - type-based hash
    Authentihash = 10   ///< 32 bytes - PE authenticode hash
};

/// @brief Get expected byte length for hash algorithm
[[nodiscard]] constexpr uint8_t GetHashLength(HashAlgorithm algo) noexcept {
    switch (algo) {
        case HashAlgorithm::MD5:          return 16;
        case HashAlgorithm::SHA1:         return 20;
        case HashAlgorithm::SHA256:       return 32;
        case HashAlgorithm::SHA512:       return 64;
        case HashAlgorithm::SHA3_256:     return 32;
        case HashAlgorithm::SHA3_512:     return 64;
        case HashAlgorithm::SSDEEP:       return 72;  // Max SSDEEP length
        case HashAlgorithm::TLSH:         return 70;
        case HashAlgorithm::ImpHash:      return 16;
        case HashAlgorithm::TypeHash:     return 32;
        case HashAlgorithm::Authentihash: return 32;
        default:                          return 0;
    }
}

/// @brief Get hash algorithm name
[[nodiscard]] constexpr const char* HashAlgorithmToString(HashAlgorithm algo) noexcept {
    switch (algo) {
        case HashAlgorithm::MD5:          return "MD5";
        case HashAlgorithm::SHA1:         return "SHA-1";
        case HashAlgorithm::SHA256:       return "SHA-256";
        case HashAlgorithm::SHA512:       return "SHA-512";
        case HashAlgorithm::SHA3_256:     return "SHA3-256";
        case HashAlgorithm::SHA3_512:     return "SHA3-512";
        case HashAlgorithm::SSDEEP:       return "SSDEEP";
        case HashAlgorithm::TLSH:         return "TLSH";
        case HashAlgorithm::ImpHash:      return "ImpHash";
        case HashAlgorithm::TypeHash:     return "TypeHash";
        case HashAlgorithm::Authentihash: return "Authentihash";
        default:                          return "Unknown";
    }
}

// ============================================================================
// IPV4 ADDRESS STRUCTURE
// ============================================================================

/// @brief IPv4 address with CIDR prefix support (cache-line optimized)
#pragma pack(push, 1)
struct alignas(4) IPv4Address {

    union {
        uint32_t address;               ///< Network byte order (big-endian)
        std::array<uint8_t, 4> octets;  ///< Octets for Radix Tree traversal
    };

    /// @brief CIDR prefix length (0-32, 32 = exact match)
    uint8_t prefixLength;
    
    /// @brief Reserved for future use
    uint8_t reserved[3];
    
    /// @brief Default constructor - 0.0.0.0/0
    IPv4Address() noexcept : address(0), prefixLength(32), reserved{} {}
    
    /// @brief Construct from 4 octets
    IPv4Address(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t prefix = 32) noexcept
        : address((static_cast<uint32_t>(a) << 24) |
            (static_cast<uint32_t>(b) << 16) |
            (static_cast<uint32_t>(c) << 8) |
            static_cast<uint32_t>(d)),
        prefixLength(prefix), reserved{} {}


    /// @brief Construct from raw 32-bit value (host byte order)
    explicit IPv4Address(uint32_t addr, uint8_t prefix = 32) noexcept
        : address(addr), prefixLength(prefix), reserved{} {}

    /// @brief Updated constructor to initialize union members correctly
    IPv4Address(std::array<uint8_t, 4> arr, uint8_t prefix = 32) noexcept : 
        octets(arr), prefixLength(prefix), reserved{} {}
    
    /// @brief Get network mask for CIDR prefix
    [[nodiscard]] uint32_t GetNetworkMask() const noexcept {
        if (prefixLength == 0) return 0;
        if (prefixLength >= 32) return 0xFFFFFFFF;
        return ~((1u << (32 - prefixLength)) - 1);
    }
    
    /// @brief Get network address (address AND mask)
    [[nodiscard]] uint32_t GetNetworkAddress() const noexcept {
        return address & GetNetworkMask();
    }
    
    /// @brief Get broadcast address
    [[nodiscard]] uint32_t GetBroadcastAddress() const noexcept {
        return GetNetworkAddress() | ~GetNetworkMask();
    }
    
    /// @brief Check if another address is within this CIDR range
    [[nodiscard]] bool Contains(const IPv4Address& other) const noexcept {
        return (other.address & GetNetworkMask()) == GetNetworkAddress();
    }
    
    /// @brief Check if this is an exact host address (no CIDR)
    [[nodiscard]] bool IsHostAddress() const noexcept {
        return prefixLength == 32;
    }
    
    /// @brief Equality comparison (exact match including prefix)
    [[nodiscard]] bool operator==(const IPv4Address& other) const noexcept {
        return address == other.address && prefixLength == other.prefixLength;
    }
    
    [[nodiscard]] bool operator!=(const IPv4Address& other) const noexcept {
        return !(*this == other);
    }
    
    /// @brief Less-than for sorting/indexing
    [[nodiscard]] bool operator<(const IPv4Address& other) const noexcept {
        if (address != other.address) return address < other.address;
        return prefixLength < other.prefixLength;
    }
    
    /// @brief Fast hash for hash table indexing
    [[nodiscard]] uint64_t FastHash() const noexcept {
        uint64_t h = 14695981039346656037ULL;
        h ^= static_cast<uint64_t>(address);
        h *= 1099511628211ULL;
        h ^= static_cast<uint64_t>(prefixLength);
        h *= 1099511628211ULL;
        return h;
    }
    
    /// @brief Check if address is private (RFC 1918)
    [[nodiscard]] bool IsPrivate() const noexcept {
        uint8_t a = (address >> 24) & 0xFF;
        uint8_t b = (address >> 16) & 0xFF;
        
        // 10.0.0.0/8
        if (a == 10) return true;
        
        // 172.16.0.0/12
        if (a == 172 && (b >= 16 && b <= 31)) return true;
        
        // 192.168.0.0/16
        if (a == 192 && b == 168) return true;
        
        return false;
    }
    
    /// @brief Check if address is loopback (127.0.0.0/8)
    [[nodiscard]] bool IsLoopback() const noexcept {
        return ((address >> 24) & 0xFF) == 127;
    }
    
    /// @brief Check if address is multicast (224.0.0.0/4)
    [[nodiscard]] bool IsMulticast() const noexcept {
        uint8_t a = (address >> 24) & 0xFF;
        return a >= 224 && a <= 239;
    }
    
    /// @brief Check if address is valid (non-zero, non-broadcast)
    [[nodiscard]] bool IsValid() const noexcept {
        return address != 0 && address != 0xFFFFFFFF;
    }
};
#pragma pack(pop)

static_assert(sizeof(IPv4Address) == 8, "IPv4Address must be exactly 8 bytes");

// ============================================================================
// IPV6 ADDRESS STRUCTURE
// ============================================================================

/// @brief IPv6 address with CIDR prefix support (128-bit optimized)
#pragma pack(push, 1)
struct alignas(8) IPv6Address {

    union {
        std::array<uint8_t, 16> address; ///< Raw bytes access
        std::array<uint16_t, 8> groups;  ///< 16-bit groups for Patricia Trie storage
    };

    /// @brief CIDR prefix length (0-128, 128 = exact match)
    uint8_t prefixLength;
    
    /// @brief Reserved for alignment
    uint8_t reserved[7];
    
    /// @brief Default constructor - all zeros
    IPv6Address() noexcept : address{}, prefixLength(128), reserved{} {
        address.fill(0);
    }
    
    /// @brief Construct from raw bytes
    IPv6Address(const uint8_t* bytes, uint8_t prefix = 128) noexcept
        : prefixLength(prefix), reserved{} {
        if (bytes) {
            std::memcpy(address.data(), bytes, 16);
        } else {
            address.fill(0);
        }
    }
    
    /// @brief Construct from two 64-bit halves (for quick construction)
    IPv6Address(uint64_t high, uint64_t low, uint8_t prefix = 128) noexcept
        : prefixLength(prefix), reserved{} {
        // Store in network byte order (big-endian)
        for (int i = 0; i < 8; ++i) {
            address[i] = static_cast<uint8_t>(high >> (56 - i * 8));
            address[8 + i] = static_cast<uint8_t>(low >> (56 - i * 8));
        }
    }
    
    /// @brief Get high 64 bits as uint64_t (host byte order)
    [[nodiscard]] uint64_t GetHigh64() const noexcept {
        uint64_t result = 0;
        for (int i = 0; i < 8; ++i) {
            result = (result << 8) | address[i];
        }
        return result;
    }
    
    /// @brief Get low 64 bits as uint64_t (host byte order)
    [[nodiscard]] uint64_t GetLow64() const noexcept {
        uint64_t result = 0;
        for (int i = 0; i < 8; ++i) {
            result = (result << 8) | address[8 + i];
        }
        return result;
    }
    
    /// @brief Check if another address is within this CIDR range
    [[nodiscard]] bool Contains(const IPv6Address& other) const noexcept {
        if (prefixLength == 0) return true;
        if (prefixLength == 128) return *this == other;
        
        size_t fullBytes = prefixLength / 8;
        size_t remainingBits = prefixLength % 8;
        
        // Compare full bytes
        if (std::memcmp(address.data(), other.address.data(), fullBytes) != 0) {
            return false;
        }
        
        // Compare remaining bits
        if (remainingBits > 0) {
            uint8_t mask = static_cast<uint8_t>(0xFF << (8 - remainingBits));
            return (address[fullBytes] & mask) == (other.address[fullBytes] & mask);
        }
        
        return true;
    }
    
    /// @brief Check if this is an exact host address (no CIDR)
    [[nodiscard]] bool IsHostAddress() const noexcept {
        return prefixLength == 128;
    }
    
    /// @brief Equality comparison
    [[nodiscard]] bool operator==(const IPv6Address& other) const noexcept {
        return std::memcmp(address.data(), other.address.data(), 16) == 0 &&
               prefixLength == other.prefixLength;
    }
    
    [[nodiscard]] bool operator!=(const IPv6Address& other) const noexcept {
        return !(*this == other);
    }
    
    /// @brief Less-than for sorting
    [[nodiscard]] bool operator<(const IPv6Address& other) const noexcept {
        int cmp = std::memcmp(address.data(), other.address.data(), 16);
        if (cmp != 0) return cmp < 0;
        return prefixLength < other.prefixLength;
    }
    
    /// @brief Fast hash for hash table indexing
    [[nodiscard]] uint64_t FastHash() const noexcept {
        uint64_t h = 14695981039346656037ULL;
        for (size_t i = 0; i < 16; ++i) {
            h ^= address[i];
            h *= 1099511628211ULL;
        }
        h ^= static_cast<uint64_t>(prefixLength);
        h *= 1099511628211ULL;
        return h;
    }
    
    /// @brief Check if address is loopback (::1)
    [[nodiscard]] bool IsLoopback() const noexcept {
        for (int i = 0; i < 15; ++i) {
            if (address[i] != 0) return false;
        }
        return address[15] == 1;
    }
    
    /// @brief Check if address is link-local (fe80::/10)
    [[nodiscard]] bool IsLinkLocal() const noexcept {
        return address[0] == 0xFE && (address[1] & 0xC0) == 0x80;
    }
    
    /// @brief Check if address is multicast (ff00::/8)
    [[nodiscard]] bool IsMulticast() const noexcept {
        return address[0] == 0xFF;
    }
    
    /// @brief Check if address is IPv4-mapped (::ffff:0:0/96)
    [[nodiscard]] bool IsIPv4Mapped() const noexcept {
        for (int i = 0; i < 10; ++i) {
            if (address[i] != 0) return false;
        }
        return address[10] == 0xFF && address[11] == 0xFF;
    }
    
    /// @brief Get embedded IPv4 address (if IPv4-mapped)
    [[nodiscard]] IPv4Address ToIPv4() const noexcept {
        if (!IsIPv4Mapped()) return IPv4Address();
        return IPv4Address(
            (static_cast<uint32_t>(address[12]) << 24) |
            (static_cast<uint32_t>(address[13]) << 16) |
            (static_cast<uint32_t>(address[14]) << 8) |
            static_cast<uint32_t>(address[15])
        );
    }
    
    /// @brief Check if address is valid (non-zero)
    [[nodiscard]] bool IsValid() const noexcept {
        for (const auto& byte : address) {
            if (byte != 0) return true;
        }
        return false;
    }
};
#pragma pack(pop)

static_assert(sizeof(IPv6Address) == 24, "IPv6Address must be exactly 24 bytes");

// ============================================================================
// HASH VALUE STRUCTURE
// ============================================================================

/// @brief Fixed-size hash storage for file hash IOCs (zero-copy compatible)
#pragma pack(push, 1)
struct alignas(4) HashValue {
    /// @brief Hash algorithm used
    HashAlgorithm algorithm;
    
    /// @brief Actual hash length in bytes
    uint8_t length;
    
    /// @brief Reserved for alignment
    uint8_t reserved[2];
    
    /// @brief Hash data (max 72 bytes for SSDEEP)
    std::array<uint8_t, 72> data;
    
    /// @brief Default constructor - initializes to zero
    HashValue() noexcept : algorithm(HashAlgorithm::SHA256), length(0), reserved{} {
        data.fill(0);
    }
    
    /// @brief Construct from raw bytes
    HashValue(HashAlgorithm algo, const uint8_t* bytes, uint8_t len) noexcept
        : algorithm(algo), length(len), reserved{} {
        data.fill(0);
        if (bytes && len > 0 && len <= 72) {
            std::memcpy(data.data(), bytes, len);
        }
    }
    
    /// @brief Zero-cost hash comparison (inlined, cache-friendly)
    [[nodiscard]] bool operator==(const HashValue& other) const noexcept {
        if (algorithm != other.algorithm || length != other.length) {
            return false;
        }
        return std::memcmp(data.data(), other.data.data(), length) == 0;
    }
    
    [[nodiscard]] bool operator!=(const HashValue& other) const noexcept {
        return !(*this == other);
    }
    
    /// @brief FNV-1a hash for hash table indexing
    [[nodiscard]] uint64_t FastHash() const noexcept {
        uint64_t h = 14695981039346656037ULL;
        h ^= static_cast<uint64_t>(algorithm);
        h *= 1099511628211ULL;
        for (size_t i = 0; i < length; ++i) {
            h ^= data[i];
            h *= 1099511628211ULL;
        }
        return h;
    }
    
    /// @brief Check if hash is empty/uninitialized
    [[nodiscard]] bool IsEmpty() const noexcept {
        return length == 0;
    }
    
    /// @brief Validate hash length matches algorithm
    [[nodiscard]] bool IsValid() const noexcept {
        if (length == 0) return false;
        uint8_t expected = GetHashLength(algorithm);
        // SSDEEP and TLSH have variable length
        if (algorithm == HashAlgorithm::SSDEEP || algorithm == HashAlgorithm::TLSH) {
            return length > 0 && length <= expected;
        }
        return length == expected;
    }
};
#pragma pack(pop)

static_assert(sizeof(HashValue) == 76, "HashValue must be exactly 76 bytes");

// ============================================================================
// IOC ENTRY FLAGS
// ============================================================================

/// @brief Behavioral flags for IOC entries
enum class IOCFlags : uint32_t {
    None = 0,
    
    /// @brief Entry is enabled for detection
    Enabled = 1 << 0,
    
    /// @brief Entry has expiration time (TTL)
    HasExpiration = 1 << 1,
    
    /// @brief Entry should trigger alert
    AlertOnMatch = 1 << 2,
    
    /// @brief Entry should trigger block action
    BlockOnMatch = 1 << 3,
    
    /// @brief Entry should be logged when matched
    LogOnMatch = 1 << 4,
    
    /// @brief Entry is from trusted/verified source
    Verified = 1 << 5,
    
    /// @brief Entry is auto-generated (not manually added)
    AutoGenerated = 1 << 6,
    
    /// @brief Entry is sinkholed (domain/IP taken down)
    Sinkholed = 1 << 7,
    
    /// @brief Entry is for monitoring only (no action)
    MonitorOnly = 1 << 8,
    
    /// @brief Entry has associated STIX bundle
    HasSTIXBundle = 1 << 9,
    
    /// @brief Entry has related IOCs
    HasRelatedIOCs = 1 << 10,
    
    /// @brief Entry is part of active campaign
    ActiveCampaign = 1 << 11,
    
    /// @brief Entry requires context for detection
    ContextRequired = 1 << 12,
    
    /// @brief Entry is deprecated/superseded
    Deprecated = 1 << 13,
    
    /// @brief Entry is for internal use only
    Internal = 1 << 14,
    
    /// @brief Entry can be shared externally
    Shareable = 1 << 15,
    
    /// @brief Entry is from government/CERT source
    GovernmentSource = 1 << 16,
    
    /// @brief Entry has high false-positive rate
    HighFPRate = 1 << 17,
    
    /// @brief Entry is whitelisted (override)
    Whitelisted = 1 << 18,
    
    /// @brief Entry pending review
    PendingReview = 1 << 19,
    
    /// @brief Entry is revoked
    Revoked = 1 << 20
};

/// @brief Enable bitwise operations on IOCFlags
inline constexpr IOCFlags operator|(IOCFlags a, IOCFlags b) noexcept {
    return static_cast<IOCFlags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline constexpr IOCFlags operator&(IOCFlags a, IOCFlags b) noexcept {
    return static_cast<IOCFlags>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

inline constexpr IOCFlags operator~(IOCFlags a) noexcept {
    return static_cast<IOCFlags>(~static_cast<uint32_t>(a));
}

inline constexpr bool HasFlag(IOCFlags flags, IOCFlags flag) noexcept {
    return (static_cast<uint32_t>(flags) & static_cast<uint32_t>(flag)) != 0;
}

inline constexpr IOCFlags& operator|=(IOCFlags& a, IOCFlags b) noexcept {
    a = a | b;
    return a;
}

inline constexpr IOCFlags& operator&=(IOCFlags& a, IOCFlags b) noexcept {
    a = a & b;
    return a;
}

// ============================================================================
// IOC ENTRY STRUCTURE (Main Data Record)
// ============================================================================

/// @brief Packed IOC entry for memory-mapped storage
/// @note Size is 256 bytes - aligned for optimal cache performance and future expansion
#pragma pack(push, 1)
struct alignas(CACHE_LINE_SIZE) IOCEntry {
    // ========================================================================
    // IDENTIFICATION (32 bytes)
    // ========================================================================
    
    /// @brief Unique entry identifier (monotonically increasing)
    uint64_t entryId;
    
    /// @brief STIX 2.1 compatible ID reference (string pool offset)
    uint32_t stixIdOffset;
    
    /// @brief STIX ID length
    uint16_t stixIdLength;
    
    /// @brief Type of IOC
    IOCType type;
    
    /// @brief Reserved
    uint8_t reserved1;
    
    /// @brief Entry behavior flags
    IOCFlags flags;
    
    /// @brief Source of this intelligence
    ThreatIntelSource source;
    
    /// @brief Secondary source (for correlation)
    ThreatIntelSource secondarySource;
    
    /// @brief Feed ID this entry belongs to
    uint32_t feedId;
    
    // ========================================================================
    // REPUTATION & CLASSIFICATION (16 bytes)
    // ========================================================================
    
    /// @brief Reputation score (0-100)
    ReputationLevel reputation;
    
    /// @brief Confidence level of the assessment
    ConfidenceLevel confidence;
    
    /// @brief Primary threat category
    ThreatCategory category;
    
    /// @brief Secondary threat category
    ThreatCategory secondaryCategory;
    
    /// @brief Number of sources confirming this IOC
    uint16_t sourceCount;
    
    /// @brief Number of related IOCs
    uint16_t relatedCount;
    
    /// @brief Severity score (0-100, used for prioritization)
    uint8_t severity;
    
    /// @brief Reserved
    uint8_t reserved2[3];
    
    // ========================================================================
    // IOC VALUE DATA (80 bytes)
    // ========================================================================
    
    /// @brief Inline IOC data (for small values like IPs, hashes)
    /// @note For larger values (URLs, domains), this contains offset to string pool
    union IOCValue {
        /// @brief IPv4 address data
        IPv4Address ipv4;
        
        /// @brief IPv6 address data
        IPv6Address ipv6;
        
        /// @brief Hash value data
        HashValue hash;
        
        /// @brief String reference (domain, URL, email, etc.)
        struct {
            uint64_t stringOffset;      ///< Offset in string pool
            uint32_t stringLength;      ///< String length in bytes
            uint32_t patternOffset;     ///< Compiled pattern offset (for regex)
            uint32_t patternLength;     ///< Compiled pattern length
            uint8_t padding[56];        ///< Pad to 76 bytes
        } stringRef;
        
        /// @brief Raw bytes for custom data
        uint8_t raw[76];
        
        /// @brief Default constructor - zero-initializes the union
        constexpr IOCValue() noexcept : raw{} {}
        
        /// @brief Copy constructor - uses constexpr-compatible element-wise copy
        constexpr IOCValue(const IOCValue& other) noexcept : raw{} {
            for (std::size_t i = 0; i < sizeof(raw); ++i) {
                raw[i] = other.raw[i];
            }
        }
        
        /// @brief Copy assignment operator - uses constexpr-compatible element-wise copy
        constexpr IOCValue& operator=(const IOCValue& other) noexcept {
            if (this != &other) {
                for (std::size_t i = 0; i < sizeof(raw); ++i) {
                    raw[i] = other.raw[i];
                }
            }
            return *this;
        }
    } value;
    
    /// @brief Value type discriminator (mirrors IOCType for union access)
    uint8_t valueType;
    
    /// @brief Reserved for alignment
    uint8_t reserved3[3];
    
    // ========================================================================
    // TIMESTAMPS (32 bytes)
    // ========================================================================
    
    /// @brief First seen timestamp (Unix epoch seconds)
    uint64_t firstSeen;
    
    /// @brief Last seen timestamp
    uint64_t lastSeen;
    
    /// @brief Entry creation timestamp
    uint64_t createdTime;
    
    /// @brief Expiration timestamp (0 = never expires)
    uint64_t expirationTime;
    
    // ========================================================================
    // METADATA REFERENCES (32 bytes)
    // ========================================================================
    
    /// @brief Description string pool offset
    uint32_t descriptionOffset;
    
    /// @brief Description length
    uint16_t descriptionLength;
    
    /// @brief Tags array offset (array of tag offsets)
    uint32_t tagsOffset;
    
    /// @brief Number of tags
    uint16_t tagCount;
    
    /// @brief MITRE ATT&CK techniques offset
    uint32_t mitreOffset;
    
    /// @brief Number of MITRE techniques
    uint16_t mitreCount;
    
    /// @brief Related IOCs array offset
    uint32_t relatedOffset;
    
    /// @brief STIX bundle offset (if HasSTIXBundle flag)
    uint32_t stixBundleOffset;
    
    /// @brief STIX bundle size
    uint32_t stixBundleSize;
    
    // ========================================================================
    // STATISTICS & COUNTERS (16 bytes)
    // Note: Using uint32_t for better alignment compatibility with std::atomic
    // ========================================================================
    
    /// @brief Hit count (how many times this IOC matched)
    std::atomic<uint32_t> hitCount;
    
    /// @brief Last hit timestamp
    std::atomic<uint32_t> lastHitTime;
    
    /// @brief False positive count (user feedback) - use lower 16 bits
    std::atomic<uint32_t> falsePositiveCount;
    
    /// @brief True positive count (confirmed) - use lower 16 bits
    std::atomic<uint32_t> truePositiveCount;
    
    // ========================================================================
    // API SOURCE DATA (32 bytes)
    // ========================================================================
    
    /// @brief VirusTotal detection ratio (positives/total)
    uint8_t vtPositives;
    uint8_t vtTotal;
    
    /// @brief AbuseIPDB confidence score (0-100)
    uint8_t abuseIPDBScore;
    
    /// @brief GreyNoise classification (0=unknown, 1=benign, 2=malicious)
    uint8_t greyNoiseClass;
    
    /// @brief Shodan open ports bitmap (common ports)
    uint16_t shodanPorts;
    
    /// @brief Reserved for additional API data
    uint8_t reserved5[26];
    
    // ========================================================================
    // PADDING TO 256 BYTES
    // Note: Due to std::atomic alignment requirements, actual byte count
    // before this padding varies. Use CACHE_LINE_SIZE (64) alignment.
    // ========================================================================
    
    // ========================================================================
    // CONSTRUCTORS
    // ========================================================================
    
    /// @brief Default constructor - zero-initializes all fields
    IOCEntry() noexcept {
        std::memset(this, 0, sizeof(IOCEntry));
        // Placement-new the atomics to properly initialize them
        new (&hitCount) std::atomic<uint32_t>(0);
        new (&lastHitTime) std::atomic<uint32_t>(0);
        new (&falsePositiveCount) std::atomic<uint32_t>(0);
        new (&truePositiveCount) std::atomic<uint32_t>(0);
    }
    
    /// @brief Copy constructor - manually copy atomic members
    IOCEntry(const IOCEntry& other) noexcept {
        // Copy non-atomic members
        std::memcpy(this, &other, offsetof(IOCEntry, hitCount));
        
        // Placement-new and initialize atomics with other's values
        new (&hitCount) std::atomic<uint32_t>(other.hitCount.load(std::memory_order_relaxed));
        new (&lastHitTime) std::atomic<uint32_t>(other.lastHitTime.load(std::memory_order_relaxed));
        new (&falsePositiveCount) std::atomic<uint32_t>(other.falsePositiveCount.load(std::memory_order_relaxed));
        new (&truePositiveCount) std::atomic<uint32_t>(other.truePositiveCount.load(std::memory_order_relaxed));
        
        // Copy remaining bytes after atomics
        constexpr size_t atomicsEnd = offsetof(IOCEntry, hitCount) + 
            sizeof(hitCount) + sizeof(lastHitTime) + sizeof(falsePositiveCount) + sizeof(truePositiveCount);
        constexpr size_t remainingSize = sizeof(IOCEntry) - atomicsEnd;
        std::memcpy(reinterpret_cast<uint8_t*>(this) + atomicsEnd,
                    reinterpret_cast<const uint8_t*>(&other) + atomicsEnd,
                    remainingSize);
    }
    
    /// @brief Copy assignment operator
    IOCEntry& operator=(const IOCEntry& other) noexcept {
        if (this != &other) {
            // Copy non-atomic members
            std::memcpy(this, &other, offsetof(IOCEntry, hitCount));
            
            // Copy atomic values
            hitCount.store(other.hitCount.load(std::memory_order_relaxed), std::memory_order_relaxed);
            lastHitTime.store(other.lastHitTime.load(std::memory_order_relaxed), std::memory_order_relaxed);
            falsePositiveCount.store(other.falsePositiveCount.load(std::memory_order_relaxed), std::memory_order_relaxed);
            truePositiveCount.store(other.truePositiveCount.load(std::memory_order_relaxed), std::memory_order_relaxed);
            
            // Copy remaining bytes after atomics
            constexpr size_t atomicsEnd = offsetof(IOCEntry, hitCount) + 
                sizeof(hitCount) + sizeof(lastHitTime) + sizeof(falsePositiveCount) + sizeof(truePositiveCount);
            constexpr size_t remainingSize = sizeof(IOCEntry) - atomicsEnd;
            std::memcpy(reinterpret_cast<uint8_t*>(this) + atomicsEnd,
                        reinterpret_cast<const uint8_t*>(&other) + atomicsEnd,
                        remainingSize);
        }
        return *this;
    }
    
    // ========================================================================
    // METHODS
    // ========================================================================
    
    /// @brief Check if entry is expired
    [[nodiscard]] bool IsExpired() const noexcept {
        if (!HasFlag(flags, IOCFlags::HasExpiration)) {
            return false;
        }
        auto now = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count()
        );
        return expirationTime > 0 && now > expirationTime;
    }
    
    /// @brief Check if entry is active (enabled, not expired, not revoked)
    [[nodiscard]] bool IsActive() const noexcept {
        return HasFlag(flags, IOCFlags::Enabled) &&
               !HasFlag(flags, IOCFlags::Revoked) &&
               !HasFlag(flags, IOCFlags::Whitelisted) &&
               !IsExpired();
    }
    
    /// @brief Check if entry should block
    [[nodiscard]] bool ShouldBlock() const noexcept {
        return IsActive() && HasFlag(flags, IOCFlags::BlockOnMatch);
    }
    
    /// @brief Check if entry should alert
    [[nodiscard]] bool ShouldAlert() const noexcept {
        return IsActive() && HasFlag(flags, IOCFlags::AlertOnMatch);
    }
    
    /// @brief Increment hit counter (thread-safe)
    void IncrementHitCount() noexcept {
        hitCount.fetch_add(1, std::memory_order_relaxed);
        lastHitTime.store(
            static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count()),
            std::memory_order_relaxed
        );
    }
    
    /// @brief Get threat score (reputation * confidence / 100)
    [[nodiscard]] uint8_t GetThreatScore() const noexcept {
        return static_cast<uint8_t>(
            (static_cast<uint16_t>(reputation) * static_cast<uint16_t>(confidence)) / 100
        );
    }
    
    /// @brief Calculate priority score for sorting
    [[nodiscard]] uint32_t GetPriorityScore() const noexcept {
        uint32_t score = static_cast<uint32_t>(reputation) * 100;
        score += static_cast<uint32_t>(confidence);
        score += static_cast<uint32_t>(sourceCount) * 10;
        if (HasFlag(flags, IOCFlags::ActiveCampaign)) score += 1000;
        if (HasFlag(flags, IOCFlags::Verified)) score += 500;
        return score;
    }
};
#pragma pack(pop)

static_assert(sizeof(IOCEntry) == 256, "IOCEntry must be exactly 256 bytes");
static_assert(alignof(IOCEntry) == CACHE_LINE_SIZE, "IOCEntry must be cache-line aligned");

// ============================================================================
// COMPACT IOC ENTRY (For high-density storage)
// ============================================================================

/// @brief Compact IOC entry for bloom filter and quick checks (64 bytes)
#pragma pack(push, 1)
struct alignas(CACHE_LINE_SIZE) CompactIOCEntry {
    /// @brief Entry ID reference
    uint64_t entryId;
    
    /// @brief Fast hash of the IOC value
    uint64_t valueHash;
    
    /// @brief IOC type
    IOCType type;
    
    /// @brief Reputation level
    ReputationLevel reputation;
    
    /// @brief Confidence level
    ConfidenceLevel confidence;
    
    /// @brief Flags (truncated to most important)
    uint8_t flagsByte;
    
    /// @brief Threat category
    ThreatCategory category;
    
    /// @brief Source
    ThreatIntelSource source;
    
    /// @brief Expiration time (truncated to days since epoch)
    uint16_t expirationDay;
    
    /// @brief Reserved
    uint8_t reserved[2];
    
    /// @brief Inline value (for small IOCs like IPv4)
    std::array<uint8_t, 32> inlineValue;
    
    /// @brief Check if compact entry matches full entry
    [[nodiscard]] bool Matches(uint64_t hash) const noexcept {
        return valueHash == hash;
    }
};
#pragma pack(pop)

static_assert(sizeof(CompactIOCEntry) == 64, "CompactIOCEntry must be exactly 64 bytes");

// ============================================================================
// FEED CONFIGURATION STRUCTURE
// ============================================================================

/// @brief Feed source configuration
#pragma pack(push, 1)
struct FeedConfig {
    /// @brief Feed unique identifier
    uint32_t feedId;
    
    /// @brief Feed source type
    ThreatIntelSource sourceType;
    
    /// @brief Is feed enabled
    bool enabled;
    
    /// @brief Reserved
    uint8_t reserved1[2];
    
    /// @brief Update interval in seconds
    uint32_t updateIntervalSeconds;
    
    /// @brief Last update timestamp
    uint64_t lastUpdateTime;
    
    /// @brief Next scheduled update
    uint64_t nextUpdateTime;
    
    /// @brief API endpoint URL offset in string pool
    uint32_t endpointOffset;
    uint16_t endpointLength;
    
    /// @brief API key offset in string pool (encrypted)
    uint32_t apiKeyOffset;
    uint16_t apiKeyLength;
    
    /// @brief Feed name offset
    uint32_t nameOffset;
    uint16_t nameLength;
    
    /// @brief Rate limit (requests per minute)
    uint16_t rateLimit;
    
    /// @brief Request timeout in milliseconds
    uint32_t timeoutMs;
    
    /// @brief Default TTL for entries from this feed
    uint32_t defaultTTL;
    
    /// @brief Default reputation for entries from this feed
    ReputationLevel defaultReputation;
    
    /// @brief Default confidence for entries from this feed
    ConfidenceLevel defaultConfidence;
    
    /// @brief Reserved
    uint8_t reserved2[2];
    
    /// @brief Total entries from this feed
    uint64_t totalEntries;
    
    /// @brief Successful updates count
    uint32_t successCount;
    
    /// @brief Failed updates count
    uint32_t failureCount;
    
    /// @brief Last error code
    uint32_t lastErrorCode;
    
    /// @brief Reserved for future expansion (81 + 47 = 128)
    uint8_t reserved3[47];
};
#pragma pack(pop)

static_assert(sizeof(FeedConfig) == 128, "FeedConfig must be exactly 128 bytes");

// ============================================================================
// DATABASE HEADER (First 4KB of database file)
// ============================================================================

#pragma pack(push, 1)
struct ThreatIntelDatabaseHeader {
    // ========================================================================
    // IDENTIFICATION (64 bytes)
    // ========================================================================
    
    /// @brief Magic number: THREATINTEL_DB_MAGIC
    uint32_t magic;
    
    /// @brief Major version
    uint16_t versionMajor;
    
    /// @brief Minor version
    uint16_t versionMinor;
    
    /// @brief Database UUID for tracking and sync
    std::array<uint8_t, 16> databaseUuid;
    
    /// @brief Creation timestamp (Unix epoch)
    uint64_t creationTime;
    
    /// @brief Last update timestamp
    uint64_t lastUpdateTime;
    
    /// @brief Incremental build number
    uint64_t buildNumber;
    
    /// @brief Database format flags
    uint32_t formatFlags;
    
    /// @brief Reserved - padding to 64 bytes
    uint8_t reserved1[12];
    
    // ========================================================================
    // SECTION OFFSETS (All 4KB page-aligned) (256 bytes)
    // ========================================================================
    
    /// @brief IPv4 index section (Radix Tree)
    uint64_t ipv4IndexOffset;
    uint64_t ipv4IndexSize;
    
    /// @brief IPv6 index section (Patricia Trie)
    uint64_t ipv6IndexOffset;
    uint64_t ipv6IndexSize;
    
    /// @brief Domain index section (Suffix Trie)
    uint64_t domainIndexOffset;
    uint64_t domainIndexSize;
    
    /// @brief URL index section
    uint64_t urlIndexOffset;
    uint64_t urlIndexSize;
    
    /// @brief Hash index section (B+Tree per type)
    uint64_t hashIndexOffset;
    uint64_t hashIndexSize;
    
    /// @brief Email index section
    uint64_t emailIndexOffset;
    uint64_t emailIndexSize;
    
    /// @brief Certificate index section
    uint64_t certIndexOffset;
    uint64_t certIndexSize;
    
    /// @brief JA3/JA3S fingerprint index
    uint64_t ja3IndexOffset;
    uint64_t ja3IndexSize;
    
    /// @brief IOC entry data section
    uint64_t entryDataOffset;
    uint64_t entryDataSize;
    
    /// @brief Compact entry section
    uint64_t compactEntryOffset;
    uint64_t compactEntrySize;
    
    /// @brief String pool section
    uint64_t stringPoolOffset;
    uint64_t stringPoolSize;
    
    /// @brief Bloom filter section (per-type filters)
    uint64_t bloomFilterOffset;
    uint64_t bloomFilterSize;
    
    /// @brief STIX bundle section
    uint64_t stixBundleOffset;
    uint64_t stixBundleSize;
    
    /// @brief Feed configuration section
    uint64_t feedConfigOffset;
    uint64_t feedConfigSize;
    
    /// @brief Metadata/audit section
    uint64_t metadataOffset;
    uint64_t metadataSize;
    
    /// @brief Related IOCs graph section
    uint64_t relationGraphOffset;
    uint64_t relationGraphSize;
    
    // ========================================================================
    // STATISTICS (128 bytes)
    // ========================================================================
    
    /// @brief Total entries by type
    uint64_t totalIPv4Entries;
    uint64_t totalIPv6Entries;
    uint64_t totalDomainEntries;
    uint64_t totalURLEntries;
    uint64_t totalHashEntries;
    uint64_t totalEmailEntries;
    uint64_t totalCertEntries;
    uint64_t totalOtherEntries;
    
    /// @brief Total active (non-expired) entries
    uint64_t totalActiveEntries;
    
    /// @brief Total feeds configured
    uint32_t totalFeeds;
    
    /// @brief Active feeds
    uint32_t activeFeeds;
    
    /// @brief Lifetime statistics
    uint64_t totalLookups;
    uint64_t totalHits;
    uint64_t totalMisses;
    uint64_t totalBlocks;
    uint64_t totalAlerts;
    
    /// @brief Reserved - padding to 128 bytes (136 - 128 = need 8 bytes less, so remove 8 from reserved2)
    uint8_t reserved2[8];
    
    // ========================================================================
    // PERFORMANCE HINTS (64 bytes)
    // ========================================================================
    
    /// @brief Recommended cache size in MB
    uint32_t recommendedCacheSize;
    
    /// @brief Bloom filter expected elements per type
    uint32_t bloomExpectedElements;
    
    /// @brief Bloom filter target false positive rate (scaled by 1M)
    uint32_t bloomFalsePositiveRate;
    
    /// @brief Compression algorithm (0=none, 1=LZ4, 2=ZSTD)
    uint8_t compressionAlgorithm;
    
    /// @brief Index optimization level (0-3)
    uint8_t indexOptLevel;
    
    /// @brief Reserved
    uint8_t reserved3[2];
    
    /// @brief Average entry size (for allocation hints)
    uint32_t avgEntrySize;
    
    /// @brief Maximum concurrent lookups supported
    uint32_t maxConcurrentLookups;
    
    /// @brief Default query timeout in milliseconds
    uint32_t defaultTimeoutMs;
    
    /// @brief Memory budget in MB
    uint32_t memoryBudgetMB;
    
    /// @brief Reserved - padding to 64 bytes (60 + 32 = need 4 more)
    uint8_t reserved4[32];
    
    // ========================================================================
    // INTEGRITY (64 bytes)
    // ========================================================================
    
    /// @brief SHA-256 checksum of entire database (excluding this field)
    std::array<uint8_t, 32> sha256Checksum;
    
    /// @brief CRC32 of header (for quick validation)
    uint32_t headerCrc32;
    
    /// @brief Database file size
    uint64_t totalFileSize;
    
    /// @brief Reserved
    uint8_t reserved5[20];
    
    // ========================================================================
    // API CONFIGURATION (256 bytes)
    // ========================================================================
    
    /// @brief VirusTotal API configuration
    struct {
        uint32_t apiKeyOffset;
        uint16_t apiKeyLength;
        uint16_t rateLimit;
        bool enabled;
        uint8_t reserved[7];
    } virusTotalConfig;
    
    /// @brief AlienVault OTX configuration
    struct {
        uint32_t apiKeyOffset;
        uint16_t apiKeyLength;
        uint16_t rateLimit;
        bool enabled;
        uint8_t reserved[7];
    } alienVaultConfig;
    
    /// @brief AbuseIPDB configuration
    struct {
        uint32_t apiKeyOffset;
        uint16_t apiKeyLength;
        uint16_t rateLimit;
        bool enabled;
        uint8_t reserved[7];
    } abuseIPDBConfig;
    
    /// @brief MISP configuration
    struct {
        uint32_t apiKeyOffset;
        uint16_t apiKeyLength;
        uint16_t rateLimit;
        uint32_t instanceUrlOffset;
        uint16_t instanceUrlLength;
        bool enabled;
        uint8_t reserved[1];
    } mispConfig;
    
    /// @brief Reserved for additional API configs
    uint8_t apiReserved[192];
    
    // ========================================================================
    // RESERVED FOR FUTURE (Pad to exactly 4096 bytes)
    // Total so far: 64 + 256 + 128 + 64 + 64 + 256 = 832 bytes
    // Need: 4096 - 832 = 3264 bytes
    // ========================================================================
    
    std::array<uint8_t, 3264> reserved;
};
#pragma pack(pop)

static_assert(sizeof(ThreatIntelDatabaseHeader) == 4096,
    "ThreatIntelDatabaseHeader must be exactly 4KB (4096 bytes)");

// ============================================================================
// BLOOM FILTER SECTION HEADER
// ============================================================================

#pragma pack(push, 1)
struct BloomFilterHeader {
    /// @brief Magic: 'TIBL' (Threat Intel BLoom)
    uint32_t magic;
    
    /// @brief Version
    uint32_t version;
    
    /// @brief IOC type this filter covers
    IOCType iocType;
    
    /// @brief Reserved
    uint8_t reserved1[3];
    
    /// @brief Number of bits in filter
    uint64_t bitCount;
    
    /// @brief Number of hash functions
    uint32_t hashFunctions;
    
    /// @brief Reserved for alignment
    uint32_t reserved2;
    
    /// @brief Estimated elements added
    uint64_t elementCount;
    
    /// @brief Target false positive rate (as double)
    double falsePositiveRate;
    
    /// @brief Offset to bit array data
    uint64_t dataOffset;
    
    /// @brief Size of bit array in bytes
    uint64_t dataSize;
    
    /// @brief Reserved padding to reach 64 bytes (60 + 4 = 64)
    uint8_t reserved3[4];
};
#pragma pack(pop)

static_assert(sizeof(BloomFilterHeader) == 64, "BloomFilterHeader must be 64 bytes");

constexpr uint32_t BLOOM_FILTER_MAGIC = 0x4C424954; // 'TIBL'

// ============================================================================
// ERROR HANDLING
// ============================================================================

/// @brief Error codes for threat intel operations
enum class ThreatIntelError : uint32_t {
    Success = 0,
    
    // File/IO errors (1-99)
    FileNotFound = 1,
    FileAccessDenied = 2,
    FileLocked = 3,
    FileCorrupted = 4,
    FileReadError = 5,
    FileWriteError = 6,
    DiskFull = 7,
    
    // Format errors (100-199)
    InvalidMagic = 100,
    InvalidVersion = 101,
    InvalidHeader = 102,
    InvalidChecksum = 103,
    InvalidSection = 104,
    InvalidEntry = 105,
    InvalidIOCType = 106,
    InvalidIPAddress = 107,
    InvalidHash = 108,
    InvalidURL = 109,
    InvalidDomain = 110,
    InvalidSTIXBundle = 111,
    
    // Memory errors (200-299)
    OutOfMemory = 200,
    MappingFailed = 201,
    AddressSpaceExhausted = 202,
    AllocationFailed = 203,
    
    // Data errors (300-399)
    EntryNotFound = 300,
    DuplicateEntry = 301,
    EntryExpired = 302,
    EntryRevoked = 303,
    FeedNotFound = 304,
    FeedDisabled = 305,
    
    // Index errors (400-499)
    IndexCorrupted = 400,
    IndexFull = 401,
    IndexRebuildRequired = 402,
    BloomFilterFull = 403,
    
    // API errors (500-599)
    APIConnectionFailed = 500,
    APIAuthenticationFailed = 501,
    APIRateLimited = 502,
    APITimeout = 503,
    APIInvalidResponse = 504,
    APIKeyMissing = 505,
    APIKeyInvalid = 506,
    
    // Operation errors (600-699)
    ReadOnlyDatabase = 600,
    OperationTimeout = 601,
    OperationCancelled = 602,
    ConcurrentModification = 603,
    NotInitialized = 604,
    AlreadyInitialized = 605,
    
    // Limit errors (700-799)
    DatabaseTooLarge = 700,
    TooManyEntries = 701,
    StringTooLong = 702,
    TooManyFeeds = 703,
    TooManyTags = 704,
    
    // Parse errors (800-899)
    ParseError = 800,
    InvalidJSON = 801,
    InvalidSTIX = 802,
    InvalidTAXII = 803,
    InvalidCSV = 804,
    
    /// @brief Unknown error
    Unknown = 0xFFFFFFFF
};

/// @brief Get error message string
[[nodiscard]] constexpr const char* ThreatIntelErrorToString(ThreatIntelError error) noexcept {
    switch (error) {
        case ThreatIntelError::Success: return "Success";
        case ThreatIntelError::FileNotFound: return "File not found";
        case ThreatIntelError::FileAccessDenied: return "Access denied";
        case ThreatIntelError::InvalidMagic: return "Invalid magic number";
        case ThreatIntelError::InvalidVersion: return "Unsupported version";
        case ThreatIntelError::InvalidChecksum: return "Checksum mismatch";
        case ThreatIntelError::OutOfMemory: return "Out of memory";
        case ThreatIntelError::EntryNotFound: return "Entry not found";
        case ThreatIntelError::APIRateLimited: return "API rate limited";
        case ThreatIntelError::APITimeout: return "API timeout";
        case ThreatIntelError::NotInitialized: return "Store not initialized";
        default: return "Unknown error";
    }
}

/// @brief Detailed error information
struct StoreError {
    ThreatIntelError code{ThreatIntelError::Success};
    DWORD win32Error{0};
    std::string message;
    std::string context;  ///< Additional context (file path, IOC value, etc.)
    
    /// @brief Check if operation succeeded
    [[nodiscard]] bool IsSuccess() const noexcept {
        return code == ThreatIntelError::Success;
    }
    
    /// @brief Implicit bool conversion for if-checks
    [[nodiscard]] explicit operator bool() const noexcept {
        return IsSuccess();
    }
    
    /// @brief Factory for success result
    [[nodiscard]] static StoreError Success() noexcept {
        return StoreError{ThreatIntelError::Success, 0, {}, {}};
    }
    
    /// @brief Factory for Win32 error
    [[nodiscard]] static StoreError FromWin32(ThreatIntelError code, DWORD win32Err) noexcept {
        StoreError err;
        err.code = code;
        err.win32Error = win32Err;
        return err;
    }
    
    /// @brief Factory with message
    [[nodiscard]] static StoreError WithMessage(ThreatIntelError code, std::string msg) noexcept {
        StoreError err;
        err.code = code;
        err.message = std::move(msg);
        return err;
    }
    
    /// @brief Factory with context
    [[nodiscard]] static StoreError WithContext(ThreatIntelError code, std::string msg, std::string ctx) noexcept {
        StoreError err;
        err.code = code;
        err.message = std::move(msg);
        err.context = std::move(ctx);
        return err;
    }
    
    /// @brief Clear error state
    void Clear() noexcept {
        code = ThreatIntelError::Success;
        win32Error = 0;
        message.clear();
        context.clear();
    }
    
    /// @brief Get full error description
    [[nodiscard]] std::string GetFullMessage() const {
        std::string result = ThreatIntelErrorToString(code);
        if (!message.empty()) {
            result += ": " + message;
        }
        if (!context.empty()) {
            result += " [" + context + "]";
        }
        if (win32Error != 0) {
            result += " (Win32: " + std::to_string(win32Error) + ")";
        }
        return result;
    }
};

// ============================================================================
// MEMORY-MAPPED VIEW STRUCTURE
// ============================================================================

/// @brief Memory-mapped file view handle
struct MemoryMappedView {
    HANDLE fileHandle{INVALID_HANDLE_VALUE};
    HANDLE mappingHandle{INVALID_HANDLE_VALUE};
    void* baseAddress{nullptr};
    uint64_t fileSize{0};
    bool readOnly{true};
    
    /// @brief Check if view is valid and usable
    [[nodiscard]] bool IsValid() const noexcept {
        return baseAddress != nullptr && fileHandle != INVALID_HANDLE_VALUE;
    }
    
    /// @brief Get typed pointer at offset with bounds checking
    template<typename T>
    [[nodiscard]] const T* GetAt(uint64_t offset) const noexcept {
        if (offset + sizeof(T) > fileSize) {
            return nullptr;
        }
        return reinterpret_cast<const T*>(
            static_cast<const uint8_t*>(baseAddress) + offset
        );
    }
    
    /// @brief Get mutable typed pointer at offset
    template<typename T>
    [[nodiscard]] T* GetAtMutable(uint64_t offset) noexcept {
        if (readOnly || offset + sizeof(T) > fileSize) {
            return nullptr;
        }
        return reinterpret_cast<T*>(
            static_cast<uint8_t*>(baseAddress) + offset
        );
    }
    
    /// @brief Get span of bytes at offset
    [[nodiscard]] std::span<const uint8_t> GetSpan(uint64_t offset, size_t length) const noexcept {
        if (offset + length > fileSize) {
            return {};
        }
        return std::span<const uint8_t>(
            static_cast<const uint8_t*>(baseAddress) + offset, length
        );
    }
    
    /// @brief Get string view at offset
    [[nodiscard]] std::string_view GetString(uint64_t offset, size_t length) const noexcept {
        if (offset + length > fileSize) {
            return {};
        }
        return std::string_view(
            reinterpret_cast<const char*>(static_cast<const uint8_t*>(baseAddress) + offset),
            length
        );
    }
    
    /// @brief Get array of items at offset
    template<typename T>
    [[nodiscard]] std::span<const T> GetArray(uint64_t offset, size_t count) const noexcept {
        size_t totalSize = count * sizeof(T);
        if (offset + totalSize > fileSize) {
            return {};
        }
        return std::span<const T>(
            reinterpret_cast<const T*>(static_cast<const uint8_t*>(baseAddress) + offset),
            count
        );
    }
};

// ============================================================================
// QUERY OPTIONS
// ============================================================================

/// @brief Options for threat intel lookup operations
struct QueryOptions {
    /// @brief Maximum time to spend on lookup (milliseconds)
    uint32_t timeoutMs{1000};
    
    /// @brief Use query result cache
    bool useCache{true};
    
    /// @brief Check bloom filter first
    bool useBloomFilter{true};
    
    /// @brief Include expired entries in results
    bool includeExpired{false};
    
    /// @brief Include revoked entries in results
    bool includeRevoked{false};
    
    /// @brief Minimum reputation level to return
    ReputationLevel minReputation{ReputationLevel::Unknown};
    
    /// @brief Minimum confidence level to return
    ConfidenceLevel minConfidence{ConfidenceLevel::None};
    
    /// @brief Filter by source (0 = any)
    ThreatIntelSource sourceFilter{ThreatIntelSource::Unknown};
    
    /// @brief Filter by category (0 = any)
    ThreatCategory categoryFilter{ThreatCategory::Unknown};
    
    /// @brief Maximum results to return (0 = unlimited)
    uint32_t maxResults{100};
    
    /// @brief Include full STIX bundle in results
    bool includeSTIXBundle{false};
    
    /// @brief Include related IOCs in results
    bool includeRelated{false};
    
    /// @brief Log this lookup for audit
    bool logLookup{false};
};

// ============================================================================
// LOOKUP RESULT
// ============================================================================

/// @brief Result of a threat intel lookup operation
struct LookupResult {
    /// @brief Was the IOC found?
    bool found{false};
    
    /// @brief Entry ID if found
    uint64_t entryId{0};
    
    /// @brief IOC type
    IOCType type{IOCType::Unknown};
    
    /// @brief Reputation level
    ReputationLevel reputation{ReputationLevel::Unknown};
    
    /// @brief Confidence level
    ConfidenceLevel confidence{ConfidenceLevel::None};
    
    /// @brief Threat category
    ThreatCategory category{ThreatCategory::Unknown};
    
    /// @brief Source of intelligence
    ThreatIntelSource source{ThreatIntelSource::Unknown};
    
    /// @brief Entry flags
    IOCFlags flags{IOCFlags::None};
    
    /// @brief Should block?
    bool shouldBlock{false};
    
    /// @brief Should alert?
    bool shouldAlert{false};
    
    /// @brief Lookup time in nanoseconds
    uint64_t lookupTimeNs{0};
    
    /// @brief Was bloom filter used?
    bool bloomFilterChecked{false};
    
    /// @brief Was cache hit?
    bool cacheHit{false};
    
    /// @brief First seen timestamp
    uint64_t firstSeen{0};
    
    /// @brief Last seen timestamp
    uint64_t lastSeen{0};
    
    /// @brief Expiration time (0 = never)
    uint64_t expirationTime{0};
    
    /// @brief Description (if available)
    std::string description;
    
    /// @brief Tags
    std::vector<std::string> tags;
    
    /// @brief MITRE ATT&CK techniques
    std::vector<std::string> mitreTechniques;
    
    /// @brief Related IOC IDs
    std::vector<uint64_t> relatedIOCs;
    
    /// @brief Raw STIX bundle (if requested)
    std::string stixBundle;
    
    /// @brief Number of sources confirming this IOC
    uint16_t sourceCount{0};
    
    /// @brief VirusTotal detection ratio
    uint8_t vtPositives{0};
    uint8_t vtTotal{0};
    
    /// @brief AbuseIPDB confidence score
    uint8_t abuseIPDBScore{0};
    
    /// @brief Get threat score (reputation * confidence / 100)
    [[nodiscard]] uint8_t GetThreatScore() const noexcept {
        return static_cast<uint8_t>(
            (static_cast<uint16_t>(reputation) * static_cast<uint16_t>(confidence)) / 100
        );
    }
};

// ============================================================================
// STATISTICS
// ============================================================================

/// @brief Threat intel store statistics
struct ThreatIntelStatistics {
    // Entry counts by type
    uint64_t totalEntries{0};
    uint64_t ipv4Entries{0};
    uint64_t ipv6Entries{0};
    uint64_t domainEntries{0};
    uint64_t urlEntries{0};
    uint64_t hashEntries{0};
    uint64_t emailEntries{0};
    uint64_t certEntries{0};
    uint64_t otherEntries{0};
    uint64_t activeEntries{0};
    uint64_t expiredEntries{0};
    
    // Lookup performance
    uint64_t totalLookups{0};
    uint64_t cacheHits{0};
    uint64_t cacheMisses{0};
    uint64_t bloomFilterHits{0};
    uint64_t bloomFilterRejects{0};
    uint64_t indexLookups{0};
    uint64_t totalHits{0};
    uint64_t totalMisses{0};
    uint64_t totalBlocks{0};
    uint64_t totalAlerts{0};
    
    // Timing (nanoseconds)
    uint64_t avgLookupTimeNs{0};
    uint64_t minLookupTimeNs{0};
    uint64_t maxLookupTimeNs{0};
    uint64_t p50LookupTimeNs{0};
    uint64_t p95LookupTimeNs{0};
    uint64_t p99LookupTimeNs{0};
    
    // Feed statistics
    uint32_t totalFeeds{0};
    uint32_t activeFeeds{0};
    uint64_t lastFeedUpdate{0};
    uint32_t feedErrors{0};
    
    // Memory
    uint64_t databaseSizeBytes{0};
    uint64_t mappedSizeBytes{0};
    uint64_t cacheMemoryBytes{0};
    uint64_t indexMemoryBytes{0};
    
    /// @brief Calculate cache hit rate (0.0 - 1.0)
    [[nodiscard]] double CacheHitRate() const noexcept {
        uint64_t total = cacheHits + cacheMisses;
        return total > 0 ? static_cast<double>(cacheHits) / static_cast<double>(total) : 0.0;
    }
    
    /// @brief Calculate bloom filter effectiveness
    [[nodiscard]] double BloomFilterEffectiveness() const noexcept {
        uint64_t total = bloomFilterHits + bloomFilterRejects;
        return total > 0 ? static_cast<double>(bloomFilterRejects) / static_cast<double>(total) : 0.0;
    }
    
    /// @brief Calculate hit rate
    [[nodiscard]] double HitRate() const noexcept {
        uint64_t total = totalHits + totalMisses;
        return total > 0 ? static_cast<double>(totalHits) / static_cast<double>(total) : 0.0;
    }
};

// ============================================================================
// STIX 2.1 STRUCTURES
// ============================================================================

/// @brief STIX 2.1 object type
enum class STIXObjectType : uint8_t {
    Unknown = 0,
    
    // STIX Domain Objects (SDO)
    AttackPattern = 1,
    Campaign = 2,
    CourseOfAction = 3,
    Grouping = 4,
    Identity = 5,
    Indicator = 6,
    Infrastructure = 7,
    IntrusionSet = 8,
    Location = 9,
    Malware = 10,
    MalwareAnalysis = 11,
    Note = 12,
    ObservedData = 13,
    Opinion = 14,
    Report = 15,
    ThreatActor = 16,
    Tool = 17,
    Vulnerability = 18,
    
    // STIX Cyber-observable Objects (SCO)
    Artifact = 50,
    AutonomousSystem = 51,
    Directory = 52,
    DomainName = 53,
    EmailAddress = 54,
    EmailMessage = 55,
    File = 56,
    IPv4Addr = 57,
    IPv6Addr = 58,
    MACAddr = 59,
    Mutex = 60,
    NetworkTraffic = 61,
    Process = 62,
    Software = 63,
    URL = 64,
    UserAccount = 65,
    WindowsRegistryKey = 66,
    X509Certificate = 67,
    
    // STIX Relationship Objects (SRO)
    Relationship = 100,
    Sighting = 101
};

/// @brief STIX bundle reference
#pragma pack(push, 1)
struct STIXBundleRef {
    /// @brief Offset to bundle JSON in STIX section
    uint64_t bundleOffset;
    
    /// @brief Bundle size in bytes
    uint32_t bundleSize;
    
    /// @brief Number of objects in bundle
    uint16_t objectCount;
    
    /// @brief Primary object type
    STIXObjectType primaryType;
    
    /// @brief Reserved
    uint8_t reserved;
    
    /// @brief Bundle creation timestamp
    uint64_t created;
    
    /// @brief Bundle modification timestamp
    uint64_t modified;
};
#pragma pack(pop)

static_assert(sizeof(STIXBundleRef) == 32, "STIXBundleRef must be 32 bytes");

// ============================================================================
// UTILITY FUNCTIONS FORWARD DECLARATIONS
// ============================================================================

namespace Format {

/// @brief Validate database header integrity
[[nodiscard]] bool ValidateHeader(const ThreatIntelDatabaseHeader* header) noexcept;

/// @brief Compute CRC32 of header
[[nodiscard]] uint32_t ComputeHeaderCRC32(const ThreatIntelDatabaseHeader* header) noexcept;

/// @brief Compute SHA256 checksum of database
[[nodiscard]] bool ComputeDatabaseChecksum(
    const MemoryMappedView& view,
    std::array<uint8_t, 32>& outChecksum
) noexcept;

/// @brief Verify database integrity
[[nodiscard]] bool VerifyIntegrity(
    const MemoryMappedView& view,
    StoreError& error
) noexcept;

/// @brief Align offset to page boundary
[[nodiscard]] constexpr uint64_t AlignToPage(uint64_t offset) noexcept {
    return (offset + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
}

/// @brief Align offset to cache line
[[nodiscard]] constexpr size_t AlignToCacheLine(size_t offset) noexcept {
    return (offset + CACHE_LINE_SIZE - 1) & ~(CACHE_LINE_SIZE - 1);
}

/// @brief Parse IPv4 address from string
[[nodiscard]] std::optional<IPv4Address> ParseIPv4(std::string_view str) noexcept;

/// @brief Parse IPv6 address from string
[[nodiscard]] std::optional<IPv6Address> ParseIPv6(std::string_view str) noexcept;

/// @brief Parse hash string to HashValue
[[nodiscard]] std::optional<HashValue> ParseHashString(
    std::string_view hashStr,
    HashAlgorithm algo
) noexcept;

/// @brief Format IPv4 address to string
[[nodiscard]] std::string FormatIPv4(const IPv4Address& addr);

/// @brief Format IPv6 address to string
[[nodiscard]] std::string FormatIPv6(const IPv6Address& addr);

/// @brief Format hash value to hex string
[[nodiscard]] std::string FormatHashString(const HashValue& hash);

/// @brief Normalize domain name (lowercase, trim)
[[nodiscard]] std::string NormalizeDomain(std::string_view domain);

/// @brief Normalize URL (lowercase scheme/host, decode percent-encoding)
[[nodiscard]] std::string NormalizeURL(std::string_view url);

/// @brief Validate domain name format
[[nodiscard]] bool IsValidDomain(std::string_view domain) noexcept;

/// @brief Validate URL format
[[nodiscard]] bool IsValidURL(std::string_view url) noexcept;

/// @brief Validate email address format
[[nodiscard]] bool IsValidEmail(std::string_view email) noexcept;

/// @brief Calculate optimal bloom filter size
[[nodiscard]] size_t CalculateBloomFilterSize(
    size_t expectedElements,
    double falsePositiveRate
) noexcept;

/// @brief Calculate optimal number of hash functions for bloom filter
[[nodiscard]] size_t CalculateBloomHashFunctions(
    size_t filterSize,
    size_t expectedElements
) noexcept;

/// @brief Calculate optimal cache size based on database size
[[nodiscard]] uint32_t CalculateOptimalCacheSize(uint64_t dbSizeBytes) noexcept;

/// @brief Convert STIX timestamp string to Unix epoch
[[nodiscard]] std::optional<uint64_t> ParseSTIXTimestamp(std::string_view timestamp) noexcept;

/// @brief Format Unix epoch to STIX timestamp string
[[nodiscard]] std::string FormatSTIXTimestamp(uint64_t epoch);

/// @brief Generate UUID v4
[[nodiscard]] std::array<uint8_t, 16> GenerateUUID() noexcept;

/// @brief Format UUID to string
[[nodiscard]] std::string FormatUUID(const std::array<uint8_t, 16>& uuid);

/// @brief Parse UUID from string
[[nodiscard]] std::optional<std::array<uint8_t, 16>> ParseUUID(std::string_view str) noexcept;

} // namespace Format

namespace MemoryMapping {

/// @brief Open memory-mapped view of database file
[[nodiscard]] bool OpenView(
    const std::wstring& path,
    bool readOnly,
    MemoryMappedView& view,
    StoreError& error
) noexcept;

/// @brief Create new database file with header
[[nodiscard]] bool CreateDatabase(
    const std::wstring& path,
    uint64_t initialSize,
    MemoryMappedView& view,
    StoreError& error
) noexcept;

/// @brief Close memory-mapped view
void CloseView(MemoryMappedView& view) noexcept;

/// @brief Flush changes to disk
[[nodiscard]] bool FlushView(
    MemoryMappedView& view,
    StoreError& error
) noexcept;

/// @brief Extend database file size
[[nodiscard]] bool ExtendDatabase(
    MemoryMappedView& view,
    uint64_t newSize,
    StoreError& error
) noexcept;

/// @brief Remap view after extension
[[nodiscard]] bool RemapView(
    MemoryMappedView& view,
    StoreError& error
) noexcept;

} // namespace MemoryMapping

// ============================================================================
// CRC32 LOOKUP TABLE (IEEE 802.3 polynomial)
// ============================================================================

namespace Detail {

/// @brief CRC32 lookup table (generated at compile time)
constexpr std::array<uint32_t, 256> GenerateCRC32Table() noexcept {
    std::array<uint32_t, 256> table{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        for (int j = 0; j < 8; ++j) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
        table[i] = crc;
    }
    return table;
}

inline constexpr auto CRC32_TABLE = GenerateCRC32Table();

/// @brief Compute CRC32 of data
[[nodiscard]] inline uint32_t ComputeCRC32(
    const void* data,
    size_t length,
    uint32_t initial = 0xFFFFFFFF
) noexcept {
    const auto* bytes = static_cast<const uint8_t*>(data);
    uint32_t crc = initial;
    for (size_t i = 0; i < length; ++i) {
        crc = CRC32_TABLE[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

} // namespace Detail

} // namespace ThreatIntel
} // namespace ShadowStrike
