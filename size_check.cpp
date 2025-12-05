#include <iostream>
#include <cstdint>
#include <atomic>
#include <array>

// Define constants
constexpr size_t CACHE_LINE_SIZE = 64;

// Minimal IOCType
enum class IOCType : uint8_t { None = 0 };
enum class IOCFlags : uint32_t { None = 0 };
enum class ThreatIntelSource : uint8_t { None = 0 };
enum class ReputationLevel : uint8_t { None = 0 };
enum class ConfidenceLevel : uint8_t { None = 0 };
enum class ThreatCategory : uint8_t { None = 0 };

struct IPv4Address { uint8_t data[4]; };
struct IPv6Address { uint8_t data[16]; };
struct HashValue { uint8_t data[64]; };

#pragma pack(push, 1)
struct alignas(CACHE_LINE_SIZE) TestIOCEntry {
    // IDENTIFICATION (32 bytes)
    uint64_t entryId;           // 8
    uint32_t stixIdOffset;      // 4
    uint16_t stixIdLength;      // 2
    IOCType type;               // 1
    uint8_t reserved1;          // 1
    IOCFlags flags;             // 4
    ThreatIntelSource source;   // 1
    ThreatIntelSource secondarySource; // 1
    uint32_t feedId;            // 4
    // = 26 bytes (need 6 more for 32)
    
    // REPUTATION (16 bytes)
    ReputationLevel reputation; // 1
    ConfidenceLevel confidence; // 1
    ThreatCategory category;    // 1
    ThreatCategory secondaryCategory; // 1
    uint16_t sourceCount;       // 2
    uint16_t relatedCount;      // 2
    uint8_t severity;           // 1
    uint8_t reserved2[3];       // 3
    // = 12 bytes
    
    // IOC VALUE (80 bytes)
    union {
        IPv4Address ipv4;
        IPv6Address ipv6;
        HashValue hash;
        struct {
            uint64_t stringOffset;
            uint32_t stringLength;
            uint32_t patternOffset;
            uint32_t patternLength;
            uint8_t padding[56];
        } stringRef;
        std::array<uint8_t, 76> raw;
    } value;
    uint8_t valueType;
    uint8_t reserved3[3];
    // = 80 bytes
    
    // TIMESTAMPS (32 bytes)
    uint64_t firstSeen;
    uint64_t lastSeen;
    uint64_t createdTime;
    uint64_t expirationTime;
    
    // METADATA (32 bytes)
    uint32_t descriptionOffset;
    uint16_t descriptionLength;
    uint32_t tagsOffset;
    uint16_t tagCount;
    uint32_t mitreOffset;
    uint16_t mitreCount;
    uint32_t relatedOffset;
    uint32_t stixBundleOffset;
    uint32_t stixBundleSize;
    // = 28 bytes
    
    // STATISTICS (16 bytes)
    std::atomic<uint32_t> hitCount;
    std::atomic<uint32_t> lastHitTime;
    std::atomic<uint16_t> falsePositiveCount;
    std::atomic<uint16_t> truePositiveCount;
    
    // Reserved
    uint8_t reserved4[4];
    
    // API DATA (32 bytes)
    uint8_t vtPositives;
    uint8_t vtTotal;
    uint8_t abuseIPDBScore;
    uint8_t greyNoiseClass;
    uint16_t shodanPorts;
    uint8_t reserved5[26];
    
    // PADDING
    uint8_t padding[16];
};
#pragma pack(pop)

int main() {
    std::cout << "sizeof(TestIOCEntry) = " << sizeof(TestIOCEntry) << std::endl;
    std::cout << "alignof(TestIOCEntry) = " << alignof(TestIOCEntry) << std::endl;
    std::cout << "sizeof(std::atomic<uint32_t>) = " << sizeof(std::atomic<uint32_t>) << std::endl;
    std::cout << "sizeof(std::atomic<uint16_t>) = " << sizeof(std::atomic<uint16_t>) << std::endl;
    
    // Section sizes
    std::cout << "\nSection offsets:" << std::endl;
    std::cout << "entryId offset: " << offsetof(TestIOCEntry, entryId) << std::endl;
    std::cout << "reputation offset: " << offsetof(TestIOCEntry, reputation) << std::endl;
    std::cout << "value offset: " << offsetof(TestIOCEntry, value) << std::endl;
    std::cout << "firstSeen offset: " << offsetof(TestIOCEntry, firstSeen) << std::endl;
    std::cout << "descriptionOffset offset: " << offsetof(TestIOCEntry, descriptionOffset) << std::endl;
    std::cout << "hitCount offset: " << offsetof(TestIOCEntry, hitCount) << std::endl;
    std::cout << "reserved4 offset: " << offsetof(TestIOCEntry, reserved4) << std::endl;
    std::cout << "vtPositives offset: " << offsetof(TestIOCEntry, vtPositives) << std::endl;
    std::cout << "padding offset: " << offsetof(TestIOCEntry, padding) << std::endl;
    return 0;
}
