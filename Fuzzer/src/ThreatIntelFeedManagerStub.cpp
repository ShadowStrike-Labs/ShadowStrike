// ============================================================================
// ThreatIntelFeedManagerStub.cpp — Minimal link closure for feed parser fuzzing
// ============================================================================
// Provides DetectIOCType (used by CsvFeedParser::Parse) without pulling in
// the full FeedManager which depends on ThreatIntelDatabase/Store/WinInet.
// ============================================================================

#include "pch.h"
#include "ThreatIntel/ThreatIntelFormat.hpp"
#include "ThreatIntel/ThreatIntelFeedManager_Util.hpp"

#include <optional>
#include <string_view>

namespace ShadowStrike {
namespace ThreatIntel {

std::optional<IOCType> DetectIOCType(std::string_view value) {
    if (value.empty()) return std::nullopt;

    if (ThreatIntel_Util::IsValidHash(value)) {
        switch (value.size()) {
            case 32:  return IOCType::FileHash;   // MD5
            case 40:  return IOCType::FileHash;   // SHA1
            case 64:  return IOCType::FileHash;   // SHA256
            case 128: return IOCType::FileHash;   // SHA512
            default:  break;
        }
    }

    if (ThreatIntel_Util::IsValidUrlString(value))
        return IOCType::URL;

    if (ThreatIntel_Util::IsValidEmail(value))
        return IOCType::Email;

    if (ThreatIntel_Util::IsValidIPv4(value))
        return IOCType::IPv4;

    if (ThreatIntel_Util::IsValidIPv6(value))
        return IOCType::IPv6;

    if (ThreatIntel_Util::IsValidDomain(value))
        return IOCType::Domain;

    return std::nullopt;
}

}  // namespace ThreatIntel
}  // namespace ShadowStrike
