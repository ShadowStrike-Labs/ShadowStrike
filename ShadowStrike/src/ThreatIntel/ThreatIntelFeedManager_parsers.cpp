

#include "ThreatIntelFeedManager.hpp"
#include"ThreatIntelFeedManager_Util.hpp"
#include "ThreatIntelDatabase.hpp"
#include "ThreatIntelStore.hpp"


// JSON parsing using nlohmann/json
#include "../../external/nlohmann/json.hpp"

namespace ShadowStrike {
	namespace ThreatIntel {

        // ============================================================================
        // JSON FEED PARSER IMPLEMENTATION
        // ============================================================================

        bool JsonFeedParser::Parse(
            std::span<const uint8_t> data,
            std::vector<IOCEntry>& outEntries,
            const ParserConfig& config
        ) {
            // Size limits to prevent DoS via massive JSON
            constexpr size_t MAX_JSON_SIZE = 100 * 1024 * 1024;  // 100MB max
            constexpr size_t MAX_IOC_COUNT = 10000000;  // 10M IOCs max per feed
            constexpr size_t MAX_PATH_DEPTH = 32;  // Maximum nesting depth

            if (data.empty()) {
                m_lastError = "Empty data";
                return false;
            }

            if (data.size() > MAX_JSON_SIZE) {
                m_lastError = "JSON data exceeds size limit (100MB)";
                return false;
            }

            try {
                // Parse JSON with size validation
                std::string_view jsonView(reinterpret_cast<const char*>(data.data()), data.size());
                nlohmann::json root = nlohmann::json::parse(jsonView);

                // Navigate to IOC array using path
                nlohmann::json* iocArray = &root;

                if (!config.iocPath.empty()) {
                    // Validate path length
                    if (config.iocPath.size() > 1024) {
                        m_lastError = "IOC path too long";
                        return false;
                    }

                    // Simple path navigation (e.g., "$.data.indicators")
                    std::string path = config.iocPath;
                    if (path.starts_with("$.")) {
                        path = path.substr(2);
                    }

                    std::istringstream pathStream(path);
                    std::string segment;
                    size_t depth = 0;

                    while (std::getline(pathStream, segment, '.')) {
                        if (++depth > MAX_PATH_DEPTH) {
                            m_lastError = "Path too deep (max " + std::to_string(MAX_PATH_DEPTH) + " levels)";
                            return false;
                        }

                        if (segment.empty()) {
                            continue;  // Skip empty segments (e.g., "a..b")
                        }

                        if (iocArray->is_object() && iocArray->contains(segment)) {
                            iocArray = &(*iocArray)[segment];
                        }
                        else if (iocArray->is_array()) {
                            // Handle array index
                            size_t idx = 0;
                            auto [ptr, ec] = std::from_chars(segment.data(), segment.data() + segment.size(), idx);
                            if (ec == std::errc() && ptr == segment.data() + segment.size()) {
                                if (idx < iocArray->size()) {
                                    iocArray = &(*iocArray)[idx];
                                }
                                else {
                                    m_lastError = "Array index out of bounds: " + segment;
                                    return false;
                                }
                            }
                            else {
                                m_lastError = "Invalid array index: " + segment;
                                return false;
                            }
                        }
                        else {
                            m_lastError = "Path not found: " + config.iocPath;
                            return false;
                        }
                    }
                }

                if (!iocArray->is_array()) {
                    m_lastError = "IOC path does not point to array";
                    return false;
                }

                // Enforce IOC count limit
                const size_t iocCount = iocArray->size();
                if (iocCount > MAX_IOC_COUNT) {
                    m_lastError = "Too many IOCs in feed (max " + std::to_string(MAX_IOC_COUNT) + ")";
                    return false;
                }

                // Pre-allocate with reasonable limit
                const size_t reserveCount = std::min(iocCount, size_t{ 100000 });
                outEntries.reserve(reserveCount);

                for (const auto& item : *iocArray) {
                    IOCEntry entry;
                    if (ParseIOCEntry(&item, entry, config)) {
                        outEntries.push_back(std::move(entry));

                        // Safety check - shouldn't grow unbounded
                        if (outEntries.size() > MAX_IOC_COUNT) {
                            m_lastError = "Exceeded maximum IOC count during parsing";
                            return false;
                        }
                    }
                }

                return true;

            }
            catch (const nlohmann::json::exception& e) {
                m_lastError = "JSON parse error: " + std::string(e.what());
                return false;
            }
            catch (const std::bad_alloc&) {
                m_lastError = "Out of memory during JSON parsing";
                return false;
            }
            catch (const std::exception& e) {
                m_lastError = "Parse error: " + std::string(e.what());
                return false;
            }
        }

        bool JsonFeedParser::ParseStreaming(
            std::span<const uint8_t> data,
            IOCReceivedCallback callback,
            const ParserConfig& config
        ) {
            // Validate inputs
            if (!callback) {
                m_lastError = "Invalid callback";
                return false;
            }

            // Size limits to prevent DoS
            constexpr size_t MAX_STREAMING_SIZE = 100 * 1024 * 1024;  // 100MB
            if (data.empty()) {
                m_lastError = "Empty data";
                return false;
            }
            if (data.size() > MAX_STREAMING_SIZE) {
                m_lastError = "Data too large for streaming parse";
                return false;
            }

            try {
                std::string_view jsonView(reinterpret_cast<const char*>(data.data()), data.size());
                nlohmann::json root = nlohmann::json::parse(jsonView);

                nlohmann::json* iocArray = &root;

                if (!config.iocPath.empty()) {
                    // Validate path length
                    if (config.iocPath.size() > 1024) {
                        m_lastError = "IOC path too long";
                        return false;
                    }

                    std::string path = config.iocPath;
                    if (path.starts_with("$.")) path = path.substr(2);

                    std::istringstream pathStream(path);
                    std::string segment;
                    size_t depth = 0;
                    constexpr size_t MAX_PATH_DEPTH = 32;

                    while (std::getline(pathStream, segment, '.')) {
                        if (++depth > MAX_PATH_DEPTH) {
                            m_lastError = "Path too deep";
                            return false;
                        }
                        if (segment.empty()) continue;

                        if (iocArray->is_object() && iocArray->contains(segment)) {
                            iocArray = &(*iocArray)[segment];
                        }
                        else {
                            m_lastError = "Path not found: " + config.iocPath;
                            return false;
                        }
                    }
                }

                if (!iocArray->is_array()) {
                    m_lastError = "IOC path does not point to array";
                    return false;
                }

                // Process each item with size limit
                constexpr size_t MAX_ITEMS = 10000000;
                size_t processedCount = 0;

                for (const auto& item : *iocArray) {
                    if (++processedCount > MAX_ITEMS) {
                        m_lastError = "Exceeded maximum item count";
                        return false;
                    }

                    IOCEntry entry;
                    if (ParseIOCEntry(&item, entry, config)) {
                        if (!callback(entry)) {
                            return true;  // Callback requested stop
                        }
                    }
                }

                return true;

            }
            catch (const nlohmann::json::exception& e) {
                m_lastError = "JSON parse error: " + std::string(e.what());
                return false;
            }
            catch (const std::bad_alloc&) {
                m_lastError = "Out of memory";
                return false;
            }
            catch (const std::exception& e) {
                m_lastError = "Streaming parse error: " + std::string(e.what());
                return false;
            }
        }

        std::optional<std::string> JsonFeedParser::GetNextPageToken(
            std::span<const uint8_t> data,
            const ParserConfig& config
        ) {
            if (config.nextPagePath.empty()) return std::nullopt;
            if (data.empty() || data.size() > 100 * 1024 * 1024) return std::nullopt;

            try {
                std::string_view jsonView(reinterpret_cast<const char*>(data.data()), data.size());
                nlohmann::json root = nlohmann::json::parse(jsonView);

                auto result = ExtractJsonPath(&root, config.nextPagePath);

                // Validate token length
                if (result && result->size() > 1024) {
                    return std::nullopt;  // Token too long
                }

                return result;

            }
            catch (...) {
                return std::nullopt;
            }
        }

        std::optional<uint64_t> JsonFeedParser::GetTotalCount(
            std::span<const uint8_t> data,
            const ParserConfig& config
        ) {
            if (config.totalCountPath.empty()) return std::nullopt;
            if (data.empty() || data.size() > 100 * 1024 * 1024) return std::nullopt;

            try {
                std::string_view jsonView(reinterpret_cast<const char*>(data.data()), data.size());
                nlohmann::json root = nlohmann::json::parse(jsonView);

                auto value = ExtractJsonPath(&root, config.totalCountPath);
                if (value) {
                    // Safe conversion with bounds check
                    const uint64_t count = std::stoull(*value);
                    constexpr uint64_t MAX_COUNT = 100000000ULL;  // 100M max
                    return std::min(count, MAX_COUNT);
                }

            }
            catch (const std::out_of_range&) {
                // Value too large
            }
            catch (const std::invalid_argument&) {
                // Not a valid number
            }
            catch (...) {}

            return std::nullopt;
        }

        bool JsonFeedParser::ParseIOCEntry(
            const void* jsonObject,
            IOCEntry& entry,
            const ParserConfig& config
        ) {
            const nlohmann::json& obj = *static_cast<const nlohmann::json*>(jsonObject);

            try {
                // Extract value
                std::string value;
                if (!config.valuePath.empty()) {
                    auto extracted = ExtractJsonPath(&obj, config.valuePath);
                    if (!extracted) return false;
                    value = *extracted;
                }
                else {
                    // Try common field names
                    if (obj.contains("value")) value = obj["value"].get<std::string>();
                    else if (obj.contains("indicator")) value = obj["indicator"].get<std::string>();
                    else if (obj.contains("ioc")) value = obj["ioc"].get<std::string>();
                    else if (obj.contains("ip")) value = obj["ip"].get<std::string>();
                    else if (obj.contains("domain")) value = obj["domain"].get<std::string>();
                    else if (obj.contains("url")) value = obj["url"].get<std::string>();
                    else if (obj.contains("hash")) value = obj["hash"].get<std::string>();
                    else return false;
                }

                // Process value
                if (config.trimWhitespace) {
                    value = ShadowStrike::ThreatIntel_Util::TrimString(value);
                }
                if (config.lowercaseValues) {
                    value = ShadowStrike::ThreatIntel_Util::ToLowerCase(value);
                }

                if (value.empty()) return false;

                // Determine IOC type
                IOCType iocType = IOCType::Domain;  // Default

                if (!config.typePath.empty()) {
                    auto typeStr = ExtractJsonPath(&obj, config.typePath);
                    if (typeStr) {
                        // Check type mapping first
                        auto it = config.typeMapping.find(*typeStr);
                        if (it != config.typeMapping.end()) {
                            iocType = it->second;
                        }
                        else {
                            // Try to detect from type string
                            std::string lowerType = ShadowStrike::ThreatIntel_Util::ToLowerCase(*typeStr);
                            if (lowerType.find("ipv4") != std::string::npos || lowerType == "ip") {
                                iocType = IOCType::IPv4;
                            }
                            else if (lowerType.find("ipv6") != std::string::npos) {
                                iocType = IOCType::IPv6;
                            }
                            else if (lowerType.find("domain") != std::string::npos ||
                                lowerType.find("hostname") != std::string::npos) {
                                iocType = IOCType::Domain;
                            }
                            else if (lowerType.find("url") != std::string::npos) {
                                iocType = IOCType::URL;
                            }
                            else if (lowerType.find("hash") != std::string::npos ||
                                lowerType.find("md5") != std::string::npos ||
                                lowerType.find("sha") != std::string::npos) {
                                iocType = IOCType::FileHash;
                            }
                            else if (lowerType.find("email") != std::string::npos) {
                                iocType = IOCType::Email;
                            }
                        }
                    }
                }
                else {
                    // Auto-detect type from value
                    auto detected = DetectIOCType(value);
                    if (detected) {
                        iocType = *detected;
                    }
                }

                entry.type = iocType;

                // Set value based on type
                switch (iocType) {
                case IOCType::IPv4:
                case IOCType::CIDRv4: {
                    // Parse IPv4 address using safe parser
                    uint8_t octets[4] = { 0 };
                    if (ShadowStrike::ThreatIntel_Util::SafeParseIPv4(value, octets)) {
                        entry.value.ipv4 = IPv4Address(
                            octets[0], octets[1], octets[2], octets[3]
                        );
                    }
                    else {
                        return false;  // Invalid IPv4 format
                    }
                    break;
                }
                case IOCType::FileHash: {
                    // Parse hash
                    HashValue hash;
                    size_t hashLen = value.size() / 2;
                    if (hashLen == 16) hash.algorithm = HashAlgorithm::MD5;
                    else if (hashLen == 20) hash.algorithm = HashAlgorithm::SHA1;
                    else if (hashLen == 32) hash.algorithm = HashAlgorithm::SHA256;
                    else if (hashLen == 64) hash.algorithm = HashAlgorithm::SHA512;
                    else break;

                    hash.length = static_cast<uint8_t>(hashLen);
                    ShadowStrike::ThreatIntel_Util::ParseHexString(value, hash.data.data(), hashLen);
                    entry.value.hash = hash;
                    break;
                }
                default: {
                    // String-based IOCs use string pool reference
                    // For now, we store a hash of the value for deduplication
                    uint32_t valueHash = 0;
                    for (char c : value) {
                        valueHash = valueHash * 31 + static_cast<uint8_t>(c);
                    }
                    entry.value.stringRef.stringOffset = valueHash;
                    entry.value.stringRef.stringLength = static_cast<uint16_t>(std::min(value.size(), size_t(65535)));
                    break;
                }
                }

                // Extract confidence
                if (!config.confidencePath.empty()) {
                    auto confStr = ExtractJsonPath(&obj, config.confidencePath);
                    if (confStr) {
                        try {
                            int conf = std::stoi(*confStr);
                            if (conf >= 90) entry.confidence = ConfidenceLevel::Confirmed;
                            else if (conf >= 70) entry.confidence = ConfidenceLevel::High;
                            else if (conf >= 50) entry.confidence = ConfidenceLevel::Medium;
                            else if (conf >= 30) entry.confidence = ConfidenceLevel::Low;
                            else entry.confidence = ConfidenceLevel::None;
                        }
                        catch (...) {}
                    }
                }

                // Extract reputation
                if (!config.reputationPath.empty()) {
                    auto repStr = ExtractJsonPath(&obj, config.reputationPath);
                    if (repStr) {
                        std::string lowerRep = ShadowStrike::ThreatIntel_Util::ToLowerCase(*repStr);
                        if (lowerRep.find("malicious") != std::string::npos ||
                            lowerRep.find("bad") != std::string::npos) {
                            entry.reputation = ReputationLevel::Malicious;
                        }
                        else if (lowerRep.find("suspicious") != std::string::npos) {
                            entry.reputation = ReputationLevel::Suspicious;
                        }
                        else if (lowerRep.find("clean") != std::string::npos ||
                            lowerRep.find("safe") != std::string::npos) {
                            entry.reputation = ReputationLevel::Safe;
                        }
                    }
                }

                // Extract timestamps
                if (!config.firstSeenPath.empty()) {
                    auto ts = ExtractJsonPath(&obj, config.firstSeenPath);
                    if (ts) entry.firstSeen = ShadowStrike::ThreatIntel_Util::ParseISO8601(*ts);
                }

                if (!config.lastSeenPath.empty()) {
                    auto ts = ExtractJsonPath(&obj, config.lastSeenPath);
                    if (ts) entry.lastSeen = ShadowStrike::ThreatIntel_Util::ParseISO8601(*ts);
                }

                // Set current time
                uint64_t now = ShadowStrike::ThreatIntel_Util::GetCurrentTimestampImpl();
                if (entry.firstSeen == 0) entry.firstSeen = now;
                if (entry.lastSeen == 0) entry.lastSeen = now;
                entry.createdTime = now;

                return true;

            }
            catch (const std::exception& e) {
                m_lastError = "Entry parse error: " + std::string(e.what());
                return false;
            }
        }

        std::optional<std::string> JsonFeedParser::ExtractJsonPath(
            const void* root,
            const std::string& path
        ) {
            if (!root) {
                return std::nullopt;
            }

            // Validate path
            if (path.empty() || path.size() > 1024) {
                return std::nullopt;
            }

            const nlohmann::json& json = *static_cast<const nlohmann::json*>(root);

            try {
                std::string cleanPath = path;
                if (cleanPath.starts_with("$.")) {
                    cleanPath = cleanPath.substr(2);
                }

                const nlohmann::json* current = &json;
                std::istringstream pathStream(cleanPath);
                std::string segment;
                size_t depth = 0;
                constexpr size_t MAX_PATH_DEPTH = 32;

                while (std::getline(pathStream, segment, '.')) {
                    if (++depth > MAX_PATH_DEPTH) {
                        return std::nullopt;  // Path too deep
                    }

                    if (segment.empty()) continue;

                    if (current->is_object() && current->contains(segment)) {
                        current = &(*current)[segment];
                    }
                    else {
                        return std::nullopt;
                    }
                }

                if (current->is_string()) {
                    const std::string result = current->get<std::string>();
                    // Limit returned string length
                    constexpr size_t MAX_STRING_LENGTH = 65536;
                    if (result.size() > MAX_STRING_LENGTH) {
                        return result.substr(0, MAX_STRING_LENGTH);
                    }
                    return result;
                }
                else if (current->is_number_integer()) {
                    return std::to_string(current->get<int64_t>());
                }
                else if (current->is_number_unsigned()) {
                    return std::to_string(current->get<uint64_t>());
                }
                else if (current->is_number_float()) {
                    // Format floating point without scientific notation for reasonable numbers
                    const double val = current->get<double>();
                    if (std::isfinite(val)) {
                        std::ostringstream oss;
                        oss << std::fixed << std::setprecision(6) << val;
                        return oss.str();
                    }
                    return std::nullopt;
                }
                else if (current->is_boolean()) {
                    return current->get<bool>() ? "true" : "false";
                }

            }
            catch (const nlohmann::json::exception&) {
                // JSON access error
            }
            catch (const std::exception&) {
                // Other errors
            }

            return std::nullopt;
        }

        // ============================================================================
        // CSV FEED PARSER IMPLEMENTATION
        // ============================================================================

        bool CsvFeedParser::Parse(
            std::span<const uint8_t> data,
            std::vector<IOCEntry>& outEntries,
            const ParserConfig& config
        ) {
            // Size limits to prevent DoS
            constexpr size_t MAX_CSV_SIZE = 100 * 1024 * 1024;  // 100MB
            constexpr size_t MAX_LINE_COUNT = 10000000;  // 10M lines
            constexpr size_t MAX_LINE_LENGTH = 65536;  // 64KB per line

            if (data.empty()) {
                m_lastError = "Empty data";
                return false;
            }

            if (data.size() > MAX_CSV_SIZE) {
                m_lastError = "CSV data too large";
                return false;
            }

            // Check for null bytes which shouldn't be in CSV
            if (std::find(data.begin(), data.end(), '\0') != data.end()) {
                m_lastError = "CSV contains null bytes";
                return false;
            }

            try {
                std::string content(reinterpret_cast<const char*>(data.data()), data.size());
                std::istringstream stream(content);
                std::string line;

                bool firstLine = true;
                size_t lineNum = 0;

                // Pre-allocate with estimate
                const size_t estimatedLines = std::count(content.begin(), content.end(), '\n');
                outEntries.reserve(std::min(estimatedLines, size_t{ 100000 }));

                while (std::getline(stream, line)) {
                    lineNum++;

                    // Line count limit
                    if (lineNum > MAX_LINE_COUNT) {
                        m_lastError = "Too many lines in CSV";
                        return false;
                    }

                    // Line length limit
                    if (line.size() > MAX_LINE_LENGTH) {
                        continue;  // Skip overly long lines
                    }

                    // Skip empty lines and comments
                    if (line.empty() || line[0] == '#') continue;

                    // Skip header if configured
                    if (firstLine && config.csvHasHeader) {
                        firstLine = false;
                        continue;
                    }
                    firstLine = false;

                    // Parse line
                    auto fields = ParseLine(line, config.csvDelimiter, config.csvQuote);

                    if (fields.empty()) continue;

                    // Validate column index
                    if (config.csvValueColumn < 0 ||
                        static_cast<size_t>(config.csvValueColumn) >= fields.size()) {
                        continue;
                    }

                    std::string value = fields[static_cast<size_t>(config.csvValueColumn)];
                    if (config.trimWhitespace) {
                        value = ShadowStrike::ThreatIntel_Util::TrimString(value);
                    }
                    if (config.lowercaseValues) {
                        value = ShadowStrike::ThreatIntel_Util::ToLowerCase(value);
                    }

                    if (value.empty()) continue;

                    // Value length limit
                    constexpr size_t MAX_VALUE_LENGTH = 8192;
                    if (value.size() > MAX_VALUE_LENGTH) {
                        continue;  // Skip overly long values
                    }

                    // Create IOC entry
                    IOCEntry entry;

                    // Determine type
                    IOCType iocType = IOCType::Domain;  // Default

                    if (config.csvTypeColumn >= 0 &&
                        static_cast<size_t>(config.csvTypeColumn) < fields.size()) {
                        std::string typeStr = fields[static_cast<size_t>(config.csvTypeColumn)];
                        auto it = config.typeMapping.find(typeStr);
                        if (it != config.typeMapping.end()) {
                            iocType = it->second;
                        }
                    }
                    else {
                        // Auto-detect
                        auto detected = DetectIOCType(value);
                        if (detected) {
                            iocType = *detected;
                        }
                    }

                    entry.type = iocType;

                    // Set value based on type
                    switch (iocType) {
                    case IOCType::IPv4:
                    case IOCType::CIDRv4: {
                        uint8_t octets[4] = { 0 };
                        if (ShadowStrike::ThreatIntel_Util::SafeParseIPv4(value, octets)) {
                            entry.value.ipv4 = IPv4Address(
                                octets[0], octets[1], octets[2], octets[3]
                            );
                        }
                        else {
                            continue;  // Invalid IPv4, skip this entry
                        }
                        break;
                    }
                    case IOCType::FileHash: {
                        HashValue hash{};
                        const size_t hashLen = value.size() / 2;
                        if (hashLen == 16) hash.algorithm = HashAlgorithm::MD5;
                        else if (hashLen == 20) hash.algorithm = HashAlgorithm::SHA1;
                        else if (hashLen == 32) hash.algorithm = HashAlgorithm::SHA256;
                        else if (hashLen == 64) hash.algorithm = HashAlgorithm::SHA512;
                        else continue;  // Invalid hash length

                        // Validate hash fits in buffer
                        if (hashLen > hash.data.size()) {
                            continue;
                        }

                        hash.length = static_cast<uint8_t>(hashLen);
                        if (!ShadowStrike::ThreatIntel_Util::ParseHexString(value, hash.data.data(), hashLen)) {
                            continue;
                        }
                        entry.value.hash = hash;
                        break;
                    }
                    default: {
                        // String-based IOCs - compute hash for deduplication
                        uint32_t valueHash = 0;
                        for (const char c : value) {
                            valueHash = valueHash * 31 + static_cast<uint8_t>(c);
                        }
                        entry.value.stringRef.stringOffset = valueHash;
                        entry.value.stringRef.stringLength = static_cast<uint16_t>(
                            std::min(value.size(), static_cast<size_t>(65535))
                            );
                        break;
                    }
                    }

                    // Set timestamps
                    const uint64_t now = ShadowStrike::ThreatIntel_Util::GetCurrentTimestampImpl();
                    entry.firstSeen = now;
                    entry.lastSeen = now;
                    entry.createdTime = now;

                    outEntries.push_back(std::move(entry));
                }

                return true;

            }
            catch (const std::bad_alloc&) {
                m_lastError = "Out of memory";
                return false;
            }
            catch (const std::exception& e) {
                m_lastError = "CSV parse error: " + std::string(e.what());
                return false;
            }
        }

        bool CsvFeedParser::ParseStreaming(
            std::span<const uint8_t> data,
            IOCReceivedCallback callback,
            const ParserConfig& config
        ) {
            if (!callback) {
                m_lastError = "Invalid callback";
                return false;
            }

            std::vector<IOCEntry> entries;
            if (!Parse(data, entries, config)) {
                return false;
            }

            for (const auto& entry : entries) {
                if (!callback(entry)) {
                    return true;  // Stop requested
                }
            }

            return true;
        }

        std::optional<std::string> CsvFeedParser::GetNextPageToken(
            std::span<const uint8_t> /*data*/,
            const ParserConfig& /*config*/
        ) {
            // CSV feeds typically don't support pagination
            return std::nullopt;
        }

        std::optional<uint64_t> CsvFeedParser::GetTotalCount(
            std::span<const uint8_t> data,
            const ParserConfig& config
        ) {
            if (data.empty()) return std::nullopt;

            // Count lines safely with size limit
            constexpr size_t MAX_SIZE = 100 * 1024 * 1024;
            if (data.size() > MAX_SIZE) return std::nullopt;

            uint64_t count = 0;
            for (size_t i = 0; i < data.size(); ++i) {
                if (data[i] == '\n') {
                    count++;
                    // Overflow protection
                    if (count >= UINT64_MAX - 1) break;
                }
            }

            // Subtract header if present
            if (config.csvHasHeader && count > 0) {
                count--;
            }

            return count;
        }

        std::vector<std::string> CsvFeedParser::ParseLine(
            std::string_view line,
            char delimiter,
            char quote
        ) {
            std::vector<std::string> fields;

            // Size limits for security
            constexpr size_t MAX_FIELDS = 1000;
            constexpr size_t MAX_FIELD_LENGTH = 65536;

            if (line.empty()) {
                return fields;
            }

            try {
                fields.reserve(std::min(size_t{ 64 }, line.size() / 2 + 1));
            }
            catch (const std::bad_alloc&) {
                return fields;
            }

            std::string field;
            field.reserve(std::min(MAX_FIELD_LENGTH, line.size()));

            bool inQuotes = false;

            for (size_t i = 0; i < line.size(); ++i) {
                const char c = line[i];

                if (c == quote) {
                    if (inQuotes && i + 1 < line.size() && line[i + 1] == quote) {
                        // Escaped quote - add single quote and skip next
                        field += quote;
                        ++i;
                    }
                    else {
                        inQuotes = !inQuotes;
                    }
                }
                else if (c == delimiter && !inQuotes) {
                    // End of field
                    if (field.size() > MAX_FIELD_LENGTH) {
                        field = field.substr(0, MAX_FIELD_LENGTH);
                    }
                    fields.push_back(std::move(field));
                    field.clear();

                    // Field count limit
                    if (fields.size() >= MAX_FIELDS) {
                        return fields;
                    }
                }
                else if (c == '\r') {
                    // Skip carriage return
                }
                else {
                    // Check field length before adding
                    if (field.size() < MAX_FIELD_LENGTH) {
                        field += c;
                    }
                }
            }

            // Add last field
            if (field.size() > MAX_FIELD_LENGTH) {
                field = field.substr(0, MAX_FIELD_LENGTH);
            }

            if (fields.size() < MAX_FIELDS) {
                fields.push_back(std::move(field));
            }

            return fields;
        }

        // ============================================================================
        // STIX FEED PARSER IMPLEMENTATION
        // ============================================================================

        bool StixFeedParser::Parse(
            std::span<const uint8_t> data,
            std::vector<IOCEntry>& outEntries,
            const ParserConfig& /*config*/
        ) {
            // Security limits to prevent DoS
            constexpr size_t MAX_STIX_SIZE = 100 * 1024 * 1024;  // 100MB
            constexpr size_t MAX_OBJECTS = 10000000;  // 10M objects

            if (data.empty()) {
                m_lastError = "Empty STIX data";
                return false;
            }

            if (data.size() > MAX_STIX_SIZE) {
                m_lastError = "STIX data too large";
                return false;
            }

            try {
                // Safe string construction with size validation
                std::string jsonStr(reinterpret_cast<const char*>(data.data()), data.size());
                nlohmann::json root = nlohmann::json::parse(jsonStr);

                // STIX bundle structure validation
                if (!root.is_object()) {
                    m_lastError = "Invalid STIX bundle: not an object";
                    return false;
                }

                if (!root.contains("objects") || !root["objects"].is_array()) {
                    m_lastError = "Invalid STIX bundle: missing objects array";
                    return false;
                }

                const auto& objects = root["objects"];

                // Check objects count limit
                if (objects.size() > MAX_OBJECTS) {
                    m_lastError = "Too many objects in STIX bundle";
                    return false;
                }

                // Pre-allocate with reasonable estimate
                const size_t estimatedIndicators = std::min(objects.size(), size_t{ 100000 });
                try {
                    outEntries.reserve(estimatedIndicators);
                }
                catch (const std::bad_alloc&) {
                    m_lastError = "Out of memory";
                    return false;
                }

                for (const auto& obj : objects) {
                    // Validate object structure
                    if (!obj.is_object() || !obj.contains("type")) {
                        continue;
                    }

                    // Get object type safely
                    if (!obj["type"].is_string()) {
                        continue;
                    }

                    const std::string objType = obj["type"].get<std::string>();

                    // Validate type string length
                    if (objType.empty() || objType.size() > 256) {
                        continue;
                    }

                    // Process indicator objects
                    if (objType == "indicator") {
                        if (!obj.contains("pattern") || !obj["pattern"].is_string()) {
                            continue;
                        }

                        const std::string pattern = obj["pattern"].get<std::string>();

                        // Pattern length limit
                        constexpr size_t MAX_PATTERN_LENGTH = 65536;
                        if (pattern.size() > MAX_PATTERN_LENGTH) {
                            continue;
                        }

                        IOCEntry entry;

                        if (ParseSTIXPattern(pattern, entry)) {
                            // Extract metadata safely
                            if (obj.contains("created") && obj["created"].is_string()) {
                                entry.createdTime = ShadowStrike::ThreatIntel_Util::ParseISO8601(obj["created"].get<std::string>());
                            }
                            if (obj.contains("modified") && obj["modified"].is_string()) {
                                entry.lastSeen = ShadowStrike::ThreatIntel_Util::ParseISO8601(obj["modified"].get<std::string>());
                            }
                            if (obj.contains("valid_from") && obj["valid_from"].is_string()) {
                                entry.firstSeen = ShadowStrike::ThreatIntel_Util::ParseISO8601(obj["valid_from"].get<std::string>());
                            }
                            if (obj.contains("valid_until") && obj["valid_until"].is_string()) {
                                entry.expirationTime = ShadowStrike::ThreatIntel_Util::ParseISO8601(obj["valid_until"].get<std::string>());
                            }
                            if (obj.contains("confidence") && obj["confidence"].is_number_integer()) {
                                const int conf = std::clamp(obj["confidence"].get<int>(), 0, 100);
                                if (conf >= 90) entry.confidence = ConfidenceLevel::Confirmed;
                                else if (conf >= 70) entry.confidence = ConfidenceLevel::High;
                                else if (conf >= 50) entry.confidence = ConfidenceLevel::Medium;
                                else entry.confidence = ConfidenceLevel::Low;
                            }

                            try {
                                outEntries.push_back(std::move(entry));
                            }
                            catch (const std::bad_alloc&) {
                                m_lastError = "Out of memory";
                                return false;
                            }
                        }
                    }
                }

                return true;

            }
            catch (const nlohmann::json::exception& e) {
                m_lastError = "STIX JSON parse error: " + std::string(e.what());
                return false;
            }
            catch (const std::bad_alloc&) {
                m_lastError = "Out of memory";
                return false;
            }
            catch (const std::exception& e) {
                m_lastError = "STIX parse error: " + std::string(e.what());
                return false;
            }
        }

        bool StixFeedParser::ParseStreaming(
            std::span<const uint8_t> data,
            IOCReceivedCallback callback,
            const ParserConfig& config
        ) {
            if (!callback) {
                m_lastError = "Invalid callback";
                return false;
            }

            std::vector<IOCEntry> entries;
            if (!Parse(data, entries, config)) {
                return false;
            }

            for (const auto& entry : entries) {
                try {
                    if (!callback(entry)) {
                        return true;  // Stop requested by callback
                    }
                }
                catch (const std::exception&) {
                    // Callback exception - continue with next entry
                }
            }

            return true;
        }

        std::optional<std::string> StixFeedParser::GetNextPageToken(
            std::span<const uint8_t> data,
            const ParserConfig& /*config*/
        ) {
            // Security limits
            constexpr size_t MAX_SIZE = 100 * 1024 * 1024;
            constexpr size_t MAX_TOKEN_LENGTH = 1024;

            if (data.empty() || data.size() > MAX_SIZE) {
                return std::nullopt;
            }

            try {
                std::string jsonStr(reinterpret_cast<const char*>(data.data()), data.size());
                nlohmann::json root = nlohmann::json::parse(jsonStr);

                if (!root.is_object()) {
                    return std::nullopt;
                }

                // Check for TAXII pagination
                if (root.contains("next") && root["next"].is_string()) {
                    std::string token = root["next"].get<std::string>();
                    if (!token.empty() && token.size() <= MAX_TOKEN_LENGTH) {
                        return token;
                    }
                }

                // Alternative pagination
                if (root.contains("more") && root["more"].is_boolean() && root["more"].get<bool>()) {
                    if (root.contains("id") && root["id"].is_string()) {
                        std::string token = root["id"].get<std::string>();
                        if (!token.empty() && token.size() <= MAX_TOKEN_LENGTH) {
                            return token;
                        }
                    }
                }

            }
            catch (const std::exception&) {
                // Parse error - no pagination available
            }

            return std::nullopt;
        }

        std::optional<uint64_t> StixFeedParser::GetTotalCount(
            std::span<const uint8_t> data,
            const ParserConfig& /*config*/
        ) {
            // Security limits
            constexpr size_t MAX_SIZE = 100 * 1024 * 1024;
            constexpr uint64_t MAX_COUNT = 100000000ULL;  // 100M max

            if (data.empty() || data.size() > MAX_SIZE) {
                return std::nullopt;
            }

            try {
                std::string jsonStr(reinterpret_cast<const char*>(data.data()), data.size());
                nlohmann::json root = nlohmann::json::parse(jsonStr);

                if (!root.is_object()) {
                    return std::nullopt;
                }

                if (root.contains("objects") && root["objects"].is_array()) {
                    const uint64_t count = root["objects"].size();
                    return std::min(count, MAX_COUNT);
                }

            }
            catch (const std::exception&) {
                // Parse error
            }

            return std::nullopt;
        }

        bool StixFeedParser::ParseSTIXPattern(
            const std::string& pattern,
            IOCEntry& entry
        ) {
            // STIX pattern format: [type:property = 'value']
            // Examples:
            // [ipv4-addr:value = '192.168.1.1']
            // [domain-name:value = 'malware.com']
            // [file:hashes.SHA-256 = 'abc123...']

            // Pattern length validation
            constexpr size_t MAX_PATTERN_LENGTH = 65536;
            if (pattern.empty() || pattern.size() > MAX_PATTERN_LENGTH) {
                return false;
            }

            // Simple pattern parser with bounds checking
            const size_t start = pattern.find('[');
            const size_t end = pattern.rfind(']');
            if (start == std::string::npos || end == std::string::npos || end <= start) {
                return false;
            }

            // Extract content between brackets safely
            const size_t contentLength = end - start - 1;
            if (contentLength == 0 || contentLength > MAX_PATTERN_LENGTH) {
                return false;
            }

            std::string content = pattern.substr(start + 1, contentLength);

            // Find type and value separator
            const size_t colonPos = content.find(':');
            if (colonPos == std::string::npos || colonPos == 0 || colonPos >= content.size() - 1) {
                return false;
            }

            // Extract STIX type with length validation
            std::string stixType = ShadowStrike::ThreatIntel_Util::TrimString(content.substr(0, colonPos));
            if (stixType.empty() || stixType.size() > 256) {
                return false;
            }

            std::string rest = content.substr(colonPos + 1);
            if (rest.empty()) {
                return false;
            }

            // Find value in quotes - use proper quote matching
            const size_t valueStart = rest.find('\'');
            const size_t valueEnd = rest.rfind('\'');
            if (valueStart == std::string::npos || valueEnd == std::string::npos || valueEnd <= valueStart) {
                return false;
            }

            // Extract value safely
            const size_t valueLength = valueEnd - valueStart - 1;
            if (valueLength == 0) {
                return false;
            }

            // Value length limit for security
            constexpr size_t MAX_VALUE_LENGTH = 8192;
            if (valueLength > MAX_VALUE_LENGTH) {
                return false;
            }

            std::string value = rest.substr(valueStart + 1, valueLength);

            // Map STIX type to IOCType
            auto iocType = MapSTIXTypeToIOCType(stixType);
            if (!iocType) {
                return false;
            }

            entry.type = *iocType;

            // Set value based on type
            switch (entry.type) {
            case IOCType::IPv4:
            case IOCType::CIDRv4: {
                uint8_t octets[4] = { 0 };
                if (ShadowStrike::ThreatIntel_Util::SafeParseIPv4(value, octets)) {
                    entry.value.ipv4 = IPv4Address(
                        octets[0], octets[1], octets[2], octets[3]
                    );
                }
                else {
                    return false;  // Invalid IPv4 format
                }
                break;
            }
            case IOCType::FileHash: {
                // Validate hex string format
                if (value.size() % 2 != 0) {
                    return false;
                }

                HashValue hash{};
                const size_t hashLen = value.size() / 2;

                // Validate hash length
                if (hashLen == 16) {
                    hash.algorithm = HashAlgorithm::MD5;
                }
                else if (hashLen == 20) {
                    hash.algorithm = HashAlgorithm::SHA1;
                }
                else if (hashLen == 32) {
                    hash.algorithm = HashAlgorithm::SHA256;
                }
                else if (hashLen == 64) {
                    hash.algorithm = HashAlgorithm::SHA512;
                }
                else {
                    return false;  // Unsupported hash length
                }

                // Bounds check before parsing
                if (hashLen > hash.data.size()) {
                    return false;
                }

                hash.length = static_cast<uint8_t>(hashLen);
                if (!ShadowStrike::ThreatIntel_Util::ParseHexString(value, hash.data.data(), hashLen)) {
                    return false;
                }
                entry.value.hash = hash;
                break;
            }
            default: {
                // String-based IOCs - compute hash for deduplication
                uint32_t valueHash = 0;
                for (const char c : value) {
                    // Overflow is intentional for hash mixing
                    valueHash = valueHash * 31 + static_cast<uint8_t>(c);
                }
                entry.value.stringRef.stringOffset = valueHash;
                entry.value.stringRef.stringLength = static_cast<uint16_t>(
                    std::min(value.size(), size_t{ 65535 })
                    );
                break;
            }
            }

            const uint64_t now = ShadowStrike::ThreatIntel_Util::GetCurrentTimestampImpl();
            entry.firstSeen = now;
            entry.lastSeen = now;
            entry.createdTime = now;

            return true;
        }

        std::optional<IOCType> StixFeedParser::MapSTIXTypeToIOCType(const std::string& stixType) {
            // Validate input
            if (stixType.empty() || stixType.size() > 256) {
                return std::nullopt;
            }

            // Standard STIX type mappings
            if (stixType == "ipv4-addr") return IOCType::IPv4;
            if (stixType == "ipv6-addr") return IOCType::IPv6;
            if (stixType == "domain-name") return IOCType::Domain;
            if (stixType == "url") return IOCType::URL;
            if (stixType == "email-addr") return IOCType::Email;
            if (stixType == "file") return IOCType::FileHash;
            if (stixType == "x509-certificate") return IOCType::CertFingerprint;
            if (stixType == "windows-registry-key") return IOCType::RegistryKey;
            if (stixType == "process") return IOCType::ProcessName;
            if (stixType == "mutex") return IOCType::MutexName;

            return std::nullopt;
        }



	}// namespace ThreatIntel
}// namespace ShadowStrike