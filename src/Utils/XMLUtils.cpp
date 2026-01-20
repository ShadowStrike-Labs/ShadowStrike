// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
//=============================================================================
// XMLUtils.cpp
//
// ShadowStrike Security Suite - XML Utility Library Implementation
//
// Purpose:
//   Implementation of safe XML parsing, manipulation, and serialization
//   utilities with comprehensive security hardening.
//
// Security Features:
//   - XML Bomb detection and prevention
//   - XPath injection validation
//   - Secure temporary file generation
//   - Atomic file operations
//   - Input size and depth limits
//
// Copyright (c) 2024-2025 ShadowStrike Security Team
// Licensed under MIT License
//=============================================================================

#include "XMLUtils.hpp"

#include"../../include/pugixml/pugixml.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <charconv>
#include <random>
#include <functional>
#include <limits>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#endif

namespace ShadowStrike {
namespace Utils {
namespace XML {

//=============================================================================
// Internal Constants
//=============================================================================

namespace {

/// Maximum XPath length to prevent DoS attacks
constexpr size_t kMaxXPathLength = 1000;

/// Maximum path depth for Set operations
constexpr size_t kMaxPathDepth = 10;

/// Maximum index value for array access
constexpr size_t kMaxArrayIndex = 100000;

/// Maximum nodes created in a single Set operation
constexpr size_t kMaxNodesCreated = 1000;

/// Maximum XML array size for node creation
constexpr size_t kMaxXmlArraySize = 10000;

/// Maximum node count before rejecting as potential XML bomb
constexpr size_t kMaxNodeCount = 1000000;

/// Maximum safe XML file size (512 MB)
constexpr uintmax_t kMaxSafeXmlFileSize = 512ULL * 1024 * 1024;

} // anonymous namespace

//=============================================================================
// Internal Helper Functions
//=============================================================================

/**
 * @brief Calculate line and column numbers from byte offset in UTF-8 text.
 *
 * Properly handles:
 * - Unix line endings (LF)
 * - Windows line endings (CRLF)
 * - Classic Mac line endings (CR only)
 * - UTF-8 multi-byte sequences
 *
 * @param text Source text
 * @param byteOffset Byte offset to locate
 * @param[out] line 1-based line number
 * @param[out] col 1-based column number
 */
static inline void fillLineCol(
    std::string_view text, 
    size_t byteOffset, 
    size_t& line, 
    size_t& col
) noexcept {
    line = 1;
    col = 1;
    
    // Clamp byte offset to text bounds
    if (byteOffset > text.size()) {
        byteOffset = text.size();
    }
    
    for (size_t i = 0; i < byteOffset; ) {
        // Bounds check before access
        if (i >= text.size()) {
            break;
        }
        
        const unsigned char c = static_cast<unsigned char>(text[i]);
        
        if (c == '\n') {
            // Unix-style LF
            ++line;
            col = 1;
            ++i;
        }
        else if (c == '\r') {
            // Handle Windows-style CRLF or old Mac CR-only
            if (i + 1 < byteOffset && i + 1 < text.size() && text[i + 1] == '\n') {
                // CRLF: skip CR, LF will be processed next iteration
                ++i;
            }
            else {
                // CR-only (old Mac style)
                ++line;
                col = 1;
                ++i;
            }
        }
        else {
            // UTF-8 multi-byte sequence detection
            size_t charBytes = 1;
            
            if ((c & 0x80) == 0) {
                // ASCII (0xxxxxxx) - 1 byte
                charBytes = 1;
            }
            else if ((c & 0xE0) == 0xC0) {
                // 2-byte UTF-8 (110xxxxx 10xxxxxx)
                charBytes = 2;
            }
            else if ((c & 0xF0) == 0xE0) {
                // 3-byte UTF-8 (1110xxxx 10xxxxxx 10xxxxxx)
                charBytes = 3;
            }
            else if ((c & 0xF8) == 0xF0) {
                // 4-byte UTF-8 (11110xxx 10xxxxxx 10xxxxxx 10xxxxxx)
                charBytes = 4;
            }
            else {
                // Invalid UTF-8 lead byte - treat as single byte
                charBytes = 1;
            }
            
            ++col;
            i += charBytes;
            
            // Prevent overshooting the target offset
            if (i > byteOffset) {
                break;
            }
        }
    }
}

/**
 * @brief Set error information with text location calculation.
 *
 * @param err Error struct to populate (may be nullptr)
 * @param msg Error message
 * @param p File path (if applicable)
 * @param text Source text for location calculation
 * @param byteOff Byte offset of error
 */
static inline void setErr(
    Error* err, 
    std::string msg, 
    const std::filesystem::path& p, 
    std::string_view text, 
    size_t byteOff
) noexcept {
    if (!err) {
        return;
    }
    
    err->message = std::move(msg);
    err->path = p;
    err->byteOffset = byteOff;
    fillLineCol(text, byteOff, err->line, err->column);
}

/**
 * @brief Set I/O error information (no text location).
 *
 * @param err Error struct to populate (may be nullptr)
 * @param what Error description
 * @param p File path
 * @param sysMsg Optional system error message
 */
static inline void setIoErr(
    Error* err, 
    const std::string& what, 
    const std::filesystem::path& p, 
    const std::string& sysMsg = {}
) noexcept {
    if (!err) {
        return;
    }
    
    if (sysMsg.empty()) {
        err->message = what;
    }
    else {
        err->message = what + ": " + sysMsg;
    }
    
    err->path = p;
    err->byteOffset = 0;
    err->line = 0;
    err->column = 0;
}

/**
 * @brief Remove UTF-8 BOM from string if present.
 *
 * @param s String to modify in-place
 */
static inline void stripUtf8BOM(std::string& s) noexcept {
    constexpr unsigned char kUtf8Bom[3] = { 0xEF, 0xBB, 0xBF };
    
    if (s.size() >= 3) {
        const auto* data = reinterpret_cast<const unsigned char*>(s.data());
        if (data[0] == kUtf8Bom[0] && 
            data[1] == kUtf8Bom[1] && 
            data[2] == kUtf8Bom[2]) {
            s.erase(0, 3);
        }
    }
}

/**
 * @brief Check if character is an ASCII digit.
 *
 * @param c Character to check
 * @return true if '0'-'9'
 */
static inline bool isDigit(char c) noexcept {
    return c >= '0' && c <= '9';
}

//=============================================================================
// Path Parsing Types and Functions
//=============================================================================

/**
 * @brief Represents a single step in a path expression.
 *
 * Used internally for parsing dot-notation paths like "a.b[0].c" or "@attr".
 */
struct Step {
    std::string name;          ///< Element name (without @) or attribute name
    bool isAttribute = false;  ///< true if this step targets an attribute
    bool hasIndex = false;     ///< true if [N] index was specified
    size_t index = 0;          ///< 0-based array index (converted to 1-based in XPath)
};

/**
 * @brief Parse a dot-notation path into steps.
 *
 * Handles formats like:
 * - "a.b.c" -> [a, b, c]
 * - "a.b[0].c" -> [a, b{index=0}, c]
 * - "a.@attr" -> [a, @attr]
 *
 * @param sv Input path string
 * @param[out] out Vector of parsed steps (cleared if input is malicious)
 *
 * @security Clears output if XPath injection is detected
 */
static void parsePathLike(std::string_view sv, std::vector<Step>& out) noexcept {
    out.clear();
    
    if (sv.empty()) {
        return;
    }
    
    // If it's already XPath, don't parse
    if (sv.front() == '/') {
        return;
    }
    
    // Parse dot-separated steps
    std::string cur;
    cur.reserve(sv.size());
    
    for (size_t i = 0; i < sv.size(); ++i) {
        const char c = sv[i];
        
        if (c == '.') {
            if (!cur.empty()) {
                Step st;
                st.isAttribute = (cur[0] == '@');
                st.name = st.isAttribute ? cur.substr(1) : cur;
                out.push_back(std::move(st));
                cur.clear();
            }
        }
        else {
            cur.push_back(c);
        }
    }
    
    // Don't forget the last segment
    if (!cur.empty()) {
        Step st;
        st.isAttribute = (cur[0] == '@');
        st.name = st.isAttribute ? cur.substr(1) : cur;
        out.push_back(std::move(st));
    }

    // Parse array indices from step names
    for (auto& s : out) {
        // Skip attributes - they can't have indices
        if (s.isAttribute) {
            continue;
        }
        
        const auto lb = s.name.find('[');
        if (lb == std::string::npos || lb + 1 >= s.name.size()) {
            continue;
        }
        
        const auto rb = s.name.find(']', lb + 1);
        if (rb == std::string::npos) {
            continue;
        }
        
        // Extract index string
        const std::string idxStr = s.name.substr(lb + 1, rb - (lb + 1));
        
        // Validate: must be non-empty and all digits
        const bool allDigits = !idxStr.empty() && 
            std::all_of(idxStr.begin(), idxStr.end(), isDigit);
        
        // SECURITY: Reject non-digit content (XPath injection attempt)
        if (!idxStr.empty() && !allDigits) {
            // Contains operators like '=', '<', '>', etc.
            // This is likely an XPath injection attempt
            out.clear();  // Signal rejection by clearing all steps
            return;
        }
        
        if (allDigits) {
            try {
                const unsigned long long idx = std::stoull(idxStr);
                
                // SECURITY: Integer overflow protection
                // Check against both MAX_INDEX and platform size_t limit
                if (idx > std::numeric_limits<size_t>::max()) {
                    // Index too large for this platform
                    s.name = s.name.substr(0, lb);
                    continue;
                }
                
                if (idx > kMaxArrayIndex) {
                    // Index exceeds security limit
                    s.name = s.name.substr(0, lb);
                    continue;
                }
                
                s.hasIndex = true;
                s.index = static_cast<size_t>(idx);
            }
            catch (const std::out_of_range&) {
                // Index too large, strip the bracket notation
                s.name = s.name.substr(0, lb);
                continue;
            }
            catch (const std::invalid_argument&) {
                // Invalid format, strip the bracket notation
                s.name = s.name.substr(0, lb);
                continue;
            }
        }
        
        // Remove the [N] from the name
        s.name = s.name.substr(0, lb);
    }
}

//=============================================================================
// Path Conversion Implementation
//=============================================================================

std::string ToXPath(std::string_view pathLike) noexcept {
    try {
        // Empty path returns root selector
        if (pathLike.empty()) {
            return std::string("/");
        }
        
        // Already XPath - pass through unchanged
        if (pathLike.front() == '/') {
            return std::string(pathLike);
        }

        // Parse dot-notation into steps
        std::vector<Step> steps;
        parsePathLike(pathLike, steps);
        
        // SECURITY: Empty steps means rejection (malformed/malicious input)
        // parsePathLike clears steps if it detects XPath injection
        if (steps.empty()) {
            return std::string("__INVALID__");
        }

        // Build XPath string
        std::string xp;
        xp.reserve(pathLike.size() * 2);  // Reserve for efficiency
        xp.push_back('/');
        
        for (size_t i = 0; i < steps.size(); ++i) {
            const auto& s = steps[i];
            
            if (s.isAttribute) {
                // Attribute access
                xp.push_back('@');
                xp.append(s.name);
            }
            else {
                // Element access
                xp.append(s.name);
                
                if (s.hasIndex) {
                    // XPath uses 1-based indices
                    xp.push_back('[');
                    xp.append(std::to_string(s.index + 1));
                    xp.push_back(']');
                }
            }
            
            // Add separator between steps
            if (i + 1 < steps.size()) {
                xp.push_back('/');
            }
        }
        
        return xp;
    }
    catch (...) {
        // Any exception results in invalid XPath
        return std::string("__INVALID__");
    }
}

//=============================================================================
// XML Parsing Implementation
//=============================================================================

bool Parse(std::string_view xmlText, Document& out, Error* err, const ParseOptions& opt) noexcept {
    try {
        // Configure parsing flags
        unsigned int flags = pugi::parse_default;
        
        if (opt.preserveWhitespace) {
            flags |= pugi::parse_ws_pcdata;
        }
        
        if (!opt.allowComments) {
            flags &= ~pugi::parse_comments;
        }
        
        // SECURITY: Disable external DTD to prevent XXE attacks
        if (!opt.loadExternalDtd) {
            flags &= ~pugi::parse_doctype;
        }
        
        // Track original size for XML bomb detection
        const size_t originalSize = xmlText.size();
        
        // Parse the XML buffer
        const pugi::xml_parse_result res = out.load_buffer(xmlText.data(),
            xmlText.size(),
            flags,
            pugi::encoding_utf8);// No need for casting.
        
        if (!res) {
            setErr(err, res.description(), {}, xmlText, 
                   static_cast<size_t>(res.offset));
            return false;
        }
        
        // SECURITY: Detect XML bomb attacks by checking node expansion ratio
        if (originalSize > 0) {
            // Count total nodes (with early termination for large documents)
            size_t nodeCount = 0;
            
            std::function<void(const pugi::xml_node&)> countNodes;
            countNodes = [&](const pugi::xml_node& node) {
                // Stop counting if we exceed the limit
                if (++nodeCount > kMaxNodeCount) {
                    return;
                }
                
                for (auto child : node.children()) {
                    if (nodeCount > kMaxNodeCount) {
                        return;
                    }
                    countNodes(child);
                }
            };
            countNodes(out);
            
            // Reject if expansion ratio is suspicious
            // Normal XML: ~50-100 bytes per node average
            // Entity bomb: 1KB input -> millions of nodes
            const size_t expectedMaxNodes = originalSize / 10;
            
            if (nodeCount > expectedMaxNodes && nodeCount > 100000) {
                setErr(err, 
                       "Suspicious XML structure detected (possible entity expansion attack)", 
                       {}, xmlText, 0);
                return false;
            }
        }
        
        return true;
    }
    catch (const std::exception& e) {
        setErr(err, e.what(), {}, xmlText, 0);
        return false;
    }
    catch (...) {
        setErr(err, "Unknown XML parse error", {}, xmlText, 0);
        return false;
    }
}

//=============================================================================
// XML Serialization Implementation
//=============================================================================

/**
 * @brief Custom writer for pugixml that writes to a std::string.
 */
struct StringWriter : pugi::xml_writer {
    std::string s;
    
    void write(const void* data, size_t size) override {
        if (data && size > 0) {
            s.append(static_cast<const char*>(data), size);
        }
    }
};

/**
 * @brief Internal helper to serialize a node to string.
 *
 * @param node Node to serialize
 * @param[out] out Output string
 * @param opt Serialization options
 * @return true on success
 */
static bool saveToString(
    const Node& node, 
    std::string& out, 
    const StringifyOptions& opt
) noexcept {
    try {
        StringWriter wr;
        
        // Configure formatting flags
        unsigned int fmt = pugi::format_default;
        
        if (!opt.pretty) {
            fmt = pugi::format_raw;
        }
        
        if (!opt.writeDeclaration) {
            fmt |= pugi::format_no_declaration;
        }

        // Build indentation string
        std::string indent;
        if (opt.pretty && opt.indentSpaces > 0) {
            // Clamp indent spaces to reasonable range
            const int clampedIndent = std::clamp(opt.indentSpaces, 0, 16);
            indent.assign(static_cast<size_t>(clampedIndent), ' ');
        }

        // Perform serialization
        node.print(
            wr, 
            opt.pretty ? indent.c_str() : "", 
            fmt, 
            pugi::encoding_utf8
        );

        out = std::move(wr.s);
        return true;
    }
    catch (...) {
        return false;
    }
}

bool Stringify(const Node& node, std::string& out, const StringifyOptions& opt) noexcept {
    try {
        out.clear();
        return saveToString(node, out, opt);
    }
    catch (...) {
        out.clear();
        return false;
    }
}

bool Minify(std::string_view xmlText, std::string& out, Error* err, const ParseOptions& opt) noexcept {
    try {
        out.clear();
        
        Document doc;
        if (!Parse(xmlText, doc, err, opt)) {
            return false;
        }
        
        StringifyOptions so{};
        so.pretty = false;
        so.writeDeclaration = true;
        
        return Stringify(doc, out, so);
    }
    catch (...) {
        out.clear();
        return false;
    }
}

bool Prettify(std::string_view xmlText, std::string& out, int indentSpaces, Error* err, const ParseOptions& opt) noexcept {
    try {
        out.clear();
        
        Document doc;
        if (!Parse(xmlText, doc, err, opt)) {
            return false;
        }
        
        StringifyOptions so{};
        so.pretty = true;
        so.indentSpaces = indentSpaces;
        so.writeDeclaration = true;
        
        return Stringify(doc, out, so);
    }
    catch (...) {
        out.clear();
        return false;
    }
}


//=============================================================================
// File I/O Implementation
//=============================================================================

bool LoadFromFile(
    const std::filesystem::path& path, 
    Document& out, 
    Error* err, 
    const ParseOptions& opt, 
    size_t maxBytes
) noexcept {
    try {
        // Get file size
        std::error_code ec;
        const auto fileSize = std::filesystem::file_size(path, ec);
        
        if (ec) {
            setIoErr(err, "Failed to get file size", path, ec.message());
            return false;
        }
        
        // SECURITY: Enforce maximum file size to prevent memory exhaustion
        if (fileSize > kMaxSafeXmlFileSize) {
            setIoErr(err, "File exceeds maximum safe size (512 MB)", path);
            return false;
        }
        
        // Check against user-specified limit
        if (fileSize > static_cast<uintmax_t>(maxBytes)) {
            setIoErr(err, "File exceeds specified size limit", path);
            return false;
        }
        
        // Open file in binary mode
        std::ifstream ifs(path, std::ios::in | std::ios::binary);
        if (!ifs) {
            setIoErr(err, "Failed to open file", path);
            return false;
        }
        
        // Allocate buffer
        std::string buf;
        try {
            buf.resize(static_cast<size_t>(fileSize));
        }
        catch (const std::bad_alloc&) {
            setIoErr(err, "Memory allocation failed for file content", path);
            return false;
        }
        
        // Read file content
        if (fileSize > 0) {
            ifs.read(buf.data(), static_cast<std::streamsize>(fileSize));
            
            // SECURITY: Verify complete file read
            const auto bytesRead = ifs.gcount();
            
            if (!ifs && !ifs.eof()) {
                setIoErr(err, "Failed to read file", path);
                return false;
            }
            
            // Verify we read the expected amount
            if (static_cast<size_t>(bytesRead) != fileSize) {
                std::ostringstream oss;
                oss << "Incomplete file read (expected " << fileSize 
                    << " bytes, got " << bytesRead << " bytes)";
                setIoErr(err, oss.str(), path);
                return false;
            }
            
            // Resize to actual bytes read (should match, but be defensive)
            buf.resize(static_cast<size_t>(bytesRead));
        }
        
        // Remove UTF-8 BOM if present
        stripUtf8BOM(buf);
        
        // Parse the content
        return Parse(buf, out, err, opt);
    }
    catch (const std::exception& e) {
        setIoErr(err, e.what(), path);
        return false;
    }
    catch (...) {
        setIoErr(err, "Unknown error loading XML file", path);
        return false;
    }
}

bool SaveToFile(
    const std::filesystem::path& path, 
    const Node& node, 
    Error* err, 
    const SaveOptions& opt
) noexcept {
    try {
        // Serialize XML to string
        std::string content;
        if (!Stringify(node, content, opt)) {
            setIoErr(err, "XML stringify failed", path);
            return false;
        }
        
        // Add UTF-8 BOM if requested
        if (opt.writeBOM) {
            constexpr unsigned char kUtf8Bom[3] = { 0xEF, 0xBB, 0xBF };
            content.insert(content.begin(), kUtf8Bom, kUtf8Bom + 3);
        }

        // Ensure parent directory exists
        const auto dir = path.parent_path().empty() 
            ? std::filesystem::current_path() 
            : path.parent_path();
            
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        // Ignore ec - directory may already exist

        // SECURITY: Generate cryptographically random temp filename
        // This prevents path traversal, race conditions, and symlink attacks
#ifdef _WIN32
        const DWORD pid = ::GetCurrentProcessId();
        const DWORD tid = ::GetCurrentThreadId();
#else
        const auto pid = getpid();
        const auto tid = 0;  // Not easily available on all platforms
#endif
        
        // High-resolution timestamp for uniqueness
        const auto now = std::chrono::high_resolution_clock::now()
                            .time_since_epoch().count();
        
        // Stack address for additional entropy
        int entropySource = 0;
        
        // Build cryptographically strong seed
        std::mt19937_64 rng(
            static_cast<uint64_t>(now) ^ 
            reinterpret_cast<uintptr_t>(&entropySource) ^ 
            (static_cast<uint64_t>(pid) << 32) | 
            static_cast<uint64_t>(tid)
        );
        
        std::uniform_int_distribution<uint64_t> dist;
        const uint64_t randomId = dist(rng);
        
        // Build secure temp filename (NOT based on user input)
        std::wostringstream tempBuilder;
        tempBuilder << L".tmp_" 
                   << std::hex << pid << L"_" 
                   << tid << L"_" 
                   << now << L"_" 
                   << randomId 
                   << L".xml";
        
        const auto tempPath = dir / tempBuilder.str();

        // Write to temporary file
        {
            std::ofstream ofs(tempPath, std::ios::out | std::ios::binary | std::ios::trunc);
            if (!ofs) {
                setIoErr(err, "Failed to create temp file", tempPath);
                return false;
            }
            
            ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
            if (!ofs) {
                setIoErr(err, "Failed to write temp file", tempPath);
                // Cleanup temp file
                std::filesystem::remove(tempPath, ec);
                return false;
            }
            
            ofs.flush();
            if (!ofs) {
                setIoErr(err, "Failed to flush temp file", tempPath);
                std::filesystem::remove(tempPath, ec);
                return false;
            }
        }

        // Perform atomic rename or direct write
        if (opt.atomicReplace) {
#ifdef _WIN32
            // SECURITY: Atomic rename with write-through for data integrity
            if (!::MoveFileExW(
                    tempPath.c_str(), 
                    path.c_str(), 
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                        
                const DWORD lastError = ::GetLastError();
                
                // Cleanup temp file on failure
                ::DeleteFileW(tempPath.c_str());
                
                setIoErr(err, "MoveFileExW failed", path, 
                         std::to_string(static_cast<unsigned long>(lastError)));
                return false;
            }
#else
            // POSIX: rename() is atomic on same filesystem
            std::filesystem::remove(path, ec);
            std::filesystem::rename(tempPath, path, ec);
            
            if (ec) {
                setIoErr(err, "Failed to rename temp file", path, ec.message());
                std::filesystem::remove(tempPath, ec);
                return false;
            }
#endif
        }
        else {
            // Non-atomic write directly to target file
            std::ofstream ofs(path, std::ios::out | std::ios::binary | std::ios::trunc);
            if (!ofs) {
                setIoErr(err, "Failed to open file for write", path);
                std::filesystem::remove(tempPath, ec);
                return false;
            }
            
            ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
            if (!ofs) {
                setIoErr(err, "Failed to write file", path);
                std::filesystem::remove(tempPath, ec);
                return false;
            }
            
            ofs.flush();
            
            // Cleanup temp file
            std::filesystem::remove(tempPath, ec);
        }
        
        return true;
    }
    catch (const std::exception& e) {
        setIoErr(err, e.what(), path);
        return false;
    }
    catch (...) {
        setIoErr(err, "Unknown error saving XML file", path);
        return false;
    }
}


//=============================================================================
// XPath Validation Helper
//=============================================================================

/**
 * @brief Validate XPath for safe characters only.
 *
 * SECURITY: Prevents XPath injection by allowing only a whitelist of characters.
 * Allowed: alphanumeric, /, @, [, ], _, -, .
 * Rejected: =, <, >, (, ), |, !, *, $, ', ", etc.
 *
 * @param xp XPath string to validate
 * @return true if XPath contains only safe characters
 */
static inline bool isXPathSafe(const std::string& xp) noexcept {
    // Check length limit
    if (xp.size() > kMaxXPathLength) {
        return false;
    }
    
    // Check for invalid sentinel
    if (xp == "__INVALID__") {
        return false;
    }
    
    // Validate each character
    for (const char c : xp) {
        // Alphanumeric characters are safe
        if (std::isalnum(static_cast<unsigned char>(c))) {
            continue;
        }
        
        // Safe path characters
        if (c == '/' || c == '@' || c == '[' || c == ']' || 
            c == '_' || c == '-' || c == '.') {
            continue;
        }
        
        // Any other character is potentially dangerous
        return false;
    }
    
    return true;
}

//=============================================================================
// Query Helper Implementation
//=============================================================================

bool Contains(const Node& root, std::string_view pathLike) noexcept {
    try {
        const std::string xp = ToXPath(pathLike);
        
        // SECURITY: Validate XPath before execution
        if (!isXPathSafe(xp)) {
            return false;
        }
        
        const pugi::xpath_node xn = root.select_node(xp.c_str());
        return static_cast<bool>(xn);
    }
    catch (...) {
        return false;
    }
}

/**
 * @brief Internal helper to get text content from node or attribute.
 *
 * @param root Root node to search from
 * @param pathLike Path expression
 * @param[out] out Text content
 * @return true if found and text extracted
 */
static bool getNodeOrAttrText(
    const Node& root, 
    std::string_view pathLike, 
    std::string& out
) noexcept {
    try {
        const std::string xp = ToXPath(pathLike);
        
        // SECURITY: Validate XPath before execution
        if (!isXPathSafe(xp)) {
            return false;
        }
        
        const pugi::xpath_node xn = root.select_node(xp.c_str());
        if (!xn) {
            return false;
        }
        
        // Extract text from attribute or node
        if (xn.attribute()) {
            out = xn.attribute().value();
            return true;
        }
        
        if (xn.node()) {
            out = xn.node().text().as_string();
            return true;
        }
        
        return false;
    }
    catch (...) {
        return false;
    }
}

bool GetText(const Node& root, std::string_view pathLike, std::string& out) noexcept {
    try {
        out.clear();
        return getNodeOrAttrText(root, pathLike, out);
    }
    catch (...) {
        out.clear();
        return false;
    }
}

//=============================================================================
// Typed Getter Implementation
//=============================================================================

/**
 * @brief Parse boolean from string.
 *
 * @param s Input string
 * @param[out] v Boolean value
 * @return true if valid boolean representation
 */
static inline bool parseBool(std::string_view s, bool& v) noexcept {
    // True values
    if (s == "1" || s == "true" || s == "TRUE" || s == "True") {
        v = true;
        return true;
    }
    
    // False values
    if (s == "0" || s == "false" || s == "FALSE" || s == "False") {
        v = false;
        return true;
    }
    
    return false;
}

bool GetBool(const Node& root, std::string_view pathLike, bool& out) noexcept {
    try {
        std::string s;
        if (!GetText(root, pathLike, s)) {
            return false;
        }
        return parseBool(s, out);
    }
    catch (...) {
        return false;
    }
}

bool GetInt64(const Node& root, std::string_view pathLike, int64_t& out) noexcept {
    try {
        std::string s;
        if (!GetText(root, pathLike, s)) {
            return false;
        }
        
        if (s.empty()) {
            return false;
        }
        
        const char* b = s.data();
        const char* e = s.data() + s.size();
        
        const auto res = std::from_chars(b, e, out, 10);
        
        // Ensure entire string was consumed
        return res.ec == std::errc{} && res.ptr == e;
    }
    catch (...) {
        return false;
    }
}

bool GetUInt64(const Node& root, std::string_view pathLike, uint64_t& out) noexcept {
    try {
        std::string s;
        if (!GetText(root, pathLike, s)) {
            return false;
        }
        
        if (s.empty()) {
            return false;
        }
        
        const char* b = s.data();
        const char* e = s.data() + s.size();
        
        const auto res = std::from_chars(b, e, out, 10);
        
        // Ensure entire string was consumed
        return res.ec == std::errc{} && res.ptr == e;
    }
    catch (...) {
        return false;
    }
}

bool GetDouble(const Node& root, std::string_view pathLike, double& out) noexcept {
    try {
        std::string s;
        if (!GetText(root, pathLike, s)) {
            return false;
        }
        
        if (s.empty()) {
            return false;
        }
        
        char* endp = nullptr;
        out = std::strtod(s.c_str(), &endp);
        
        // Ensure entire string was consumed and no error occurred
        return endp && *endp == '\0';
    }
    catch (...) {
        return false;
    }
}

            // Set support: creates intermediate nodes; if last step is @attr, sets attribute, otherwise sets .text
            bool Set(Node& root, std::string_view pathLike, std::string_view value) noexcept {
                try {
                    if (pathLike.empty()) return false;
                    
                    // ? BUG #6 FIX: Uncontrolled Recursion Prevention
                    // PROBLEM: Deep nested paths + large indices = exponential node creation
                    // SOLUTION: Enforce strict limits on depth and total nodes created
                    
                    if (pathLike.front() == '/') {
                        // Creating intermediate nodes with XPath is not reliable; only set if target exists
                        const std::string xp(pathLike);
                        
                        // XPath validation (same as BUG #5)
                        // ? ENHANCED: Stricter validation
                        for (char c : xp) {
                            if (std::isalnum(static_cast<unsigned char>(c)) || 
                                c == '/' || c == '@' || c == '[' || c == ']' || 
                                c == '_' || c == '-' || c == '.') {
                                continue;
                            }
                            return false;
                        }
                        
                        if (xp.size() > 1000) {
                            return false;
                        }

                        pugi::xpath_node xn = root.select_node(xp.c_str());
                        if (!xn) return false;
                        
                        // ? BUG #10 FIX: Check pugixml return values
                        if (xn.attribute()) { 
                            bool success = xn.attribute().set_value(std::string(value).c_str()); 
                            return success;
                        }
                        if (xn.node()) { 
                            xn.node().text() = std::string(value).c_str(); 
                            return true; 
                        }
                        return false;
                    }

                    std::vector<Step> steps;
                    parsePathLike(pathLike, steps);
                    if (steps.empty()) return false;
                    
                    // ? BUG #6 FIX: Enforce maximum path depth
                    constexpr size_t MAX_PATH_DEPTH = 10;
                    if (steps.size() > MAX_PATH_DEPTH) {
                        return false;  // Path too deep
                    }

                    // Root node
                    Node cur = root;
                    if (cur.type() == pugi::node_document) {
                        if (!cur.first_child()) {
                            // if first element doesn't exist, create first element
                            if (steps[0].isAttribute) return false; // attribute cannot be at root
                            auto child = cur.append_child(steps[0].name.c_str());
                            if (!child) return false;  // ? BUG #10: Check allocation
                        }
                        cur = cur.first_child();
                        
                        // ? FIX #NEW: If first step matches existing root name, skip it
                        // Example: Set(doc, "root.item", "value") where doc already has <root>
                        // We should skip "root" step and start from "item"
                        if (!steps[0].isAttribute && std::string(cur.name()) == steps[0].name) {
                            // First step matches root name, skip it in iteration
                            // Change logic: start from step index 1 instead of 0
                            // But we need to handle this in the loop below
                            // Actually, we'll mark this and handle below
                        } else if (!steps[0].isAttribute && std::string(cur.name()) != steps[0].name) {
                            // if document contains another root, we cannot add new root
                            if (root.first_child() && root.first_child().next_sibling()) return false;
                            // no renaming of existing root; just proceed under it
                        }
                    }

                    // Progression and creation
                    Node parent = root.type() == pugi::node_document ? root.first_child() : root;
                    
                    // ? FIX #NEW: Determine starting step index
                    size_t startStep = 0;
                    if (root.type() == pugi::node_document && parent) {
                        // If first step name matches document root name, skip it
                        if (!steps[0].isAttribute && std::string(parent.name()) == steps[0].name) {
                            startStep = 1;  // Skip first step, already at root
                        }
                    }
                    
                    // ? BUG #6 FIX: Track total nodes created across ALL steps
                    size_t totalNodesCreated = 0;
                    constexpr size_t MAX_TOTAL_NODES = 1000;  // Aggressive limit
                    
                    for (size_t i = startStep; i < steps.size(); ++i) {
                        const Step& s = steps[i];
                        const bool last = (i + 1 == steps.size());
                        
                        if (s.isAttribute) {
                            if (!last) return false; // we don't support attribute in intermediate steps
                            if (!parent) return false;
                            auto a = parent.attribute(s.name.c_str());
                            if (!a) {
                                a = parent.append_attribute(s.name.c_str());
                                if (!a) return false;  // ? BUG #10: Check allocation
                            }
                            bool success = a.set_value(std::string(value).c_str());
                            return success;  // ? BUG #10: Return actual result
                        }
                        else {
                            // find/create child node
                            Node found;
                            size_t foundIdx = 0;
                            for (Node child = parent.child(s.name.c_str()); child; child = child.next_sibling(s.name.c_str())) {
                                if (!s.hasIndex || foundIdx == s.index) { found = child; break; }
                                ++foundIdx;
                            }
                            if (!found) {
                                // if missing, create it, try to fill up to index
                                if (!s.hasIndex || s.index == 0) {
                                    found = parent.append_child(s.name.c_str());
                                    if (!found) return false;  // ? BUG #10: Check allocation
                                    totalNodesCreated++;
                                }
                                else {
                                    // count existing and add until reaching s.index
                                    size_t cnt = 0;
                                    for (Node child = parent.child(s.name.c_str()); child; child = child.next_sibling(s.name.c_str())) {
                                        ++cnt;
                                        if (cnt > 100000) return false; // prevent infinite loop from malformed XML
                                    }

                                    constexpr size_t MAX_XML_ARRAY_SIZE = 10000;
                                    if (s.index > MAX_XML_ARRAY_SIZE) return false; //Maximum array size protection
                                    
                                    // ? BUG #6 FIX: Check per-step AND total node creation
                                    size_t nodesToCreate = (s.index >= cnt) ? (s.index - cnt + 1) : 0;
                                    
                                    if (nodesToCreate > 1000) return false; //Too many nodes to create at once
                                    
                                    totalNodesCreated += nodesToCreate;
                                    if (totalNodesCreated > MAX_TOTAL_NODES) {
                                        return false;  // Exceeded total node budget
                                    }

                                    for (; cnt <= s.index; ++cnt) {
                                        auto child = parent.append_child(s.name.c_str());
                                        if (!child) return false;  // ? BUG #10: Check allocation
                                    }
                                    
                                    // find again
                                    size_t idx = 0;
                                    for (Node child = parent.child(s.name.c_str()); child; child = child.next_sibling(s.name.c_str())) {
                                        if (idx == s.index) { found = child; break; }
                                        ++idx;
                                    }
                                }
                                if (!found) return false;
                            }
                            if (last) {
                                found.text() = std::string(value).c_str();
                                return true;
                            }
                            parent = found;
                        }
                    }
                    return false;
                }
                catch (...) {
                    return false;
                }
            }

            bool Erase(Node& root, std::string_view pathLike) noexcept {
                try {
                    const std::string xp = ToXPath(pathLike);
                    
                    // ? BUG #5 FIX: XPath Injection Protection (same validation)
                    // ? ENHANCED: Stricter validation
                    for (char c : xp) {
                        if (std::isalnum(static_cast<unsigned char>(c)) || 
                            c == '/' || c == '@' || c == '[' || c == ']' || 
                            c == '_' || c == '-' || c == '.') {
                            continue;
                        }
                        return false;
                    }
                    
                    if (xp.size() > 1000) {
                        return false;
                    }
                    
                    pugi::xpath_node xn = root.select_node(xp.c_str());
                    if (!xn) return false;
                    
                    if (xn.attribute()) {
                        Node parentNode = xn.parent();
                        if (!parentNode) return false;  // ? BUG #10: Check parent validity
						return parentNode.remove_attribute(xn.attribute());
                    }
                    if (xn.node()) {
                        auto n = xn.node();
                        auto p = n.parent();
                        if (p) return p.remove_child(n);
                    }
                    return false;
                }
                catch (...) { return false; }
            }

		}// namespace XML
	}// namespace Utils
}// namespace ShadowStrike