//=============================================================================
// XMLUtils.hpp
//
// ShadowStrike Security Suite - XML Utility Library
//
// Purpose:
//   Provides safe, hardened XML parsing, manipulation, and serialization
//   utilities for the ShadowStrike security platform. Built on top of
//   pugixml with additional security hardening against:
//   - XML Bomb attacks (Billion Laughs)
//   - XPath injection
//   - Path traversal
//   - Entity expansion attacks
//   - Resource exhaustion
//
// Security Considerations:
//   - External DTD loading is disabled by default
//   - XPath queries are validated before execution
//   - Maximum file sizes and node counts are enforced
//   - Atomic file operations prevent race conditions
//
// Thread Safety:
//   - All functions are thread-safe for distinct Document instances
//   - Concurrent access to the same Document requires external synchronization
//
// Copyright (c) 2024-2025 ShadowStrike Security Team
// Licensed under MIT License
//=============================================================================

#ifndef SHADOWSTRIKE_XMLUTILS_HPP
#define SHADOWSTRIKE_XMLUTILS_HPP

#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <filesystem>
#include <optional>
#include <cstdint>

#include"../../../../ShadowStrike/external/pugixml/pugixml.hpp"


namespace ShadowStrike {
namespace Utils {
namespace XML {

//-----------------------------------------------------------------------------
// Type Aliases
//-----------------------------------------------------------------------------

/// @brief XML document container (wraps pugi::xml_document)
using Document = pugi::xml_document;

/// @brief XML node handle (wraps pugi::xml_node)
using Node = pugi::xml_node;

//-----------------------------------------------------------------------------
// Error Information
//-----------------------------------------------------------------------------

/**
 * @brief Error information structure for XML operations.
 *
 * Provides detailed error context including message, file path,
 * and precise location (byte offset, line, column) when available.
 */
struct Error {
    std::string message;           ///< Human-readable error description
    std::filesystem::path path;    ///< File path (if applicable)
    size_t byteOffset = 0;         ///< Byte offset in source (if known)
    size_t line = 0;               ///< 1-based line number (if calculable)
    size_t column = 0;             ///< 1-based column number (if calculable)
};

//-----------------------------------------------------------------------------
// Configuration Options
//-----------------------------------------------------------------------------

/**
 * @brief Options controlling XML parsing behavior.
 *
 * @warning loadExternalDtd should remain false in production environments
 *          to prevent XML External Entity (XXE) attacks.
 */
struct ParseOptions {
    /// Preserve whitespace in PCDATA sections
    bool preserveWhitespace = false;
    
    /// Allow XML comments in document
    bool allowComments = true;
    
    /// Load external DTD references (DANGEROUS - enables XXE attacks)
    /// @warning Set to true only for trusted, local XML files
    bool loadExternalDtd = false;
};

/**
 * @brief Options controlling XML serialization to string.
 */
struct StringifyOptions {
    /// Enable pretty-printing with indentation
    bool pretty = false;
    
    /// Number of spaces per indentation level (when pretty=true)
    int indentSpaces = 2;
    
    /// Include XML declaration (<?xml version="1.0"?>)
    bool writeDeclaration = true;
};

/**
 * @brief Options controlling XML file save operations.
 *
 * Extends StringifyOptions with file-specific settings.
 */
struct SaveOptions : StringifyOptions {
    /// Use atomic write-then-rename for crash safety
    bool atomicReplace = true;
    
    /// Write UTF-8 BOM at file start (rarely needed)
    bool writeBOM = false;
};

//-----------------------------------------------------------------------------
// Path Conversion
//-----------------------------------------------------------------------------

/**
 * @brief Convert a path-like string to XPath format.
 *
 * Supports two input formats:
 * - XPath: "/root/a/b[1]/@id" (passed through unchanged)
 * - Dot notation: "a.b[0].c" or "@attr" (converted to XPath)
 *
 * @param pathLike Path expression to convert
 * @return XPath string, or "__INVALID__" if input is malformed/malicious
 *
 * @note Returns "__INVALID__" for XPath injection attempts
 */
[[nodiscard]]
std::string ToXPath(std::string_view pathLike) noexcept;

//-----------------------------------------------------------------------------
// Text Operations
//-----------------------------------------------------------------------------

/**
 * @brief Parse XML text into a document.
 *
 * @param xmlText XML content to parse
 * @param[out] out Document to populate
 * @param[out] err Optional error details on failure
 * @param opt Parsing options
 * @return true on success, false on parse error
 *
 * @security Validates against XML bomb attacks when loadExternalDtd=false
 */
[[nodiscard]]
bool Parse(std::string_view xmlText, Document& out, Error* err = nullptr, 
           const ParseOptions& opt = {}) noexcept;

/**
 * @brief Serialize an XML node to string.
 *
 * @param node Node to serialize
 * @param[out] out String to populate
 * @param opt Serialization options
 * @return true on success
 */
[[nodiscard]]
bool Stringify(const Node& node, std::string& out, 
               const StringifyOptions& opt = {}) noexcept;

/**
 * @brief Minify XML by removing whitespace and formatting.
 *
 * @param xmlText Input XML
 * @param[out] out Minified output
 * @param[out] err Optional error details
 * @param opt Parse options for input
 * @return true on success
 */
[[nodiscard]]
bool Minify(std::string_view xmlText, std::string& out, Error* err = nullptr, 
            const ParseOptions& opt = {}) noexcept;

/**
 * @brief Pretty-print XML with indentation.
 *
 * @param xmlText Input XML
 * @param[out] out Formatted output
 * @param indentSpaces Spaces per indent level
 * @param[out] err Optional error details
 * @param opt Parse options for input
 * @return true on success
 */
[[nodiscard]]
bool Prettify(std::string_view xmlText, std::string& out, int indentSpaces = 2, 
              Error* err = nullptr, const ParseOptions& opt = {}) noexcept;

//-----------------------------------------------------------------------------
// File Operations
//-----------------------------------------------------------------------------

/// Default maximum file size for XML loading (32 MB)
inline constexpr size_t kDefaultMaxXmlFileSize = static_cast<size_t>(32) * 1024 * 1024;

/**
 * @brief Load and parse XML from a file.
 *
 * @param path File path to load
 * @param[out] out Document to populate
 * @param[out] err Optional error details
 * @param opt Parse options
 * @param maxBytes Maximum file size allowed
 * @return true on success
 *
 * @security Enforces file size limits to prevent memory exhaustion
 */
[[nodiscard]]
bool LoadFromFile(const std::filesystem::path& path, Document& out, 
                  Error* err = nullptr, const ParseOptions& opt = {}, 
                  size_t maxBytes = kDefaultMaxXmlFileSize) noexcept;

/**
 * @brief Save XML node to a file.
 *
 * @param path Destination file path
 * @param node Node to save
 * @param[out] err Optional error details
 * @param opt Save options
 * @return true on success
 *
 * @security Uses atomic write-then-rename by default for crash safety
 */
[[nodiscard]]
bool SaveToFile(const std::filesystem::path& path, const Node& node, 
                Error* err = nullptr, const SaveOptions& opt = {}) noexcept;

//-----------------------------------------------------------------------------
// Query Helpers
//-----------------------------------------------------------------------------

/**
 * @brief Check if a path exists in the document.
 *
 * @param root Root node to search from
 * @param pathLike Path expression (XPath or dot notation)
 * @return true if path exists
 *
 * @security Validates XPath to prevent injection attacks
 */
[[nodiscard]]
bool Contains(const Node& root, std::string_view pathLike) noexcept;

/**
 * @brief Get text content at a path.
 *
 * @param root Root node to search from
 * @param pathLike Path expression
 * @param[out] out Text content
 * @return true if path exists and has text
 */
[[nodiscard]]
bool GetText(const Node& root, std::string_view pathLike, std::string& out) noexcept;

/**
 * @brief Get boolean value at a path.
 *
 * Recognizes: "1", "true", "TRUE", "True" as true
 *             "0", "false", "FALSE", "False" as false
 *
 * @param root Root node
 * @param pathLike Path expression
 * @param[out] out Boolean value
 * @return true if path exists and contains valid boolean
 */
[[nodiscard]]
bool GetBool(const Node& root, std::string_view pathLike, bool& out) noexcept;

/**
 * @brief Get signed 64-bit integer at a path.
 *
 * @param root Root node
 * @param pathLike Path expression
 * @param[out] out Integer value
 * @return true if path exists and contains valid integer
 */
[[nodiscard]]
bool GetInt64(const Node& root, std::string_view pathLike, int64_t& out) noexcept;

/**
 * @brief Get unsigned 64-bit integer at a path.
 *
 * @param root Root node
 * @param pathLike Path expression
 * @param[out] out Integer value
 * @return true if path exists and contains valid unsigned integer
 */
[[nodiscard]]
bool GetUInt64(const Node& root, std::string_view pathLike, uint64_t& out) noexcept;

/**
 * @brief Get double-precision float at a path.
 *
 * @param root Root node
 * @param pathLike Path expression
 * @param[out] out Double value
 * @return true if path exists and contains valid number
 */
[[nodiscard]]
bool GetDouble(const Node& root, std::string_view pathLike, double& out) noexcept;

//-----------------------------------------------------------------------------
// Mutation Operations
//-----------------------------------------------------------------------------

/**
 * @brief Set value at a path, creating intermediate nodes if needed.
 *
 * If pathLike ends with @attr, sets attribute; otherwise sets node text.
 *
 * @param root Root node to modify
 * @param pathLike Path expression
 * @param value Value to set
 * @return true on success
 *
 * @security Enforces depth and node creation limits
 */
[[nodiscard]]
bool Set(Node& root, std::string_view pathLike, std::string_view value) noexcept;

/**
 * @brief Delete a node or attribute at a path.
 *
 * @param root Root node to modify
 * @param pathLike Path expression to delete
 * @return true if target was found and deleted
 */
[[nodiscard]]
bool Erase(Node& root, std::string_view pathLike) noexcept;

} // namespace XML
} // namespace Utils
} // namespace ShadowStrike

#endif // SHADOWSTRIKE_XMLUTILS_HPP
