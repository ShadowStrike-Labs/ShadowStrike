#pragma once
/**
 * @file JSONUtils.hpp
 * @brief JSON parsing, serialization, and manipulation utilities for ShadowStrike.
 *
 * Provides secure JSON operations including:
 * - Safe parsing with depth limits to prevent stack overflow attacks
 * - File I/O with atomic write support
 * - JSON Pointer and dot/bracket path navigation
 * - RFC 7396 JSON Merge Patch support
 * - Schema validation helpers
 *
 * Implementation uses nlohmann/json library with security-hardened wrappers.
 *
 * @note All functions are noexcept and return success/failure status.
 * @warning JSON depth is limited to prevent DoS via deeply nested structures.
 */

#include <string>
#include <string_view>
#include <vector>
#include <filesystem>
#include <cstdint>
#include <optional>
#include <algorithm>

// Fix include path - use proper relative path
#include "../../external/nlohmann/json.hpp"

namespace ShadowStrike {
	namespace Utils {
		namespace JSON {

			/// @brief Type alias for nlohmann::json
			using Json = nlohmann::json;

			// ============================================================================
			// Security Constants
			// ============================================================================

			/// Maximum JSON file size to prevent memory exhaustion (100MB)
			inline constexpr size_t MAX_JSON_SIZE = 100ULL * 1024 * 1024;

			/// Maximum nesting depth to prevent stack overflow attacks
			inline constexpr size_t MAX_JSON_DEPTH = 1000;

			/// Maximum hex input size for validation (10MB)
			inline constexpr size_t MAX_HEX_INPUT = 10ULL * 1024 * 1024;

			/// Default file size limit for LoadFromFile (32MB)
			inline constexpr size_t DEFAULT_MAX_FILE_SIZE = 32ULL * 1024 * 1024;

			// ============================================================================
			// Error Handling
			// ============================================================================

			/**
			 * @brief Error information structure for JSON operations.
			 *
			 * Captures detailed error information including file path,
			 * byte offset, and approximate line/column for parse errors.
			 */
			struct Error {
				std::string message;              ///< Human-readable error description
				std::filesystem::path path;       ///< File path (if applicable)
				size_t byteOffset = 0;            ///< Byte offset in JSON text (0 = unknown)
				size_t line = 0;                  ///< Approximate line number (1-based, 0 = unknown)
				size_t column = 0;                ///< Approximate column number (1-based, 0 = unknown)

				/// @brief Check if an error occurred
				[[nodiscard]] constexpr bool hasError() const noexcept {
					return !message.empty();
				}

				/// @brief Clear error state
				void clear() noexcept {
					message.clear();
					path.clear();
					byteOffset = 0;
					line = 0;
					column = 0;
				}
			};

			// ============================================================================
			// Parse/Stringify Options
			// ============================================================================

			/**
			 * @brief Options for JSON parsing operations.
			 */
			struct ParseOptions {
				bool allowComments = true;         ///< Allow // and /* */ comments
				bool allowExceptions = true;       ///< Throw exceptions on parse errors
				size_t maxDepth = MAX_JSON_DEPTH;  ///< Maximum nesting depth (DoS protection)
			};

			/**
			 * @brief Options for JSON stringification.
			 */
			struct StringifyOptions {
				bool pretty = false;               ///< Enable pretty printing with indentation
				int indentSpaces = 2;              ///< Number of spaces per indent level
				bool ensureAscii = false;          ///< Escape non-ASCII characters
			};

			/**
			 * @brief Options for saving JSON to file.
			 */
			struct SaveOptions : StringifyOptions {
				bool atomicReplace = true;         ///< Use atomic file replacement (recommended)
				bool writeBOM = false;             ///< Write UTF-8 BOM (not recommended)
			};

			// ============================================================================
			// Text Parsing Functions
			// ============================================================================

			/**
			 * @brief Parse JSON text into a Json object.
			 *
			 * Parses JSON text with configurable depth limits to prevent DoS attacks.
			 *
			 * @param jsonText Input JSON text
			 * @param out Output Json object (cleared on failure)
			 * @param err Optional error output
			 * @param opt Parse options
			 * @return true on success, false on parse error
			 */
			[[nodiscard]] bool Parse(std::string_view jsonText, Json& out, Error* err = nullptr,
			                         const ParseOptions& opt = {}) noexcept;

			/**
			 * @brief Serialize Json object to string.
			 *
			 * @param j Input Json object
			 * @param out Output string
			 * @param opt Stringify options
			 * @return true on success, false on serialization error
			 */
			[[nodiscard]] bool Stringify(const Json& j, std::string& out,
			                             const StringifyOptions& opt = {}) noexcept;

			/**
			 * @brief Minify JSON text (remove whitespace).
			 *
			 * @param jsonText Input JSON text
			 * @param out Output minified string
			 * @param err Optional error output
			 * @param opt Parse options
			 * @return true on success, false on error
			 */
			[[nodiscard]] bool Minify(std::string_view jsonText, std::string& out,
			                          Error* err = nullptr, const ParseOptions& opt = {}) noexcept;

			/**
			 * @brief Prettify JSON text (add indentation).
			 *
			 * @param jsonText Input JSON text
			 * @param out Output prettified string
			 * @param indentSpaces Number of spaces per indent level
			 * @param err Optional error output
			 * @param opt Parse options
			 * @return true on success, false on error
			 */
			[[nodiscard]] bool Prettify(std::string_view jsonText, std::string& out,
			                            int indentSpaces = 2, Error* err = nullptr,
			                            const ParseOptions& opt = {}) noexcept;

			// ============================================================================
			// File I/O Functions
			// ============================================================================

			/**
			 * @brief Load JSON from file.
			 *
			 * Reads and parses a JSON file with size and depth limits.
			 * Automatically strips UTF-8 BOM if present.
			 *
			 * @param path File path to load
			 * @param out Output Json object
			 * @param err Optional error output
			 * @param opt Parse options
			 * @param maxBytes Maximum file size in bytes (default 32MB)
			 * @return true on success, false on error
			 */
			[[nodiscard]] bool LoadFromFile(const std::filesystem::path& path, Json& out,
			                                Error* err = nullptr, const ParseOptions& opt = {},
			                                size_t maxBytes = DEFAULT_MAX_FILE_SIZE) noexcept;

			/**
			 * @brief Save JSON to file.
			 *
			 * Writes JSON to file with optional atomic replacement.
			 * Creates parent directories if they don't exist.
			 *
			 * @param path File path to save
			 * @param j Json object to save
			 * @param err Optional error output
			 * @param opt Save options
			 * @return true on success, false on error
			 */
			[[nodiscard]] bool SaveToFile(const std::filesystem::path& path, const Json& j,
			                              Error* err = nullptr, const SaveOptions& opt = {}) noexcept;

			// ============================================================================
			// JSON Pointer / Path Helpers
			// ============================================================================

			/**
			 * @brief Convert path-like string to JSON Pointer.
			 *
			 * Accepts either JSON Pointer ("/a/b/0") or dot/bracket notation ("a.b[0].c").
			 * Strings starting with '/' are treated as JSON Pointers.
			 *
			 * @param pathLike Input path string
			 * @return JSON Pointer string (starts with '/')
			 */
			[[nodiscard]] std::string ToJsonPointer(std::string_view pathLike) noexcept;

			/**
			 * @brief Check if a path exists in a Json object.
			 *
			 * @param j Json object to search
			 * @param pathLike Path (JSON Pointer or dot/bracket notation)
			 * @return true if path exists, false otherwise
			 */
			[[nodiscard]] bool Contains(const Json& j, std::string_view pathLike) noexcept;

			// ============================================================================
			// Typed Getters
			// ============================================================================

			/**
			 * @brief Get typed value from Json using path.
			 *
			 * Retrieves a value at the specified path and converts to type T.
			 * T must be compatible with nlohmann::json::get<T>().
			 *
			 * @tparam T Target type
			 * @param j Json object to search
			 * @param pathLike Path (JSON Pointer or dot/bracket notation)
			 * @param out Output value (unchanged on failure)
			 * @return true if path exists and conversion succeeded, false otherwise
			 */
			template <typename T>
			[[nodiscard]] bool Get(const Json& j, std::string_view pathLike, T& out) noexcept {
				try {
					const auto jp = ToJsonPointer(pathLike);

					// Handle root path specially
					if (jp == "/") {
						out = j.template get<T>();
						return true;
					}

					const nlohmann::json::json_pointer ptr(jp);
					if (!j.contains(ptr)) {
						return false;
					}
					out = j.at(ptr).template get<T>();
					return true;
				}
				catch (...) {
					return false;
				}
			}

			/**
			 * @brief Get typed value or return default.
			 *
			 * @tparam T Target type
			 * @param j Json object to search
			 * @param pathLike Path (JSON Pointer or dot/bracket notation)
			 * @param defaultValue Value to return if path not found or conversion fails
			 * @return Retrieved value or defaultValue
			 */
			template <typename T>
			[[nodiscard]] T GetOr(const Json& j, std::string_view pathLike, T defaultValue) noexcept {
				T val{};
				if (Get<T>(j, pathLike, val)) {
					return val;
				}
				return std::move(defaultValue);
			}

			// ============================================================================
			// Setters
			// ============================================================================

			/**
			 * @brief Set value at path, creating intermediate objects/arrays as needed.
			 *
			 * Creates intermediate objects or arrays along the path if they don't exist.
			 * Array indices cause array expansion if needed.
			 *
			 * @tparam T Value type
			 * @param j Json object to modify
			 * @param pathLike Path (JSON Pointer or dot/bracket notation)
			 * @param value Value to set
			 * @return true on success, false on type mismatch or other error
			 */
			template <typename T>
			[[nodiscard]] bool Set(Json& j, std::string_view pathLike, T&& value) noexcept {
				try {
					const auto jpStr = ToJsonPointer(pathLike);

					// Handle root path
					if (jpStr == "/" || jpStr.empty()) {
						j = std::forward<T>(value);
						return true;
					}

					// Parse tokens from json pointer string
					std::vector<std::string> tokens;
					tokens.reserve(16);  // Reasonable default capacity
					std::string current;
					current.reserve(64);

					for (size_t i = 1; i < jpStr.size(); ++i) {  // Skip leading '/'
						if (jpStr[i] == '/') {
							if (!current.empty()) {
								tokens.push_back(std::move(current));
								current.clear();
								current.reserve(64);
							}
						}
						else {
							current.push_back(jpStr[i]);
						}
					}
					if (!current.empty()) {
						tokens.push_back(std::move(current));
					}

					if (tokens.empty()) {
						j = std::forward<T>(value);
						return true;
					}

					// Helper lambda to check if token is array index
					auto isArrayIndex = [](const std::string& tok) -> bool {
						if (tok.empty()) return false;
						return std::all_of(tok.begin(), tok.end(),
							[](char c) { return c >= '0' && c <= '9'; });
					};

					// Create intermediate paths
					Json* cur = &j;
					for (size_t i = 0; i < tokens.size() - 1; ++i) {
						const auto& tok = tokens[i];
						const bool isIndex = isArrayIndex(tok);

						// Initialize current node if null
						if (cur->is_null()) {
							*cur = isIndex ? Json::array() : Json::object();
						}

						// Validate type consistency
						if (isIndex && !cur->is_array()) {
							return false;  // Type mismatch
						}
						if (!isIndex && !cur->is_object()) {
							return false;  // Type mismatch
						}

						// Navigate or create intermediate node
						if (isIndex) {
							size_t idx = 0;
							try {
								idx = std::stoull(tok);
							}
							catch (...) {
								return false;  // Invalid index
							}

							// Prevent unreasonably large array expansion
							constexpr size_t MAX_ARRAY_EXPANSION = 10000;
							if (idx > cur->size() + MAX_ARRAY_EXPANSION) {
								return false;  // Prevent DoS via huge array allocation
							}

							// Expand array if needed
							while (cur->size() <= idx) {
								cur->push_back(Json::object());
							}
							cur = &(*cur)[idx];
						}
						else {
							if (!cur->contains(tok)) {
								// Look ahead to determine what type to create
								const bool nextIsIndex = (i + 1 < tokens.size() - 1) &&
									isArrayIndex(tokens[i + 1]);
								(*cur)[tok] = nextIsIndex ? Json::array() : Json::object();
							}
							cur = &(*cur)[tok];
						}
					}

					// Set final value
					const auto& finalTok = tokens.back();
					const bool isFinalIndex = isArrayIndex(finalTok);

					if (cur->is_null()) {
						*cur = isFinalIndex ? Json::array() : Json::object();
					}

					if (isFinalIndex) {
						if (!cur->is_array()) return false;
						size_t idx = 0;
						try {
							idx = std::stoull(finalTok);
						}
						catch (...) {
							return false;
						}

						// Prevent unreasonably large array expansion
						constexpr size_t MAX_ARRAY_EXPANSION = 10000;
						if (idx > cur->size() + MAX_ARRAY_EXPANSION) {
							return false;
						}

						// Expand array if needed
						while (cur->size() <= idx) {
							cur->push_back(nullptr);
						}
						(*cur)[idx] = std::forward<T>(value);
					}
					else {
						if (!cur->is_object()) return false;
						(*cur)[finalTok] = std::forward<T>(value);
					}

					return true;
				}
				catch (...) {
					return false;
				}
			}

			// ============================================================================
			// Merge and Validation
			// ============================================================================

			/**
			 * @brief Apply RFC 7396 JSON Merge Patch.
			 *
			 * Modifies target in-place according to patch semantics.
			 * Null values in patch remove keys from target.
			 *
			 * @param target Json object to modify
			 * @param patch Patch to apply
			 */
			void MergePatch(Json& target, const Json& patch) noexcept;

			/**
			 * @brief Validate that required keys exist in an object.
			 *
			 * @param j Json object to validate
			 * @param objectPathLike Path to the object (use "/" for root)
			 * @param requiredKeys List of keys that must exist
			 * @param err Optional error output
			 * @return true if all keys exist, false otherwise
			 */
			[[nodiscard]] bool RequireKeys(const Json& j, std::string_view objectPathLike,
			                               const std::vector<std::string>& requiredKeys,
			                               Error* err = nullptr) noexcept;

		}  // namespace JSON
	}  // namespace Utils
}  // namespace ShadowStrike









