/**
 * @file JSONUtils.cpp
 * @brief Implementation of JSON utilities for ShadowStrike.
 *
 * Provides secure JSON parsing, serialization, and file I/O with:
 * - Depth-limited parsing to prevent stack overflow attacks
 * - Atomic file writes for data integrity
 * - Comprehensive error handling and reporting
 */

#include "JSONUtils.hpp"

#include <fstream>
#include <sstream>
#include <limits>
#include <algorithm>
#include <chrono>
#include <random>
#include <cstring>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

using nlohmann::json;

namespace ShadowStrike {
	namespace Utils {
		namespace JSON {

			// ============================================================================
			// Internal Helper Functions
			// ============================================================================

			/**
			 * @brief Calculate line and column from byte offset in text.
			 *
			 * @param text Source text
			 * @param byteOffset Byte offset (clamped to text size)
			 * @param line Output line number (1-based)
			 * @param col Output column number (1-based)
			 */
			static inline void fillLineCol(std::string_view text, size_t byteOffset,
			                               size_t& line, size_t& col) noexcept {
				line = 1;
				col = 1;

				// Clamp byte offset to valid range
				const size_t maxOff = text.size();
				if (byteOffset > maxOff) {
					byteOffset = maxOff;
				}

				for (size_t i = 0; i < byteOffset; ++i) {
					if (text[i] == '\n') {
						++line;
						col = 1;
					}
					else {
						++col;
					}
				}
			}

			/**
			 * @brief Set parse error with location information.
			 */
			static inline void setErr(Error* err, std::string msg,
			                          const std::filesystem::path& p,
			                          std::string_view text, size_t byteOff) noexcept {
				if (!err) return;

				try {
					err->message = std::move(msg);
					err->path = p;
					err->byteOffset = byteOff;
					fillLineCol(text, byteOff, err->line, err->column);
				}
				catch (...) {
					// Fallback if assignment fails
					err->message = "Error occurred (details unavailable)";
					err->byteOffset = 0;
					err->line = 0;
					err->column = 0;
				}
			}

			/**
			 * @brief Set I/O error information.
			 */
			static inline void setIoErr(Error* err, const std::string& what,
			                            const std::filesystem::path& p,
			                            const std::string& sysMsg = {}) noexcept {
				if (!err) return;

				try {
					err->message = what;
					if (!sysMsg.empty()) {
						err->message += ": ";
						err->message += sysMsg;
					}
					err->path = p;
					err->byteOffset = 0;
					err->line = 0;
					err->column = 0;
				}
				catch (...) {
					err->message = "I/O error occurred";
					err->byteOffset = 0;
					err->line = 0;
					err->column = 0;
				}
			}

			/**
			 * @brief Strip UTF-8 BOM from string if present.
			 *
			 * @param s String to modify in-place
			 */
			static inline void stripUtf8BOM(std::string& s) noexcept {
				static constexpr unsigned char BOM[3] = { 0xEF, 0xBB, 0xBF };

				if (s.size() >= 3 &&
				    static_cast<unsigned char>(s[0]) == BOM[0] &&
				    static_cast<unsigned char>(s[1]) == BOM[1] &&
				    static_cast<unsigned char>(s[2]) == BOM[2]) {
					s.erase(0, 3);
				}
			}

			/**
			 * @brief Escape a token for use in JSON Pointer (RFC 6901).
			 *
			 * Escapes '~' as '~0' and '/' as '~1'.
			 *
			 * @param token Input token
			 * @return Escaped token string
			 */
			static inline std::string escapeJsonPointerToken(std::string_view token) noexcept {
				std::string out;
				try {
					out.reserve(token.size() + 8);  // Allow room for escapes
					for (char c : token) {
						if (c == '~') {
							out += "~0";
						}
						else if (c == '/') {
							out += "~1";
						}
						else {
							out.push_back(c);
						}
					}
				}
				catch (...) {
					// On allocation failure, return partial result
				}
				return out;
			}

			// ============================================================================
			// JSON Pointer Conversion
			// ============================================================================

			std::string ToJsonPointer(std::string_view pathLike) noexcept {
				try {
					// Empty path or already a JSON Pointer
					if (pathLike.empty()) {
						return "/";
					}
					if (pathLike.front() == '/') {
						return std::string(pathLike);
					}

					// Convert "a.b[0].c" -> "/a/b/0/c"
					std::string pointer;
					pointer.reserve(pathLike.size() + 16);
					pointer.push_back('/');

					std::string current;
					current.reserve(pathLike.size());

					// Lambda to flush accumulated key
					auto flushKey = [&]() {
						if (!current.empty()) {
							pointer += escapeJsonPointerToken(current);
							pointer.push_back('/');
							current.clear();
						}
					};

					bool inBracket = false;
					std::string indexBuf;
					indexBuf.reserve(16);

					for (size_t i = 0; i < pathLike.size(); ++i) {
						const char c = pathLike[i];

						if (!inBracket) {
							if (c == '.') {
								flushKey();
							}
							else if (c == '[') {
								inBracket = true;
								flushKey();
								indexBuf.clear();
							}
							else {
								current.push_back(c);
							}
						}
						else {
							// Inside bracket
							if (c == ']') {
								// Check if valid numeric index
								const bool isNumeric = !indexBuf.empty() &&
									std::all_of(indexBuf.begin(), indexBuf.end(),
										[](char d) { return d >= '0' && d <= '9'; });

								if (isNumeric) {
									pointer += indexBuf;  // JSON Pointer index (unescaped)
								}
								else {
									// Treat as string key
									pointer += escapeJsonPointerToken(indexBuf);
								}
								pointer.push_back('/');
								inBracket = false;
							}
							else {
								indexBuf.push_back(c);
							}
						}
					}

					// Flush any remaining key
					if (!current.empty()) {
						flushKey();
					}

					// Remove trailing slash if present
					if (!pointer.empty() && pointer.back() == '/') {
						pointer.pop_back();
					}

					// Ensure non-empty result
					if (pointer.empty()) {
						pointer = "/";
					}

					return pointer;
				}
				catch (...) {
					return "/";  // Fallback to root on any error
				}
			}

			// ============================================================================
			// Parse Functions
			// ============================================================================

			bool Parse(std::string_view jsonText, Json& out, Error* err, const ParseOptions& opt) noexcept {
				// Clear output first
				out = Json();

				// Clear error if provided
				if (err) {
					err->clear();
				}

				// Validate input size to prevent DoS
				if (jsonText.size() > MAX_JSON_SIZE) {
					setErr(err, "JSON text exceeds maximum allowed size", {}, jsonText, 0);
					return false;
				}

				try {
					// Track nesting depth manually for reliable depth limiting
					size_t currentDepth = 0;
					size_t maxObservedDepth = 0;
					const size_t maxDepth = (opt.maxDepth > 0) ? opt.maxDepth : MAX_JSON_DEPTH;

					auto depthCallback = [&currentDepth, &maxObservedDepth, maxDepth](
						int /*depth*/,
						nlohmann::json::parse_event_t event,
						Json& /*parsed*/) -> bool {

						// Track depth on structure start/end
						if (event == nlohmann::json::parse_event_t::object_start ||
						    event == nlohmann::json::parse_event_t::array_start) {
							++currentDepth;
							if (currentDepth > maxObservedDepth) {
								maxObservedDepth = currentDepth;
							}
							if (currentDepth > maxDepth) {
								return false;  // Reject - depth exceeded
							}
						}
						else if (event == nlohmann::json::parse_event_t::object_end ||
						         event == nlohmann::json::parse_event_t::array_end) {
							if (currentDepth > 0) {
								--currentDepth;
							}
						}

						return true;  // Continue parsing
					};

					out = Json::parse(jsonText, depthCallback,
					                  /*allow_exceptions*/ opt.allowExceptions,
					                  /*ignore_comments*/ opt.allowComments);

					// Verify depth limit wasn't exceeded
					if (maxObservedDepth > maxDepth) {
						setErr(err, "JSON depth exceeds maximum allowed depth (" +
						       std::to_string(maxDepth) + ")", {}, jsonText, 0);
						out = Json();
						return false;
					}

					// Check for discarded result (parse failure with exceptions disabled)
					if (!opt.allowExceptions && out.is_discarded()) {
						setErr(err, "JSON parse failed", {}, jsonText, 0);
						return false;
					}

					return true;
				}
				catch (const nlohmann::json::parse_error& e) {
					// Extract byte offset from nlohmann exception (1-based)
					const size_t byteOff = (e.byte > 0) ? static_cast<size_t>(e.byte - 1) : 0;
					setErr(err, e.what(), {}, jsonText, byteOff);
					out = Json();
					return false;
				}
				catch (const std::exception& e) {
					setErr(err, e.what(), {}, jsonText, 0);
					out = Json();
					return false;
				}
				catch (...) {
					setErr(err, "Unknown JSON parse error", {}, jsonText, 0);
					out = Json();
					return false;
				}
			}

			// ============================================================================
			// Stringify Functions
			// ============================================================================

			bool Stringify(const Json& j, std::string& out, const StringifyOptions& opt) noexcept {
				out.clear();

				try {
					// Calculate indent: -1 for minified, >= 0 for pretty
					const int indent = opt.pretty ? std::max(0, opt.indentSpaces) : -1;
					out = j.dump(indent, ' ', opt.ensureAscii);
					return true;
				}
				catch (const std::bad_alloc&) {
					// Memory allocation failure
					out.clear();
					return false;
				}
				catch (...) {
					out.clear();
					return false;
				}
			}

			bool Minify(std::string_view jsonText, std::string& out, Error* err, const ParseOptions& opt) noexcept {
				out.clear();

				// Parse first
				Json j;
				if (!Parse(jsonText, j, err, opt)) {
					return false;
				}

				// Stringify without formatting
				StringifyOptions so;
				so.pretty = false;
				so.ensureAscii = false;

				if (!Stringify(j, out, so)) {
					if (err) {
						err->message = "Failed to stringify JSON";
					}
					return false;
				}

				return true;
			}

			bool Prettify(std::string_view jsonText, std::string& out, int indentSpaces,
			              Error* err, const ParseOptions& opt) noexcept {
				out.clear();

				// Parse first
				Json j;
				if (!Parse(jsonText, j, err, opt)) {
					return false;
				}

				// Stringify with formatting
				StringifyOptions so;
				so.pretty = true;
				so.indentSpaces = std::max(0, indentSpaces);
				so.ensureAscii = false;

				if (!Stringify(j, out, so)) {
					if (err) {
						err->message = "Failed to stringify JSON";
					}
					return false;
				}

				return true;
			}

			// ============================================================================
			// File I/O Functions
			// ============================================================================

			bool LoadFromFile(const std::filesystem::path& path, Json& out, Error* err,
			                  const ParseOptions& opt, size_t maxBytes) noexcept {
				// Clear output first
				out = Json();

				// Clear error if provided
				if (err) {
					err->clear();
				}

				try {
					// Validate path is not empty
					if (path.empty()) {
						setIoErr(err, "Empty file path", path);
						return false;
					}

					// Get file size via filesystem (fast check)
					std::error_code ec;
					const uintmax_t fsz = std::filesystem::file_size(path, ec);
					if (ec) {
						setIoErr(err, "Failed to get file size", path, ec.message());
						return false;
					}

					// Apply size limits
					constexpr size_t MAX_SAFE_JSON_SIZE = 100ULL * 1024 * 1024;  // 100MB hard limit
					const size_t effectiveMax = (maxBytes > 0)
						? std::min(maxBytes, MAX_SAFE_JSON_SIZE)
						: MAX_SAFE_JSON_SIZE;

					if (fsz > static_cast<uintmax_t>(effectiveMax)) {
						setIoErr(err, "File too large", path,
						         "Size: " + std::to_string(fsz) + " bytes, max: " + std::to_string(effectiveMax));
						return false;
					}

					// Open file for reading
					std::ifstream ifs(path, std::ios::in | std::ios::binary);
					if (!ifs) {
						setIoErr(err, "Failed to open file", path);
						return false;
					}

					// Seek to end to verify size
					ifs.seekg(0, std::ios::end);
					if (!ifs) {
						setIoErr(err, "Failed to seek to end of file", path);
						return false;
					}

					const auto tellPos = ifs.tellg();
					if (tellPos < 0) {
						setIoErr(err, "Failed to determine file size", path);
						return false;
					}

					// Convert streampos to size_t safely
					const std::streamoff tellOff = static_cast<std::streamoff>(tellPos);
					if (tellOff < 0) {
						setIoErr(err, "Invalid file size", path);
						return false;
					}

					// Check against SIZE_MAX for 32-bit systems
					if (static_cast<uint64_t>(tellOff) > static_cast<uint64_t>(SIZE_MAX)) {
						setIoErr(err, "File size exceeds addressable memory", path);
						return false;
					}

					const size_t fileSz = static_cast<size_t>(tellOff);

					// Re-check against effective max (stream size may differ from fs size)
					if (fileSz > effectiveMax) {
						setIoErr(err, "File too large", path,
						         "Size: " + std::to_string(fileSz) + " bytes, max: " + std::to_string(effectiveMax));
						return false;
					}

					// Seek back to beginning
					ifs.seekg(0, std::ios::beg);
					if (!ifs) {
						setIoErr(err, "Failed to seek to beginning of file", path);
						return false;
					}

					// Allocate buffer
					std::string buf;
					try {
						buf.resize(fileSz);
					}
					catch (const std::bad_alloc&) {
						setIoErr(err, "Memory allocation failed", path,
						         "Requested: " + std::to_string(fileSz) + " bytes");
						return false;
					}

					// Read file contents
					if (fileSz > 0) {
						ifs.read(buf.data(), static_cast<std::streamsize>(fileSz));
						const auto bytesRead = ifs.gcount();

						// Check for read errors (but not EOF)
						if (!ifs && !ifs.eof()) {
							setIoErr(err, "Failed to read file", path);
							return false;
						}

						// Verify we read the expected number of bytes
						if (static_cast<size_t>(bytesRead) != fileSz) {
							setIoErr(err, "File size changed during read", path,
							         "Expected: " + std::to_string(fileSz) +
							         ", got: " + std::to_string(bytesRead));
							return false;
						}
					}

					// Strip UTF-8 BOM if present
					stripUtf8BOM(buf);

					// Parse JSON with depth limiting
					const size_t maxDepth = (opt.maxDepth > 0) ? opt.maxDepth : MAX_JSON_DEPTH;

					try {
						size_t currentDepth = 0;
						size_t maxObservedDepth = 0;

						auto depthCallback = [&currentDepth, &maxObservedDepth, maxDepth](
							int /*depth*/,
							nlohmann::json::parse_event_t event,
							Json& /*parsed*/) -> bool {

							if (event == nlohmann::json::parse_event_t::object_start ||
							    event == nlohmann::json::parse_event_t::array_start) {
								++currentDepth;
								if (currentDepth > maxObservedDepth) {
									maxObservedDepth = currentDepth;
								}
								if (currentDepth > maxDepth) {
									return false;  // Depth exceeded
								}
							}
							else if (event == nlohmann::json::parse_event_t::object_end ||
							         event == nlohmann::json::parse_event_t::array_end) {
								if (currentDepth > 0) {
									--currentDepth;
								}
							}
							return true;
						};

						out = Json::parse(buf, depthCallback,
						                  /*allow_exceptions*/ opt.allowExceptions,
						                  /*ignore_comments*/ opt.allowComments);

						// Verify depth limit
						if (maxObservedDepth > maxDepth) {
							setErr(err, "JSON depth exceeds maximum allowed depth (" +
							       std::to_string(maxDepth) + ")", path, buf, 0);
							out = Json();
							return false;
						}

						// Check for discarded result
						if (!opt.allowExceptions && out.is_discarded()) {
							setErr(err, "JSON parse failed", path, buf, 0);
							return false;
						}

						return true;
					}
					catch (const nlohmann::json::parse_error& e) {
						const size_t byteOff = (e.byte > 0) ? static_cast<size_t>(e.byte - 1) : 0;
						setErr(err, e.what(), path, buf, byteOff);
						out = Json();
						return false;
					}
					catch (const std::exception& e) {
						setErr(err, e.what(), path, buf, 0);
						out = Json();
						return false;
					}
				}
				catch (const std::filesystem::filesystem_error& e) {
					setIoErr(err, "Filesystem error", path, e.what());
					return false;
				}
				catch (const std::exception& e) {
					setIoErr(err, e.what(), path);
					return false;
				}
				catch (...) {
					setIoErr(err, "Unknown error loading JSON file", path);
					return false;
				}
			}

			bool SaveToFile(const std::filesystem::path& path, const Json& j,
			                Error* err, const SaveOptions& opt) noexcept {
				// Clear error if provided
				if (err) {
					err->clear();
				}

				try {
					// Validate path
					if (path.empty()) {
						setIoErr(err, "Empty file path", path);
						return false;
					}

					// Serialize JSON to string
					std::string content;
					if (!Stringify(j, content, opt)) {
						setIoErr(err, "JSON stringify failed", path);
						return false;
					}

					// Optionally prepend UTF-8 BOM
					if (opt.writeBOM) {
						static constexpr unsigned char BOM[3] = { 0xEF, 0xBB, 0xBF };
						content.insert(content.begin(), BOM, BOM + 3);
					}

					// Ensure parent directory exists
					const auto dir = path.parent_path().empty()
						? std::filesystem::current_path()
						: path.parent_path();

					std::error_code ec;
					std::filesystem::create_directories(dir, ec);
					// Ignore error - directory might already exist

					// Generate secure temporary file name
					// Use high-resolution clock + random number for uniqueness
					const auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();

					std::random_device rd;
					uint64_t randomId = 0;

					try {
						std::mt19937_64 rng(static_cast<uint64_t>(now) ^ static_cast<uint64_t>(rd()));
						std::uniform_int_distribution<uint64_t> dist;
						randomId = dist(rng);
					}
					catch (...) {
						// Fallback to time-based only
						randomId = static_cast<uint64_t>(now);
					}

					// Build temp filename
					std::wostringstream tempNameStream;
					tempNameStream << L".tmp." << std::hex << now << L"_" << randomId << L".json";
					const auto tmp = dir / tempNameStream.str();

					// Write to temporary file first
					{
						std::ofstream ofs(tmp, std::ios::out | std::ios::binary | std::ios::trunc);
						if (!ofs) {
							setIoErr(err, "Failed to create temp file", tmp);
							return false;
						}

						ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
						if (!ofs) {
							setIoErr(err, "Failed to write temp file", tmp);
							// Attempt cleanup
							std::filesystem::remove(tmp, ec);
							return false;
						}

						ofs.flush();
						if (!ofs) {
							setIoErr(err, "Failed to flush temp file", tmp);
							std::filesystem::remove(tmp, ec);
							return false;
						}

						// Close file explicitly before rename
						ofs.close();
					}

					// Perform atomic or direct write
					if (opt.atomicReplace) {
#ifdef _WIN32
						// Windows: Use MoveFileExW for atomic replacement with write-through
						if (!MoveFileExW(tmp.c_str(), path.c_str(),
						                 MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
							const DWORD lastErr = GetLastError();
							setIoErr(err, "MoveFileExW failed", path,
							         "Error code: " + std::to_string(static_cast<unsigned long>(lastErr)));
							// Attempt cleanup of temp file
							std::filesystem::remove(tmp, ec);
							return false;
						}
#else
						// POSIX: Remove destination first, then rename
						std::filesystem::remove(path, ec);  // Ignore error if file doesn't exist
						std::filesystem::rename(tmp, path, ec);
						if (ec) {
							setIoErr(err, "Failed to rename temp file", path, ec.message());
							std::filesystem::remove(tmp, ec);
							return false;
						}
#endif
					}
					else {
						// Non-atomic: Write directly to destination
						std::ofstream ofs(path, std::ios::out | std::ios::binary | std::ios::trunc);
						if (!ofs) {
							setIoErr(err, "Failed to open file for write", path);
							std::filesystem::remove(tmp, ec);
							return false;
						}

						ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
						if (!ofs) {
							setIoErr(err, "Failed to write file", path);
							std::filesystem::remove(tmp, ec);
							return false;
						}

						ofs.flush();
						if (!ofs) {
							setIoErr(err, "Failed to flush file", path);
							std::filesystem::remove(tmp, ec);
							return false;
						}

						ofs.close();

						// Remove temp file (was written but not used in non-atomic mode)
						std::filesystem::remove(tmp, ec);
					}

					return true;
				}
				catch (const std::filesystem::filesystem_error& e) {
					setIoErr(err, "Filesystem error", path, e.what());
					return false;
				}
				catch (const std::exception& e) {
					setIoErr(err, e.what(), path);
					return false;
				}
				catch (...) {
					setIoErr(err, "Unknown error saving JSON file", path);
					return false;
				}
			}

			// ============================================================================
			// JSON Navigation and Manipulation
			// ============================================================================

			bool Contains(const Json& j, std::string_view pathLike) noexcept {
				try {
					const std::string jpStr = ToJsonPointer(pathLike);

					// Handle root path specially
					if (jpStr == "/" || jpStr.empty()) {
						return true;  // Root always exists
					}

					const nlohmann::json::json_pointer jp(jpStr);
					return j.contains(jp);
				}
				catch (...) {
					return false;
				}
			}

			void MergePatch(Json& target, const Json& patch) noexcept {
				try {
					target.merge_patch(patch);
				}
				catch (...) {
					// Silently ignore merge errors
					// This is consistent with RFC 7396 behavior
				}
			}

			bool RequireKeys(const Json& j, std::string_view objectPathLike,
			                 const std::vector<std::string>& requiredKeys, Error* err) noexcept {
				// Clear error if provided
				if (err) {
					err->clear();
				}

				try {
					const std::string objPtr = ToJsonPointer(objectPathLike);

					// Get the target node
					const Json* node = nullptr;

					if (objPtr == "/" || objPtr.empty()) {
						// Root path
						node = &j;
					}
					else {
						const nlohmann::json::json_pointer jp(objPtr);
						if (!j.contains(jp)) {
							if (err) {
								err->message = "Object path not found: " + objPtr;
							}
							return false;
						}
						node = &j.at(jp);
					}

					// Validate that target is an object
					if (!node->is_object()) {
						if (err) {
							err->message = "Target is not an object: " + objPtr;
						}
						return false;
					}

					// Check for all required keys
					for (const auto& key : requiredKeys) {
						if (!node->contains(key)) {
							if (err) {
								err->message = "Missing required key: " + key;
							}
							return false;
						}
					}

					return true;
				}
				catch (const nlohmann::json::exception& e) {
					if (err) {
						err->message = std::string("JSON error: ") + e.what();
					}
					return false;
				}
				catch (const std::exception& e) {
					if (err) {
						err->message = e.what();
					}
					return false;
				}
				catch (...) {
					if (err) {
						err->message = "Unknown error in RequireKeys";
					}
					return false;
				}
			}

		}  // namespace JSON
	}  // namespace Utils
}  // namespace ShadowStrike