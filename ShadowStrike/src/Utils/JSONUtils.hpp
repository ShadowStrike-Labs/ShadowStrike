#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <filesystem>
#include <cstdint>
#include <optional>

#include<../../external/nlohmann/json.hpp>


namespace ShadowStrike {
	namespace Utils {
		namespace JSON {

			using Json = nlohmann::json;

			// ? ADDED: Security constants
			constexpr size_t MAX_JSON_SIZE = 100ULL * 1024 * 1024; // 100MB
			constexpr size_t MAX_JSON_DEPTH = 1000; // Max nesting depth
			constexpr size_t MAX_HEX_INPUT = 10 * 1024 * 1024; // 10MB hex input limit

			struct Error {
				// Error info
				std::string message;
				std::filesystem::path path;  // if exists
				size_t byteOffset = 0;       // if known
				size_t line = 0;             // approximately : 1-based
				size_t column = 0;           // approximately : 1-based
			};

			struct ParseOptions {
				bool allowComments = true;         // // ve /* */ comments
				bool allowExceptions = true;       // Allow exceptions at parsing?
				size_t maxDepth = MAX_JSON_DEPTH;  // ? ADDED: Max nesting depth
			};

			struct StringifyOptions {
				bool pretty = false;
				int indentSpaces = 2;              // for pretty
				bool ensureAscii = false;          
			};

			struct SaveOptions : StringifyOptions {
				bool atomicReplace = true;         // Change the destination file atomically (default true)
				bool writeBOM = false;             // UTF-8 BOM writing(default false)
			};

			//
			//Working with texts
			//
			bool Parse(std::string_view jsonText, Json& out, Error* err = nullptr, const ParseOptions& opt = {}) noexcept;
			bool Stringify(const Json& j, std::string& out, const StringifyOptions& opt = {}) noexcept;
			bool Minify(std::string_view jsonText, std::string& out, Error* err = nullptr, const ParseOptions& opt = {}) noexcept;
			bool Prettify(std::string_view jsonText, std::string& out, int indentSpaces = 2, Error* err = nullptr, const ParseOptions& opt = {}) noexcept;

			//
			//Working with files(UTF-8)
			//
			bool LoadFromFile(const std::filesystem::path& path, Json& out, Error* err = nullptr, const ParseOptions& opt = {}, size_t maxBytes = static_cast<size_t>(32) * 1024 * 1024 /* 32MB */) noexcept;
			bool SaveToFile(const std::filesystem::path& path, const Json& j, Error* err = nullptr, const SaveOptions& opt = {}) noexcept;

			//
            // JSON Pointer / Path helpers
            // - path can be "/a/b/0" (JSON Pointer) or "a.b[0].c" (dot/bracket).
            // - Automatically detected; starting with '/' is considered a JSON Pointer.
            //
			std::string ToJsonPointer(std::string_view pathLike) noexcept;

			//exists or not checks
			bool Contains(const Json& j, std::string_view pathLike) noexcept;


			// Typed getter (JSON Pointer or dot/bracket path)
            // - If the return value is true, out is filled.
            // - T must be compatible with nlohmann::json::get<T>().
			template <typename T>
			bool Get(const Json& j, std::string_view pathLike, T& out) noexcept {
				try {
					const auto jp = ToJsonPointer(pathLike);
					if (!j.contains(nlohmann::json::json_pointer(jp))) return false;
					out = j.at(nlohmann::json::json_pointer(jp)).template get<T>();
					return true;
				}
				catch (...) {
					return false;
				}
			}

			template <typename T>
			T GetOr(const Json& j, std::string_view pathLike, T defaultValue) noexcept {
				T val{};
				return Get<T>(j, pathLike, val) ? val : std::move(defaultValue);
			}

			// Set/Replace 
			template <typename T>
			bool Set(Json& j, std::string_view pathLike, T&& value) noexcept {
				try {
					const auto jpStr = ToJsonPointer(pathLike);
					const nlohmann::json::json_pointer jp(jpStr);
					
					if (jpStr == "/") { 
						j = std::forward<T>(value); 
						return true; 
					}
					
					// Parse tokens from json pointer string manually
					std::vector<std::string> tokens;
					std::string current;
					for (size_t i = 1; i < jpStr.size(); ++i) { // Skip leading '/'
						if (jpStr[i] == '/') {
							if (!current.empty()) {
								tokens.push_back(current);
								current.clear();
							}
						} else {
							current.push_back(jpStr[i]);
						}
					}
					if (!current.empty()) {
						tokens.push_back(current);
					}
					
					if (tokens.empty()) {
						j = std::forward<T>(value);
						return true;
					}
					
					// Create intermediate paths
					Json* cur = &j;
					for (size_t i = 0; i < tokens.size() - 1; ++i) {
						const auto& tok = tokens[i];
						bool isIndex = !tok.empty() && std::all_of(tok.begin(), tok.end(), [](char c) { return c >= '0' && c <= '9'; });
						
						// Initialize current node if null
						if (cur->is_null()) {
							*cur = isIndex ? Json::array() : Json::object();
						}
						
						// Ensure correct type
						if (isIndex && !cur->is_array()) {
							return false; // Type mismatch
						}
						if (!isIndex && !cur->is_object()) {
							return false; // Type mismatch
						}
						
						// Navigate or create intermediate node
						if (isIndex) {
							size_t idx = std::stoull(tok);
							// Expand array if needed
							while (cur->size() <= idx) {
								cur->push_back(Json::object());
							}
							cur = &(*cur)[idx];
						} else {
							if (!cur->contains(tok)) {
								// Look ahead to determine what to create
								bool nextIsIndex = (i + 1 < tokens.size() - 1) && 
								                   !tokens[i + 1].empty() && 
								                   std::all_of(tokens[i + 1].begin(), tokens[i + 1].end(), [](char c) { return c >= '0' && c <= '9'; });
								(*cur)[tok] = nextIsIndex ? Json::array() : Json::object();
							}
							cur = &(*cur)[tok];
						}
					}
					
					// Set final value
					const auto& finalTok = tokens.back();
					bool isFinalIndex = !finalTok.empty() && std::all_of(finalTok.begin(), finalTok.end(), [](char c) { return c >= '0' && c <= '9'; });
					
					if (cur->is_null()) {
						*cur = isFinalIndex ? Json::array() : Json::object();
					}
					
					if (isFinalIndex) {
						if (!cur->is_array()) return false;
						size_t idx = std::stoull(finalTok);
						// Expand array if needed
						while (cur->size() <= idx) {
							cur->push_back(nullptr);
						}
						(*cur)[idx] = std::forward<T>(value);
					} else {
						if (!cur->is_object()) return false;
						(*cur)[finalTok] = std::forward<T>(value);
					}
					
					return true;
				}
				catch (...) {
					return false;
				}
			}

			// RFC 7396 merge_patch
			void MergePatch(Json& target, const Json& patch) noexcept;

			//validations
			bool RequireKeys(const Json& j, std::string_view objectPathLike, const std::vector<std::string>& requiredKeys, Error* err = nullptr) noexcept;


		}// namespace JSON
	}// namespace Utils
}// namespace ShadowStrike









