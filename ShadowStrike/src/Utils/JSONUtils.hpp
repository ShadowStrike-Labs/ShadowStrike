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
					// Create intermediate paths
                    // nlohmann::json does not create intermediate paths directly; we do.
					if (jpStr == "/") { j = std::forward<T>(value); return true; }
					Json* cur = &j;
					std::string acc;
					for (const auto& tok : jp) {
						acc.push_back('/');
						acc.append(tok);
						nlohmann::json::json_pointer partial(acc);
						if (!j.contains(partial)) {
							
							bool isIndex = !tok.empty() && std::all_of(tok.begin(), tok.end(), [](char c) { return c >= '0' && c <= '9'; });
							(*cur)[tok] = isIndex ? Json::array() : Json::object();
						}
						cur = &j.at(partial);
					}
					j[nlohmann::json::json_pointer(jpStr)] = std::forward<T>(value);
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



