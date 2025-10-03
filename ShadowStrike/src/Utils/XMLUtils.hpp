#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <filesystem>
#include <optional>
#include <cstdint>

#include <../../external/pugixml/pugixml.hpp>


namespace ShadowStrike {
	namespace Utils {
		namespace XML {

			using Document = pugi::xml_document;
			using Node = pugi::xml_node;

			//Error information
			struct Error {
				std::string message;
				std::filesystem::path path;  // if exists
				size_t byteOffset = 0;       // if known
				size_t line = 0;             // 1-based
				size_t column = 0;           // 1-based
			};

			struct ParseOptions {
				bool preserveWhitespace = false; // PCDATA whitespace
				bool allowComments = true;       //Allow comments
				bool loadExternalDtd = false;    // External DTD reading. Not secure, Dangerous(Billion Laughs Attack, etc.). Use with caution.
			};
			struct StringifyOptions {
				bool pretty = false;
				int  indentSpaces = 2;
				bool writeDeclaration = true; // write <?xml ...?>
			};

			struct SaveOptions : StringifyOptions {
				bool atomicReplace = true; // atomic rename in Windows
				bool writeBOM = false;     // UTF-8 BOM (Usually not necessary but some editors require it)
			};
			// Path helpers
            // XPath of the form "/root/a/b[1]/@id" ends.
            // If the input begins with "/..", it is accepted as a direct XPath.
            // Dot/bracket notation: a.b[0].c or @attr
			std::string ToXPath(std::string_view pathLike) noexcept;


			//Working with texts
			bool Parse(std::string_view xmlText, Document& out, Error* err = nullptr, const ParseOptions& opt = {}) noexcept;
			bool Stringify(const Node& node, std::string& out, const StringifyOptions& opt = {}) noexcept;
			bool Minify(std::string_view xmlText, std::string& out, Error* err = nullptr, const ParseOptions& opt = {}) noexcept;
			bool Prettify(std::string_view xmlText, std::string& out, int indentSpaces = 2, Error* err = nullptr, const ParseOptions& opt = {}) noexcept;

			//Working with files
			bool LoadFromFile(const std::filesystem::path& path, Document& out, Error* err = nullptr, const ParseOptions& opt = {}, size_t maxBytes = static_cast<size_t>(32) * 1024 * 1024 /*32MB*/) noexcept;
			bool SaveToFile(const std::filesystem::path& path, const Node& node, Error* err = nullptr, const SaveOptions& opt = {}) noexcept;

			//Query helpers
			bool Contains(const Node& root, std::string_view pathLike) noexcept;
			bool GetText(const Node& root, std::string_view pathLike, std::string& out) noexcept;

			// Typed getter (supports bool/int64/uint64/double). If true, out is filled.
			bool GetBool(const Node& root, std::string_view pathLike, bool& out) noexcept;
			bool GetInt64(const Node& root, std::string_view pathLike, int64_t& out) noexcept;
			bool GetUInt64(const Node& root, std::string_view pathLike, uint64_t& out) noexcept;
			bool GetDouble(const Node& root, std::string_view pathLike, double& out) noexcept;

			// Set/Replace (creates intermediate nodes if necessary). 
            // If the pathLike last step is @attr, the attribute is set; otherwise, the node text is set.
			bool Set(Node& root, std::string_view pathLike, std::string_view value) noexcept;

			// Delete node (false if not found). If @attr is targeted, the attribute is deleted.
			bool Erase(Node& root, std::string_view pathLike) noexcept;



		}// namespace XML
	}// namespace Utils
}// namespace ShadowStrike
