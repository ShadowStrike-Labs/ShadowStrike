
#include "XMLUtils.hpp"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <charconv>

#ifdef _WIN32
#  define NOMINMAX
#  include <Windows.h>
#endif

namespace ShadowStrike {
	namespace Utils {
		namespace XML {

            static inline void fillLineCol(std::string_view text, size_t byteOffset, size_t& line, size_t& col) {
                line = 1; col = 1;
                if (byteOffset > text.size()) byteOffset = text.size();
                for (size_t i = 0; i < byteOffset; ++i) {
                    char c = text[i];
                    if (c == '\n') { ++line; col = 1; }
                    else { ++col; }
                }
            }

            static inline void setErr(Error* err, std::string msg, const std::filesystem::path& p, std::string_view text, size_t byteOff) {
                if (!err) return;
                err->message = std::move(msg);
                err->path = p;
                err->byteOffset = byteOff;
                fillLineCol(text, byteOff, err->line, err->column);
            }

            static inline void setIoErr(Error* err, const std::string& what, const std::filesystem::path& p, const std::string& sysMsg = {}) {
                if (!err) return;
                err->message = what + (sysMsg.empty() ? "" : (": " + sysMsg));
                err->path = p;
                err->byteOffset = 0;
                err->line = 0;
                err->column = 0;
            }

            static inline void stripUtf8BOM(std::string& s) {
                static const unsigned char bom[3] = { 0xEF,0xBB,0xBF };
                if (s.size() >= 3 && (unsigned char)s[0] == bom[0] && (unsigned char)s[1] == bom[1] && (unsigned char)s[2] == bom[2]) {
                    s.erase(0, 3);
                }
            }

            static inline bool isDigit(char c) noexcept { return c >= '0' && c <= '9'; }

            struct Step {
                std::string name;     // element name or "@attr"
                bool isAttribute = false;
                bool hasIndex = false;
				size_t index = 0;     // 0-based, will be transformed to 1-based in XPath
            };

            static void parsePathLike(std::string_view sv, std::vector<Step>& out) {
                out.clear();
                if (sv.empty()) return;
                if (sv.front() == '/') {
					// if its Xpath already, do nothing
                    return;
                }
                std::string cur;
                cur.reserve(sv.size());
                for (size_t i = 0; i < sv.size(); ++i) {
                    char c = sv[i];
                    if (c == '.') {
                        if (!cur.empty()) {
                            Step st;
                            st.isAttribute = (!cur.empty() && cur[0] == '@');
                            if (st.isAttribute) st.name = cur.substr(1);
                            else st.name = cur;
                            out.push_back(std::move(st));
                            cur.clear();
                        }
                    }
                    else {
                        cur.push_back(c);
                    }
                }
                if (!cur.empty()) {
                    Step st;
                    st.isAttribute = (!cur.empty() && cur[0] == '@');
                    if (st.isAttribute) st.name = cur.substr(1);
                    else st.name = cur;
                    out.push_back(std::move(st));
                }

                // Does it have any index?
                for (auto& s : out) {
                    auto lb = s.name.find('[');
                    if (lb != std::string::npos && lb + 1 < s.name.size() && !s.isAttribute) {
                        auto rb = s.name.find(']', lb + 1);
                        if (rb != std::string::npos) {
                            std::string idxStr = s.name.substr(lb + 1, rb - (lb + 1));
                            bool allDigits = !idxStr.empty() && std::all_of(idxStr.begin(), idxStr.end(), isDigit);
                            if (allDigits) {
                                try {
                                    unsigned long long idx = std::stoull(idxStr);
									// Max index limit to prevent DoS attack
                                    constexpr size_t MAX_INDEX = 100000;
                                    if (idx > MAX_INDEX) {
                                        // invalid index, skip it
                                        continue;
                                    }
                                    s.hasIndex = true;
                                    s.index = static_cast<size_t>(idx);
                                }
                                catch (const std::out_of_range&) {
                                    // Index is too large, skip it
                                    continue;
                                }
                                catch (const std::invalid_argument&) {
                                    // invalid format , skip it
                                    continue;
                                }
                            }
                            s.name = s.name.substr(0, lb);
                        }
                    }
                }
            }

            std::string ToXPath(std::string_view pathLike) noexcept {
                try {
                    if (pathLike.empty()) return std::string("/");
                    if (pathLike.front() == '/') return std::string(pathLike); // already XPath

                    std::vector<Step> steps;
                    parsePathLike(pathLike, steps);
                    if (steps.empty()) return std::string("/");

                    std::string xp;
                    xp.reserve(pathLike.size() * 2);
                    xp.push_back('/');
                    for (size_t i = 0; i < steps.size(); ++i) {
                        const auto& s = steps[i];
                        if (s.isAttribute) {
                            xp.push_back('@');
                            xp.append(s.name);
							
                        }
                        else {
                            xp.append(s.name);
                            if (s.hasIndex) {
                                // XPath indexes are 1-based
                                xp.push_back('[');
                                xp.append(std::to_string(s.index + 1));
                                xp.push_back(']');
                            }
                        }
                        if (i + 1 < steps.size()) xp.push_back('/');
                    }
                    return xp;
                }
                catch (...) {
                    return std::string("/");
                }
            }

            bool Parse(std::string_view xmlText, Document& out, Error* err, const ParseOptions& opt) noexcept {
                try {
                    pugi::xml_parse_result res{};
                    unsigned int flags = pugi::parse_default;
                    if (opt.preserveWhitespace) flags |= pugi::parse_ws_pcdata;
                    if (!opt.allowComments)     flags &= ~pugi::parse_comments;
					if (!opt.loadExternalDtd)   flags &= ~pugi::parse_doctype; // Block the external DTD loading for security
                    // pugi::encoding_utf8: accept utf-8 even if there is no xml declaration
                    res = out.load_buffer(xmlText.data(), static_cast<unsigned int>(xmlText.size()), flags, pugi::encoding_utf8);
                    if (!res) {
                        setErr(err, res.description(), {}, xmlText, static_cast<size_t>(res.offset));
                        return false;
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

            struct StringWriter : pugi::xml_writer {
                std::string s;
                void write(const void* data, size_t size) override {
                    s.append(static_cast<const char*>(data), size);
                }
            };

            static bool saveToString(const Node& node, std::string& out, const StringifyOptions& opt) {
                StringWriter wr;
                unsigned int fmt = pugi::format_default;
                if (!opt.pretty) fmt = pugi::format_raw;
                if (!opt.writeDeclaration) fmt |= pugi::format_no_declaration;

                std::string indent;
                if (opt.pretty) indent.assign(std::max(0, opt.indentSpaces), ' ');

                
                node.print(wr, opt.pretty ? indent.c_str() : "", fmt, pugi::encoding_utf8);

                out = std::move(wr.s);
                return true;
            }

            bool Stringify(const Node& node, std::string& out, const StringifyOptions& opt) noexcept {
                try {
                    return saveToString(node, out, opt);
                }
                catch (...) {
                    return false;
                }
            }

            bool Minify(std::string_view xmlText, std::string& out, Error* err, const ParseOptions& opt) noexcept {
                Document doc;
                if (!Parse(xmlText, doc, err, opt)) return false;
                StringifyOptions so{};
                so.pretty = false;
                so.writeDeclaration = true;
                return Stringify(doc, out, so);
            }

            bool Prettify(std::string_view xmlText, std::string& out, int indentSpaces, Error* err, const ParseOptions& opt) noexcept {
                Document doc;
                if (!Parse(xmlText, doc, err, opt)) return false;
                StringifyOptions so{};
                so.pretty = true;
                so.indentSpaces = indentSpaces;
                so.writeDeclaration = true;
                return Stringify(doc, out, so);
            }


            bool LoadFromFile(const std::filesystem::path& path, Document& out, Error* err, const ParseOptions& opt, size_t maxBytes) noexcept {
                try {
                    std::error_code ec;
                    auto sz = std::filesystem::file_size(path, ec);
                    if (ec) {
                        setIoErr(err, "Failed to get file size", path, ec.message());
                        return false;
                    }
					constexpr uintmax_t MAX_SAFE_XML_SIZE = 512ULL * 1024 * 1024; // 512MB
                    if (sz > MAX_SAFE_XML_SIZE) {
                        setIoErr(err, "File too large", path);
                        return false;
                    }
                    std::ifstream ifs(path, std::ios::in | std::ios::binary);
                    if (!ifs) {
                        setIoErr(err, "Failed to open file", path);
                        return false;
                    }
                    std::string buf;
                    try {
                        buf.resize(static_cast<size_t>(sz));
                    }catch(const std::bad_alloc&) {
                        setIoErr(err, "Memory allocation failed for file size", path);
                        return false;
					}
                    if (sz > 0) {
                        ifs.read(buf.data(), static_cast<std::streamsize>(sz));
                        if (!ifs) {
                            setIoErr(err, "Failed to read file", path);
                            return false;
                        }
                    }
                    stripUtf8BOM(buf);
                    return Parse(buf, out, err, opt);
                }
                catch (const std::exception& e) {
                    setIoErr(err, e.what(), path);
                    return false;
                }
            }

            bool SaveToFile(const std::filesystem::path& path, const Node& node, Error* err, const SaveOptions& opt) noexcept {
                try {
                    std::string content;
                    if (!Stringify(node, content, opt)) {
                        setIoErr(err, "XML stringify failed", path);
                        return false;
                    }
                    if (opt.writeBOM) {
                        static const unsigned char bom[3] = { 0xEF,0xBB,0xBF };
                        content.insert(content.begin(), bom, bom + 3);
                    }

                    const auto dir = path.parent_path().empty() ? std::filesystem::current_path() : path.parent_path();
                    std::error_code ec;
                    std::filesystem::create_directories(dir, ec);

                    const auto tmp = dir / (path.filename().wstring() + L".tmp.xml");

                    {
                        std::ofstream ofs(tmp, std::ios::out | std::ios::binary | std::ios::trunc);
                        if (!ofs) {
                            setIoErr(err, "Failed to create temp file", tmp);
                            return false;
                        }
                        ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
                        if (!ofs) {
                            setIoErr(err, "Failed to write temp file", tmp);
                            return false;
                        }
                        ofs.flush();
                        if (!ofs) {
                            setIoErr(err, "Failed to flush temp file", tmp);
                            return false;
                        }
                    }

                    if (opt.atomicReplace) {
#ifdef _WIN32
                        if (!MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                            DWORD le = GetLastError();
                            setIoErr(err, "MoveFileExW failed", path, std::to_string(static_cast<unsigned long>(le)));
                            std::filesystem::remove(tmp, ec);
                            return false;
                        }
#else
                        std::filesystem::remove(path, ec);
                        std::filesystem::rename(tmp, path, ec);
                        if (ec) {
                            setIoErr(err, "Failed to rename temp file", path, ec.message());
                            std::filesystem::remove(tmp, ec);
                            return false;
                        }
#endif
                    }
                    else {
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
                        std::filesystem::remove(tmp, ec);
                    }
                    return true;
                }
                catch (const std::exception& e) {
                    setIoErr(err, e.what(), path);
                    return false;
                }
            }


            bool Contains(const Node& root, std::string_view pathLike) noexcept {
                try {
                    const std::string xp = ToXPath(pathLike);
                    pugi::xpath_node xn = root.select_node(xp.c_str());
                    if (xn) return true;
                    return false;
                }
                catch (...) { return false; }
            }

            static bool getNodeOrAttrText(const Node& root, std::string_view pathLike, std::string& out) {
                const std::string xp = ToXPath(pathLike);
                pugi::xpath_node xn = root.select_node(xp.c_str());
                if (!xn) return false;
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

            bool GetText(const Node& root, std::string_view pathLike, std::string& out) noexcept {
                try {
                    out.clear();
                    return getNodeOrAttrText(root, pathLike, out);
                }
                catch (...) { return false; }
            }

            static inline bool parse_bool(std::string_view s, bool& v) noexcept {
                if (s == "1" || s == "true" || s == "TRUE" || s == "True") { v = true; return true; }
                if (s == "0" || s == "false" || s == "FALSE" || s == "False") { v = false; return true; }
                return false;
            }

            bool GetBool(const Node& root, std::string_view pathLike, bool& out) noexcept {
                std::string s;
                if (!GetText(root, pathLike, s)) return false;
                return parse_bool(s, out);
            }

            bool GetInt64(const Node& root, std::string_view pathLike, int64_t& out) noexcept {
                std::string s;
                if (!GetText(root, pathLike, s)) return false;
                auto* b = s.data();
                auto* e = s.data() + s.size();
                auto res = std::from_chars(b, e, out, 10);
                return res.ec == std::errc{} && res.ptr == e;
            }

            bool GetUInt64(const Node& root, std::string_view pathLike, uint64_t& out) noexcept {
                std::string s;
                if (!GetText(root, pathLike, s)) return false;
                auto* b = s.data();
                auto* e = s.data() + s.size();
                auto res = std::from_chars(b, e, out, 10);
                return res.ec == std::errc{} && res.ptr == e;
            }

            bool GetDouble(const Node& root, std::string_view pathLike, double& out) noexcept {
                std::string s;
                if (!GetText(root, pathLike, s)) return false;
                char* endp = nullptr;
                out = std::strtod(s.c_str(), &endp);
                return endp && *endp == '\0';
            }

            // Set support: creates intermediate nodes; if last step is @attr, sets attribute, otherwise sets .text
            bool Set(Node& root, std::string_view pathLike, std::string_view value) noexcept {
                try {
                    if (pathLike.empty()) return false;
                    if (pathLike.front() == '/') {
                        // Creating intermediate nodes with XPath is not reliable; only set if target exists
                        const std::string xp(pathLike);
                        pugi::xpath_node xn = root.select_node(xp.c_str());
                        if (!xn) return false;
                        if (xn.attribute()) { return xn.attribute().set_value(std::string(value).c_str()); }
                        if (xn.node()) { xn.node().text() = std::string(value).c_str(); return true; }
                        return false;
                    }

                    std::vector<Step> steps;
                    parsePathLike(pathLike, steps);
                    if (steps.empty()) return false;

                    // Root node
                    Node cur = root;
                    if (cur.type() == pugi::node_document) {
                        if (!cur.first_child()) {
                            // if first element doesn't exist, create first element
                            if (steps[0].isAttribute) return false; // attribute cannot be at root
                            cur.append_child(steps[0].name.c_str());
                        }
                        cur = cur.first_child();
                        // If first step doesn't match root, we'll establish hierarchy by adding it as child
                        if (!steps[0].isAttribute && std::string(cur.name()) != steps[0].name) {
                            // if document contains another root, we cannot add new root
                            if (root.first_child() && root.first_child().next_sibling()) return false;
                            // no renaming of existing root; just proceed under it
                        }
                    }

                    // Progression and creation
                    Node parent = root.type() == pugi::node_document ? root.first_child() : root;
                    for (size_t i = 0; i < steps.size(); ++i) {
                        const Step& s = steps[i];
                        const bool last = (i + 1 == steps.size());
                        if (s.isAttribute) {
                            if (!last) return false; // we don't support attribute in intermediate steps
                            if (!parent) return false;
                            auto a = parent.attribute(s.name.c_str());
                            if (!a) a = parent.append_attribute(s.name.c_str());
                            return a.set_value(std::string(value).c_str());
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
                                }
                                else {
                                    // count existing and add until reaching s.index
                                    size_t cnt = 0;
                                    for (Node child = parent.child(s.name.c_str()); child; child = child.next_sibling(s.name.c_str())) ++cnt;
									if (cnt > 100000) return false; // prevent infinite loop from malformed XML

                                    constexpr size_t MAX_XML_ARRAY_SIZE = 10000;
									if (s.index > MAX_XML_ARRAY_SIZE) return false; //Maximum array size protection

                                    if (s.index - cnt > 1000) return false; //Too many nodes to create at once.
                                    for (; cnt <= s.index; ++cnt) parent.append_child(s.name.c_str());
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
                    pugi::xpath_node xn = root.select_node(xp.c_str());
                    if (!xn) return false;
                    if (xn.attribute()) {
                        Node parentNode = xn.parent();
						return parentNode.remove_attribute(xn.attribute());
                    }
                    if (xn.node()) {
                        auto n = xn.node();
                        if (n.parent()) return n.parent().remove_child(n);
                    }
                    return false;
                }
                catch (...) { return false; }
            }

		}// namespace XML
	}// namespace Utils
}// namespace ShadowStrike