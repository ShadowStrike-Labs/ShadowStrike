#include "JSONUtils.hpp"

#include <fstream>
#include <sstream>
#include <limits>
#include <algorithm>

#ifdef _WIN32
#  define NOMINMAX
#  include <Windows.h>
#endif

using nlohmann::json;

namespace ShadowStrike {
	namespace Utils {
		namespace JSON {

            static inline void fillLineCol(std::string_view text, size_t byteOffset, size_t& line, size_t& col) {
                line = 1; col = 1;
                if (byteOffset > text.size()) byteOffset = text.size();
                for (size_t i = 0; i < byteOffset; ++i) {
                    if (text[i] == '\n') { ++line; col = 1; }
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

            static inline void stripUtf8BOM(std::string& s) {
                static const unsigned char bom[3] = { 0xEF,0xBB,0xBF };
                if (s.size() >= 3 && (unsigned char)s[0] == bom[0] && (unsigned char)s[1] == bom[1] && (unsigned char)s[2] == bom[2]) {
                    s.erase(0, 3);
                }
            }

            static inline std::string escapeJsonPointerToken(std::string_view token) {
                std::string out;
                out.reserve(token.size());
                for (char c : token) {
                    if (c == '~') { out += "~0"; }
                    else if (c == '/') { out += "~1"; }
                    else { out.push_back(c); }
                }
                return out;
            }


            std::string ToJsonPointer(std::string_view pathLike) noexcept {
                if (pathLike.empty() || pathLike.front() == '/') {
                    // already JSON pointer
                    return std::string(pathLike.empty() ? "/" : pathLike);
                }

				// "a.b[0].c" -> "/a/b/0/c"
                std::string pointer;
                pointer.reserve(pathLike.size() + 1);
                pointer.push_back('/');

                std::string cur;
                cur.reserve(pathLike.size());

                auto flush_key = [&]() {
                    if (!cur.empty()) {
                        pointer += escapeJsonPointerToken(cur);
                        pointer.push_back('/');
                        cur.clear();
                    }
                    };

                bool inBracket = false;
                std::string indexBuf;
                for (size_t i = 0; i < pathLike.size(); ++i) {
                    char c = pathLike[i];
                    if (!inBracket) {
                        if (c == '.') {
                            flush_key();
                        }
                        else if (c == '[') {
                            inBracket = true;
                            flush_key();
                            indexBuf.clear();
                        }
                        else {
                            cur.push_back(c);
                        }
                    }
                    else {
                        if (c == ']') {
                            // index
                            if (indexBuf.empty() || !std::all_of(indexBuf.begin(), indexBuf.end(), [](char d) { return d >= '0' && d <= '9'; })) {
								//invalid index, treat as string key
                                pointer += escapeJsonPointerToken(indexBuf);
                            }
                            else {
                                pointer += indexBuf; // JSON Pointer index rule
                            }
                            pointer.push_back('/');
                            inBracket = false;
                        }
                        else {
                            indexBuf.push_back(c);
                        }
                    }
                }
                if (!cur.empty()) flush_key();
                if (!pointer.empty() && pointer.back() == '/') pointer.pop_back();
                if (pointer.empty()) pointer = "/";
                return pointer;
            }


            bool Parse(std::string_view jsonText, Json& out, Error* err, const ParseOptions& opt) noexcept {
                try {
					//if allowExceptions is false, parse errors will not throw but return discarded json
                    out = Json::parse(jsonText, /*cb*/nullptr, /*allow_exceptions*/ opt.allowExceptions, /*ignore_comments*/ opt.allowComments);
                    if (!opt.allowExceptions && out.is_discarded()) {
                        setErr(err, "JSON parse failed", {}, jsonText, 0);
                        return false;
                    }
                    return true;
                }
                catch (const nlohmann::json::parse_error& e) {
                    // e.byte: 1-based ofset
                    size_t byteOff = e.byte > 0 ? static_cast<size_t>(e.byte - 1) : 0;
                    setErr(err, e.what(), {}, jsonText, byteOff);
                    return false;
                }
                catch (const std::exception& e) {
                    setErr(err, e.what(), {}, jsonText, 0);
                    return false;
                }
                catch (...) {
                    setErr(err, "Unknown JSON parse error", {}, jsonText, 0);
                    return false;
                }
            }

            bool Stringify(const Json& j, std::string& out, const StringifyOptions& opt) noexcept {
                try {
                    const int indent = opt.pretty ? std::max(0, opt.indentSpaces) : -1;
                    out = j.dump(indent, ' ', opt.ensureAscii);
                    return true;
                }
                catch (...) {
                    return false;
                }
            }

            bool Minify(std::string_view jsonText, std::string& out, Error* err, const ParseOptions& opt) noexcept {
                Json j;
                if (!Parse(jsonText, j, err, opt)) return false;
                StringifyOptions so;
                so.pretty = false;
                return Stringify(j, out, so);
            }

            bool Prettify(std::string_view jsonText, std::string& out, int indentSpaces, Error* err, const ParseOptions& opt) noexcept {
                Json j;
                if (!Parse(jsonText, j, err, opt)) return false;
                StringifyOptions so;
                so.pretty = true;
                so.indentSpaces = indentSpaces;
                return Stringify(j, out, so);
            }


            bool LoadFromFile(const std::filesystem::path& path, Json& out, Error* err, const ParseOptions& opt, size_t maxBytes) noexcept {
                try {
                    std::error_code ec;
                    uintmax_t fsz = std::filesystem::file_size(path, ec); // filesystem size (uintmax_t)
                    if (ec) {
                        setIoErr(err, "Failed to get file size", path, ec.message());
                        return false;
                    }
                    if (fsz > static_cast<uintmax_t>(maxBytes)) { // first check using filesystem size
                        setIoErr(err, "File too large", path);
                        return false;
                    }

                    std::ifstream ifs(path, std::ios::in | std::ios::binary);
                    if (!ifs) {
                        setIoErr(err, "Failed to open file", path);
                        return false;
                    }

                    ifs.seekg(0, std::ios::end);
                    if (!ifs) {
                        setIoErr(err, "Failed to seek file", path);
                        return false;
                    }

                    auto tell = ifs.tellg();
                    if (tell < 0) {
                        setIoErr(err, "Failed to tell file size", path);
                        return false;
                    }
                    size_t fileSz = static_cast<size_t>(tell); // stream-derived size (size_t), used below

                    // size validation
                    constexpr size_t MAX_SAFE_JSON_SIZE = 100ULL * 1024 * 1024; // 100MB
                    size_t effectiveMax = (maxBytes > 0) ? std::min(maxBytes, MAX_SAFE_JSON_SIZE) : MAX_SAFE_JSON_SIZE;

                    if (fileSz > effectiveMax) {
                        setIoErr(err, "File too large", path,
                            "Size: " + std::to_string(fileSz) + " bytes, max: " + std::to_string(effectiveMax));
                        return false;
                    }

                    ifs.seekg(0, std::ios::beg);
                    if (!ifs) {
                        setIoErr(err, "Failed to seek to beginning of file", path);
                        return false;
                    }

                    std::string buf;
                    try {
                        buf.resize(fileSz);
                    }
                    catch (const std::bad_alloc&) {
                        setIoErr(err, "Memory allocation failed for file size", path);
                        return false;
                    }

                    if (fileSz > 0) {
                        ifs.read(buf.data(), static_cast<std::streamsize>(fileSz));

                        // VERIFY ACTUAL BYTES READ
                        auto bytesRead = ifs.gcount();
                        if (!ifs && !ifs.eof()) {
                            setIoErr(err, "Failed to read file", path);
                            return false;
                        }

                        if (static_cast<size_t>(bytesRead) != fileSz) {
                            // File size changed during read
                            setIoErr(err, "File size changed during read", path,
                                "Expected: " + std::to_string(fileSz) + ", got: " + std::to_string(bytesRead));
                            return false;
                        }

                        buf.resize(static_cast<size_t>(bytesRead));
                    }

                    stripUtf8BOM(buf);

                    // Parse
                    try {
                        out = Json::parse(buf, /*cb*/nullptr, /*allow_exceptions*/ opt.allowExceptions, /*ignore_comments*/ opt.allowComments);
                        if (!opt.allowExceptions && out.is_discarded()) {
                            setErr(err, "JSON parse failed", path, buf, 0);
                            return false;
                        }
                        return true;
                    }
                    catch (const nlohmann::json::parse_error& e) {
                        size_t byteOff = e.byte > 0 ? static_cast<size_t>(e.byte - 1) : 0;
                        setErr(err, e.what(), path, buf, byteOff);
                        return false;
                    }
                    catch (const std::exception& e) {
                        setErr(err, e.what(), path, buf, 0);
                        return false;
                    }
                }
                catch (const std::exception& e) {
                    setIoErr(err, e.what(), path);
                    return false;
                }
            }

            bool SaveToFile(const std::filesystem::path& path, const Json& j, Error* err, const SaveOptions& opt) noexcept {
                try {
                    std::string content;
                    if (!Stringify(j, content, opt)) {
                        setIoErr(err, "JSON stringify failed", path);
                        return false;
                    }
                    if (opt.writeBOM) {
                        static const unsigned char bom[3] = { 0xEF,0xBB,0xBF };
                        content.insert(content.begin(), bom, bom + 3);
                    }

                    const auto dir = path.parent_path().empty() ? std::filesystem::current_path() : path.parent_path();
                    std::error_code ec;
					std::filesystem::create_directories(dir, ec); //create if not exists
                    // temp file name
                    const auto tmp = dir / (path.filename().wstring() + L".tmp.json");

                    // write to temp file 
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

                    // Atomic change 
                    if (opt.atomicReplace) {
#ifdef _WIN32
                        //atomic and write-through change in windows
                        if (!MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                            DWORD le = GetLastError();
                            setIoErr(err, "MoveFileExW failed", path, std::to_string(static_cast<unsigned long>(le)));
                            // Temizlik dene
                            std::filesystem::remove(tmp, ec);
                            return false;
                        }
#else
                       //POSIX: 
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
						//Write directly (not atomic)
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


            bool Contains(const Json& j, std::string_view pathLike) noexcept {
                try {
                    const nlohmann::json::json_pointer jp(ToJsonPointer(pathLike));
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
					// ignore
                }
            }

            bool RequireKeys(const Json& j, std::string_view objectPathLike, const std::vector<std::string>& requiredKeys, Error* err) noexcept {
                try {
                    const auto objPtr = ToJsonPointer(objectPathLike);
                    const nlohmann::json::json_pointer jp(objPtr);
                    if (!j.contains(jp)) {
                        if (err) err->message = "Object path not found: " + objPtr;
                        return false;
                    }
                    const auto& node = j.at(jp);
                    if (!node.is_object()) {
                        if (err) err->message = "Target is not an object: " + objPtr;
                        return false;
                    }
                    for (const auto& k : requiredKeys) {
                        if (!node.contains(k)) {
                            if (err) err->message = "Missing required key: " + k;
                            return false;
                        }
                    }
                    return true;
                }
                catch (const std::exception& e) {
                    if (err) err->message = e.what();
                    return false;
                }
                catch (...) {
                    if (err) err->message = "Unknown error in RequireKeys";
                    return false;
                }
            }


		}// namespace JSON
	}// namespace Utils
}// namespace ShadowStrike