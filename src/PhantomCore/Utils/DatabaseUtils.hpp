/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#pragma once
/**
 * @file DatabaseUtils.hpp
 * @brief Header-only SQL safety helpers for ShadowStrike storage layers.
 *
 * SECURITY POSTURE
 * ----------------
 * The ShadowStrike storage layer is built on top of SQLite via the
 * ::ShadowStrike::PhantomCore::Database modules (QuarantineDB, LogDB,
 * ConfigurationDB, DatabaseManager). Those modules MUST use parameterized
 * statements (sqlite3_bind_*) for any value supplied by, or derived from,
 * untrusted input (filesystem metadata, telemetry, user supplied filters,
 * imported feed records, etc.). The helpers in this header are intended
 * ONLY for the narrow remaining cases where dynamic SQL must be assembled
 * (identifiers in DDL, LIKE patterns where the wildcard semantics must be
 * preserved, audit trail strings emitted into pre-formatted SQL scripts).
 *
 * The helpers are deliberately strict:
 *   - Embedded NUL bytes and C0 control characters (excluding TAB/CR/LF)
 *     are rejected. Embedded NULs can truncate a query in C-string based
 *     drivers and are a known SQL injection / smuggling vector.
 *   - Identifier validation rejects empty input, leading digits, oversize
 *     input, and SQL reserved words. It does NOT attempt to model every
 *     SQL dialect's reserved set; callers that need stricter checks must
 *     layer their own validation on top.
 *
 * THREAD SAFETY
 * -------------
 * All helpers are pure functions that operate on caller-owned storage;
 * they are reentrant and safe to invoke concurrently from any thread.
 *
 * Prefer parameterized queries. Treat anything in this header as the
 * last line of defense, never the first.
 */

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace ShadowStrike {
namespace Utils {
namespace DatabaseUtils {

    /// Hard upper bound on identifier length. SQLite tolerates up to ~2000
    /// chars, but no legitimate ShadowStrike schema name needs more than this.
    inline constexpr std::size_t kMaxIdentifierLength = 128;

    /// Hard upper bound on a single SQL literal we are willing to escape.
    /// Bounded to defend against pathological inputs producing multi-MiB
    /// allocations on a hot insert path.
    inline constexpr std::size_t kMaxSqlLiteralLength = 1u << 20; // 1 MiB

    namespace detail {

        [[nodiscard]] constexpr bool IsForbiddenLiteralByte(unsigned char c) noexcept {
            // Reject NUL outright; reject C0 control chars except common
            // whitespace (HT/LF/CR) which legitimately appear in payloads.
            if (c == 0u) return true;
            if (c < 0x20u && c != 0x09u && c != 0x0Au && c != 0x0Du) return true;
            if (c == 0x7Fu) return true; // DEL
            return false;
        }

        [[nodiscard]] constexpr bool IsAsciiAlpha(char c) noexcept {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        }

        [[nodiscard]] constexpr bool IsAsciiDigit(char c) noexcept {
            return c >= '0' && c <= '9';
        }

        [[nodiscard]] constexpr bool IsAsciiIdentChar(char c) noexcept {
            return IsAsciiAlpha(c) || IsAsciiDigit(c) || c == '_';
        }

        [[nodiscard]] inline char AsciiToLower(char c) noexcept {
            return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
        }

        // Conservative ANSI/SQLite reserved word set. Identifiers matching
        // any of these are rejected by IsValidIdentifier so DDL emitting
        // CREATE TABLE ${name} cannot accidentally produce a syntax error
        // or shadow a built-in.
        [[nodiscard]] inline bool IsReservedWord(std::string_view lower) noexcept {
            static constexpr std::string_view kReserved[] = {
                "abort","action","add","after","all","alter","analyze","and",
                "as","asc","attach","autoincrement","before","begin","between",
                "by","cascade","case","cast","check","collate","column","commit",
                "constraint","create","cross","database","default","deferrable",
                "deferred","delete","desc","detach","distinct","drop","each",
                "else","end","escape","except","exclusive","exists","explain",
                "fail","for","foreign","from","full","glob","group","having",
                "if","ignore","immediate","in","index","indexed","initially",
                "inner","insert","instead","intersect","into","is","isnull",
                "join","key","left","like","limit","match","natural","no","not",
                "notnull","null","of","offset","on","or","order","outer","plan",
                "pragma","primary","query","raise","recursive","references",
                "regexp","reindex","release","rename","replace","restrict",
                "right","rollback","row","savepoint","select","set","table",
                "temp","temporary","then","to","transaction","trigger","union",
                "unique","update","using","vacuum","values","view","virtual",
                "when","where","with","without","true","false","blob","integer",
                "real","text","numeric","null_","rowid","oid","_rowid_","sqlite_",
                "sqlite_master"
            };
            for (const auto& w : kReserved) {
                if (w.size() == lower.size() &&
                    std::equal(w.begin(), w.end(), lower.begin())) {
                    return true;
                }
            }
            return false;
        }

    } // namespace detail

    /**
     * @brief Validate that a string is safe to embed as a SQL string literal
     *        body (i.e. between single quotes).
     *
     * @param input Candidate string.
     * @return true  iff @p input contains no NUL byte, no forbidden C0
     *               control character, and its size is below
     *               kMaxSqlLiteralLength.
     */
    [[nodiscard]] inline bool IsSafeSqlLiteralBody(std::string_view input) noexcept {
        if (input.size() > kMaxSqlLiteralLength) return false;
        for (char c : input) {
            if (detail::IsForbiddenLiteralByte(static_cast<unsigned char>(c))) {
                return false;
            }
        }
        return true;
    }

    /**
     * @brief Escape a string for safe SQL single-quoted literal interpolation.
     *
     * Doubles every embedded apostrophe per the SQL standard. Returns
     * std::nullopt if the input contains a NUL byte, forbidden control
     * character, or exceeds kMaxSqlLiteralLength.
     *
     * Prefer parameterized queries (sqlite3_bind_text / bind_blob) over
     * this helper wherever possible.
     */
    [[nodiscard]] inline std::optional<std::string>
    TryEscapeSqlString(std::string_view input) noexcept {
        if (!IsSafeSqlLiteralBody(input)) {
            return std::nullopt;
        }
        std::string out;
        // Worst case: every byte is an apostrophe.
        try {
            out.reserve(input.size() + (input.size() >> 3) + 1u);
        } catch (...) {
            return std::nullopt;
        }
        for (char c : input) {
            if (c == '\'') {
                out.push_back('\'');
                out.push_back('\'');
            } else {
                out.push_back(c);
            }
        }
        return out;
    }

    /**
     * @brief Strict variant of TryEscapeSqlString that throws on rejection.
     *
     * Intended for code paths where rejecting the input is a programmer
     * error (i.e. the caller has already validated the source). Callers
     * that accept external input must use TryEscapeSqlString and handle
     * std::nullopt explicitly.
     *
     * @throws std::invalid_argument if the input contains a NUL byte,
     *         forbidden control character, or exceeds kMaxSqlLiteralLength.
     */
    [[nodiscard]] inline std::string EscapeSqlString(std::string_view input) {
        auto escaped = TryEscapeSqlString(input);
        if (!escaped) {
            throw std::invalid_argument(
                "DatabaseUtils::EscapeSqlString: input contains forbidden "
                "control bytes, embedded NUL, or exceeds size limit");
        }
        return std::move(*escaped);
    }

    /**
     * @brief Legacy alias for EscapeSqlString.
     *
     * Older call sites used DatabaseUtils::EscapeSql(); preserved here so
     * that no future caller can fall back to the previously-published
     * stub which silently accepted NUL bytes.
     */
    [[nodiscard]] inline std::string EscapeSql(std::string_view input) {
        return EscapeSqlString(input);
    }

    /**
     * @brief Escape a LIKE pattern body, preserving wildcard semantics.
     *
     * Doubles the chosen escape character so that any literal backslashes
     * (or alternative escape char) supplied by the caller survive the
     * conversion. The resulting pattern is intended to be embedded in a
     * statement that declares the same ESCAPE clause, e.g.
     *   "... WHERE col LIKE ? ESCAPE '\\'".
     * Wildcards ('%' and '_') are intentionally NOT escaped here; callers
     * that wish to perform a literal substring match must pre-escape them
     * (or use a parameterized exact match).
     */
    [[nodiscard]] inline std::optional<std::string>
    TryEscapeSqlLikePattern(std::string_view input, char escapeChar = '\\') noexcept {
        if (!IsSafeSqlLiteralBody(input)) {
            return std::nullopt;
        }
        if (escapeChar == '\0' || escapeChar == '\'') {
            return std::nullopt;
        }
        std::string out;
        try {
            out.reserve(input.size() + (input.size() >> 3) + 1u);
        } catch (...) {
            return std::nullopt;
        }
        for (char c : input) {
            if (c == escapeChar || c == '\'') {
                if (c == '\'') {
                    out.push_back('\'');
                    out.push_back('\'');
                } else {
                    out.push_back(escapeChar);
                    out.push_back(escapeChar);
                }
            } else {
                out.push_back(c);
            }
        }
        return out;
    }

    /**
     * @brief Throwing variant of TryEscapeSqlLikePattern.
     * @throws std::invalid_argument on rejected input.
     */
    [[nodiscard]] inline std::string
    EscapeSqlLikePattern(std::string_view input, char escapeChar = '\\') {
        auto escaped = TryEscapeSqlLikePattern(input, escapeChar);
        if (!escaped) {
            throw std::invalid_argument(
                "DatabaseUtils::EscapeSqlLikePattern: invalid pattern or "
                "escape character");
        }
        return std::move(*escaped);
    }

    /**
     * @brief Validate that a string is a safe SQL identifier.
     *
     * Rules:
     *   - 1..kMaxIdentifierLength bytes
     *   - First byte: ASCII letter or underscore
     *   - Subsequent bytes: ASCII letter, digit, or underscore
     *   - Not equal (case-insensitive) to a known SQL reserved word
     *
     * This deliberately rejects identifiers containing whitespace,
     * punctuation, double-quotes, or any non-ASCII byte. Callers that
     * absolutely must accept such identifiers should quote them through
     * QuoteIdentifier() and document the threat model.
     */
    [[nodiscard]] inline bool IsValidIdentifier(std::string_view name) noexcept {
        if (name.empty() || name.size() > kMaxIdentifierLength) return false;
        if (!(detail::IsAsciiAlpha(name.front()) || name.front() == '_')) return false;
        for (std::size_t i = 1; i < name.size(); ++i) {
            if (!detail::IsAsciiIdentChar(name[i])) return false;
        }
        std::string lower;
        lower.resize(name.size());
        for (std::size_t i = 0; i < name.size(); ++i) {
            lower[i] = detail::AsciiToLower(name[i]);
        }
        if (detail::IsReservedWord(lower)) return false;
        return true;
    }

    /**
     * @brief Stricter convenience predicate for table names.
     *
     * Alias for IsValidIdentifier kept for backward compatibility with the
     * earlier stub API. The previous implementation allowed leading digits
     * and reserved words; this version does not.
     */
    [[nodiscard]] inline bool IsValidTableName(std::string_view name) noexcept {
        return IsValidIdentifier(name);
    }

    /**
     * @brief Quote a SQL identifier using double quotes (ANSI / SQLite).
     *
     * Returns std::nullopt if the identifier fails IsValidIdentifier; the
     * resulting string is always safe to splice directly into DDL. Embedded
     * double-quote bytes cannot occur (the validator rejects them) so the
     * function performs a straight copy with surrounding quotes.
     */
    [[nodiscard]] inline std::optional<std::string>
    TryQuoteIdentifier(std::string_view name) noexcept {
        if (!IsValidIdentifier(name)) return std::nullopt;
        std::string out;
        try {
            out.reserve(name.size() + 2u);
        } catch (...) {
            return std::nullopt;
        }
        out.push_back('"');
        out.append(name.data(), name.size());
        out.push_back('"');
        return out;
    }

    /**
     * @brief Throwing variant of TryQuoteIdentifier.
     * @throws std::invalid_argument on rejected identifier.
     */
    [[nodiscard]] inline std::string QuoteIdentifier(std::string_view name) {
        auto quoted = TryQuoteIdentifier(name);
        if (!quoted) {
            throw std::invalid_argument(
                "DatabaseUtils::QuoteIdentifier: identifier failed validation");
        }
        return std::move(*quoted);
    }

} // namespace DatabaseUtils
} // namespace Utils
} // namespace ShadowStrike
