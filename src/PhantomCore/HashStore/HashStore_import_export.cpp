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
#include "pch.h"
#include "HashStore.hpp"
#include "HashStore_Record.hpp"
#include <sstream>
#include <fstream>
#include <string>
#include <algorithm>
#include <chrono>
#include "../Utils/JSONUtils.hpp"

namespace ShadowStrike {
namespace HashStore {

    // ============================================================================
    // ================= IMPORT / EXPORT OPERATIONS ===============================
    // ============================================================================

    // ---- Compile-time constants ----

    /** Batch size for streaming import - caps per-batch memory. */
    constexpr size_t IMPORT_BATCH_SIZE = 1000;

    /** Maximum import file size (100 MB) to prevent resource exhaustion. */
    constexpr size_t MAX_IMPORT_FILE_SIZE = 100ULL * 1024 * 1024;

    /** Maximum text line length. Lines exceeding this are hostile or corrupt. */
    constexpr size_t MAX_LINE_LENGTH = 4096;

    /** Maximum name/description length after sanitization. */
    constexpr size_t MAX_NAME_LENGTH = 256;

    /** Maximum JSON input size for ImportFromJson (same cap as file import). */
    constexpr size_t MAX_JSON_IMPORT_SIZE = MAX_IMPORT_FILE_SIZE;

    /** JSON nesting depth limit. Hash import schema is flat; deep nesting is never needed. */
    constexpr size_t JSON_MAX_PARSE_DEPTH = 16;

    // ---- Static helpers (file-scope, not exposed in header) ----

    /**
     * @brief Parse hash type identifier string to enum.
     * Supports all 7 HashStore types: MD5, SHA1, SHA256, SHA512, IMPHASH, FUZZY/CTPH, TLSH.
     */
    static HashType ParseHashTypeString(const std::string& typeStr, bool& valid) noexcept {
        valid = true;
        if (typeStr == "MD5")     return HashType::MD5;
        if (typeStr == "SHA1")    return HashType::SHA1;
        if (typeStr == "SHA256")  return HashType::SHA256;
        if (typeStr == "SHA512")  return HashType::SHA512;
        if (typeStr == "IMPHASH") return HashType::IMPHASH;
        if (typeStr == "FUZZY" || typeStr == "CTPH") return HashType::FUZZY;
        if (typeStr == "TLSH")    return HashType::TLSH;
        valid = false;
        return HashType::SHA256;
    }

    /**
     * @brief Parse threat level from string (named or numeric, for backward compat).
     * Named: "Critical", "High", "Medium", "Low", "Info"
     * Numeric: integer 0-100 mapped to nearest named level.
     */
    static ThreatLevel ParseThreatLevelString(const std::string& levelStr) noexcept {
        // Named levels (preferred)
        if (levelStr == "Critical") return ThreatLevel::Critical;
        if (levelStr == "High")     return ThreatLevel::High;
        if (levelStr == "Medium")   return ThreatLevel::Medium;
        if (levelStr == "Low")      return ThreatLevel::Low;
        if (levelStr == "Info")     return ThreatLevel::Info;

        // Numeric levels (backward compat with legacy exports that wrote e.g. "50")
        try {
            const unsigned long val = std::stoul(levelStr);
            if (val >= 90)  return ThreatLevel::Critical;
            if (val >= 65)  return ThreatLevel::High;
            if (val >= 35)  return ThreatLevel::Medium;
            if (val >= 10)  return ThreatLevel::Low;
            return ThreatLevel::Info;
        }
        catch (const std::exception&) {
            return ThreatLevel::Medium;
        }
    }

    /**
     * @brief Convert ThreatLevel enum to its canonical string name.
     * Used by ExportToFile so that ImportFromFile can round-trip correctly.
     */
    static const char* ThreatLevelToString(ThreatLevel level) noexcept {
        switch (level) {
            case ThreatLevel::Critical: return "Critical";
            case ThreatLevel::High:     return "High";
            case ThreatLevel::Medium:   return "Medium";
            case ThreatLevel::Low:      return "Low";
            case ThreatLevel::Info:     return "Info";
            default:                    return "Medium";
        }
    }

    /**
     * @brief Map a clamped integer (0-100) to the nearest valid ThreatLevel enum value.
     * Prevents creating invalid enum values from arbitrary numeric input.
     */
    static ThreatLevel MapIntToThreatLevel(int value) noexcept {
        if (value >= 90)  return ThreatLevel::Critical;
        if (value >= 65)  return ThreatLevel::High;
        if (value >= 35)  return ThreatLevel::Medium;
        if (value >= 10)  return ThreatLevel::Low;
        return ThreatLevel::Info;
    }

    /**
     * @brief Sanitize an imported name for safe storage and logging.
     *
     * - Strips ASCII control characters (0x00-0x1F, 0x7F)
     * - Strips '%' (defense-in-depth against format string misuse)
     * - Preserves high-byte characters (UTF-8 multibyte sequences)
     * - Caps length at MAX_NAME_LENGTH
     * - Returns "Unknown" if result is empty after filtering
     */
    static std::string SanitizeName(const std::string& input) noexcept {
        try {
            std::string result;
            const size_t limit = std::min(input.size(), MAX_NAME_LENGTH);
            result.reserve(limit);

            for (size_t i = 0; i < limit; ++i) {
                const auto c = static_cast<unsigned char>(input[i]);
                if (c >= 0x20 && c <= 0x7E && c != '%') {
                    result += static_cast<char>(c);
                } else if (c > 0x7F) {
                    result += static_cast<char>(c);
                }
                // else: drop control characters, DEL (0x7F), and '%'
            }

            return result.empty() ? std::string("Unknown") : result;
        }
        catch (const std::exception&) {
            return "Unknown";
        }
    }

    // ============================================================================
    // IMPORT FROM TEXT FILE
    // ============================================================================

    StoreError HashStore::ImportFromFile(
        const std::wstring& filePath,
        std::function<void(size_t, size_t)> progressCallback
    ) noexcept {
        /*
         * ========================================================================
         * STREAMING TEXT FILE HASH IMPORT
         * ========================================================================
         *
         * Format: TYPE:HASH:NAME:LEVEL  (one entry per line)
         * Example: SHA256:a1b2c3...:Trojan.Generic:High
         *
         * Security controls:
         *   - Path validation via ValidateAndCanonicalizePath (traversal, NUL, etc.)
         *   - File size cap (MAX_IMPORT_FILE_SIZE) checked before any reads
         *   - Per-line length cap (MAX_LINE_LENGTH) to bound heap usage
         *   - Hash type whitelist (all 7 supported types)
         *   - Name sanitization (control chars, format string chars stripped)
         *   - Exception-safe progress callback invocation
         *
         * Memory model:
         *   - Streaming line-by-line with batch flushes every IMPORT_BATCH_SIZE
         *   - Batch vectors capped and reused (capacity preserved across flushes)
         *
         * Thread safety:
         *   - No import-level lock. AddHashBatch handles its own exclusive locking.
         *   - Concurrent imports serialize at the AddHashBatch level.
         *
         * NOTE: This operation is NOT transactional. If a mid-file batch fails,
         *       previously committed batches remain in the store.
         *
         * ========================================================================
         */

        SS_LOG_INFO(L"HashStore", L"ImportFromFile: beginning import");

        // Pre-condition: database must be initialized
        if (!m_initialized.load(std::memory_order_acquire)) {
            SS_LOG_ERROR(L"HashStore", L"ImportFromFile: database not initialized");
            return StoreError{ SignatureStoreError::Unknown, 0, "Database not initialized" };
        }

        if (m_readOnly.load(std::memory_order_acquire)) {
            SS_LOG_ERROR(L"HashStore", L"ImportFromFile: database is read-only");
            return StoreError{ SignatureStoreError::AccessDenied, 0, "Database is read-only" };
        }

        // SECURITY: Validate and canonicalize path (rejects traversal, NUL bytes,
        // non-absolute paths, reserved device names, etc.)
        std::wstring canonicalPath;
        std::string pathError;
        if (!Format::ValidateAndCanonicalizePath(filePath, canonicalPath, pathError)) {
            SS_LOG_ERROR(L"HashStore", L"ImportFromFile: path validation failed: %S",
                pathError.c_str());
            return StoreError{ SignatureStoreError::InvalidFormat, 0,
                "Invalid file path: " + pathError };
        }

        try {
            // Open file (binary | ate: seek to end to measure size, then rewind)
            std::ifstream file(canonicalPath, std::ios::binary | std::ios::ate);
            if (!file.is_open()) {
                SS_LOG_ERROR(L"HashStore", L"ImportFromFile: cannot open file");
                return StoreError{ SignatureStoreError::FileNotFound, 0,
                    "Cannot open import file" };
            }

            // SECURITY: Check file size BEFORE reading any content
            const auto fileSize = file.tellg();
            if (fileSize < 0) {
                SS_LOG_ERROR(L"HashStore", L"ImportFromFile: cannot determine file size");
                return StoreError{ SignatureStoreError::Unknown, 0,
                    "Cannot determine file size" };
            }

            if (static_cast<size_t>(fileSize) > MAX_IMPORT_FILE_SIZE) {
                SS_LOG_ERROR(L"HashStore",
                    L"ImportFromFile: file too large (%lld bytes, max %zu)",
                    static_cast<long long>(fileSize), MAX_IMPORT_FILE_SIZE);
                return StoreError{ SignatureStoreError::TooLarge, 0,
                    "File exceeds 100 MB limit" };
            }

            file.seekg(0, std::ios::beg);

            // Rough line-count estimate for progress reporting (~80 bytes/line average)
            const size_t estimatedTotalLines = (fileSize > 0)
                ? static_cast<size_t>(fileSize) / 80 + 1
                : 0;

            // Batch buffers (bounded to IMPORT_BATCH_SIZE)
            std::vector<HashValue> hashes;
            std::vector<std::string> names;
            std::vector<ThreatLevel> levels;
            hashes.reserve(IMPORT_BATCH_SIZE);
            names.reserve(IMPORT_BATCH_SIZE);
            levels.reserve(IMPORT_BATCH_SIZE);

            size_t lineNum = 0;
            size_t totalImported = 0;
            size_t totalSkipped = 0;
            std::string line;
            line.reserve(512);

            while (std::getline(file, line)) {
                lineNum++;

                // Strip trailing CR from CRLF line endings (file opened in binary mode)
                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }

                // SECURITY: Reject overlong lines. Without this check, a file with no
                // newlines could cause std::getline to allocate up to MAX_IMPORT_FILE_SIZE.
                if (line.size() > MAX_LINE_LENGTH) {
                    SS_LOG_WARN(L"HashStore",
                        L"ImportFromFile: line %zu exceeds max length (%zu), skipping",
                        lineNum, line.size());
                    totalSkipped++;
                    continue;
                }

                // Skip empty lines and comment lines
                if (line.empty() || line[0] == '#') {
                    continue;
                }

                // Parse: TYPE:HASH:NAME:LEVEL
                std::istringstream iss(line);
                std::string typeStr, hashStr, name, levelStr;

                if (!std::getline(iss, typeStr, ':') ||
                    !std::getline(iss, hashStr, ':') ||
                    !std::getline(iss, name, ':') ||
                    !std::getline(iss, levelStr)) {
                    SS_LOG_WARN(L"HashStore",
                        L"ImportFromFile: malformed line %zu (expected TYPE:HASH:NAME:LEVEL)",
                        lineNum);
                    totalSkipped++;
                    continue;
                }

                // Validate hash type (all 7 types: MD5, SHA1, SHA256, SHA512, IMPHASH, FUZZY, TLSH)
                bool typeValid = false;
                HashType type = ParseHashTypeString(typeStr, typeValid);
                if (!typeValid) {
                    SS_LOG_WARN(L"HashStore",
                        L"ImportFromFile: unknown hash type '%S' at line %zu",
                        typeStr.c_str(), lineNum);
                    totalSkipped++;
                    continue;
                }

                // Parse and validate hash value (ParseHashString validates hex format,
                // length, and character set internally)
                auto hash = Format::ParseHashString(hashStr, type);
                if (!hash.has_value()) {
                    SS_LOG_WARN(L"HashStore",
                        L"ImportFromFile: invalid hash at line %zu", lineNum);
                    totalSkipped++;
                    continue;
                }

                // Parse threat level (supports both named strings and numeric values)
                ThreatLevel level = ParseThreatLevelString(levelStr);

                // Sanitize name (strip control chars, cap length)
                name = SanitizeName(name);

                // Accumulate into batch
                hashes.push_back(*hash);
                names.push_back(std::move(name));
                levels.push_back(level);

                // Flush batch at threshold
                if (hashes.size() >= IMPORT_BATCH_SIZE) {
                    StoreError err = AddHashBatch(hashes, names, levels);
                    if (err.code != SignatureStoreError::Success) {
                        SS_LOG_ERROR(L"HashStore",
                            L"ImportFromFile: batch import failed at line %zu: %S",
                            lineNum, err.message.c_str());
                        return err;
                    }
                    totalImported += hashes.size();
                    hashes.clear();
                    names.clear();
                    levels.clear();
                }

                // Progress callback (exception-safe: must not propagate through noexcept)
                if (progressCallback) {
                    try {
                        progressCallback(lineNum, estimatedTotalLines);
                    }
                    catch (const std::exception& ex) {
                        SS_LOG_WARN(L"HashStore",
                            L"ImportFromFile: progress callback threw at line %zu: %S",
                            lineNum, ex.what());
                    }
                }
            }

            // Detect I/O errors (distinct from normal EOF)
            if (file.bad()) {
                SS_LOG_ERROR(L"HashStore", L"ImportFromFile: I/O error during file read");
                return StoreError{ SignatureStoreError::Unknown, 0,
                    "I/O error reading import file" };
            }

            // Flush remaining entries in final partial batch
            if (!hashes.empty()) {
                StoreError err = AddHashBatch(hashes, names, levels);
                if (err.code != SignatureStoreError::Success) {
                    SS_LOG_ERROR(L"HashStore",
                        L"ImportFromFile: final batch import failed: %S",
                        err.message.c_str());
                    return err;
                }
                totalImported += hashes.size();
            }

            SS_LOG_INFO(L"HashStore",
                L"ImportFromFile: completed - imported %zu hashes, skipped %zu invalid entries",
                totalImported, totalSkipped);

            return StoreError{ SignatureStoreError::Success };
        }
        catch (const std::bad_alloc&) {
            SS_LOG_ERROR(L"HashStore", L"ImportFromFile: memory allocation failed");
            return StoreError{ SignatureStoreError::OutOfMemory, 0,
                "Memory allocation failed during import" };
        }
        catch (const std::exception& ex) {
            SS_LOG_ERROR(L"HashStore", L"ImportFromFile: exception: %S", ex.what());
            return StoreError{ SignatureStoreError::Unknown, 0,
                "Unexpected exception during import" };
        }
    }

    // ============================================================================
    // EXPORT TO TEXT FILE
    // ============================================================================

    StoreError HashStore::ExportToFile(
        const std::wstring& filePath,
        HashType typeFilter
    ) const noexcept {
        /*
         * ========================================================================
         * EXPORT HASHES TO TEXT FILE
         * ========================================================================
         *
         * Outputs TYPE:HASH:NAME:LEVEL format, compatible with ImportFromFile.
         *
         * NOTE (ForEach metadata limitation):
         *   ForEach only provides (fastHash, signatureOffset). Actual signature
         *   name, threat level, description, and tags are read from the mapped
         *   SignatureRecord at signatureOffset. If the record is unavailable or
         *   corrupt, placeholder values are used. See BuildDetectionResult().
         *
         * ========================================================================
         */

        SS_LOG_INFO(L"HashStore", L"ExportToFile: filter=%S",
            Format::HashTypeToString(typeFilter));

        if (!m_initialized.load(std::memory_order_acquire)) {
            SS_LOG_ERROR(L"HashStore", L"ExportToFile: database not initialized");
            return StoreError{ SignatureStoreError::Unknown, 0, "Database not initialized" };
        }

        // SECURITY: Validate and canonicalize output path
        std::wstring canonicalPath;
        std::string pathError;
        if (!Format::ValidateAndCanonicalizePath(filePath, canonicalPath, pathError)) {
            SS_LOG_ERROR(L"HashStore", L"ExportToFile: path validation failed: %S",
                pathError.c_str());
            return StoreError{ SignatureStoreError::InvalidFormat, 0,
                "Invalid file path: " + pathError };
        }

        std::shared_lock<std::shared_mutex> lock(m_globalLock);

        try {
            std::ofstream file(canonicalPath, std::ios::binary);
            if (!file.is_open()) {
                SS_LOG_ERROR(L"HashStore", L"ExportToFile: cannot create output file");
                return StoreError{ SignatureStoreError::FileNotFound, 0,
                    "Cannot create output file" };
            }

            file << "# ShadowStrike Hash Export\n";
            file << "# Format: TYPE:HASH:NAME:LEVEL\n";
            file << "# Generated: "
                 << std::chrono::system_clock::now().time_since_epoch().count() << "\n";
            file << "# Filter: " << Format::HashTypeToString(typeFilter) << "\n\n";

            if (file.fail()) {
                SS_LOG_ERROR(L"HashStore", L"ExportToFile: I/O error writing header");
                return StoreError{ SignatureStoreError::Unknown, 0,
                    "I/O error writing export header" };
            }

            size_t exportedCount = 0;
            bool writeError = false;

            LARGE_INTEGER startTime{}, endTime{};
            if (!QueryPerformanceCounter(&startTime)) {
                startTime.QuadPart = 0;
            }

            for (const auto& [bucketType, bucket] : m_buckets) {
                // HashType::All = export all types; any specific type filters to that type only.
                if (typeFilter != HashType::All && bucketType != typeFilter) {
                    continue;
                }

                if (!bucket || !bucket->m_index) {
                    continue;
                }

                bucket->m_index->ForEach(
                    [&](uint64_t fastHash, uint64_t signatureOffset) -> bool {
                        // ForEach is noexcept; lambda must not allow exceptions to propagate.
                        try {
                            const HashValue* hashPtr = Record::GetHash(m_mappedView, signatureOffset);
                            if (!hashPtr || hashPtr->length == 0 || hashPtr->length > 64) {
                                return true; // Skip corrupt entry
                            }

                            // Pull authoritative metadata from the on-disk record
                            // allocated alongside the HashValue. ReadName returns
                            // an empty string for malformed records — fall back to
                            // a deterministic synthetic identifier so the export
                            // round-trip never emits an empty NAME field.
                            std::string storedName =
                                Record::ReadName(m_mappedView, signatureOffset);
                            if (storedName.empty()) {
                                storedName = "Hash_" + std::to_string(fastHash);
                            }

                            const ThreatLevel storedLevel =
                                Record::ReadThreatLevel(m_mappedView, signatureOffset);

                            // Write TYPE:HASH:NAME:LEVEL with named threat level for round-trip
                            const char* hashTypeStr = Format::HashTypeToString(hashPtr->type);
                            std::string hashHex = Format::FormatHashString(*hashPtr);

                            file << hashTypeStr << ":"
                                 << hashHex << ":"
                                 << storedName << ":"
                                 << ThreatLevelToString(storedLevel) << "\n";

                            if (file.fail()) {
                                writeError = true;
                                return false;
                            }

                            exportedCount++;
                            return true;
                        }
                        catch (const std::exception& ex) {
                            SS_LOG_ERROR(L"HashStore",
                                L"ExportToFile: exception while exporting offset 0x%llX: %S",
                                signatureOffset, ex.what());
                            writeError = true;
                            return false;
                        }
                    });

                if (writeError) {
                    break;
                }
            }

            if (writeError) {
                SS_LOG_ERROR(L"HashStore", L"ExportToFile: I/O error during hash export");
                return StoreError{ SignatureStoreError::Unknown, 0,
                    "I/O error during hash export" };
            }

            if (!QueryPerformanceCounter(&endTime)) {
                endTime.QuadPart = startTime.QuadPart;
            }

            uint64_t exportTimeUs = 0;
            if (m_perfFrequency.QuadPart > 0 && endTime.QuadPart >= startTime.QuadPart) {
                const uint64_t elapsed = static_cast<uint64_t>(
                    endTime.QuadPart - startTime.QuadPart);
                const uint64_t freq = static_cast<uint64_t>(m_perfFrequency.QuadPart);
                if (elapsed <= UINT64_MAX / 1'000'000ULL) {
                    exportTimeUs = (elapsed * 1'000'000ULL) / freq;
                }
                else {
                    exportTimeUs = (elapsed / freq) * 1'000'000ULL;
                }
            }

            file << "\n# Total exported: " << exportedCount << " hashes\n";
            file << "# Export time: " << exportTimeUs << " microseconds\n";

            file.flush();
            if (file.fail()) {
                SS_LOG_ERROR(L"HashStore", L"ExportToFile: I/O error flushing output");
                return StoreError{ SignatureStoreError::Unknown, 0,
                    "I/O error flushing export file" };
            }

            file.close();

            SS_LOG_INFO(L"HashStore",
                L"ExportToFile: complete - %zu hashes exported in %llu us",
                exportedCount, exportTimeUs);

            return StoreError{ SignatureStoreError::Success };
        }
        catch (const std::exception& ex) {
            SS_LOG_ERROR(L"HashStore", L"ExportToFile: exception: %S", ex.what());
            return StoreError{ SignatureStoreError::Unknown, 0, "Export operation failed" };
        }
    }

    // ============================================================================
    // IMPORT FROM JSON
    // ============================================================================

    StoreError HashStore::ImportFromJson(const std::string& jsonData) noexcept {
        /*
         * ========================================================================
         * JSON HASH IMPORT
         * ========================================================================
         *
         * Expected schema:
         * {
         *   "hashes": [
         *     { "type": "SHA256", "hash": "abc...", "name": "Trojan.X",
         *       "threat_level": 75 },
         *     ...
         *   ]
         * }
         *
         * Security: input size cap, reduced JSON depth limit, per-entry validation,
         *           name sanitization, batched persistence.
         *
         * Thread safety: relies on AddHashBatch internal locking (same as ImportFromFile).
         *
         * NOTE: Not transactional. Partial batch commits persist on failure.
         *
         * ========================================================================
         */

        SS_LOG_INFO(L"HashStore", L"ImportFromJson: %zu bytes", jsonData.size());

        // Pre-condition checks
        if (!m_initialized.load(std::memory_order_acquire)) {
            SS_LOG_ERROR(L"HashStore", L"ImportFromJson: database not initialized");
            return StoreError{ SignatureStoreError::Unknown, 0, "Database not initialized" };
        }

        if (m_readOnly.load(std::memory_order_acquire)) {
            SS_LOG_ERROR(L"HashStore", L"ImportFromJson: database is read-only");
            return StoreError{ SignatureStoreError::AccessDenied, 0, "Database is read-only" };
        }

        if (jsonData.empty()) {
            SS_LOG_ERROR(L"HashStore", L"ImportFromJson: empty JSON data");
            return StoreError{ SignatureStoreError::InvalidFormat, 0,
                "JSON data cannot be empty" };
        }

        // SECURITY: Cap JSON input size to prevent resource exhaustion
        if (jsonData.size() > MAX_JSON_IMPORT_SIZE) {
            SS_LOG_ERROR(L"HashStore",
                L"ImportFromJson: JSON too large (%zu bytes, max %zu)",
                jsonData.size(), MAX_JSON_IMPORT_SIZE);
            return StoreError{ SignatureStoreError::TooLarge, 0,
                "JSON data exceeds size limit" };
        }

        try {
            using namespace ShadowStrike::Utils::JSON;

            Json jsonRoot;
            Error jsonErr;
            ParseOptions parseOpts;
            parseOpts.allowComments = true;
            parseOpts.allowExceptions = false;
            parseOpts.maxDepth = JSON_MAX_PARSE_DEPTH;

            if (!Parse(jsonData, jsonRoot, &jsonErr, parseOpts)) {
                SS_LOG_ERROR(L"HashStore",
                    L"ImportFromJson: parse error at line %zu, col %zu: %S",
                    jsonErr.line, jsonErr.column, jsonErr.message.c_str());
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "JSON parse error" };
            }

            if (!jsonRoot.is_object()) {
                SS_LOG_ERROR(L"HashStore", L"ImportFromJson: root must be a JSON object");
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "Root must be JSON object" };
            }

            if (!jsonRoot.contains("hashes")) {
                SS_LOG_ERROR(L"HashStore", L"ImportFromJson: missing 'hashes' array");
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "Missing 'hashes' field" };
            }

            const Json& hashesArray = jsonRoot["hashes"];
            if (!hashesArray.is_array()) {
                SS_LOG_ERROR(L"HashStore", L"ImportFromJson: 'hashes' must be an array");
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "'hashes' must be array" };
            }

            const size_t totalEntries = hashesArray.size();

            LARGE_INTEGER startTime{}, endTime{};
            if (!QueryPerformanceCounter(&startTime)) {
                startTime.QuadPart = 0;
            }

            // Batch buffers (capped reserve to prevent huge upfront allocation)
            std::vector<HashValue> hashes;
            std::vector<std::string> names;
            std::vector<ThreatLevel> levels;
            const size_t reserveSize = std::min(totalEntries, IMPORT_BATCH_SIZE);
            hashes.reserve(reserveSize);
            names.reserve(reserveSize);
            levels.reserve(reserveSize);

            size_t validCount = 0;
            size_t invalidCount = 0;
            size_t totalImported = 0;

            for (size_t i = 0; i < totalEntries; ++i) {
                const Json& entry = hashesArray[i];

                try {
                    if (!entry.is_object()) {
                        SS_LOG_WARN(L"HashStore",
                            L"ImportFromJson: entry %zu is not an object", i);
                        invalidCount++;
                        continue;
                    }

                    std::string typeStr;
                    if (!Get<std::string>(entry, "type", typeStr)) {
                        SS_LOG_WARN(L"HashStore",
                            L"ImportFromJson: entry %zu missing 'type'", i);
                        invalidCount++;
                        continue;
                    }

                    std::string hashStr;
                    if (!Get<std::string>(entry, "hash", hashStr)) {
                        SS_LOG_WARN(L"HashStore",
                            L"ImportFromJson: entry %zu missing 'hash'", i);
                        invalidCount++;
                        continue;
                    }

                    std::string name;
                    if (!Get<std::string>(entry, "name", name)) {
                        name = "Imported_" + std::to_string(i);
                    }
                    name = SanitizeName(name);

                    // Parse threat_level (supports both int and string for flexibility)
                    int threatLevelInt = static_cast<int>(ThreatLevel::Medium);
                    if (!Get<int>(entry, "threat_level", threatLevelInt)) {
                        std::string levelStr;
                        if (Get<std::string>(entry, "threat_level", levelStr)) {
                            threatLevelInt = static_cast<int>(
                                ParseThreatLevelString(levelStr));
                        }
                    }
                    threatLevelInt = std::clamp(threatLevelInt, 0, 100);

                    // Validate hash type (all 7 types)
                    bool typeValid = false;
                    HashType hashType = ParseHashTypeString(typeStr, typeValid);
                    if (!typeValid) {
                        SS_LOG_WARN(L"HashStore",
                            L"ImportFromJson: unknown type at entry %zu: %S",
                            i, typeStr.c_str());
                        invalidCount++;
                        continue;
                    }

                    // Parse and validate hash value
                    auto parsedHash = Format::ParseHashString(hashStr, hashType);
                    if (!parsedHash.has_value()) {
                        SS_LOG_WARN(L"HashStore",
                            L"ImportFromJson: invalid hash at entry %zu", i);
                        invalidCount++;
                        continue;
                    }

                    hashes.push_back(*parsedHash);
                    names.push_back(std::move(name));
                    levels.push_back(MapIntToThreatLevel(threatLevelInt));
                    validCount++;

                    // Batch flush to prevent memory exhaustion on large JSON inputs
                    if (hashes.size() >= IMPORT_BATCH_SIZE) {
                        StoreError err = AddHashBatch(hashes, names, levels);
                        if (err.code != SignatureStoreError::Success) {
                            SS_LOG_ERROR(L"HashStore",
                                L"ImportFromJson: batch insert failed at entry %zu: %S",
                                i, err.message.c_str());
                            return err;
                        }
                        totalImported += hashes.size();
                        hashes.clear();
                        names.clear();
                        levels.clear();
                    }
                }
                catch (const std::exception& ex) {
                    SS_LOG_WARN(L"HashStore",
                        L"ImportFromJson: exception at entry %zu: %S", i, ex.what());
                    invalidCount++;
                    continue;
                }
            }

            // Flush remaining entries
            if (!hashes.empty()) {
                StoreError err = AddHashBatch(hashes, names, levels);
                if (err.code != SignatureStoreError::Success) {
                    SS_LOG_ERROR(L"HashStore",
                        L"ImportFromJson: final batch insert failed: %S",
                        err.message.c_str());
                    return err;
                }
                totalImported += hashes.size();
            }

            if (!QueryPerformanceCounter(&endTime)) {
                endTime.QuadPart = startTime.QuadPart;
            }

            uint64_t parseTimeUs = 0;
            if (m_perfFrequency.QuadPart > 0 && endTime.QuadPart >= startTime.QuadPart) {
                const uint64_t elapsed = static_cast<uint64_t>(
                    endTime.QuadPart - startTime.QuadPart);
                const uint64_t freq = static_cast<uint64_t>(m_perfFrequency.QuadPart);
                if (elapsed <= UINT64_MAX / 1'000'000ULL) {
                    parseTimeUs = (elapsed * 1'000'000ULL) / freq;
                }
                else {
                    parseTimeUs = (elapsed / freq) * 1'000'000ULL;
                }
            }

            if (totalImported == 0 && validCount == 0) {
                SS_LOG_ERROR(L"HashStore",
                    L"ImportFromJson: no valid hashes found (invalid: %zu)",
                    invalidCount);
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "No valid hashes in JSON" };
            }

            SS_LOG_INFO(L"HashStore",
                L"ImportFromJson: completed - imported %zu hashes "
                L"(invalid: %zu, time: %llu us)",
                totalImported, invalidCount, parseTimeUs);

            return StoreError{ SignatureStoreError::Success };
        }
        catch (const std::bad_alloc&) {
            SS_LOG_ERROR(L"HashStore", L"ImportFromJson: memory allocation failed");
            return StoreError{ SignatureStoreError::OutOfMemory, 0,
                "Memory allocation failed during JSON import" };
        }
        catch (const std::exception& ex) {
            SS_LOG_ERROR(L"HashStore", L"ImportFromJson: exception: %S", ex.what());
            return StoreError{ SignatureStoreError::Unknown, 0,
                "Unexpected exception during JSON import" };
        }
    }

    // ============================================================================
    // EXPORT TO JSON
    // ============================================================================

    std::string HashStore::ExportToJson(
        HashType typeFilter,
        uint32_t maxEntries
    ) const noexcept {
        /*
         * ========================================================================
         * JSON HASH EXPORT
         * ========================================================================
         *
         * The v2 on-disk record stores HashValue plus authoritative metadata at
         * each signature offset, allowing JSON exports to preserve name,
         * description, and threat level without placeholder synthesis except for
         * corrupt legacy entries.
         *
         * Security:
         *   - Internal offsets (signatureOffset, fastHash) are NOT exported.
         *   - Memory bounded by maxEntries.
         *
         * Thread safety:
         *   - Shared lock held during iteration, released before GetStatistics()
         *     to avoid UB from recursive shared_mutex acquisition.
         *
         * ========================================================================
         */

        SS_LOG_DEBUG(L"HashStore", L"ExportToJson: filter=%S, max=%u",
            Format::HashTypeToString(typeFilter), maxEntries);

        if (!m_initialized.load(std::memory_order_acquire)) {
            SS_LOG_ERROR(L"HashStore", L"ExportToJson: database not initialized");
            return "{}";
        }

        try {
            using namespace ShadowStrike::Utils::JSON;

            Json exportRoot;
            exportRoot["version"] = "1.0";
            exportRoot["format"] = "ShadowStrike Hash Export";
            exportRoot["timestamp"] =
                std::chrono::system_clock::now().time_since_epoch().count();
            exportRoot["filter"] = Format::HashTypeToString(typeFilter);

            Json hashesArray = Json::array();

            LARGE_INTEGER startTime{}, endTime{};
            if (!QueryPerformanceCounter(&startTime)) {
                startTime.QuadPart = 0;
            }

            size_t exportCount = 0;

            // Scoped shared lock for iteration over memory-mapped data
            {
                std::shared_lock<std::shared_mutex> lock(m_globalLock);

                const uint8_t* dataBase =
                    static_cast<const uint8_t*>(m_mappedView.baseAddress);

                if (dataBase == nullptr) {
                    SS_LOG_ERROR(L"HashStore",
                        L"ExportToJson: memory-mapped base address is null");
                    return "{}";
                }

                for (const auto& [bucketType, bucket] : m_buckets) {
                    // HashType::All = export all types; any specific type filters to that type only.
                    if (typeFilter != HashType::All && bucketType != typeFilter) {
                        continue;
                    }

                    if (!bucket || !bucket->m_index) {
                        continue;
                    }

                    bucket->m_index->ForEach(
                        [&](uint64_t fastHash, uint64_t signatureOffset) -> bool {
                            // Lambda must not throw through noexcept ForEach.
                            try {
                                if (exportCount >= maxEntries) {
                                    return false;
                                }

                                const HashValue* hashPtr = Record::GetHash(m_mappedView, signatureOffset);
                                if (!hashPtr || hashPtr->length == 0 || hashPtr->length > 64) {
                                    return true;
                                }

                                // Authoritative name / threat level / description
                                // pulled from the on-disk record. Empty fields fall
                                // back to safe synthetic values so JSON consumers
                                // never see missing keys.
                                std::string storedName =
                                    Record::ReadName(m_mappedView, signatureOffset);
                                if (storedName.empty()) {
                                    storedName = "Hash_" + std::to_string(fastHash);
                                }
                                const ThreatLevel storedLevel =
                                    Record::ReadThreatLevel(m_mappedView, signatureOffset);
                                const std::string storedDesc =
                                    Record::ReadDescription(m_mappedView, signatureOffset);

                                Json entry;
                                entry["type"] =
                                    Format::HashTypeToString(hashPtr->type);
                                entry["hash"] =
                                    Format::FormatHashString(*hashPtr);
                                entry["name"] = std::move(storedName);
                                entry["threat_level"] =
                                    static_cast<int>(storedLevel);
                                entry["length_bytes"] = hashPtr->length;
                                if (!storedDesc.empty()) {
                                    entry["description"] = storedDesc;
                                }

                                hashesArray.push_back(std::move(entry));
                                exportCount++;
                                return true;
                            }
                            catch (const std::exception& ex) {
                                SS_LOG_ERROR(L"HashStore",
                                    L"ExportToJson: exception while exporting offset 0x%llX: %S",
                                    signatureOffset, ex.what());
                                return false;
                            }
                        });

                    if (exportCount >= maxEntries) {
                        break;
                    }
                }
            } // shared lock released here

            if (!QueryPerformanceCounter(&endTime)) {
                endTime.QuadPart = startTime.QuadPart;
            }

            uint64_t exportTimeUs = 0;
            if (m_perfFrequency.QuadPart > 0 && endTime.QuadPart >= startTime.QuadPart) {
                const uint64_t elapsed = static_cast<uint64_t>(
                    endTime.QuadPart - startTime.QuadPart);
                const uint64_t freq = static_cast<uint64_t>(m_perfFrequency.QuadPart);
                if (elapsed <= UINT64_MAX / 1'000'000ULL) {
                    exportTimeUs = (elapsed * 1'000'000ULL) / freq;
                }
                else {
                    exportTimeUs = (elapsed / freq) * 1'000'000ULL;
                }
            }

            exportRoot["hashes"] = std::move(hashesArray);
            exportRoot["count"] = exportCount;
            exportRoot["export_time_microseconds"] = exportTimeUs;

            // GetStatistics() safely called AFTER releasing m_globalLock to avoid
            // undefined behavior from recursive shared_mutex acquisition.
            auto storeStats = GetStatistics();
            Json stats;
            stats["total_hashes"] = storeStats.totalHashes;
            stats["total_lookups"] = storeStats.totalLookups;
            stats["cache_hit_rate"] = storeStats.cacheHitRate;
            stats["database_size_bytes"] = storeStats.databaseSizeBytes;
            exportRoot["statistics"] = std::move(stats);

            std::string result;
            StringifyOptions stringOpts;
            stringOpts.pretty = true;
            stringOpts.indentSpaces = 2;

            if (!Stringify(exportRoot, result, stringOpts)) {
                SS_LOG_ERROR(L"HashStore", L"ExportToJson: failed to stringify JSON");
                return "{}";
            }

            SS_LOG_DEBUG(L"HashStore",
                L"ExportToJson: exported %zu hashes in %llu us, JSON size: %zu bytes",
                exportCount, exportTimeUs, result.size());

            return result;
        }
        catch (const std::bad_alloc&) {
            SS_LOG_ERROR(L"HashStore", L"ExportToJson: memory allocation failed");
            return "{}";
        }
        catch (const std::exception& ex) {
            SS_LOG_ERROR(L"HashStore", L"ExportToJson: exception: %S", ex.what());
            return "{}";
        }
    }

} // namespace HashStore
} // namespace ShadowStrike
