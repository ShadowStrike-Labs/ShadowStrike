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
#include"pch.h"
#include"HashStore.hpp"
#include <sstream>
#include <fstream>
#include<string>
#include "../Utils/JSONUtils.hpp"



namespace ShadowStrike {
	namespace SignatureStore {

        // ============================================================================
        // ================= IMPORT / EXPORT OPERATIONS ===============================
        // ============================================================================

        /**
         * @brief Batch size for streaming file import to prevent memory exhaustion.
         * 
         * @details This constant limits memory usage during import operations.
         * Processing in batches of 1000 hashes ensures:
         * - Constant memory footprint regardless of input file size
         * - Good balance between memory usage and I/O efficiency
         * - Prevention of DoS attacks via large file uploads
         */
        constexpr size_t IMPORT_BATCH_SIZE = 1000;

        /**
         * @brief Maximum allowed file size for import operations (100 MB).
         * 
         * @details Prevents processing of excessively large files that could
         * cause resource exhaustion or take too long to process.
         */
        constexpr size_t MAX_IMPORT_FILE_SIZE = 100ULL * 1024 * 1024;

        //imports hashes from the given file path to the hash store
        StoreError HashStore::ImportFromFile(
            const std::wstring& filePath,
            std::function<void(size_t, size_t)> progressCallback
        ) noexcept {
            /*
             * ========================================================================
             * IMPORT FROM FILE - STREAMING TEXT FILE HASH IMPORT
             * ========================================================================
             *
             * Format: TYPE:HASH:NAME:LEVEL
             * Example: SHA256:a1b2c3...:Trojan.Generic:High
             *
             * Security Features:
             * - Streaming line-by-line processing (prevents memory exhaustion DoS)
             * - Batch accumulation with bounded size
             * - File size validation
             * - Progress tracking for large files
             *
             * ========================================================================
             */

            SS_LOG_INFO(L"HashStore", L"ImportFromFile: %s", filePath.c_str());

            if (m_readOnly.load(std::memory_order_acquire)) {
                return StoreError{ SignatureStoreError::AccessDenied, 0, "Read-only mode" };
            }

            // Open file
            std::ifstream file(filePath, std::ios::binary | std::ios::ate);
            if (!file.is_open()) {
                SS_LOG_ERROR(L"HashStore", L"ImportFromFile: Cannot open file");
                return StoreError{ SignatureStoreError::FileNotFound, 0, "Cannot open file" };
            }

            // Security: Check file size to prevent resource exhaustion
            const auto fileSize = file.tellg();
            if (fileSize < 0) {
                SS_LOG_ERROR(L"HashStore", L"ImportFromFile: Cannot determine file size");
                return StoreError{ SignatureStoreError::Unknown, 0, "Cannot determine file size" };
            }
            
            if (static_cast<size_t>(fileSize) > MAX_IMPORT_FILE_SIZE) {
                SS_LOG_ERROR(L"HashStore", L"ImportFromFile: File too large (%lld bytes, max %zu)",
                    static_cast<long long>(fileSize), MAX_IMPORT_FILE_SIZE);
                return StoreError{ SignatureStoreError::TooLarge, 0, 
                    "File exceeds maximum allowed size (100 MB)" };
            }
            
            // Reset to beginning for line-by-line reading
            file.seekg(0, std::ios::beg);

            // Estimate total lines for progress reporting (rough estimate: ~80 bytes per line)
            const size_t estimatedTotalLines = (fileSize > 0) 
                ? static_cast<size_t>(fileSize) / 80 + 1 
                : 0;

            // Batch buffers - bounded size to prevent memory exhaustion
            std::vector<HashValue> hashes;
            std::vector<std::string> names;
            std::vector<ThreatLevel> levels;
            
            // Pre-allocate batch buffers
            hashes.reserve(IMPORT_BATCH_SIZE);
            names.reserve(IMPORT_BATCH_SIZE);
            levels.reserve(IMPORT_BATCH_SIZE);

            size_t lineNum = 0;
            size_t totalImported = 0;
            size_t totalSkipped = 0;
            std::string line;

            // Stream file line-by-line to prevent memory exhaustion
            while (std::getline(file, line)) {
                lineNum++;

                // Skip empty lines and comments
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
                    SS_LOG_WARN(L"HashStore", L"ImportFromFile: Invalid format at line %zu", lineNum);
                    totalSkipped++;
                    continue;
                }

                // Parse hash type
                HashType type = HashType::SHA256;  // Default
                if (typeStr == "MD5") type = HashType::MD5;
                else if (typeStr == "SHA1") type = HashType::SHA1;
                else if (typeStr == "SHA256") type = HashType::SHA256;
                else if (typeStr == "SHA512") type = HashType::SHA512;

                // Parse hash value
                auto hash = Format::ParseHashString(hashStr, type);
                if (!hash.has_value()) {
                    SS_LOG_WARN(L"HashStore", L"ImportFromFile: Invalid hash at line %zu", lineNum);
                    totalSkipped++;
                    continue;
                }

                // Parse threat level
                ThreatLevel level = ThreatLevel::Medium;
                if (levelStr == "Critical") level = ThreatLevel::Critical;
                else if (levelStr == "High") level = ThreatLevel::High;
                else if (levelStr == "Low") level = ThreatLevel::Low;

                // Add to current batch
                hashes.push_back(*hash);
                names.push_back(std::move(name));
                levels.push_back(level);

                // Process batch when full to maintain bounded memory usage
                if (hashes.size() >= IMPORT_BATCH_SIZE) {
                    StoreError err = AddHashBatch(hashes, names, levels);
                    if (err.code != SignatureStoreError::Success) {
                        SS_LOG_ERROR(L"HashStore", 
                            L"ImportFromFile: Batch import failed at line %zu: %S",
                            lineNum, err.message.c_str());
                        return err;
                    }
                    
                    totalImported += hashes.size();
                    
                    // Clear buffers for next batch (capacity preserved)
                    hashes.clear();
                    names.clear();
                    levels.clear();
                }

                // Progress callback
                if (progressCallback) {
                    progressCallback(lineNum, estimatedTotalLines);
                }
            }

            file.close();

            // Process remaining entries in final batch
            if (!hashes.empty()) {
                StoreError err = AddHashBatch(hashes, names, levels);
                if (err.code != SignatureStoreError::Success) {
                    SS_LOG_ERROR(L"HashStore", L"ImportFromFile: Final batch import failed: %S",
                        err.message.c_str());
                    return err;
                }
                totalImported += hashes.size();
            }

            SS_LOG_INFO(L"HashStore", 
                L"ImportFromFile: Completed - imported %zu hashes, skipped %zu invalid entries",
                totalImported, totalSkipped);
            
            return StoreError{ SignatureStoreError::Success };
        }


        //exports hashes from database to a file. Supports filtering by hash type.
        StoreError HashStore::ExportToFile(
            const std::wstring& filePath,
            HashType typeFilter
        ) const noexcept {
            SS_LOG_INFO(L"HashStore", L"ExportToFile: %s (filter=%S)",
                filePath.c_str(), Format::HashTypeToString(typeFilter));

            if (!m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_ERROR(L"HashStore", L"ExportToFile: Database not initialized");
                return StoreError{ SignatureStoreError::Unknown, 0, "Database not initialized" };
            }

            if (filePath.empty()) {
                SS_LOG_ERROR(L"HashStore", L"ExportToFile: Empty file path");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "File path cannot be empty" };
            }

            std::shared_lock<std::shared_mutex> lock(m_globalLock);

            std::ofstream file(filePath);
            if (!file.is_open()) {
                SS_LOG_ERROR(L"HashStore", L"ExportToFile: Cannot create file: %s", filePath.c_str());
                return StoreError{ SignatureStoreError::FileNotFound, 0, "Cannot create output file" };
            }

            try {
                file << "# ShadowStrike Hash Export\n";
                file << "# Format: TYPE:HASH:NAME:LEVEL\n";
                file << "# Generated: " << std::chrono::system_clock::now().time_since_epoch().count() << "\n";
                file << "# Filter: " << Format::HashTypeToString(typeFilter) << "\n\n";

                size_t exportedCount = 0;
                LARGE_INTEGER startTime{}, endTime{};
                if (!QueryPerformanceCounter(&startTime)) {
                    startTime.QuadPart = 0;
                }

                for (const auto& [bucketType, bucket] : m_buckets) {
                    if (typeFilter != HashType::MD5 && bucketType != typeFilter) {
                        continue;
                    }

                    bucket->m_index->ForEach(
                        [&](uint64_t fastHash, uint64_t signatureOffset) -> bool {
                            const uint8_t* dataBase =
                                static_cast<const uint8_t*>(m_mappedView.baseAddress);

                            // Null pointer check
                            if (dataBase == nullptr) {
                                return true; // Continue to next
                            }

                            if (signatureOffset >= m_mappedView.fileSize) {
                                return true;
                            }

                            // Bounds check before dereferencing
                            if (signatureOffset > m_mappedView.fileSize - sizeof(HashValue)) {
                                return true;
                            }

                            const HashValue* hashPtr =
                                reinterpret_cast<const HashValue*>(dataBase + signatureOffset);

                            if (hashPtr->length == 0 || hashPtr->length > 64) {
                                return true;
                            }

                            std::string hashTypeStr = Format::HashTypeToString(hashPtr->type);
                            std::string hashHex = Format::FormatHashString(*hashPtr);
                            std::string threatLevelStr = std::to_string(
                                static_cast<uint8_t>(ThreatLevel::Medium));

                            file << hashTypeStr << ":" << hashHex << ":Hash_" << fastHash
                                << ":" << threatLevelStr << "\n";

                            exportedCount++;
                            return true;
                        });
                }

                if (!QueryPerformanceCounter(&endTime)) {
                    endTime.QuadPart = startTime.QuadPart;
                }

                uint64_t exportTimeUs = 0;
                if (m_perfFrequency.QuadPart > 0 && endTime.QuadPart >= startTime.QuadPart) {
                    const uint64_t elapsed = static_cast<uint64_t>(endTime.QuadPart - startTime.QuadPart);
                    const uint64_t freq = static_cast<uint64_t>(m_perfFrequency.QuadPart);
                    if (elapsed <= UINT64_MAX / 1000000ULL) {
                        exportTimeUs = (elapsed * 1000000ULL) / freq;
                    }
                    else {
                        exportTimeUs = (elapsed / freq) * 1000000ULL;
                    }
                }

                file << "\n# Total exported: " << exportedCount << " hashes\n";
                file << "# Export time: " << exportTimeUs << " microseconds\n";

                file.close();

                SS_LOG_INFO(L"HashStore",
                    L"ExportToFile: Complete - %zu hashes exported in %llu �s",
                    exportedCount, exportTimeUs);

                return StoreError{ SignatureStoreError::Success };
            }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(L"HashStore", L"ExportToFile: Exception: %S", ex.what());
                file.close();
                return StoreError{ SignatureStoreError::Unknown, 0, "Export operation failed" };
            }
        }

        //imports hashes from a JSON string to the hash store
        StoreError HashStore::ImportFromJson(const std::string& jsonData) noexcept {
            SS_LOG_INFO(L"HashStore", L"ImportFromJson: %zu bytes", jsonData.size());

            if (m_readOnly.load(std::memory_order_acquire)) {
                SS_LOG_ERROR(L"HashStore", L"ImportFromJson: Database is read-only");
                return StoreError{ SignatureStoreError::AccessDenied, 0, "Database is read-only" };
            }

            if (jsonData.empty()) {
                SS_LOG_ERROR(L"HashStore", L"ImportFromJson: Empty JSON data");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "JSON data cannot be empty" };
            }

            using namespace ShadowStrike::Utils::JSON;

            Json jsonRoot;
            Error jsonErr;
            ParseOptions parseOpts;
            parseOpts.allowComments = true;
            parseOpts.maxDepth = 1000;

            if (!Parse(jsonData, jsonRoot, &jsonErr, parseOpts)) {
                SS_LOG_ERROR(L"HashStore",
                    L"ImportFromJson: Parse error at line %zu, column %zu: %S",
                    jsonErr.line, jsonErr.column, jsonErr.message.c_str());
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "JSON parse error" };
            }

            if (!jsonRoot.is_object()) {
                SS_LOG_ERROR(L"HashStore", L"ImportFromJson: Root must be a JSON object");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Root must be JSON object" };
            }

            if (!jsonRoot.contains("hashes")) {
                SS_LOG_ERROR(L"HashStore", L"ImportFromJson: Missing 'hashes' array");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Missing 'hashes' field" };
            }

            const Json& hashesArray = jsonRoot["hashes"];
            if (!hashesArray.is_array()) {
                SS_LOG_ERROR(L"HashStore", L"ImportFromJson: 'hashes' must be an array");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "'hashes' must be array" };
            }

            std::vector<HashValue> hashes;
            std::vector<std::string> names;
            std::vector<ThreatLevel> levels;

            LARGE_INTEGER startTime{}, endTime{};
            if (!QueryPerformanceCounter(&startTime)) {
                startTime.QuadPart = 0;
            }

            size_t validCount = 0;
            size_t invalidCount = 0;

            // Pre-allocate vectors to reduce reallocations
            const size_t expectedSize = hashesArray.size();
            try {
                hashes.reserve(expectedSize);
                names.reserve(expectedSize);
                levels.reserve(expectedSize);
            }
            catch (const std::bad_alloc&) {
                SS_LOG_ERROR(L"HashStore", L"ImportFromJson: Memory allocation failed");
                return StoreError{ SignatureStoreError::Unknown, 0, "Memory allocation failed" };
            }

            for (size_t i = 0; i < hashesArray.size(); ++i) {
                const Json& entry = hashesArray[i];

                try {
                    if (!entry.is_object()) {
                        SS_LOG_WARN(L"HashStore",
                            L"ImportFromJson: Entry %zu is not an object", i);
                        invalidCount++;
                        continue;
                    }

                    std::string typeStr;
                    if (!Get<std::string>(entry, "type", typeStr)) {
                        SS_LOG_WARN(L"HashStore", L"ImportFromJson: Entry %zu missing 'type'", i);
                        invalidCount++;
                        continue;
                    }

                    std::string hashStr;
                    if (!Get<std::string>(entry, "hash", hashStr)) {
                        SS_LOG_WARN(L"HashStore", L"ImportFromJson: Entry %zu missing 'hash'", i);
                        invalidCount++;
                        continue;
                    }

                    std::string name;
                    if (!Get<std::string>(entry, "name", name)) {
                        name = "Imported_" + std::to_string(i);
                    }

                    int threatLevelInt = 50;
                    if (Get<int>(entry, "threat_level", threatLevelInt) == true) {
                        threatLevelInt = std::clamp(threatLevelInt, 0, 100);
                    }
                    HashType hashType = HashType::SHA256;
                    if (typeStr == "MD5") hashType = HashType::MD5;
                    else if (typeStr == "SHA1") hashType = HashType::SHA1;
                    else if (typeStr == "SHA256") hashType = HashType::SHA256;
                    else if (typeStr == "SHA512") hashType = HashType::SHA512;
                    else {
                        SS_LOG_WARN(L"HashStore",
                            L"ImportFromJson: Unknown hash type at entry %zu: %S",
                            i, typeStr.c_str());
                        invalidCount++;
                        continue;
                    }

                    auto parsedHash = Format::ParseHashString(hashStr, hashType);
                    if (!parsedHash.has_value()) {
                        SS_LOG_WARN(L"HashStore",
                            L"ImportFromJson: Invalid hash value at entry %zu",
                            i);
                        invalidCount++;
                        continue;
                    }

                    hashes.push_back(*parsedHash);
                    names.push_back(std::move(name));
                    levels.push_back(static_cast<ThreatLevel>(threatLevelInt));
                    validCount++;
                }
                catch (const std::exception& ex) {
                    SS_LOG_WARN(L"HashStore",
                        L"ImportFromJson: Exception at entry %zu: %S",
                        i, ex.what());
                    invalidCount++;
                    continue;
                }
            }

            if (!QueryPerformanceCounter(&endTime)) {
                endTime.QuadPart = startTime.QuadPart;
            }

            uint64_t parseTimeUs = 0;
            if (m_perfFrequency.QuadPart > 0 && endTime.QuadPart >= startTime.QuadPart) {
                const uint64_t elapsed = static_cast<uint64_t>(endTime.QuadPart - startTime.QuadPart);
                const uint64_t freq = static_cast<uint64_t>(m_perfFrequency.QuadPart);
                if (elapsed <= UINT64_MAX / 1000000ULL) {
                    parseTimeUs = (elapsed * 1000000ULL) / freq;
                }
                else {
                    parseTimeUs = (elapsed / freq) * 1000000ULL;
                }
            }

            if (validCount == 0) {
                SS_LOG_ERROR(L"HashStore",
                    L"ImportFromJson: No valid hashes found (invalid: %zu)",
                    invalidCount);
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "No valid hashes in JSON" };
            }

            SS_LOG_INFO(L"HashStore",
                L"ImportFromJson: Parsed %zu valid hashes (invalid: %zu, parse time: %llu �s)",
                validCount, invalidCount, parseTimeUs);

            StoreError batchErr = AddHashBatch(hashes, names, levels);

            if (!batchErr.IsSuccess()) {
                SS_LOG_ERROR(L"HashStore",
                    L"ImportFromJson: Batch insert failed: %S",
                    batchErr.message.c_str());
                return batchErr;
            }

            SS_LOG_INFO(L"HashStore",
                L"ImportFromJson: Successfully imported %zu hashes",
                validCount);

            return StoreError{ SignatureStoreError::Success };
        }

        //exports hashes from the hash store to a JSON string. Supports filtering by hash type and limiting entries.
        std::string HashStore::ExportToJson(
            HashType typeFilter,
            uint32_t maxEntries
        ) const noexcept {
            SS_LOG_DEBUG(L"HashStore", L"ExportToJson: filter=%S, max=%u",
                Format::HashTypeToString(typeFilter), maxEntries);

            if (!m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_ERROR(L"HashStore", L"ExportToJson: Database not initialized");
                return "{}";
            }

            using namespace ShadowStrike::Utils::JSON;

            std::shared_lock<std::shared_mutex> lock(m_globalLock);

            Json exportRoot;
            exportRoot["version"] = "1.0";
            exportRoot["format"] = "ShadowStrike Hash Export";
            exportRoot["timestamp"] = std::chrono::system_clock::now().time_since_epoch().count();
            exportRoot["filter"] = Format::HashTypeToString(typeFilter);

            Json hashesArray = Json::array();

            LARGE_INTEGER startTime{}, endTime{};
            if (!QueryPerformanceCounter(&startTime)) {
                startTime.QuadPart = 0;
            }

            size_t exportCount = 0;
            const uint8_t* dataBase = static_cast<const uint8_t*>(m_mappedView.baseAddress);

            // Early exit if base address is null
            if (dataBase == nullptr) {
                SS_LOG_ERROR(L"HashStore", L"ExportToJson: Memory-mapped base address is null");
                return "{}";
            }

            for (const auto& [bucketType, bucket] : m_buckets) {
                if (typeFilter != HashType::MD5 && bucketType != typeFilter) {
                    continue;
                }

                bucket->m_index->ForEach(
                    [&](uint64_t fastHash, uint64_t signatureOffset) -> bool {
                        if (exportCount >= maxEntries) {
                            return false;
                        }

                        if (signatureOffset >= m_mappedView.fileSize) {
                            return true;
                        }

                        // Bounds check before dereferencing
                        if (signatureOffset > m_mappedView.fileSize - sizeof(HashValue)) {
                            return true;
                        }

                        const HashValue* hashPtr =
                            reinterpret_cast<const HashValue*>(dataBase + signatureOffset);

                        if (hashPtr->length == 0 || hashPtr->length > 64) {
                            return true;
                        }

                        Json entry;
                        entry["type"] = Format::HashTypeToString(hashPtr->type);
                        entry["hash"] = Format::FormatHashString(*hashPtr);
                        entry["name"] = "Hash_" + std::to_string(fastHash);
                        entry["threat_level"] = 50;
                        entry["fast_hash"] = fastHash;
                        entry["signature_offset"] = signatureOffset;
                        entry["length_bytes"] = hashPtr->length;

                        hashesArray.push_back(entry);
                        exportCount++;

                        return true;
                    });

                if (exportCount >= maxEntries) {
                    break;
                }
            }

            if (!QueryPerformanceCounter(&endTime)) {
                endTime.QuadPart = startTime.QuadPart;
            }

            uint64_t exportTimeUs = 0;
            if (m_perfFrequency.QuadPart > 0 && endTime.QuadPart >= startTime.QuadPart) {
                const uint64_t elapsed = static_cast<uint64_t>(endTime.QuadPart - startTime.QuadPart);
                const uint64_t freq = static_cast<uint64_t>(m_perfFrequency.QuadPart);
                if (elapsed <= UINT64_MAX / 1000000ULL) {
                    exportTimeUs = (elapsed * 1000000ULL) / freq;
                }
                else {
                    exportTimeUs = (elapsed / freq) * 1000000ULL;
                }
            }

            exportRoot["hashes"] = hashesArray;
            exportRoot["count"] = exportCount;
            exportRoot["export_time_microseconds"] = exportTimeUs;

            Json stats;
            auto storeStats = GetStatistics();
            stats["total_hashes"] = storeStats.totalHashes;
            stats["total_lookups"] = storeStats.totalLookups;
            stats["cache_hit_rate"] = storeStats.cacheHitRate;
            stats["database_size_bytes"] = storeStats.databaseSizeBytes;

            exportRoot["statistics"] = stats;

            std::string result;
            StringifyOptions stringOpts;
            stringOpts.pretty = true;
            stringOpts.indentSpaces = 2;

            if (!Stringify(exportRoot, result, stringOpts)) {
                SS_LOG_ERROR(L"HashStore", L"ExportToJson: Failed to stringify JSON");
                return "{}";
            }

            SS_LOG_DEBUG(L"HashStore",
                L"ExportToJson: Exported %zu hashes in %llu �s, JSON size: %zu bytes",
                exportCount, exportTimeUs, result.size());

            return result;
        }

	}
}