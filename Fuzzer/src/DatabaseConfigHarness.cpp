// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
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
/**
 * @file DatabaseConfigHarness.cpp
 * @brief Implementation of the DatabaseManager / ConfigurationDB fuzz harness.
 */

#include "ShadowStrike/Fuzzer/Harnesses/DatabaseConfigHarness.hpp"

#include "PhantomCore/Database/ConfigurationDB.hpp"
#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/JSONUtils.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace SSF = ShadowStrike::Fuzzer;
namespace SSD = ShadowStrike::Database;
namespace SSJ = ShadowStrike::Utils::JSON;

namespace {

constexpr uint8_t kLaneMask = 0x01;
constexpr uint8_t kLaneDatabase = 0;
constexpr uint8_t kLaneConfiguration = 1;
constexpr size_t kMaxBinaryValueSize = 256;

std::atomic<uint64_t> g_databaseConfigSequence{0};
thread_local std::filesystem::path g_databaseConfigIterationRoot;
thread_local std::string g_databaseConfigCleanupIssue;

void CaptureFirstIssue(SSF::HarnessResult& result, std::string_view message) {
    if (result.errorMessage.empty()) {
        result.errorMessage.assign(message.begin(), message.end());
    }
}

void RecordValidationIssue(SSF::HarnessResult& result, std::string_view message) {
    ++result.validationIssueCount;
    CaptureFirstIssue(result, message);
}

void RecordAnomaly(SSF::HarnessResult& result, std::string_view message) {
    ++result.anomalyCount;
    CaptureFirstIssue(result, message);
}

[[nodiscard]] std::string ExceptionCodeToStringInternal(DWORD code) {
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:         return "EXCEPTION_ACCESS_VIOLATION";
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
    case EXCEPTION_BREAKPOINT:               return "EXCEPTION_BREAKPOINT";
    case EXCEPTION_DATATYPE_MISALIGNMENT:    return "EXCEPTION_DATATYPE_MISALIGNMENT";
    case EXCEPTION_FLT_DENORMAL_OPERAND:     return "EXCEPTION_FLT_DENORMAL_OPERAND";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:       return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
    case EXCEPTION_FLT_INEXACT_RESULT:       return "EXCEPTION_FLT_INEXACT_RESULT";
    case EXCEPTION_FLT_INVALID_OPERATION:    return "EXCEPTION_FLT_INVALID_OPERATION";
    case EXCEPTION_FLT_OVERFLOW:             return "EXCEPTION_FLT_OVERFLOW";
    case EXCEPTION_FLT_STACK_CHECK:          return "EXCEPTION_FLT_STACK_CHECK";
    case EXCEPTION_FLT_UNDERFLOW:            return "EXCEPTION_FLT_UNDERFLOW";
    case EXCEPTION_GUARD_PAGE:               return "EXCEPTION_GUARD_PAGE";
    case EXCEPTION_ILLEGAL_INSTRUCTION:      return "EXCEPTION_ILLEGAL_INSTRUCTION";
    case EXCEPTION_IN_PAGE_ERROR:            return "EXCEPTION_IN_PAGE_ERROR";
    case EXCEPTION_INT_DIVIDE_BY_ZERO:       return "EXCEPTION_INT_DIVIDE_BY_ZERO";
    case EXCEPTION_INT_OVERFLOW:             return "EXCEPTION_INT_OVERFLOW";
    case EXCEPTION_INVALID_DISPOSITION:      return "EXCEPTION_INVALID_DISPOSITION";
    case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "EXCEPTION_NONCONTINUABLE_EXCEPTION";
    case EXCEPTION_PRIV_INSTRUCTION:         return "EXCEPTION_PRIV_INSTRUCTION";
    case EXCEPTION_SINGLE_STEP:              return "EXCEPTION_SINGLE_STEP";
    case EXCEPTION_STACK_OVERFLOW:           return "EXCEPTION_STACK_OVERFLOW";
    case STATUS_HEAP_CORRUPTION:             return "STATUS_HEAP_CORRUPTION";
    default: {
        char buffer[32]{};
        std::snprintf(buffer, sizeof(buffer), "EXCEPTION_0x%08lX", code);
        return buffer;
    }
    }
}

[[nodiscard]] uint64_t ReadLe64(std::span<const uint8_t> payload, size_t offset, uint64_t fallback) noexcept {
    if (offset >= payload.size()) {
        return fallback;
    }

    uint64_t value = 0;
    const size_t available = std::min(sizeof(value), payload.size() - offset);
    std::memcpy(&value, payload.data() + offset, available);
    return value;
}

[[nodiscard]] std::string MakeAsciiToken(std::span<const uint8_t> payload, size_t maxLen = 32) {
    static constexpr char kHex[] = "0123456789abcdef";

    if (payload.empty()) {
        return "empty";
    }

    const size_t limit = std::min(payload.size(), maxLen / 2);
    std::string token;
    token.reserve(limit * 2);
    for (size_t i = 0; i < limit; ++i) {
        const uint8_t byte = payload[i];
        token.push_back(kHex[(byte >> 4) & 0x0F]);
        token.push_back(kHex[byte & 0x0F]);
    }
    return token.empty() ? "00" : token;
}

[[nodiscard]] std::wstring MakeWideToken(std::span<const uint8_t> payload, size_t maxLen = 32) {
    const std::string narrow = MakeAsciiToken(payload, maxLen);
    return std::wstring(narrow.begin(), narrow.end());
}

[[nodiscard]] std::vector<uint8_t> MakeBinaryValue(std::span<const uint8_t> payload) {
    if (payload.empty()) {
        return { 0x10, 0x20, 0x30, 0x40 };
    }

    const size_t cappedSize = std::min(payload.size(), kMaxBinaryValueSize);
    return std::vector<uint8_t>(payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(cappedSize));
}

[[nodiscard]] std::vector<uint8_t> MakeMasterKey(std::span<const uint8_t> payload) {
    std::vector<uint8_t> key(32, 0);
    for (size_t i = 0; i < key.size(); ++i) {
        const uint8_t source = payload.empty() ? static_cast<uint8_t>(0xA5u + i)
                                               : payload[i % payload.size()];
        key[i] = static_cast<uint8_t>(source ^ static_cast<uint8_t>(0x5Au + i));
    }
    return key;
}

[[nodiscard]] std::vector<uint8_t> SerializeWideString(const std::wstring& value) {
    std::vector<uint8_t> blob(value.size() * sizeof(wchar_t));
    if (!blob.empty()) {
        std::memcpy(blob.data(), value.data(), blob.size());
    }
    return blob;
}

bool WriteTextFile(const std::filesystem::path& path, std::string_view contents) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) {
        return false;
    }

    stream.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    return static_cast<bool>(stream);
}

[[nodiscard]] std::filesystem::path CreateIterationRoot() {
    std::error_code ec;
    const std::filesystem::path base = std::filesystem::temp_directory_path(ec);
    const auto pid = static_cast<unsigned long>(GetCurrentProcessId());
    const uint64_t sequence = g_databaseConfigSequence.fetch_add(1, std::memory_order_relaxed);

    std::wstringstream name;
    name << L"shadowstrike-db-config-" << pid << L"-" << sequence;

    const std::filesystem::path root = base / name.str();
    std::filesystem::create_directories(root, ec);
    return root;
}

void CleanupIterationState() {
    SSD::ConfigurationDB::Instance().Shutdown();
    SSD::DatabaseManager::Instance().Shutdown();

    g_databaseConfigCleanupIssue.clear();
    if (!g_databaseConfigIterationRoot.empty()) {
        std::error_code cleanupError;
        const auto removalCount = std::filesystem::remove_all(g_databaseConfigIterationRoot, cleanupError);
        (void)removalCount;

        if (cleanupError) {
            g_databaseConfigCleanupIssue = "database-config cleanup failed for " +
                g_databaseConfigIterationRoot.string() + ": " + cleanupError.message();
        } else if (std::filesystem::exists(g_databaseConfigIterationRoot, cleanupError)) {
            if (cleanupError) {
                g_databaseConfigCleanupIssue = "database-config cleanup verification failed for " +
                    g_databaseConfigIterationRoot.string() + ": " + cleanupError.message();
            } else {
                g_databaseConfigCleanupIssue = "database-config cleanup left iteration workspace behind: " +
                    g_databaseConfigIterationRoot.string();
            }
        }

        g_databaseConfigIterationRoot.clear();
    }
}

[[nodiscard]] SSD::DatabaseConfig BuildDatabaseConfig(const std::filesystem::path& root) {
    SSD::DatabaseConfig config{};
    config.databasePath = (root / "database-manager.sqlite").wstring();
    config.enableWAL = true;
    config.enableForeignKeys = true;
    config.enableSecureDelete = true;
    config.enableMemoryMappedIO = false;
    config.busyTimeoutMs = 1000;
    config.maxConnections = 2;
    config.minConnections = 1;
    config.autoBackup = false;
    config.backupDirectory = (root / "backups").wstring();
    config.synchronousMode = L"NORMAL";
    return config;
}

[[nodiscard]] SSD::ConfigurationDB::Config BuildConfigurationConfig(
    const std::filesystem::path& root,
    std::span<const uint8_t> payload)
{
    SSD::ConfigurationDB::Config config{};
    config.dbPath = (root / "configuration.sqlite").wstring();
    config.enableEncryption = true;
    config.masterKey = MakeMasterKey(payload);
    config.requireStrongKeys = true;
    config.enableAuditLog = true;
    config.trackAllChanges = true;
    config.enableVersioning = true;
    config.maxVersionsPerKey = 8;
    config.enforceValidation = true;
    config.allowUnknownKeys = true;
    config.enableCaching = true;
    config.maxCacheEntries = 128;
    config.enableHotReload = false;
    config.maxAuditRecords = 2048;
    return config;
}

void ExerciseDatabaseLane(
    const std::filesystem::path& root,
    std::span<const uint8_t> payload,
    uint8_t flags,
    SSF::HarnessResult& result)
{
    auto& manager = SSD::DatabaseManager::Instance();
    SSD::DatabaseError error{};
    const SSD::DatabaseConfig config = BuildDatabaseConfig(root);

    if (!manager.Initialize(config, &error)) {
        RecordValidationIssue(result, "DatabaseManager initialization failed");
        return;
    }

    result.parsedOk = true;

    if (!manager.Execute(
            "CREATE TABLE IF NOT EXISTS fuzz_records ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "name TEXT NOT NULL, "
            "score INTEGER NOT NULL, "
            "payload BLOB)",
            &error)) {
        RecordValidationIssue(result, "DatabaseManager failed to create fuzz_records");
        return;
    }

    const std::string token = MakeAsciiToken(payload);
    const int64_t score = static_cast<int64_t>(ReadLe64(payload, 8, 1337) % 100000);
    const std::vector<uint8_t> blob = MakeBinaryValue(payload);

    if (!manager.ExecuteWithParams(
            "INSERT INTO fuzz_records(name, score, payload) VALUES(?, ?, ?)",
            &error,
            token,
            score,
            blob)) {
        RecordValidationIssue(result, "DatabaseManager failed to insert parameterized row");
        return;
    }

    int64_t rowCountBeforeTransaction = 0;
    {
        auto query = manager.Query("SELECT COUNT(*) FROM fuzz_records", &error);
        if (!query.Next()) {
            RecordValidationIssue(result, "DatabaseManager count query produced no rows");
            return;
        }
        rowCountBeforeTransaction = query.GetInt64(0);
    }

    std::vector<std::string> statements{
        "INSERT INTO fuzz_records(name, score, payload) VALUES('batch-one', 1, X'0102')",
        "INSERT INTO fuzz_records(name, score, payload) VALUES('batch-two', 2, X'0304')"
    };
    if ((flags & 0x01u) != 0) {
        statements.push_back("INSERT INTO fuzz_records(no_such_column) VALUES(1)");
        if (manager.ExecuteMany(statements, &error)) {
            RecordValidationIssue(result, "ExecuteMany accepted an invalid batch");
        }
        error.Clear();
    } else if (!manager.ExecuteMany(statements, &error)) {
        RecordValidationIssue(result, "ExecuteMany failed on valid statements");
        return;
    }

    bool committed = false;
    {
        auto transaction = manager.BeginTransaction(SSD::Transaction::Type::Immediate, &error);
        if (!transaction || !transaction->IsActive()) {
            RecordValidationIssue(result, "BeginTransaction failed");
            return;
        }

        if (!transaction->ExecuteWithParams(
                "INSERT INTO fuzz_records(name, score, payload) VALUES(?, ?, ?)",
                &error,
                std::string("txn-") + token,
                score + 1,
                blob)) {
            RecordValidationIssue(result, "Transaction insert failed");
            transaction->Rollback(nullptr);
            return;
        }

        if ((flags & 0x02u) != 0) {
            transaction->Rollback(nullptr);
        } else {
            if (!transaction->Commit(&error)) {
                RecordValidationIssue(result, "Transaction commit failed");
                return;
            }
            committed = true;
        }
    }

    int64_t finalRowCount = 0;
    {
        auto query = manager.Query("SELECT COUNT(*) FROM fuzz_records", &error);
        if (!query.Next()) {
            RecordValidationIssue(result, "Post-transaction count query produced no rows");
            return;
        }
        finalRowCount = query.GetInt64(0);
    }

    const int64_t expectedRowCount =
        rowCountBeforeTransaction + (((flags & 0x01u) == 0) ? 2 : 0) + (committed ? 1 : 0);
    if (finalRowCount != expectedRowCount) {
        RecordValidationIssue(result, "Database row count invariant failed");
    }

    if (!manager.TableExists("fuzz_records", &error)) {
        RecordValidationIssue(result, "TableExists failed for fuzz_records");
    }

    const auto tableNames = manager.GetTableNames(&error);
    if (std::find(tableNames.begin(), tableNames.end(), "fuzz_records") == tableNames.end()) {
        RecordValidationIssue(result, "GetTableNames missed fuzz_records");
    }

    const auto columns = manager.GetColumnNames("fuzz_records", &error);
    if (columns.size() < 4) {
        RecordValidationIssue(result, "GetColumnNames returned an incomplete schema");
    }

    std::vector<std::wstring> issues;
    if (!manager.CheckIntegrity(issues, &error) || !issues.empty()) {
        RecordValidationIssue(result, "Database integrity check reported issues");
    }

    if (!manager.Optimize(&error)) {
        RecordValidationIssue(result, "Database optimization failed");
    }

    const std::filesystem::path backupPath = root / "database-backup.sqlite";
    if (!manager.BackupToFile(backupPath.wstring(), &error)) {
        RecordValidationIssue(result, "Database backup failed");
        return;
    }

    if (!std::filesystem::exists(backupPath)) {
        RecordValidationIssue(result, "Database backup file was not created");
        return;
    }

    if (!manager.RestoreFromFile(backupPath.wstring(), &error)) {
        RecordValidationIssue(result, "Database restore failed");
        return;
    }

    {
        auto query = manager.Query("SELECT COUNT(*) FROM fuzz_records", &error);
        if (!query.Next() || query.GetInt64(0) != finalRowCount) {
            RecordValidationIssue(result, "Database restore changed committed row count");
        }
    }

    const auto stats = manager.GetStats(&error);
    if (stats.totalQueries == 0) {
        RecordValidationIssue(result, "Database statistics did not record executed queries");
    }
}

void ExerciseConfigurationLane(
    const std::filesystem::path& root,
    std::span<const uint8_t> payload,
    uint8_t flags,
    SSF::HarnessResult& result)
{
    auto& configDb = SSD::ConfigurationDB::Instance();
    SSD::DatabaseError error{};
    const SSD::ConfigurationDB::Config config = BuildConfigurationConfig(root, payload);

    if (!configDb.Initialize(config, &error)) {
        RecordValidationIssue(result, "ConfigurationDB initialization failed");
        return;
    }

    result.parsedOk = true;
    configDb.ResetStatistics();

    std::atomic<uint64_t> listenerNotifications{0};
    const int listenerId = configDb.RegisterChangeListener(
        L"fuzz.*",
        [&listenerNotifications](
            std::wstring_view,
            const SSD::ConfigurationDB::ConfigValue&,
            const SSD::ConfigurationDB::ConfigValue&) {
            listenerNotifications.fetch_add(1, std::memory_order_relaxed);
        });

    SSD::ConfigurationDB::ValidationRule intRule{};
    intRule.key = L"fuzz.numeric";
    intRule.expectedType = SSD::ConfigurationDB::ValueType::Integer;
    intRule.required = false;
    intRule.minInt = 0;
    intRule.maxInt = 100000;
    if (!configDb.RegisterValidationRule(intRule)) {
        RecordValidationIssue(result, "ConfigurationDB failed to register integer validation rule");
    }

    SSD::ConfigurationDB::ValidationRule modeRule{};
    modeRule.key = L"fuzz.mode";
    modeRule.expectedType = SSD::ConfigurationDB::ValueType::String;
    modeRule.allowedValues = { L"alpha", L"beta" };
    if (!configDb.RegisterValidationRule(modeRule)) {
        RecordValidationIssue(result, "ConfigurationDB failed to register mode validation rule");
    }

    const std::wstring token = MakeWideToken(payload);
    const std::wstring secret = L"secret-" + token;
    const int64_t numericValue = static_cast<int64_t>(ReadLe64(payload, 0, 4242) % 100000);
    const std::wstring modeValue = ((flags & 0x01u) != 0) ? L"beta" : L"alpha";
    std::vector<uint8_t> binaryValue = MakeBinaryValue(payload);
    std::vector<std::pair<std::wstring, SSD::ConfigurationDB::ConfigValue>> batchEntries;
    std::vector<std::wstring> prefixedKeys;
    std::unordered_map<std::wstring, SSD::ConfigurationDB::ConfigValue> batchValues;
    std::vector<std::wstring> validationErrors;
    const std::filesystem::path jsonPath = root / "config-export.json";
    const std::filesystem::path xmlPath = root / "config-export.xml";

    SSJ::Json profile = SSJ::Json::object();
    profile["token"] = MakeAsciiToken(payload);
    profile["payloadSize"] = payload.size();
    profile["enableFeature"] = (flags & 0x08u) != 0;

    do {
        if (!configDb.SetString(L"fuzz.name", token, SSD::ConfigurationDB::ConfigScope::Global, L"DatabaseConfigHarness", &error)) {
            RecordValidationIssue(result, "ConfigurationDB failed to set fuzz.name");
            break;
        }

        if (!configDb.SetInt(L"fuzz.numeric", numericValue, SSD::ConfigurationDB::ConfigScope::Global, L"DatabaseConfigHarness", &error)) {
            RecordValidationIssue(result, "ConfigurationDB failed to set fuzz.numeric");
            break;
        }

        if (!configDb.SetString(L"fuzz.mode", modeValue, SSD::ConfigurationDB::ConfigScope::Global, L"DatabaseConfigHarness", &error)) {
            RecordValidationIssue(result, "ConfigurationDB failed to set fuzz.mode");
            break;
        }

        if (!configDb.SetJson(L"fuzz.profile", profile, SSD::ConfigurationDB::ConfigScope::Global, L"DatabaseConfigHarness", &error)) {
            RecordValidationIssue(result, "ConfigurationDB failed to set fuzz.profile");
            break;
        }

        if (!configDb.SetBool(L"fuzz.flag", (flags & 0x02u) != 0, SSD::ConfigurationDB::ConfigScope::Global, L"DatabaseConfigHarness", &error)) {
            RecordValidationIssue(result, "ConfigurationDB failed to set fuzz.flag");
            break;
        }

        if (!configDb.Set(L"fuzz.secret", secret, SSD::ConfigurationDB::ConfigScope::Global, L"DatabaseConfigHarness", L"seed secret", &error)) {
            RecordValidationIssue(result, "ConfigurationDB failed to set fuzz.secret");
            break;
        }

        if (!configDb.Set(L"fuzz.binary", binaryValue, SSD::ConfigurationDB::ConfigScope::Global, L"DatabaseConfigHarness", L"seed blob", &error)) {
            RecordValidationIssue(result, "ConfigurationDB failed to set fuzz.binary");
            break;
        }

        batchEntries.emplace_back(L"fuzz.batch.one", token + L"-one");
        batchEntries.emplace_back(L"fuzz.batch.two", numericValue + 7);
        if (!configDb.SetBatch(batchEntries, SSD::ConfigurationDB::ConfigScope::Agent, L"DatabaseConfigHarness", &error)) {
            RecordValidationIssue(result, "ConfigurationDB batch write failed");
            break;
        }

        if (configDb.GetString(L"fuzz.name", L"", &error) != token) {
            RecordValidationIssue(result, "ConfigurationDB returned wrong value for fuzz.name");
        }

        if (configDb.GetInt(L"fuzz.numeric", -1, &error) != numericValue) {
            RecordValidationIssue(result, "ConfigurationDB returned wrong value for fuzz.numeric");
        }

        if (!configDb.Contains(L"fuzz.profile")) {
            RecordValidationIssue(result, "ConfigurationDB lost fuzz.profile");
        }

        prefixedKeys = configDb.GetKeysByPrefix(L"fuzz.", std::nullopt, 64, &error);
        if (prefixedKeys.size() < 6) {
            RecordValidationIssue(result, "ConfigurationDB prefix query returned too few keys");
        }

        batchValues = configDb.GetBatch({ L"fuzz.name", L"fuzz.numeric", L"fuzz.batch.one" }, &error);
        if (batchValues.size() < 3) {
            RecordValidationIssue(result, "ConfigurationDB batch read missed written keys");
        }

        if (!configDb.ValidateAll(validationErrors, &error) || !validationErrors.empty()) {
            RecordValidationIssue(result, "ConfigurationDB ValidateAll reported errors on valid state");
        }

        if (!configDb.Encrypt(L"fuzz.secret", L"DatabaseConfigHarness", &error)) {
            RecordValidationIssue(result, "ConfigurationDB failed to encrypt fuzz.secret");
            break;
        }

        if (!configDb.IsEncrypted(L"fuzz.secret")) {
            RecordValidationIssue(result, "ConfigurationDB did not mark fuzz.secret as encrypted");
        }

        if (!configDb.ExportToJson(jsonPath, std::nullopt, true, &error)) {
            RecordValidationIssue(result, "ConfigurationDB JSON export failed");
            break;
        }

        if (!configDb.ExportToXml(xmlPath, std::nullopt, true, &error)) {
            RecordValidationIssue(result, "ConfigurationDB XML export failed");
            break;
        }

        if (!configDb.Decrypt(L"fuzz.secret", L"DatabaseConfigHarness", &error)) {
            RecordValidationIssue(result, "ConfigurationDB failed to decrypt fuzz.secret");
            break;
        }

        if (configDb.GetString(L"fuzz.secret", L"", &error) != secret) {
            RecordValidationIssue(result, "ConfigurationDB decrypt round-trip changed fuzz.secret");
        }

        if (!configDb.RemoveBatch({ L"fuzz.name", L"fuzz.profile" }, L"DatabaseConfigHarness", &error)) {
            RecordValidationIssue(result, "ConfigurationDB failed to remove keys before re-import");
            break;
        }

        if (!configDb.ImportFromJson(jsonPath, true, L"DatabaseConfigHarness", &error)) {
            RecordValidationIssue(result, "ConfigurationDB JSON import failed");
            break;
        }

        if (!configDb.Contains(L"fuzz.name") || !configDb.Contains(L"fuzz.profile")) {
            RecordValidationIssue(result, "ConfigurationDB JSON import did not restore removed keys");
        }

        if (!configDb.RemoveBatch({ L"fuzz.batch.one" }, L"DatabaseConfigHarness", &error)) {
            RecordValidationIssue(result, "ConfigurationDB failed to remove XML-import target key");
            break;
        }

        if (!configDb.ImportFromXml(xmlPath, true, L"DatabaseConfigHarness", &error)) {
            RecordValidationIssue(result, "ConfigurationDB XML import failed");
            break;
        }

        if (!configDb.Contains(L"fuzz.batch.one")) {
            RecordValidationIssue(result, "ConfigurationDB XML import did not restore fuzz.batch.one");
        }

        {
            auto& manager = SSD::DatabaseManager::Instance();
            const std::wstring externalValue = L"external-" + token;
            const std::vector<uint8_t> externalBlob = SerializeWideString(externalValue);
            const int64_t modifiedAt = static_cast<int64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count() + 1000);

            if (!manager.ExecuteWithParams(
                    "UPDATE configurations SET value = ?, type = ?, modified_at = ?, modified_by = ? WHERE key = ?",
                    &error,
                    externalBlob,
                    static_cast<int>(SSD::ConfigurationDB::ValueType::String),
                    modifiedAt,
                    std::string("HotReload"),
                    std::string("fuzz.name"))) {
                RecordValidationIssue(result, "External configuration mutation failed");
                break;
            }

            if (!configDb.HotReload(&error)) {
                RecordValidationIssue(result, "ConfigurationDB hot reload failed");
                break;
            }

            if (configDb.GetString(L"fuzz.name", L"", &error) != externalValue) {
                RecordValidationIssue(result, "ConfigurationDB hot reload did not surface external mutation");
            }
        }

        if (!configDb.Optimize(&error) || !configDb.Vacuum(&error) || !configDb.CheckIntegrity(&error)) {
            RecordValidationIssue(result, "ConfigurationDB maintenance routine failed");
        }

        {
            const auto stats = configDb.GetStatistics();
            if (stats.totalWrites == 0 || stats.totalReads == 0) {
                RecordValidationIssue(result, "ConfigurationDB statistics did not record reads and writes");
            }
        }

        if (listenerNotifications.load(std::memory_order_relaxed) == 0) {
            RecordValidationIssue(result, "ConfigurationDB change listeners did not receive notifications");
        }
    } while (false);

    if (listenerId != 0) {
        configDb.UnregisterChangeListener(listenerId);
    }
}

[[nodiscard]] bool ExerciseDatabaseConfigInput(
    std::span<const uint8_t> input,
    SSF::HarnessResult& result)
{
    if (input.size() < 2) {
        result.errorMessage = "database-config input too small";
        return false;
    }

    const uint8_t lane = input[0] & kLaneMask;
    const uint8_t flags = input[1];
    const std::span<const uint8_t> payload = input.subspan(2);

    switch (lane) {
    case kLaneDatabase:
        ExerciseDatabaseLane(g_databaseConfigIterationRoot, payload, flags, result);
        break;
    case kLaneConfiguration:
        ExerciseConfigurationLane(g_databaseConfigIterationRoot, payload, flags, result);
        break;
    default:
        result.errorMessage = "invalid database-config lane";
        return false;
    }

    return result.validationIssueCount == 0;
}

void EnsureSeedCorpus(const std::filesystem::path& corpusDir) {
    const std::array<std::pair<std::string_view, std::vector<uint8_t>>, 2> seeds{{
        { "seed-database.bin", { kLaneDatabase, 0x00, 'D', 'B', '0', '1', 'f', 'u', 'z', 'z' } },
        { "seed-config.bin", { kLaneConfiguration, 0x00, 'C', 'F', 'G', '0', '1', 's', 'e', 'e', 'd' } },
    }};

    for (const auto& [name, bytes] : seeds) {
        const std::filesystem::path seedPath = corpusDir / name;
        if (std::filesystem::exists(seedPath)) {
            continue;
        }

        std::ofstream stream(seedPath, std::ios::binary | std::ios::trunc);
        if (!stream) {
            continue;
        }

        stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }
}

[[nodiscard]] std::optional<std::vector<uint8_t>> ReadFileBytes(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        return std::nullopt;
    }

    stream.seekg(0, std::ios::end);
    const std::streamoff size = stream.tellg();
    if (size < 0) {
        return std::nullopt;
    }

    stream.seekg(0, std::ios::beg);
    std::vector<uint8_t> bytes(static_cast<size_t>(size));
    if (!bytes.empty()) {
        stream.read(reinterpret_cast<char*>(bytes.data()), size);
        if (!stream) {
            return std::nullopt;
        }
    }

    return bytes;
}

}  // namespace

namespace ShadowStrike::Fuzzer {

unsigned long DatabaseConfigHarness::SEHCallDatabaseConfig(
    const uint8_t* data,
    size_t size,
    HarnessResult* result) noexcept
{
    __try {
        ExerciseDatabaseConfigImpl(data, size, *result);
        return static_cast<unsigned long>(EXCEPTION_CONTINUE_EXECUTION);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return static_cast<unsigned long>(GetExceptionCode());
    }
}

bool DatabaseConfigHarness::ExerciseDatabaseConfigImpl(
    const uint8_t* data,
    size_t size,
    HarnessResult& result)
{
    return ExerciseDatabaseConfigInput(std::span<const uint8_t>(data, size), result);
}

HarnessResult DatabaseConfigHarness::Run(std::span<const uint8_t> input) noexcept {
    HarnessResult result{};

    try {
        if (input.empty()) {
            result.errorMessage = "database-config input is empty";
            return result;
        }

        g_databaseConfigIterationRoot = CreateIterationRoot();
        const unsigned long sehCode = SEHCallDatabaseConfig(input.data(), input.size(), &result);
        CleanupIterationState();

        if (!g_databaseConfigCleanupIssue.empty()) {
            ++result.anomalyCount;
            CaptureFirstIssue(result, g_databaseConfigCleanupIssue);
        }

        if (sehCode != EXCEPTION_CONTINUE_EXECUTION) {
            result.crashed = true;
            result.crashSignal = ExceptionCodeToString(sehCode);
            if (result.errorMessage.empty()) {
                result.errorMessage = "database-config harness raised a structured exception";
            }
            return result;
        }

        if (result.validationIssueCount != 0) {
            result.parsedOk = false;
        }
    } catch (const std::exception& ex) {
        CleanupIterationState();
        if (!g_databaseConfigCleanupIssue.empty()) {
            ++result.anomalyCount;
        }
        result.crashed = true;
        result.crashSignal = "CPP_EXCEPTION";
        result.errorMessage = ex.what();
    } catch (...) {
        CleanupIterationState();
        if (!g_databaseConfigCleanupIssue.empty()) {
            ++result.anomalyCount;
            CaptureFirstIssue(result, g_databaseConfigCleanupIssue);
        }
        result.crashed = true;
        result.crashSignal = "CPP_UNKNOWN_EXCEPTION";
    }

    return result;
}

HarnessFunction DatabaseConfigHarness::GetHarnessFunction() noexcept {
    return &DatabaseConfigHarness::Run;
}

std::string_view DatabaseConfigHarness::GetName() noexcept {
    return "database-config";
}

std::string_view DatabaseConfigHarness::GetDescription() noexcept {
    return "Exercises DatabaseManager and ConfigurationDB stateful entry points.";
}

std::string DatabaseConfigHarness::ExceptionCodeToString(unsigned long code) {
    return ExceptionCodeToStringInternal(code);
}

int RunDatabaseConfigFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config) noexcept
{
    if (!InstallCtrlCHandler()) {
        std::cerr << "[DatabaseConfigFuzzer] Warning: Failed to install Ctrl+C handler\n";
    }

    const std::filesystem::path corpusDir = workspaceDir / "corpora" / "database-config";
    const std::filesystem::path crashDir = workspaceDir / "crashes" / "database-config";

    std::error_code error;
    std::filesystem::create_directories(corpusDir, error);
    if (error) {
        std::cerr << "[DatabaseConfigFuzzer] Failed to create corpus directory: " << corpusDir << '\n';
        return 1;
    }

    error.clear();
    std::filesystem::create_directories(crashDir, error);
    if (error) {
        std::cerr << "[DatabaseConfigFuzzer] Failed to create crash directory: " << crashDir << '\n';
        return 1;
    }

    EnsureSeedCorpus(corpusDir);

    static constexpr std::array<std::string_view, 2> kSanitySeeds{
        "seed-database.bin",
        "seed-config.bin",
    };

    for (const auto seedName : kSanitySeeds) {
        const auto seedBytes = ReadFileBytes(corpusDir / seedName);
        if (!seedBytes.has_value()) {
            std::cerr << "[DatabaseConfigFuzzer] Failed to read sanity seed: " << seedName << '\n';
            return 1;
        }

        const HarnessResult sanity = DatabaseConfigHarness::Run(*seedBytes);
        if (sanity.crashed || !sanity.parsedOk) {
            std::cerr << "[DatabaseConfigFuzzer] Sanity check failed for " << seedName;
            if (!sanity.errorMessage.empty()) {
                std::cerr << ": " << sanity.errorMessage;
            }
            if (!sanity.crashSignal.empty()) {
                std::cerr << " (" << sanity.crashSignal << ")";
            }
            std::cerr << '\n';
            return 1;
        }
    }

    FuzzLoopConfig loopConfig = config;
    loopConfig.targetName = std::string(DatabaseConfigHarness::GetName());

    std::cout << "[DatabaseConfigFuzzer] Starting database/config fuzzing...\n";
    std::cout << "[DatabaseConfigFuzzer] Corpus: " << corpusDir << '\n';
    std::cout << "[DatabaseConfigFuzzer] Crashes: " << crashDir << '\n';

    FuzzLoop loop(corpusDir, crashDir, DatabaseConfigHarness::GetHarnessFunction(), loopConfig);
    const bool success = loop.Run();
    const auto& stats = loop.GetStatistics();

    std::cout << "\n[DatabaseConfigFuzzer] Final Results:\n";
    std::cout << "  Total iterations: " << stats.totalIterations << '\n';
    std::cout << "  Unique crashes:   " << stats.uniqueCrashes << '\n';
    std::cout << "  Total crashes:    " << stats.crashesFound << '\n';
    std::cout << "  Final corpus:     " << stats.corpusSize << '\n';
    std::cout << "  Parse success:    " << stats.parseSuccesses << '\n';
    std::cout << "  Parse failure:    " << stats.parseFailures << '\n';
    std::cout << "  Duration:         " << (stats.durationMs / 1000) << "s\n";
    std::cout << "  Speed:            " << std::fixed << std::setprecision(1)
              << stats.iterationsPerSecond << " iter/s\n";

    return success ? 0 : 1;
}

}  // namespace ShadowStrike::Fuzzer
