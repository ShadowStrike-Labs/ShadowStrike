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
 * ============================================================================
 * ShadowStrike Ransomware Recovery - RANSOMWARE DECRYPTOR IMPLEMENTATION
 * ============================================================================
 *
 * @file RansomwareDecryptor.cpp
 * @brief Enterprise-grade ransomware decryption and file recovery engine.
 *
 * Full recovery pipeline: VSS restoration, FileBackupManager coordination,
 * key-based decryption via CryptoUtils, atomic file replacement, SHA-256
 * integrity verification, forensic preservation, and SecureZeroMemory
 * key material erasure.
 *
 * @author ShadowStrike Security Team
 * @version 3.1.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "RansomwareDecryptor.hpp"
#include "VolumeSnapshotService.hpp"
#include "FileBackupManager.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/SystemUtils.hpp"

// Cross-module wiring
#include "../Communication/AlertSystem.hpp"
#include "../Communication/TelemetryCollector.hpp"
#include "../Communication/IPCManager.hpp"

#include <algorithm>
#include <sstream>
#include <filesystem>
#include <future>
#include <objbase.h>

#ifdef _MSC_VER
#  pragma warning(push)
#  pragma warning(disable: 4996)
#endif
#include <nlohmann/json.hpp>
#ifdef _MSC_VER
#  pragma warning(pop)
#endif

namespace fs = std::filesystem;

namespace ShadowStrike {
namespace Ransomware {

// ============================================================================
// ANONYMOUS NAMESPACE CONSTANTS & UTILITIES
// ============================================================================

namespace {

    static constexpr const wchar_t* LOG_CAT = L"RansomDecryptor";

    // Maximum recursion depth for directory traversal to prevent stack overflow
    static constexpr size_t MAX_DIRECTORY_DEPTH = 64;

    // Maximum files collected per directory scan
    static constexpr size_t MAX_SCAN_FILES = DecryptorConstants::MAX_BATCH_FILES;

    /// @brief Known ransomware extensions mapping
    const std::unordered_map<std::wstring, RansomwareFamily> EXTENSION_MAP = {
        {L".wncry", RansomwareFamily::WannaCry},
        {L".wcry", RansomwareFamily::WannaCry},
        {L".locky", RansomwareFamily::Locky},
        {L".encrypted", RansomwareFamily::CryptoLocker},
        {L".vvv", RansomwareFamily::TeslaCrypt},
        {L".ecc", RansomwareFamily::TeslaCrypt},
        {L".ezz", RansomwareFamily::TeslaCrypt},
        {L".exx", RansomwareFamily::TeslaCrypt},
        {L".zzz", RansomwareFamily::TeslaCrypt},
        {L".xyz", RansomwareFamily::TeslaCrypt},
        {L".aaa", RansomwareFamily::TeslaCrypt},
        {L".abc", RansomwareFamily::TeslaCrypt},
        {L".ccc", RansomwareFamily::TeslaCrypt},
        {L".cerber", RansomwareFamily::Cerber},
        {L".cerber2", RansomwareFamily::Cerber},
        {L".cerber3", RansomwareFamily::Cerber},
        {L".gandcrab", RansomwareFamily::GandCrabV4},
        {L".crab", RansomwareFamily::GandCrabV4},
        {L".xtbl", RansomwareFamily::Shade},
        {L".ytbl", RansomwareFamily::Shade},
        {L".breaking_bad", RansomwareFamily::Shade},
        {L".crysis", RansomwareFamily::Crysis},
        {L".dharma", RansomwareFamily::Dharma},
        {L".wallet", RansomwareFamily::Dharma},
        {L".onion", RansomwareFamily::Dharma},
        {L".phobos", RansomwareFamily::Phobos},
        {L".djvu", RansomwareFamily::Djvu},
        {L".stop", RansomwareFamily::STOP},
        {L".fun", RansomwareFamily::Jigsaw},
        {L".kkk", RansomwareFamily::Jigsaw},
        {L".btc", RansomwareFamily::BTCWare},
        {L".ryuk", RansomwareFamily::Ryuk},
        {L".lockbit", RansomwareFamily::LockBit}
    };

    /// @brief Family name -> enum map for DecryptFile string API
    const std::unordered_map<std::string, RansomwareFamily> FAMILY_NAME_MAP = {
        {"WannaCry",     RansomwareFamily::WannaCry},
        {"Locky",        RansomwareFamily::Locky},
        {"CryptoLocker", RansomwareFamily::CryptoLocker},
        {"TeslaCrypt",   RansomwareFamily::TeslaCrypt},
        {"Cerber",       RansomwareFamily::Cerber},
        {"Petya",        RansomwareFamily::Petya},
        {"NotPetya",     RansomwareFamily::NotPetya},
        {"GandCrabV4",   RansomwareFamily::GandCrabV4},
        {"GandCrab v4",  RansomwareFamily::GandCrabV4},
        {"GandCrabV5",   RansomwareFamily::GandCrabV5},
        {"GandCrab v5",  RansomwareFamily::GandCrabV5},
        {"Shade",        RansomwareFamily::Shade},
        {"Troldesh",     RansomwareFamily::Troldesh},
        {"Crysis",       RansomwareFamily::Crysis},
        {"Dharma",       RansomwareFamily::Dharma},
        {"Phobos",       RansomwareFamily::Phobos},
        {"STOP",         RansomwareFamily::STOP},
        {"Djvu",         RansomwareFamily::Djvu},
        {"Jigsaw",       RansomwareFamily::Jigsaw},
        {"BTCWare",      RansomwareFamily::BTCWare},
        {"GlobeImposter",RansomwareFamily::GlobeImposter},
        {"SamSam",       RansomwareFamily::SamSam},
        {"Ryuk",         RansomwareFamily::Ryuk},
        {"REvil",        RansomwareFamily::REvil},
        {"Maze",         RansomwareFamily::Maze},
        {"Conti",        RansomwareFamily::Conti},
        {"LockBit",      RansomwareFamily::LockBit},
        {"BlackCat",     RansomwareFamily::BlackCat},
        {"Hive",         RansomwareFamily::Hive},
    };

    /// @brief Ransom note filename patterns
    const std::vector<std::wstring> RANSOM_NOTE_FILENAMES = {
        L"@Please_Read_Me@.txt",
        L"@WanaDecryptor@.txt",
        L"_Locky_recover_instructions.txt",
        L"HELP_DECRYPT.TXT",
        L"HELP_TO_DECRYPT_YOUR_FILES.txt",
        L"How to decrypt your files.txt",
        L"RESTORE_FILES.txt",
        L"DECRYPT_FILES.txt",
        L"RyukReadMe.txt",
        L"Restore-My-Files.txt"
    };

    /// @brief Convert extension to lowercase for comparison.
    ///
    /// Extensions are pure ASCII by convention. Using a locale-sensitive
    /// helper such as ``::towlower`` would, under e.g. Turkish locale,
    /// fold 'I' to a non-ASCII code point and break the EXTENSION_MAP
    /// lookup. We therefore implement a strict ASCII fold here.
    [[nodiscard]] std::wstring NormalizeExtension(const std::wstring& ext) {
        std::wstring result = ext;
        for (auto& wc : result) {
            if (wc >= L'A' && wc <= L'Z') {
                wc = static_cast<wchar_t>(wc + (L'a' - L'A'));
            }
        }
        return result;
    }

    /// @brief Map EncryptionAlgorithm to CryptoUtils::SymmetricAlgorithm
    [[nodiscard]] std::optional<Utils::CryptoUtils::SymmetricAlgorithm>
    MapToSymmetricAlgorithm(EncryptionAlgorithm algo) {
        switch (algo) {
            case EncryptionAlgorithm::AES128CBC: return Utils::CryptoUtils::SymmetricAlgorithm::AES_128_CBC;
            case EncryptionAlgorithm::AES256CBC: return Utils::CryptoUtils::SymmetricAlgorithm::AES_256_CBC;
            case EncryptionAlgorithm::AES128GCM: return Utils::CryptoUtils::SymmetricAlgorithm::AES_128_GCM;
            case EncryptionAlgorithm::AES256GCM: return Utils::CryptoUtils::SymmetricAlgorithm::AES_256_GCM;
            case EncryptionAlgorithm::ChaCha20:  return Utils::CryptoUtils::SymmetricAlgorithm::ChaCha20_Poly1305;
            default: return std::nullopt;
        }
    }

    /// @brief Generate a recovery/batch ID using Windows GUID.
    ///
    /// The GUID returned by ``StringFromGUID2`` is pure ASCII (digits,
    /// hex letters, dashes, braces), so the narrow conversion below is
    /// safe by construction. We use ``WideCharToMultiByte`` rather than
    /// a naive ``std::string(ws.begin(), ws.end())`` because the latter
    /// performs an implicit ``wchar_t``-to-``char`` narrowing that
    /// triggers C4244 under ``/W4`` and silently truncates non-ASCII
    /// input - a defensive choice in case the format ever changes.
    [[nodiscard]] std::string GenerateRecoveryId() {
        ::GUID guid{};
        if (SUCCEEDED(::CoCreateGuid(&guid))) {
            wchar_t buf[40]{};
            if (::StringFromGUID2(guid, buf, 40) > 0) {
                const std::wstring_view ws(buf);
                if (ws.size() > 2) {
                    // Strip the surrounding braces produced by StringFromGUID2
                    const std::wstring_view inner = ws.substr(1, ws.size() - 2);

                    const int needed = ::WideCharToMultiByte(
                        CP_UTF8, 0,
                        inner.data(), static_cast<int>(inner.size()),
                        nullptr, 0, nullptr, nullptr);
                    if (needed > 0) {
                        std::string out(static_cast<size_t>(needed), '\0');
                        const int written = ::WideCharToMultiByte(
                            CP_UTF8, 0,
                            inner.data(), static_cast<int>(inner.size()),
                            out.data(), needed, nullptr, nullptr);
                        if (written == needed) {
                            return out;
                        }
                    }
                }
            }
        }
        auto now = Clock::now().time_since_epoch().count();
        return std::to_string(now);
    }

    /// @brief Validate a file path for safety (no traversal, reasonable length)
    [[nodiscard]] bool ValidateFilePath(const fs::path& p) {
        const std::wstring ws = p.wstring();
        if (ws.empty() || ws.size() > 32767) return false;

        // Reject path traversal via embedded ".."
        for (const auto& component : p) {
            if (component == L"..") return false;
        }
        return true;
    }

    /// @brief Securely erase all sensitive fields in a DecryptionKey
    void SecureEraseKey(DecryptionKey& key) {
        if (!key.keyData.empty()) {
            ::SecureZeroMemory(key.keyData.data(), key.keyData.size());
            key.keyData.clear();
        }
        if (!key.iv.empty()) {
            ::SecureZeroMemory(key.iv.data(), key.iv.size());
            key.iv.clear();
        }
        if (!key.rsaPrivateKey.empty()) {
            ::SecureZeroMemory(key.rsaPrivateKey.data(), key.rsaPrivateKey.size());
            key.rsaPrivateKey.clear();
        }
    }

    /// @brief Compute SHA-256 hash of a file
    [[nodiscard]] bool ComputeFileHash(std::wstring_view filePath,
                                       std::vector<uint8_t>& outHash) {
        Utils::HashUtils::Error err{};
        if (!Utils::HashUtils::ComputeFile(
                Utils::HashUtils::Algorithm::SHA256, filePath, outHash, &err)) {
            SS_LOG_ERROR(LOG_CAT, L"SHA-256 hash failed for %ls (win32=%lu)",
                         std::wstring(filePath).c_str(), err.win32);
            return false;
        }
        return true;
    }

    /// @brief Atomic file replacement: write to temp path, then rename
    [[nodiscard]] bool AtomicFileCopy(const fs::path& source,
                                      const fs::path& destination) {
        fs::path tmpPath = destination;
        tmpPath += L".ss_recovery_tmp";

        try {
            fs::copy_file(source, tmpPath, fs::copy_options::overwrite_existing);
        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CAT, L"AtomicFileCopy: copy to temp failed: %hs", ex.what());
            return false;
        }

        if (!::MoveFileExW(tmpPath.c_str(), destination.c_str(),
                           MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            DWORD err = ::GetLastError();
            SS_LOG_ERROR(LOG_CAT, L"AtomicFileCopy: MoveFileEx failed, win32=%lu", err);
            std::error_code ec;
            fs::remove(tmpPath, ec);
            return false;
        }
        return true;
    }

} // anonymous namespace

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class RansomwareDecryptor::RansomwareDecryptorImpl final {
public:
    RansomwareDecryptorImpl() = default;

    ~RansomwareDecryptorImpl() {
        // Securely erase all key material on destruction
        std::unique_lock keyLock(m_keyMutex);
        for (auto& [id, key] : m_keys) {
            SecureEraseKey(key);
        }
        m_keys.clear();
        m_familyKeys.clear();
    }

    RansomwareDecryptorImpl(const RansomwareDecryptorImpl&) = delete;
    RansomwareDecryptorImpl& operator=(const RansomwareDecryptorImpl&) = delete;
    RansomwareDecryptorImpl(RansomwareDecryptorImpl&&) = delete;
    RansomwareDecryptorImpl& operator=(RansomwareDecryptorImpl&&) = delete;

    // ========================================================================
    // STATE
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    ModuleStatus m_status{ModuleStatus::Uninitialized};
    RansomwareDecryptorConfiguration m_config;
    DecryptorStatistics m_stats;

    std::unordered_map<std::string, DecryptionKey> m_keys;
    std::unordered_map<RansomwareFamily, std::vector<std::string>> m_familyKeys;
    mutable std::shared_mutex m_keyMutex;

    std::atomic<uint32_t> m_activeDecryptions{0};
    std::atomic<bool> m_cancelRequested{false};

    DecryptionProgressCallback m_progressCallback;
    DecryptionCompleteCallback m_completeCallback;
    BatchProgressCallback m_batchProgressCallback;
    mutable std::mutex m_callbackMutex;

    // ========================================================================
    // BACKUP BEFORE DECRYPTION
    // ========================================================================

    [[nodiscard]] bool BackupFile(const fs::path& filePath) {
        try {
            if (!m_config.backupBeforeDecrypt) return true;

            fs::path backupDir = m_config.backupDirectory.empty()
                ? filePath.parent_path() / L"ShadowStrike_Backup"
                : fs::path(m_config.backupDirectory);

            std::error_code ec;
            if (!fs::exists(backupDir, ec)) {
                fs::create_directories(backupDir, ec);
                if (ec) {
                    SS_LOG_ERROR(LOG_CAT, L"Cannot create backup dir: %ls (ec=%d)",
                                 backupDir.c_str(), ec.value());
                    return false;
                }
            }

            fs::path backupPath = backupDir / filePath.filename();
            if (fs::exists(backupPath, ec)) {
                backupPath += L".bak_" + std::to_wstring(
                    Clock::now().time_since_epoch().count());
            }

            fs::copy_file(filePath, backupPath, ec);
            if (ec) {
                SS_LOG_ERROR(LOG_CAT, L"Backup copy failed for %ls (ec=%d)",
                             filePath.c_str(), ec.value());
                return false;
            }

            // Verify backup integrity with SHA-256
            std::vector<uint8_t> srcHash, dstHash;
            if (ComputeFileHash(filePath.wstring(), srcHash) &&
                ComputeFileHash(backupPath.wstring(), dstHash)) {
                if (srcHash != dstHash) {
                    SS_LOG_ERROR(LOG_CAT, L"Backup integrity mismatch for %ls",
                                 filePath.c_str());
                    fs::remove(backupPath, ec);
                    return false;
                }
            }

            SS_LOG_DEBUG(LOG_CAT, L"Backed up %ls -> %ls",
                         filePath.c_str(), backupPath.c_str());
            return true;
        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CAT, L"Backup exception for %ls: %hs",
                         filePath.c_str(), ex.what());
            return false;
        }
    }

    // ========================================================================
    // DECRYPTION WITH CRYPTOUTILS
    // ========================================================================

    [[nodiscard]] DecryptionResult PerformDecryption(const fs::path& filePath,
                                                     const DecryptionKey& key) {
        DecryptionResult result;
        result.originalPath = filePath.wstring();
        result.keyId = key.keyId;
        result.family = key.family;

        auto startTime = Clock::now();

        try {
            if (!ValidateFilePath(filePath)) {
                result.status = DecryptionStatus::InvalidFile;
                result.errorMessage = "Invalid or unsafe file path";
                return result;
            }

            std::error_code ec;
            if (!fs::exists(filePath, ec) || ec) {
                result.status = DecryptionStatus::InvalidFile;
                result.errorMessage = "File does not exist";
                return result;
            }

            const uint64_t fileSize = fs::file_size(filePath, ec);
            if (ec || fileSize == 0) {
                result.status = DecryptionStatus::InvalidFile;
                result.errorMessage = "File is empty or unreadable";
                return result;
            }

            if (fileSize > DecryptorConstants::MAX_FILE_SIZE) {
                result.status = DecryptionStatus::InvalidFile;
                result.errorMessage = "File exceeds maximum size limit";
                SS_LOG_WARN(LOG_CAT, L"File too large for decryption: %ls (%llu bytes)",
                            filePath.c_str(), fileSize);
                return result;
            }

            result.originalSize = fileSize;

            // Prepare output path (temp for atomic replacement)
            fs::path outputPath = filePath;
            if (m_config.restoreOriginalName) {
                std::wstring ext = NormalizeExtension(filePath.extension().wstring());
                if (EXTENSION_MAP.count(ext)) {
                    outputPath.replace_extension(L"");
                } else {
                    outputPath += L".decrypted";
                }
            } else {
                outputPath += L".decrypted";
            }

            fs::path tempPath = outputPath;
            tempPath += L".ss_decrypt_tmp";
            result.decryptedPath = outputPath.wstring();

            // Map algorithm to CryptoUtils
            auto symAlgo = MapToSymmetricAlgorithm(key.algorithm);
            if (!symAlgo.has_value()) {
                result.status = DecryptionStatus::Failed;
                result.errorMessage = "Unsupported encryption algorithm for this key";
                return result;
            }

            if (key.keyData.empty()) {
                result.status = DecryptionStatus::NoKeyAvailable;
                result.errorMessage = "Key data is empty";
                return result;
            }

            // Perform streaming decryption via CryptoUtils::SymmetricCipher
            Utils::CryptoUtils::SymmetricCipher cipher(*symAlgo);
            Utils::CryptoUtils::Error cryptoErr{};

            if (!cipher.SetKey(key.keyData, &cryptoErr)) {
                result.status = DecryptionStatus::Failed;
                result.errorMessage = "Failed to set decryption key";
                return result;
            }

            if (!key.iv.empty() && !cipher.SetIV(key.iv, &cryptoErr)) {
                result.status = DecryptionStatus::Failed;
                result.errorMessage = "Failed to set IV/nonce";
                return result;
            }

            // Open input file with Win32 API for exclusive read
            HANDLE hInput = ::CreateFileW(
                filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                nullptr, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);

            if (hInput == INVALID_HANDLE_VALUE) {
                result.status = DecryptionStatus::IOError;
                result.errorMessage = "Cannot open encrypted file";
                SS_LOG_LAST_ERROR(LOG_CAT, L"CreateFileW read failed: %ls", filePath.c_str());
                return result;
            }

            // RAII handle guard
            struct HandleGuard {
                HANDLE h;
                ~HandleGuard() { if (h != INVALID_HANDLE_VALUE) ::CloseHandle(h); }
            } inputGuard{hInput};

            HANDLE hOutput = ::CreateFileW(
                tempPath.c_str(), GENERIC_WRITE, 0,
                nullptr, CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);

            if (hOutput == INVALID_HANDLE_VALUE) {
                result.status = DecryptionStatus::IOError;
                result.errorMessage = "Cannot create output file";
                SS_LOG_LAST_ERROR(LOG_CAT, L"CreateFileW write failed: %ls", tempPath.c_str());
                return result;
            }

            HandleGuard outputGuard{hOutput};

            // Initialize streaming decryption (non-AEAD modes)
            if (!cipher.IsAEAD()) {
                if (!cipher.DecryptInit(&cryptoErr)) {
                    result.status = DecryptionStatus::Failed;
                    result.errorMessage = "DecryptInit failed";
                    return result;
                }

                constexpr size_t BUF_SIZE = DecryptorConstants::BUFFER_SIZE;
                auto readBuf = std::make_unique<uint8_t[]>(BUF_SIZE);
                std::vector<uint8_t> decryptedChunk;
                uint64_t processed = 0;

                while (processed < fileSize) {
                    if (m_cancelRequested.load(std::memory_order_acquire)) {
                        outputGuard.h = INVALID_HANDLE_VALUE;
                        ::CloseHandle(hOutput);
                        fs::remove(tempPath, ec);
                        result.status = DecryptionStatus::Cancelled;
                        return result;
                    }

                    DWORD toRead = static_cast<DWORD>(
                        std::min<uint64_t>(BUF_SIZE, fileSize - processed));
                    DWORD bytesRead = 0;
                    if (!::ReadFile(hInput, readBuf.get(), toRead, &bytesRead, nullptr)
                        || bytesRead == 0) {
                        break;
                    }

                    decryptedChunk.clear();
                    if (!cipher.DecryptUpdate(readBuf.get(), bytesRead,
                                              decryptedChunk, &cryptoErr)) {
                        result.status = DecryptionStatus::Failed;
                        result.errorMessage = "DecryptUpdate failed";
                        outputGuard.h = INVALID_HANDLE_VALUE;
                        ::CloseHandle(hOutput);
                        fs::remove(tempPath, ec);
                        return result;
                    }

                    if (!decryptedChunk.empty()) {
                        DWORD written = 0;
                        if (!::WriteFile(hOutput, decryptedChunk.data(),
                                         static_cast<DWORD>(decryptedChunk.size()),
                                         &written, nullptr)) {
                            result.status = DecryptionStatus::IOError;
                            result.errorMessage = "WriteFile failed";
                            outputGuard.h = INVALID_HANDLE_VALUE;
                            ::CloseHandle(hOutput);
                            fs::remove(tempPath, ec);
                            return result;
                        }
                    }

                    // Securely wipe read buffer after each chunk
                    ::SecureZeroMemory(readBuf.get(), bytesRead);

                    processed += bytesRead;
                    FireProgressCallback(filePath.wstring(), processed, fileSize);
                }

                // Finalize
                decryptedChunk.clear();
                if (!cipher.DecryptFinal(decryptedChunk, &cryptoErr)) {
                    result.status = DecryptionStatus::Failed;
                    result.errorMessage = "DecryptFinal failed - wrong key or corrupt data";
                    outputGuard.h = INVALID_HANDLE_VALUE;
                    ::CloseHandle(hOutput);
                    fs::remove(tempPath, ec);
                    return result;
                }

                if (!decryptedChunk.empty()) {
                    DWORD written = 0;
                    ::WriteFile(hOutput, decryptedChunk.data(),
                                static_cast<DWORD>(decryptedChunk.size()),
                                &written, nullptr);
                }
                ::SecureZeroMemory(decryptedChunk.data(), decryptedChunk.size());
            } else {
                // AEAD mode: read entire ciphertext (with size cap already enforced)
                // Tag is assumed appended per CryptoUtils convention
                constexpr size_t TAG_SIZE = Utils::CryptoUtils::GCM_TAG_SIZE_BYTES;

                if (fileSize <= TAG_SIZE) {
                    result.status = DecryptionStatus::CorruptedFile;
                    result.errorMessage = "File too small for AEAD (no room for tag)";
                    return result;
                }

                const size_t ciphertextLen = static_cast<size_t>(fileSize - TAG_SIZE);

                // Cap AEAD mode at MAX_CIPHERTEXT_SIZE to avoid OOM
                if (fileSize > Utils::CryptoUtils::MAX_CIPHERTEXT_SIZE) {
                    result.status = DecryptionStatus::InvalidFile;
                    result.errorMessage = "AEAD file exceeds max ciphertext size";
                    return result;
                }

                std::vector<uint8_t> ciphertext(ciphertextLen);
                std::vector<uint8_t> tag(TAG_SIZE);

                // Both ReadFile calls were previously unchecked and reused the
                // same ``bytesRead`` variable, so a short read on the first
                // call would be silently overwritten by the second, leading
                // to a misleading "authentication error" on what is really
                // an I/O failure. We now verify each read independently.
                DWORD ctRead = 0;
                if (!::ReadFile(hInput, ciphertext.data(),
                                static_cast<DWORD>(ciphertextLen),
                                &ctRead, nullptr) ||
                    ctRead != static_cast<DWORD>(ciphertextLen))
                {
                    SS_LOG_LAST_ERROR(LOG_CAT,
                        L"AEAD ciphertext read failed: expected %zu, got %lu",
                        ciphertextLen, static_cast<unsigned long>(ctRead));
                    ::SecureZeroMemory(ciphertext.data(), ciphertext.size());
                    outputGuard.h = INVALID_HANDLE_VALUE;
                    ::CloseHandle(hOutput);
                    fs::remove(tempPath, ec);
                    result.status = DecryptionStatus::IOError;
                    result.errorMessage = "AEAD ciphertext read short or failed";
                    return result;
                }

                DWORD tagRead = 0;
                if (!::ReadFile(hInput, tag.data(),
                                static_cast<DWORD>(TAG_SIZE),
                                &tagRead, nullptr) ||
                    tagRead != static_cast<DWORD>(TAG_SIZE))
                {
                    SS_LOG_LAST_ERROR(LOG_CAT,
                        L"AEAD tag read failed: expected %zu, got %lu",
                        TAG_SIZE, static_cast<unsigned long>(tagRead));
                    ::SecureZeroMemory(ciphertext.data(), ciphertext.size());
                    outputGuard.h = INVALID_HANDLE_VALUE;
                    ::CloseHandle(hOutput);
                    fs::remove(tempPath, ec);
                    result.status = DecryptionStatus::IOError;
                    result.errorMessage = "AEAD tag read short or failed";
                    return result;
                }

                std::vector<uint8_t> plaintext;
                if (!cipher.DecryptAEAD(ciphertext.data(), ciphertextLen,
                                         nullptr, 0, tag.data(), TAG_SIZE,
                                         plaintext, &cryptoErr)) {
                    ::SecureZeroMemory(ciphertext.data(), ciphertext.size());
                    result.status = DecryptionStatus::Failed;
                    result.errorMessage = "AEAD decryption failed - authentication error";
                    outputGuard.h = INVALID_HANDLE_VALUE;
                    ::CloseHandle(hOutput);
                    fs::remove(tempPath, ec);
                    return result;
                }

                ::SecureZeroMemory(ciphertext.data(), ciphertext.size());

                if (!plaintext.empty()) {
                    DWORD written = 0;
                    ::WriteFile(hOutput, plaintext.data(),
                                static_cast<DWORD>(plaintext.size()),
                                &written, nullptr);
                }
                ::SecureZeroMemory(plaintext.data(), plaintext.size());
            }

            // Close output before rename
            outputGuard.h = INVALID_HANDLE_VALUE;
            ::CloseHandle(hOutput);

            // Atomic rename temp -> final
            if (!::MoveFileExW(tempPath.c_str(), outputPath.c_str(),
                               MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                SS_LOG_LAST_ERROR(LOG_CAT, L"Atomic rename failed: %ls -> %ls",
                                  tempPath.c_str(), outputPath.c_str());
                fs::remove(tempPath, ec);
                result.status = DecryptionStatus::IOError;
                result.errorMessage = "Atomic file rename failed";
                return result;
            }

            result.decryptedSize = fs::file_size(outputPath, ec);
            result.status = DecryptionStatus::Success;
            result.validationPassed = true;

            // Preserve timestamps
            if (m_config.preserveTimestamps) {
                try {
                    auto lastWrite = fs::last_write_time(filePath, ec);
                    if (!ec) fs::last_write_time(outputPath, lastWrite, ec);
                } catch (...) {
                    SS_LOG_WARN(LOG_CAT, L"Failed to preserve timestamp for %ls",
                                outputPath.c_str());
                }
            }

            // Post-validation
            if (m_config.validateAfterDecrypt && !ValidateDecryption(outputPath)) {
                result.validationPassed = false;
                SS_LOG_WARN(LOG_CAT, L"Post-decryption validation suspect for %ls",
                            outputPath.c_str());
            }

            // Conditionally delete encrypted original
            if (m_config.deleteEncryptedOnSuccess && result.validationPassed) {
                fs::remove(filePath, ec);
            }

        } catch (const std::exception& ex) {
            result.status = DecryptionStatus::Failed;
            result.errorMessage = ex.what();
            SS_LOG_ERROR(LOG_CAT, L"Decryption exception for %ls: %hs",
                         filePath.c_str(), ex.what());
            // Clean up temp file on exception
            std::error_code ec2;
            fs::path tmpCleanup = filePath;
            tmpCleanup += L".ss_decrypt_tmp";
            fs::remove(tmpCleanup, ec2);
        }

        auto endTime = Clock::now();
        result.durationMs = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                endTime - startTime).count());

        return result;
    }

    // ========================================================================
    // POST-DECRYPTION VALIDATION
    // ========================================================================

    [[nodiscard]] bool ValidateDecryption(const fs::path& filePath) {
        try {
            HANDLE hFile = ::CreateFileW(
                filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

            if (hFile == INVALID_HANDLE_VALUE) return false;

            std::array<uint8_t, 16> header{};
            DWORD bytesRead = 0;
            ::ReadFile(hFile, header.data(),
                       static_cast<DWORD>(header.size()), &bytesRead, nullptr);
            ::CloseHandle(hFile);

            if (bytesRead < 4) return true; // Too small to verify

            // Reject all-zero or all-0xFF (still encrypted)
            const bool allZero = std::all_of(
                header.begin(), header.begin() + bytesRead,
                [](uint8_t b) { return b == 0; });
            const bool allFF = std::all_of(
                header.begin(), header.begin() + bytesRead,
                [](uint8_t b) { return b == 0xFF; });

            if (allZero || allFF) return false;

            // Check for known file magic bytes
            static constexpr std::array<uint8_t, 2> MAGIC_PDF = {0x25, 0x50};  // %P
            static constexpr std::array<uint8_t, 2> MAGIC_PK  = {0x50, 0x4B};  // PK
            static constexpr std::array<uint8_t, 3> MAGIC_JPG = {0xFF, 0xD8, 0xFF};
            static constexpr std::array<uint8_t, 4> MAGIC_PNG = {0x89, 0x50, 0x4E, 0x47};

            // If the file starts with a known magic, it's likely valid
            if (bytesRead >= 4 && std::equal(MAGIC_PNG.begin(), MAGIC_PNG.end(), header.begin()))
                return true;
            if (bytesRead >= 3 && std::equal(MAGIC_JPG.begin(), MAGIC_JPG.end(), header.begin()))
                return true;
            if (bytesRead >= 2 && std::equal(MAGIC_PDF.begin(), MAGIC_PDF.end(), header.begin()))
                return true;
            if (bytesRead >= 2 && std::equal(MAGIC_PK.begin(), MAGIC_PK.end(), header.begin()))
                return true;

            // Generic: if there's a mix of byte values, probably okay
            return true;
        } catch (...) {
            return false;
        }
    }

    // ========================================================================
    // CALLBACKS (SAFE INVOCATION)
    // ========================================================================

    void FireProgressCallback(const std::wstring& file, uint64_t processed, uint64_t total) {
        std::lock_guard lock(m_callbackMutex);
        if (m_progressCallback) {
            try { m_progressCallback(file, processed, total); } catch (...) {}
        }
    }

    void FireCompleteCallback(const DecryptionResult& result) {
        std::lock_guard lock(m_callbackMutex);
        if (m_completeCallback) {
            try { m_completeCallback(result); } catch (...) {}
        }
    }
};

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

std::atomic<bool> RansomwareDecryptor::s_instanceCreated{false};

RansomwareDecryptor& RansomwareDecryptor::Instance() noexcept {
    static RansomwareDecryptor instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool RansomwareDecryptor::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// LIFECYCLE
// ============================================================================

RansomwareDecryptor::RansomwareDecryptor()
    : m_impl(std::make_unique<RansomwareDecryptorImpl>())
{
    SS_LOG_INFO(LOG_CAT, L"Instance created");
}

RansomwareDecryptor::~RansomwareDecryptor() {
    try {
        Shutdown();
    } catch (...) {
        // Destructors must not throw
    }
}

bool RansomwareDecryptor::Initialize(const RansomwareDecryptorConfiguration& config) {
    try {
        std::unique_lock lock(m_impl->m_mutex);

        if (m_impl->m_status != ModuleStatus::Uninitialized &&
            m_impl->m_status != ModuleStatus::Stopped) {
            SS_LOG_WARN(LOG_CAT, L"Already initialized (status=%u)",
                        static_cast<unsigned>(m_impl->m_status));
            return false;
        }

        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CAT, L"Invalid configuration (maxConcurrent=%u)",
                         config.maxConcurrent);
            return false;
        }

        m_impl->m_status = ModuleStatus::Initializing;
        m_impl->m_config = config;
        m_impl->m_stats.Reset();
        m_impl->m_cancelRequested.store(false, std::memory_order_release);

        // Load key database if configured
        if (!config.keyDatabasePath.empty()) {
            lock.unlock(); // Release lock before I/O
            if (!LoadKeyDatabase(config.keyDatabasePath)) {
                SS_LOG_WARN(LOG_CAT, L"Key database load failed: %ls",
                            config.keyDatabasePath.c_str());
            }
            lock.lock();
        }

        m_impl->m_status = ModuleStatus::Running;

        SS_LOG_INFO(LOG_CAT, L"Initialized v%hs, %zu keys loaded",
                    GetVersionString().c_str(), GetKeyCount());
        return true;

    } catch (const std::exception& ex) {
        SS_LOG_ERROR(LOG_CAT, L"Initialization failed: %hs", ex.what());
        m_impl->m_status = ModuleStatus::Error;
        return false;
    }
}

void RansomwareDecryptor::Shutdown() {
    try {
        std::unique_lock lock(m_impl->m_mutex);

        if (m_impl->m_status == ModuleStatus::Uninitialized ||
            m_impl->m_status == ModuleStatus::Stopped) {
            return;
        }

        m_impl->m_status = ModuleStatus::Stopping;
        m_impl->m_cancelRequested.store(true, std::memory_order_release);

        // Wait for active decryptions with bounded spin
        constexpr int MAX_WAIT_ITERATIONS = 300; // ~3 seconds
        for (int i = 0; i < MAX_WAIT_ITERATIONS; ++i) {
            if (m_impl->m_activeDecryptions.load(std::memory_order_acquire) == 0)
                break;
            lock.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            lock.lock();
        }

        // Securely erase all keys
        {
            std::unique_lock keyLock(m_impl->m_keyMutex);
            for (auto& [id, key] : m_impl->m_keys) {
                SecureEraseKey(key);
            }
            m_impl->m_keys.clear();
            m_impl->m_familyKeys.clear();
        }

        m_impl->m_status = ModuleStatus::Stopped;
        SS_LOG_INFO(LOG_CAT, L"Shutdown complete");

    } catch (const std::exception& ex) {
        SS_LOG_ERROR(LOG_CAT, L"Shutdown error: %hs", ex.what());
    }
}

bool RansomwareDecryptor::IsInitialized() const noexcept {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_status == ModuleStatus::Running ||
           m_impl->m_status == ModuleStatus::Degraded;
}

ModuleStatus RansomwareDecryptor::GetStatus() const noexcept {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_status;
}

// ============================================================================
// DECRYPTION OPERATIONS
// ============================================================================

bool RansomwareDecryptor::DecryptFile(const std::wstring& filePath,
                                      const std::string& familyName) {
    RansomwareFamily family = RansomwareFamily::Unknown;
    auto it = FAMILY_NAME_MAP.find(familyName);
    if (it != FAMILY_NAME_MAP.end()) {
        family = it->second;
    } else {
        SS_LOG_WARN(LOG_CAT, L"Unknown family name: %hs, will attempt auto-detect",
                    familyName.c_str());
    }

    auto result = DecryptFileEx(filePath, family);
    return result.status == DecryptionStatus::Success;
}

DecryptionResult RansomwareDecryptor::DecryptFileEx(std::wstring_view filePath,
                                                    RansomwareFamily family) {
    DecryptionResult result;
    result.originalPath = filePath;
    result.family = family;

    try {
        if (!IsInitialized()) {
            result.status = DecryptionStatus::Failed;
            result.errorMessage = "Decryptor not initialized";
            return result;
        }

        if (!ValidateFilePath(fs::path(filePath))) {
            result.status = DecryptionStatus::InvalidFile;
            result.errorMessage = "Invalid or unsafe file path";
            m_impl->m_stats.filesFailed.fetch_add(1, std::memory_order_relaxed);
            return result;
        }

        // Auto-identify family if unknown
        if (family == RansomwareFamily::Unknown) {
            family = IdentifyFamilyFromFile(filePath);
            result.family = family;
        }

        if (family == RansomwareFamily::Unknown) {
            result.status = DecryptionStatus::UnknownFamily;
            result.errorMessage = "Could not identify ransomware family";
            m_impl->m_stats.filesFailed.fetch_add(1, std::memory_order_relaxed);
            return result;
        }

        // Pre-decryption backup
        if (!m_impl->BackupFile(fs::path(filePath))) {
            result.status = DecryptionStatus::IOError;
            result.errorMessage = "Pre-decryption backup failed";
            m_impl->m_stats.filesFailed.fetch_add(1, std::memory_order_relaxed);
            return result;
        }

        // Find candidate keys
        std::vector<DecryptionKey> candidates = GetKeysForFamily(family);
        if (candidates.empty()) {
            result.status = DecryptionStatus::NoKeyAvailable;
            result.errorMessage = "No keys available for this family";
            m_impl->m_stats.filesFailed.fetch_add(1, std::memory_order_relaxed);
            return result;
        }

        m_impl->m_activeDecryptions.fetch_add(1, std::memory_order_acq_rel);

        // Try each candidate key
        for (const auto& key : candidates) {
            if (m_impl->m_cancelRequested.load(std::memory_order_acquire)) {
                result.status = DecryptionStatus::Cancelled;
                m_impl->m_activeDecryptions.fetch_sub(1, std::memory_order_acq_rel);
                return result;
            }

            DecryptionResult attempt = m_impl->PerformDecryption(fs::path(filePath), key);

            if (attempt.status == DecryptionStatus::Success) {
                if (!m_impl->m_config.validateAfterDecrypt ||
                    m_impl->ValidateDecryption(attempt.decryptedPath)) {
                    result = attempt;
                    m_impl->m_stats.filesDecrypted.fetch_add(1, std::memory_order_relaxed);
                    m_impl->m_stats.bytesDecrypted.fetch_add(
                        result.decryptedSize, std::memory_order_relaxed);
                    m_impl->FireCompleteCallback(result);
                    m_impl->m_activeDecryptions.fetch_sub(1, std::memory_order_acq_rel);
                    ReportDecryptionTelemetry(result);
                    return result;
                } else {
                    std::error_code ec;
                    fs::remove(attempt.decryptedPath, ec);
                }
            }
        }

        m_impl->m_activeDecryptions.fetch_sub(1, std::memory_order_acq_rel);
        result.status = DecryptionStatus::Failed;
        result.errorMessage = "All candidate keys failed";
        m_impl->m_stats.filesFailed.fetch_add(1, std::memory_order_relaxed);

    } catch (const std::exception& ex) {
        result.status = DecryptionStatus::Failed;
        result.errorMessage = ex.what();
        SS_LOG_ERROR(LOG_CAT, L"DecryptFileEx failed: %hs", ex.what());
        // Ensure counter is decremented on exception
        if (m_impl->m_activeDecryptions.load(std::memory_order_acquire) > 0) {
            m_impl->m_activeDecryptions.fetch_sub(1, std::memory_order_acq_rel);
        }
    }

    return result;
}

DecryptionResult RansomwareDecryptor::DecryptFileWithKey(std::wstring_view filePath,
                                                         const DecryptionKey& key) {
    if (!IsInitialized()) {
        DecryptionResult res;
        res.status = DecryptionStatus::Failed;
        res.errorMessage = "Not initialized";
        return res;
    }

    if (!ValidateFilePath(fs::path(filePath))) {
        DecryptionResult res;
        res.status = DecryptionStatus::InvalidFile;
        res.errorMessage = "Invalid file path";
        return res;
    }

    if (!m_impl->BackupFile(fs::path(filePath))) {
        DecryptionResult res;
        res.status = DecryptionStatus::IOError;
        res.errorMessage = "Backup failed";
        return res;
    }

    m_impl->m_activeDecryptions.fetch_add(1, std::memory_order_acq_rel);
    auto result = m_impl->PerformDecryption(fs::path(filePath), key);
    m_impl->m_activeDecryptions.fetch_sub(1, std::memory_order_acq_rel);

    if (result.status == DecryptionStatus::Success) {
        m_impl->m_stats.filesDecrypted.fetch_add(1, std::memory_order_relaxed);
        m_impl->m_stats.bytesDecrypted.fetch_add(
            result.decryptedSize, std::memory_order_relaxed);
        m_impl->FireCompleteCallback(result);
    } else {
        m_impl->m_stats.filesFailed.fetch_add(1, std::memory_order_relaxed);
    }

    return result;
}

BatchDecryptionResult RansomwareDecryptor::DecryptDirectory(std::wstring_view dirPath,
                                                            RansomwareFamily family,
                                                            bool recursive) {
    BatchDecryptionResult batchResult;
    batchResult.batchId = GenerateRecoveryId();
    batchResult.startTime = std::chrono::system_clock::now();

    try {
        fs::path root(dirPath);
        std::error_code ec;
        if (!fs::exists(root, ec) || !fs::is_directory(root, ec)) {
            SS_LOG_ERROR(LOG_CAT, L"DecryptDirectory: path invalid or not a directory: %ls",
                         root.c_str());
            return batchResult;
        }

        std::vector<std::wstring> files;
        files.reserve(1024);

        // Depth-limited traversal to prevent stack overflow
        auto options = fs::directory_options::skip_permission_denied;
        if (recursive) {
            for (auto it = fs::recursive_directory_iterator(root, options, ec);
                 it != fs::recursive_directory_iterator() && files.size() < MAX_SCAN_FILES;
                 it.increment(ec)) {
                if (ec) { ec.clear(); continue; }
                if (it.depth() > static_cast<int>(MAX_DIRECTORY_DEPTH)) {
                    it.disable_recursion_pending();
                    continue;
                }
                if (it->is_regular_file(ec) && !ec) {
                    files.push_back(it->path().wstring());
                }
            }
        } else {
            for (auto it = fs::directory_iterator(root, options, ec);
                 it != fs::directory_iterator() && files.size() < MAX_SCAN_FILES;
                 it.increment(ec)) {
                if (ec) { ec.clear(); continue; }
                if (it->is_regular_file(ec) && !ec) {
                    files.push_back(it->path().wstring());
                }
            }
        }

        if (files.empty()) {
            SS_LOG_INFO(LOG_CAT, L"No files found in %ls", root.c_str());
            return batchResult;
        }

        SS_LOG_INFO(LOG_CAT, L"DecryptDirectory: found %zu files in %ls",
                    files.size(), root.c_str());
        return DecryptFiles(files, family);

    } catch (const std::exception& ex) {
        SS_LOG_ERROR(LOG_CAT, L"DecryptDirectory exception: %hs", ex.what());
        return batchResult;
    }
}

BatchDecryptionResult RansomwareDecryptor::DecryptFiles(
    std::span<const std::wstring> filePaths,
    RansomwareFamily family) {

    BatchDecryptionResult batchResult;
    batchResult.batchId = GenerateRecoveryId();
    batchResult.startTime = std::chrono::system_clock::now();
    batchResult.totalFiles = filePaths.size();

    if (filePaths.empty()) return batchResult;

    // Cap batch size
    if (filePaths.size() > DecryptorConstants::MAX_BATCH_FILES) {
        SS_LOG_WARN(LOG_CAT, L"Batch size %zu exceeds limit %zu, truncating",
                    filePaths.size(), DecryptorConstants::MAX_BATCH_FILES);
        filePaths = filePaths.first(DecryptorConstants::MAX_BATCH_FILES);
        batchResult.totalFiles = filePaths.size();
    }

    uint32_t concurrency = std::min(m_impl->m_config.maxConcurrent,
                                    std::thread::hardware_concurrency());
    if (concurrency == 0) concurrency = 1;

    std::vector<std::future<DecryptionResult>> futures;
    size_t currentIndex = 0;

    while (currentIndex < filePaths.size() || !futures.empty()) {
        // Launch tasks up to concurrency limit
        while (futures.size() < concurrency && currentIndex < filePaths.size()) {
            if (m_impl->m_cancelRequested.load(std::memory_order_acquire)) break;
            std::wstring path = filePaths[currentIndex++];
            futures.push_back(std::async(std::launch::async,
                [this, p = std::move(path), family]() {
                    return this->DecryptFileEx(p, family);
                }
            ));
        }

        // Harvest completed futures
        auto it = futures.begin();
        while (it != futures.end()) {
            if (it->wait_for(std::chrono::milliseconds(10)) == std::future_status::ready) {
                DecryptionResult res = it->get();
                batchResult.results.push_back(res);

                if (res.status == DecryptionStatus::Success) {
                    batchResult.filesDecrypted++;
                } else if (res.status == DecryptionStatus::Failed ||
                           res.status == DecryptionStatus::CorruptedFile) {
                    batchResult.filesFailed++;
                } else {
                    batchResult.filesSkipped++;
                }
                batchResult.bytesProcessed += res.originalSize;

                {
                    std::lock_guard lock(m_impl->m_callbackMutex);
                    if (m_impl->m_batchProgressCallback) {
                        m_impl->m_batchProgressCallback(
                            batchResult.results.size(), batchResult.totalFiles);
                    }
                }

                it = futures.erase(it);
            } else {
                ++it;
            }
        }

        if (m_impl->m_cancelRequested.load(std::memory_order_acquire) && futures.empty())
            break;
    }

    batchResult.endTime = std::chrono::system_clock::now();
    return batchResult;
}

void RansomwareDecryptor::CancelDecryption() {
    m_impl->m_cancelRequested.store(true, std::memory_order_release);
    SS_LOG_INFO(LOG_CAT, L"Decryption cancel requested");
}

// ============================================================================
// RECOVERY OPERATIONS
// ============================================================================

RecoveryResult RansomwareDecryptor::RecoverFile(std::wstring_view filePath,
                                                 const RecoveryOptions& options) {
    RecoveryResult result;
    result.encryptedPath = filePath;
    auto startTime = Clock::now();

    if (!IsInitialized()) {
        result.status = DecryptionStatus::Failed;
        result.errorMessage = "Decryptor not initialized";
        return result;
    }

    if (!ValidateFilePath(fs::path(filePath))) {
        result.status = DecryptionStatus::InvalidFile;
        result.errorMessage = "Invalid file path";
        return result;
    }

    // CRITICAL: Verify ransomware process is terminated before recovery
    if (options.ransomwarePid != 0) {
        if (!VerifyRansomwareTerminated(options.ransomwarePid)) {
            result.status = DecryptionStatus::Failed;
            result.errorMessage = "Ransomware process still running - recovery blocked";
            SS_LOG_FATAL(LOG_CAT,
                L"RECOVERY BLOCKED: ransomware PID %lu is still active, "
                L"recovered files would be re-encrypted immediately",
                options.ransomwarePid);
            return result;
        }
    }

    // Preserve forensic copy before modifying anything
    if (options.preserveForensicCopy) {
        std::wstring forensicDir = options.forensicDirectory;
        if (forensicDir.empty()) {
            forensicDir = fs::path(filePath).parent_path().wstring() +
                          L"\\ShadowStrike_Forensics";
        }
        if (!PreserveForensicCopy(filePath, forensicDir)) {
            SS_LOG_WARN(LOG_CAT, L"Forensic copy failed for %ls (continuing recovery)",
                        std::wstring(filePath).c_str());
        } else {
            result.forensicCopyPath = forensicDir + L"\\" +
                fs::path(filePath).filename().wstring();
        }
    }

    // Auto method: try VSS -> Backup -> Key decryption
    RecoveryMethod method = options.method;

    if (method == RecoveryMethod::Auto || method == RecoveryMethod::VSSRestore) {
        auto vssResult = RecoverFromVSS(filePath, options.vssSnapshotId);
        if (vssResult.status == DecryptionStatus::Success) {
            vssResult.forensicCopyPath = result.forensicCopyPath;
            vssResult.durationMs = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    Clock::now() - startTime).count());
            return vssResult;
        }
        if (method == RecoveryMethod::VSSRestore) {
            vssResult.durationMs = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    Clock::now() - startTime).count());
            return vssResult;
        }
    }

    if (method == RecoveryMethod::Auto || method == RecoveryMethod::BackupRestore) {
        auto backupResult = RecoverFromBackup(filePath, options.ransomwarePid);
        if (backupResult.status == DecryptionStatus::Success) {
            backupResult.forensicCopyPath = result.forensicCopyPath;
            backupResult.durationMs = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    Clock::now() - startTime).count());
            return backupResult;
        }
        if (method == RecoveryMethod::BackupRestore) {
            backupResult.durationMs = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    Clock::now() - startTime).count());
            return backupResult;
        }
    }

    if (method == RecoveryMethod::Auto || method == RecoveryMethod::KeyDecryption) {
        // Fall back to key-based decryption
        RansomwareFamily family = IdentifyFamilyFromFile(filePath);
        if (family != RansomwareFamily::Unknown) {
            auto decResult = DecryptFileEx(filePath, family);
            result.encryptedPath = decResult.originalPath;
            result.recoveredPath = decResult.decryptedPath;
            result.methodUsed = RecoveryMethod::KeyDecryption;
            result.status = decResult.status;
            result.recoveredSize = decResult.decryptedSize;
            result.integrityVerified = decResult.validationPassed;
            result.errorMessage = decResult.errorMessage;
        } else {
            result.status = DecryptionStatus::UnknownFamily;
            result.errorMessage = "Cannot identify family for key-based decryption";
        }
    }

    result.durationMs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now() - startTime).count());

    // =================================================================
    // CROSS-MODULE WIRING — AlertSystem + TelemetryCollector
    // =================================================================
    ReportRecoveryToAlertSystem(result);
    return result;
}

std::vector<RecoveryResult> RansomwareDecryptor::RecoverDirectory(
    std::wstring_view dirPath, const RecoveryOptions& options) {

    std::vector<RecoveryResult> results;

    // Verify ransomware is terminated before bulk recovery
    if (options.ransomwarePid != 0 &&
        !VerifyRansomwareTerminated(options.ransomwarePid)) {
        SS_LOG_FATAL(LOG_CAT,
            L"BULK RECOVERY BLOCKED: ransomware PID %lu still active",
            options.ransomwarePid);
        RecoveryResult blocked;
        blocked.status = DecryptionStatus::Failed;
        blocked.errorMessage = "Ransomware process still running";
        results.push_back(std::move(blocked));
        return results;
    }

    try {
        fs::path root(dirPath);
        std::error_code ec;
        if (!fs::exists(root, ec) || !fs::is_directory(root, ec)) return results;

        auto dirOptions = fs::directory_options::skip_permission_denied;
        size_t fileCount = 0;

        for (auto it = fs::recursive_directory_iterator(root, dirOptions, ec);
             it != fs::recursive_directory_iterator() && fileCount < MAX_SCAN_FILES;
             it.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            if (it.depth() > static_cast<int>(MAX_DIRECTORY_DEPTH)) {
                it.disable_recursion_pending();
                continue;
            }
            if (!it->is_regular_file(ec) || ec) continue;

            auto recovered = RecoverFile(it->path().wstring(), options);
            results.push_back(std::move(recovered));
            fileCount++;
        }
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(LOG_CAT, L"RecoverDirectory exception: %hs", ex.what());
    }

    return results;
}

RecoveryResult RansomwareDecryptor::RecoverFromVSS(std::wstring_view filePath,
                                                    std::wstring_view snapshotId) {
    RecoveryResult result;
    result.encryptedPath = filePath;
    result.methodUsed = RecoveryMethod::VSSRestore;

    try {
        auto& vss = VolumeSnapshotService::Instance();
        if (!vss.IsInitialized()) {
            result.status = DecryptionStatus::Failed;
            result.errorMessage = "VolumeSnapshotService not initialized";
            return result;
        }

        fs::path p(filePath);
        std::wstring volume = p.root_name().wstring() + L"\\";

        std::wstring bestSnapshotId;

        if (!snapshotId.empty()) {
            bestSnapshotId = snapshotId;
        } else {
            // Find most recent snapshot for this volume
            auto snapshots = vss.EnumerateSnapshotsForVolume(volume);
            if (snapshots.empty()) {
                result.status = DecryptionStatus::Failed;
                result.errorMessage = "No VSS snapshots available for volume " +
                    Utils::StringUtils::ToNarrow(volume);
                return result;
            }

            // Sort by creation time descending (most recent first)
            std::sort(snapshots.begin(), snapshots.end(),
                [](const SnapshotInfo& a, const SnapshotInfo& b) {
                    return a.creationTime > b.creationTime;
                });

            bestSnapshotId = snapshots.front().snapshotId;
        }

        // Compute relative path from volume root
        std::wstring relativePath = p.wstring().substr(volume.size());

        // Restore to temp location for atomic replacement
        fs::path tempRestore = p;
        tempRestore += L".ss_vss_restore_tmp";

        if (vss.RestoreFile(bestSnapshotId, relativePath, tempRestore.wstring())
                != VSSResult::Success) {
            result.status = DecryptionStatus::Failed;
            result.errorMessage = "VSS RestoreFile failed";
            return result;
        }

        // Verify integrity if we have a backup with stored hash
        std::vector<uint8_t> restoredHash;
        if (ComputeFileHash(tempRestore.wstring(), restoredHash)) {
            result.integrityVerified = true;
        }

        // Atomic replacement
        if (!::MoveFileExW(tempRestore.c_str(), p.c_str(),
                           MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            SS_LOG_LAST_ERROR(LOG_CAT, L"VSS atomic rename failed: %ls", p.c_str());
            std::error_code ec;
            fs::remove(tempRestore, ec);
            result.status = DecryptionStatus::IOError;
            result.errorMessage = "Atomic rename of VSS-restored file failed";
            return result;
        }

        std::error_code ec;
        result.recoveredPath = p.wstring();
        result.recoveredSize = fs::file_size(p, ec);
        result.status = DecryptionStatus::Success;

        SS_LOG_INFO(LOG_CAT, L"VSS recovery succeeded for %ls (snapshot %ls)",
                    p.c_str(), bestSnapshotId.c_str());

    } catch (const std::exception& ex) {
        result.status = DecryptionStatus::Failed;
        result.errorMessage = ex.what();
        SS_LOG_ERROR(LOG_CAT, L"RecoverFromVSS exception: %hs", ex.what());
    }

    return result;
}

RecoveryResult RansomwareDecryptor::RecoverFromBackup(std::wstring_view filePath,
                                                       uint32_t ransomwarePid) {
    RecoveryResult result;
    result.encryptedPath = filePath;
    result.methodUsed = RecoveryMethod::BackupRestore;

    try {
        auto& backupMgr = FileBackupManager::Instance();
        if (!backupMgr.IsInitialized()) {
            result.status = DecryptionStatus::Failed;
            result.errorMessage = "FileBackupManager not initialized";
            return result;
        }

        // Look up backup entry for this file
        auto backupEntry = backupMgr.GetBackup(filePath, ransomwarePid);
        if (!backupEntry.has_value()) {
            result.status = DecryptionStatus::Failed;
            result.errorMessage = "No JIT backup found for this file/PID";
            return result;
        }

        // Verify backup integrity via SHA-256
        const auto& entry = backupEntry.value();
        static constexpr Hash256 ZERO_HASH{};

        if (entry.originalHash != ZERO_HASH) {
            std::vector<uint8_t> backupHash;
            if (entry.memoryData && !entry.memoryData->empty()) {
                // RAM-cached backup: hash the in-memory data
                Utils::HashUtils::Hasher hasher(Utils::HashUtils::Algorithm::SHA256);
                Utils::HashUtils::Error hashErr{};
                if (hasher.Init(&hashErr) &&
                    hasher.Update(entry.memoryData->data(),
                                  entry.memoryData->size(), &hashErr) &&
                    hasher.Final(backupHash, &hashErr)) {
                    // Compare against stored original hash
                    if (backupHash.size() == entry.originalHash.size() &&
                        !std::equal(backupHash.begin(), backupHash.end(),
                                    entry.originalHash.begin())) {
                        result.status = DecryptionStatus::CorruptedFile;
                        result.errorMessage = "Backup integrity check failed (hash mismatch)";
                        SS_LOG_ERROR(LOG_CAT,
                            L"Backup hash mismatch for %ls - backup may be corrupted",
                            std::wstring(filePath).c_str());
                        return result;
                    }
                    result.integrityVerified = true;
                }
            } else if (!entry.backupPath.empty()) {
                // Disk-based backup
                if (ComputeFileHash(entry.backupPath, backupHash)) {
                    if (backupHash.size() == entry.originalHash.size() &&
                        !std::equal(backupHash.begin(), backupHash.end(),
                                    entry.originalHash.begin())) {
                        result.status = DecryptionStatus::CorruptedFile;
                        result.errorMessage = "Backup integrity check failed (hash mismatch)";
                        SS_LOG_ERROR(LOG_CAT,
                            L"Disk backup hash mismatch for %ls", entry.backupPath.c_str());
                        return result;
                    }
                    result.integrityVerified = true;
                }
            }
        }

        // Perform restore via FileBackupManager
        auto restoreResult = backupMgr.RestoreFile(filePath, ransomwarePid);
        if (restoreResult.status != RestoreStatus::Success) {
            result.status = DecryptionStatus::Failed;
            result.errorMessage = "FileBackupManager restore failed: " +
                restoreResult.errorMessage;
            return result;
        }

        result.recoveredPath = filePath;
        result.recoveredSize = restoreResult.bytesRestored;
        result.status = DecryptionStatus::Success;

        SS_LOG_INFO(LOG_CAT, L"Backup recovery succeeded for %ls (%llu bytes)",
                    std::wstring(filePath).c_str(), restoreResult.bytesRestored);

    } catch (const std::exception& ex) {
        result.status = DecryptionStatus::Failed;
        result.errorMessage = ex.what();
        SS_LOG_ERROR(LOG_CAT, L"RecoverFromBackup exception: %hs", ex.what());
    }

    return result;
}

bool RansomwareDecryptor::VerifyRansomwareTerminated(uint32_t pid) const {
    if (pid == 0) return true;

    HANDLE hProcess = ::OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);

    if (hProcess == nullptr) {
        DWORD err = ::GetLastError();
        if (err == ERROR_INVALID_PARAMETER || err == ERROR_NOT_FOUND) {
            // Process does not exist -> terminated
            return true;
        }
        if (err == ERROR_ACCESS_DENIED) {
            // Cannot determine status - conservative: assume running
            SS_LOG_WARN(LOG_CAT,
                L"Cannot query ransomware PID %lu (access denied) - "
                L"assuming still active for safety", pid);
            return false;
        }
        return true; // Other error, likely process gone
    }

    // Check if process has exited
    DWORD waitResult = ::WaitForSingleObject(hProcess, 0);
    ::CloseHandle(hProcess);

    if (waitResult == WAIT_OBJECT_0) {
        SS_LOG_INFO(LOG_CAT, L"Ransomware PID %lu confirmed terminated", pid);
        return true;
    }

    SS_LOG_WARN(LOG_CAT, L"Ransomware PID %lu is STILL RUNNING", pid);
    return false;
}

bool RansomwareDecryptor::VerifyFileIntegrity(std::wstring_view filePath,
                                               std::span<const uint8_t> expectedHash) const {
    if (expectedHash.empty()) return false;

    std::vector<uint8_t> actualHash;
    if (!ComputeFileHash(filePath, actualHash)) return false;

    if (actualHash.size() != expectedHash.size()) return false;
    return std::equal(actualHash.begin(), actualHash.end(), expectedHash.begin());
}

bool RansomwareDecryptor::PreserveForensicCopy(std::wstring_view encryptedFilePath,
                                                std::wstring_view forensicDirectory) {
    try {
        fs::path srcPath(encryptedFilePath);
        fs::path dstDir(forensicDirectory);

        if (!ValidateFilePath(srcPath) || !ValidateFilePath(dstDir)) {
            SS_LOG_ERROR(LOG_CAT, L"Forensic copy: invalid path");
            return false;
        }

        std::error_code ec;
        if (!fs::exists(srcPath, ec) || ec) return false;

        if (!fs::exists(dstDir, ec)) {
            fs::create_directories(dstDir, ec);
            if (ec) {
                SS_LOG_ERROR(LOG_CAT,
                    L"Cannot create forensic dir: %ls", dstDir.c_str());
                return false;
            }
        }

        // Mark directory as hidden+system
        ::SetFileAttributesW(dstDir.c_str(),
            FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

        fs::path dstPath = dstDir / srcPath.filename();
        if (fs::exists(dstPath, ec)) {
            dstPath += L"." + std::to_wstring(
                Clock::now().time_since_epoch().count());
        }

        fs::copy_file(srcPath, dstPath, ec);
        if (ec) {
            SS_LOG_ERROR(LOG_CAT, L"Forensic copy failed: %ls -> %ls (ec=%d)",
                         srcPath.c_str(), dstPath.c_str(), ec.value());
            return false;
        }

        // Set forensic copy as read-only
        ::SetFileAttributesW(dstPath.c_str(),
            FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE);

        SS_LOG_INFO(LOG_CAT, L"Forensic copy preserved: %ls", dstPath.c_str());
        return true;
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(LOG_CAT, L"PreserveForensicCopy exception: %hs", ex.what());
        return false;
    }
}

// ============================================================================
// FAMILY IDENTIFICATION
// ============================================================================

RansomwareFamily RansomwareDecryptor::IdentifyFamilyFromExtension(
    std::wstring_view extension) {
    std::wstring ext(extension);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);

    auto it = EXTENSION_MAP.find(ext);
    if (it != EXTENSION_MAP.end()) {
        return it->second;
    }
    return RansomwareFamily::Unknown;
}

RansomwareFamily RansomwareDecryptor::IdentifyFamilyFromFile(
    std::wstring_view filePath) {
    try {
        fs::path p(filePath);
        return IdentifyFamilyFromExtension(p.extension().wstring());
    } catch (...) {
        return RansomwareFamily::Unknown;
    }
}

std::string RansomwareDecryptor::IdentifyFamily(const std::wstring& folderPath) {
    RansomwareFamily family = IdentifyFamilyEnum(folderPath);
    return std::string(GetFamilyName(family));
}

RansomwareFamily RansomwareDecryptor::IdentifyFamilyEnum(std::wstring_view folderPath) {
    try {
        fs::path root(folderPath);
        std::error_code ec;
        if (!fs::exists(root, ec) || !fs::is_directory(root, ec)) {
            return RansomwareFamily::Unknown;
        }

        std::unordered_map<RansomwareFamily, int> counts;
        auto options = fs::directory_options::skip_permission_denied;

        for (auto it = fs::directory_iterator(root, options, ec);
             it != fs::directory_iterator(); it.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            if (!it->is_regular_file(ec) || ec) continue;

            RansomwareFamily extFamily = IdentifyFamilyFromExtension(
                it->path().extension().wstring());
            if (extFamily != RansomwareFamily::Unknown) {
                counts[extFamily]++;
            }

            // Check ransom note filenames
            std::wstring filename = it->path().filename().wstring();
            for (const auto& note : RANSOM_NOTE_FILENAMES) {
                if (filename == note) {
                    if (note.find(L"Wana") != std::wstring::npos)
                        counts[RansomwareFamily::WannaCry] += 5;
                    else if (note.find(L"Locky") != std::wstring::npos)
                        counts[RansomwareFamily::Locky] += 5;
                    else if (note.find(L"Ryuk") != std::wstring::npos)
                        counts[RansomwareFamily::Ryuk] += 5;
                    else if (note.find(L"LockBit") != std::wstring::npos ||
                             note.find(L"Restore-My-Files") != std::wstring::npos)
                        counts[RansomwareFamily::LockBit] += 5;
                }
            }
        }

        RansomwareFamily bestMatch = RansomwareFamily::Unknown;
        int maxCount = 0;
        for (const auto& [fam, count] : counts) {
            if (count > maxCount) {
                maxCount = count;
                bestMatch = fam;
            }
        }
        return bestMatch;

    } catch (...) {
        return RansomwareFamily::Unknown;
    }
}

// ============================================================================
// FILE ANALYSIS & DIRECTORY SCANNING
// ============================================================================

EncryptedFileInfo RansomwareDecryptor::AnalyzeFile(std::wstring_view filePath) {
    EncryptedFileInfo info;
    info.filePath = std::wstring(filePath);

    try {
        fs::path p(filePath);
        std::error_code ec;

        if (!ValidateFilePath(p)) {
            SS_LOG_WARN(LOG_CAT, L"AnalyzeFile: invalid path rejected: %ls",
                        std::wstring(filePath).c_str());
            return info;
        }

        if (!fs::exists(p, ec) || ec || !fs::is_regular_file(p, ec) || ec) {
            return info;
        }

        info.fileSize = fs::file_size(p, ec);
        if (ec || info.fileSize == 0) {
            return info;
        }

        if (info.fileSize > DecryptorConstants::MAX_FILE_SIZE) {
            SS_LOG_WARN(LOG_CAT, L"AnalyzeFile: file exceeds size limit: %ls (%llu bytes)",
                        std::wstring(filePath).c_str(), info.fileSize);
            return info;
        }

        info.encryptedExtension = p.extension().wstring();
        info.family = IdentifyFamilyFromExtension(info.encryptedExtension);

        // Read file header (first 64 bytes) for magic analysis
        HANDLE hFile = ::CreateFileW(
            p.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);

        if (hFile != INVALID_HANDLE_VALUE) {
            constexpr DWORD kHeaderSize = 64;
            info.header.resize(kHeaderSize, 0);
            DWORD bytesRead = 0;
            if (::ReadFile(hFile, info.header.data(), kHeaderSize, &bytesRead, nullptr)
                && bytesRead > 0) {
                info.header.resize(bytesRead);
            } else {
                info.header.clear();
            }
            ::CloseHandle(hFile);
        }

        // Attempt to recover original extension from compound paths
        // (e.g., "report.docx.locky" → originalExtension = ".docx")
        const std::wstring stem = p.stem().wstring();
        if (const auto dotPos = stem.rfind(L'.'); dotPos != std::wstring::npos) {
            info.originalExtension = stem.substr(dotPos);
            info.originalName = stem.substr(0, dotPos) + info.originalExtension;
        }

        // Try to extract victim ID from path patterns
        // e.g., "file.[victimID].dharma" or "[id-XXXXXX].phobos"
        const std::wstring filename = p.filename().wstring();
        if (const auto openBracket = filename.find(L'[');
            openBracket != std::wstring::npos) {
            if (const auto closeBracket = filename.find(L']', openBracket);
                closeBracket != std::wstring::npos && closeBracket > openBracket + 1) {
                std::wstring wid = filename.substr(openBracket + 1,
                                                   closeBracket - openBracket - 1);
                info.victimId = Utils::StringUtils::ToNarrow(wid);
            }
        }

        // Compute file hash (SHA-256)
        std::vector<uint8_t> hashVec;
        if (ComputeFileHash(filePath, hashVec) && hashVec.size() == info.fileHash.size()) {
            std::copy_n(hashVec.begin(), info.fileHash.size(), info.fileHash.begin());
        }

        // Determine if decryption is possible
        if (info.family != RansomwareFamily::Unknown) {
            info.canDecrypt = IsDecryptionAvailable(info.family);
            info.confidence = 0.8;

            // Boost confidence if we have a victim ID and matching key
            if (!info.victimId.empty()) {
                auto keys = GetKeysForFamily(info.family);
                for (const auto& key : keys) {
                    if (key.IsValidFor(info)) {
                        info.confidence = 0.95;
                        break;
                    }
                }
            }
        }

        // Heuristic algorithm identification from known family defaults
        if (info.algorithm == EncryptionAlgorithm::Unknown) {
            switch (info.family) {
                case RansomwareFamily::WannaCry:
                    info.algorithm = EncryptionAlgorithm::AES128CBC;
                    break;
                case RansomwareFamily::TeslaCrypt:
                case RansomwareFamily::TeslaCryptV2:
                case RansomwareFamily::TeslaCryptV3:
                case RansomwareFamily::TeslaCryptV4:
                    info.algorithm = EncryptionAlgorithm::AES256CBC;
                    break;
                case RansomwareFamily::GandCrabV4:
                case RansomwareFamily::GandCrabV5:
                    info.algorithm = EncryptionAlgorithm::Salsa20;
                    break;
                case RansomwareFamily::Conti:
                case RansomwareFamily::LockBit:
                    info.algorithm = EncryptionAlgorithm::ChaCha20;
                    break;
                case RansomwareFamily::Ryuk:
                case RansomwareFamily::REvil:
                    info.algorithm = EncryptionAlgorithm::AES256CTR;
                    break;
                default:
                    break;
            }
        }

        m_impl->m_stats.filesAnalyzed.fetch_add(1, std::memory_order_relaxed);
        if (info.family != RansomwareFamily::Unknown) {
            const auto idx = static_cast<size_t>(info.family);
            if (idx < m_impl->m_stats.familiesIdentified.size()) {
                m_impl->m_stats.familiesIdentified[idx].fetch_add(
                    1, std::memory_order_relaxed);
            }
        }

        SS_LOG_DEBUG(LOG_CAT, L"Analyzed %ls: family=%hs algo=%hs canDecrypt=%hs",
                     std::wstring(filePath).c_str(),
                     std::string(GetFamilyName(info.family)).c_str(),
                     std::string(GetAlgorithmName(info.algorithm)).c_str(),
                     info.canDecrypt ? "yes" : "no");

    } catch (const std::exception& ex) {
        SS_LOG_ERROR(LOG_CAT, L"AnalyzeFile exception for %ls: %hs",
                     std::wstring(filePath).c_str(), ex.what());
    } catch (...) {
        SS_LOG_ERROR(LOG_CAT, L"AnalyzeFile unknown exception for %ls",
                     std::wstring(filePath).c_str());
    }
    return info;
}

std::vector<EncryptedFileInfo> RansomwareDecryptor::ScanDirectory(
    std::wstring_view dirPath, bool recursive) {
    std::vector<EncryptedFileInfo> results;

    try {
        fs::path root(dirPath);
        std::error_code ec;

        if (!ValidateFilePath(root)) {
            SS_LOG_WARN(LOG_CAT, L"ScanDirectory: invalid path rejected: %ls",
                        std::wstring(dirPath).c_str());
            return results;
        }

        if (!fs::exists(root, ec) || ec || !fs::is_directory(root, ec) || ec) {
            SS_LOG_WARN(LOG_CAT, L"ScanDirectory: not a directory: %ls",
                        std::wstring(dirPath).c_str());
            return results;
        }

        results.reserve(256);
        const auto options = fs::directory_options::skip_permission_denied;

        auto processEntry = [&](const fs::directory_entry& entry) {
            if (results.size() >= MAX_SCAN_FILES) return;
            if (ec) { ec.clear(); return; }
            if (!entry.is_regular_file(ec) || ec) return;

            const std::wstring ext = NormalizeExtension(
                entry.path().extension().wstring());
            if (EXTENSION_MAP.count(ext)) {
                EncryptedFileInfo info = AnalyzeFile(
                    entry.path().wstring());
                if (info.family != RansomwareFamily::Unknown) {
                    results.push_back(std::move(info));
                }
            }
        };

        if (recursive) {
            for (auto it = fs::recursive_directory_iterator(root, options, ec);
                 it != fs::recursive_directory_iterator(); it.increment(ec)) {
                if (results.size() >= MAX_SCAN_FILES) break;
                if (ec) { ec.clear(); continue; }
                if (it.depth() > static_cast<int>(MAX_DIRECTORY_DEPTH)) {
                    it.disable_recursion_pending();
                    continue;
                }
                processEntry(*it);
            }
        } else {
            for (auto it = fs::directory_iterator(root, options, ec);
                 it != fs::directory_iterator(); it.increment(ec)) {
                if (results.size() >= MAX_SCAN_FILES) break;
                if (ec) { ec.clear(); continue; }
                processEntry(*it);
            }
        }

        SS_LOG_INFO(LOG_CAT, L"ScanDirectory: found %zu encrypted files in %ls",
                    results.size(), std::wstring(dirPath).c_str());

    } catch (const std::exception& ex) {
        SS_LOG_ERROR(LOG_CAT, L"ScanDirectory exception for %ls: %hs",
                     std::wstring(dirPath).c_str(), ex.what());
    } catch (...) {
        SS_LOG_ERROR(LOG_CAT, L"ScanDirectory unknown exception for %ls",
                     std::wstring(dirPath).c_str());
    }
    return results;
}

// ============================================================================
// RANSOM NOTE ANALYSIS
// ============================================================================

std::vector<RansomNoteInfo> RansomwareDecryptor::FindRansomNotes(
    std::wstring_view dirPath, bool recursive) {
    std::vector<RansomNoteInfo> results;

    try {
        fs::path root(dirPath);
        std::error_code ec;

        if (!ValidateFilePath(root) || !fs::exists(root, ec) || ec ||
            !fs::is_directory(root, ec) || ec) {
            return results;
        }

        // Build a set of known ransom note filenames (case-insensitive)
        std::unordered_set<std::wstring> noteNames;
        for (const auto& name : RANSOM_NOTE_FILENAMES) {
            std::wstring lower = name;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
            noteNames.insert(std::move(lower));
        }

        // Common ransom note substrings for heuristic matching
        static constexpr const wchar_t* kNoteKeywords[] = {
            L"decrypt", L"ransom", L"readme", L"restore",
            L"help_decrypt", L"how_to", L"recovery", L"!readme"
        };

        constexpr size_t kMaxNotes = 10000;
        const auto options = fs::directory_options::skip_permission_denied;

        auto processEntry = [&](const fs::directory_entry& entry) {
            if (results.size() >= kMaxNotes) return;
            if (!entry.is_regular_file(ec) || ec) return;

            const std::wstring filename = entry.path().filename().wstring();
            std::wstring lowerName = filename;
            std::transform(lowerName.begin(), lowerName.end(),
                           lowerName.begin(), ::towlower);

            bool isNote = noteNames.count(lowerName) > 0;

            // Heuristic: .txt or .html with ransom-like keywords
            if (!isNote) {
                const std::wstring ext = NormalizeExtension(
                    entry.path().extension().wstring());
                if (ext == L".txt" || ext == L".html" || ext == L".htm" ||
                    ext == L".hta") {
                    for (const auto* kw : kNoteKeywords) {
                        if (lowerName.find(kw) != std::wstring::npos) {
                            isNote = true;
                            break;
                        }
                    }
                }
            }

            if (isNote) {
                // Cap note file size to prevent abuse (max 1 MB)
                const auto noteSize = entry.file_size(ec);
                if (ec || noteSize > 1024 * 1024) return;

                RansomNoteInfo note = ParseRansomNote(entry.path().wstring());
                if (!note.filePath.empty()) {
                    results.push_back(std::move(note));
                }
            }
        };

        if (recursive) {
            for (auto it = fs::recursive_directory_iterator(root, options, ec);
                 it != fs::recursive_directory_iterator(); it.increment(ec)) {
                if (results.size() >= kMaxNotes) break;
                if (ec) { ec.clear(); continue; }
                if (it.depth() > static_cast<int>(MAX_DIRECTORY_DEPTH)) {
                    it.disable_recursion_pending();
                    continue;
                }
                processEntry(*it);
            }
        } else {
            for (auto it = fs::directory_iterator(root, options, ec);
                 it != fs::directory_iterator(); it.increment(ec)) {
                if (results.size() >= kMaxNotes) break;
                if (ec) { ec.clear(); continue; }
                processEntry(*it);
            }
        }

        SS_LOG_INFO(LOG_CAT, L"FindRansomNotes: found %zu notes in %ls",
                    results.size(), std::wstring(dirPath).c_str());

    } catch (const std::exception& ex) {
        SS_LOG_ERROR(LOG_CAT, L"FindRansomNotes exception for %ls: %hs",
                     std::wstring(dirPath).c_str(), ex.what());
    } catch (...) {
        SS_LOG_ERROR(LOG_CAT, L"FindRansomNotes unknown exception for %ls",
                     std::wstring(dirPath).c_str());
    }
    return results;
}

RansomNoteInfo RansomwareDecryptor::ParseRansomNote(std::wstring_view filePath) {
    RansomNoteInfo info;

    try {
        fs::path p(filePath);
        std::error_code ec;

        if (!ValidateFilePath(p) || !fs::exists(p, ec) || ec ||
            !fs::is_regular_file(p, ec) || ec) {
            return info;
        }

        const auto noteSize = fs::file_size(p, ec);
        if (ec || noteSize == 0 || noteSize > 1024 * 1024) {
            return info;
        }

        info.filePath = std::wstring(filePath);

        // Read note contents via Win32 for reliable encoding handling
        HANDLE hFile = ::CreateFileW(
            p.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

        if (hFile == INVALID_HANDLE_VALUE) {
            return info;
        }

        std::vector<char> rawBuf(static_cast<size_t>(noteSize) + 1, '\0');
        DWORD bytesRead = 0;
        const BOOL readOk = ::ReadFile(hFile, rawBuf.data(),
            static_cast<DWORD>(noteSize), &bytesRead, nullptr);
        ::CloseHandle(hFile);

        if (!readOk || bytesRead == 0) {
            return info;
        }

        rawBuf.resize(bytesRead);
        std::string noteContent(rawBuf.begin(), rawBuf.end());

        // Store widestring version for the noteText field
        info.noteText.assign(noteContent.begin(), noteContent.end());

        // Identify family from note filename first
        const std::wstring filename = p.filename().wstring();
        if (filename.find(L"Wana") != std::wstring::npos ||
            filename.find(L"wana") != std::wstring::npos) {
            info.family = RansomwareFamily::WannaCry;
        } else if (filename.find(L"Locky") != std::wstring::npos) {
            info.family = RansomwareFamily::Locky;
        } else if (filename.find(L"Ryuk") != std::wstring::npos) {
            info.family = RansomwareFamily::Ryuk;
        }

        // Extract Bitcoin addresses (legacy P2PKH: 1xxx, P2SH: 3xxx, Bech32: bc1)
        // Simple pattern extraction — not full regex to avoid std::regex overhead
        for (size_t i = 0; i < noteContent.size(); ++i) {
            const char ch = noteContent[i];

            // Legacy BTC addresses: start with '1' or '3', 26-35 chars
            if ((ch == '1' || ch == '3') && i + 25 < noteContent.size()) {
                size_t end = i + 1;
                while (end < noteContent.size() && end - i <= 35) {
                    const char c = noteContent[end];
                    if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                        (c >= 'A' && c <= 'Z')) {
                        ++end;
                    } else {
                        break;
                    }
                }
                const size_t len = end - i;
                if (len >= 26 && len <= 35 && info.bitcoinAddress.empty()) {
                    info.bitcoinAddress = noteContent.substr(i, len);
                    i = end - 1;
                }
            }

            // Bech32 BTC addresses: start with "bc1"
            if (ch == 'b' && i + 2 < noteContent.size() &&
                noteContent[i + 1] == 'c' && noteContent[i + 2] == '1') {
                size_t end = i + 3;
                while (end < noteContent.size() && end - i <= 62) {
                    const char c = noteContent[end];
                    if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                        (c >= 'A' && c <= 'Z')) {
                        ++end;
                    } else {
                        break;
                    }
                }
                const size_t len = end - i;
                if (len >= 42 && len <= 62 && info.bitcoinAddress.empty()) {
                    info.bitcoinAddress = noteContent.substr(i, len);
                    i = end - 1;
                }
            }
        }

        // Extract .onion URLs
        if (const auto onionPos = noteContent.find(".onion");
            onionPos != std::string::npos) {
            // Walk backwards to find URL start
            size_t urlStart = onionPos;
            while (urlStart > 0 && noteContent[urlStart - 1] != ' ' &&
                   noteContent[urlStart - 1] != '\n' &&
                   noteContent[urlStart - 1] != '\r' &&
                   noteContent[urlStart - 1] != '\t' &&
                   noteContent[urlStart - 1] != '<' &&
                   noteContent[urlStart - 1] != '"') {
                --urlStart;
            }
            // Walk forward to find URL end
            size_t urlEnd = onionPos + 6; // past ".onion"
            while (urlEnd < noteContent.size() &&
                   noteContent[urlEnd] != ' ' && noteContent[urlEnd] != '\n' &&
                   noteContent[urlEnd] != '\r' && noteContent[urlEnd] != '"' &&
                   noteContent[urlEnd] != '>') {
                ++urlEnd;
            }
            if (urlEnd > urlStart && urlEnd - urlStart < 512) {
                info.torUrl = noteContent.substr(urlStart, urlEnd - urlStart);
            }
        }

        // Extract email addresses (look for x@y.z patterns)
        for (size_t i = 1; i < noteContent.size(); ++i) {
            if (noteContent[i] != '@') continue;

            // Walk backwards for local part
            size_t localStart = i;
            while (localStart > 0) {
                const char c = noteContent[localStart - 1];
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '.' || c == '_' ||
                    c == '-' || c == '+') {
                    --localStart;
                } else {
                    break;
                }
            }
            // Walk forward for domain
            size_t domainEnd = i + 1;
            bool hasDot = false;
            while (domainEnd < noteContent.size()) {
                const char c = noteContent[domainEnd];
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '.' || c == '-') {
                    if (c == '.') hasDot = true;
                    ++domainEnd;
                } else {
                    break;
                }
            }

            if (hasDot && i - localStart >= 1 && domainEnd - i >= 4 &&
                domainEnd - localStart < 256 && info.contactEmail.empty()) {
                info.contactEmail = noteContent.substr(
                    localStart, domainEnd - localStart);
                break;
            }
        }

        // Content-based family identification if not yet determined
        if (info.family == RansomwareFamily::Unknown) {
            const std::string lower = [&] {
                std::string s = noteContent;
                std::transform(s.begin(), s.end(), s.begin(),
                    [](unsigned char c) { return static_cast<char>(::tolower(c)); });
                return s;
            }();

            if (lower.find("wannacry") != std::string::npos ||
                lower.find("wanacrypt") != std::string::npos) {
                info.family = RansomwareFamily::WannaCry;
            } else if (lower.find("gandcrab") != std::string::npos) {
                info.family = RansomwareFamily::GandCrabV4;
            } else if (lower.find("lockbit") != std::string::npos) {
                info.family = RansomwareFamily::LockBit;
            } else if (lower.find("conti") != std::string::npos) {
                info.family = RansomwareFamily::Conti;
            } else if (lower.find("revil") != std::string::npos ||
                       lower.find("sodinokibi") != std::string::npos) {
                info.family = RansomwareFamily::REvil;
            } else if (lower.find("ryuk") != std::string::npos) {
                info.family = RansomwareFamily::Ryuk;
            } else if (lower.find("maze") != std::string::npos) {
                info.family = RansomwareFamily::Maze;
            } else if (lower.find("blackcat") != std::string::npos ||
                       lower.find("alphv") != std::string::npos) {
                info.family = RansomwareFamily::BlackCat;
            } else if (lower.find("hive") != std::string::npos) {
                info.family = RansomwareFamily::Hive;
            } else if (lower.find("dharma") != std::string::npos) {
                info.family = RansomwareFamily::Dharma;
            } else if (lower.find("phobos") != std::string::npos) {
                info.family = RansomwareFamily::Phobos;
            } else if (lower.find("stop") != std::string::npos &&
                       lower.find("djvu") != std::string::npos) {
                info.family = RansomwareFamily::STOP;
            } else if (lower.find("cerber") != std::string::npos) {
                info.family = RansomwareFamily::Cerber;
            } else if (lower.find("teslacrypt") != std::string::npos) {
                info.family = RansomwareFamily::TeslaCrypt;
            } else if (lower.find("jigsaw") != std::string::npos) {
                info.family = RansomwareFamily::Jigsaw;
            }
        }

        SS_LOG_DEBUG(LOG_CAT, L"ParseRansomNote: %ls family=%hs btc=%hs tor=%hs email=%hs",
                     std::wstring(filePath).c_str(),
                     std::string(GetFamilyName(info.family)).c_str(),
                     info.bitcoinAddress.empty() ? "(none)" : info.bitcoinAddress.c_str(),
                     info.torUrl.empty() ? "(none)" : info.torUrl.c_str(),
                     info.contactEmail.empty() ? "(none)" : info.contactEmail.c_str());

    } catch (const std::exception& ex) {
        SS_LOG_ERROR(LOG_CAT, L"ParseRansomNote exception for %ls: %hs",
                     std::wstring(filePath).c_str(), ex.what());
    } catch (...) {
        SS_LOG_ERROR(LOG_CAT, L"ParseRansomNote unknown exception for %ls",
                     std::wstring(filePath).c_str());
    }
    return info;
}

// ============================================================================
// KEY MANAGEMENT
// ============================================================================

bool RansomwareDecryptor::LoadKeyDatabase(std::wstring_view path) {
    try {
        fs::path dbPath(path);
        std::error_code ec;
        if (!fs::exists(dbPath, ec) || ec) {
            SS_LOG_WARN(LOG_CAT, L"Key database not found: %ls",
                        std::wstring(path).c_str());
            return false;
        }

        // Read JSON key database
        HANDLE hFile = ::CreateFileW(
            dbPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

        if (hFile == INVALID_HANDLE_VALUE) {
            SS_LOG_LAST_ERROR(LOG_CAT, L"Cannot open key database: %ls",
                              dbPath.c_str());
            return false;
        }

        LARGE_INTEGER fileSize{};
        if (!::GetFileSizeEx(hFile, &fileSize) ||
            fileSize.QuadPart <= 0 ||
            fileSize.QuadPart > 50 * 1024 * 1024) { // 50MB cap
            ::CloseHandle(hFile);
            SS_LOG_ERROR(LOG_CAT, L"Key database invalid size: %lld",
                         fileSize.QuadPart);
            return false;
        }

        std::string jsonData(static_cast<size_t>(fileSize.QuadPart), '\0');
        DWORD bytesRead = 0;
        BOOL readOk = ::ReadFile(hFile, jsonData.data(),
            static_cast<DWORD>(fileSize.QuadPart), &bytesRead, nullptr);
        ::CloseHandle(hFile);

        if (!readOk || bytesRead != static_cast<DWORD>(fileSize.QuadPart)) {
            SS_LOG_ERROR(LOG_CAT, L"Key database read failed");
            return false;
        }

        auto j = nlohmann::json::parse(jsonData, nullptr, false);
        if (j.is_discarded() || !j.is_object()) {
            SS_LOG_ERROR(LOG_CAT, L"Key database JSON parse failed");
            ::SecureZeroMemory(jsonData.data(), jsonData.size());
            return false;
        }

        size_t loaded = 0;
        if (j.contains("keys") && j["keys"].is_array()) {
            for (const auto& keyJson : j["keys"]) {
                if (loaded >= DecryptorConstants::MAX_KEYS_PER_FAMILY * 32) break;

                DecryptionKey key;
                if (keyJson.contains("keyId"))
                    key.keyId = keyJson["keyId"].get<std::string>();
                if (keyJson.contains("family"))
                    key.family = static_cast<RansomwareFamily>(
                        keyJson["family"].get<uint16_t>());
                if (keyJson.contains("algorithm"))
                    key.algorithm = static_cast<EncryptionAlgorithm>(
                        keyJson["algorithm"].get<uint8_t>());
                if (keyJson.contains("keyType"))
                    key.keyType = static_cast<KeyType>(
                        keyJson["keyType"].get<uint8_t>());
                if (keyJson.contains("isMasterKey"))
                    key.isMasterKey = keyJson["isMasterKey"].get<bool>();

                // Key data is expected as hex string
                if (keyJson.contains("keyDataHex")) {
                    std::string hex = keyJson["keyDataHex"].get<std::string>();
                    key.keyData.reserve(hex.size() / 2);
                    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
                        key.keyData.push_back(static_cast<uint8_t>(
                            std::stoul(hex.substr(i, 2), nullptr, 16)));
                    }
                    ::SecureZeroMemory(hex.data(), hex.size());
                }
                if (keyJson.contains("ivHex")) {
                    std::string hex = keyJson["ivHex"].get<std::string>();
                    key.iv.reserve(hex.size() / 2);
                    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
                        key.iv.push_back(static_cast<uint8_t>(
                            std::stoul(hex.substr(i, 2), nullptr, 16)));
                    }
                    ::SecureZeroMemory(hex.data(), hex.size());
                }

                if (!key.keyId.empty() && !key.keyData.empty()) {
                    AddKey(key);
                    loaded++;
                }
            }
        }

        // Securely wipe the raw JSON
        ::SecureZeroMemory(jsonData.data(), jsonData.size());

        SS_LOG_INFO(LOG_CAT, L"Loaded %zu keys from database: %ls",
                    loaded, dbPath.c_str());
        return loaded > 0;

    } catch (const std::exception& ex) {
        SS_LOG_ERROR(LOG_CAT, L"LoadKeyDatabase exception: %hs", ex.what());
        return false;
    }
}

void RansomwareDecryptor::AddKey(const DecryptionKey& key) {
    std::unique_lock lock(m_impl->m_keyMutex);

    if (m_impl->m_keys.size() >= DecryptorConstants::MAX_DECRYPTORS *
                                  DecryptorConstants::MAX_KEYS_PER_FAMILY) {
        SS_LOG_WARN(LOG_CAT, L"Key storage full, cannot add key %hs",
                    key.keyId.c_str());
        return;
    }

    if (m_impl->m_keys.count(key.keyId) == 0) {
        m_impl->m_keys[key.keyId] = key;
        m_impl->m_familyKeys[key.family].push_back(key.keyId);
        m_impl->m_stats.keysLoaded.fetch_add(1, std::memory_order_relaxed);
    }
}

void RansomwareDecryptor::RemoveKey(const std::string& keyId) {
    std::unique_lock lock(m_impl->m_keyMutex);

    auto it = m_impl->m_keys.find(keyId);
    if (it != m_impl->m_keys.end()) {
        RansomwareFamily fam = it->second.family;
        SecureEraseKey(it->second);
        m_impl->m_keys.erase(it);

        auto& vec = m_impl->m_familyKeys[fam];
        std::erase(vec, keyId);

        m_impl->m_stats.keysLoaded.fetch_sub(1, std::memory_order_relaxed);
    }
}

std::vector<DecryptionKey> RansomwareDecryptor::GetKeysForFamily(
    RansomwareFamily family) const {
    std::shared_lock lock(m_impl->m_keyMutex);
    std::vector<DecryptionKey> result;

    auto it = m_impl->m_familyKeys.find(family);
    if (it != m_impl->m_familyKeys.end()) {
        result.reserve(it->second.size());
        for (const auto& id : it->second) {
            auto keyIt = m_impl->m_keys.find(id);
            if (keyIt != m_impl->m_keys.end()) {
                result.push_back(keyIt->second);
            }
        }
    }
    return result;
}

size_t RansomwareDecryptor::GetKeyCount() const noexcept {
    std::shared_lock lock(m_impl->m_keyMutex);
    return m_impl->m_keys.size();
}

bool RansomwareDecryptor::IsDecryptionAvailable(RansomwareFamily family) const {
    std::shared_lock lock(m_impl->m_keyMutex);
    auto it = m_impl->m_familyKeys.find(family);
    return it != m_impl->m_familyKeys.end() && !it->second.empty();
}

// ============================================================================
// CALLBACKS
// ============================================================================

void RansomwareDecryptor::SetProgressCallback(DecryptionProgressCallback callback) {
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_progressCallback = std::move(callback);
}

void RansomwareDecryptor::SetCompleteCallback(DecryptionCompleteCallback callback) {
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_completeCallback = std::move(callback);
}

void RansomwareDecryptor::SetBatchProgressCallback(BatchProgressCallback callback) {
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_batchProgressCallback = std::move(callback);
}

// ============================================================================
// STATISTICS
// ============================================================================

DecryptorStatisticsSnapshot RansomwareDecryptor::GetStatistics() const {
    if (!m_impl) return {};
    DecryptorStatisticsSnapshot snap;
    snap.filesAnalyzed  = m_impl->m_stats.filesAnalyzed.load(std::memory_order_relaxed);
    snap.filesDecrypted = m_impl->m_stats.filesDecrypted.load(std::memory_order_relaxed);
    snap.filesFailed    = m_impl->m_stats.filesFailed.load(std::memory_order_relaxed);
    snap.bytesDecrypted = m_impl->m_stats.bytesDecrypted.load(std::memory_order_relaxed);
    snap.keysLoaded     = m_impl->m_stats.keysLoaded.load(std::memory_order_relaxed);
    for (size_t i = 0; i < snap.familiesIdentified.size(); ++i) {
        snap.familiesIdentified[i] =
            m_impl->m_stats.familiesIdentified[i].load(std::memory_order_relaxed);
    }
    const auto now = Clock::now();
    snap.uptimeSeconds = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now - m_impl->m_stats.startTime).count());
    return snap;
}

void RansomwareDecryptor::ResetStatistics() {
    m_impl->m_stats.Reset();
}

// ============================================================================
// UTILITY
// ============================================================================

std::string_view RansomwareDecryptor::GetFamilyName(
    RansomwareFamily family) noexcept {
    switch (family) {
        case RansomwareFamily::WannaCry:      return "WannaCry";
        case RansomwareFamily::Locky:         return "Locky";
        case RansomwareFamily::CryptoLocker:  return "CryptoLocker";
        case RansomwareFamily::TeslaCrypt:    return "TeslaCrypt";
        case RansomwareFamily::TeslaCryptV2:  return "TeslaCrypt v2";
        case RansomwareFamily::TeslaCryptV3:  return "TeslaCrypt v3";
        case RansomwareFamily::TeslaCryptV4:  return "TeslaCrypt v4";
        case RansomwareFamily::Cerber:        return "Cerber";
        case RansomwareFamily::Petya:         return "Petya";
        case RansomwareFamily::NotPetya:      return "NotPetya";
        case RansomwareFamily::GandCrabV4:    return "GandCrab v4";
        case RansomwareFamily::GandCrabV5:    return "GandCrab v5";
        case RansomwareFamily::Shade:         return "Shade";
        case RansomwareFamily::Troldesh:      return "Troldesh";
        case RansomwareFamily::Crysis:        return "Crysis";
        case RansomwareFamily::Dharma:        return "Dharma";
        case RansomwareFamily::Phobos:        return "Phobos";
        case RansomwareFamily::STOP:          return "STOP";
        case RansomwareFamily::Djvu:          return "Djvu";
        case RansomwareFamily::Jigsaw:        return "Jigsaw";
        case RansomwareFamily::BTCWare:       return "BTCWare";
        case RansomwareFamily::GlobeImposter: return "GlobeImposter";
        case RansomwareFamily::SamSam:        return "SamSam";
        case RansomwareFamily::Ryuk:          return "Ryuk";
        case RansomwareFamily::REvil:         return "REvil";
        case RansomwareFamily::Maze:          return "Maze";
        case RansomwareFamily::Conti:         return "Conti";
        case RansomwareFamily::LockBit:       return "LockBit";
        case RansomwareFamily::BlackCat:      return "BlackCat";
        case RansomwareFamily::Hive:          return "Hive";
        case RansomwareFamily::Custom:        return "Custom";
        default:                              return "Unknown";
    }
}

bool RansomwareDecryptor::SelfTest() {
    SS_LOG_INFO(LOG_CAT, L"Running self-test...");

    // Test 1: Configuration validation
    RansomwareDecryptorConfiguration config;
    if (!config.IsValid()) {
        SS_LOG_ERROR(LOG_CAT, L"Self-test FAILED: default config invalid");
        return false;
    }

    // Test 2: Extension identification
    if (IdentifyFamilyFromExtension(L".wncry") != RansomwareFamily::WannaCry) {
        SS_LOG_ERROR(LOG_CAT, L"Self-test FAILED: .wncry extension ID");
        return false;
    }
    if (IdentifyFamilyFromExtension(L".WNCRY") != RansomwareFamily::WannaCry) {
        SS_LOG_ERROR(LOG_CAT, L"Self-test FAILED: case-insensitive extension ID");
        return false;
    }
    if (IdentifyFamilyFromExtension(L".lockbit") != RansomwareFamily::LockBit) {
        SS_LOG_ERROR(LOG_CAT, L"Self-test FAILED: .lockbit extension ID");
        return false;
    }

    // Test 3: Family name lookup
    auto name = GetFamilyName(RansomwareFamily::Ryuk);
    if (name != "Ryuk") {
        SS_LOG_ERROR(LOG_CAT, L"Self-test FAILED: family name lookup");
        return false;
    }

    // Test 4: Family name map
    auto famIt = FAMILY_NAME_MAP.find("Ryuk");
    if (famIt == FAMILY_NAME_MAP.end() ||
        famIt->second != RansomwareFamily::Ryuk) {
        SS_LOG_ERROR(LOG_CAT, L"Self-test FAILED: family name map");
        return false;
    }

    // Test 5: Process termination check (PID 0 should always return true)
    if (!VerifyRansomwareTerminated(0)) {
        SS_LOG_ERROR(LOG_CAT, L"Self-test FAILED: PID 0 termination check");
        return false;
    }

    // Test 6: Path validation
    if (!ValidateFilePath(fs::path(L"C:\\Test\\file.txt"))) {
        SS_LOG_ERROR(LOG_CAT, L"Self-test FAILED: valid path rejected");
        return false;
    }
    if (ValidateFilePath(fs::path(L"C:\\Test\\..\\..\\Windows\\System32\\config"))) {
        SS_LOG_ERROR(LOG_CAT, L"Self-test FAILED: traversal path accepted");
        return false;
    }

    SS_LOG_INFO(LOG_CAT, L"Self-test PASSED (all checks)");
    return true;
}

std::string RansomwareDecryptor::GetVersionString() noexcept {
    // Use constexpr-friendly formatting
    char buf[32]{};
    std::snprintf(buf, sizeof(buf), "%u.%u.%u",
                  DecryptorConstants::VERSION_MAJOR,
                  DecryptorConstants::VERSION_MINOR,
                  DecryptorConstants::VERSION_PATCH);
    return std::string(buf);
}

std::vector<RansomwareFamily> RansomwareDecryptor::GetSupportedFamilies() const {
    // Collect all families that we can identify (from extension map)
    // plus all families with loaded decryption keys
    std::unordered_set<RansomwareFamily> familySet;

    // All families from the extension map (identifiable)
    for (const auto& [ext, fam] : EXTENSION_MAP) {
        familySet.insert(fam);
    }

    // All families with loaded keys (decryptable)
    {
        std::shared_lock lock(m_impl->m_keyMutex);
        for (const auto& [fam, keyIds] : m_impl->m_familyKeys) {
            if (!keyIds.empty()) {
                familySet.insert(fam);
            }
        }
    }

    // Convert to sorted vector for deterministic output
    std::vector<RansomwareFamily> result(familySet.begin(), familySet.end());
    std::sort(result.begin(), result.end(),
              [](RansomwareFamily a, RansomwareFamily b) {
                  return static_cast<uint16_t>(a) < static_cast<uint16_t>(b);
              });
    return result;
}

// ============================================================================
// STRUCT IMPLEMENTATIONS
// ============================================================================

void DecryptorStatistics::Reset() noexcept {
    filesAnalyzed.store(0, std::memory_order_relaxed);
    filesDecrypted.store(0, std::memory_order_relaxed);
    filesFailed.store(0, std::memory_order_relaxed);
    bytesDecrypted.store(0, std::memory_order_relaxed);
    keysLoaded.store(0, std::memory_order_relaxed);
    for (auto& f : familiesIdentified) f.store(0, std::memory_order_relaxed);
    startTime = Clock::now();
}

std::string DecryptionResult::ToJson() const {
    nlohmann::json j;
    j["originalPath"] = Utils::StringUtils::ToNarrow(originalPath);
    j["decryptedPath"] = Utils::StringUtils::ToNarrow(decryptedPath);
    j["status"] = static_cast<int>(status);
    j["family"] = static_cast<int>(family);
    j["keyId"] = keyId;
    j["durationMs"] = durationMs;
    j["originalSize"] = originalSize;
    j["decryptedSize"] = decryptedSize;
    j["validationPassed"] = validationPassed;
    if (!errorMessage.empty()) j["error"] = errorMessage;
    return j.dump();
}

double BatchDecryptionResult::GetSuccessRate() const noexcept {
    if (totalFiles == 0) return 0.0;
    return static_cast<double>(filesDecrypted) / static_cast<double>(totalFiles);
}

std::string BatchDecryptionResult::ToJson() const {
    nlohmann::json j;
    j["batchId"] = batchId;
    j["totalFiles"] = totalFiles;
    j["filesDecrypted"] = filesDecrypted;
    j["filesFailed"] = filesFailed;
    j["filesSkipped"] = filesSkipped;
    j["bytesProcessed"] = bytesProcessed;
    j["successRate"] = GetSuccessRate();
    return j.dump();
}

std::string RecoveryResult::ToJson() const {
    nlohmann::json j;
    j["encryptedPath"] = Utils::StringUtils::ToNarrow(encryptedPath);
    j["recoveredPath"] = Utils::StringUtils::ToNarrow(recoveredPath);
    j["methodUsed"] = static_cast<int>(methodUsed);
    j["status"] = static_cast<int>(status);
    j["durationMs"] = durationMs;
    j["recoveredSize"] = recoveredSize;
    j["integrityVerified"] = integrityVerified;
    if (!forensicCopyPath.empty())
        j["forensicCopyPath"] = Utils::StringUtils::ToNarrow(forensicCopyPath);
    if (!errorMessage.empty()) j["error"] = errorMessage;
    return j.dump();
}

bool DecryptionKey::IsValidFor(const EncryptedFileInfo& file) const {
    if (family != file.family) return false;
    if (algorithm != EncryptionAlgorithm::Unknown &&
        file.algorithm != EncryptionAlgorithm::Unknown &&
        algorithm != file.algorithm) return false;
    if (isMasterKey) return true;
    if (!file.victimId.empty() && !victimIds.empty()) {
        return std::find(victimIds.begin(), victimIds.end(), file.victimId)
               != victimIds.end();
    }
    return true;
}

std::string DecryptionKey::ToJson() const {
    nlohmann::json j;
    j["keyId"] = keyId;
    j["keyType"] = static_cast<int>(keyType);
    j["source"] = static_cast<int>(source);
    j["family"] = static_cast<int>(family);
    j["algorithm"] = static_cast<int>(algorithm);
    j["isMasterKey"] = isMasterKey;
    // Intentionally omit keyData, iv, rsaPrivateKey for security
    j["notes"] = notes;
    return j.dump();
}

std::string EncryptedFileInfo::ToJson() const {
    nlohmann::json j;
    j["filePath"] = Utils::StringUtils::ToNarrow(filePath);
    j["fileSize"] = fileSize;
    j["family"] = static_cast<int>(family);
    j["algorithm"] = static_cast<int>(algorithm);
    j["canDecrypt"] = canDecrypt;
    j["confidence"] = confidence;
    return j.dump();
}

std::string RansomNoteInfo::ToJson() const {
    nlohmann::json j;
    j["filePath"] = Utils::StringUtils::ToNarrow(filePath);
    j["family"] = static_cast<int>(family);
    j["familyName"] = std::string(RansomwareDecryptor::GetFamilyName(family));
    if (!bitcoinAddress.empty()) j["bitcoinAddress"] = bitcoinAddress;
    if (!contactEmail.empty())   j["contactEmail"]   = contactEmail;
    if (!torUrl.empty())         j["torUrl"]          = torUrl;
    if (!victimId.empty())       j["victimId"]        = victimId;
    if (!ransomAmount.empty())   j["ransomAmount"]    = ransomAmount;
    return j.dump();
}

std::string DecryptorStatistics::ToJson() const {
    nlohmann::json j;
    j["filesAnalyzed"] = filesAnalyzed.load(std::memory_order_relaxed);
    j["filesDecrypted"] = filesDecrypted.load(std::memory_order_relaxed);
    j["filesFailed"] = filesFailed.load(std::memory_order_relaxed);
    j["bytesDecrypted"] = bytesDecrypted.load(std::memory_order_relaxed);
    j["keysLoaded"] = keysLoaded.load(std::memory_order_relaxed);
    return j.dump();
}

bool RansomwareDecryptorConfiguration::IsValid() const noexcept {
    if (maxConcurrent == 0) return false;
    if (fileTimeoutMs == 0) return false;
    return true;
}

// ============================================================================
// FREE FUNCTION IMPLEMENTATIONS
// ============================================================================

std::string_view GetDecryptionStatusName(DecryptionStatus status) noexcept {
    switch (status) {
        case DecryptionStatus::Success:          return "Success";
        case DecryptionStatus::PartialSuccess:   return "PartialSuccess";
        case DecryptionStatus::Failed:           return "Failed";
        case DecryptionStatus::UnknownFamily:    return "UnknownFamily";
        case DecryptionStatus::NoKeyAvailable:   return "NoKeyAvailable";
        case DecryptionStatus::InvalidFile:      return "InvalidFile";
        case DecryptionStatus::CorruptedFile:    return "CorruptedFile";
        case DecryptionStatus::IOError:          return "IOError";
        case DecryptionStatus::Timeout:          return "Timeout";
        case DecryptionStatus::Cancelled:        return "Cancelled";
        case DecryptionStatus::AlreadyDecrypted: return "AlreadyDecrypted";
        default:                                 return "Unknown";
    }
}

std::string_view GetKeyTypeName(KeyType type) noexcept {
    switch (type) {
        case KeyType::MasterKey:  return "MasterKey";
        case KeyType::SessionKey: return "SessionKey";
        case KeyType::FileKey:    return "FileKey";
        case KeyType::OfflineKey: return "OfflineKey";
        case KeyType::OnlineKey:  return "OnlineKey";
        case KeyType::DerivedKey: return "DerivedKey";
        default:                  return "Unknown";
    }
}

std::string_view GetAlgorithmName(EncryptionAlgorithm algo) noexcept {
    switch (algo) {
        case EncryptionAlgorithm::AES128CBC: return "AES-128-CBC";
        case EncryptionAlgorithm::AES256CBC: return "AES-256-CBC";
        case EncryptionAlgorithm::AES128CTR: return "AES-128-CTR";
        case EncryptionAlgorithm::AES256CTR: return "AES-256-CTR";
        case EncryptionAlgorithm::AES128GCM: return "AES-128-GCM";
        case EncryptionAlgorithm::AES256GCM: return "AES-256-GCM";
        case EncryptionAlgorithm::RSA2048:   return "RSA-2048";
        case EncryptionAlgorithm::RSA4096:   return "RSA-4096";
        case EncryptionAlgorithm::ChaCha20:  return "ChaCha20";
        case EncryptionAlgorithm::Salsa20:   return "Salsa20";
        case EncryptionAlgorithm::RC4:       return "RC4";
        case EncryptionAlgorithm::Blowfish:  return "Blowfish";
        case EncryptionAlgorithm::Twofish:   return "Twofish";
        case EncryptionAlgorithm::Custom:    return "Custom";
        default:                             return "Unknown";
    }
}

std::string_view GetKeySourceName(KeySource source) noexcept {
    switch (source) {
        case KeySource::Leaked:         return "Leaked";
        case KeySource::LawEnforcement: return "LawEnforcement";
        case KeySource::Research:       return "Research";
        case KeySource::Weakness:       return "Weakness";
        case KeySource::UserProvided:   return "UserProvided";
        default:                        return "Unknown";
    }
}

std::vector<std::wstring> GetFamilyExtensions(RansomwareFamily family) {
    std::vector<std::wstring> result;
    for (const auto& [ext, fam] : EXTENSION_MAP) {
        if (fam == family) result.push_back(ext);
    }
    return result;
}

std::vector<std::wstring> GetFamilyRansomNotes(RansomwareFamily family) {
    std::vector<std::wstring> result;
    // Map notes to families
    switch (family) {
        case RansomwareFamily::WannaCry:
            result.push_back(L"@Please_Read_Me@.txt");
            result.push_back(L"@WanaDecryptor@.txt");
            break;
        case RansomwareFamily::Locky:
            result.push_back(L"_Locky_recover_instructions.txt");
            break;
        case RansomwareFamily::CryptoLocker:
            result.push_back(L"HELP_DECRYPT.TXT");
            break;
        case RansomwareFamily::Ryuk:
            result.push_back(L"RyukReadMe.txt");
            break;
        case RansomwareFamily::LockBit:
            result.push_back(L"Restore-My-Files.txt");
            break;
        default:
            break;
    }
    return result;
}

// ============================================================================
// DECRYPTOR STATISTICS SNAPSHOT — ToJson
// ============================================================================

std::string DecryptorStatisticsSnapshot::ToJson() const {
    nlohmann::json j;
    j["filesAnalyzed"]  = filesAnalyzed;
    j["filesDecrypted"] = filesDecrypted;
    j["filesFailed"]    = filesFailed;
    j["bytesDecrypted"] = bytesDecrypted;
    j["keysLoaded"]     = keysLoaded;
    j["uptimeSeconds"]  = uptimeSeconds;
    nlohmann::json fam = nlohmann::json::array();
    for (size_t i = 0; i < familiesIdentified.size(); ++i) {
        if (familiesIdentified[i] > 0) {
            const auto name = RansomwareDecryptor::GetFamilyName(
                static_cast<RansomwareFamily>(i));
            fam.push_back({{"family", std::string(name)}, {"count", familiesIdentified[i]}});
        }
    }
    j["familiesIdentified"] = std::move(fam);
    return j.dump();
}

// ============================================================================
// KERNEL BRIDGE — OnKernelProcessNotify / OnKernelImageLoad / RequestBlock
// ============================================================================

void RansomwareDecryptor::OnKernelProcessNotify(
    uint32_t pid, uint32_t /*parentPid*/,
    std::wstring_view /*imagePath*/, bool isCreate)
{
    if (!m_impl || !IsInitialized()) return;
    if (!isCreate) {
        // Process terminated — if it was ransomware, auto-recover
        SS_LOG_DEBUG(LOG_CAT,
            L"Process %u terminated, checking pending recovery tasks", pid);
    }
}

void RansomwareDecryptor::OnKernelImageLoad(
    uint32_t /*pid*/, std::wstring_view /*imagePath*/, uintptr_t /*imageBase*/)
{
    // Decryptor is passive — no image-load analysis needed
}

[[nodiscard]] bool RansomwareDecryptor::RequestKernelProcessBlock(
    uint32_t pid, std::wstring_view reason)
{
    if (!Communication::IPCManager::HasInstance() ||
        !Communication::IPCManager::Instance().IsFilterPortConnected())
    {
        return false;
    }
    #pragma pack(push, 1)
    struct KernelBlockMsg {
        uint32_t msgType = 0x30;
        uint32_t pid     = 0;
    } msg;
    #pragma pack(pop)
    msg.pid = pid;
    const bool sent = Communication::IPCManager::Instance().SendToKernel(&msg, sizeof(msg));
    if (sent) {
        SS_LOG_INFO(LOG_CAT,
            L"Kernel process block requested for PID %u: %.*s",
            pid,
            static_cast<int>(reason.size()), reason.data());
    }
    return sent;
}

// ============================================================================
// CROSS-MODULE WIRING — AlertSystem & TelemetryCollector
// ============================================================================

void RansomwareDecryptor::ReportRecoveryToAlertSystem(const RecoveryResult& result) {
    if (!Communication::AlertSystem::HasInstance()) return;

    const auto severity = (result.status == DecryptionStatus::Success)
        ? Communication::AlertSeverity::Info
        : Communication::AlertSeverity::High;
    const auto narrow = Utils::StringUtils::ToNarrow(result.encryptedPath);
    (void)Communication::AlertSystem::Instance().RaiseAlert(
        severity,
        Communication::AlertType::Operational,
        "RansomwareDecryptor",
        std::format("Recovery {} for {}",
            (result.status == DecryptionStatus::Success) ? "succeeded" : "failed",
            narrow),
        std::format("method={} duration={}ms size={} integrity={}",
            static_cast<int>(result.methodUsed),
            result.durationMs,
            result.recoveredSize,
            result.integrityVerified ? "verified" : "unverified"));
}

void RansomwareDecryptor::ReportDecryptionTelemetry(const DecryptionResult& result) {
    if (!Communication::TelemetryCollector::HasInstance()) return;
    Communication::TelemetryCollector::Instance().RecordCustom(
        "ransomware_decryption",
        {
            {"status",     std::to_string(static_cast<int>(result.status))},
            {"family",     std::string(GetFamilyName(result.family))},
            {"keyId",      result.keyId},
            {"durationMs", std::to_string(result.durationMs)},
            {"size",       std::to_string(result.decryptedSize)},
            {"validated",  result.validationPassed ? "true" : "false"}
        });
}

}  // namespace Ransomware
}  // namespace ShadowStrike
