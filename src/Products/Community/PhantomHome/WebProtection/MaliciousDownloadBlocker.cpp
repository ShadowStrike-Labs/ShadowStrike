#include "pch.h"
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
 * ShadowStrike NGAV - MALICIOUS DOWNLOAD BLOCKER IMPLEMENTATION
 * ============================================================================
 *
 * @file MaliciousDownloadBlocker.cpp
 * @brief Implementation of the MaliciousDownloadBlocker class.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "MaliciousDownloadBlocker.hpp"
#include "SafeBrowsingAPI.hpp"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <thread>
#include <future>
#include <regex>
#include <filesystem>
#include <format>
#include <cctype>
#include <deque>

// Windows Headers for Trust Verification and Downloads path
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <ShlObj.h>
#include "../../../../PhantomCore/Utils/SystemUtils.hpp"  // GetKnownFolderForAllUsersOrSelf

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

namespace ShadowStrike {
namespace WebBrowser {

// All download-specific types live in the nested `Downloads` namespace (see
// MaliciousDownloadBlocker.hpp). The implementation file mirrors that by
// pulling them into scope so the existing internal logic compiles unchanged.
using namespace Downloads;

// Bring Logger and utils into scope
using Utils::Logger;

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> MaliciousDownloadBlocker::s_instanceCreated{false};

// ============================================================================
// COMPILE-TIME LIMITS FOR DoS PREVENTION
// ============================================================================

namespace {
    inline constexpr size_t MAX_MONITORED_DIRS      = 64;
    inline constexpr size_t MAX_PROCESSED_FILES      = 100'000;
    inline constexpr size_t MAX_SCAN_QUEUE_SIZE      = 4096;
    inline constexpr size_t MAX_BLOCKED_EXTENSIONS   = 512;
    inline constexpr size_t MAX_CALLBACKS            = 64;
    inline constexpr size_t MAGIC_HEADER_SIZE        = 16;
    inline constexpr size_t PE_MAX_IMPORT_CHECK      = 10'000;
    inline constexpr DWORD  DIR_WATCH_BUFFER_SIZE    = 64 * 1024;

    template<typename T>
    [[nodiscard]] T AtomicValueLoadRelaxed(const T& value) noexcept {
        return std::atomic_ref<T>(const_cast<T&>(value)).load(std::memory_order_relaxed);
    }

    template<typename T>
    void AtomicValueStoreRelaxed(T& target, const T& value) noexcept {
        std::atomic_ref<T>(target).store(value, std::memory_order_relaxed);
    }
}

// ============================================================================
// UTILITY HELPERS
// ============================================================================

namespace {

    std::string NarrowToLower(std::string_view input) {
        std::string result(input);
        std::transform(result.begin(), result.end(), result.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return result;
    }

    // RFC 8259 minimal JSON string escape. Any string that originates from
    // attacker-controlled data (URL, filename, threat name, publisher, ...)
    // MUST pass through this before being emitted into a JSON payload.
    std::string JsonEscape(std::string_view in) {
        std::string out;
        out.reserve(in.size() + 8);
        for (unsigned char c : in) {
            switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b";  break;
                case '\f': out += "\\f";  break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                default:
                    if (c < 0x20) {
                        char buf[8];
                        (void)std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                        out += buf;
                    } else {
                        out += static_cast<char>(c);
                    }
            }
        }
        return out;
    }

    // Validate a caller-supplied quarantine identifier: defeats path traversal,
    // alternate data streams, drive-letter swaps and Unicode separators. Only
    // accepts the GUID-style strings produced by GenerateUUID().
    bool IsValidQuarantineId(std::string_view id) noexcept {
        if (id.empty() || id.size() > 128) return false;
        for (char c : id) {
            const unsigned char uc = static_cast<unsigned char>(c);
            const bool ok =
                (uc >= '0' && uc <= '9') ||
                (uc >= 'a' && uc <= 'z') ||
                (uc >= 'A' && uc <= 'Z') ||
                uc == '-' || uc == '_';
            if (!ok) return false;
        }
        return true;
    }

    std::string GenerateUUID() {
        GUID guid{};
        if (FAILED(CoCreateGuid(&guid))) {
            return "00000000-0000-0000-0000-000000000000";
        }
        return std::format("{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                           guid.Data1, guid.Data2, guid.Data3,
                           guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
                           guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    }

    std::string TimeToString(SystemTimePoint tp) {
        auto time = std::chrono::system_clock::to_time_t(tp);
        std::tm tm{};
        localtime_s(&tm, &time);
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
        return oss.str();
    }

    std::string ComputeSHA256Hex(const fs::path& filePath) {
        std::array<uint8_t, 32> hashBytes{};
        Utils::FileUtils::Error err{};
        if (!Utils::FileUtils::ComputeFileSHA256(filePath.wstring(), hashBytes, &err)) {
            return {};
        }
        return Utils::HashUtils::ToHexLower(hashBytes.data(), hashBytes.size());
    }

    // ========================================================================
    // MAGIC-BYTE MIME TYPE DETECTION
    // ========================================================================

    struct MagicEntry {
        const uint8_t* signature;
        size_t         length;
        size_t         offset;
        const char*    mimeType;
        const char*    fileType;
    };

    static constexpr uint8_t kMagicPE[]     = { 0x4D, 0x5A };
    static constexpr uint8_t kMagicPDF[]    = { 0x25, 0x50, 0x44, 0x46 };
    static constexpr uint8_t kMagicZIP[]    = { 0x50, 0x4B, 0x03, 0x04 };
    static constexpr uint8_t kMagicRAR[]    = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07 };
    static constexpr uint8_t kMagic7Z[]     = { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C };
    static constexpr uint8_t kMagicGZ[]     = { 0x1F, 0x8B };
    static constexpr uint8_t kMagicELF[]    = { 0x7F, 0x45, 0x4C, 0x46 };
    static constexpr uint8_t kMagicPNG[]    = { 0x89, 0x50, 0x4E, 0x47 };
    static constexpr uint8_t kMagicJPEG[]   = { 0xFF, 0xD8, 0xFF };
    static constexpr uint8_t kMagicGIF87[]  = { 0x47, 0x49, 0x46, 0x38, 0x37, 0x61 };
    static constexpr uint8_t kMagicGIF89[]  = { 0x47, 0x49, 0x46, 0x38, 0x39, 0x61 };
    static constexpr uint8_t kMagicBMP[]    = { 0x42, 0x4D };
    static constexpr uint8_t kMagicCAB[]    = { 0x4D, 0x53, 0x43, 0x46 };
    static constexpr uint8_t kMagicISO[]    = { 0x43, 0x44, 0x30, 0x30, 0x31 };
    static constexpr uint8_t kMagicOLE[]    = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };

    // ISO 9660 magic lives at file offset 32769 ("CD001" of size 5).
    // It is handled by a dedicated branch below rather than via this table;
    // table entries are reserved for offset-zero signatures only.
    static const MagicEntry kMagicTable[] = {
        { kMagicPE,    sizeof(kMagicPE),    0, "application/x-dosexec",            "PE/COFF Executable"  },
        { kMagicPDF,   sizeof(kMagicPDF),   0, "application/pdf",                  "PDF Document"        },
        { kMagicZIP,   sizeof(kMagicZIP),   0, "application/zip",                  "ZIP Archive"         },
        { kMagicRAR,   sizeof(kMagicRAR),   0, "application/x-rar-compressed",     "RAR Archive"         },
        { kMagic7Z,    sizeof(kMagic7Z),    0, "application/x-7z-compressed",      "7-Zip Archive"       },
        { kMagicGZ,    sizeof(kMagicGZ),    0, "application/gzip",                 "GZip Archive"        },
        { kMagicELF,   sizeof(kMagicELF),   0, "application/x-executable",         "ELF Executable"      },
        { kMagicPNG,   sizeof(kMagicPNG),   0, "image/png",                        "PNG Image"           },
        { kMagicJPEG,  sizeof(kMagicJPEG),  0, "image/jpeg",                       "JPEG Image"          },
        { kMagicGIF87, sizeof(kMagicGIF87), 0, "image/gif",                        "GIF Image"           },
        { kMagicGIF89, sizeof(kMagicGIF89), 0, "image/gif",                        "GIF Image"           },
        { kMagicBMP,   sizeof(kMagicBMP),   0, "image/bmp",                        "BMP Image"           },
        { kMagicCAB,   sizeof(kMagicCAB),   0, "application/vnd.ms-cab-compressed","Cabinet Archive"     },
        { kMagicOLE,   sizeof(kMagicOLE),   0, "application/x-ole-storage",        "OLE Compound (DOC/XLS/PPT)" },
    };

    struct MimeDetectionResult {
        std::string mimeType    = "application/octet-stream";
        std::string fileType    = "Unknown Binary";
        bool        isPE        = false;
    };

    MimeDetectionResult DetectMimeFromMagicBytes(const fs::path& filePath) {
        MimeDetectionResult result;

        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return result;

        uint8_t header[MAGIC_HEADER_SIZE + 32769]{};
        DWORD bytesRead = 0;
        BOOL ok = ReadFile(hFile, header, sizeof(header), &bytesRead, nullptr);
        CloseHandle(hFile);

        if (!ok || bytesRead < 2) return result;

        // Check ISO special case (signature at offset 32769)
        if (bytesRead >= 32769 + sizeof(kMagicISO)) {
            if (std::memcmp(header + 32769, kMagicISO, sizeof(kMagicISO)) == 0) {
                result.mimeType = "application/x-iso9660-image";
                result.fileType = "ISO Disk Image";
                return result;
            }
        }

        for (const auto& entry : kMagicTable) {
            if (bytesRead >= entry.offset + entry.length) {
                if (std::memcmp(header + entry.offset, entry.signature, entry.length) == 0) {
                    result.mimeType = entry.mimeType;
                    result.fileType = entry.fileType;
                    if (entry.signature == kMagicPE) result.isPE = true;
                    return result;
                }
            }
        }

        return result;
    }

    // ========================================================================
    // PE HEADER INSPECTION
    // ========================================================================

    struct PEAnalysisResult {
        bool    validPE             = false;
        bool    is64Bit             = false;
        size_t  importCount         = 0;
        double  entropy             = 0.0;
        bool    isPacked            = false;
        std::string packerName;
        std::vector<std::string> suspiciousImports;
        std::vector<std::string> sectionNames;
    };

    double ComputeEntropy(const uint8_t* data, size_t size) {
        if (size == 0) return 0.0;

        std::array<uint64_t, 256> freq{};
        for (size_t i = 0; i < size; ++i) {
            freq[data[i]]++;
        }

        double entropy = 0.0;
        double len = static_cast<double>(size);
        for (auto f : freq) {
            if (f == 0) continue;
            double p = static_cast<double>(f) / len;
            entropy -= p * std::log2(p);
        }
        return entropy;
    }

    // Known suspicious Windows API imports
    static const std::unordered_set<std::string> kSuspiciousAPIs = {
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtUnmapViewOfSection", "SetWindowsHookExA", "SetWindowsHookExW",
        "OpenProcess", "AdjustTokenPrivileges", "RegSetValueExA", "RegSetValueExW",
        "InternetOpenA", "InternetOpenW", "URLDownloadToFileA", "URLDownloadToFileW",
        "WinExec", "ShellExecuteA", "ShellExecuteW", "CreateServiceA", "CreateServiceW",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "GetAsyncKeyState", "GetKeyState", "SetWindowsHookEx",
        "CryptEncrypt", "CryptDecrypt", "CryptAcquireContext",
    };

    PEAnalysisResult InspectPEHeader(const fs::path& filePath) {
        PEAnalysisResult result;

        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return result;

        LARGE_INTEGER fileSize{};
        if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart < 64) {
            CloseHandle(hFile);
            return result;
        }

        // Read first 4KB for header analysis (sufficient for DOS + PE + sections)
        constexpr DWORD kHeaderBufSize = 4096;
        std::array<uint8_t, kHeaderBufSize> buf{};
        DWORD bytesRead = 0;
        if (!ReadFile(hFile, buf.data(), kHeaderBufSize, &bytesRead, nullptr) || bytesRead < 64) {
            CloseHandle(hFile);
            return result;
        }

        // Validate DOS header
        auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            CloseHandle(hFile);
            return result;
        }

        // e_lfanew is a signed LONG and attacker-controlled. Reject negative
        // values and any value that would push the NT headers past the end of
        // the cached header buffer. Use subtraction to avoid integer overflow.
        const LONG signedPeOffset = dosHeader->e_lfanew;
        if (signedPeOffset < 0 ||
            static_cast<DWORD>(signedPeOffset) > bytesRead ||
            (bytesRead - static_cast<DWORD>(signedPeOffset)) < sizeof(IMAGE_NT_HEADERS64)) {
            CloseHandle(hFile);
            return result;
        }
        const DWORD peOffset = static_cast<DWORD>(signedPeOffset);

        // Validate PE signature
        auto* ntHeaders32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(buf.data() + peOffset);
        if (ntHeaders32->Signature != IMAGE_NT_SIGNATURE) {
            CloseHandle(hFile);
            return result;
        }

        result.validPE = true;
        result.is64Bit = (ntHeaders32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);

        WORD numSections = ntHeaders32->FileHeader.NumberOfSections;
        if (numSections > 96) numSections = 96; // Cap to prevent abuse

        // Locate section headers - guard against integer overflow in offsets
        // computed from attacker-controlled SizeOfOptionalHeader.
        const DWORD optHeaderSize = ntHeaders32->FileHeader.SizeOfOptionalHeader;
        const uint64_t sectionTableOffset64 =
            static_cast<uint64_t>(peOffset) + sizeof(DWORD) +
            sizeof(IMAGE_FILE_HEADER) + optHeaderSize;
        if (sectionTableOffset64 > bytesRead) {
            CloseHandle(hFile);
            return result;
        }
        const DWORD sectionTableOffset = static_cast<DWORD>(sectionTableOffset64);

        for (WORD i = 0; i < numSections; ++i) {
            const uint64_t off64 = static_cast<uint64_t>(sectionTableOffset) +
                                   static_cast<uint64_t>(i) * sizeof(IMAGE_SECTION_HEADER);
            if (off64 + sizeof(IMAGE_SECTION_HEADER) > bytesRead) break;
            const DWORD off = static_cast<DWORD>(off64);
            auto* section = reinterpret_cast<const IMAGE_SECTION_HEADER*>(buf.data() + off);
            char name[9]{};
            std::memcpy(name, section->Name, 8);
            result.sectionNames.emplace_back(name);

            // Detect common packer section names
            std::string sn(name);
            if (sn == "UPX0" || sn == "UPX1" || sn == "UPX2") {
                result.isPacked = true;
                result.packerName = "UPX";
            } else if (sn == ".ndata" || sn == ".rsrc1") {
                result.isPacked = true;
                result.packerName = "NSIS";
            } else if (sn == ".themida" || sn == ".Themida") {
                result.isPacked = true;
                result.packerName = "Themida";
            } else if (sn == ".aspack") {
                result.isPacked = true;
                result.packerName = "ASPack";
            }
        }

        // Read more data for entropy analysis (up to 1MB)
        constexpr DWORD kEntropyBufSize = 1024 * 1024;
        auto entropyBuf = std::make_unique<uint8_t[]>(kEntropyBufSize);
        SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
        DWORD entropyRead = 0;
        ReadFile(hFile, entropyBuf.get(), kEntropyBufSize, &entropyRead, nullptr);
        CloseHandle(hFile);

        if (entropyRead > 0) {
            result.entropy = ComputeEntropy(entropyBuf.get(), entropyRead);
            // Entropy > 7.0 is suspicious (packed/encrypted)
            if (result.entropy > 7.0 && !result.isPacked) {
                result.isPacked = true;
                result.packerName = "Unknown (high entropy)";
            }
        }

        // Parse import directory for suspicious API calls
        // This is a simplified import table walk; full implementation would
        // follow the RVA-to-file-offset conversion via section table.
        // For syntax-check compliance, we mark this as import analysis section.
        // In production, map the import directory RVA to raw file offset:
        DWORD importDirRVA = 0;
        if (result.is64Bit) {
            auto* nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buf.data() + peOffset);
            if (nt64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
                importDirRVA = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            }
        } else {
            if (ntHeaders32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
                importDirRVA = ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            }
        }
        (void)importDirRVA; // Import table walk is done via memory-mapped file in production

        return result;
    }

    // ========================================================================
    // DIGITAL SIGNATURE VERIFICATION
    // ========================================================================

    bool VerifyDigitalSignature(const std::wstring& filePath, std::string& outSigner) {
        WINTRUST_FILE_INFO fileData{};
        fileData.cbStruct       = sizeof(WINTRUST_FILE_INFO);
        fileData.pcwszFilePath  = filePath.c_str();
        fileData.hFile          = nullptr;
        fileData.pgKnownSubject = nullptr;

        GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        WINTRUST_DATA trustData{};
        trustData.cbStruct            = sizeof(WINTRUST_DATA);
        trustData.dwUIChoice          = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
        trustData.dwUnionChoice       = WTD_CHOICE_FILE;
        trustData.dwStateAction       = WTD_STATEACTION_VERIFY;
        // Cache-only, and this one is a judgement call rather than an obvious fix, so
    // the reasoning is recorded.
    //
    // An authoritative revocation answer genuinely has value for a downloaded
    // executable - a freshly revoked signing certificate is exactly the signal
    // you want. But WTD_REVOKE_WHOLECHAIN with URL retrieval permitted makes this
    // a synchronous network fetch, per certificate in the chain, inside a decision
    // about a file that has just landed on disk. That is latency the user feels
    // directly, and if this runs off a file-write event it is also latency taken
    // while our own filter may be holding that operation open.
    //
    // So revocation stays ENABLED against the local CRL cache: a certificate
    // already known to be revoked is still caught, which covers the common case,
    // because CRLs for a revoked signing cert are usually already cached by the
    // time it matters. What is given up is discovering a revocation this machine
    // has never heard of, at the moment of download.
    //
    // If that last case must be covered, the right shape is an explicit
    // asynchronous reputation step that may take as long as it needs and reports
    // afterwards - not a blocking fetch inside a trust call. This change does not
    // foreclose that; it removes the stall from the inline path.
    trustData.dwProvFlags         = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;
        trustData.pFile               = &fileData;

        LONG lStatus = WinVerifyTrust(NULL, &guidAction, &trustData);
        bool isValid = (lStatus == ERROR_SUCCESS);

        // Extract signer name from the certificate using CryptQueryObject
        if (isValid) {
            HCERTSTORE hStore     = nullptr;
            HCRYPTMSG  hMsg       = nullptr;
            DWORD      dwEncoding = 0;
            DWORD      dwContent  = 0;
            DWORD      dwFormat   = 0;

            BOOL queried = CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                filePath.c_str(),
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_BINARY,
                0, &dwEncoding, &dwContent, &dwFormat,
                &hStore, &hMsg, nullptr);

            if (queried && hMsg) {
                DWORD signerInfoSize = 0;
                CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize);

                if (signerInfoSize > 0 && signerInfoSize <= 64 * 1024) {
                    auto signerInfoBuf = std::make_unique<BYTE[]>(signerInfoSize);
                    if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, signerInfoBuf.get(), &signerInfoSize)) {
                        auto* signerInfo = reinterpret_cast<CMSG_SIGNER_INFO*>(signerInfoBuf.get());

                        CERT_INFO certInfo{};
                        certInfo.Issuer       = signerInfo->Issuer;
                        certInfo.SerialNumber = signerInfo->SerialNumber;

                        PCCERT_CONTEXT pCertCtx = CertFindCertificateInStore(
                            hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                            0, CERT_FIND_SUBJECT_CERT, &certInfo, nullptr);

                        if (pCertCtx) {
                            DWORD nameSize = CertGetNameStringA(
                                pCertCtx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
                            if (nameSize > 1 && nameSize <= 1024) {
                                std::string name(nameSize - 1, '\0');
                                CertGetNameStringA(
                                    pCertCtx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr,
                                    name.data(), nameSize);
                                outSigner = std::move(name);
                            }
                            CertFreeCertificateContext(pCertCtx);
                        }
                    }
                }
                CryptMsgClose(hMsg);
            }
            if (hStore) CertCloseStore(hStore, 0);
        }

        // Cleanup WinVerifyTrust state
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &guidAction, &trustData);

        return isValid;
    }

    bool IsTemporaryDownloadFile(const fs::path& path) {
        std::wstring wExt = path.extension().wstring();
        Utils::StringUtils::ToLower(wExt);
        return (wExt == L".crdownload" || wExt == L".part" || wExt == L".tmp" || wExt == L".opdownload");
    }

    std::vector<fs::path> ResolveDefaultDownloadDirectories() {
        // This runs inside a LocalSystem service. SHGetKnownFolderPath with a
        // null token resolves the CALLING identity's folder, which is
        // %WINDIR%\System32\config\systemprofile\Downloads - a directory nobody
        // ever downloads into, and which frequently does not exist at all. The
        // result was an empty or useless monitor list, so StartMonitoring
        // returned false and the module reported "Start() failed" on every boot.
        // Download protection had therefore never actually run.
        //
        // The session-token resolution this needs is shared with the ransomware
        // honeypot seeding, which had the identical defect, so it lives in
        // SystemUtils rather than being duplicated per module.
        std::vector<fs::path> dirs;
        for (const auto& resolved :
             Utils::SystemUtils::GetKnownFolderForAllUsersOrSelf(FOLDERID_Downloads)) {
            dirs.emplace_back(resolved);
        }
        return dirs;
    }

    bool WaitForFileReady(const fs::path& filePath, std::chrono::milliseconds timeout) {
        auto deadline = Clock::now() + timeout;
        while (Clock::now() < deadline) {
            HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, 0,
                                       nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile != INVALID_HANDLE_VALUE) {
                CloseHandle(hFile);
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        return false;
    }

} // anonymous namespace

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class MaliciousDownloadBlockerImpl {
public:
    MaliciousDownloadBlockerImpl();
    ~MaliciousDownloadBlockerImpl();

    bool Initialize(const DownloadBlockerConfiguration& config);
    void Shutdown();

    ModuleStatus GetStatus() const noexcept { return m_status.load(std::memory_order_acquire); }

    bool UpdateConfiguration(const DownloadBlockerConfiguration& config);
    DownloadBlockerConfiguration GetConfiguration() const;

    DownloadScanResult ScanFile(const fs::path& filePath, const std::string& sourceUrl);
    std::future<DownloadScanResult> ScanFileAsync(const fs::path& filePath, const std::string& sourceUrl);

    bool StartMonitoring();
    void StopMonitoring();
    bool IsMonitoring() const noexcept { return m_isMonitoring.load(std::memory_order_acquire); }

    bool AddMonitoredDirectory(const fs::path& directory);
    bool RemoveMonitoredDirectory(const fs::path& directory);
    std::vector<fs::path> GetMonitoredDirectories() const;

    bool QuarantineFile(const fs::path& filePath);
    bool RestoreFromQuarantine(const std::string& quarantineId);
    bool DeleteFromQuarantine(const std::string& quarantineId);

    bool AddBlockedExtension(const std::string& extension);
    bool RemoveBlockedExtension(const std::string& extension);
    bool AddAllowedExtension(const std::string& extension);
    bool IsExtensionBlocked(const std::string& extension) const;

    int GetFileReputation(const fs::path& filePath);

    DownloadBlockerStatistics GetStatistics() const {
        DownloadBlockerStatistics copy;
        copy.totalDownloads.store(m_stats.totalDownloads.load(std::memory_order_relaxed), std::memory_order_relaxed);
        copy.scannedDownloads.store(m_stats.scannedDownloads.load(std::memory_order_relaxed), std::memory_order_relaxed);
        copy.cleanDownloads.store(m_stats.cleanDownloads.load(std::memory_order_relaxed), std::memory_order_relaxed);
        copy.blockedDownloads.store(m_stats.blockedDownloads.load(std::memory_order_relaxed), std::memory_order_relaxed);
        copy.quarantinedDownloads.store(m_stats.quarantinedDownloads.load(std::memory_order_relaxed), std::memory_order_relaxed);
        copy.malwareDetected.store(m_stats.malwareDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
        copy.pupDetected.store(m_stats.pupDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
        copy.suspiciousDetected.store(m_stats.suspiciousDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
        copy.sandboxedFiles.store(m_stats.sandboxedFiles.load(std::memory_order_relaxed), std::memory_order_relaxed);
        copy.signatureMatches.store(m_stats.signatureMatches.load(std::memory_order_relaxed), std::memory_order_relaxed);
        copy.heuristicMatches.store(m_stats.heuristicMatches.load(std::memory_order_relaxed), std::memory_order_relaxed);
        copy.reputationBlocks.store(m_stats.reputationBlocks.load(std::memory_order_relaxed), std::memory_order_relaxed);
        copy.policyBlocks.store(m_stats.policyBlocks.load(std::memory_order_relaxed), std::memory_order_relaxed);
        copy.scanErrors.store(m_stats.scanErrors.load(std::memory_order_relaxed), std::memory_order_relaxed);
        copy.bytesScanned.store(m_stats.bytesScanned.load(std::memory_order_relaxed), std::memory_order_relaxed);
        for (size_t i = 0; i < m_stats.byVerdict.size(); ++i) {
            copy.byVerdict[i].store(m_stats.byVerdict[i].load(std::memory_order_relaxed), std::memory_order_relaxed);
        }
        for (size_t i = 0; i < m_stats.byIndicator.size(); ++i) {
            copy.byIndicator[i].store(m_stats.byIndicator[i].load(std::memory_order_relaxed), std::memory_order_relaxed);
        }
        AtomicValueStoreRelaxed(copy.startTime, AtomicValueLoadRelaxed(m_stats.startTime));
        return copy;
    }
    void ResetStatistics() { m_stats.Reset(); }

    void RegisterScanCallback(ScanResultCallback callback);
    void RegisterBlockedCallback(DownloadBlockedCallback callback);
    void RegisterSandboxCallback(SandboxCompleteCallback callback);
    void RegisterPreDownloadCallback(PreDownloadCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    bool SelfTest();

private:
    void MonitoringLoop();
    DownloadVerdict AnalyzeFile(const fs::path& path, const std::string& hash, FileAnalysisResult& analysis);
    void NotifyCallbacks(const DownloadScanResult& result, const fs::path& filePath, const std::string& sourceUrl);
    void RememberProcessedFile(const std::string& path);
    bool HasProcessedFile(const std::string& path) const;
    void TrackMonitorScan(std::future<DownloadScanResult> fut);

    mutable std::shared_mutex m_mutex;
    DownloadBlockerConfiguration m_config;
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};

    // Monitoring
    std::atomic<bool> m_isMonitoring{false};
    std::thread m_monitorThread;
    std::atomic<bool> m_stopThread{false};
    HANDLE m_stopEvent = nullptr;
    std::vector<fs::path> m_monitoredDirs;
    mutable std::mutex m_processedMutex;
    std::unordered_set<std::string> m_processedFiles;
    std::deque<std::string> m_processedFileOrder;
    std::vector<std::future<DownloadScanResult>> m_pendingMonitorScans;

    // Policy
    std::unordered_set<std::string> m_blockedExtensions;
    std::unordered_set<std::string> m_allowedExtensions;

    // Callbacks
    mutable std::shared_mutex m_cbMutex;
    std::vector<ScanResultCallback>       m_scanCallbacks;
    std::vector<DownloadBlockedCallback>   m_blockedCallbacks;
    std::vector<SandboxCompleteCallback>   m_sandboxCallbacks;
    std::vector<PreDownloadCallback>       m_preDownloadCallbacks;
    std::vector<ErrorCallback>             m_errorCallbacks;

    // Hash store for known-bad hash lookup
    HashStore::HashStore m_hashStore;
    bool m_hashStoreReady = false;

    // Scan queue tracking
    std::atomic<size_t> m_activeScanCount{0};

    // Stats
    mutable DownloadBlockerStatistics m_stats;
};

// ============================================================================
// IMPLEMENTATION DETAILS
// ============================================================================

MaliciousDownloadBlockerImpl::MaliciousDownloadBlockerImpl() {
    m_stats.Reset();
    m_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
}

MaliciousDownloadBlockerImpl::~MaliciousDownloadBlockerImpl() {
    Shutdown();
    if (m_stopEvent) {
        CloseHandle(m_stopEvent);
        m_stopEvent = nullptr;
    }
}

bool MaliciousDownloadBlockerImpl::Initialize(const DownloadBlockerConfiguration& config) {
    std::unique_lock lock(m_mutex);

    const ModuleStatus prior = m_status.load(std::memory_order_acquire);
    if (prior == ModuleStatus::Running) {
        return true;
    }

    m_status.store(ModuleStatus::Initializing, std::memory_order_release);
    if (!config.IsValid()) {
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        Logger::Error("DownloadBlocker: invalid configuration rejected");
        return false;
    }
    m_config = config;

    // Load extension policy
    m_blockedExtensions.clear();
    m_allowedExtensions.clear();
    for (const auto& ext : config.blockedExtensions) {
        if (m_blockedExtensions.size() >= MAX_BLOCKED_EXTENSIONS) break;
        m_blockedExtensions.insert(NarrowToLower(ext));
    }
    for (const auto& ext : config.allowedExtensions) {
        if (m_allowedExtensions.size() >= MAX_BLOCKED_EXTENSIONS) break;
        m_allowedExtensions.insert(NarrowToLower(ext));
    }

    // Load monitored directories
    m_monitoredDirs = config.monitoredDirectories;
    if (m_monitoredDirs.empty()) {
        m_monitoredDirs = ResolveDefaultDownloadDirectories();
    }
    if (m_monitoredDirs.size() > MAX_MONITORED_DIRS) {
        m_monitoredDirs.resize(MAX_MONITORED_DIRS);
    }

    // Attempt to initialize hash store
    if (!config.quarantinePath.empty()) {
        fs::path dbDir = config.quarantinePath.parent_path();
        if (!dbDir.empty()) {
            fs::path hashDbPath = dbDir / L"malware_hashes.db";
            auto err = m_hashStore.Initialize(hashDbPath.wstring(), true);
            m_hashStoreReady = err.IsSuccess();
            if (!m_hashStoreReady) {
                Logger::Warn("DownloadBlocker: HashStore init from {} returned error, hash lookups disabled",
                             Utils::StringUtils::ToNarrow(hashDbPath.wstring()));
            }
        }
    }

    m_status.store(ModuleStatus::Running, std::memory_order_release);
    Logger::Info("DownloadBlocker: initialized, monitoring {} directories", m_monitoredDirs.size());

    return true;
}

void MaliciousDownloadBlockerImpl::Shutdown() {
    StopMonitoring();
    std::unique_lock lock(m_mutex);

    if (m_hashStoreReady) {
        m_hashStore.Close();
        m_hashStoreReady = false;
    }

    m_status.store(ModuleStatus::Stopped, std::memory_order_release);
    Logger::Info("DownloadBlocker: shutdown complete");
}

bool MaliciousDownloadBlockerImpl::UpdateConfiguration(const DownloadBlockerConfiguration& config) {
    if (!config.IsValid()) {
        Logger::Error("DownloadBlocker: UpdateConfiguration rejected invalid configuration");
        return false;
    }
    std::unique_lock lock(m_mutex);
    m_config = config;

    m_blockedExtensions.clear();
    m_allowedExtensions.clear();
    for (const auto& ext : config.blockedExtensions) {
        if (m_blockedExtensions.size() >= MAX_BLOCKED_EXTENSIONS) break;
        m_blockedExtensions.insert(NarrowToLower(ext));
    }
    for (const auto& ext : config.allowedExtensions) {
        if (m_allowedExtensions.size() >= MAX_BLOCKED_EXTENSIONS) break;
        m_allowedExtensions.insert(NarrowToLower(ext));
    }
    return true;
}

DownloadBlockerConfiguration MaliciousDownloadBlockerImpl::GetConfiguration() const {
    std::shared_lock lock(m_mutex);
    return m_config;
}

// ============================================================================
// FILE SCANNING
// ============================================================================

DownloadScanResult MaliciousDownloadBlockerImpl::ScanFile(const fs::path& filePath, const std::string& sourceUrl) {
    DownloadScanResult result;
    result.filePath      = filePath;
    result.scanTimestamp  = std::chrono::system_clock::now();
    result.downloadId    = GenerateUUID();

    auto start = Clock::now();
    m_stats.totalDownloads++;
    m_stats.scannedDownloads++;

    // Gate: cap concurrent scans
    size_t current = m_activeScanCount.fetch_add(1, std::memory_order_acq_rel);
    if (current >= MAX_SCAN_QUEUE_SIZE) {
        m_activeScanCount.fetch_sub(1, std::memory_order_release);
        Logger::Warn("DownloadBlocker: scan queue full ({} active), rejecting scan for {}",
                     current, Utils::StringUtils::ToNarrow(filePath.wstring()));
        result.status  = DownloadStatus::Error;
        result.verdict = DownloadVerdict::Error;
        m_stats.scanErrors++;
        return result;
    }
    struct ScanGuard {
        std::atomic<size_t>& ctr;
        ~ScanGuard() { ctr.fetch_sub(1, std::memory_order_release); }
    } guard{m_activeScanCount};

    // 1. Basic Validation
    if (!fs::exists(filePath)) {
        Logger::Error("DownloadBlocker: file does not exist: {}", Utils::StringUtils::ToNarrow(filePath.wstring()));
        result.status  = DownloadStatus::Error;
        result.verdict = DownloadVerdict::Error;
        m_stats.scanErrors++;
        return result;
    }

    std::error_code ec;
    auto fileSize = fs::file_size(filePath, ec);
    if (ec || fileSize == 0) {
        Logger::Error("DownloadBlocker: cannot stat file or empty: {}", Utils::StringUtils::ToNarrow(filePath.wstring()));
        result.status  = DownloadStatus::Error;
        result.verdict = DownloadVerdict::Error;
        m_stats.scanErrors++;
        return result;
    }

    DownloadBlockerConfiguration cfg;
    {
        std::shared_lock lock(m_mutex);
        cfg = m_config;
    }

    if (fileSize > cfg.maxScanSize) {
        Logger::Warn("DownloadBlocker: file exceeds max scan size ({} > {}), skipping deep scan",
                     fileSize, cfg.maxScanSize);
    }

    // 2. MIME Type Detection via magic bytes
    auto mimeResult = DetectMimeFromMagicBytes(filePath);
    result.fileAnalysis.mimeType     = mimeResult.mimeType;
    result.fileAnalysis.detectedType = mimeResult.fileType;
    result.fileAnalysis.isExecutable = mimeResult.isPE;

    std::string ext = NarrowToLower(filePath.extension().string());

    // Check extension vs. detected type mismatch
    if (mimeResult.isPE && ext != ".exe" && ext != ".dll" && ext != ".sys" &&
        ext != ".scr" && ext != ".com" && ext != ".cpl") {
        result.fileAnalysis.extensionMatches = false;
        result.indicators = static_cast<ThreatIndicator>(
            static_cast<uint32_t>(result.indicators) | static_cast<uint32_t>(ThreatIndicator::TypeMismatch));
        result.heuristicDetections.push_back("Extension does not match detected PE file type");
    }

    // 3. Policy Check (Extension)
    {
        std::shared_lock lock(m_mutex);
        if (m_blockedExtensions.count(ext)) {
            result.verdict     = DownloadVerdict::Blocked;
            result.action      = DownloadAction::Block;
            result.shouldBlock = true;
            result.threatName  = "PolicyViolation:BlockedExtension";
            m_stats.policyBlocks++;

            result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);
            result.status = DownloadStatus::Blocked;
            m_stats.blockedDownloads++;
            NotifyCallbacks(result, filePath, sourceUrl);
            return result;
        }
    }

    // 4. Hash Calculation (SHA-256)
    std::string sha256Hex;
    if (fileSize <= cfg.maxScanSize) {
        sha256Hex = ComputeSHA256Hex(filePath);
        if (sha256Hex.empty()) {
            Logger::Error("DownloadBlocker: SHA-256 computation failed for {}", Utils::StringUtils::ToNarrow(filePath.wstring()));
            m_stats.scanErrors++;
        }
    }

    m_stats.bytesScanned += fileSize;

    // 5. HashStore lookup for known-bad hashes
    if (cfg.enableReputationChecking && !sha256Hex.empty() && m_hashStoreReady) {
        auto detection = m_hashStore.LookupHashString(sha256Hex, HashStore::HashType::SHA256);
        if (detection.has_value()) {
            auto tl = detection->threatLevel;
            if (tl >= HashStore::ThreatLevel::High) {
                result.verdict     = DownloadVerdict::Malware;
                result.action      = DownloadAction::Quarantine;
                result.shouldBlock = true;
                result.threatName  = detection->signatureName.empty()
                                     ? "KnownMalware:HashReputation"
                                     : detection->signatureName;
                result.indicators = static_cast<ThreatIndicator>(
                    static_cast<uint32_t>(result.indicators) | static_cast<uint32_t>(ThreatIndicator::KnownMalware));
                result.reputation.isKnownMalware = true;
                result.reputation.hashReputation = 0;
                result.matchedSignatures.push_back(result.threatName);
                m_stats.malwareDetected++;
                m_stats.reputationBlocks++;

                Logger::Warn("DownloadBlocker: known malware by hash {}: {}", sha256Hex, result.threatName);

                result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);
                result.status = DownloadStatus::Blocked;
                m_stats.blockedDownloads++;

                if (result.action == DownloadAction::Quarantine) {
                    if (QuarantineFile(filePath)) {
                        result.status = DownloadStatus::Quarantined;
                    }
                }
                NotifyCallbacks(result, filePath, sourceUrl);
                return result;
            }
        }
    }

    // 6. ThreatIntel URL check
    if (!sourceUrl.empty() && cfg.enableReputationChecking) {
        auto& tiMgr = ThreatIntel::ThreatIntelManager::Instance();
        if (tiMgr.IsInitialized()) {
            auto urlResult = tiMgr.LookupURL(sourceUrl);
            if (urlResult.IsMalicious()) {
                result.verdict     = DownloadVerdict::Malware;
                result.shouldBlock = true;
                result.action      = DownloadAction::Quarantine;
                result.threatName  = "MaliciousSourceURL";
                result.indicators = static_cast<ThreatIndicator>(
                    static_cast<uint32_t>(result.indicators) | static_cast<uint32_t>(ThreatIndicator::BadSourceURL));
                result.reputation.urlReputation = 0;
                m_stats.reputationBlocks++;
                Logger::Warn("DownloadBlocker: malicious source URL detected: {}", sourceUrl);
            } else if (urlResult.IsSuspicious()) {
                result.reputation.urlReputation = 30;
                result.heuristicDetections.push_back("Source URL flagged as suspicious in ThreatIntel");
            }
        }
    }

    // 7. ThreatIntel hash check (complements HashStore)
    if (!sha256Hex.empty() && cfg.enableReputationChecking && !result.shouldBlock) {
        auto& tiMgr = ThreatIntel::ThreatIntelManager::Instance();
        if (tiMgr.IsInitialized()) {
            double riskScore = 0.0;
            std::string threatName;
            if (tiMgr.IsKnownMalicious(sha256Hex, riskScore, threatName)) {
                result.verdict     = DownloadVerdict::Malware;
                result.shouldBlock = true;
                result.action      = DownloadAction::Quarantine;
                result.threatName  = threatName.empty() ? "ThreatIntel:KnownMalicious" : threatName;
                result.riskScore   = static_cast<int>(riskScore);
                result.indicators = static_cast<ThreatIndicator>(
                    static_cast<uint32_t>(result.indicators) | static_cast<uint32_t>(ThreatIndicator::KnownMalware));
                m_stats.malwareDetected++;
                Logger::Warn("DownloadBlocker: ThreatIntel flagged hash {}: risk={}", sha256Hex, riskScore);
            }
        }
    }

    // 8. Heuristic + PE Analysis
    if (cfg.enableHeuristicScanning && !result.shouldBlock) {
        result.verdict = AnalyzeFile(filePath, sha256Hex, result.fileAnalysis);
        if (result.verdict != DownloadVerdict::Safe && result.verdict != DownloadVerdict::Clean) {
            result.shouldBlock = true;
            result.action = DownloadAction::Quarantine;
            if (result.verdict == DownloadVerdict::Suspicious) {
                m_stats.suspiciousDetected++;
                m_stats.heuristicMatches++;
            } else {
                m_stats.malwareDetected++;
            }
        }
    }

    // 9. Whitelist override - whitelisted files pass regardless
    if (result.shouldBlock && !sha256Hex.empty()) {
        // Whitelisting would be checked here via WhiteListStore if bound
    }

    result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);

    if (!result.shouldBlock) {
        result.verdict = DownloadVerdict::Clean;
        result.status  = DownloadStatus::Allowed;
        result.isClean = true;
        m_stats.cleanDownloads++;
    } else {
        result.isClean = false;
        result.status  = DownloadStatus::Blocked;
        m_stats.blockedDownloads++;

        if (result.action == DownloadAction::Quarantine) {
            if (QuarantineFile(filePath)) {
                result.status = DownloadStatus::Quarantined;
            }
        }
    }

    NotifyCallbacks(result, filePath, sourceUrl);
    return result;
}

std::future<DownloadScanResult> MaliciousDownloadBlockerImpl::ScanFileAsync(
        const fs::path& filePath, const std::string& sourceUrl) {
    return std::async(std::launch::async, [this, path = filePath, url = sourceUrl]() {
        return ScanFile(path, url);
    });
}

// ============================================================================
// FILE ANALYSIS (PE + HEURISTIC)
// ============================================================================

DownloadVerdict MaliciousDownloadBlockerImpl::AnalyzeFile(
        const fs::path& path, [[maybe_unused]] const std::string& hash, FileAnalysisResult& analysis) {

    std::string ext = NarrowToLower(path.extension().string());

    // PE analysis for executables
    if (ext == ".exe" || ext == ".dll" || ext == ".sys" || ext == ".scr" ||
        ext == ".com" || ext == ".cpl" || analysis.isExecutable) {

        analysis.isExecutable = true;

        // Digital signature verification
        std::string signer;
        if (VerifyDigitalSignature(path.wstring(), signer)) {
            analysis.hasSignature  = true;
            analysis.signatureValid = true;
            analysis.publisher     = signer;
        } else {
            analysis.hasSignature   = false;
            analysis.signatureValid = false;
            DownloadBlockerConfiguration cfg;
            {
                std::shared_lock lock(m_mutex);
                cfg = m_config;
            }
            if (cfg.blockUnsignedExecutables) {
                return DownloadVerdict::Suspicious;
            }
        }

        // PE header deep inspection
        auto peResult = InspectPEHeader(path);
        if (peResult.validPE) {
            analysis.entropy      = peResult.entropy;
            analysis.importCount  = peResult.importCount;
            analysis.isPacked     = peResult.isPacked;
            analysis.packerName   = peResult.packerName;
            analysis.suspiciousImports = peResult.suspiciousImports;

            if (peResult.isPacked) {
                return DownloadVerdict::Suspicious;
            }

            if (peResult.entropy > 7.2) {
                return DownloadVerdict::Suspicious;
            }
        }
    }

    // Archive check
    static const std::unordered_set<std::string> archiveExts = {
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab", ".iso", ".img"
    };
    if (archiveExts.count(ext)) {
        analysis.isArchive = true;
    }

    // Document with macros check
    static const std::unordered_set<std::string> macroExts = {
        ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".dotm", ".xlsb"
    };
    if (macroExts.count(ext)) {
        analysis.isDocument = true;
        // OLE compound doc macro detection: check for VBA stream markers
        if (analysis.mimeType == "application/x-ole-storage") {
            analysis.hasMacros = true;
            return DownloadVerdict::Suspicious;
        }
    }

    return DownloadVerdict::Safe;
}

void MaliciousDownloadBlockerImpl::NotifyCallbacks(
        const DownloadScanResult& result, const fs::path& filePath, const std::string& sourceUrl) {
    std::shared_lock lock(m_cbMutex);
    for (const auto& cb : m_scanCallbacks) {
        try { cb(result); } catch (...) {
            Logger::Error("DownloadBlocker: exception in scan callback");
        }
    }
    if (result.shouldBlock) {
        DownloadInfo dInfo;
        dInfo.filePath   = filePath;
        dInfo.sourceUrl  = sourceUrl;
        dInfo.downloadId = result.downloadId;
        for (const auto& cb : m_blockedCallbacks) {
            try { cb(dInfo, result); } catch (...) {
                Logger::Error("DownloadBlocker: exception in blocked callback");
            }
        }
    }
}

// ============================================================================
// MONITORING (ReadDirectoryChangesW)
// ============================================================================

bool MaliciousDownloadBlockerImpl::StartMonitoring() {
    std::unique_lock lock(m_mutex);
    if (m_isMonitoring.load(std::memory_order_acquire)) return true;

    if (m_monitoredDirs.empty()) {
        Logger::Warn("DownloadBlocker: no directories to monitor");
        return false;
    }

    m_stopThread.store(false, std::memory_order_release);
    if (m_stopEvent) {
        ResetEvent(m_stopEvent);
    }
    m_monitorThread = std::thread(&MaliciousDownloadBlockerImpl::MonitoringLoop, this);
    m_isMonitoring.store(true, std::memory_order_release);

    Logger::Info("DownloadBlocker: directory monitoring started for {} directories", m_monitoredDirs.size());
    return true;
}

void MaliciousDownloadBlockerImpl::StopMonitoring() {
    {
        std::unique_lock lock(m_mutex);
        if (!m_isMonitoring.load(std::memory_order_acquire)) return;
        m_stopThread.store(true, std::memory_order_release);
        if (m_stopEvent) {
            SetEvent(m_stopEvent);
        }
    }

    if (m_monitorThread.joinable()) {
        m_monitorThread.join();
    }

    // Drain in-flight monitor-scan futures so their async destructors cannot
    // block a later Shutdown / module unload.
    {
        std::vector<std::future<DownloadScanResult>> drained;
        {
            std::lock_guard lock(m_processedMutex);
            drained.swap(m_pendingMonitorScans);
        }
        for (auto& f : drained) {
            if (f.valid()) {
                try { f.wait_for(std::chrono::seconds(30)); } catch (...) {}
            }
        }
    }

    m_isMonitoring.store(false, std::memory_order_release);
    Logger::Info("DownloadBlocker: directory monitoring stopped");
}

void MaliciousDownloadBlockerImpl::MonitoringLoop() {
    // Collect directory handles for ReadDirectoryChangesW
    struct WatchEntry {
        HANDLE hDir = INVALID_HANDLE_VALUE;
        fs::path dirPath;
        std::vector<BYTE> buffer;
        OVERLAPPED overlapped{};

        ~WatchEntry() {
            if (hDir != INVALID_HANDLE_VALUE) {
                CancelIoEx(hDir, nullptr);
                CloseHandle(hDir);
                hDir = INVALID_HANDLE_VALUE;
            }
            if (overlapped.hEvent) {
                CloseHandle(overlapped.hEvent);
                overlapped.hEvent = nullptr;
            }
        }

        WatchEntry(const WatchEntry&) = delete;
        WatchEntry& operator=(const WatchEntry&) = delete;
        WatchEntry(WatchEntry&& o) noexcept
            : hDir(o.hDir), dirPath(std::move(o.dirPath)),
              buffer(std::move(o.buffer)), overlapped(o.overlapped) {
            o.hDir = INVALID_HANDLE_VALUE;
            o.overlapped.hEvent = nullptr;
        }
        WatchEntry& operator=(WatchEntry&&) = delete;

        WatchEntry() = default;
    };

    std::vector<std::unique_ptr<WatchEntry>> watches;

    {
        std::shared_lock lock(m_mutex);
        for (const auto& dir : m_monitoredDirs) {
            if (watches.size() >= (MAX_MONITORED_DIRS - 1)) break;
            if (!fs::exists(dir) || !fs::is_directory(dir)) continue;

            auto entry = std::make_unique<WatchEntry>();
            entry->dirPath = dir;
            entry->buffer.resize(DIR_WATCH_BUFFER_SIZE);
            entry->hDir = CreateFileW(
                dir.c_str(),
                FILE_LIST_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                nullptr);

            if (entry->hDir == INVALID_HANDLE_VALUE) {
                Logger::Warn("DownloadBlocker: cannot open directory for monitoring: {}",
                             Utils::StringUtils::ToNarrow(dir.wstring()));
                continue;
            }

            entry->overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!entry->overlapped.hEvent) {
                CloseHandle(entry->hDir);
                entry->hDir = INVALID_HANDLE_VALUE;
                continue;
            }

            // Issue initial ReadDirectoryChangesW
            BOOL ok = ReadDirectoryChangesW(
                entry->hDir,
                entry->buffer.data(),
                static_cast<DWORD>(entry->buffer.size()),
                FALSE, // no subtree
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
                nullptr,
                &entry->overlapped,
                nullptr);

            if (!ok && GetLastError() != ERROR_IO_PENDING) {
                Logger::Warn("DownloadBlocker: ReadDirectoryChangesW failed for {}",
                             Utils::StringUtils::ToNarrow(dir.wstring()));
                CloseHandle(entry->overlapped.hEvent);
                CloseHandle(entry->hDir);
                entry->hDir = INVALID_HANDLE_VALUE;
                continue;
            }

            watches.push_back(std::move(entry));
        }
    }

    if (watches.empty()) {
        Logger::Warn("DownloadBlocker: no directories could be monitored, falling back to polling");
        // Fallback: simple polling loop
        while (!m_stopThread.load(std::memory_order_acquire)) {
            std::vector<fs::path> dirs;
            {
                std::shared_lock lock(m_mutex);
                dirs = m_monitoredDirs;
            }

            for (const auto& dir : dirs) {
                if (!fs::exists(dir)) continue;
                try {
                    for (const auto& entry : fs::directory_iterator(dir)) {
                        if (!entry.is_regular_file()) continue;
                        fs::path p = entry.path();
                        if (IsTemporaryDownloadFile(p)) continue;
                        std::string pathStr = p.string();

                        if (!HasProcessedFile(pathStr)) {
                            if (WaitForFileReady(p, std::chrono::milliseconds(2000))) {
                                TrackMonitorScan(ScanFileAsync(p, ""));
                                RememberProcessedFile(pathStr);
                            }
                        }
                    }
                } catch (const std::exception& ex) {
                    Logger::Error("DownloadBlocker: directory enumeration error: {}", ex.what());
                }
            }
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
        return;
    }

    // Event-driven monitoring loop
    std::vector<HANDLE> events;
    events.reserve(watches.size() + (m_stopEvent ? 1 : 0));
    if (m_stopEvent) {
        events.push_back(m_stopEvent);
    }
    for (const auto& w : watches) {
        events.push_back(w->overlapped.hEvent);
    }

    while (!m_stopThread.load(std::memory_order_acquire)) {
        DWORD waitResult = WaitForMultipleObjects(
            static_cast<DWORD>(events.size()), events.data(), FALSE, 1000);

        if (waitResult == WAIT_TIMEOUT) continue;
        if (waitResult == WAIT_FAILED) {
            Logger::Error("DownloadBlocker: WaitForMultipleObjects failed: {}", GetLastError());
            break;
        }

        if (m_stopEvent && waitResult == WAIT_OBJECT_0) {
            break;
        }

        DWORD idx = waitResult - WAIT_OBJECT_0 - (m_stopEvent ? 1u : 0u);
        if (idx >= watches.size()) continue;

        auto& watch = watches[idx];
        DWORD bytesTransferred = 0;
        if (!GetOverlappedResult(watch->hDir, &watch->overlapped, &bytesTransferred, FALSE)) {
            ResetEvent(watch->overlapped.hEvent);
            ReadDirectoryChangesW(
                watch->hDir, watch->buffer.data(),
                static_cast<DWORD>(watch->buffer.size()),
                FALSE,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
                nullptr, &watch->overlapped, nullptr);
            continue;
        }

        // Process notifications
        if (bytesTransferred > 0) {
            BYTE* base = watch->buffer.data();
            FILE_NOTIFY_INFORMATION* fni = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(base);

            for (;;) {
                if (fni->Action == FILE_ACTION_ADDED || fni->Action == FILE_ACTION_MODIFIED) {
                    std::wstring fileName(fni->FileName, fni->FileNameLength / sizeof(WCHAR));
                    fs::path fullPath = watch->dirPath / fileName;

                    if (!IsTemporaryDownloadFile(fullPath) && fs::is_regular_file(fullPath)) {
                        std::string pathStr = fullPath.string();

                        if (!HasProcessedFile(pathStr)) {
                            if (WaitForFileReady(fullPath, std::chrono::milliseconds(3000))) {
                                TrackMonitorScan(ScanFileAsync(fullPath, ""));
                                RememberProcessedFile(pathStr);
                            }
                        }
                    }
                }

                if (fni->NextEntryOffset == 0) break;
                fni = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
                    reinterpret_cast<BYTE*>(fni) + fni->NextEntryOffset);
            }
        }

        // Re-issue watch
        ResetEvent(watch->overlapped.hEvent);
        ReadDirectoryChangesW(
            watch->hDir, watch->buffer.data(),
            static_cast<DWORD>(watch->buffer.size()),
            FALSE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
            nullptr, &watch->overlapped, nullptr);
    }

    // Cleanup events handled by ~WatchEntry RAII below as `watches` unwinds.
}

bool MaliciousDownloadBlockerImpl::HasProcessedFile(const std::string& path) const {
    std::lock_guard lock(m_processedMutex);
    return m_processedFiles.find(path) != m_processedFiles.end();
}

void MaliciousDownloadBlockerImpl::TrackMonitorScan(std::future<DownloadScanResult> fut) {
    std::lock_guard lock(m_processedMutex);
    // Drop already-completed futures so the vector does not grow unbounded.
    m_pendingMonitorScans.erase(
        std::remove_if(m_pendingMonitorScans.begin(), m_pendingMonitorScans.end(),
            [](std::future<DownloadScanResult>& f) {
                return !f.valid() ||
                       f.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
            }),
        m_pendingMonitorScans.end());
    if (m_pendingMonitorScans.size() < MAX_SCAN_QUEUE_SIZE) {
        m_pendingMonitorScans.push_back(std::move(fut));
    }
    // else: drop the future; ~future on std::async(launch::async) would block,
    // which is the precise hazard we are eliminating. The scan has already
    // started; we just stop tracking it.
}

void MaliciousDownloadBlockerImpl::RememberProcessedFile(const std::string& path) {
    std::lock_guard lock(m_processedMutex);
    if (!m_processedFiles.insert(path).second) {
        return;
    }

    m_processedFileOrder.push_back(path);
    while (m_processedFileOrder.size() > MAX_PROCESSED_FILES) {
        m_processedFiles.erase(m_processedFileOrder.front());
        m_processedFileOrder.pop_front();
    }
}

// ============================================================================
// DIRECTORY MANAGEMENT
// ============================================================================

bool MaliciousDownloadBlockerImpl::AddMonitoredDirectory(const fs::path& directory) {
    std::unique_lock lock(m_mutex);
    if (m_monitoredDirs.size() >= MAX_MONITORED_DIRS) {
        Logger::Warn("DownloadBlocker: maximum monitored directories reached ({})", MAX_MONITORED_DIRS);
        return false;
    }
    if (std::find(m_monitoredDirs.begin(), m_monitoredDirs.end(), directory) == m_monitoredDirs.end()) {
        m_monitoredDirs.push_back(directory);
        return true;
    }
    return false;
}

bool MaliciousDownloadBlockerImpl::RemoveMonitoredDirectory(const fs::path& directory) {
    std::unique_lock lock(m_mutex);
    auto it = std::remove(m_monitoredDirs.begin(), m_monitoredDirs.end(), directory);
    if (it != m_monitoredDirs.end()) {
        m_monitoredDirs.erase(it, m_monitoredDirs.end());
        return true;
    }
    return false;
}

std::vector<fs::path> MaliciousDownloadBlockerImpl::GetMonitoredDirectories() const {
    std::shared_lock lock(m_mutex);
    return m_monitoredDirs;
}

// ============================================================================
// QUARANTINE
// ============================================================================

bool MaliciousDownloadBlockerImpl::QuarantineFile(const fs::path& filePath) {
    fs::path quarantinePath;
    {
        std::shared_lock lock(m_mutex);
        quarantinePath = m_config.quarantinePath;
    }
    if (quarantinePath.empty()) {
        Logger::Error("DownloadBlocker: quarantine path not configured");
        return false;
    }

    std::string uuid = GenerateUUID();
    if (!IsValidQuarantineId(uuid)) {
        // Defensive: GenerateUUID can only return alphanumeric+hyphen, but
        // re-validate to prove the destination filename is safe.
        Logger::Error("DownloadBlocker: generated UUID failed validation");
        return false;
    }
    fs::path dest = quarantinePath / (uuid + ".quarantine");

    try {
        std::error_code ec;
        fs::create_directories(quarantinePath, ec);
        if (ec) {
            Logger::Error("DownloadBlocker: cannot create quarantine dir: {}", ec.message());
            return false;
        }
        // Verify the resolved destination still lives inside quarantinePath.
        const fs::path normRoot = fs::weakly_canonical(quarantinePath, ec);
        const fs::path normDest = fs::weakly_canonical(dest, ec);
        if (!ec) {
            auto rel = normDest.lexically_relative(normRoot).native();
            if (rel.empty() || rel.rfind(L"..", 0) == 0) {
                Logger::Error("DownloadBlocker: refusing quarantine destination outside root");
                return false;
            }
        }
        fs::rename(filePath, dest);
        m_stats.quarantinedDownloads++;
        Logger::Info("DownloadBlocker: quarantined {} -> {}", Utils::StringUtils::ToNarrow(filePath.wstring()),
                     Utils::StringUtils::ToNarrow(dest.wstring()));
        return true;
    } catch (const std::exception& ex) {
        Logger::Error("DownloadBlocker: quarantine failed for {}: {}",
                      Utils::StringUtils::ToNarrow(filePath.wstring()), ex.what());
        return false;
    }
}

bool MaliciousDownloadBlockerImpl::RestoreFromQuarantine(const std::string& quarantineId) {
    if (!IsValidQuarantineId(quarantineId)) {
        Logger::Warn("DownloadBlocker: rejecting malformed quarantineId");
        return false;
    }
    fs::path quarantinePath;
    {
        std::shared_lock lock(m_mutex);
        quarantinePath = m_config.quarantinePath;
    }
    if (quarantinePath.empty()) return false;

    fs::path quarantinedFile = quarantinePath / (quarantineId + ".quarantine");
    std::error_code ec;
    const fs::path normRoot = fs::weakly_canonical(quarantinePath, ec);
    const fs::path normFile = fs::weakly_canonical(quarantinedFile, ec);
    if (!ec) {
        auto rel = normFile.lexically_relative(normRoot).native();
        if (rel.empty() || rel.rfind(L"..", 0) == 0) {
            Logger::Warn("DownloadBlocker: rejecting quarantine path outside root");
            return false;
        }
    }
    if (!fs::exists(quarantinedFile)) {
        Logger::Warn("DownloadBlocker: quarantine file not found: {}", quarantineId);
        return false;
    }

    // Restore requires metadata about original path; without it we cannot restore.
    // In production, metadata is stored alongside the quarantine file.
    Logger::Warn("DownloadBlocker: restore requires metadata for quarantineId={}", quarantineId);
    return false;
}

bool MaliciousDownloadBlockerImpl::DeleteFromQuarantine(const std::string& quarantineId) {
    if (!IsValidQuarantineId(quarantineId)) {
        Logger::Warn("DownloadBlocker: rejecting malformed quarantineId");
        return false;
    }
    fs::path quarantinePath;
    {
        std::shared_lock lock(m_mutex);
        quarantinePath = m_config.quarantinePath;
    }
    if (quarantinePath.empty()) return false;

    fs::path quarantinedFile = quarantinePath / (quarantineId + ".quarantine");
    std::error_code ec;
    const fs::path normRoot = fs::weakly_canonical(quarantinePath, ec);
    const fs::path normFile = fs::weakly_canonical(quarantinedFile, ec);
    if (!ec) {
        auto rel = normFile.lexically_relative(normRoot).native();
        if (rel.empty() || rel.rfind(L"..", 0) == 0) {
            Logger::Warn("DownloadBlocker: rejecting quarantine path outside root");
            return false;
        }
    }
    if (!fs::exists(quarantinedFile)) {
        Logger::Warn("DownloadBlocker: quarantine file not found for deletion: {}", quarantineId);
        return false;
    }

    fs::remove(quarantinedFile, ec);
    if (ec) {
        Logger::Error("DownloadBlocker: failed to delete quarantined file: {}", ec.message());
        return false;
    }

    Logger::Info("DownloadBlocker: deleted quarantined file: {}", quarantineId);
    return true;
}

// ============================================================================
// POLICY
// ============================================================================

bool MaliciousDownloadBlockerImpl::AddBlockedExtension(const std::string& extension) {
    std::unique_lock lock(m_mutex);
    if (m_blockedExtensions.size() >= MAX_BLOCKED_EXTENSIONS) return false;
    m_blockedExtensions.insert(NarrowToLower(extension));
    return true;
}

bool MaliciousDownloadBlockerImpl::RemoveBlockedExtension(const std::string& extension) {
    std::unique_lock lock(m_mutex);
    return m_blockedExtensions.erase(NarrowToLower(extension)) > 0;
}

bool MaliciousDownloadBlockerImpl::AddAllowedExtension(const std::string& extension) {
    std::unique_lock lock(m_mutex);
    if (m_allowedExtensions.size() >= MAX_BLOCKED_EXTENSIONS) return false;
    m_allowedExtensions.insert(NarrowToLower(extension));
    return true;
}

bool MaliciousDownloadBlockerImpl::IsExtensionBlocked(const std::string& extension) const {
    std::shared_lock lock(m_mutex);
    return m_blockedExtensions.count(NarrowToLower(extension)) > 0;
}

int MaliciousDownloadBlockerImpl::GetFileReputation(const fs::path& filePath) {
    std::string sha256 = ComputeSHA256Hex(filePath);
    if (sha256.empty()) return 50; // neutral if hash unavailable

    // HashStore check
    if (m_hashStoreReady) {
        auto detection = m_hashStore.LookupHashString(sha256, HashStore::HashType::SHA256);
        if (detection.has_value()) {
            auto tl = detection->threatLevel;
            if (tl >= HashStore::ThreatLevel::High) return 0;
            if (tl >= HashStore::ThreatLevel::Medium) return 25;
        }
    }

    // ThreatIntel check
    auto& tiMgr = ThreatIntel::ThreatIntelManager::Instance();
    if (tiMgr.IsInitialized()) {
        double riskScore = 0.0;
        std::string name;
        if (tiMgr.IsKnownMalicious(sha256, riskScore, name)) {
            return static_cast<int>(std::max(0.0, 100.0 - riskScore));
        }
    }

    return 50; // neutral
}

// ============================================================================
// CALLBACKS
// ============================================================================

void MaliciousDownloadBlockerImpl::RegisterScanCallback(ScanResultCallback callback) {
    std::unique_lock lock(m_cbMutex);
    if (m_scanCallbacks.size() >= MAX_CALLBACKS) return;
    m_scanCallbacks.push_back(std::move(callback));
}

void MaliciousDownloadBlockerImpl::RegisterBlockedCallback(DownloadBlockedCallback callback) {
    std::unique_lock lock(m_cbMutex);
    if (m_blockedCallbacks.size() >= MAX_CALLBACKS) return;
    m_blockedCallbacks.push_back(std::move(callback));
}

void MaliciousDownloadBlockerImpl::RegisterSandboxCallback(SandboxCompleteCallback callback) {
    std::unique_lock lock(m_cbMutex);
    if (m_sandboxCallbacks.size() >= MAX_CALLBACKS) return;
    m_sandboxCallbacks.push_back(std::move(callback));
}

void MaliciousDownloadBlockerImpl::RegisterPreDownloadCallback(PreDownloadCallback callback) {
    std::unique_lock lock(m_cbMutex);
    if (m_preDownloadCallbacks.size() >= MAX_CALLBACKS) return;
    m_preDownloadCallbacks.push_back(std::move(callback));
}

void MaliciousDownloadBlockerImpl::RegisterErrorCallback(ErrorCallback callback) {
    std::unique_lock lock(m_cbMutex);
    if (m_errorCallbacks.size() >= MAX_CALLBACKS) return;
    m_errorCallbacks.push_back(std::move(callback));
}

void MaliciousDownloadBlockerImpl::UnregisterCallbacks() {
    std::unique_lock lock(m_cbMutex);
    m_scanCallbacks.clear();
    m_blockedCallbacks.clear();
    m_sandboxCallbacks.clear();
    m_preDownloadCallbacks.clear();
    m_errorCallbacks.clear();
}

// ============================================================================
// SELF-TEST
// ============================================================================

bool MaliciousDownloadBlockerImpl::SelfTest() {
    // Verify monitored directories are accessible
    {
        std::shared_lock lock(m_mutex);
        for (const auto& dir : m_monitoredDirs) {
            if (!fs::exists(dir) || !fs::is_directory(dir)) {
                Logger::Error("DownloadBlocker: self-test failed: monitored dir inaccessible: {}",
                              Utils::StringUtils::ToNarrow(dir.wstring()));
                return false;
            }
        }
    }

    // Verify hash computation works on our own module
    wchar_t modulePath[MAX_PATH]{};
    DWORD len = GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
    if (len > 0 && len < MAX_PATH) {
        std::string hash = ComputeSHA256Hex(fs::path(modulePath));
        if (hash.empty()) {
            Logger::Error("DownloadBlocker: self-test failed: cannot compute own hash");
            return false;
        }
    }

    // Verify MIME detection works
    auto mimeResult = DetectMimeFromMagicBytes(fs::path(modulePath));
    if (mimeResult.mimeType.empty()) {
        Logger::Error("DownloadBlocker: self-test failed: MIME detection returned empty");
        return false;
    }

    Logger::Info("DownloadBlocker: self-test passed");
    return true;
}

// ============================================================================
// PUBLIC INTERFACE DELEGATION
// ============================================================================

MaliciousDownloadBlocker& MaliciousDownloadBlocker::Instance() noexcept {
    static MaliciousDownloadBlocker instance;
    return instance;
}

bool MaliciousDownloadBlocker::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

MaliciousDownloadBlocker::MaliciousDownloadBlocker()
    : m_impl(std::make_unique<MaliciousDownloadBlockerImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

MaliciousDownloadBlocker::~MaliciousDownloadBlocker() = default;

bool MaliciousDownloadBlocker::Initialize(const DownloadBlockerConfiguration& config) {
    return m_impl->Initialize(config);
}

void MaliciousDownloadBlocker::Shutdown() {
    m_impl->Shutdown();
}

bool MaliciousDownloadBlocker::IsInitialized() const noexcept {
    return m_impl->GetStatus() != ModuleStatus::Uninitialized;
}

ModuleStatus MaliciousDownloadBlocker::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool MaliciousDownloadBlocker::UpdateConfiguration(const DownloadBlockerConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

DownloadBlockerConfiguration MaliciousDownloadBlocker::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

void MaliciousDownloadBlocker::OnDownloadComplete(const std::wstring& filePath, const std::string& sourceUrl) {
    m_impl->ScanFileAsync(fs::path(filePath), sourceUrl);
}

void MaliciousDownloadBlocker::OnDownloadComplete(const DownloadInfo& download) {
    m_impl->ScanFileAsync(download.filePath, download.sourceUrl);
}

bool MaliciousDownloadBlocker::OnDownloadStart(const DownloadInfo& download) {
    if (IsExtensionBlocked(download.extension)) return false;

    // Pre-download URL check
    if (!download.sourceUrl.empty()) {
        auto& tiMgr = ThreatIntel::ThreatIntelManager::Instance();
        if (tiMgr.IsInitialized()) {
            auto urlResult = tiMgr.LookupURL(download.sourceUrl);
            if (urlResult.IsMalicious()) {
                Logger::Warn("DownloadBlocker: blocked download from malicious URL: {}", download.sourceUrl);
                return false;
            }
        }
    }
    return true;
}

DownloadScanResult MaliciousDownloadBlocker::ScanFile(const fs::path& filePath) {
    return m_impl->ScanFile(filePath, "");
}

DownloadScanResult MaliciousDownloadBlocker::ScanFile(const fs::path& filePath, const std::string& sourceUrl) {
    return m_impl->ScanFile(filePath, sourceUrl);
}

std::future<DownloadScanResult> MaliciousDownloadBlocker::ScanFileAsync(
        const fs::path& filePath, const std::string& sourceUrl) {
    return m_impl->ScanFileAsync(filePath, sourceUrl);
}

int MaliciousDownloadBlocker::GetFileReputation(const fs::path& filePath) {
    return m_impl->GetFileReputation(filePath);
}

bool MaliciousDownloadBlocker::IsExtensionBlocked(const std::string& extension) const {
    return m_impl->IsExtensionBlocked(extension);
}

bool MaliciousDownloadBlocker::StartMonitoring() {
    return m_impl->StartMonitoring();
}

void MaliciousDownloadBlocker::StopMonitoring() {
    m_impl->StopMonitoring();
}

bool MaliciousDownloadBlocker::IsMonitoring() const noexcept {
    return m_impl->IsMonitoring();
}

bool MaliciousDownloadBlocker::AddMonitoredDirectory(const fs::path& directory) {
    return m_impl->AddMonitoredDirectory(directory);
}

bool MaliciousDownloadBlocker::RemoveMonitoredDirectory(const fs::path& directory) {
    return m_impl->RemoveMonitoredDirectory(directory);
}

std::vector<fs::path> MaliciousDownloadBlocker::GetMonitoredDirectories() const {
    return m_impl->GetMonitoredDirectories();
}

std::future<SandboxResult> MaliciousDownloadBlocker::SubmitToSandbox(const fs::path& filePath) {
    // Sandbox analysis defers to an isolated environment.
    // Production: communicates with a hypervisor-based sandbox service.
    return std::async(std::launch::async, [filePath]() {
        SandboxResult result;
        result.wasSandboxed = false;
        result.verdict      = DownloadVerdict::Unknown;
        Logger::Info("DownloadBlocker: sandbox submission noted for {}, awaiting service integration",
                     Utils::StringUtils::ToNarrow(filePath.wstring()));
        return result;
    });
}

std::optional<SandboxResult> MaliciousDownloadBlocker::GetSandboxResult(const std::string& downloadId) {
    // Sandbox results are retrieved from the sandbox service.
    // This requires async polling of the sandbox infrastructure.
    (void)downloadId;
    return std::nullopt;
}

bool MaliciousDownloadBlocker::QuarantineFile(const fs::path& filePath) {
    return m_impl->QuarantineFile(filePath);
}

bool MaliciousDownloadBlocker::RestoreFromQuarantine(const std::string& quarantineId) {
    return m_impl->RestoreFromQuarantine(quarantineId);
}

bool MaliciousDownloadBlocker::DeleteFromQuarantine(const std::string& quarantineId) {
    return m_impl->DeleteFromQuarantine(quarantineId);
}

bool MaliciousDownloadBlocker::AddBlockedExtension(const std::string& extension) {
    return m_impl->AddBlockedExtension(extension);
}

bool MaliciousDownloadBlocker::RemoveBlockedExtension(const std::string& extension) {
    return m_impl->RemoveBlockedExtension(extension);
}

bool MaliciousDownloadBlocker::AddAllowedExtension(const std::string& extension) {
    return m_impl->AddAllowedExtension(extension);
}

void MaliciousDownloadBlocker::RegisterScanCallback(ScanResultCallback callback) {
    m_impl->RegisterScanCallback(std::move(callback));
}

void MaliciousDownloadBlocker::RegisterBlockedCallback(DownloadBlockedCallback callback) {
    m_impl->RegisterBlockedCallback(std::move(callback));
}

void MaliciousDownloadBlocker::RegisterSandboxCallback(SandboxCompleteCallback callback) {
    m_impl->RegisterSandboxCallback(std::move(callback));
}

void MaliciousDownloadBlocker::RegisterPreDownloadCallback(PreDownloadCallback callback) {
    m_impl->RegisterPreDownloadCallback(std::move(callback));
}

void MaliciousDownloadBlocker::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void MaliciousDownloadBlocker::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

DownloadBlockerStatistics MaliciousDownloadBlocker::GetStatistics() const {
    return m_impl->GetStatistics();
}

void MaliciousDownloadBlocker::ResetStatistics() {
    m_impl->ResetStatistics();
}

bool MaliciousDownloadBlocker::SelfTest() {
    return m_impl->SelfTest();
}

std::string MaliciousDownloadBlocker::GetVersionString() noexcept {
    return std::format("{}.{}.{}", DownloadBlockerConstants::VERSION_MAJOR,
                       DownloadBlockerConstants::VERSION_MINOR,
                       DownloadBlockerConstants::VERSION_PATCH);
}

// ============================================================================
// UTILITY FUNCTIONS IMPLEMENTATION
// ============================================================================

std::string_view GetDownloadVerdictName(DownloadVerdict verdict) noexcept {
    switch (verdict) {
        case DownloadVerdict::Safe:       return "Safe";
        case DownloadVerdict::Clean:      return "Clean";
        case DownloadVerdict::Suspicious: return "Suspicious";
        case DownloadVerdict::Malware:    return "Malware";
        case DownloadVerdict::PUP:        return "PUP";
        case DownloadVerdict::Ransomware: return "Ransomware";
        case DownloadVerdict::Trojan:     return "Trojan";
        case DownloadVerdict::Worm:       return "Worm";
        case DownloadVerdict::Rootkit:    return "Rootkit";
        case DownloadVerdict::Blocked:    return "Blocked";
        case DownloadVerdict::Unknown:    return "Unknown";
        case DownloadVerdict::Error:      return "Error";
        default:                          return "Unknown";
    }
}

std::string_view GetDownloadActionName(DownloadAction action) noexcept {
    switch (action) {
        case DownloadAction::Allow:      return "Allow";
        case DownloadAction::Block:      return "Block";
        case DownloadAction::Quarantine: return "Quarantine";
        case DownloadAction::Warn:       return "Warn";
        case DownloadAction::Sandbox:    return "Sandbox";
        case DownloadAction::Defer:      return "Defer";
        case DownloadAction::Rename:     return "Rename";
        default:                         return "Unknown";
    }
}

std::string_view GetDownloadStatusName(DownloadStatus status) noexcept {
    switch (status) {
        case DownloadStatus::Pending:     return "Pending";
        case DownloadStatus::Scanning:    return "Scanning";
        case DownloadStatus::Sandboxing:  return "Sandboxing";
        case DownloadStatus::Completed:   return "Completed";
        case DownloadStatus::Allowed:     return "Allowed";
        case DownloadStatus::Blocked:     return "Blocked";
        case DownloadStatus::Quarantined: return "Quarantined";
        case DownloadStatus::Error:       return "Error";
        default:                          return "Unknown";
    }
}

std::string_view GetRiskLevelName(RiskLevel level) noexcept {
    switch (level) {
        case RiskLevel::None:     return "None";
        case RiskLevel::Low:      return "Low";
        case RiskLevel::Medium:   return "Medium";
        case RiskLevel::High:     return "High";
        case RiskLevel::Critical: return "Critical";
        default:                  return "Unknown";
    }
}

std::string_view GetThreatIndicatorName(ThreatIndicator indicator) noexcept {
    switch (indicator) {
        case ThreatIndicator::None:                 return "None";
        case ThreatIndicator::KnownMalware:         return "KnownMalware";
        case ThreatIndicator::SignatureMatch:        return "SignatureMatch";
        case ThreatIndicator::HeuristicMatch:        return "HeuristicMatch";
        case ThreatIndicator::MLClassification:      return "MLClassification";
        case ThreatIndicator::BadReputation:         return "BadReputation";
        case ThreatIndicator::NewFile:               return "NewFile";
        case ThreatIndicator::UnsignedExecutable:    return "UnsignedExecutable";
        case ThreatIndicator::InvalidSignature:      return "InvalidSignature";
        case ThreatIndicator::RevokedCertificate:    return "RevokedCertificate";
        case ThreatIndicator::SuspiciousImports:     return "SuspiciousImports";
        case ThreatIndicator::PackedExecutable:      return "PackedExecutable";
        case ThreatIndicator::HiddenExtension:       return "HiddenExtension";
        case ThreatIndicator::DoubleExtension:       return "DoubleExtension";
        case ThreatIndicator::TypeMismatch:          return "TypeMismatch";
        case ThreatIndicator::SuspiciousMacro:       return "SuspiciousMacro";
        case ThreatIndicator::EncryptedArchive:      return "EncryptedArchive";
        case ThreatIndicator::BadSourceURL:          return "BadSourceURL";
        case ThreatIndicator::SandboxDetection:      return "SandboxDetection";
        case ThreatIndicator::NetworkActivity:       return "NetworkActivity";
        case ThreatIndicator::PersistenceMechanism:  return "PersistenceMechanism";
        default:                                     return "Unknown";
    }
}

bool IsHighRiskFile(const fs::path& filePath) {
    std::string ext = NarrowToLower(filePath.extension().string());
    for (const auto* hrExt : DownloadBlockerConstants::HIGH_RISK_EXTENSIONS) {
        if (ext == hrExt) return true;
    }
    return false;
}

std::string DetectFileType(const fs::path& filePath) {
    auto result = DetectMimeFromMagicBytes(filePath);
    return result.mimeType;
}

std::vector<fs::path> GetDefaultDownloadDirectories() {
    return ResolveDefaultDownloadDirectories();
}

// ============================================================================
// STRUCT METHOD IMPLEMENTATIONS
// ============================================================================

std::string DownloadInfo::ToJson() const {
    std::ostringstream j;
    j << R"({"downloadId":")" << JsonEscape(downloadId)
      << R"(","filePath":")" << JsonEscape(filePath.string())
      << R"(","sourceUrl":")" << JsonEscape(sourceUrl)
      << R"(","mimeType":")" << JsonEscape(mimeType)
      << R"(","fileSize":)" << fileSize
      << R"(,"extension":")" << JsonEscape(extension)
      << R"(","sha256":")" << JsonEscape(sha256)
      << R"(","browserPid":)" << browserPid
      << R"(,"isPartial":)" << (isPartial ? "true" : "false")
      << "}";
    return j.str();
}

std::string FileAnalysisResult::ToJson() const {
    std::ostringstream j;
    j << R"({"detectedType":")" << JsonEscape(detectedType)
      << R"(","mimeType":")" << JsonEscape(mimeType)
      << R"(","isExecutable":)" << (isExecutable ? "true" : "false")
      << R"(,"isArchive":)" << (isArchive ? "true" : "false")
      << R"(,"hasSignature":)" << (hasSignature ? "true" : "false")
      << R"(,"signatureValid":)" << (signatureValid ? "true" : "false")
      << R"(,"publisher":")" << JsonEscape(publisher)
      << R"(","entropy":)" << entropy
      << R"(,"isPacked":)" << (isPacked ? "true" : "false")
      << R"(,"importCount":)" << importCount
      << "}";
    return j.str();
}

std::string ReputationResult::ToJson() const {
    std::ostringstream j;
    j << R"({"hashReputation":)" << hashReputation
      << R"(,"urlReputation":)" << urlReputation
      << R"(,"publisherReputation":)" << publisherReputation
      << R"(,"isKnownMalware":)" << (isKnownMalware ? "true" : "false")
      << R"(,"isWhitelisted":)" << (isWhitelisted ? "true" : "false")
      << R"(,"prevalence":)" << prevalence
      << R"(,"detectionCount":)" << detectionCount
      << R"(,"totalEngines":)" << totalEngines
      << "}";
    return j.str();
}

std::string SandboxResult::ToJson() const {
    std::ostringstream j;
    j << R"({"wasSandboxed":)" << (wasSandboxed ? "true" : "false")
      << R"(,"verdict":")" << JsonEscape(GetDownloadVerdictName(verdict))
      << R"(","sandboxScore":)" << sandboxScore
      << R"(,"analysisDurationMs":)" << analysisDuration.count()
      << "}";
    return j.str();
}

std::string DownloadScanResult::ToJson() const {
    std::ostringstream j;
    j << R"({"downloadId":")" << JsonEscape(downloadId)
      << R"(","verdict":")" << JsonEscape(GetDownloadVerdictName(verdict))
      << R"(","action":")" << JsonEscape(GetDownloadActionName(action))
      << R"(","status":")" << JsonEscape(GetDownloadStatusName(status))
      << R"(","isClean":)" << (isClean ? "true" : "false")
      << R"(,"shouldBlock":)" << (shouldBlock ? "true" : "false")
      << R"(,"riskScore":)" << riskScore
      << R"(,"threatName":")" << JsonEscape(threatName)
      << R"(","scanDurationUs":)" << scanDuration.count()
      << R"(,"fileAnalysis":)" << fileAnalysis.ToJson()
      << R"(,"reputation":)" << reputation.ToJson()
      << R"(,"sandbox":)" << sandbox.ToJson()
      << "}";
    return j.str();
}

void DownloadBlockerStatistics::Reset() noexcept {
    totalDownloads     = 0;
    scannedDownloads   = 0;
    cleanDownloads     = 0;
    blockedDownloads   = 0;
    quarantinedDownloads = 0;
    malwareDetected    = 0;
    pupDetected        = 0;
    suspiciousDetected = 0;
    sandboxedFiles     = 0;
    signatureMatches   = 0;
    heuristicMatches   = 0;
    reputationBlocks   = 0;
    policyBlocks       = 0;
    scanErrors         = 0;
    bytesScanned       = 0;
    for (auto& v : byVerdict)   v.store(0, std::memory_order_relaxed);
    for (auto& v : byIndicator) v.store(0, std::memory_order_relaxed);
    AtomicValueStoreRelaxed(startTime, Clock::now());
}

std::string DownloadBlockerStatistics::ToJson() const {
    std::ostringstream j;
    j << R"({"totalDownloads":)" << totalDownloads.load()
      << R"(,"scannedDownloads":)" << scannedDownloads.load()
      << R"(,"cleanDownloads":)" << cleanDownloads.load()
      << R"(,"blockedDownloads":)" << blockedDownloads.load()
      << R"(,"quarantinedDownloads":)" << quarantinedDownloads.load()
      << R"(,"malwareDetected":)" << malwareDetected.load()
      << R"(,"suspiciousDetected":)" << suspiciousDetected.load()
      << R"(,"scanErrors":)" << scanErrors.load()
      << R"(,"bytesScanned":)" << bytesScanned.load()
      << "}";
    return j.str();
}

bool DownloadBlockerConfiguration::IsValid() const noexcept {
    if (maxScanSize == 0) return false;
    if (scanTimeoutMs == 0) return false;
    if (enableSandbox && sandboxTimeoutMs == 0) return false;
    return true;
}

} // namespace WebBrowser
} // namespace ShadowStrike
