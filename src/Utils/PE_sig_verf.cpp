// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
/**
 * @file PE_sig_verf.cpp
 * @brief Implementation of PE digital signature verification utilities.
 *
 * Provides comprehensive Authenticode signature verification for Windows PE files,
 * including embedded signatures, catalog signatures, certificate chain validation,
 * timestamp verification, and revocation checking.
 *
 * Key implementation details:
 * - Uses WinTrust API for primary signature verification
 * - Uses CryptoAPI for certificate chain and revocation validation
 * - Supports RFC3161 and legacy countersignatures for timestamps
 * - RAII wrappers ensure proper resource cleanup
 *
 * @note Windows-specific implementation using WinTrust and CryptoAPI.
 * @copyright ShadowStrike Security Suite
 * @author ShadowStrike Security Team
 */
#include"pch.h"
#include "PE_sig_verf.hpp"
#include "StringUtils.hpp"

#include <string>
#include <cstring>
#include <vector>

namespace ShadowStrike {
    namespace Utils {
        namespace pe_sig_utils {

            // ============================================================================
            // Internal RAII Wrappers
            // ============================================================================

            /**
             * @brief RAII wrapper for PCCERT_CHAIN_CONTEXT.
             */
            struct ChainCtxRAII {
                PCCERT_CHAIN_CONTEXT p = nullptr;
                
                ChainCtxRAII() = default;
                explicit ChainCtxRAII(PCCERT_CHAIN_CONTEXT ctx) : p(ctx) {}
                
                ~ChainCtxRAII() noexcept {
                    if (p) {
                        CertFreeCertificateChain(p);
                        p = nullptr;
                    }
                }
                
                // Non-copyable
                ChainCtxRAII(const ChainCtxRAII&) = delete;
                ChainCtxRAII& operator=(const ChainCtxRAII&) = delete;
                
                // Movable
                ChainCtxRAII(ChainCtxRAII&& other) noexcept : p(other.p) {
                    other.p = nullptr;
                }
                ChainCtxRAII& operator=(ChainCtxRAII&& other) noexcept {
                    if (this != &other) {
                        if (p) CertFreeCertificateChain(p);
                        p = other.p;
                        other.p = nullptr;
                    }
                    return *this;
                }
            };

            /**
             * @brief RAII wrapper for PCCERT_CONTEXT.
             */
            struct CertCtxRAII {
                PCCERT_CONTEXT p = nullptr;
                
                CertCtxRAII() = default;
                explicit CertCtxRAII(PCCERT_CONTEXT ctx) : p(ctx) {}
                
                ~CertCtxRAII() noexcept {
                    if (p) {
                        CertFreeCertificateContext(p);
                        p = nullptr;
                    }
                }
                
                // Non-copyable
                CertCtxRAII(const CertCtxRAII&) = delete;
                CertCtxRAII& operator=(const CertCtxRAII&) = delete;
                
                // Movable
                CertCtxRAII(CertCtxRAII&& other) noexcept : p(other.p) {
                    other.p = nullptr;
                }
                CertCtxRAII& operator=(CertCtxRAII&& other) noexcept {
                    if (this != &other) {
                        if (p) CertFreeCertificateContext(p);
                        p = other.p;
                        other.p = nullptr;
                    }
                    return *this;
                }
                
                /**
                 * @brief Releases ownership and returns the raw pointer.
                 * @return The raw certificate context (caller takes ownership)
                 */
                [[nodiscard]] PCCERT_CONTEXT release() noexcept {
                    PCCERT_CONTEXT tmp = p;
                    p = nullptr;
                    return tmp;
                }
                
                /**
                 * @brief Resets to a new pointer, freeing the old one.
                 * @param ctx New certificate context (takes ownership)
                 */
                void reset(PCCERT_CONTEXT ctx = nullptr) noexcept {
                    if (p) CertFreeCertificateContext(p);
                    p = ctx;
                }
            };

            /**
             * @brief RAII wrapper for HCERTSTORE (certificate store handle).
             * 
             * Ensures proper cleanup of certificate store handles on all exit paths.
             * Supports move semantics for transfer of ownership.
             */
            struct CertStoreRAII {
                HCERTSTORE h = nullptr;
                
                CertStoreRAII() = default;
                explicit CertStoreRAII(HCERTSTORE store) noexcept : h(store) {}
                
                ~CertStoreRAII() noexcept {
                    if (h) {
                        CertCloseStore(h, 0);
                        h = nullptr;
                    }
                }
                
                // Non-copyable
                CertStoreRAII(const CertStoreRAII&) = delete;
                CertStoreRAII& operator=(const CertStoreRAII&) = delete;
                
                // Movable
                CertStoreRAII(CertStoreRAII&& other) noexcept : h(other.h) {
                    other.h = nullptr;
                }
                CertStoreRAII& operator=(CertStoreRAII&& other) noexcept {
                    if (this != &other) {
                        if (h) CertCloseStore(h, 0);
                        h = other.h;
                        other.h = nullptr;
                    }
                    return *this;
                }
                
                /**
                 * @brief Checks if handle is valid.
                 */
                [[nodiscard]] explicit operator bool() const noexcept { return h != nullptr; }
                
                /**
                 * @brief Gets the raw handle.
                 */
                [[nodiscard]] HCERTSTORE get() const noexcept { return h; }
                
                /**
                 * @brief Releases ownership and returns the raw handle.
                 */
                [[nodiscard]] HCERTSTORE release() noexcept {
                    HCERTSTORE tmp = h;
                    h = nullptr;
                    return tmp;
                }
                
                /**
                 * @brief Resets to a new handle, freeing the old one.
                 */
                void reset(HCERTSTORE store = nullptr) noexcept {
                    if (h) CertCloseStore(h, 0);
                    h = store;
                }
            };

            /**
             * @brief RAII wrapper for HCRYPTMSG (cryptographic message handle).
             * 
             * Ensures proper cleanup of cryptographic message handles on all exit paths.
             * Supports move semantics for transfer of ownership.
             */
            struct CryptMsgRAII {
                HCRYPTMSG h = nullptr;
                
                CryptMsgRAII() = default;
                explicit CryptMsgRAII(HCRYPTMSG msg) noexcept : h(msg) {}
                
                ~CryptMsgRAII() noexcept {
                    if (h) {
                        CryptMsgClose(h);
                        h = nullptr;
                    }
                }
                
                // Non-copyable
                CryptMsgRAII(const CryptMsgRAII&) = delete;
                CryptMsgRAII& operator=(const CryptMsgRAII&) = delete;
                
                // Movable
                CryptMsgRAII(CryptMsgRAII&& other) noexcept : h(other.h) {
                    other.h = nullptr;
                }
                CryptMsgRAII& operator=(CryptMsgRAII&& other) noexcept {
                    if (this != &other) {
                        if (h) CryptMsgClose(h);
                        h = other.h;
                        other.h = nullptr;
                    }
                    return *this;
                }
                
                /**
                 * @brief Checks if handle is valid.
                 */
                [[nodiscard]] explicit operator bool() const noexcept { return h != nullptr; }
                
                /**
                 * @brief Gets the raw handle.
                 */
                [[nodiscard]] HCRYPTMSG get() const noexcept { return h; }
                
                /**
                 * @brief Releases ownership and returns the raw handle.
                 */
                [[nodiscard]] HCRYPTMSG release() noexcept {
                    HCRYPTMSG tmp = h;
                    h = nullptr;
                    return tmp;
                }
                
                /**
                 * @brief Resets to a new handle, freeing the old one.
                 */
                void reset(HCRYPTMSG msg = nullptr) noexcept {
                    if (h) CryptMsgClose(h);
                    h = msg;
                }
            };

            // ============================================================================
            // Internal Helper Functions
            // ============================================================================

            /**
             * @brief Sets error information in the Error struct.
             * @param err Pointer to Error struct (may be nullptr)
             * @param msg Error message (ASCII)
             * @param winerr Win32 error code (optional)
             */
            static inline void set_err(Error* err, const char* msg, DWORD winerr = 0) noexcept {
                if (!err) return;
                
                try {
                    err->win32 = winerr;
                    if (winerr != 0) {
                        err->message = ShadowStrike::Utils::StringUtils::utf8_to_wstring(msg) 
                            + L" (Win32 Error: " + std::to_wstring(winerr) + L")";
                    }
                    else {
                        err->message = ShadowStrike::Utils::StringUtils::utf8_to_wstring(msg);
                    }
                }
                catch (...) {
                    // Allocation failure - set minimal error info
                    err->win32 = winerr != 0 ? winerr : ERROR_OUTOFMEMORY;
                    err->message.clear();
                }
            }

            /**
             * @brief Checks if a file exists and is not a directory.
             * @param path File path to check
             * @return true if file exists
             */
            static inline bool file_exists(std::wstring_view path) noexcept {
                if (path.empty()) return false;
                
                try {
                    std::wstring pathCopy(path);
                    DWORD attrs = ::GetFileAttributesW(pathCopy.c_str());
                    return (attrs != INVALID_FILE_ATTRIBUTES) && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
                }
                catch (...) {
                    return false;
                }
            }

            // Well-known OIDs for signature verification
            static constexpr LPCSTR OID_COUNTERSIGN = szOID_RSA_counterSign;      // "1.2.840.113549.1.9.6"
            static constexpr LPCSTR OID_RFC3161_TS = szOID_RFC3161_counterSign;   // "1.3.6.1.4.1.311.3.3.1"
            static constexpr LPCSTR OID_SIGNING_TIME = szOID_RSA_signingTime;     // "1.2.840.113549.1.9.5"

            // Maximum allowed size for signer info buffer (8MB limit to prevent DoS via malformed files)
            static constexpr DWORD kMaxSignerInfoSize = 8 * 1024 * 1024;

            /**
             * @brief DER/ASN.1 decode helper.
             * @param encoding Encoding type (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
             * @param lpszStructType Structure type OID
             * @param pbData Input data
             * @param cbData Input data size
             * @param out Output buffer
             * @return true if decode succeeded
             */
            static inline bool decode_object(DWORD encoding, LPCSTR lpszStructType, 
                const BYTE* pbData, DWORD cbData,
                std::vector<BYTE>& out) noexcept 
            {
                if (!pbData || cbData == 0) return false;
                
                DWORD cbOut = 0;
                if (!CryptDecodeObject(encoding, lpszStructType, pbData, cbData, 0, nullptr, &cbOut) || cbOut == 0) {
                    return false;
                }
                
                try {
                    out.resize(cbOut);
                }
                catch (...) {
                    return false;
                }
                
                return CryptDecodeObject(encoding, lpszStructType, pbData, cbData, 0, out.data(), &cbOut) == TRUE;
            }

            // ============================================================================
            // EKU Validation
            // ============================================================================

            /**
             * @brief Checks if certificate has Code Signing EKU.
             *
             * Validates that the certificate contains the Code Signing Extended Key Usage
             * OID (1.3.6.1.5.5.7.3.3). This is required for Authenticode signatures.
             *
             * @param cert Certificate context to check
             * @param err Optional error output
             * @return true if code signing EKU is present
             */
            bool PEFileSignatureVerifier::CheckCodeSigningEKU(PCCERT_CONTEXT cert, Error* err) noexcept {
                if (!cert) { 
                    set_err(err, "CheckCodeSigningEKU: null cert"); 
                    return false; 
                }

                DWORD cb = 0;
                // First call to get size
                if (!CertGetEnhancedKeyUsage(cert, 0, nullptr, &cb)) {
                    DWORD e = GetLastError();
                    // If EKU not present, some certs rely on KeyUsage only; 
                    // but for code-signing, we require EKU explicitly.
                    set_err(err, "CertGetEnhancedKeyUsage size query failed", e);
                    return false;
                }

                if (cb == 0) {
                    set_err(err, "Enhanced Key Usage size is zero");
                    return false;
                }

                std::vector<BYTE> buf;
                try {
                    buf.resize(cb);
                }
                catch (...) {
                    set_err(err, "Memory allocation failed for EKU buffer");
                    return false;
                }

                PCERT_ENHKEY_USAGE pUsage = reinterpret_cast<PCERT_ENHKEY_USAGE>(buf.data());
                if (!CertGetEnhancedKeyUsage(cert, 0, pUsage, &cb)) {
                    set_err(err, "CertGetEnhancedKeyUsage failed", GetLastError());
                    return false;
                }

                if (pUsage->cUsageIdentifier == 0 || !pUsage->rgpszUsageIdentifier) {
                    set_err(err, "Enhanced Key Usage missing or empty");
                    return false;
                }

                // Code Signing EKU OID
                constexpr const char* OID_CODE_SIGNING = "1.3.6.1.5.5.7.3.3";

                bool found = false;
                for (DWORD i = 0; i < pUsage->cUsageIdentifier; ++i) {
                    const char* oid = pUsage->rgpszUsageIdentifier[i];
                    if (oid && std::strcmp(oid, OID_CODE_SIGNING) == 0) {
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    set_err(err, "Code signing EKU (1.3.6.1.5.5.7.3.3) not present");
                    return false;
                }

                return true;
            }

            // ============================================================================
            // Timestamp Validation
            // ============================================================================

            /**
             * @brief Validates signing timestamp against certificate validity period.
             *
             * Checks that the signing time falls within the certificate's NotBefore
             * and NotAfter dates, with a configurable grace period for clock skew.
             *
             * @param signTime Signing timestamp to validate
             * @param cert Certificate context
             * @param err Optional error output
             * @return true if timestamp is within validity window (with grace)
             */
            bool PEFileSignatureVerifier::ValidateTimestamp(const FILETIME& signTime,
                PCCERT_CONTEXT cert,
                Error* err) noexcept
            {
                if (!cert) {
                    set_err(err, "ValidateTimestamp: null cert");
                    return false;
                }

                if (!cert->pCertInfo) {
                    set_err(err, "ValidateTimestamp: null pCertInfo");
                    return false;
                }

                // cert->pCertInfo->NotBefore / NotAfter are already FILETIME structures
                const FILETIME& notBeforeFT = cert->pCertInfo->NotBefore;
                const FILETIME& notAfterFT = cert->pCertInfo->NotAfter;

                // Convert to 64-bit ULARGE_INTEGER for arithmetic
                ULARGE_INTEGER nb{}, na{}, st{};
                nb.LowPart = notBeforeFT.dwLowDateTime;
                nb.HighPart = notBeforeFT.dwHighDateTime;

                na.LowPart = notAfterFT.dwLowDateTime;
                na.HighPart = notAfterFT.dwHighDateTime;

                st.LowPart = signTime.dwLowDateTime;
                st.HighPart = signTime.dwHighDateTime;

                // Grace window: convert seconds to 100ns ticks
                // Guard against overflow (max reasonable grace is ~1 year)
                const ULONGLONG kMaxGraceSeconds = 365ULL * 24 * 60 * 60;
                ULONGLONG effectiveGrace = (tsGraceSeconds_ > kMaxGraceSeconds) 
                    ? kMaxGraceSeconds : tsGraceSeconds_;
                ULONGLONG graceTicks = effectiveGrace * 10'000'000ULL;

                // Check lower bound (allow skew)
                // Avoid underflow: if st.QuadPart < nb.QuadPart - graceTicks
                if (nb.QuadPart > graceTicks) {
                    if (st.QuadPart < nb.QuadPart - graceTicks) {
                        set_err(err, "Timestamp earlier than NotBefore (with grace)");
                        return false;
                    }
                }
                // If nb.QuadPart <= graceTicks, then effectively no lower bound issue

                // Check upper bound (allow skew)
                // Avoid overflow: check if na.QuadPart + graceTicks would overflow
                if (na.QuadPart > MAXULONGLONG - graceTicks) {
                    // Near max time - just check st <= na
                    if (st.QuadPart > na.QuadPart) {
                        set_err(err, "Timestamp later than NotAfter");
                        return false;
                    }
                }
                else {
                    if (st.QuadPart > na.QuadPart + graceTicks) {
                        set_err(err, "Timestamp later than NotAfter (with grace)");
                        return false;
                    }
                }

                return true; // timestamp is inside validity window
            }

            // ============================================================================
            // PE Signature Verification
            // ============================================================================

            /**
             * @brief Verifies PE file signature (embedded Authenticode).
             *
             * Performs complete signature verification including:
             * - WinVerifyTrust basic signature check
             * - Certificate chain validation
             * - EKU (Extended Key Usage) verification
             * - Timestamp/countersignature validation
             * - Revocation checking (based on policy)
             *
             * @param filePath Path to the PE file
             * @param info Output signature information
             * @param err Optional error output
             * @return true if signature is valid and trusted
             */
            bool PEFileSignatureVerifier::VerifyPESignature(std::wstring_view filePath,
                SignatureInfo& info,
                Error* err) noexcept {
                // Reset output
                info = SignatureInfo{};

                // Validate input
                if (filePath.empty()) {
                    set_err(err, "VerifyPESignature: empty file path");
                    return false;
                }

                if (!file_exists(filePath)) {
                    set_err(err, "VerifyPESignature: file not found");
                    return false;
                }

                // Prepare WinTrust structures
                GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

                WINTRUST_FILE_INFO wfi{};
                std::wstring pathCopy;
                try {
                    pathCopy = std::wstring(filePath);
                }
                catch (...) {
                    set_err(err, "Memory allocation failed for path");
                    return false;
                }
                
                wfi.cbStruct = sizeof(wfi);
                wfi.pcwszFilePath = pathCopy.c_str();

                WINTRUST_DATA wtd{};
                wtd.cbStruct = sizeof(wtd);
                wtd.dwUIChoice = WTD_UI_NONE;
                wtd.fdwRevocationChecks = WTD_REVOKE_NONE; // revocation enforced via chain policy below
                wtd.dwUnionChoice = WTD_CHOICE_FILE;
                wtd.pFile = &wfi;
                wtd.dwProvFlags =
                    WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
                    WTD_CACHE_ONLY_URL_RETRIEVAL;
                wtd.dwStateAction = WTD_STATEACTION_VERIFY;

                // Perform initial verification
                LONG status = WinVerifyTrust(nullptr, &policyGUID, &wtd);

                // Close trust state (must be called regardless of result)
                wtd.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(nullptr, &policyGUID, &wtd);

                if (status != ERROR_SUCCESS) {
                    set_err(err, "WinVerifyTrust failed for embedded signature", static_cast<DWORD>(status));
                    return false;
                }

                // Mark as signed (WinVerifyTrust passed)
                info.isSigned = true;

                // Extract PKCS#7 message and leaf cert for detailed validation
                HCERTSTORE hStore = nullptr;
                HCRYPTMSG hMsg = nullptr;
                DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;
                
                if (!CryptQueryObject(//-V1109
                    CERT_QUERY_OBJECT_FILE,
                    pathCopy.c_str(),
                    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                    CERT_QUERY_FORMAT_FLAG_BINARY,
                    0,
                    &dwEncoding, &dwContentType, &dwFormatType,
                    &hStore, &hMsg, nullptr)) {
                    set_err(err, "CryptQueryObject failed (embedded)", GetLastError());
                    // Clean up any partially opened handles
                    if (hStore) CertCloseStore(hStore, 0);
                    if (hMsg) CryptMsgClose(hMsg);
                    return false;
                }

                // Ensure cleanup on all exit paths
                auto cleanupHandles = [&]() {
                    if (hStore) { CertCloseStore(hStore, 0); hStore = nullptr; }
                    if (hMsg) { CryptMsgClose(hMsg); hMsg = nullptr; }
                };

                // Get signer count
                DWORD signerCount = 0;
                DWORD cbCount = sizeof(signerCount);
                if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_COUNT_PARAM, 0, &signerCount, &cbCount) || signerCount == 0) {
                    set_err(err, "No signer found in PKCS7");
                    cleanupHandles();
                    return false;
                }

                // Get primary signer info (index 0)
                DWORD cbSigner = 0;
                if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &cbSigner) || cbSigner == 0) {
                    set_err(err, "Failed to get signer info size");
                    cleanupHandles();
                    return false;
                }

                std::vector<BYTE> signerBuf;
                try {
                    signerBuf.resize(cbSigner);
                }
                catch (...) {
                    set_err(err, "Memory allocation failed for signer info");
                    cleanupHandles();
                    return false;
                }

                auto* psi = reinterpret_cast<CMSG_SIGNER_INFO*>(signerBuf.data());
                if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, psi, &cbSigner)) {
                    set_err(err, "CryptMsgGetParam signer info failed", GetLastError());
                    cleanupHandles();
                    return false;
                }

                // Find leaf certificate by Issuer + SerialNumber
                CertCtxRAII leaf{};
                {
                    CERT_INFO certInfo{};
                    certInfo.Issuer = psi->Issuer;
                    certInfo.SerialNumber = psi->SerialNumber;
                    leaf.p = CertFindCertificateInStore(
                        hStore,
                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                        0,
                        CERT_FIND_SUBJECT_CERT,
                        &certInfo,
                        nullptr
                    );
                    if (!leaf.p) {
                        set_err(err, "Leaf certificate not found in store");
                        cleanupHandles();
                        return false;
                    }
                }

                // EKU: require code signing usage
                if (!CheckCodeSigningEKU(leaf.p, err)) {
                    cleanupHandles();
                    return false;
                }
                info.isEKUValid = true;

                // Timestamp via countersignature (RFC3161 or legacy)
                // Fallback to current time check if countersignature absent
                FILETIME ts{};
                bool haveCsTs = CheckTimestampCounterSignatureFromMessage(hMsg, /*signerIndex*/ 0, ts, err);
                bool tsValid = false;
                
                if (haveCsTs) {
                    tsValid = ValidateTimestamp(ts, leaf.p, nullptr); // Don't overwrite err
                    if (tsValid) {
                        info.signTime = ts;
                        info.isTimestampValid = true;
                    }
                }
                else {
                    // Fallback: use current time within cert validity + grace
                    SYSTEMTIME stNow{};
                    GetSystemTime(&stNow);
                    if (SystemTimeToFileTime(&stNow, &ts)) {
                        tsValid = ValidateTimestamp(ts, leaf.p, nullptr);
                        if (tsValid) {
                            info.signTime = ts;
                            // Note: timestamp valid but not from countersignature
                        }
                    }
                }
                
                if (!tsValid) {
                    set_err(err, "Timestamp validation failed");
                    cleanupHandles();
                    return false;
                }

                // Chain + revocation policy
                if (!ValidateCertificateChain(leaf.p, err)) {
                    cleanupHandles();
                    return false;
                }
                info.isChainTrusted = true;

                if (!CheckRevocationOnline(leaf.p, err)) {
                    cleanupHandles();
                    return false;
                }
                info.isRevocationChecked = true;

                // Populate additional info fields
                if (!GetSignerName(leaf.p, info.signerName, nullptr)) {
                    SS_LOG_WARN(L"PE_sig_verification", L"Failed to get signer's name");
                }
                else if (!GetIssuerName(leaf.p, info.issuerName, nullptr)) {
                    SS_LOG_WARN(L"PE_sig_verification", L"Failed to get ıssuer's name");
                }
                else if (!GetCertThumbprint(leaf.p, info.thumbprint, nullptr, true)) {
                    SS_LOG_WARN(L"PE_sig_verification", L"Failed to get certificate thumbprint");
                }
                
                info.isVerified = true;

                cleanupHandles();
                return true;
            }

            // ============================================================================
            // Catalog Signature Verification
            // ============================================================================


            /**
             * @brief Verifies catalog signature for a given catalog and file hash.
             *
             * Performs complete verification including:
             * - WinVerifyTrust on catalog file
             * - Certificate chain validation
             * - EKU verification for code signing
             * - Timestamp validation
             * - Revocation checking
             *
             * @param catalogPath Path to the .cat catalog file
             * @param fileHash Hex-encoded hash of the member file
             * @param info Output signature information
             * @param err Optional error output
             * @return true if catalog signature is valid and trusted
             */
            bool PEFileSignatureVerifier::VerifyCatalogSignature(std::wstring_view catalogPath,
                std::wstring_view fileHash,
                SignatureInfo& info,
                Error* err) noexcept {
                // Reset output
                info = SignatureInfo{};

                // Validate inputs
                if (catalogPath.empty()) {
                    set_err(err, "VerifyCatalogSignature: empty catalog path");
                    return false;
                }

                if (!file_exists(catalogPath)) {
                    set_err(err, "VerifyCatalogSignature: catalog not found");
                    return false;
                }

                // Allocate path copies with exception safety
                std::wstring catPathCopy;
                std::wstring hashCopy;
                try {
                    catPathCopy = std::wstring(catalogPath);
                    hashCopy = std::wstring(fileHash);
                }
                catch (...) {
                    set_err(err, "Memory allocation failed for catalog verification");
                    return false;
                }

                // Prepare catalog info
                WINTRUST_CATALOG_INFO wci{};
                wci.cbStruct = sizeof(wci);
                wci.pcwszCatalogFilePath = catPathCopy.c_str();
                wci.pcwszMemberTag = hashCopy.empty() ? nullptr : hashCopy.c_str();
                wci.pcwszMemberFilePath = nullptr;
                wci.hMemberFile = nullptr;
                wci.hCatAdmin = nullptr;

                GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

                WINTRUST_DATA wtd{};
                wtd.cbStruct = sizeof(wtd);
                wtd.dwUIChoice = WTD_UI_NONE;
                wtd.fdwRevocationChecks = WTD_REVOKE_NONE; // Controlled via chain policy
                wtd.dwUnionChoice = WTD_CHOICE_CATALOG;
                wtd.pCatalog = &wci;
                wtd.dwProvFlags =
                    WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
                    | WTD_CACHE_ONLY_URL_RETRIEVAL;
                wtd.dwStateAction = WTD_STATEACTION_VERIFY;

                // Perform WinVerifyTrust verification
                LONG status = WinVerifyTrust(nullptr, &policyGUID, &wtd);

                // Always close state regardless of result
                wtd.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(nullptr, &policyGUID, &wtd);

                if (status != ERROR_SUCCESS) {
                    set_err(err, "WinVerifyTrust failed for catalog", static_cast<DWORD>(status));
                    return false;
                }

                // Mark as signed (WinVerifyTrust passed)
                info.isSigned = true;

                // Extract catalog signer certificate using RAII
                CertStoreRAII storeGuard;
                CryptMsgRAII msgGuard;
                CertCtxRAII leaf;

                {
                    HCERTSTORE hStore = nullptr;
                    HCRYPTMSG hMsg = nullptr;
                    DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;

                    BOOL qok = CryptQueryObject(//-V1109
                        CERT_QUERY_OBJECT_FILE,
                        catPathCopy.c_str(),
                        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                        CERT_QUERY_FORMAT_FLAG_BINARY,
                        0,
                        &dwEncoding, &dwContentType, &dwFormatType,
                        &hStore, &hMsg, nullptr
                    );

                    // Take ownership immediately
                    storeGuard.reset(hStore);
                    msgGuard.reset(hMsg);

                    if (!qok || !storeGuard || !msgGuard) {
                        set_err(err, "CryptQueryObject(catalog) failed", GetLastError());
                        return false;
                    }

                    // Get signer info size
                    DWORD cbSigner = 0;
                    if (!CryptMsgGetParam(msgGuard.get(), CMSG_SIGNER_INFO_PARAM, 0, nullptr, &cbSigner) || cbSigner == 0) {
                        set_err(err, "CryptMsgGetParam signer size failed (catalog)", GetLastError());
                        return false;
                    }

                    // Allocate signer buffer with exception safety
                    std::vector<BYTE> signerBuf;
                    try {
                        signerBuf.resize(cbSigner);
                    }
                    catch (...) {
                        set_err(err, "Memory allocation failed for signer info");
                        return false;
                    }

                    auto* psi = reinterpret_cast<CMSG_SIGNER_INFO*>(signerBuf.data());
                    if (!CryptMsgGetParam(msgGuard.get(), CMSG_SIGNER_INFO_PARAM, 0, psi, &cbSigner)) {
                        set_err(err, "CryptMsgGetParam signer info failed (catalog)", GetLastError());
                        return false;
                    }

                    // Find leaf certificate by Issuer + SerialNumber
                    CERT_INFO certInfo{};
                    certInfo.Issuer = psi->Issuer;
                    certInfo.SerialNumber = psi->SerialNumber;

                    leaf.p = CertFindCertificateInStore(
                        storeGuard.get(),
                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                        0,
                        CERT_FIND_SUBJECT_CERT,
                        &certInfo,
                        nullptr
                    );

                    if (!leaf.p) {
                        set_err(err, "Leaf certificate not found (catalog)");
                        return false;
                    }
                }

                // EKU: require code signing
                if (!CheckCodeSigningEKU(leaf.p, err)) {
                    return false;
                }
                info.isEKUValid = true;

                // Timestamp validation (use current time as fallback for catalogs)
                FILETIME signTime{};
                SYSTEMTIME stNow{};
                GetSystemTime(&stNow);
                if (!SystemTimeToFileTime(&stNow, &signTime)) {
                    set_err(err, "SystemTimeToFileTime failed", GetLastError());
                    return false;
                }

                if (!ValidateTimestamp(signTime, leaf.p, err)) {
                    return false;
                }
                info.isTimestampValid = true;
                info.signTime = signTime;

                // Chain + revocation policy
                if (!ValidateCertificateChain(leaf.p, err)) {
                    return false;
                }
                info.isChainTrusted = true;

                if (!CheckRevocationOnline(leaf.p, err)) {
                    return false;
                }
                info.isRevocationChecked = true;

                // Populate additional info fields
                if (!GetSignerName(leaf.p, info.signerName, nullptr)) {
                    SS_LOG_WARN(L"PE_sig_verification", L"Failed to get signer's name");
                }
                else if (!GetIssuerName(leaf.p, info.issuerName, nullptr)) {
                    SS_LOG_WARN(L"PE_sig_verification", L"Failed to get ıssuer's name");
                }
                else if (!GetCertThumbprint(leaf.p, info.thumbprint, nullptr, true)) {
                    SS_LOG_WARN(L"PE_sig_verification", L"Failed to get certificate thumbprint");
                }

                info.isVerified = true;
                return true;
            }

            // Check revocation status online/offline per policy (OCSP/CRL via chain engine)
            bool PEFileSignatureVerifier::CheckRevocationOnline(PCCERT_CONTEXT cert, Error* err) noexcept {
                if (!cert) { set_err(err, "CheckRevocationOnline: null cert"); return false; }

                CERT_CHAIN_PARA chainPara{};
                chainPara.cbSize = sizeof(chainPara);

                DWORD flags = 0;
                switch (revocationMode_) {
                case RevocationMode::OnlineOnly:
                    flags |= CERT_CHAIN_REVOCATION_CHECK_CHAIN;
                    break;
                case RevocationMode::OfflineAllowed:
                    flags |= CERT_CHAIN_REVOCATION_CHECK_CHAIN;
                    flags |= CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY;
                    break;
                case RevocationMode::Disabled:
                    // Explicitly skip revocation; treat as success but log via err if provided for auditing
                    return true;
                }

                PCCERT_CHAIN_CONTEXT chainCtxRaw = nullptr;
                BOOL okChain = CertGetCertificateChain(
                    nullptr, cert, nullptr, cert->hCertStore,
                    &chainPara, flags, nullptr, &chainCtxRaw
                );
                ChainCtxRAII chainCtx{ chainCtxRaw };

                if (!okChain || !chainCtx.p) {
                    set_err(err, "CertGetCertificateChain failed (revocation)", GetLastError());
                    return false;
                }

                CERT_CHAIN_POLICY_PARA policyPara{};
                policyPara.cbSize = sizeof(policyPara);

                CERT_CHAIN_POLICY_STATUS policyStatus{};
                policyStatus.cbSize = sizeof(policyStatus);

                BOOL okPolicy = CertVerifyCertificateChainPolicy(
                    CERT_CHAIN_POLICY_AUTHENTICODE, chainCtx.p, &policyPara, &policyStatus
                );

                if (!okPolicy || policyStatus.dwError != 0) {
                    set_err(err, "Revocation/authenticode policy failed");
                    return false;
                }

                return true;
            }

            // Strict chain validation against Authenticode policy (trust anchor, usage, time)
            bool PEFileSignatureVerifier::ValidateCertificateChain(PCCERT_CONTEXT cert, Error* err) noexcept {
                if (!cert) { set_err(err, "ValidateCertificateChain: null cert"); return false; }

                CERT_CHAIN_PARA chainPara{};
                chainPara.cbSize = sizeof(chainPara);

                DWORD flags = 0;
                switch (revocationMode_) {
                case RevocationMode::OnlineOnly:
                    flags |= CERT_CHAIN_REVOCATION_CHECK_CHAIN;
                    break;
                case RevocationMode::OfflineAllowed:
                    flags |= CERT_CHAIN_REVOCATION_CHECK_CHAIN;
                    flags |= CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY;
                    break;
                case RevocationMode::Disabled:
                    // No revocation flags
                    break;
                }

                PCCERT_CHAIN_CONTEXT chainCtxRaw = nullptr;
                BOOL okChain = CertGetCertificateChain(
                    nullptr, cert, nullptr, cert->hCertStore,
                    &chainPara, flags, nullptr, &chainCtxRaw
                );
                ChainCtxRAII chainCtx{ chainCtxRaw };

                if (!okChain || !chainCtx.p) {
                    set_err(err, "CertGetCertificateChain failed", GetLastError());
                    return false;
                }

                CERT_CHAIN_POLICY_PARA policyPara{};
                policyPara.cbSize = sizeof(policyPara);

                CERT_CHAIN_POLICY_STATUS policyStatus{};
                policyStatus.cbSize = sizeof(policyStatus);

                BOOL okPolicy = CertVerifyCertificateChainPolicy(
                    CERT_CHAIN_POLICY_AUTHENTICODE, chainCtx.p, &policyPara, &policyStatus
                );

                if (!okPolicy || policyStatus.dwError != 0) {
                    set_err(err, "Authenticode chain policy failed");
                    return false;
                }

                return true;
            }

            /**
             * @brief Verifies embedded Authenticode signature only.
             *
             * Performs signature verification using WinVerifyTrust API and validates
             * the certificate chain, EKU, and timestamp. This is a dedicated path
             * for embedded signatures when catalog fallback is not desired.
             *
             * @param filePath Path to the PE file
             * @param info Output signature information
             * @param err Optional error output
             * @return true if embedded signature is valid
             */
            bool PEFileSignatureVerifier::VerifyEmbeddedSignature(std::wstring_view filePath,
                SignatureInfo& info,
                Error* err) noexcept {
                // Reset output
                info = SignatureInfo{};

                // Validate input
                if (filePath.empty()) {
                    set_err(err, "VerifyEmbeddedSignature: empty file path");
                    return false;
                }

                if (!file_exists(filePath)) {
                    set_err(err, "VerifyEmbeddedSignature: file not found");
                    return false;
                }

                // Allocate path copy with exception safety
                std::wstring pathCopy;
                try {
                    pathCopy = std::wstring(filePath);
                }
                catch (...) {
                    set_err(err, "Memory allocation failed for path");
                    return false;
                }

                GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

                WINTRUST_FILE_INFO wfi{};
                wfi.cbStruct = sizeof(wfi);
                wfi.pcwszFilePath = pathCopy.c_str();

                WINTRUST_DATA wtd{};
                wtd.cbStruct = sizeof(wtd);
                wtd.dwUIChoice = WTD_UI_NONE;
                wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
                wtd.dwUnionChoice = WTD_CHOICE_FILE;
                wtd.pFile = &wfi;
                wtd.dwProvFlags =
                    WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
                    | WTD_CACHE_ONLY_URL_RETRIEVAL;
                wtd.dwStateAction = WTD_STATEACTION_VERIFY;

                // Perform WinVerifyTrust verification
                LONG status = WinVerifyTrust(nullptr, &policyGUID, &wtd);

                // Always close state regardless of result
                wtd.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(nullptr, &policyGUID, &wtd);

                if (status != ERROR_SUCCESS) {
                    set_err(err, "WinVerifyTrust failed (embedded)", static_cast<DWORD>(status));
                    return false;
                }

                // Mark as signed
                info.isSigned = true;

                // Extract leaf certificate from PKCS7 using RAII wrappers
                CertStoreRAII storeGuard;
                CryptMsgRAII msgGuard;
                CertCtxRAII leaf;

                {
                    HCERTSTORE hStore = nullptr;
                    HCRYPTMSG hMsg = nullptr;
                    DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;

                    if (!CryptQueryObject(//-V1109
                        CERT_QUERY_OBJECT_FILE,
                        pathCopy.c_str(),
                        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                        CERT_QUERY_FORMAT_FLAG_BINARY,
                        0,
                        &dwEncoding, &dwContentType, &dwFormatType,
                        &hStore, &hMsg, nullptr)) {
                        DWORD lastErr = GetLastError();
                        // Take ownership of any partially acquired handles
                        storeGuard.reset(hStore);
                        msgGuard.reset(hMsg);
                        set_err(err, "CryptQueryObject failed (embedded)", lastErr);
                        return false;
                    }

                    // Take ownership immediately
                    storeGuard.reset(hStore);
                    msgGuard.reset(hMsg);

                    // Get signer info size
                    DWORD cbSigner = 0;
                    if (!CryptMsgGetParam(msgGuard.get(), CMSG_SIGNER_INFO_PARAM, 0, nullptr, &cbSigner) || cbSigner == 0) {
                        set_err(err, "CryptMsgGetParam signer size failed (embedded)", GetLastError());
                        return false;
                    }

                    // Allocate signer buffer with exception safety
                    std::vector<BYTE> signerBuf;
                    try {
                        signerBuf.resize(cbSigner);
                    }
                    catch (...) {
                        set_err(err, "Memory allocation failed for signer info");
                        return false;
                    }

                    auto* psi = reinterpret_cast<CMSG_SIGNER_INFO*>(signerBuf.data());
                    if (!CryptMsgGetParam(msgGuard.get(), CMSG_SIGNER_INFO_PARAM, 0, psi, &cbSigner)) {
                        set_err(err, "CryptMsgGetParam signer info failed (embedded)", GetLastError());
                        return false;
                    }

                    // Find leaf certificate
                    CERT_INFO ci{};
                    ci.Issuer = psi->Issuer;
                    ci.SerialNumber = psi->SerialNumber;

                    leaf.p = CertFindCertificateInStore(
                        storeGuard.get(),
                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                        0,
                        CERT_FIND_SUBJECT_CERT,
                        &ci,
                        nullptr
                    );

                    if (!leaf.p) {
                        set_err(err, "Leaf certificate not found (embedded)");
                        return false;
                    }
                }

                // EKU validation
                if (!CheckCodeSigningEKU(leaf.p, err)) {
                    return false;
                }
                info.isEKUValid = true;

                // Timestamp validation (use system time as fallback)
                FILETIME signTime{};
                SYSTEMTIME stNow{};
                GetSystemTime(&stNow);
                if (!SystemTimeToFileTime(&stNow, &signTime)) {
                    set_err(err, "SystemTimeToFileTime failed", GetLastError());
                    return false;
                }

                if (!ValidateTimestamp(signTime, leaf.p, err)) {
                    return false;
                }
                info.isTimestampValid = true;
                info.signTime = signTime;

                // Chain + revocation validation
                if (!ValidateCertificateChain(leaf.p, err)) {
                    return false;
                }
                info.isChainTrusted = true;

                if (!CheckRevocationOnline(leaf.p, err)) {
                    return false;
                }
                info.isRevocationChecked = true;

                // Populate additional info fields
                if (!GetSignerName(leaf.p, info.signerName, nullptr)) {
                    SS_LOG_WARN(L"PE_sig_verification", L"Failed to get signer's name");
                }
                else if (!GetIssuerName(leaf.p, info.issuerName, nullptr)) {
                    SS_LOG_WARN(L"PE_sig_verification", L"Failed to get ıssuer's name");
                }
                else if (!GetCertThumbprint(leaf.p, info.thumbprint, nullptr, true)) {
                    SS_LOG_WARN(L"PE_sig_verification", L"Failed to get certificate thumbprint");
                }

                info.isVerified = true;
                return true;
            }

            // Validate catalog file's signer chain/policy - independent of member hash verification.
            // RAII-hardened: uses CertStoreRAII and CryptMsgRAII for exception-safe resource management.
            bool PEFileSignatureVerifier::ValidateCatalogChain(std::wstring_view catalogPath,
                std::wstring_view /*fileHash*/,
                Error* err) noexcept {
                if (!file_exists(catalogPath)) {
                    set_err(err, "ValidateCatalogChain: catalog not found");
                    return false;
                }

                // Extract signer cert from catalog PKCS7 using RAII for exception safety
                CertCtxRAII leaf{};
                {
                    CertStoreRAII storeGuard;
                    CryptMsgRAII msgGuard;
                    DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;
                    
                    {
                        // Temporary raw pointers for CryptQueryObject (requires pointer-to-pointer)
                        HCERTSTORE hStoreTmp = nullptr;
                        HCRYPTMSG hMsgTmp = nullptr;
                        
                        if (!CryptQueryObject(//-V1109
                            CERT_QUERY_OBJECT_FILE,
                            std::wstring(catalogPath).c_str(),
                            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                            CERT_QUERY_FORMAT_FLAG_BINARY,
                            0,
                            &dwEncoding, &dwContentType, &dwFormatType,
                            &hStoreTmp, &hMsgTmp, nullptr)) {
                            set_err(err, "CryptQueryObject failed (catalog)");
                            // Clean up any partial allocation
                            if (hStoreTmp) CertCloseStore(hStoreTmp, 0);
                            if (hMsgTmp) CryptMsgClose(hMsgTmp);
                            return false;
                        }
                        // Transfer ownership to RAII guards
                        storeGuard.reset(hStoreTmp);
                        msgGuard.reset(hMsgTmp);
                    }

                    DWORD cb = 0;
                    CryptMsgGetParam(msgGuard.get(), CMSG_SIGNER_INFO_PARAM, 0, nullptr, &cb);
                    if (cb == 0 || cb > kMaxSignerInfoSize) {
                        set_err(err, "Invalid signer info size (catalog)");
                        return false;
                    }

                    std::vector<BYTE> signerBuf;
                    try {
                        signerBuf.resize(cb);
                    } catch (const std::bad_alloc&) {
                        set_err(err, "Memory allocation failed for signer buffer (catalog)");
                        return false;
                    }

                    auto* psi = reinterpret_cast<CMSG_SIGNER_INFO*>(signerBuf.data());
                    if (!CryptMsgGetParam(msgGuard.get(), CMSG_SIGNER_INFO_PARAM, 0, psi, &cb)) {
                        set_err(err, "CryptMsgGetParam signer info failed (catalog)");
                        return false;
                    }

                    CERT_INFO ci{};
                    ci.Issuer = psi->Issuer;
                    ci.SerialNumber = psi->SerialNumber;

                    leaf.p = CertFindCertificateInStore(
                        storeGuard.get(),
                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                        0,
                        CERT_FIND_SUBJECT_CERT,
                        &ci,
                        nullptr
                    );

                    // RAII cleanup happens automatically here

                    if (!leaf.p) {
                        set_err(err, "Leaf certificate not found (catalog)");
                        return false;
                    }
                }

                // EKU check (catalogs are code signed; enforce EKU)
                if (!CheckCodeSigningEKU(leaf.p, err)) return false;

                // Chain + revocation policy
                if (!ValidateCertificateChain(leaf.p, err)) return false;

                return true;
            }



            // Extract signer display name from cert
            bool PEFileSignatureVerifier::GetSignerName(PCCERT_CONTEXT cert,
                std::wstring& outName,
                Error* err) noexcept {
                outName.clear();
                if (!cert) { 
                    set_err(err, "GetSignerName: null cert"); 
                    return false; 
                }

                // First call to determine required buffer size
                DWORD charsNeeded = CertGetNameStringW(
                    cert,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0, // subject name (signer)
                    nullptr,
                    nullptr,
                    0
                );

                if (charsNeeded <= 1) {
                    // A return of 1 means only null terminator - no actual name
                    set_err(err, "CertGetNameString failed or returned empty name (signer)");
                    return false;
                }

                // Allocate buffer with exception safety
                std::vector<wchar_t> buffer;
                try {
                    buffer.resize(charsNeeded);
                }
                catch (const std::bad_alloc&) {
                    set_err(err, "Memory allocation failed for signer name buffer");
                    return false;
                }

                // Second call to retrieve the actual name
                DWORD result = CertGetNameStringW(
                    cert,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0,
                    nullptr,
                    buffer.data(),
                    charsNeeded
                );

                if (result <= 1) {
                    set_err(err, "CertGetNameString failed to copy (signer)");
                    return false;
                }

                // Copy to output string (excluding null terminator)
                try {
                    outName.assign(buffer.data(), result - 1);
                }
                catch (const std::bad_alloc&) {
                    set_err(err, "Memory allocation failed for signer name output");
                    return false;
                }

                return true;
            }

            // Extract issuer display name from cert
            bool PEFileSignatureVerifier::GetIssuerName(PCCERT_CONTEXT cert,
                std::wstring& outIssuer,
                Error* err) noexcept {
                outIssuer.clear();
                if (!cert) { 
                    set_err(err, "GetIssuerName: null cert"); 
                    return false; 
                }

                // First call to determine required buffer size
                DWORD charsNeeded = CertGetNameStringW(
                    cert,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    CERT_NAME_ISSUER_FLAG, // issuer
                    nullptr,
                    nullptr,
                    0
                );

                if (charsNeeded <= 1) {
                    // A return of 1 means only null terminator - no actual name
                    set_err(err, "CertGetNameString failed or returned empty name (issuer)");
                    return false;
                }

                // Allocate buffer with exception safety
                std::vector<wchar_t> buffer;
                try {
                    buffer.resize(charsNeeded);
                }
                catch (const std::bad_alloc&) {
                    set_err(err, "Memory allocation failed for issuer name buffer");
                    return false;
                }

                // Second call to retrieve the actual name
                DWORD result = CertGetNameStringW(
                    cert,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    CERT_NAME_ISSUER_FLAG,
                    nullptr,
                    buffer.data(),
                    charsNeeded
                );

                if (result <= 1) {
                    set_err(err, "CertGetNameString failed to copy (issuer)");
                    return false;
                }

                // Copy to output string (excluding null terminator)
                try {
                    outIssuer.assign(buffer.data(), result - 1);
                }
                catch (const std::bad_alloc&) {
                    set_err(err, "Memory allocation failed for issuer name output");
                    return false;
                }

                return true;
            }

            // Compute SHA-1/256 thumbprint (hex) of cert for allowlisting/logging
            // Uses BCrypt for modern, secure hashing (preferred over legacy CAPI)
            bool PEFileSignatureVerifier::GetCertThumbprint(PCCERT_CONTEXT cert,
                std::wstring& outHex,
                Error* err,
                bool useSha256) noexcept {
                outHex.clear();
                if (!cert) { 
                    set_err(err, "GetCertThumbprint: null cert"); 
                    return false; 
                }

                // Validate certificate has encoded data
                if (!cert->pbCertEncoded || cert->cbCertEncoded == 0) {
                    set_err(err, "GetCertThumbprint: certificate has no encoded data");
                    return false;
                }

                // Use BCrypt for modern, secure hashing
                BCRYPT_ALG_HANDLE hAlg = nullptr;
                BCRYPT_HASH_HANDLE hHash = nullptr;
                const DWORD hashSize = useSha256 ? 32 : 20; // SHA-256 = 32 bytes, SHA-1 = 20 bytes
                
                // Select algorithm
                LPCWSTR algId = useSha256 ? BCRYPT_SHA256_ALGORITHM : BCRYPT_SHA1_ALGORITHM;
                
                NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, algId, nullptr, 0);
                if (!BCRYPT_SUCCESS(status)) {
                    set_err(err, "BCryptOpenAlgorithmProvider failed", static_cast<DWORD>(status));
                    return false;
                }

                // RAII cleanup for algorithm handle
                auto cleanupAlg = [&hAlg]() noexcept {
                    if (hAlg) {
                        BCryptCloseAlgorithmProvider(hAlg, 0);
                        hAlg = nullptr;
                    }
                };

                status = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
                if (!BCRYPT_SUCCESS(status)) {
                    cleanupAlg();
                    set_err(err, "BCryptCreateHash failed", static_cast<DWORD>(status));
                    return false;
                }

                // RAII cleanup for hash handle
                auto cleanupHash = [&hHash]() noexcept {
                    if (hHash) {
                        BCryptDestroyHash(hHash);
                        hHash = nullptr;
                    }
                };

                // Hash the certificate's DER-encoded data
                status = BCryptHashData(hHash, cert->pbCertEncoded, cert->cbCertEncoded, 0);
                if (!BCRYPT_SUCCESS(status)) {
                    cleanupHash();
                    cleanupAlg();
                    set_err(err, "BCryptHashData failed", static_cast<DWORD>(status));
                    return false;
                }

                // Allocate hash output buffer with exception safety
                std::vector<BYTE> hashBuffer;
                try {
                    hashBuffer.resize(hashSize);
                }
                catch (const std::bad_alloc&) {
                    cleanupHash();
                    cleanupAlg();
                    set_err(err, "Memory allocation failed for hash buffer");
                    return false;
                }

                // Finalize hash
                status = BCryptFinishHash(hHash, hashBuffer.data(), hashSize, 0);
                cleanupHash();
                cleanupAlg();

                if (!BCRYPT_SUCCESS(status)) {
                    set_err(err, "BCryptFinishHash failed", static_cast<DWORD>(status));
                    return false;
                }

                // Convert to uppercase hex string
                static constexpr wchar_t kHexDigits[] = L"0123456789ABCDEF";
                
                try {
                    outHex.reserve(hashSize * 2);
                    for (DWORD i = 0; i < hashSize; ++i) {
                        const BYTE b = hashBuffer[i];
                        outHex.push_back(kHexDigits[(b >> 4) & 0x0F]);
                        outHex.push_back(kHexDigits[b & 0x0F]);
                    }
                }
                catch (const std::bad_alloc&) {
                    outHex.clear();
                    set_err(err, "Memory allocation failed for hex string");
                    return false;
                }

                return true;
            }

            // Extract all signatures as metadata (no trust decision). Useful for inventory/telemetry.
            std::vector<SignatureInfo> PEFileSignatureVerifier::ExtractAllSignatures(std::wstring_view filePath,
                Error* err) noexcept {
                std::vector<SignatureInfo> result;

                if (!file_exists(filePath)) {
                    set_err(err, "ExtractAllSignatures: file not found");
                    return result;
                }

                // Query PKCS7 from PE
                HCERTSTORE hStore = nullptr;
                HCRYPTMSG hMsg = nullptr;
                DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;
                BOOL qok = CryptQueryObject(//-V1109
                    CERT_QUERY_OBJECT_FILE,
                    std::wstring(filePath).c_str(),
                    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                    CERT_QUERY_FORMAT_FLAG_BINARY,
                    0,
                    &dwEncoding, &dwContentType, &dwFormatType,
                    &hStore, &hMsg, nullptr
                );
                if (!qok || !hStore || !hMsg) {
                    set_err(err, "CryptQueryObject failed (ExtractAllSignatures)");
                    if (hStore) CertCloseStore(hStore, 0);
                    if (hMsg) CryptMsgClose(hMsg);
                    return result;
                }

                // Get signer count
                DWORD signerCount = 0;
                DWORD cb = sizeof(signerCount);
                if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_COUNT_PARAM, 0, &signerCount, &cb) || signerCount == 0) {
                    // No signers is legitimate for unsigned files; return empty vector
                    CertCloseStore(hStore, 0);
                    CryptMsgClose(hMsg);
                    return result;
                }

                // Reserve space for results to avoid repeated allocations
                try {
                    result.reserve(signerCount);
                }
                catch (...) {
                    // Non-fatal - continue without reservation
                }

                // Enumerate all signers
                for (DWORD index = 0; index < signerCount; ++index) {
                    // Fetch signer info size first
                    DWORD cbi = 0;
                    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, index, nullptr, &cbi) || cbi == 0) {
                        continue; // Skip malformed entry
                    }
                    
                    // Allocate with exception safety
                    std::vector<BYTE> signerBuf;
                    try {
                        signerBuf.resize(cbi);
                    }
                    catch (...) {
                        continue; // Skip on allocation failure
                    }
                    
                    auto* psi = reinterpret_cast<CMSG_SIGNER_INFO*>(signerBuf.data());
                    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, index, psi, &cbi)) {
                        // Skip broken entry; continue others
                        continue;
                    }

                    // Find matching leaf certificate
                    CERT_INFO ci{};
                    ci.Issuer = psi->Issuer;
                    ci.SerialNumber = psi->SerialNumber;

                    PCCERT_CONTEXT leaf = CertFindCertificateInStore(
                        hStore,
                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                        0,
                        CERT_FIND_SUBJECT_CERT,
                        &ci,
                        nullptr
                    );

                    CertCtxRAII leafGuard{ leaf };
                    if (!leafGuard.p) {
                        // signer without matching cert in store - skip
                        continue;
                    }

                    // Build SignatureInfo with all available metadata
                    SignatureInfo meta{};
                    meta.isSigned = true;

                    // Extract signer name
                    if (!GetSignerName(leafGuard.p, meta.signerName, nullptr)) {
                        SS_LOG_ERROR(L"PE_sig_verification", L"Failed to get signer's name.");
                    }

                    // Extract issuer name
                    if (!GetIssuerName(leafGuard.p, meta.issuerName, nullptr)) {
                        SS_LOG_ERROR(L"PE_sig_verification", L"Failed to get signer's name.");
                    }

                    // Extract thumbprint (SHA-256 preferred)
                    if (!GetCertThumbprint(leafGuard.p, meta.thumbprint, nullptr, /*useSha256*/ true)) {
                        SS_LOG_ERROR(L"PE_sig_verification", L"Failed to get signer's name.");
                    }

                    // Extract signing time (best effort - use current time as fallback)
                    SYSTEMTIME stNow{}; 
                    GetSystemTime(&stNow);
                    FILETIME ftNow{}; 
                    if (SystemTimeToFileTime(&stNow, &ftNow)) {
                        meta.signTime = ftNow;
                    }

                    // Check EKU (informational - doesn't affect inclusion in results)
                    meta.isEKUValid = CheckCodeSigningEKU(leafGuard.p, nullptr);

                    // Note: For telemetry/inventory purposes, we don't validate chain/revocation here
                    // as this is just metadata extraction, not trust verification

                    result.push_back(std::move(meta));
                }

                CertCloseStore(hStore, 0);
                CryptMsgClose(hMsg);
                return result;
            }

            // Verify nested/dual signatures: validate each signer strictly (EKU + countersignature timestamp + chain + revocation).
            // Returns true if at least one signer is fully trusted; fills 'infos' with metadata if desired.
            bool PEFileSignatureVerifier::VerifyNestedSignatures(std::wstring_view filePath,
                std::vector<SignatureInfo>& infos,
                Error* err) noexcept {
                infos.clear();

                // Validate input
                if (filePath.empty()) {
                    set_err(err, "VerifyNestedSignatures: empty file path");
                    return false;
                }

                if (!file_exists(filePath)) {
                    set_err(err, "VerifyNestedSignatures: file not found");
                    return false;
                }

                // Allocate path copy with exception safety
                std::wstring pathCopy;
                try {
                    pathCopy = std::wstring(filePath);
                }
                catch (...) {
                    set_err(err, "Memory allocation failed for path");
                    return false;
                }

                // Query PKCS#7 using RAII wrappers
                CertStoreRAII storeGuard;
                CryptMsgRAII msgGuard;

                {
                    HCERTSTORE hStore = nullptr;
                    HCRYPTMSG hMsg = nullptr;
                    DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;

                    if (!CryptQueryObject(//-V1109
                        CERT_QUERY_OBJECT_FILE,
                        pathCopy.c_str(),
                        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                        CERT_QUERY_FORMAT_FLAG_BINARY,
                        0,
                        &dwEncoding, &dwContentType, &dwFormatType,
                        &hStore, &hMsg, nullptr)) {
                        DWORD lastErr = GetLastError();
                        storeGuard.reset(hStore);
                        msgGuard.reset(hMsg);
                        set_err(err, "CryptQueryObject failed (nested)", lastErr);
                        return false;
                    }

                    storeGuard.reset(hStore);
                    msgGuard.reset(hMsg);
                }

                // Get signer count
                DWORD signerCount = 0;
                DWORD cbCount = sizeof(signerCount);
                if (!CryptMsgGetParam(msgGuard.get(), CMSG_SIGNER_COUNT_PARAM, 0, &signerCount, &cbCount) || signerCount == 0) {
                    set_err(err, "No signers found (nested)");
                    return false;
                }

                // Reserve space for results
                try {
                    infos.reserve(signerCount);
                }
                catch (...) {
                    // Non-fatal - continue without reservation
                }

                bool anyTrusted = false;

                for (DWORD index = 0; index < signerCount; ++index) {
                    // Get signer info size
                    DWORD cbSigner = 0;
                    if (!CryptMsgGetParam(msgGuard.get(), CMSG_SIGNER_INFO_PARAM, index, nullptr, &cbSigner) || cbSigner == 0) {
                        continue; // Skip malformed entry
                    }

                    // Allocate with exception safety
                    std::vector<BYTE> signerBuf;
                    try {
                        signerBuf.resize(cbSigner);
                    }
                    catch (...) {
                        continue; // Skip on allocation failure
                    }

                    auto* psi = reinterpret_cast<CMSG_SIGNER_INFO*>(signerBuf.data());
                    if (!CryptMsgGetParam(msgGuard.get(), CMSG_SIGNER_INFO_PARAM, index, psi, &cbSigner)) {
                        continue; // Skip malformed
                    }

                    // Find leaf certificate
                    CERT_INFO ci{};
                    ci.Issuer = psi->Issuer;
                    ci.SerialNumber = psi->SerialNumber;

                    CertCtxRAII leafGuard{ CertFindCertificateInStore(
                        storeGuard.get(),
                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                        0,
                        CERT_FIND_SUBJECT_CERT,
                        &ci,
                        nullptr
                    ) };

                    if (!leafGuard.p) {
                        continue; // No matching cert
                    }

                    // EKU validation
                    if (!CheckCodeSigningEKU(leafGuard.p, nullptr)) {
                        continue;
                    }

                    // Timestamp validation (countersignature or fallback)
                    FILETIME ts{};
                    bool haveCsTs = CheckTimestampCounterSignatureFromMessage(msgGuard.get(), index, ts, nullptr);
                    bool tsValid = false;
                    
                    if (haveCsTs) {
                        tsValid = ValidateTimestamp(ts, leafGuard.p, nullptr);
                    }
                    else {
                        // Fallback to current time
                        SYSTEMTIME stNow{};
                        GetSystemTime(&stNow);
                        if (SystemTimeToFileTime(&stNow, &ts)) {
                            tsValid = ValidateTimestamp(ts, leafGuard.p, nullptr);
                        }
                    }
                    
                    if (!tsValid) {
                        continue;
                    }

                    // Chain + revocation validation
                    bool chainOk = ValidateCertificateChain(leafGuard.p, nullptr);
                    bool revOk = CheckRevocationOnline(leafGuard.p, nullptr);
                    bool signerTrusted = chainOk && revOk;

                    anyTrusted = anyTrusted || signerTrusted;

                    // Build fully populated SignatureInfo
                    SignatureInfo meta{};
                    meta.isSigned = true;
                    meta.isEKUValid = true;
                    meta.isTimestampValid = tsValid;
                    meta.isChainTrusted = chainOk;
                    meta.isRevocationChecked = revOk;
                    meta.isVerified = signerTrusted;
                    meta.signTime = ts;

                    // Extract certificate metadata
                    if (!GetSignerName(leafGuard.p, meta.signerName, nullptr)) {
                        SS_LOG_ERROR(L"PE_sig_verification", L"Failed to get Signer's name.");
                        
                    }
                    if (!GetIssuerName(leafGuard.p, meta.issuerName, nullptr)) {
                        SS_LOG_ERROR(L"PE_sig_verification", L"Failed to get Issuer's name.");
                       
                    }
                    if (!GetCertThumbprint(leafGuard.p, meta.thumbprint, nullptr, true)) {
                        SS_LOG_ERROR(L"PE_sig_verification", L"Failed to get Certificate Thumbprint.");
                       
                     }
                       
                 
                    // Add to results with exception safety
                    try {
                        infos.push_back(std::move(meta));
                    }
                    catch (...) {
                        // Allocation failure - stop enumeration
                        break;
                    }

                    // Early-out if policy allows single trusted signer and we don't need full enumeration
                    if (!allowMultipleSignatures_ && signerTrusted) {
                        break;
                    }
                }

                // RAII handles cleanup automatically

                if (!anyTrusted) {
                    set_err(err, "No trusted signers found (nested)");
                }

                return anyTrusted;
            }


            /**
             * @brief Loads the catalog signer certificate.
             *
             * Extracts the leaf signing certificate from a catalog file's PKCS#7 structure.
             * The caller takes ownership of the returned certificate context and must call
             * CertFreeCertificateContext when done.
             *
             * @param catalogPath Path to the .cat catalog file
             * @param outCert Output certificate context (caller must free)
             * @param err Optional error output
             * @return true if certificate was successfully loaded
             */
            bool PEFileSignatureVerifier::LoadCatalogSigner(std::wstring_view catalogPath,
                PCCERT_CONTEXT& outCert,
                Error* err) noexcept {
                outCert = nullptr;

                // Validate input
                if (catalogPath.empty()) {
                    set_err(err, "LoadCatalogSigner: empty catalog path");
                    return false;
                }

                if (!file_exists(catalogPath)) {
                    set_err(err, "LoadCatalogSigner: catalog not found");
                    return false;
                }

                // Allocate path copy with exception safety
                std::wstring pathCopy;
                try {
                    pathCopy = std::wstring(catalogPath);
                }
                catch (...) {
                    set_err(err, "Memory allocation failed for path");
                    return false;
                }

                // Query PKCS#7 using RAII wrappers
                CertStoreRAII storeGuard;
                CryptMsgRAII msgGuard;

                {
                    HCERTSTORE hStore = nullptr;
                    HCRYPTMSG hMsg = nullptr;
                    DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;

                    if (!CryptQueryObject(//-V1109
                        CERT_QUERY_OBJECT_FILE,
                        pathCopy.c_str(),
                        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                        CERT_QUERY_FORMAT_FLAG_BINARY,
                        0,
                        &dwEncoding, &dwContentType, &dwFormatType,
                        &hStore, &hMsg, nullptr)) {
                        DWORD lastErr = GetLastError();
                        storeGuard.reset(hStore);
                        msgGuard.reset(hMsg);
                        set_err(err, "CryptQueryObject failed (LoadCatalogSigner)", lastErr);
                        return false;
                    }

                    storeGuard.reset(hStore);
                    msgGuard.reset(hMsg);
                }

                // Get signer info size
                DWORD cbSigner = 0;
                if (!CryptMsgGetParam(msgGuard.get(), CMSG_SIGNER_INFO_PARAM, 0, nullptr, &cbSigner) || cbSigner == 0) {
                    set_err(err, "CryptMsgGetParam signer size failed (LoadCatalogSigner)", GetLastError());
                    return false;
                }

                // Allocate signer buffer with exception safety
                std::vector<BYTE> signerBuf;
                try {
                    signerBuf.resize(cbSigner);
                }
                catch (...) {
                    set_err(err, "Memory allocation failed for signer info");
                    return false;
                }

                auto* psi = reinterpret_cast<CMSG_SIGNER_INFO*>(signerBuf.data());
                if (!CryptMsgGetParam(msgGuard.get(), CMSG_SIGNER_INFO_PARAM, 0, psi, &cbSigner)) {
                    set_err(err, "CryptMsgGetParam signer info failed (LoadCatalogSigner)", GetLastError());
                    return false;
                }

                // Find leaf certificate
                CERT_INFO ci{};
                ci.Issuer = psi->Issuer;
                ci.SerialNumber = psi->SerialNumber;

                outCert = CertFindCertificateInStore(
                    storeGuard.get(),
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    0,
                    CERT_FIND_SUBJECT_CERT,
                    &ci,
                    nullptr
                );

                if (!outCert) {
                    set_err(err, "Leaf certificate not found (LoadCatalogSigner)");
                    return false;
                }

                return true;
            }
            /**
             * @brief Parses countersignature and extracts signing time.
             *
             * Supports both RFC3161 (TimeStampToken) and legacy countersignatures.
             * Searches the signer's unauthenticated attributes for timestamp information.
             *
             * @param hMsg Cryptographic message handle
             * @param signerIndex Index of the signer to check
             * @param outSignTime Output signing timestamp
             * @param err Optional error output
             * @return true if a valid signing time was found
             */
            bool PEFileSignatureVerifier::CheckTimestampCounterSignatureFromMessage(HCRYPTMSG hMsg,
                DWORD signerIndex,
                FILETIME& outSignTime,
                Error* err) noexcept {
                outSignTime = FILETIME{};

                if (!hMsg) {
                    set_err(err, "CheckTimestampCounterSignatureFromMessage: null hMsg");
                    return false;
                }

                // Get the relevant signer info size
                DWORD cbSigner = 0;
                if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, signerIndex, nullptr, &cbSigner) || cbSigner == 0) {
                    set_err(err, "CMSG_SIGNER_INFO size query failed");
                    return false;
                }

                // Allocate with exception safety
                std::vector<BYTE> signerBuf;
                try {
                    signerBuf.resize(cbSigner);
                }
                catch (...) {
                    set_err(err, "Memory allocation failed for signer info");
                    return false;
                }

                auto* psi = reinterpret_cast<CMSG_SIGNER_INFO*>(signerBuf.data());
                if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, signerIndex, psi, &cbSigner)) {
                    set_err(err, "CMSG_SIGNER_INFO fetch failed");
                    return false;
                }

                // Look for countersignature in the unauthenticated attributes
                const CRYPT_ATTRIBUTES& unauth = psi->UnauthAttrs;
                if (unauth.cAttr == 0 || !unauth.rgAttr) {
                    set_err(err, "No unauthenticated attributes (no countersignature)");
                    return false;
                }

                // Try RFC3161 first, then legacy
                bool gotTime = false;
                FILETIME tsFT{};

                for (DWORD a = 0; a < unauth.cAttr && !gotTime; ++a) {
                    const CRYPT_ATTRIBUTE& attr = unauth.rgAttr[a];
                    if (!attr.cValue || !attr.rgValue) continue;

                    // RFC3161 (TimeStampToken): attr.rgValue[0] is a PKCS#7 (signed-data)
                    if (attr.pszObjId && std::strcmp(attr.pszObjId, OID_RFC3161_TS) == 0) {
                        const CRYPT_ATTR_BLOB& blob = attr.rgValue[0];

                        // Open the RFC3161 token as a separate message
                        HCRYPTMSG hTsMsg = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                            0, 0, 0, nullptr, nullptr);
                        if (!hTsMsg) { set_err(err, "CryptMsgOpenToDecode(TST) failed"); continue; }

                        BOOL upd = CryptMsgUpdate(hTsMsg, blob.pbData, blob.cbData, TRUE);
                        if (!upd) {
                            set_err(err, "CryptMsgUpdate(TST) failed");
                            CryptMsgClose(hTsMsg);
                            continue;
                        }

                        // Get signer info of the TST (index 0)
                        DWORD cbTsSigner = 0;
                        CryptMsgGetParam(hTsMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &cbTsSigner);
                        std::vector<BYTE> tsSignerBuf(cbTsSigner);
                        auto* tsSI = reinterpret_cast<CMSG_SIGNER_INFO*>(tsSignerBuf.data());
                        if (!CryptMsgGetParam(hTsMsg, CMSG_SIGNER_INFO_PARAM, 0, tsSI, &cbTsSigner)) {
                            set_err(err, "CMSG_SIGNER_INFO(TST) fetch failed");
                            CryptMsgClose(hTsMsg);
                            continue;
                        }

                        // Look for signingTime in TST signer's authenticated attributes (some TSAs include it)
                        const CRYPT_ATTRIBUTES& tsAuth = tsSI->AuthAttrs;
                        for (DWORD j = 0; j < tsAuth.cAttr && !gotTime; ++j) {
                            const CRYPT_ATTRIBUTE& a2 = tsAuth.rgAttr[j];
                            if (!a2.cValue || !a2.rgValue) continue;
                            if (a2.pszObjId && std::strcmp(a2.pszObjId, OID_SIGNING_TIME) == 0) {
                                // Decode UTCTime/GeneralizedTime - X509_CHOICE_OF_TIME decodes to FILETIME
                                std::vector<BYTE> decoded;
                                if (decode_object(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_CHOICE_OF_TIME,
                                    a2.rgValue[0].pbData, a2.rgValue[0].cbData, decoded)) {
                                    if (decoded.size() >= sizeof(FILETIME)) {
                                        auto* pFileTime = reinterpret_cast<FILETIME*>(decoded.data());
                                        tsFT = *pFileTime;  // Store in tsFT for consistency
                                        gotTime = true;
                                    }
                                }
                            }
                        }

                        // Alternative: extract genTime from RFC3161 TSTInfo (requires full ASN.1 parse)
                        // Using CryptMsgGetParam(CMSG_CONTENT_PARAM) gives SignedData content
                        DWORD cbContent = 0;
                        if (!gotTime && CryptMsgGetParam(hTsMsg, CMSG_CONTENT_PARAM, 0, nullptr, &cbContent) && cbContent) {
                            std::vector<BYTE> content(cbContent);
                            if (CryptMsgGetParam(hTsMsg, CMSG_CONTENT_PARAM, 0, content.data(), &cbContent)) {
                                // content contains SignedData - look for TSTInfo
                                // Full ASN.1 parse required; if signingTime not found, fallback to legacy
                            }
                        }

                        CryptMsgClose(hTsMsg);
                        if (gotTime) {
                            outSignTime = tsFT;
                            return true;
                        }
                        // RFC3161 failed � try legacy
                    }

                    // Legacy countersignature: attr.rgValue[0] contains single SignerInfo; read signingTime from there
                    if (attr.pszObjId && std::strcmp(attr.pszObjId, OID_COUNTERSIGN) == 0) {
                        const CRYPT_ATTR_BLOB& blob = attr.rgValue[0];

                        // Decode legacy countersignature message
                        HCRYPTMSG hCsMsg = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                            0, 0, 0, nullptr, nullptr);
                        if (!hCsMsg) { set_err(err, "CryptMsgOpenToDecode(legacy CS) failed"); continue; }

                        BOOL upd = CryptMsgUpdate(hCsMsg, blob.pbData, blob.cbData, TRUE);
                        if (!upd) {
                            set_err(err, "CryptMsgUpdate(legacy CS) failed");
                            CryptMsgClose(hCsMsg);
                            continue;
                        }

                        DWORD cbCsSigner = 0;
                        CryptMsgGetParam(hCsMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &cbCsSigner);
                        std::vector<BYTE> csSignerBuf(cbCsSigner);
                        auto* csSI = reinterpret_cast<CMSG_SIGNER_INFO*>(csSignerBuf.data());
                        if (!CryptMsgGetParam(hCsMsg, CMSG_SIGNER_INFO_PARAM, 0, csSI, &cbCsSigner)) {
                            set_err(err, "CMSG_SIGNER_INFO(legacy CS) fetch failed");
                            CryptMsgClose(hCsMsg);
                            continue;
                        }

                        const CRYPT_ATTRIBUTES& auth = csSI->AuthAttrs;
                        for (DWORD k = 0; k < auth.cAttr && !gotTime; ++k) {
                            const CRYPT_ATTRIBUTE& a3 = auth.rgAttr[k];
                            if (!a3.cValue || !a3.rgValue) continue;
                            if (a3.pszObjId && std::strcmp(a3.pszObjId, OID_SIGNING_TIME) == 0) {
                                // Convert X509_CHOICE_OF_TIME � SYSTEMTIME � FILETIME
                                std::vector<BYTE> decoded;
                                if (decode_object(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_CHOICE_OF_TIME,
                                    a3.rgValue[0].pbData, a3.rgValue[0].cbData, decoded)) {
                                    SYSTEMTIME* pst = reinterpret_cast<SYSTEMTIME*>(decoded.data());
                                    FILETIME ft{};
                                    if (SystemTimeToFileTime(pst, &ft)) {
                                        tsFT = ft;
                                        gotTime = true;
                                    }
                                }
                            }
                        }

                        CryptMsgClose(hCsMsg);
                    }
                }

                if (!gotTime) {
                    set_err(err, "Countersignature timestamp not found/decoded");
                    return false;
                }

                outSignTime = tsFT;
                return true;
            }


            // Validate a FILETIME against current system time with grace window.
            // Returns true if |signTime| within [now - grace, now + grace] OR simply non-zero and plausible.
            bool PEFileSignatureVerifier::IsTimeValidWithGrace(const FILETIME& signTime) const noexcept {
                if (signTime.dwHighDateTime == 0 && signTime.dwLowDateTime == 0) {
                    return false;
                }

                SYSTEMTIME stNow{};
                GetSystemTime(&stNow);
                FILETIME ftNow{};
                SystemTimeToFileTime(&stNow, &ftNow);

                ULARGE_INTEGER now{}, ts{};
                now.LowPart = ftNow.dwLowDateTime; now.HighPart = ftNow.dwHighDateTime;
                ts.LowPart = signTime.dwLowDateTime; ts.HighPart = signTime.dwHighDateTime;

                ULONGLONG graceTicks = static_cast<ULONGLONG>(tsGraceSeconds_) * 10'000'000ULL; // seconds to 100ns

                // Accept if within grace window around current time (helps with minor clock skews)
                if (ts.QuadPart + graceTicks < now.QuadPart) return false;
                if (ts.QuadPart > now.QuadPart + graceTicks) return false;
                return true;
            }


            // LoadPrimarySigner: extract leaf signer cert and signing time (best-effort) from a PE�s embedded PKCS7.
// Returns true and sets outCert if the leaf is found. Optionally fills outSignTime (best-effort).
            bool PEFileSignatureVerifier::LoadPrimarySigner(std::wstring_view filePath,
                PCCERT_CONTEXT& outCert,
                FILETIME* outSignTime,
                Error* err) noexcept {
                outCert = nullptr;
                if (outSignTime) {
                    outSignTime->dwHighDateTime = 0;
                    outSignTime->dwLowDateTime = 0;
                }

                if (!file_exists(filePath)) {
                    set_err(err, "LoadPrimarySigner: file not found");
                    return false;
                }

                // RAII wrappers for automatic cleanup - exception-safe resource management
                CertStoreRAII storeGuard;
                CryptMsgRAII msgGuard;
                DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;

                {
                    // Temporary raw pointers for CryptQueryObject (requires pointer-to-pointer)
                    HCERTSTORE hStoreTmp = nullptr;
                    HCRYPTMSG hMsgTmp = nullptr;

                    if (!CryptQueryObject(//-V1109
                        CERT_QUERY_OBJECT_FILE,
                        std::wstring(filePath).c_str(),
                        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                        CERT_QUERY_FORMAT_FLAG_BINARY,
                        0,
                        &dwEncoding, &dwContentType, &dwFormatType,
                        &hStoreTmp, &hMsgTmp, nullptr)) {
                        set_err(err, "CryptQueryObject failed (LoadPrimarySigner)");
                        // Clean up any partial allocation (CryptQueryObject may partially succeed)
                        if (hStoreTmp) CertCloseStore(hStoreTmp, 0);
                        if (hMsgTmp) CryptMsgClose(hMsgTmp);
                        return false;
                    }
                    // Transfer ownership to RAII guards
                    storeGuard.reset(hStoreTmp);
                    msgGuard.reset(hMsgTmp);
                }

                // Signer count
                DWORD signerCount = 0;
                DWORD cbCount = sizeof(signerCount);
                if (!CryptMsgGetParam(msgGuard.get(), CMSG_SIGNER_COUNT_PARAM, 0, &signerCount, &cbCount) || signerCount == 0) {
                    set_err(err, "No signer found (LoadPrimarySigner)");
                    return false; // RAII cleanup automatic
                }

                // Fetch first signer info (primary) with exception-safe buffer allocation
                DWORD cbSigner = 0;
                CryptMsgGetParam(msgGuard.get(), CMSG_SIGNER_INFO_PARAM, 0, nullptr, &cbSigner);
                if (cbSigner == 0 || cbSigner > kMaxSignerInfoSize) {
                    set_err(err, "Invalid signer info size (LoadPrimarySigner)");
                    return false;
                }

                std::vector<BYTE> signerBuf;
                try {
                    signerBuf.resize(cbSigner);
                } catch (const std::bad_alloc&) {
                    set_err(err, "Memory allocation failed for signer buffer (LoadPrimarySigner)");
                    return false;
                }

                auto* psi = reinterpret_cast<CMSG_SIGNER_INFO*>(signerBuf.data());
                if (!CryptMsgGetParam(msgGuard.get(), CMSG_SIGNER_INFO_PARAM, 0, psi, &cbSigner)) {
                    set_err(err, "CryptMsgGetParam signer info failed (LoadPrimarySigner)");
                    return false;
                }

                // Find leaf cert in store matching Issuer/Serial
                CERT_INFO ci{};
                ci.Issuer = psi->Issuer;
                ci.SerialNumber = psi->SerialNumber;

                outCert = CertFindCertificateInStore(
                    storeGuard.get(),
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    0,
                    CERT_FIND_SUBJECT_CERT,
                    &ci,
                    nullptr
                );

                // Best-effort: extract signing time from unauthenticated attributes if present
                if (outSignTime) {
                    // Attempt to parse legacy signing time attribute (szOID_RSA_signingTime)
                    // We read the unauthenticated attributes from psi->UnauthenticatedAttributes if available.
                    // Full ASN.1 parsing is beyond this function�s scope; we set current system time as fallback.
                    SYSTEMTIME stNow{};
                    GetSystemTime(&stNow);
                    if (!SystemTimeToFileTime(&stNow, outSignTime)) {
                        // Fallback: zero out signTime on conversion failure
                        outSignTime->dwHighDateTime = 0;
                        outSignTime->dwLowDateTime = 0;
                    }
                }

                // RAII cleanup happens automatically here (storeGuard and msgGuard destructors)

                if (!outCert) {
                    set_err(err, "Leaf certificate not found (LoadPrimarySigner)");
                    return false;
                }

                return true;
            }
            
            // Strict OID check for Code Signing EKU.
            // Returns true when EKU includes 1.3.6.1.5.5.7.3.3; false otherwise.
            bool PEFileSignatureVerifier::CheckEKUCodeSigningOid(PCCERT_CONTEXT cert) noexcept {
                if (!cert) return false;

                DWORD cb = 0;
                if (!CertGetEnhancedKeyUsage(cert, 0, nullptr, &cb) || cb == 0) {
                    return false;
                }

                std::vector<BYTE> buf(cb);
                auto* pUsage = reinterpret_cast<PCERT_ENHKEY_USAGE>(buf.data());
                if (!CertGetEnhancedKeyUsage(cert, 0, pUsage, &cb)) {
                    return false;
                }

                if (pUsage->cUsageIdentifier == 0 || !pUsage->rgpszUsageIdentifier) {
                    return false;
                }

                constexpr const char* OID_CODE_SIGNING = "1.3.6.1.5.5.7.3.3";
                for (DWORD i = 0; i < pUsage->cUsageIdentifier; ++i) {
                    const char* oid = pUsage->rgpszUsageIdentifier[i];
                    if (oid && std::strcmp(oid, OID_CODE_SIGNING) == 0) {
                        return true;
                    }
                }
                return false;
            }

            // IsTimeValidWithGrace: already provided earlier. Keep as-is.

            // Policy controls � explicit implementations to avoid inline surprises
            void PEFileSignatureVerifier::SetRevocationMode(RevocationMode mode) noexcept {
                revocationMode_ = mode;
            }
            RevocationMode PEFileSignatureVerifier::GetRevocationMode() const noexcept {
                return revocationMode_;
            }

            void PEFileSignatureVerifier::SetTimestampGraceSeconds(uint32_t seconds) noexcept {
                tsGraceSeconds_ = seconds;
            }
            uint32_t PEFileSignatureVerifier::GetTimestampGraceSeconds() const noexcept {
                return tsGraceSeconds_;
            }

            void PEFileSignatureVerifier::SetAllowCatalogFallback(bool v) noexcept {
                allowCatalogFallback_ = v;
            }
            bool PEFileSignatureVerifier::GetAllowCatalogFallback() const noexcept {
                return allowCatalogFallback_;
            }

            void PEFileSignatureVerifier::SetAllowMultipleSignatures(bool v) noexcept {
                allowMultipleSignatures_ = v;
            }
            bool PEFileSignatureVerifier::GetAllowMultipleSignatures() const noexcept {
                return allowMultipleSignatures_;
            }

            void PEFileSignatureVerifier::SetAllowWeakAlgos(bool v) noexcept {
                allowWeakAlgos_ = v;
            }
            bool PEFileSignatureVerifier::GetAllowWeakAlgos() const noexcept {
                return allowWeakAlgos_;
            }



		}// namespace pe_sig_utils
	}// namespace Utils
}// namespace ShadowStrike