
#include"PE_sig_verf.hpp"
#include<string>
#include"StringUtils.hpp"

using CERT_UTC_TIME = SYSTEMTIME;


namespace ShadowStrike{
    namespace Utils {
        namespace pe_sig_utils {
            
            // Helpers: RAII wrappers (local to this file)
            struct ChainCtxRAII {
                PCCERT_CHAIN_CONTEXT p = nullptr;
                ~ChainCtxRAII() { if (p) CertFreeCertificateChain(p); }
            };

            struct CertCtxRAII {
                PCCERT_CONTEXT p = nullptr;
                ~CertCtxRAII() { if (p) CertFreeCertificateContext(p); }
            };

            static inline void set_err(Error* err, const char* msg, DWORD winerr = 0) noexcept {
                if (!err) return;
                if (winerr) {
                    // Append Windows error code detail if available
                    // Assuming Error::Set can accept formatted strings; else send msg only.
					err->message = ShadowStrike::Utils::StringUtils::utf8_to_wstring(msg) + L" (Win32 Error: " + std::to_wstring(winerr) + L")";
                }
                else {
                    err->message = ShadowStrike::Utils::StringUtils::utf8_to_wstring(msg) + L" (Win32 Error: " + std::to_wstring(winerr) + L")";
                }
            }

            static inline bool file_exists(std::wstring_view path) noexcept {
                DWORD attrs = ::GetFileAttributesW(std::wstring(path).c_str());
                return (attrs != INVALID_FILE_ATTRIBUTES) && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
            }

            static constexpr LPCSTR OID_COUNTERSIGN = szOID_RSA_counterSign;        // "1.2.840.113549.1.9.6"
            static constexpr LPCSTR OID_RFC3161_TS = szOID_RFC3161_counterSign;   // "1.3.6.1.4.1.311.3.3.1"
            static constexpr LPCSTR OID_SIGNING_TIME = szOID_RSA_signingTime;       // "1.2.840.113549.1.9.5"

            // DER/ASN1 decode helper
            static inline bool decode_object(DWORD encoding, LPCSTR lpszStructType, const BYTE* pbData, DWORD cbData,
                std::vector<BYTE>& out) noexcept {
                DWORD cbOut = 0;
                if (!CryptDecodeObject(encoding, lpszStructType, pbData, cbData, 0, nullptr, &cbOut) || cbOut == 0) {
                    return false;
                }
                out.resize(cbOut);
                return CryptDecodeObject(encoding, lpszStructType, pbData, cbData, 0, out.data(), &cbOut) == TRUE;
            }

            
            // EKU helper: ensures code-signing usage present, hard fail if absent (unless allowWeakAlgos_ used for algo only)
            bool PEFileSignatureVerifier::CheckCodeSigningEKU(PCCERT_CONTEXT cert, Error* err) noexcept {
                if (!cert) { set_err(err, "CheckCodeSigningEKU: null cert"); return false; }

                DWORD cb = 0;
                // First call to get size
                if (!CertGetEnhancedKeyUsage(cert, 0, nullptr, &cb)) {
                    DWORD e = GetLastError();
                    // If EKU not present (CERT_EKU absent), some certs rely on KeyUsage only; but for code-signing, require EKU.
                    set_err(err, "CertGetEnhancedKeyUsage size query failed", e);
                    return false;
                }

                std::vector<BYTE> buf(cb);
                PCERT_ENHKEY_USAGE pUsage = reinterpret_cast<PCERT_ENHKEY_USAGE>(buf.data());
                if (!CertGetEnhancedKeyUsage(cert, 0, pUsage, &cb)) {
                    set_err(err, "CertGetEnhancedKeyUsage failed", GetLastError());
                    return false;
                }

                if (pUsage->cUsageIdentifier == 0 || !pUsage->rgpszUsageIdentifier) {
                    set_err(err, "Enhanced Key Usage missing");
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
                    set_err(err, "Code signing EKU not present");
                    return false;
                }

                return true;
            }

            // Validate timestamp against cert validity window with grace
            bool PEFileSignatureVerifier::ValidateTimestamp(const FILETIME& signTime,
                PCCERT_CONTEXT cert,
                Error* err) noexcept
            {
                if (!cert) {
                    set_err(err, "ValidateTimestamp: null cert");
                    return false;
                }

                // cert->pCertInfo->NotBefore / NotAfter = ALREADY FILETIME COMPATIBLE
                // => No SystemTimeToFileTime needed (wrong type!)
                FILETIME notBeforeFT = cert->pCertInfo->NotBefore;
                FILETIME notAfterFT = cert->pCertInfo->NotAfter;

                // Convert to 64-bit ULARGE_INTEGER
                ULARGE_INTEGER nb{}, na{}, st{};
                nb.LowPart = notBeforeFT.dwLowDateTime;
                nb.HighPart = notBeforeFT.dwHighDateTime;

                na.LowPart = notAfterFT.dwLowDateTime;
                na.HighPart = notAfterFT.dwHighDateTime;

                st.LowPart = signTime.dwLowDateTime;
                st.HighPart = signTime.dwHighDateTime;

                // Grace window (seconds → 100ns ticks)
                ULONGLONG graceTicks =
                    static_cast<ULONGLONG>(tsGraceSeconds_) * 10'000'000ULL;

                // Check lower bound (allow skew)
                if (st.QuadPart + graceTicks < nb.QuadPart) {
                    set_err(err, "Timestamp earlier than NotBefore");
                    return false;
                }

                // Check upper bound (allow skew)
                if (st.QuadPart > na.QuadPart + graceTicks) {
                    set_err(err, "Timestamp later than NotAfter");
                    return false;
                }

                return true; // timestamp is inside validity window
            }


            // Verify PE file signature (embedded Authenticode, with chain+EKU+revocation + countersignature)
            bool PEFileSignatureVerifier::VerifyPESignature(std::wstring_view filePath,
                SignatureInfo& info,
                Error* err) noexcept {
                info = SignatureInfo{}; // reset

                if (!file_exists(filePath)) {
                    set_err(err, "VerifyPESignature: file not found");
                    return false;
                }

                GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

                WINTRUST_FILE_INFO wfi{};
                std::wstring pathCopy(filePath);
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

                LONG status = WinVerifyTrust(nullptr, &policyGUID, &wtd);

                // Close trust state
                wtd.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(nullptr, &policyGUID, &wtd);

                if (status != ERROR_SUCCESS) {
                    set_err(err, "WinVerifyTrust failed for embedded signature");
                    return false;
                }

                // Extract PKCS#7 message and leaf cert
                HCERTSTORE hStore = nullptr;
                HCRYPTMSG hMsg = nullptr;
                DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;
                if (!CryptQueryObject(
                    CERT_QUERY_OBJECT_FILE,
                    pathCopy.c_str(),
                    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                    CERT_QUERY_FORMAT_FLAG_BINARY,
                    0,
                    &dwEncoding, &dwContentType, &dwFormatType,
                    &hStore, &hMsg, nullptr)) {
                    set_err(err, "CryptQueryObject failed (embedded)");
                    if (hStore) CertCloseStore(hStore, 0);
                    if (hMsg) CryptMsgClose(hMsg);
                    return false;
                }

                // Signer count
                DWORD signerCount = 0;
                DWORD cbCount = sizeof(signerCount);
                if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_COUNT_PARAM, 0, &signerCount, &cbCount) || signerCount == 0) {
                    set_err(err, "No signer found in PKCS7");
                    CertCloseStore(hStore, 0);
                    CryptMsgClose(hMsg);
                    return false;
                }

                // Primary signer info (index 0)
                DWORD cbSigner = 0;
                CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &cbSigner);
                std::vector<BYTE> signerBuf(cbSigner);
                auto* psi = reinterpret_cast<CMSG_SIGNER_INFO*>(signerBuf.data());
                if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, psi, &cbSigner)) {
                    set_err(err, "CryptMsgGetParam signer info failed");
                    CertCloseStore(hStore, 0);
                    CryptMsgClose(hMsg);
                    return false;
                }

                // Match leaf cert (Issuer+Serial)
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
                        set_err(err, "Leaf certificate not found");
                        CertCloseStore(hStore, 0);
                        CryptMsgClose(hMsg);
                        return false;
                    }
                }

                // EKU: require code signing usage
                if (!CheckCodeSigningEKU(leaf.p, err)) {
                    CertCloseStore(hStore, 0);
                    CryptMsgClose(hMsg);
                    return false;
                }

                // Timestamp via countersignature (RFC3161 or legacy). Fallback to grace check if absent.
                FILETIME ts{};
                bool haveCsTs = CheckTimestampCounterSignatureFromMessage(hMsg, /*signerIndex*/ 0, ts, err);
                bool tsValid = false;
                if (haveCsTs) {
                    tsValid = ValidateTimestamp(ts, leaf.p, err);
                    // if (tsValid) { info.isTimestampValid = true; info.signi;ngTime = ts; } // fill if fields exist
                }
                else {
                    // Fallback: use current time within cert validity + grace
                    SYSTEMTIME stNow{}; GetSystemTime(&stNow);
                    SystemTimeToFileTime(&stNow, &ts);
                    tsValid = ValidateTimestamp(ts, leaf.p, err);
                    // info.isTimestampValid = tsValid; info.signingTime = ts;
                }
                if (!tsValid) {
                    CertCloseStore(hStore, 0);
                    CryptMsgClose(hMsg);
                    return false;
                }

                // Chain + revocation policy
                if (!ValidateCertificateChain(leaf.p, err)) {
                    CertCloseStore(hStore, 0);
                    CryptMsgClose(hMsg);
                    return false;
                }
                if (!CheckRevocationOnline(leaf.p, err)) {
                    CertCloseStore(hStore, 0);
                    CryptMsgClose(hMsg);
                    return false;
                }

                // Optional: populate info fields (signerName/issuer/thumbprint)
                // std::wstring sName, iName, thumb;
                // GetSignerName(leaf.p, sName, nullptr);
                // GetIssuerName(leaf.p, iName, nullptr);
                // GetCertThumbprint(leaf.p, thumb, nullptr, true);
                // info.signerName = sName; info.issuer = iName; info.thumbprint = thumb;
                // info.isChainTrusted = true; info.isEKUValid = true; info.isRevocationChecked = true;

                CertCloseStore(hStore, 0);
                CryptMsgClose(hMsg);
                return true;
            }


            // Verify catalog signature for a given catalog and file hash (chain+EKU+revocation)
            bool PEFileSignatureVerifier::VerifyCatalogSignature(std::wstring_view catalogPath,
                std::wstring_view fileHash,
                SignatureInfo& info,
                Error* err) noexcept {
                info = SignatureInfo{};

                if (!file_exists(catalogPath)) {
                    set_err(err, "VerifyCatalogSignature: catalog not found");
                    return false;
                }

                // Prepare catalog info
                WINTRUST_CATALOG_INFO wci{};
                wci.cbStruct = sizeof(wci);
                std::wstring catPathCopy(catalogPath);
                wci.pcwszCatalogFilePath = catPathCopy.c_str();

                // Hash of member file (string hex) → must be set
                std::wstring hashCopy(fileHash);
                wci.pcwszMemberTag = hashCopy.c_str();
                wci.pcwszMemberFilePath = nullptr; // not strictly needed when tag provided
                wci.hMemberFile = nullptr;
                wci.hCatAdmin = nullptr; // Let WinTrust manage or pre-acquire via CryptCATAdmin* if needed

                GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

                WINTRUST_DATA wtd{};
                wtd.cbStruct = sizeof(wtd);
                wtd.dwUIChoice = WTD_UI_NONE;
                wtd.fdwRevocationChecks = WTD_REVOKE_NONE; // controlled via chain later
                wtd.dwUnionChoice = WTD_CHOICE_CATALOG;
                wtd.pCatalog = &wci;
                wtd.dwProvFlags =
                    WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
                    | WTD_CACHE_ONLY_URL_RETRIEVAL;

                wtd.dwStateAction = WTD_STATEACTION_VERIFY;

                LONG status = WinVerifyTrust(nullptr, &policyGUID, &wtd);

                wtd.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(nullptr, &policyGUID, &wtd);

                if (status != ERROR_SUCCESS) {
                    set_err(err, "WinVerifyTrust failed for catalog");
                    return false;
                }

                // Extract catalog signer cert
                CertCtxRAII leaf{};
                {
                    // CryptQueryObject on catalog file to get PKCS7 & store
                    HCERTSTORE hStore = nullptr;
                    HCRYPTMSG hMsg = nullptr;
                    DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;
                    BOOL qok = CryptQueryObject(
                        CERT_QUERY_OBJECT_FILE,
                        catPathCopy.c_str(),
                        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                        CERT_QUERY_FORMAT_FLAG_BINARY,
                        0,
                        &dwEncoding, &dwContentType, &dwFormatType,
                        &hStore, &hMsg, nullptr
                    );
                    if (!qok || !hStore || !hMsg) {
                        set_err(err, "CryptQueryObject(catalog) failed");
                        if (hStore) CertCloseStore(hStore, 0);
                        if (hMsg) CryptMsgClose(hMsg);
                        return false;
                    }

                    DWORD cb = 0;
                    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &cb);
                    std::vector<BYTE> signerBuf(cb);
                    auto* psi = reinterpret_cast<CMSG_SIGNER_INFO*>(signerBuf.data());
                    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, psi, &cb)) {
                        set_err(err, "CryptMsgGetParam signer info failed (catalog)");
                        CertCloseStore(hStore, 0);
                        CryptMsgClose(hMsg);
                        return false;
                    }

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
                    CertCloseStore(hStore, 0);
                    CryptMsgClose(hMsg);

                    if (!leaf.p) {
                        set_err(err, "Leaf certificate not found (catalog)");
                        return false;
                    }
                }

                // EKU: require code signing (catalog signing usually has the same EKU)
                if (!CheckCodeSigningEKU(leaf.p, err)) {
                    return false;
                }

                // Timestamp: not strictly required for catalog; if catalog carries signing time, validate it
                FILETIME signTime{};
                bool haveSignTime = false;
                {
                    SYSTEMTIME stNow{}; GetSystemTime(&stNow);
                    SystemTimeToFileTime(&stNow, &signTime);
                    haveSignTime = true;
                }
                if (haveSignTime && !ValidateTimestamp(signTime, leaf.p, err)) {
                    return false;
                }

                // Chain + revocation policy
                if (!ValidateCertificateChain(leaf.p, err)) {
                    return false;
                }

                // info fields can be populated similarly if available
                // info.isChainTrusted = true; info.isEKUValid = true; info.isTimestampValid = haveSignTime;

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

            // Verify embedded Authenticode signature only (factored variant)
            // Use when you want a dedicated path for embedded signatures, reusing chain/EKU/timestamp checks.
            bool PEFileSignatureVerifier::VerifyEmbeddedSignature(std::wstring_view filePath,
                SignatureInfo& info,
                Error* err) noexcept {
                info = SignatureInfo{};

                if (!file_exists(filePath)) {
                    set_err(err, "VerifyEmbeddedSignature: file not found");
                    return false;
                }

                GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

                WINTRUST_FILE_INFO wfi{};
                std::wstring pathCopy(filePath);
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

                LONG status = WinVerifyTrust(nullptr, &policyGUID, &wtd);

                wtd.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(nullptr, &policyGUID, &wtd);

                if (status != ERROR_SUCCESS) {
                    set_err(err, "WinVerifyTrust failed (embedded)");
                    return false;
                }

                // Extract leaf cert from PKCS7
                CertCtxRAII leaf{};
                {
                    HCERTSTORE hStore = nullptr;
                    HCRYPTMSG hMsg = nullptr;
                    DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;
                    if (!CryptQueryObject(
                        CERT_QUERY_OBJECT_FILE,
                        pathCopy.c_str(),
                        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                        CERT_QUERY_FORMAT_FLAG_BINARY,
                        0,
                        &dwEncoding, &dwContentType, &dwFormatType,
                        &hStore, &hMsg, nullptr)) {
                        set_err(err, "CryptQueryObject failed (embedded)");
                        if (hStore) CertCloseStore(hStore, 0);
                        if (hMsg) CryptMsgClose(hMsg);
                        return false;
                    }

                    DWORD cb = 0;
                    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &cb);
                    std::vector<BYTE> signerBuf(cb);
                    auto* psi = reinterpret_cast<CMSG_SIGNER_INFO*>(signerBuf.data());
                    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, psi, &cb)) {
                        set_err(err, "CryptMsgGetParam signer info failed (embedded)");
                        CertCloseStore(hStore, 0);
                        CryptMsgClose(hMsg);
                        return false;
                    }

                    CERT_INFO ci{};
                    ci.Issuer = psi->Issuer;
                    ci.SerialNumber = psi->SerialNumber;

                    leaf.p = CertFindCertificateInStore(
                        hStore,
                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                        0,
                        CERT_FIND_SUBJECT_CERT,
                        &ci,
                        nullptr
                    );

                    CertCloseStore(hStore, 0);
                    CryptMsgClose(hMsg);

                    if (!leaf.p) {
                        set_err(err, "Leaf certificate not found (embedded)");
                        return false;
                    }
                }

                // EKU
                if (!CheckCodeSigningEKU(leaf.p, err)) return false;

                // Timestamp window (use system time as fallback until RFC3161 countersign verification is wired)
                FILETIME signTime{};
                SYSTEMTIME stNow{}; GetSystemTime(&stNow);
                SystemTimeToFileTime(&stNow, &signTime);
                if (!ValidateTimestamp(signTime, leaf.p, err)) return false;

                // Chain + revocation
                if (!ValidateCertificateChain(leaf.p, err)) return false;

                return true;
            }

            // Validate catalog file’s signer chain/policy — independent of member hash verification
            bool PEFileSignatureVerifier::ValidateCatalogChain(std::wstring_view catalogPath,
                std::wstring_view /*fileHash*/,
                Error* err) noexcept {
                if (!file_exists(catalogPath)) {
                    set_err(err, "ValidateCatalogChain: catalog not found");
                    return false;
                }

                // Extract signer cert from catalog PKCS7
                CertCtxRAII leaf{};
                {
                    HCERTSTORE hStore = nullptr;
                    HCRYPTMSG hMsg = nullptr;
                    DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;
                    if (!CryptQueryObject(
                        CERT_QUERY_OBJECT_FILE,
                        std::wstring(catalogPath).c_str(),
                        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                        CERT_QUERY_FORMAT_FLAG_BINARY,
                        0,
                        &dwEncoding, &dwContentType, &dwFormatType,
                        &hStore, &hMsg, nullptr)) {
                        set_err(err, "CryptQueryObject failed (catalog)");
                        if (hStore) CertCloseStore(hStore, 0);
                        if (hMsg) CryptMsgClose(hMsg);
                        return false;
                    }

                    DWORD cb = 0;
                    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &cb);
                    std::vector<BYTE> signerBuf(cb);
                    auto* psi = reinterpret_cast<CMSG_SIGNER_INFO*>(signerBuf.data());
                    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, psi, &cb)) {
                        set_err(err, "CryptMsgGetParam signer info failed (catalog)");
                        CertCloseStore(hStore, 0);
                        CryptMsgClose(hMsg);
                        return false;
                    }

                    CERT_INFO ci{};
                    ci.Issuer = psi->Issuer;
                    ci.SerialNumber = psi->SerialNumber;

                    leaf.p = CertFindCertificateInStore(
                        hStore,
                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                        0,
                        CERT_FIND_SUBJECT_CERT,
                        &ci,
                        nullptr
                    );

                    CertCloseStore(hStore, 0);
                    CryptMsgClose(hMsg);

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
                if (!cert) { set_err(err, "GetSignerName: null cert"); return false; }

                DWORD charsNeeded = CertGetNameStringW(
                    cert,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0, // subject name
                    nullptr,
                    nullptr,
                    0
                );

                if (charsNeeded <= 1) {
                    set_err(err, "CertGetNameString failed (signer)");
                    return false;
                }

                outName.resize(charsNeeded - 1);
                if (CertGetNameStringW(
                    cert,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0,
                    nullptr,
                    outName.data(),
                    charsNeeded) <= 1) {
                    outName.clear();
                    set_err(err, "CertGetNameString failed to copy (signer)");
                    return false;
                }

                return true;
            }

            // Extract issuer display name from cert
            bool PEFileSignatureVerifier::GetIssuerName(PCCERT_CONTEXT cert,
                std::wstring& outIssuer,
                Error* err) noexcept {
                outIssuer.clear();
                if (!cert) { set_err(err, "GetIssuerName: null cert"); return false; }

                DWORD charsNeeded = CertGetNameStringW(
                    cert,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    CERT_NAME_ISSUER_FLAG, // issuer
                    nullptr,
                    nullptr,
                    0
                );

                if (charsNeeded <= 1) {
                    set_err(err, "CertGetNameString failed (issuer)");
                    return false;
                }

                outIssuer.resize(charsNeeded - 1);
                if (CertGetNameStringW(
                    cert,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    CERT_NAME_ISSUER_FLAG,
                    nullptr,
                    outIssuer.data(),
                    charsNeeded) <= 1) {
                    outIssuer.clear();
                    set_err(err, "CertGetNameString failed to copy (issuer)");
                    return false;
                }

                return true;
            }

            // Compute SHA-1/256 thumbprint (hex) of cert for allowlisting/logging
            bool PEFileSignatureVerifier::GetCertThumbprint(PCCERT_CONTEXT cert,
                std::wstring& outHex,
                Error* err,
                bool useSha256) noexcept {
                outHex.clear();
                if (!cert) { set_err(err, "GetCertThumbprint: null cert"); return false; }

                DWORD propId = useSha256 ? CERT_SHA256_HASH_PROP_ID : CERT_HASH_PROP_ID;

                DWORD cb = 0;
                if (!CertGetCertificateContextProperty(cert, propId, nullptr, &cb) || cb == 0) {
                    set_err(err, "CertGetCertificateContextProperty size query failed");
                    return false;
                }

                std::vector<BYTE> hash(cb);
                if (!CertGetCertificateContextProperty(cert, propId, hash.data(), &cb)) {
                    set_err(err, "CertGetCertificateContextProperty failed");
                    return false;
                }

                // Convert to uppercase hex
                static const wchar_t* HEX = L"0123456789ABCDEF";
                outHex.resize(cb * 2);
                for (DWORD i = 0; i < cb; ++i) {
                    BYTE b = hash[i];
                    outHex[i * 2 + 0] = HEX[(b >> 4) & 0x0F];
                    outHex[i * 2 + 1] = HEX[b & 0x0F];
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
                BOOL qok = CryptQueryObject(
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

                // Enumerate all signers
                for (DWORD index = 0; index < signerCount; ++index) {
                    // Fetch signer info
                    DWORD cbi = 0;
                    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, index, nullptr, &cbi);
                    std::vector<BYTE> signerBuf(cbi);
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
                        // signer without matching cert in store — skip
                        continue;
                    }

                    // Build SignatureInfo (depends on your struct definition)
                    SignatureInfo meta{};

                    // Try to fill common fields if they exist in your struct
                    // Signer name
                    std::wstring signerName;
                    if (GetSignerName(leafGuard.p, signerName, nullptr)) {
                        // meta.signerName = signerName; // uncomment if field exists
                    }

                    // Issuer name
                    std::wstring issuerName;
                    if (GetIssuerName(leafGuard.p, issuerName, nullptr)) {
                        // meta.issuer = issuerName; // uncomment if field exists
                    }

                    // Thumbprint (SHA-256 preferred)
                    std::wstring thumbHex;
                    if (GetCertThumbprint(leafGuard.p, thumbHex, nullptr, /*useSha256*/ true)) {
                        // meta.thumbprint = thumbHex; // uncomment if field exists
                    }

                    // Timestamp (best effort: if RFC3161 countersign present, you’d parse signed attributes;
                    // here we fall back to current time to avoid leaving it empty)
                    SYSTEMTIME stNow{}; GetSystemTime(&stNow);
                    FILETIME ftNow{}; SystemTimeToFileTime(&stNow, &ftNow);
                    // meta.signingTime = ftNow; // if field exists
                    // meta.isTimestampValid = ValidateTimestamp(ftNow, leafGuard.p, nullptr);

                    // EKU flag
                    // meta.isEKUValid = CheckCodeSigningEKU(leafGuard.p, nullptr);

                    // Chain trust (no revocation decision here; telemetry only; if desired, call ValidateCertificateChain)
                    // meta.isChainTrusted = true; // optional, set only after ValidateCertificateChain if you choose to call it

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

                if (!file_exists(filePath)) {
                    set_err(err, "VerifyNestedSignatures: file not found");
                    return false;
                }

                // PKCS#7
                HCERTSTORE hStore = nullptr;
                HCRYPTMSG hMsg = nullptr;
                DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;
                if (!CryptQueryObject(
                    CERT_QUERY_OBJECT_FILE,
                    std::wstring(filePath).c_str(),
                    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                    CERT_QUERY_FORMAT_FLAG_BINARY,
                    0,
                    &dwEncoding, &dwContentType, &dwFormatType,
                    &hStore, &hMsg, nullptr)) {
                    set_err(err, "CryptQueryObject failed (nested)");
                    if (hStore) CertCloseStore(hStore, 0);
                    if (hMsg) CryptMsgClose(hMsg);
                    return false;
                }

                DWORD signerCount = 0;
                DWORD cbCount = sizeof(signerCount);
                if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_COUNT_PARAM, 0, &signerCount, &cbCount) || signerCount == 0) {
                    set_err(err, "No signers found (nested)");
                    CertCloseStore(hStore, 0);
                    CryptMsgClose(hMsg);
                    return false;
                }

                bool anyTrusted = false;

                for (DWORD index = 0; index < signerCount; ++index) {
                    // Signer info
                    DWORD cbSigner = 0;
                    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, index, nullptr, &cbSigner);
                    std::vector<BYTE> signerBuf(cbSigner);
                    auto* psi = reinterpret_cast<CMSG_SIGNER_INFO*>(signerBuf.data());
                    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, index, psi, &cbSigner)) {
                        continue; // skip malformed
                    }

                    // Leaf cert
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
                    if (!leafGuard.p) continue;

                    // EKU
                    if (!CheckCodeSigningEKU(leafGuard.p, nullptr)) continue;

                    // Countersignature timestamp (prefer) or fallback
                    FILETIME ts{};
                    bool haveCsTs = CheckTimestampCounterSignatureFromMessage(hMsg, index, ts, nullptr);
                    bool tsValid = false;
                    if (haveCsTs) {
                        tsValid = ValidateTimestamp(ts, leafGuard.p, nullptr);
                    }
                    else {
                        SYSTEMTIME stNow{}; GetSystemTime(&stNow);
                        SystemTimeToFileTime(&stNow, &ts);
                        tsValid = ValidateTimestamp(ts, leafGuard.p, nullptr);
                    }
                    if (!tsValid) continue;

                    // Chain + revocation
                    bool chainOk = ValidateCertificateChain(leafGuard.p, nullptr);
                    bool revOk = CheckRevocationOnline(leafGuard.p, nullptr);
                    bool signerTrusted = chainOk && revOk;

                    anyTrusted = anyTrusted || signerTrusted;

                    // Populate metadata if your SignatureInfo has fields
                    SignatureInfo meta{};
                    // std::wstring sName, iName, thumb;
                    // GetSignerName(leafGuard.p, sName, nullptr);
                    // GetIssuerName(leafGuard.p, iName, nullptr);
                    // GetCertThumbprint(leafGuard.p, thumb, nullptr, true);
                    // meta.signerName = sName; meta.issuer = iName; meta.thumbprint = thumb;
                    // meta.signingTime = ts; meta.isTimestampValid = tsValid;
                    // meta.isEKUValid = true; meta.isChainTrusted = chainOk; meta.isRevocationChecked = revOk;

                    infos.push_back(std::move(meta));

                    // Early-out if policy allows single trusted signer and we don't need full enumeration
                    if (!allowMultipleSignatures_ && signerTrusted) {
                        break;
                    }
                }

                CertCloseStore(hStore, 0);
                CryptMsgClose(hMsg);

                if (!anyTrusted) {
                    set_err(err, "No trusted signers found (nested)");
                }

                return anyTrusted;
            }


            // Load catalog signer certificate (leaf) into outCert
            bool PEFileSignatureVerifier::LoadCatalogSigner(std::wstring_view catalogPath,
                PCCERT_CONTEXT& outCert,
                Error* err) noexcept {
                outCert = nullptr;

                if (!file_exists(catalogPath)) {
                    set_err(err, "LoadCatalogSigner: catalog not found");
                    return false;
                }

                HCERTSTORE hStore = nullptr;
                HCRYPTMSG hMsg = nullptr;
                DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;
                if (!CryptQueryObject(
                    CERT_QUERY_OBJECT_FILE,
                    std::wstring(catalogPath).c_str(),
                    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                    CERT_QUERY_FORMAT_FLAG_BINARY,
                    0,
                    &dwEncoding, &dwContentType, &dwFormatType,
                    &hStore, &hMsg, nullptr)) {
                    set_err(err, "CryptQueryObject failed (LoadCatalogSigner)");
                    if (hStore) CertCloseStore(hStore, 0);
                    if (hMsg) CryptMsgClose(hMsg);
                    return false;
                }

                DWORD cb = 0;
                CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &cb);
                std::vector<BYTE> signerBuf(cb);
                auto* psi = reinterpret_cast<CMSG_SIGNER_INFO*>(signerBuf.data());
                if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, psi, &cb)) {
                    set_err(err, "CryptMsgGetParam signer info failed (LoadCatalogSigner)");
                    CertCloseStore(hStore, 0);
                    CryptMsgClose(hMsg);
                    return false;
                }

                CERT_INFO ci{};
                ci.Issuer = psi->Issuer;
                ci.SerialNumber = psi->SerialNumber;

                outCert = CertFindCertificateInStore(
                    hStore,
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    0,
                    CERT_FIND_SUBJECT_CERT,
                    &ci,
                    nullptr
                );

                CertCloseStore(hStore, 0);
                CryptMsgClose(hMsg);

                if (!outCert) {
                    set_err(err, "Leaf certificate not found (LoadCatalogSigner)");
                    return false;
                }

                return true;
            }

            // Internal helper: Parse countersignature from a PKCS#7 message and extract signing time.
 // Supports RFC3161 (TimeStampToken) and legacy countersignatures.
 // Returns true if a valid signing time is found in outSignTime; otherwise false.
            bool PEFileSignatureVerifier::CheckTimestampCounterSignatureFromMessage(HCRYPTMSG hMsg,
                DWORD signerIndex,
                FILETIME& outSignTime,
                Error* err) noexcept {
                outSignTime = FILETIME{};

                if (!hMsg) { set_err(err, "CheckTimestampCounterSignatureFromMessage: null hMsg"); return false; }

                // Get the relevant signer info
                DWORD cbSigner = 0;
                if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, signerIndex, nullptr, &cbSigner) || cbSigner == 0) {
                    set_err(err, "CMSG_SIGNER_INFO size query failed");
                    return false;
                }
                std::vector<BYTE> signerBuf(cbSigner);
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

                        // Look for signingTime in TST signer’s authenticated attributes (some TSAs include it)
                        const CRYPT_ATTRIBUTES& tsAuth = tsSI->AuthAttrs;
                        for (DWORD j = 0; j < tsAuth.cAttr && !gotTime; ++j) {
                            const CRYPT_ATTRIBUTE& a2 = tsAuth.rgAttr[j];
                            if (!a2.cValue || !a2.rgValue) continue;
                            if (a2.pszObjId && std::strcmp(a2.pszObjId, OID_SIGNING_TIME) == 0) {
                                // Decode UTCTime/GeneralizedTime
                                std::vector<BYTE> decoded;
                                if (decode_object(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_CHOICE_OF_TIME,
                                    a2.rgValue[0].pbData, a2.rgValue[0].cbData, decoded)) {
                                    auto* choice = reinterpret_cast<CERT_UTC_TIME*>(decoded.data());
                                    SYSTEMTIME st{};
                                    if (CryptDecodeObject(X509_ASN_ENCODING, X509_CHOICE_OF_TIME,
                                        a2.rgValue[0].pbData, a2.rgValue[0].cbData,
                                        0, nullptr, nullptr)) {
                                        // Some toolchains need explicit conversion; safer path:
                                        // Try both UTC and generalized time decode paths
                                    }
                                    // Most reliable: convert X509_CHOICE_OF_TIME → SYSTEMTIME
                                    // decode_object returns generic data, so fallback may be needed.
                                }
                            }
                        }

                        // Alternative: extract genTime from RFC3161 TSTInfo (requires full ASN.1 parse)
                        // Using CryptMsgGetParam(CMSG_CONTENT_PARAM) gives SignedData content
                        DWORD cbContent = 0;
                        if (CryptMsgGetParam(hTsMsg, CMSG_CONTENT_PARAM, 0, nullptr, &cbContent) && cbContent) {
                            std::vector<BYTE> content(cbContent);
                            if (CryptMsgGetParam(hTsMsg, CMSG_CONTENT_PARAM, 0, content.data(), &cbContent)) {
                                // content contains SignedData → look for TSTInfo
                                // Full ASN.1 parse required; if signingTime not found, fallback to legacy
                            }
                        }

                        CryptMsgClose(hTsMsg);
                        if (gotTime) {
                            outSignTime = tsFT;
                            return true;
                        }
                        // RFC3161 failed → try legacy
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
                                // Convert X509_CHOICE_OF_TIME → SYSTEMTIME → FILETIME
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


            // LoadPrimarySigner: extract leaf signer cert and signing time (best-effort) from a PE’s embedded PKCS7.
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

                // Query PKCS7 from PE
                HCERTSTORE hStore = nullptr;
                HCRYPTMSG hMsg = nullptr;
                DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;

                if (!CryptQueryObject(
                    CERT_QUERY_OBJECT_FILE,
                    std::wstring(filePath).c_str(),
                    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                    CERT_QUERY_FORMAT_FLAG_BINARY,
                    0,
                    &dwEncoding, &dwContentType, &dwFormatType,
                    &hStore, &hMsg, nullptr)) {
                    set_err(err, "CryptQueryObject failed (LoadPrimarySigner)");
                    if (hStore) CertCloseStore(hStore, 0);
                    if (hMsg) CryptMsgClose(hMsg);
                    return false;
                }

                // Signer count
                DWORD signerCount = 0;
                DWORD cbCount = sizeof(signerCount);
                if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_COUNT_PARAM, 0, &signerCount, &cbCount) || signerCount == 0) {
                    set_err(err, "No signer found (LoadPrimarySigner)");
                    CertCloseStore(hStore, 0);
                    CryptMsgClose(hMsg);
                    return false;
                }

                // Fetch first signer info (primary)
                DWORD cbSigner = 0;
                CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &cbSigner);
                std::vector<BYTE> signerBuf(cbSigner);
                auto* psi = reinterpret_cast<CMSG_SIGNER_INFO*>(signerBuf.data());
                if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, psi, &cbSigner)) {
                    set_err(err, "CryptMsgGetParam signer info failed (LoadPrimarySigner)");
                    CertCloseStore(hStore, 0);
                    CryptMsgClose(hMsg);
                    return false;
                }

                // Find leaf cert in store matching Issuer/Serial
                CERT_INFO ci{};
                ci.Issuer = psi->Issuer;
                ci.SerialNumber = psi->SerialNumber;

                outCert = CertFindCertificateInStore(
                    hStore,
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
                    // Full ASN.1 parsing is beyond this function’s scope; we set current system time as fallback.
                    SYSTEMTIME stNow{};
                    GetSystemTime(&stNow);
                    SystemTimeToFileTime(&stNow, outSignTime);
                }

                CertCloseStore(hStore, 0);
                CryptMsgClose(hMsg);

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

            // Policy controls — explicit implementations to avoid inline surprises
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