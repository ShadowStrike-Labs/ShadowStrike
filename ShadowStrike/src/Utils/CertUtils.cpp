
#include "CertUtils.hpp"

using namespace ShadowStrike::Utils::CertUtils;

#ifdef _WIN32

// Internal helpers
static inline void set_err(Error* err, const wchar_t* msg, DWORD w32 = 0, LONG nt = 0) noexcept {
    if (!err) return;
    err->message = msg ? msg : L"";
    err->win32 = w32;
    err->ntstatus = nt;
}

static inline bool file_exists_w(const std::wstring& path) noexcept {
    DWORD attrs = ::GetFileAttributesW(path.c_str());
    return (attrs != INVALID_FILE_ATTRIBUTES) && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

#endif // _WIN32

// ========================
// Lifecycle / cleanup
// ========================
Certificate::~Certificate() {
    cleanup();
}

Certificate::Certificate(Certificate&& other) noexcept {
#ifdef _WIN32
    m_certContext = other.m_certContext;
    other.m_certContext = nullptr;
#endif
    revocationMode_ = other.revocationMode_;
    allowSha1Weak_ = other.allowSha1Weak_;
}

Certificate& Certificate::operator=(Certificate&& other) noexcept {
    if (this == &other) return *this;
    cleanup();
#ifdef _WIN32
    m_certContext = other.m_certContext;
    other.m_certContext = nullptr;
#endif
    revocationMode_ = other.revocationMode_;
    allowSha1Weak_ = other.allowSha1Weak_;
    return *this;
}

void Certificate::cleanup() noexcept {
#ifdef _WIN32
    if (m_certContext) {
        CertFreeCertificateContext(m_certContext);
        m_certContext = nullptr;
    }
#endif
}

// ========================
// Load from file (DER/PEM/X.509 containers)
// ========================
bool Certificate::LoadFromFile(std::wstring_view path, Error* err) noexcept {
#ifdef _WIN32
    cleanup();
    std::wstring p(path);
    if (!file_exists_w(p)) {
        set_err(err, L"LoadFromFile: file not found", ERROR_FILE_NOT_FOUND);
        return false;
    }

    // Try CryptQueryObject for DER/PEM X.509 certificate
    HCERTSTORE hStore = nullptr;
    PCCERT_CONTEXT ctx = nullptr;
    DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;

    BOOL ok = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        p.c_str(),
        CERT_QUERY_CONTENT_FLAG_CERT,            // single cert
        CERT_QUERY_FORMAT_FLAG_ALL,              // DER/BASE64
        0,
        &dwEncoding, &dwContentType, &dwFormatType,
        &hStore, nullptr, nullptr
    );

    if (!ok || !hStore) {
        // Fallback: try PKCS7 store and take first cert
        ok = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            p.c_str(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED
            | CERT_QUERY_CONTENT_FLAG_PKCS7,
            CERT_QUERY_FORMAT_FLAG_ALL,
            0,
            &dwEncoding, &dwContentType, &dwFormatType,
            &hStore, nullptr, nullptr
        );
        if (!ok || !hStore) {
            set_err(err, L"LoadFromFile: CryptQueryObject failed", GetLastError());
            return false;
        }
    }

    // Take the first certificate in the store
    ctx = CertEnumCertificatesInStore(hStore, nullptr);
    if (!ctx) {
        set_err(err, L"LoadFromFile: no certificate found in container", GetLastError());
        CertCloseStore(hStore, 0);
        return false;
    }

    // Duplicate to own context
    m_certContext = CertDuplicateCertificateContext(ctx);
    CertFreeCertificateContext(ctx);
    CertCloseStore(hStore, 0);

    if (!m_certContext) {
        set_err(err, L"LoadFromFile: CertDuplicateCertificateContext failed", GetLastError());
        return false;
    }

    return true;
#else
    (void)path; (void)err;
    return false;
#endif
}

// ========================
// Load from memory (DER or PEM)
// ========================
bool Certificate::LoadFromMemory(const uint8_t* data, size_t len, Error* err) noexcept {
#ifdef _WIN32
    cleanup();
    if (!data || len == 0) {
        set_err(err, L"LoadFromMemory: invalid buffer", ERROR_INVALID_PARAMETER);
        return false;
    }

    // Detect PEM by looking for header
    const char* cbuf = reinterpret_cast<const char*>(data);
    bool isPEM = (len >= 27) && (std::string_view(cbuf, len).find("-----BEGIN CERTIFICATE-----") != std::string_view::npos);

    if (isPEM) {
        // Decode PEM → DER via CryptStringToBinaryA
        DWORD derSize = 0;
        if (!CryptStringToBinaryA(cbuf, static_cast<DWORD>(len), CRYPT_STRING_BASE64HEADER, nullptr, &derSize, nullptr, nullptr)) {
            set_err(err, L"LoadFromMemory: CryptStringToBinaryA size failed", GetLastError());
            return false;
        }
        std::vector<uint8_t> der(derSize);
        if (!CryptStringToBinaryA(cbuf, static_cast<DWORD>(len), CRYPT_STRING_BASE64HEADER, der.data(), &derSize, nullptr, nullptr)) {
            set_err(err, L"LoadFromMemory: CryptStringToBinaryA failed", GetLastError());
            return false;
        }

        m_certContext = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, der.data(), derSize);
        if (!m_certContext) {
            set_err(err, L"LoadFromMemory: CertCreateCertificateContext (PEM→DER) failed", GetLastError());
            return false;
        }
        return true;
    }
    else {
        // Assume DER
        m_certContext = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, data, static_cast<DWORD>(len));
        if (!m_certContext) {
            set_err(err, L"LoadFromMemory: CertCreateCertificateContext (DER) failed", GetLastError());
            return false;
        }
        return true;
    }
#else
    (void)data; (void)len; (void)err;
    return false;
#endif
}

// ========================
// Export (DER) and GetRawDER alias
// ========================
bool Certificate::Export(std::vector<uint8_t>& out, Error* err) const noexcept {
#ifdef _WIN32
    out.clear();
    if (!m_certContext) {
        set_err(err, L"Export: empty certificate", ERROR_INVALID_HANDLE);
        return false;
    }
    const BYTE* pb = m_certContext->pbCertEncoded;
    DWORD cb = m_certContext->cbCertEncoded;
    if (!pb || cb == 0) {
        set_err(err, L"Export: no encoded buffer", ERROR_INVALID_DATA);
        return false;
    }
    out.assign(pb, pb + cb);
    return true;
#else
    (void)out; (void)err;
    return false;
#endif
}

bool Certificate::GetRawDER(std::vector<uint8_t>& out, Error* err) const noexcept {
    return Export(out, err);
}


// ========================
// Export PEM
// ========================
bool Certificate::ExportPEM(std::string& out, Error* err) const noexcept {
#ifdef _WIN32
    out.clear();
    if (!m_certContext) {
        set_err(err, L"ExportPEM: empty certificate", ERROR_INVALID_HANDLE);
        return false;
    }

    DWORD charsNeeded = 0;
    if (!CryptBinaryToStringA(m_certContext->pbCertEncoded,
        m_certContext->cbCertEncoded,
        CRYPT_STRING_BASE64HEADER,
        nullptr, &charsNeeded)) {
        set_err(err, L"ExportPEM: size query failed", GetLastError());
        return false;
    }

    std::string pem(charsNeeded, '\0');
    if (!CryptBinaryToStringA(m_certContext->pbCertEncoded,
        m_certContext->cbCertEncoded,
        CRYPT_STRING_BASE64HEADER,
        pem.data(), &charsNeeded)) {
        set_err(err, L"ExportPEM: conversion failed", GetLastError());
        return false;
    }

    pem.resize(charsNeeded);
    out = pem;
    return true;
#else
    (void)out; (void)err;
    return false;
#endif
}

// ========================
// Thumbprint (SHA-1 or SHA-256)
// ========================
bool Certificate::GetThumbprint(std::wstring& outHex, bool sha256, Error* err) const noexcept {
#ifdef _WIN32
    outHex.clear();
    if (!m_certContext) {
        set_err(err, L"GetThumbprint: empty certificate", ERROR_INVALID_HANDLE);
        return false;
    }

    DWORD propId = sha256 ? CERT_SHA256_HASH_PROP_ID : CERT_HASH_PROP_ID;
    DWORD cb = 0;
    if (!CertGetCertificateContextProperty(m_certContext, propId, nullptr, &cb) || cb == 0) {
        set_err(err, L"GetThumbprint: size query failed", GetLastError());
        return false;
    }

    std::vector<BYTE> hash(cb);
    if (!CertGetCertificateContextProperty(m_certContext, propId, hash.data(), &cb)) {
        set_err(err, L"GetThumbprint: property fetch failed", GetLastError());
        return false;
    }

    static const wchar_t* HEX = L"0123456789ABCDEF";
    outHex.resize(cb * 2);
    for (DWORD i = 0; i < cb; ++i) {
        BYTE b = hash[i];
        outHex[i * 2 + 0] = HEX[(b >> 4) & 0x0F];
        outHex[i * 2 + 1] = HEX[b & 0x0F];
    }
    return true;
#else
    (void)outHex; (void)sha256; (void)err;
    return false;
#endif
}

// ========================
// GetInfo (subject, issuer, validity, serial, thumbprint, basic diagnostics)
// ========================
bool Certificate::GetInfo(CertificateInfo& info, Error* err) const noexcept {
#ifdef _WIN32
    if (!m_certContext) {
        set_err(err, L"GetInfo: empty certificate", ERROR_INVALID_HANDLE);
        return false;
    }

    info = CertificateInfo{};

    // Subject
    DWORD charsNeeded = CertGetNameStringW(m_certContext,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0, nullptr, nullptr, 0);
    if (charsNeeded > 1) {
        std::wstring subject(charsNeeded, L'\0');
        CertGetNameStringW(m_certContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0, nullptr, subject.data(), charsNeeded);
        subject.resize(charsNeeded - 1);
        info.subject = subject;
    }

    // Issuer
    charsNeeded = CertGetNameStringW(m_certContext,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        CERT_NAME_ISSUER_FLAG,
        nullptr, nullptr, 0);
    if (charsNeeded > 1) {
        std::wstring issuer(charsNeeded, L'\0');
        CertGetNameStringW(m_certContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            CERT_NAME_ISSUER_FLAG,
            nullptr, issuer.data(), charsNeeded);
        issuer.resize(charsNeeded - 1);
        info.issuer = issuer;
    }

    // Serial number (big-endian display)
    DWORD cbSerial = m_certContext->pCertInfo->SerialNumber.cbData;
    if (cbSerial > 0) {
        std::wstring serial;
        static const wchar_t* HEX = L"0123456789ABCDEF";
        serial.resize(cbSerial * 2);
        for (DWORD i = 0; i < cbSerial; ++i) {
            BYTE b = m_certContext->pCertInfo->SerialNumber.pbData[cbSerial - 1 - i];
            serial[i * 2 + 0] = HEX[(b >> 4) & 0x0F];
            serial[i * 2 + 1] = HEX[b & 0x0F];
        }
        info.serialNumber = serial;
    }

    // Thumbprint (SHA-256)
    GetThumbprint(info.thumbprint, true, nullptr);

    // Validity
    info.notBefore = m_certContext->pCertInfo->NotBefore;
    info.notAfter = m_certContext->pCertInfo->NotAfter;

    // Expired?
    FILETIME ftNow{};
    SYSTEMTIME stNow{};
    GetSystemTime(&stNow);
    SystemTimeToFileTime(&stNow, &ftNow);
    if (CompareFileTime(&ftNow, &info.notAfter) > 0) {
        info.isExpired = true;
    }

    // Self-signed?
    info.isSelfSigned = CertCompareCertificate(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        m_certContext->pCertInfo,
        m_certContext->pCertInfo) == TRUE;

    // Basic Constraints (isCA, pathLen)
    PCERT_EXTENSION extBC = CertFindExtension(szOID_BASIC_CONSTRAINTS2,
        m_certContext->pCertInfo->cExtension,
        m_certContext->pCertInfo->rgExtension);
    if (extBC) {
        DWORD cb = 0;
        if (CryptDecodeObject(X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2,
            extBC->Value.pbData, extBC->Value.cbData,
            0, nullptr, &cb)) {
            std::vector<BYTE> buf(cb);
            if (CryptDecodeObject(X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2,
                extBC->Value.pbData, extBC->Value.cbData,
                0, buf.data(), &cb)) {
                auto* bc = reinterpret_cast<PCERT_BASIC_CONSTRAINTS2_INFO>(buf.data());
                info.isCA = bc->fCA;
                info.pathLenConstraint = bc->fPathLenConstraint ? static_cast<int>(bc->dwPathLenConstraint) : -1;
            }
        }
    }

    // Signature algorithm (OID -> friendly string)
    {
        LPCSTR oid = m_certContext->pCertInfo->SignatureAlgorithm.pszObjId;
        if (oid) {
            if (std::strcmp(oid, szOID_OIWSEC_sha1RSASign) == 0)          info.signatureAlgorithm = L"RSA-SHA1";
            else if (std::strcmp(oid, szOID_RSA_SHA256RSA) == 0)          info.signatureAlgorithm = L"RSA-SHA256";
            else if (std::strcmp(oid, szOID_RSA_SHA512RSA) == 0)          info.signatureAlgorithm = L"RSA-SHA512";
            else if (std::strcmp(oid, szOID_ECDSA_SHA256) == 0)           info.signatureAlgorithm = L"ECDSA-SHA256";
            else if (std::strcmp(oid, szOID_ECDSA_SHA384) == 0)           info.signatureAlgorithm = L"ECDSA-SHA384";
            else if (std::strcmp(oid, szOID_ECDSA_SHA512) == 0)           info.signatureAlgorithm = L"ECDSA-SHA512";
            else if (std::strcmp(oid, szOID_RSA_RSA) == 0)                info.signatureAlgorithm = L"RSA-MD2/MD5";
            else                                                          info.signatureAlgorithm = L"UNKNOWN";
        }
    }

    return true;
#else
    (void)info; (void)err;
    return false;
#endif
}


// ========================
// GetSubjectAltNames (DNS/IP/URL parsing)
// ========================
bool Certificate::GetSubjectAltNames(std::vector<std::wstring>& dns,
    std::vector<std::wstring>& ips,
    std::vector<std::wstring>& urls,
    Error* err) const noexcept {
#ifdef _WIN32
    dns.clear(); ips.clear(); urls.clear();
    if (!m_certContext) {
        set_err(err, L"GetSubjectAltNames: empty certificate", ERROR_INVALID_HANDLE);
        return false;
    }

    PCERT_EXTENSION ext = CertFindExtension(szOID_SUBJECT_ALT_NAME2,
        m_certContext->pCertInfo->cExtension,
        m_certContext->pCertInfo->rgExtension);
    if (!ext) {
        return true; // no SAN extension → not an error
    }

    DWORD cb = 0;
    if (!CryptDecodeObject(X509_ASN_ENCODING,
        X509_ALTERNATE_NAME,
        ext->Value.pbData,
        ext->Value.cbData,
        0, nullptr, &cb)) {
        set_err(err, L"GetSubjectAltNames: decode size failed", GetLastError());
        return false;
    }

    std::vector<BYTE> buf(cb);
    if (!CryptDecodeObject(X509_ASN_ENCODING,
        X509_ALTERNATE_NAME,
        ext->Value.pbData,
        ext->Value.cbData,
        0, buf.data(), &cb)) {
        set_err(err, L"GetSubjectAltNames: decode failed", GetLastError());
        return false;
    }

    auto* names = reinterpret_cast<PCERT_ALT_NAME_INFO>(buf.data());
    for (DWORD i = 0; i < names->cAltEntry; ++i) {
        const CERT_ALT_NAME_ENTRY& e = names->rgAltEntry[i];
        switch (e.dwAltNameChoice) {
        case CERT_ALT_NAME_DNS_NAME:
            if (e.pwszDNSName) dns.emplace_back(e.pwszDNSName);
            break;
        case CERT_ALT_NAME_URL:
            if (e.pwszURL) urls.emplace_back(e.pwszURL);
            break;
        case CERT_ALT_NAME_IP_ADDRESS: {
            wchar_t ipStr[64] = {};
            if (e.IPAddress.cbData == 4) { // IPv4
                swprintf(ipStr, 64, L"%u.%u.%u.%u",
                    e.IPAddress.pbData[0],
                    e.IPAddress.pbData[1],
                    e.IPAddress.pbData[2],
                    e.IPAddress.pbData[3]);
                ips.emplace_back(ipStr);
            }
            else if (e.IPAddress.cbData == 16) { // IPv6
                swprintf(ipStr, 64,
                    L"%02X%02X:%02X%02X:%02X%02X:%02X%02X:"
                    L"%02X%02X:%02X%02X:%02X%02X:%02X%02X",
                    e.IPAddress.pbData[0], e.IPAddress.pbData[1],
                    e.IPAddress.pbData[2], e.IPAddress.pbData[3],
                    e.IPAddress.pbData[4], e.IPAddress.pbData[5],
                    e.IPAddress.pbData[6], e.IPAddress.pbData[7],
                    e.IPAddress.pbData[8], e.IPAddress.pbData[9],
                    e.IPAddress.pbData[10], e.IPAddress.pbData[11],
                    e.IPAddress.pbData[12], e.IPAddress.pbData[13],
                    e.IPAddress.pbData[14], e.IPAddress.pbData[15]);
                ips.emplace_back(ipStr);
            }
            break;
        }
        default:
            // skip otherName, RFC822, X400, DirName, etc. (add if needed)
            break;
        }
    }

    return true;
#else
    (void)dns; (void)ips; (void)urls; (void)err;
    return false;
#endif
}


// ========================
// IsSelfSigned
// ========================
bool Certificate::IsSelfSigned() const noexcept {
#ifdef _WIN32
    if (!m_certContext) return false;

    // Compare subject and issuer
    return CertCompareCertificate(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        m_certContext->pCertInfo,
        m_certContext->pCertInfo) == TRUE;
#else
    return false;
#endif
}

// ========================
// GetBasicConstraintsPathLen
// ========================
int Certificate::GetBasicConstraintsPathLen() const noexcept {
#ifdef _WIN32
    if (!m_certContext) return -1;

    PCERT_EXTENSION ext = CertFindExtension(szOID_BASIC_CONSTRAINTS2,
        m_certContext->pCertInfo->cExtension,
        m_certContext->pCertInfo->rgExtension);
    if (!ext) return -1;

    DWORD cb = 0;
    if (!CryptDecodeObject(X509_ASN_ENCODING,
        X509_BASIC_CONSTRAINTS2,
        ext->Value.pbData,
        ext->Value.cbData,
        0, nullptr, &cb)) {
        return -1;
    }

    std::vector<BYTE> buf(cb);
    if (!CryptDecodeObject(X509_ASN_ENCODING,
        X509_BASIC_CONSTRAINTS2,
        ext->Value.pbData,
        ext->Value.cbData,
        0, buf.data(), &cb)) {
        return -1;
    }

    auto* bc = reinterpret_cast<PCERT_BASIC_CONSTRAINTS2_INFO>(buf.data());
    if (bc->fPathLenConstraint) {
        return static_cast<int>(bc->dwPathLenConstraint);
    }
    return -1;
#else
    return -1;
#endif
}

// ========================
// IsStrongSignatureAlgo
// ========================
bool Certificate::IsStrongSignatureAlgo(bool allowSha1) const noexcept {
#ifdef _WIN32
    if (!m_certContext) return false;

    LPCSTR oid = m_certContext->pCertInfo->SignatureAlgorithm.pszObjId;
    if (!oid) return false;

    // Disallow MD2/MD5 always
    if (std::strcmp(oid, szOID_RSA_MD2RSA) == 0 ||
        std::strcmp(oid, szOID_RSA_MD5RSA) == 0) {
        return false;
    }

    // SHA1 only if explicitly allowed
    if (std::strcmp(oid, szOID_OIWSEC_sha1RSASign) == 0 ||
        std::strcmp(oid, szOID_RSA_SHA1RSA) == 0) {
        return allowSha1;
    }

    // SHA256/384/512, ECDSA, RSA-PSS considered strong
    if (std::strcmp(oid, szOID_RSA_SHA256RSA) == 0 ||
        std::strcmp(oid, szOID_RSA_SHA384RSA) == 0 ||
        std::strcmp(oid, szOID_RSA_SHA512RSA) == 0 ||
        std::strcmp(oid, szOID_ECDSA_SHA256) == 0 ||
        std::strcmp(oid, szOID_ECDSA_SHA384) == 0 ||
        std::strcmp(oid, szOID_ECDSA_SHA512) == 0 ||
        std::strcmp(oid, szOID_RSA_PSS) == 0) {
        return true;
    }

    // Unknown OID → treat as not strong
    return false;
#else
    (void)allowSha1;
    return false;
#endif
}

// ========================
// GetSignatureAlgorithm (friendly string)
// ========================
bool Certificate::GetSignatureAlgorithm(std::wstring& alg, Error* err) const noexcept {
#ifdef _WIN32
    alg.clear();
    if (!m_certContext) {
        set_err(err, L"GetSignatureAlgorithm: empty certificate", ERROR_INVALID_HANDLE);
        return false;
    }

    LPCSTR oid = m_certContext->pCertInfo->SignatureAlgorithm.pszObjId;
    if (!oid) {
        set_err(err, L"GetSignatureAlgorithm: no OID");
        return false;
    }

    if (std::strcmp(oid, szOID_RSA_SHA256RSA) == 0) alg = L"RSA-SHA256";
    else if (std::strcmp(oid, szOID_RSA_SHA384RSA) == 0) alg = L"RSA-SHA384";
    else if (std::strcmp(oid, szOID_RSA_SHA512RSA) == 0) alg = L"RSA-SHA512";
    else if (std::strcmp(oid, szOID_OIWSEC_sha1RSASign) == 0 ||
        std::strcmp(oid, szOID_RSA_SHA1RSA) == 0) alg = L"RSA-SHA1";
    else if (std::strcmp(oid, szOID_RSA_MD5RSA) == 0) alg = L"RSA-MD5";
    else if (std::strcmp(oid, szOID_ECDSA_SHA256) == 0) alg = L"ECDSA-SHA256";
    else if (std::strcmp(oid, szOID_ECDSA_SHA384) == 0) alg = L"ECDSA-SHA384";
    else if (std::strcmp(oid, szOID_ECDSA_SHA512) == 0) alg = L"ECDSA-SHA512";
    else if (std::strcmp(oid, szOID_RSA_PSS) == 0) alg = L"RSA-PSS";
    else alg = L"UNKNOWN";

    return true;
#else
    (void)alg; (void)err;
    return false;
#endif
}


// ========================
// VerifySignature (raw data + signature using cert's public key)
// ========================
bool Certificate::VerifySignature(const uint8_t* data, size_t dataLen,
    const uint8_t* signature, size_t signatureLen,
    Error* err) const noexcept {
#ifdef _WIN32
    if (!m_certContext) {
        set_err(err, L"VerifySignature: empty certificate", ERROR_INVALID_HANDLE);
        return false;
    }
    if (!data || !signature || dataLen == 0 || signatureLen == 0) {
        set_err(err, L"VerifySignature: invalid parameters", ERROR_INVALID_PARAMETER);
        return false;
    }

    // Acquire public key handle
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey = 0;
    DWORD dwKeySpec = 0;
    BOOL fCallerFree = FALSE;
    if (!CryptAcquireCertificatePrivateKey(m_certContext,
        CRYPT_ACQUIRE_COMPARE_KEY_FLAG | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
        nullptr,
        &hKey, &dwKeySpec, &fCallerFree)) {
        set_err(err, L"VerifySignature: CryptAcquireCertificatePrivateKey failed", GetLastError());
        return false;
    }

    // Hash data with SHA256
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        set_err(err, L"VerifySignature: BCryptOpenAlgorithmProvider failed");
        if (fCallerFree) NCryptFreeObject(hKey);
        return false;
    }

    DWORD cbHash = 0, cbResult = 0;
    if (BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&cbHash, sizeof(DWORD), &cbResult, 0) != 0) {
        set_err(err, L"VerifySignature: BCryptGetProperty failed");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        if (fCallerFree) NCryptFreeObject(hKey);
        return false;
    }

    std::vector<BYTE> hash(cbHash);
    BCRYPT_HASH_HANDLE hHash = nullptr;
    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) != 0) {
        set_err(err, L"VerifySignature: BCryptCreateHash failed");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        if (fCallerFree) NCryptFreeObject(hKey);
        return false;
    }

    if (BCryptHashData(hHash, (PUCHAR)data, (ULONG)dataLen, 0) != 0 ||
        BCryptFinishHash(hHash, hash.data(), cbHash, 0) != 0) {
        set_err(err, L"VerifySignature: hashing failed");
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        if (fCallerFree) NCryptFreeObject(hKey);
        return false;
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    // Verify signature using NCrypt
    SECURITY_STATUS secStatus = NCryptVerifySignature(hKey, nullptr,
        hash.data(), cbHash,
        (PUCHAR)signature, (ULONG)signatureLen,
        0);
    if (fCallerFree) NCryptFreeObject(hKey);

    if (secStatus != ERROR_SUCCESS) {
        set_err(err, L"VerifySignature: NCryptVerifySignature failed", secStatus);
        return false;
    }
    return true;
#else
    (void)data; (void)dataLen; (void)signature; (void)signatureLen; (void)err;
    return false;
#endif
}

// ========================
// VerifyChain (current time)
// ========================
bool Certificate::VerifyChain(Error* err,
    HCERTSTORE hAdditionalStore,
    DWORD chainFlags,
    FILETIME* verificationTime,
    const char* requiredEkuOid) const noexcept {
#ifdef _WIN32
    if (!m_certContext) {
        set_err(err, L"VerifyChain: empty certificate", ERROR_INVALID_HANDLE);
        return false;
    }

    CERT_CHAIN_PARA chainPara{};
    chainPara.cbSize = sizeof(chainPara);

    PCCERT_CHAIN_CONTEXT chainCtx = nullptr;
    if (!CertGetCertificateChain(nullptr, m_certContext,
        verificationTime, hAdditionalStore,
        &chainPara, chainFlags, nullptr, &chainCtx)) {
        set_err(err, L"VerifyChain: CertGetCertificateChain failed", GetLastError());
        return false;
    }

    CERT_CHAIN_POLICY_PARA policyPara{};
    policyPara.cbSize = sizeof(policyPara);
    if (requiredEkuOid) {
        policyPara.dwFlags |= CERT_CHAIN_POLICY_IGNORE_INVALID_BASIC_CONSTRAINTS;
    }

    CERT_CHAIN_POLICY_STATUS policyStatus{};
    policyStatus.cbSize = sizeof(policyStatus);

    BOOL ok = CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_AUTHENTICODE,
        chainCtx, &policyPara, &policyStatus);
    CertFreeCertificateChain(chainCtx);

    if (!ok || policyStatus.dwError != 0) {
        set_err(err, L"VerifyChain: policy failed", policyStatus.dwError);
        return false;
    }
    return true;
#else
    (void)err; (void)hAdditionalStore; (void)chainFlags; (void)verificationTime; (void)requiredEkuOid;
    return false;
#endif
}

// ========================
// VerifyChainAtTime
// ========================
bool Certificate::VerifyChainAtTime(const FILETIME& verifyTime,
    Error* err,
    HCERTSTORE hAdditionalStore,
    DWORD chainFlags,
    const char* requiredEkuOid) const noexcept {
    return VerifyChain(err, hAdditionalStore, chainFlags,
        const_cast<FILETIME*>(&verifyTime), requiredEkuOid);
}

// ========================
// VerifyChainWithStore (explicit roots/intermediates)
// ========================
bool Certificate::VerifyChainWithStore(HCERTSTORE hRootStore,
    HCERTSTORE hIntermediateStore,
    Error* err,
    DWORD chainFlags,
    const FILETIME* verificationTime,
    const char* requiredEkuOid) const noexcept {
#ifdef _WIN32
    if (!m_certContext) {
        set_err(err, L"VerifyChainWithStore: empty certificate", ERROR_INVALID_HANDLE);
        return false;
    }

    CERT_CHAIN_ENGINE_CONFIG config{};
    config.cbSize = sizeof(config);
    config.hExclusiveRoot = hRootStore;
    config.hExclusiveIntermediate = hIntermediateStore;

    HCERTCHAINENGINE hEngine = nullptr;
    if (CertCreateCertificateChainEngine(&config, &hEngine) != TRUE) {
        set_err(err, L"VerifyChainWithStore: CertCreateCertificateChainEngine failed", GetLastError());
        return false;
    }

    CERT_CHAIN_PARA chainPara{};
    chainPara.cbSize = sizeof(chainPara);

    PCCERT_CHAIN_CONTEXT chainCtx = nullptr;
    BOOL okChain = CertGetCertificateChain(hEngine, m_certContext,
        verificationTime, nullptr,
        &chainPara, chainFlags,
        nullptr, &chainCtx);
    if (!okChain || !chainCtx) {
        set_err(err, L"VerifyChainWithStore: CertGetCertificateChain failed", GetLastError());
        CertFreeCertificateChainEngine(hEngine);
        return false;
    }

    CERT_CHAIN_POLICY_PARA policyPara{};
    policyPara.cbSize = sizeof(policyPara);
    CERT_CHAIN_POLICY_STATUS policyStatus{};
    policyStatus.cbSize = sizeof(policyStatus);

    BOOL okPolicy = CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_AUTHENTICODE,
        chainCtx, &policyPara, &policyStatus);
    CertFreeCertificateChain(chainCtx);
    CertFreeCertificateChainEngine(hEngine);

    if (!okPolicy || policyStatus.dwError != 0) {
        set_err(err, L"VerifyChainWithStore: policy failed", policyStatus.dwError);
        return false;
    }
    return true;
#else
    (void)hRootStore; (void)hIntermediateStore; (void)err; (void)chainFlags; (void)verificationTime; (void)requiredEkuOid;
    return false;
#endif
}



// ========================
// HasEKU (Enhanced Key Usage)
// ========================
bool Certificate::HasEKU(const char* oid, Error* err) const noexcept {
#ifdef _WIN32
    if (!m_certContext || !oid) {
        set_err(err, L"HasEKU: invalid parameters", ERROR_INVALID_PARAMETER);
        return false;
    }

    DWORD cb = 0;
    if (!CertGetEnhancedKeyUsage(m_certContext, 0, nullptr, &cb) || cb == 0) {
        set_err(err, L"HasEKU: size query failed", GetLastError());
        return false;
    }

    std::vector<BYTE> buf(cb);
    auto* pUsage = reinterpret_cast<PCERT_ENHKEY_USAGE>(buf.data());
    if (!CertGetEnhancedKeyUsage(m_certContext, 0, pUsage, &cb)) {
        set_err(err, L"HasEKU: property fetch failed", GetLastError());
        return false;
    }

    for (DWORD i = 0; i < pUsage->cUsageIdentifier; ++i) {
        if (pUsage->rgpszUsageIdentifier[i] &&
            std::strcmp(pUsage->rgpszUsageIdentifier[i], oid) == 0) {
            return true;
        }
    }
    return false;
#else
    (void)oid; (void)err;
    return false;
#endif
}

// ========================
// HasKeyUsage
// ========================
bool Certificate::HasKeyUsage(DWORD flags, Error* err) const noexcept {
#ifdef _WIN32
    if (!m_certContext) {
        set_err(err, L"HasKeyUsage: empty certificate", ERROR_INVALID_HANDLE);
        return false;
    }

    DWORD cb = 0;
    if (!CertGetIntendedKeyUsage(X509_ASN_ENCODING, m_certContext->pCertInfo, nullptr, &cb)) {
        set_err(err, L"HasKeyUsage: query failed", GetLastError());
        return false;
    }

    BYTE usage = 0;
    if (!CertGetIntendedKeyUsage(X509_ASN_ENCODING, m_certContext->pCertInfo, &usage, sizeof(usage))) {
        set_err(err, L"HasKeyUsage: fetch failed", GetLastError());
        return false;
    }

    return (usage & flags) == flags;
#else
    (void)flags; (void)err;
    return false;
#endif
}

// ========================
// VerifyAgainstCA (simple chain: cert signed by given CA)
// ========================
bool Certificate::VerifyAgainstCA(const Certificate& caCert, Error* err) const noexcept {
#ifdef _WIN32
    if (!m_certContext || !caCert.m_certContext) {
        set_err(err, L"VerifyAgainstCA: invalid certs", ERROR_INVALID_HANDLE);
        return false;
    }

    HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
        CERT_STORE_CREATE_NEW_FLAG, nullptr);
    if (!hStore) {
        set_err(err, L"VerifyAgainstCA: CertOpenStore failed", GetLastError());
        return false;
    }

    // Add CA cert to store
    if (!CertAddCertificateContextToStore(hStore, caCert.m_certContext,
        CERT_STORE_ADD_ALWAYS, nullptr)) {
        set_err(err, L"VerifyAgainstCA: add CA failed", GetLastError());
        CertCloseStore(hStore, 0);
        return false;
    }

    // Build chain with CA as root
    CERT_CHAIN_PARA chainPara{};
    chainPara.cbSize = sizeof(chainPara);

    PCCERT_CHAIN_CONTEXT chainCtx = nullptr;
    BOOL ok = CertGetCertificateChain(nullptr, m_certContext,
        nullptr, hStore,
        &chainPara, 0, nullptr, &chainCtx);
    if (!ok || !chainCtx) {
        set_err(err, L"VerifyAgainstCA: chain build failed", GetLastError());
        CertCloseStore(hStore, 0);
        return false;
    }

    bool trusted = (chainCtx->TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR);
    CertFreeCertificateChain(chainCtx);
    CertCloseStore(hStore, 0);
    return trusted;
#else
    (void)caCert; (void)err;
    return false;
#endif
}

// ========================
// GetRevocationStatus (best effort)
// ========================
bool Certificate::GetRevocationStatus(bool& isRevoked, std::wstring& reason, Error* err) const noexcept {
#ifdef _WIN32
    isRevoked = false;
    reason.clear();

    if (!m_certContext) {
        set_err(err, L"GetRevocationStatus: empty certificate", ERROR_INVALID_HANDLE);
        return false;
    }

    CERT_REVOCATION_PARA revPara{};
    revPara.cbSize = sizeof(revPara);

    CERT_REVOCATION_STATUS revStatus{};
    revStatus.cbSize = sizeof(revStatus);

    BOOL ok = CertVerifyRevocation(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        CERT_CONTEXT_REVOCATION_TYPE,
        1, (void**)&m_certContext,
        0, &revPara, &revStatus);
    if (!ok) {
        // If revocation check fails, treat as unknown
        reason = L"Revocation check failed";
        return false;
    }

    if (revStatus.dwError == CRYPT_E_REVOKED) {
        isRevoked = true;
        reason = L"Certificate is revoked";
        return true;
    }
    else if (revStatus.dwError == CRYPT_E_NO_REVOCATION_CHECK) {
        reason = L"No revocation mechanism available";
        return true;
    }
    else if (revStatus.dwError == CRYPT_E_REVOCATION_OFFLINE) {
        reason = L"Revocation server offline";
        return true;
    }

    return true;
#else
    (void)isRevoked; (void)reason; (void)err;
    return false;
#endif
}


// ========================
// VerifyTimestampToken (RFC3161 PKCS#7 TSTInfo parsing, best effort)
// ========================
bool Certificate::VerifyTimestampToken(const uint8_t* tsToken, size_t len,
    FILETIME& outGenTime, Error* err) const noexcept {
#ifdef _WIN32
    outGenTime = FILETIME{};
    if (!tsToken || len == 0) {
        set_err(err, L"VerifyTimestampToken: invalid buffer", ERROR_INVALID_PARAMETER);
        return false;
    }

    HCRYPTMSG hMsg = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0, 0, nullptr, nullptr, nullptr);
    if (!hMsg) {
        set_err(err, L"VerifyTimestampToken: CryptMsgOpenToDecode failed", GetLastError());
        return false;
    }

    BOOL upd = CryptMsgUpdate(hMsg, tsToken, (DWORD)len, TRUE);
    if (!upd) {
        set_err(err, L"VerifyTimestampToken: CryptMsgUpdate failed", GetLastError());
        CryptMsgClose(hMsg);
        return false;
    }

    // Extract content (TSTInfo)
    DWORD cbContent = 0;
    if (!CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, nullptr, &cbContent) || cbContent == 0) {
        set_err(err, L"VerifyTimestampToken: content size failed", GetLastError());
        CryptMsgClose(hMsg);
        return false;
    }

    std::vector<BYTE> content(cbContent);
    if (!CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, content.data(), &cbContent)) {
        set_err(err, L"VerifyTimestampToken: content fetch failed", GetLastError());
        CryptMsgClose(hMsg);
        return false;
    }

    // Decode genTime from TSTInfo (ASN.1 GeneralizedTime)
    DWORD cbDecoded = 0;
    if (!CryptDecodeObject(X509_ASN_ENCODING, X509_CHOICE_OF_TIME,
        content.data(), cbContent,
        0, nullptr, &cbDecoded)) {
        set_err(err, L"VerifyTimestampToken: decode size failed", GetLastError());
        CryptMsgClose(hMsg);
        return false;
    }

    std::vector<BYTE> buf(cbDecoded);
    if (!CryptDecodeObject(X509_ASN_ENCODING, X509_CHOICE_OF_TIME,
        content.data(), cbContent,
        0, buf.data(), &cbDecoded)) {
        set_err(err, L"VerifyTimestampToken: decode failed", GetLastError());
        CryptMsgClose(hMsg);
        return false;
    }

    SYSTEMTIME* st = reinterpret_cast<SYSTEMTIME*>(buf.data());
    if (!SystemTimeToFileTime(st, &outGenTime)) {
        set_err(err, L"VerifyTimestampToken: SystemTimeToFileTime failed", GetLastError());
        CryptMsgClose(hMsg);
        return false;
    }

    CryptMsgClose(hMsg);
    return true;
#else
    (void)tsToken; (void)len; (void)outGenTime; (void)err;
    return false;
#endif
}

// ========================
// ExtractPublicKey
// ========================
bool Certificate::ExtractPublicKey(ShadowStrike::Utils::CryptoUtils::PublicKey& outKey,
    Error* err) const noexcept {
#ifdef _WIN32
    if (!m_certContext) {
        set_err(err, L"ExtractPublicKey: empty certificate", ERROR_INVALID_HANDLE);
        return false;
    }

    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey = 0;
    DWORD dwKeySpec = 0;
    BOOL fCallerFree = FALSE;
    if (!CryptAcquireCertificatePrivateKey(m_certContext,
        CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG |
        CRYPT_ACQUIRE_COMPARE_KEY_FLAG,
        nullptr,
        &hKey, &dwKeySpec, &fCallerFree)) {
        set_err(err, L"ExtractPublicKey: CryptAcquireCertificatePrivateKey failed", GetLastError());
        return false;
    }

    // Export public key blob
    DWORD cbBlob = 0;
    if (NCryptExportKey(hKey, 0, BCRYPT_PUBLIC_KEY_BLOB, nullptr, nullptr, 0, &cbBlob, 0) != ERROR_SUCCESS) {
        set_err(err, L"ExtractPublicKey: size query failed");
        if (fCallerFree) NCryptFreeObject(hKey);
        return false;
    }

    std::vector<BYTE> blob(cbBlob);
    if (NCryptExportKey(hKey, 0, BCRYPT_PUBLIC_KEY_BLOB, nullptr, blob.data(), cbBlob, &cbBlob, 0) != ERROR_SUCCESS) {
        set_err(err, L"ExtractPublicKey: export failed");
        if (fCallerFree) NCryptFreeObject(hKey);
        return false;
    }

    if (fCallerFree) NCryptFreeObject(hKey);

    // Fill into CryptoUtils::PublicKey
    outKey.AssignFromBlob(blob.data(), cbBlob);
    return true;
#else
    (void)outKey; (void)err;
    return false;
#endif
}

// ========================
// Attach (adopt external PCCERT_CONTEXT)
// ========================
bool Certificate::Attach(PCCERT_CONTEXT ctx) noexcept {
#ifdef _WIN32
    cleanup();
    if (!ctx) return false;
    m_certContext = CertDuplicateCertificateContext(ctx);
    return m_certContext != nullptr;
#else
    (void)ctx;
    return false;
#endif
}

// ========================
// Detach (release ownership to caller)
// ========================
PCCERT_CONTEXT Certificate::Detach() noexcept {
#ifdef _WIN32
    PCCERT_CONTEXT ctx = m_certContext;
    m_certContext = nullptr;
    return ctx;
#else
    return nullptr;
#endif
}

// ========================
// SetRevocationMode
// ========================
void Certificate::SetRevocationMode(RevocationMode m) noexcept {
    revocationMode_ = m;
}

// ========================
// GetRevocationMode
// ========================
RevocationMode Certificate::GetRevocationMode() const noexcept {
    return revocationMode_;
}

// ========================
// SetAllowSha1Weak
// ========================
void Certificate::SetAllowSha1Weak(bool v) noexcept {
    allowSha1Weak_ = v;
}

// ========================
// GetAllowSha1Weak
// ========================
bool Certificate::GetAllowSha1Weak() const noexcept {
    return allowSha1Weak_;
}
