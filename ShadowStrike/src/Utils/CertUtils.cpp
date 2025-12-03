/**
 * @file CertUtils.cpp
 * @brief Implementation of X.509 Certificate Utilities.
 *
 * @copyright Copyright (c) 2025 ShadowStrike Security
 * @license Proprietary - All rights reserved
 */

#include "CertUtils.hpp"

#include <algorithm>
#include <cwchar>
#include <cstring>
#include <limits>

using namespace ShadowStrike::Utils::CertUtils;

#ifdef _WIN32

// ============================================================================
// Internal Helper Functions
// ============================================================================

namespace {

    /**
     * @brief Sets error information in an Error structure.
     *
     * @param err Pointer to Error structure (may be nullptr).
     * @param msg Error message.
     * @param w32 Win32 error code.
     * @param nt NTSTATUS error code.
     */
    inline void set_err(Error* err, const wchar_t* msg, DWORD w32 = 0, LONG nt = 0) noexcept {
        if (!err) {
            return;
        }
        err->Clear();
        err->message = msg ? msg : L"";
        err->win32 = w32;
        err->ntstatus = nt;
    }

    /**
     * @brief Checks if a file exists and is not a directory.
     *
     * @param path Path to check.
     * @return true if file exists, false otherwise.
     */
    [[nodiscard]] inline bool file_exists_w(const std::wstring& path) noexcept {
        if (path.empty()) {
            return false;
        }
        const DWORD attrs = ::GetFileAttributesW(path.c_str());
        return (attrs != INVALID_FILE_ATTRIBUTES) && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
    }

    /**
     * @brief Safely converts size_t to DWORD with overflow check.
     *
     * @param value Value to convert.
     * @param out Output DWORD.
     * @return true if conversion succeeded, false on overflow.
     */
    [[nodiscard]] inline bool safe_size_to_dword(size_t value, DWORD& out) noexcept {
        if (value > static_cast<size_t>(std::numeric_limits<DWORD>::max())) {
            return false;
        }
        out = static_cast<DWORD>(value);
        return true;
    }

    /**
     * @brief Validates a hex character.
     *
     * @param c Character to check.
     * @return true if valid hex character.
     */
    [[nodiscard]] constexpr bool is_hex_char(wchar_t c) noexcept {
        return (c >= L'0' && c <= L'9') ||
               (c >= L'A' && c <= L'F') ||
               (c >= L'a' && c <= L'f');
    }

    /**
     * @brief Converts a hex character to its numeric value.
     *
     * @param c Hex character.
     * @return Numeric value (0-15), or 0 if invalid.
     */
    [[nodiscard]] constexpr uint8_t hex_char_to_value(wchar_t c) noexcept {
        if (c >= L'0' && c <= L'9') return static_cast<uint8_t>(c - L'0');
        if (c >= L'A' && c <= L'F') return static_cast<uint8_t>(c - L'A' + 10);
        if (c >= L'a' && c <= L'f') return static_cast<uint8_t>(c - L'a' + 10);
        return 0;
    }

    /// Hex character lookup table for byte-to-hex conversion
    constexpr wchar_t kHexChars[] = L"0123456789ABCDEF";

    // ========================================================================
    // Security Constants
    // ========================================================================
    
    /// Maximum certificate file size (10 MB) - prevents DoS via huge files
    constexpr size_t kMaxFileSize = 10ULL * 1024 * 1024;

    /// Maximum raw certificate size (1 MB) - reasonable limit for DER/PEM certs
    constexpr size_t kMaxCertificateSize = 1ULL * 1024 * 1024;

    /// Maximum decoded structure size (64 KB) - for CryptDecodeObject outputs
    constexpr DWORD kMaxDecodedStructureSize = 64 * 1024;

    // ========================================================================
    // OID Definitions (if not defined by Windows SDK)
    // ========================================================================

    // RSA-PSS OID (PKCS#1 v2.1)
#ifndef szOID_RSA_PSS
    constexpr char szOID_RSA_PSS[] = "1.2.840.113549.1.1.10";
#endif

    // DSA with SHA-1 OID
#ifndef szOID_DSA_SHA1
    constexpr char szOID_DSA_SHA1[] = "1.2.840.10040.4.3";
#endif

    // ECDSA with SHA-1 OID
#ifndef szOID_ECDSA_SHA1
    constexpr char szOID_ECDSA_SHA1[] = "1.2.840.10045.4.1";
#endif

} // anonymous namespace

#endif // _WIN32

// ============================================================================
// Certificate Lifecycle Management
// ============================================================================

/**
 * @brief Destructor - releases all resources.
 */
Certificate::~Certificate() {
    cleanup();
}

/**
 * @brief Move constructor - transfers ownership from another Certificate.
 *
 * @param other Source certificate to move from.
 */
Certificate::Certificate(Certificate&& other) noexcept
    : revocationMode_(other.revocationMode_)
    , allowSha1Weak_(other.allowSha1Weak_) {
#ifdef _WIN32
    m_certContext = other.m_certContext;
    other.m_certContext = nullptr;
#endif
    // Reset other to defaults
    other.revocationMode_ = RevocationMode::OnlineOnly;
    other.allowSha1Weak_ = false;
}

/**
 * @brief Move assignment - transfers ownership from another Certificate.
 *
 * @param other Source certificate to move from.
 * @return Reference to this.
 */
Certificate& Certificate::operator=(Certificate&& other) noexcept {
    if (this == &other) {
        return *this;
    }

    // Release current resources
    cleanup();

#ifdef _WIN32
    m_certContext = other.m_certContext;
    other.m_certContext = nullptr;
#endif
    revocationMode_ = other.revocationMode_;
    allowSha1Weak_ = other.allowSha1Weak_;

    // Reset other to defaults
    other.revocationMode_ = RevocationMode::OnlineOnly;
    other.allowSha1Weak_ = false;

    return *this;
}

/**
 * @brief Releases the certificate context and resets internal state.
 */
void Certificate::cleanup() noexcept {
#ifdef _WIN32
    if (m_certContext != nullptr) {
        CertFreeCertificateContext(m_certContext);
        m_certContext = nullptr;
    }
#endif
}

// ============================================================================
// Certificate Loading Methods
// ============================================================================

/**
 * @brief Loads a certificate from a file.
 *
 * Supports DER, PEM, and PKCS#7 container formats. The function
 * automatically detects the format and extracts the first certificate.
 *
 * @param path Path to the certificate file.
 * @param err Optional error output.
 * @return true on success, false on failure.
 */
bool Certificate::LoadFromFile(std::wstring_view path, Error* err) noexcept {
#ifdef _WIN32
    // Release any existing certificate
    cleanup();

    // Validate path
    if (path.empty()) {
        set_err(err, L"LoadFromFile: empty path", ERROR_INVALID_PARAMETER);
        return false;
    }

    // Convert to null-terminated string (wstring_view may not be null-terminated)
    std::wstring pathStr(path);
    if (!file_exists_w(pathStr)) {
        set_err(err, L"LoadFromFile: file not found", ERROR_FILE_NOT_FOUND);
        return false;
    }

    // Variables for CryptQueryObject
    HCERTSTORE hStore = nullptr;
    DWORD dwEncoding = 0;
    DWORD dwContentType = 0;
    DWORD dwFormatType = 0;

    // Try CryptQueryObject for DER/PEM X.509 certificate
    BOOL ok = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        pathStr.c_str(),
        CERT_QUERY_CONTENT_FLAG_CERT,
        CERT_QUERY_FORMAT_FLAG_ALL,
        0,
        &dwEncoding,
        &dwContentType,
        &dwFormatType,
        &hStore,
        nullptr,
        nullptr
    );

    if (!ok || hStore == nullptr) {
        // Fallback: try PKCS#7 container formats
        ok = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            pathStr.c_str(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED |
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED |
            CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED,
            CERT_QUERY_FORMAT_FLAG_ALL,
            0,
            &dwEncoding,
            &dwContentType,
            &dwFormatType,
            &hStore,
            nullptr,
            nullptr
        );

        if (!ok || hStore == nullptr) {
            set_err(err, L"LoadFromFile: CryptQueryObject failed", GetLastError());
            return false;
        }
    }

    // Extract the first certificate from the store
    PCCERT_CONTEXT ctx = CertEnumCertificatesInStore(hStore, nullptr);
    if (ctx == nullptr) {
        const DWORD lastError = GetLastError();
        CertCloseStore(hStore, 0);
        set_err(err, L"LoadFromFile: no certificate found in container", lastError);
        return false;
    }

    // Duplicate to own context (increments reference count)
    m_certContext = CertDuplicateCertificateContext(ctx);

    // Release enumerated context and close store
    CertFreeCertificateContext(ctx);
    CertCloseStore(hStore, 0);

    if (m_certContext == nullptr) {
        set_err(err, L"LoadFromFile: CertDuplicateCertificateContext failed", GetLastError());
        return false;
    }

    return true;
#else
    (void)path;
    (void)err;
    return false;
#endif
}

/**
 * @brief Loads a certificate from memory (DER or PEM format).
 *
 * Automatically detects PEM format by looking for the standard header.
 * Falls back to DER if PEM header is not found.
 *
 * @param data Pointer to certificate data.
 * @param len Length of data in bytes.
 * @param err Optional error output.
 * @return true on success, false on failure.
 */
bool Certificate::LoadFromMemory(const uint8_t* data, size_t len, Error* err) noexcept {
#ifdef _WIN32
    // Release any existing certificate
    cleanup();

    // Validate parameters
    if (data == nullptr || len == 0) {
        set_err(err, L"LoadFromMemory: invalid buffer", ERROR_INVALID_PARAMETER);
        return false;
    }

    // Check for size overflow when converting to DWORD
    DWORD dataLen = 0;
    if (!safe_size_to_dword(len, dataLen)) {
        set_err(err, L"LoadFromMemory: data too large", ERROR_INVALID_PARAMETER);
        return false;
    }

    // Detect PEM format by looking for header
    const char* cbuf = reinterpret_cast<const char*>(data);
    constexpr const char* kPemHeader = "-----BEGIN CERTIFICATE-----";
    constexpr size_t kPemHeaderLen = 27;

    const bool isPEM = (len >= kPemHeaderLen) &&
        (std::string_view(cbuf, len).find(kPemHeader) != std::string_view::npos);

    if (isPEM) {
        // Decode PEM → DER via CryptStringToBinaryA
        DWORD derSize = 0;
        if (!CryptStringToBinaryA(
            cbuf,
            dataLen,
            CRYPT_STRING_BASE64HEADER,
            nullptr,
            &derSize,
            nullptr,
            nullptr)) {
            set_err(err, L"LoadFromMemory: CryptStringToBinaryA size query failed", GetLastError());
            return false;
        }

        if (derSize == 0) {
            set_err(err, L"LoadFromMemory: decoded size is zero", ERROR_INVALID_DATA);
            return false;
        }

        // Allocate buffer for DER data
        std::vector<uint8_t> der;
        try {
            der.resize(derSize);
        }
        catch (const std::bad_alloc&) {
            set_err(err, L"LoadFromMemory: allocation failed", ERROR_OUTOFMEMORY);
            return false;
        }

        // Decode PEM to DER
        if (!CryptStringToBinaryA(
            cbuf,
            dataLen,
            CRYPT_STRING_BASE64HEADER,
            der.data(),
            &derSize,
            nullptr,
            nullptr)) {
            set_err(err, L"LoadFromMemory: CryptStringToBinaryA decode failed", GetLastError());
            return false;
        }

        // Create certificate context from DER
        m_certContext = CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            der.data(),
            derSize
        );

        if (m_certContext == nullptr) {
            set_err(err, L"LoadFromMemory: CertCreateCertificateContext (PEM) failed", GetLastError());
            return false;
        }

        return true;
    }
    else {
        // Assume DER format
        m_certContext = CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            data,
            dataLen
        );

        if (m_certContext == nullptr) {
            set_err(err, L"LoadFromMemory: CertCreateCertificateContext (DER) failed", GetLastError());
            return false;
        }

        return true;
    }
#else
    (void)data;
    (void)len;
    (void)err;
    return false;
#endif
}
/**
 * @brief Loads a certificate from Windows Certificate Store by thumbprint.
 *
 * Tries Current User store first, then falls back to Local Machine store.
 * Thumbprint is expected to be a hex string (spaces, colons, dashes are stripped).
 *
 * @param storeName Store name (e.g., L"MY", L"ROOT", L"CA").
 * @param thumbprint Certificate thumbprint (SHA-1 hex string).
 * @param err Optional error output.
 * @return true on success, false on failure.
 */
bool Certificate::LoadFromStore(std::wstring_view storeName, std::wstring_view thumbprint, Error* err) noexcept {
#ifdef _WIN32
    // Release any existing certificate
    cleanup();

    // Validate parameters
    if (storeName.empty()) {
        set_err(err, L"LoadFromStore: empty store name", ERROR_INVALID_PARAMETER);
        return false;
    }
    if (thumbprint.empty()) {
        set_err(err, L"LoadFromStore: empty thumbprint", ERROR_INVALID_PARAMETER);
        return false;
    }

    // Convert store name to null-terminated string
    std::wstring storeNameStr(storeName);

    // Open system certificate store (Current User first)
    HCERTSTORE hStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        0,
        0,
        CERT_SYSTEM_STORE_CURRENT_USER,
        storeNameStr.c_str()
    );

    if (hStore == nullptr) {
        // Fallback: try Local Machine store
        hStore = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            0,
            0,
            CERT_SYSTEM_STORE_LOCAL_MACHINE,
            storeNameStr.c_str()
        );

        if (hStore == nullptr) {
            set_err(err, L"LoadFromStore: CertOpenStore failed", GetLastError());
            return false;
        }
    }

    // Convert thumbprint hex string to binary
    std::wstring thumbHex(thumbprint);

    // Remove common separators (spaces, colons, dashes)
    thumbHex.erase(
        std::remove_if(thumbHex.begin(), thumbHex.end(),
            [](wchar_t c) {
                return c == L' ' || c == L':' || c == L'-';
            }),
        thumbHex.end()
    );

    // Validate thumbprint format
    if (thumbHex.empty() || (thumbHex.length() % 2) != 0) {
        set_err(err, L"LoadFromStore: invalid thumbprint length", ERROR_INVALID_PARAMETER);
        CertCloseStore(hStore, 0);
        return false;
    }

    // Validate all characters are hex
    for (wchar_t c : thumbHex) {
        if (!is_hex_char(c)) {
            set_err(err, L"LoadFromStore: invalid hex character in thumbprint", ERROR_INVALID_PARAMETER);
            CertCloseStore(hStore, 0);
            return false;
        }
    }

    // Convert hex string to bytes
    std::vector<BYTE> thumbBytes;
    try {
        thumbBytes.resize(thumbHex.length() / 2);
    }
    catch (const std::bad_alloc&) {
        set_err(err, L"LoadFromStore: allocation failed", ERROR_OUTOFMEMORY);
        CertCloseStore(hStore, 0);
        return false;
    }

    for (size_t i = 0; i < thumbBytes.size(); ++i) {
        const uint8_t highNibble = hex_char_to_value(thumbHex[i * 2]);
        const uint8_t lowNibble = hex_char_to_value(thumbHex[i * 2 + 1]);
        thumbBytes[i] = static_cast<BYTE>((highNibble << 4) | lowNibble);
    }

    // Find certificate by SHA-1 thumbprint
    CRYPT_HASH_BLOB hashBlob{};
    hashBlob.cbData = static_cast<DWORD>(thumbBytes.size());
    hashBlob.pbData = thumbBytes.data();

    PCCERT_CONTEXT ctx = CertFindCertificateInStore(
        hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_HASH,
        &hashBlob,
        nullptr
    );

    if (ctx == nullptr) {
        const DWORD lastError = GetLastError();
        CertCloseStore(hStore, 0);
        set_err(err, L"LoadFromStore: certificate not found", lastError);
        return false;
    }

    // Duplicate to own context
    m_certContext = CertDuplicateCertificateContext(ctx);

    // Release found context and close store
    CertFreeCertificateContext(ctx);
    CertCloseStore(hStore, 0);

    if (m_certContext == nullptr) {
        set_err(err, L"LoadFromStore: CertDuplicateCertificateContext failed", GetLastError());
        return false;
    }

    return true;
#else
    (void)storeName;
    (void)thumbprint;
    (void)err;
    return false;
#endif
}

/**
 * @brief Loads a certificate from a PEM-encoded string.
 *
 * Validates PEM format markers before attempting decode.
 *
 * @param pem PEM string containing the certificate.
 * @param err Optional error output.
 * @return true on success, false on failure.
 */
bool Certificate::LoadFromPEM(std::string_view pem, Error* err) noexcept {
#ifdef _WIN32
    // Release any existing certificate
    cleanup();

    // Validate parameters
    if (pem.empty()) {
        set_err(err, L"LoadFromPEM: empty PEM string", ERROR_INVALID_PARAMETER);
        return false;
    }

    // Verify PEM header/footer presence
    constexpr const char* kPemHeader = "-----BEGIN CERTIFICATE-----";
    constexpr const char* kPemFooter = "-----END CERTIFICATE-----";

    if (pem.find(kPemHeader) == std::string_view::npos ||
        pem.find(kPemFooter) == std::string_view::npos) {
        set_err(err, L"LoadFromPEM: invalid PEM format (missing markers)", ERROR_INVALID_DATA);
        return false;
    }

    // Check for size overflow
    DWORD pemLen = 0;
    if (!safe_size_to_dword(pem.length(), pemLen)) {
        set_err(err, L"LoadFromPEM: PEM data too large", ERROR_INVALID_PARAMETER);
        return false;
    }

    // Query required buffer size for DER output
    DWORD derSize = 0;
    if (!CryptStringToBinaryA(
        pem.data(),
        pemLen,
        CRYPT_STRING_BASE64HEADER,
        nullptr,
        &derSize,
        nullptr,
        nullptr)) {
        set_err(err, L"LoadFromPEM: CryptStringToBinaryA size query failed", GetLastError());
        return false;
    }

    if (derSize == 0) {
        set_err(err, L"LoadFromPEM: decoded size is zero", ERROR_INVALID_DATA);
        return false;
    }

    // Allocate buffer for DER data
    std::vector<uint8_t> der;
    try {
        der.resize(derSize);
    }
    catch (const std::bad_alloc&) {
        set_err(err, L"LoadFromPEM: allocation failed", ERROR_OUTOFMEMORY);
        return false;
    }

    // Decode PEM to DER
    if (!CryptStringToBinaryA(
        pem.data(),
        pemLen,
        CRYPT_STRING_BASE64HEADER,
        der.data(),
        &derSize,
        nullptr,
        nullptr)) {
        set_err(err, L"LoadFromPEM: CryptStringToBinaryA decode failed", GetLastError());
        return false;
    }

    // Create certificate context from DER
    m_certContext = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        der.data(),
        derSize
    );

    if (m_certContext == nullptr) {
        set_err(err, L"LoadFromPEM: CertCreateCertificateContext failed", GetLastError());
        return false;
    }

    return true;
#else
    (void)pem;
    (void)err;
    return false;
#endif
}


// ============================================================================
// Certificate Export Methods
// ============================================================================

/**
 * @brief Exports the certificate in DER format.
 *
 * @param out Output buffer for DER-encoded certificate.
 * @param err Optional error output.
 * @return true on success, false on failure.
 */
bool Certificate::Export(std::vector<uint8_t>& out, Error* err) const noexcept {
#ifdef _WIN32
    out.clear();

    if (m_certContext == nullptr) {
        set_err(err, L"Export: no certificate loaded", ERROR_INVALID_HANDLE);
        return false;
    }

    // Validate encoded data is available
    const BYTE* pb = m_certContext->pbCertEncoded;
    const DWORD cb = m_certContext->cbCertEncoded;

    if (pb == nullptr || cb == 0) {
        set_err(err, L"Export: no encoded data available", ERROR_INVALID_DATA);
        return false;
    }

    // Copy to output vector
    try {
        out.assign(pb, pb + cb);
    }
    catch (const std::bad_alloc&) {
        set_err(err, L"Export: allocation failed", ERROR_OUTOFMEMORY);
        return false;
    }

    return true;
#else
    (void)out;
    (void)err;
    return false;
#endif
}

/**
 * @brief Gets the raw DER-encoded certificate (alias for Export).
 *
 * @param out Output buffer for DER-encoded certificate.
 * @param err Optional error output.
 * @return true on success, false on failure.
 */
bool Certificate::GetRawDER(std::vector<uint8_t>& out, Error* err) const noexcept {
    return Export(out, err);
}

/**
 * @brief Exports the certificate in PEM format.
 *
 * @param out Output string for PEM-encoded certificate.
 * @param err Optional error output.
 * @return true on success, false on failure.
 */
bool Certificate::ExportPEM(std::string& out, Error* err) const noexcept {
#ifdef _WIN32
    out.clear();

    if (m_certContext == nullptr) {
        set_err(err, L"ExportPEM: no certificate loaded", ERROR_INVALID_HANDLE);
        return false;
    }

    // Validate encoded data
    if (m_certContext->pbCertEncoded == nullptr ||
        m_certContext->cbCertEncoded == 0) {
        set_err(err, L"ExportPEM: no encoded data available", ERROR_INVALID_DATA);
        return false;
    }

    // Query required buffer size
    DWORD charsNeeded = 0;
    if (!CryptBinaryToStringA(
        m_certContext->pbCertEncoded,
        m_certContext->cbCertEncoded,
        CRYPT_STRING_BASE64HEADER,
        nullptr,
        &charsNeeded)) {
        set_err(err, L"ExportPEM: size query failed", GetLastError());
        return false;
    }

    if (charsNeeded == 0) {
        set_err(err, L"ExportPEM: output size is zero", ERROR_INVALID_DATA);
        return false;
    }

    // Allocate buffer
    std::string pem;
    try {
        pem.resize(charsNeeded);
    }
    catch (const std::bad_alloc&) {
        set_err(err, L"ExportPEM: allocation failed", ERROR_OUTOFMEMORY);
        return false;
    }

    // Convert to PEM
    if (!CryptBinaryToStringA(
        m_certContext->pbCertEncoded,
        m_certContext->cbCertEncoded,
        CRYPT_STRING_BASE64HEADER,
        pem.data(),
        &charsNeeded)) {
        set_err(err, L"ExportPEM: conversion failed", GetLastError());
        return false;
    }

    // Trim to actual size (may include null terminator)
    if (charsNeeded > 0 && pem[charsNeeded - 1] == '\0') {
        pem.resize(charsNeeded - 1);
    }
    else {
        pem.resize(charsNeeded);
    }

    out = std::move(pem);
    return true;
#else
    (void)out;
    (void)err;
    return false;
#endif
}

// ============================================================================
// Certificate Property Methods
// ============================================================================

/**
 * @brief Gets the certificate thumbprint (hash).
 *
 * @param outHex Output string for hex-encoded thumbprint.
 * @param sha256 If true, use SHA-256 (32 bytes); otherwise SHA-1 (20 bytes).
 * @param err Optional error output.
 * @return true on success, false on failure.
 */
bool Certificate::GetThumbprint(std::wstring& outHex, bool sha256, Error* err) const noexcept {
#ifdef _WIN32
    outHex.clear();

    if (m_certContext == nullptr) {
        set_err(err, L"GetThumbprint: no certificate loaded", ERROR_INVALID_HANDLE);
        return false;
    }

    // Select property ID based on hash type
    const DWORD propId = sha256 ? CERT_SHA256_HASH_PROP_ID : CERT_HASH_PROP_ID;

    // Query required buffer size
    DWORD cb = 0;
    if (!CertGetCertificateContextProperty(m_certContext, propId, nullptr, &cb) || cb == 0) {
        set_err(err, L"GetThumbprint: size query failed", GetLastError());
        return false;
    }

    // Allocate buffer for hash
    std::vector<BYTE> hash;
    try {
        hash.resize(cb);
    }
    catch (const std::bad_alloc&) {
        set_err(err, L"GetThumbprint: allocation failed", ERROR_OUTOFMEMORY);
        return false;
    }

    // Get the hash
    if (!CertGetCertificateContextProperty(m_certContext, propId, hash.data(), &cb)) {
        set_err(err, L"GetThumbprint: property fetch failed", GetLastError());
        return false;
    }

    // Convert to hex string
    try {
        outHex.resize(cb * 2);
    }
    catch (const std::bad_alloc&) {
        set_err(err, L"GetThumbprint: hex allocation failed", ERROR_OUTOFMEMORY);
        return false;
    }

    for (DWORD i = 0; i < cb; ++i) {
        const BYTE b = hash[i];
        outHex[i * 2 + 0] = kHexChars[(b >> 4) & 0x0F];
        outHex[i * 2 + 1] = kHexChars[b & 0x0F];
    }

    return true;
#else
    (void)outHex;
    (void)sha256;
    (void)err;
    return false;
#endif
}

/**
 * @brief Retrieves comprehensive certificate information.
 *
 * Extracts subject, issuer, serial number, thumbprint, validity period,
 * basic constraints, and signature algorithm information.
 *
 * @param info Output structure to receive certificate info.
 * @param err Optional error output.
 * @return true on success, false on failure.
 */
bool Certificate::GetInfo(CertificateInfo& info, Error* err) const noexcept {
#ifdef _WIN32
    if (m_certContext == nullptr) {
        set_err(err, L"GetInfo: no certificate loaded", ERROR_INVALID_HANDLE);
        return false;
    }

    // Clear output structure
    info.Clear();

    // Validate cert info pointer
    if (m_certContext->pCertInfo == nullptr) {
        set_err(err, L"GetInfo: invalid certificate structure", ERROR_INVALID_DATA);
        return false;
    }

    // Extract Subject name
    DWORD charsNeeded = CertGetNameStringW(
        m_certContext,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        nullptr,
        nullptr,
        0
    );

    if (charsNeeded > 1) {
        try {
            std::wstring subject(charsNeeded, L'\0');
            CertGetNameStringW(
                m_certContext,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                nullptr,
                subject.data(),
                charsNeeded
            );
            // Remove null terminator from count
            if (charsNeeded > 0) {
                subject.resize(charsNeeded - 1);
            }
            info.subject = std::move(subject);
        }
        catch (const std::bad_alloc&) {
            // Continue with empty subject
        }
    }

    // Extract Issuer name
    charsNeeded = CertGetNameStringW(
        m_certContext,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        CERT_NAME_ISSUER_FLAG,
        nullptr,
        nullptr,
        0
    );

    if (charsNeeded > 1) {
        try {
            std::wstring issuer(charsNeeded, L'\0');
            CertGetNameStringW(
                m_certContext,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                CERT_NAME_ISSUER_FLAG,
                nullptr,
                issuer.data(),
                charsNeeded
            );
            if (charsNeeded > 0) {
                issuer.resize(charsNeeded - 1);
            }
            info.issuer = std::move(issuer);
        }
        catch (const std::bad_alloc&) {
            // Continue with empty issuer
        }
    }

    // Extract Serial Number (displayed in big-endian/most-significant-first)
    const DWORD cbSerial = m_certContext->pCertInfo->SerialNumber.cbData;
    if (cbSerial > 0 && m_certContext->pCertInfo->SerialNumber.pbData != nullptr) {
        try {
            std::wstring serial;
            serial.resize(cbSerial * 2);

            for (DWORD i = 0; i < cbSerial; ++i) {
                // Serial is stored little-endian, display big-endian
                const BYTE b = m_certContext->pCertInfo->SerialNumber.pbData[cbSerial - 1 - i];
                serial[i * 2 + 0] = kHexChars[(b >> 4) & 0x0F];
                serial[i * 2 + 1] = kHexChars[b & 0x0F];
            }
            info.serialNumber = std::move(serial);
        }
        catch (const std::bad_alloc&) {
            // Continue with empty serial
        }
    }

    // Get SHA-256 thumbprint (ignore errors)
    GetThumbprint(info.thumbprint, true, nullptr);

    // Validity period
    info.notBefore = m_certContext->pCertInfo->NotBefore;
    info.notAfter = m_certContext->pCertInfo->NotAfter;

    // Check if expired
    FILETIME ftNow{};
    SYSTEMTIME stNow{};
    GetSystemTime(&stNow);
    if (SystemTimeToFileTime(&stNow, &ftNow)) {
        if (CompareFileTime(&ftNow, &info.notAfter) > 0) {
            info.isExpired = true;
        }
    }

    // Check if self-signed (subject == issuer)
    // Note: CertCompareCertificate compares subject of first with issuer of second
    // To check self-signed, we compare the certificate's subject with its own issuer
    const DWORD subjectLen = m_certContext->pCertInfo->Subject.cbData;
    const DWORD issuerLen = m_certContext->pCertInfo->Issuer.cbData;
    if (subjectLen > 0 && subjectLen == issuerLen &&
        m_certContext->pCertInfo->Subject.pbData != nullptr &&
        m_certContext->pCertInfo->Issuer.pbData != nullptr) {
        info.isSelfSigned = (std::memcmp(
            m_certContext->pCertInfo->Subject.pbData,
            m_certContext->pCertInfo->Issuer.pbData,
            subjectLen) == 0);
    }

    // Parse Basic Constraints extension
    PCERT_EXTENSION extBC = CertFindExtension(
        szOID_BASIC_CONSTRAINTS2,
        m_certContext->pCertInfo->cExtension,
        m_certContext->pCertInfo->rgExtension
    );

    if (extBC != nullptr && extBC->Value.pbData != nullptr && extBC->Value.cbData > 0) {
        DWORD cb = 0;
        if (CryptDecodeObject(
            X509_ASN_ENCODING,
            X509_BASIC_CONSTRAINTS2,
            extBC->Value.pbData,
            extBC->Value.cbData,
            0,
            nullptr,
            &cb) && cb > 0) {

            try {
                std::vector<BYTE> buf(cb);
                if (CryptDecodeObject(
                    X509_ASN_ENCODING,
                    X509_BASIC_CONSTRAINTS2,
                    extBC->Value.pbData,
                    extBC->Value.cbData,
                    0,
                    buf.data(),
                    &cb)) {

                    auto* bc = reinterpret_cast<PCERT_BASIC_CONSTRAINTS2_INFO>(buf.data());
                    info.isCA = (bc->fCA != FALSE);
                    info.pathLenConstraint = bc->fPathLenConstraint
                        ? static_cast<int>(bc->dwPathLenConstraint)
                        : -1;
                }
            }
            catch (const std::bad_alloc&) {
                // Continue with defaults
            }
        }
    }

    // Get Signature Algorithm (OID -> friendly string)
    LPCSTR oid = m_certContext->pCertInfo->SignatureAlgorithm.pszObjId;
    if (oid != nullptr) {
        // Map common OIDs to friendly names
        if (std::strcmp(oid, szOID_RSA_SHA1RSA) == 0 ||
            std::strcmp(oid, szOID_OIWSEC_sha1RSASign) == 0) {
            info.signatureAlgorithm = L"RSA-SHA1";
        }
        else if (std::strcmp(oid, szOID_RSA_SHA256RSA) == 0) {
            info.signatureAlgorithm = L"RSA-SHA256";
        }
        else if (std::strcmp(oid, szOID_RSA_SHA384RSA) == 0) {
            info.signatureAlgorithm = L"RSA-SHA384";
        }
        else if (std::strcmp(oid, szOID_RSA_SHA512RSA) == 0) {
            info.signatureAlgorithm = L"RSA-SHA512";
        }
        else if (std::strcmp(oid, szOID_ECDSA_SHA256) == 0) {
            info.signatureAlgorithm = L"ECDSA-SHA256";
        }
        else if (std::strcmp(oid, szOID_ECDSA_SHA384) == 0) {
            info.signatureAlgorithm = L"ECDSA-SHA384";
        }
        else if (std::strcmp(oid, szOID_ECDSA_SHA512) == 0) {
            info.signatureAlgorithm = L"ECDSA-SHA512";
        }
        else if (std::strcmp(oid, szOID_RSA_MD5RSA) == 0) {
            info.signatureAlgorithm = L"RSA-MD5";
        }
        else if (std::strcmp(oid, szOID_RSA_MD2RSA) == 0) {
            info.signatureAlgorithm = L"RSA-MD2";
        }
        else if (std::strcmp(oid, szOID_RSA_PSS) == 0) {
            info.signatureAlgorithm = L"RSA-PSS";
        }
        else {
            info.signatureAlgorithm = L"UNKNOWN";
        }
    }

    return true;
#else
    (void)info;
    (void)err;
    return false;
#endif
}


/**
 * @brief Extracts Subject Alternative Names from the certificate.
 *
 * Parses the SAN extension and categorizes entries into DNS names,
 * IP addresses (IPv4/IPv6), and URLs.
 *
 * @param dns Output vector for DNS names.
 * @param ips Output vector for IP addresses (formatted strings).
 * @param urls Output vector for URLs.
 * @param err Optional error output.
 * @return true on success (including no SAN extension), false on decode error.
 */
bool Certificate::GetSubjectAltNames(std::vector<std::wstring>& dns,
    std::vector<std::wstring>& ips,
    std::vector<std::wstring>& urls,
    Error* err) const noexcept {
#ifdef _WIN32
    // Clear output vectors first
    dns.clear();
    ips.clear();
    urls.clear();

    if (m_certContext == nullptr) {
        set_err(err, L"GetSubjectAltNames: no certificate loaded", ERROR_INVALID_HANDLE);
        return false;
    }

    if (m_certContext->pCertInfo == nullptr) {
        set_err(err, L"GetSubjectAltNames: invalid certificate structure", ERROR_INVALID_DATA);
        return false;
    }

    // Find Subject Alternative Name extension
    PCERT_EXTENSION ext = CertFindExtension(
        szOID_SUBJECT_ALT_NAME2,
        m_certContext->pCertInfo->cExtension,
        m_certContext->pCertInfo->rgExtension
    );

    if (ext == nullptr) {
        // No SAN extension is not an error - many certificates don't have one
        return true;
    }

    // Validate extension data
    if (ext->Value.pbData == nullptr || ext->Value.cbData == 0) {
        // Empty SAN extension data - treat as no SAN
        return true;
    }

    // Get required buffer size for decode
    DWORD cbDecoded = 0;
    if (!CryptDecodeObject(
        X509_ASN_ENCODING,
        X509_ALTERNATE_NAME,
        ext->Value.pbData,
        ext->Value.cbData,
        0,
        nullptr,
        &cbDecoded)) {
        set_err(err, L"GetSubjectAltNames: decode size query failed", GetLastError());
        return false;
    }

    if (cbDecoded == 0 || cbDecoded > kMaxDecodedStructureSize) {
        set_err(err, L"GetSubjectAltNames: invalid decoded size", ERROR_INVALID_DATA);
        return false;
    }

    // Allocate buffer
    std::vector<BYTE> buf;
    try {
        buf.resize(cbDecoded);
    }
    catch (const std::bad_alloc&) {
        set_err(err, L"GetSubjectAltNames: allocation failed", ERROR_OUTOFMEMORY);
        return false;
    }

    // Decode the SAN extension
    if (!CryptDecodeObject(
        X509_ASN_ENCODING,
        X509_ALTERNATE_NAME,
        ext->Value.pbData,
        ext->Value.cbData,
        0,
        buf.data(),
        &cbDecoded)) {
        set_err(err, L"GetSubjectAltNames: decode failed", GetLastError());
        return false;
    }

    auto* names = reinterpret_cast<PCERT_ALT_NAME_INFO>(buf.data());
    if (names == nullptr || names->cAltEntry == 0) {
        // No entries - success with empty output
        return true;
    }

    // Sanity check entry count (prevent DoS)
    constexpr DWORD kMaxSanEntries = 10000;
    if (names->cAltEntry > kMaxSanEntries) {
        set_err(err, L"GetSubjectAltNames: excessive entry count", ERROR_INVALID_DATA);
        return false;
    }

    // Reserve space to reduce reallocations
    try {
        dns.reserve(names->cAltEntry);
        ips.reserve(16);  // Usually fewer IPs
        urls.reserve(16); // Usually fewer URLs
    }
    catch (const std::bad_alloc&) {
        // Continue without reservation - non-fatal
    }

    // Process each SAN entry
    for (DWORD i = 0; i < names->cAltEntry; ++i) {
        if (names->rgAltEntry == nullptr) {
            break;
        }

        const CERT_ALT_NAME_ENTRY& entry = names->rgAltEntry[i];

        try {
            switch (entry.dwAltNameChoice) {
            case CERT_ALT_NAME_DNS_NAME:
                if (entry.pwszDNSName != nullptr && entry.pwszDNSName[0] != L'\0') {
                    // Validate DNS name length
                    const size_t len = wcsnlen(entry.pwszDNSName, 256);
                    if (len > 0 && len < 256) {
                        dns.emplace_back(entry.pwszDNSName, len);
                    }
                }
                break;

            case CERT_ALT_NAME_URL:
                if (entry.pwszURL != nullptr && entry.pwszURL[0] != L'\0') {
                    // Validate URL length
                    const size_t len = wcsnlen(entry.pwszURL, 2048);
                    if (len > 0 && len < 2048) {
                        urls.emplace_back(entry.pwszURL, len);
                    }
                }
                break;

            case CERT_ALT_NAME_IP_ADDRESS:
                if (entry.IPAddress.pbData != nullptr) {
                    std::array<wchar_t, 64> ipStr{};

                    if (entry.IPAddress.cbData == 4) {
                        // IPv4 address
                        swprintf_s(ipStr.data(), ipStr.size(),
                            L"%u.%u.%u.%u",
                            static_cast<unsigned>(entry.IPAddress.pbData[0]),
                            static_cast<unsigned>(entry.IPAddress.pbData[1]),
                            static_cast<unsigned>(entry.IPAddress.pbData[2]),
                            static_cast<unsigned>(entry.IPAddress.pbData[3]));
                        ips.emplace_back(ipStr.data());
                    }
                    else if (entry.IPAddress.cbData == 16) {
                        // IPv6 address (full format)
                        swprintf_s(ipStr.data(), ipStr.size(),
                            L"%02X%02X:%02X%02X:%02X%02X:%02X%02X:"
                            L"%02X%02X:%02X%02X:%02X%02X:%02X%02X",
                            static_cast<unsigned>(entry.IPAddress.pbData[0]),
                            static_cast<unsigned>(entry.IPAddress.pbData[1]),
                            static_cast<unsigned>(entry.IPAddress.pbData[2]),
                            static_cast<unsigned>(entry.IPAddress.pbData[3]),
                            static_cast<unsigned>(entry.IPAddress.pbData[4]),
                            static_cast<unsigned>(entry.IPAddress.pbData[5]),
                            static_cast<unsigned>(entry.IPAddress.pbData[6]),
                            static_cast<unsigned>(entry.IPAddress.pbData[7]),
                            static_cast<unsigned>(entry.IPAddress.pbData[8]),
                            static_cast<unsigned>(entry.IPAddress.pbData[9]),
                            static_cast<unsigned>(entry.IPAddress.pbData[10]),
                            static_cast<unsigned>(entry.IPAddress.pbData[11]),
                            static_cast<unsigned>(entry.IPAddress.pbData[12]),
                            static_cast<unsigned>(entry.IPAddress.pbData[13]),
                            static_cast<unsigned>(entry.IPAddress.pbData[14]),
                            static_cast<unsigned>(entry.IPAddress.pbData[15]));
                        ips.emplace_back(ipStr.data());
                    }
                    // Ignore invalid IP address sizes
                }
                break;

            case CERT_ALT_NAME_RFC822_NAME:
            case CERT_ALT_NAME_X400_ADDRESS:
            case CERT_ALT_NAME_DIRECTORY_NAME:
            case CERT_ALT_NAME_EDI_PARTY_NAME:
            case CERT_ALT_NAME_REGISTERED_ID:
            case CERT_ALT_NAME_OTHER_NAME:
                // Skip unsupported entry types (can be extended if needed)
                break;

            default:
                // Unknown entry type - skip silently
                break;
            }
        }
        catch (const std::bad_alloc&) {
            // Memory allocation failed during emplace - continue processing
            continue;
        }
    }

    return true;
#else
    (void)dns;
    (void)ips;
    (void)urls;
    (void)err;
    return false;
#endif
}


/**
 * @brief Checks if the certificate is self-signed.
 *
 * Compares the certificate's subject and issuer distinguished names.
 * A true result indicates Subject == Issuer (self-signed).
 *
 * @return true if self-signed, false otherwise or if no cert loaded.
 */
bool Certificate::IsSelfSigned() const noexcept {
#ifdef _WIN32
    if (m_certContext == nullptr || m_certContext->pCertInfo == nullptr) {
        return false;
    }

    // Compare subject and issuer binary blobs directly
    // This is more reliable than CertCompareCertificate for self-signed check
    const DWORD subjectLen = m_certContext->pCertInfo->Subject.cbData;
    const DWORD issuerLen = m_certContext->pCertInfo->Issuer.cbData;

    if (subjectLen == 0 || subjectLen != issuerLen) {
        return false;
    }

    if (m_certContext->pCertInfo->Subject.pbData == nullptr ||
        m_certContext->pCertInfo->Issuer.pbData == nullptr) {
        return false;
    }

    return std::memcmp(
        m_certContext->pCertInfo->Subject.pbData,
        m_certContext->pCertInfo->Issuer.pbData,
        subjectLen) == 0;
#else
    return false;
#endif
}

/**
 * @brief Retrieves the path length constraint from Basic Constraints extension.
 *
 * The path length constraint limits the number of CA certificates that may
 * appear below this certificate in a valid chain.
 *
 * @return Path length constraint value, or -1 if not present/applicable.
 */
int Certificate::GetBasicConstraintsPathLen() const noexcept {
#ifdef _WIN32
    if (m_certContext == nullptr || m_certContext->pCertInfo == nullptr) {
        return -1;
    }

    // Find Basic Constraints extension
    PCERT_EXTENSION ext = CertFindExtension(
        szOID_BASIC_CONSTRAINTS2,
        m_certContext->pCertInfo->cExtension,
        m_certContext->pCertInfo->rgExtension
    );

    if (ext == nullptr || ext->Value.pbData == nullptr || ext->Value.cbData == 0) {
        return -1;
    }

    // Get decode buffer size
    DWORD cbDecoded = 0;
    if (!CryptDecodeObject(
        X509_ASN_ENCODING,
        X509_BASIC_CONSTRAINTS2,
        ext->Value.pbData,
        ext->Value.cbData,
        0,
        nullptr,
        &cbDecoded)) {
        return -1;
    }

    // Validate size
    if (cbDecoded == 0 || cbDecoded > kMaxDecodedStructureSize) {
        return -1;
    }

    // Allocate and decode
    std::vector<BYTE> buf;
    try {
        buf.resize(cbDecoded);
    }
    catch (const std::bad_alloc&) {
        return -1;
    }

    if (!CryptDecodeObject(
        X509_ASN_ENCODING,
        X509_BASIC_CONSTRAINTS2,
        ext->Value.pbData,
        ext->Value.cbData,
        0,
        buf.data(),
        &cbDecoded)) {
        return -1;
    }

    auto* bc = reinterpret_cast<PCERT_BASIC_CONSTRAINTS2_INFO>(buf.data());
    if (bc != nullptr && bc->fPathLenConstraint != FALSE) {
        return static_cast<int>(bc->dwPathLenConstraint);
    }

    return -1;
#else
    return -1;
#endif
}

/**
 * @brief Evaluates whether the certificate uses a strong signature algorithm.
 *
 * Strong algorithms include SHA-256/384/512 with RSA/ECDSA/RSA-PSS.
 * MD2 and MD5 are always rejected. SHA-1 is optional.
 *
 * @param allowSha1 If true, SHA-1 signatures are considered strong.
 * @return true if the signature algorithm is considered strong, false otherwise.
 */
bool Certificate::IsStrongSignatureAlgo(bool allowSha1) const noexcept {
#ifdef _WIN32
    if (m_certContext == nullptr || m_certContext->pCertInfo == nullptr) {
        return false;
    }

    LPCSTR oid = m_certContext->pCertInfo->SignatureAlgorithm.pszObjId;
    if (oid == nullptr || oid[0] == '\0') {
        return false;
    }

    // MD2 and MD5 are cryptographically broken - always reject
    if (std::strcmp(oid, szOID_RSA_MD2RSA) == 0 ||
        std::strcmp(oid, szOID_RSA_MD5RSA) == 0 ||
        std::strcmp(oid, szOID_RSA_MD2) == 0 ||
        std::strcmp(oid, szOID_RSA_MD5) == 0) {
        return false;
    }

    // SHA-1 has known collision attacks - allow only if explicitly permitted
    if (std::strcmp(oid, szOID_RSA_SHA1RSA) == 0 ||
        std::strcmp(oid, szOID_OIWSEC_sha1RSASign) == 0 ||
        std::strcmp(oid, szOID_ECDSA_SHA1) == 0 ||
        std::strcmp(oid, szOID_DSA_SHA1) == 0) {
        return allowSha1;
    }

    // SHA-256/384/512 family - considered strong
    if (std::strcmp(oid, szOID_RSA_SHA256RSA) == 0 ||
        std::strcmp(oid, szOID_RSA_SHA384RSA) == 0 ||
        std::strcmp(oid, szOID_RSA_SHA512RSA) == 0 ||
        std::strcmp(oid, szOID_ECDSA_SHA256) == 0 ||
        std::strcmp(oid, szOID_ECDSA_SHA384) == 0 ||
        std::strcmp(oid, szOID_ECDSA_SHA512) == 0 ||
        std::strcmp(oid, szOID_RSA_PSS) == 0) {
        return true;
    }

    // Unknown algorithm OID - conservative approach: treat as weak
    return false;
#else
    (void)allowSha1;
    return false;
#endif
}

/**
 * @brief Retrieves a human-readable signature algorithm name.
 *
 * Maps the OID to a friendly string representation.
 *
 * @param alg Output string for algorithm name.
 * @param err Optional error output.
 * @return true on success, false on failure.
 */
bool Certificate::GetSignatureAlgorithm(std::wstring& alg, Error* err) const noexcept {
#ifdef _WIN32
    alg.clear();

    if (m_certContext == nullptr) {
        set_err(err, L"GetSignatureAlgorithm: no certificate loaded", ERROR_INVALID_HANDLE);
        return false;
    }

    if (m_certContext->pCertInfo == nullptr) {
        set_err(err, L"GetSignatureAlgorithm: invalid certificate structure", ERROR_INVALID_DATA);
        return false;
    }

    LPCSTR oid = m_certContext->pCertInfo->SignatureAlgorithm.pszObjId;
    if (oid == nullptr || oid[0] == '\0') {
        set_err(err, L"GetSignatureAlgorithm: missing algorithm OID", ERROR_INVALID_DATA);
        return false;
    }

    // Map OID to friendly name
    // RSA signatures
    if (std::strcmp(oid, szOID_RSA_SHA256RSA) == 0) {
        alg = L"RSA-SHA256";
    }
    else if (std::strcmp(oid, szOID_RSA_SHA384RSA) == 0) {
        alg = L"RSA-SHA384";
    }
    else if (std::strcmp(oid, szOID_RSA_SHA512RSA) == 0) {
        alg = L"RSA-SHA512";
    }
    else if (std::strcmp(oid, szOID_RSA_SHA1RSA) == 0 ||
             std::strcmp(oid, szOID_OIWSEC_sha1RSASign) == 0) {
        alg = L"RSA-SHA1";
    }
    else if (std::strcmp(oid, szOID_RSA_MD5RSA) == 0) {
        alg = L"RSA-MD5";
    }
    else if (std::strcmp(oid, szOID_RSA_MD2RSA) == 0) {
        alg = L"RSA-MD2";
    }
    else if (std::strcmp(oid, szOID_RSA_PSS) == 0) {
        alg = L"RSA-PSS";
    }
    // ECDSA signatures
    else if (std::strcmp(oid, szOID_ECDSA_SHA256) == 0) {
        alg = L"ECDSA-SHA256";
    }
    else if (std::strcmp(oid, szOID_ECDSA_SHA384) == 0) {
        alg = L"ECDSA-SHA384";
    }
    else if (std::strcmp(oid, szOID_ECDSA_SHA512) == 0) {
        alg = L"ECDSA-SHA512";
    }
    else if (std::strcmp(oid, szOID_ECDSA_SHA1) == 0) {
        alg = L"ECDSA-SHA1";
    }
    // DSA signatures
    else if (std::strcmp(oid, szOID_DSA_SHA1) == 0 ||
             std::strcmp(oid, szOID_X957_SHA1DSA) == 0) {
        alg = L"DSA-SHA1";
    }
    // Unknown OID
    else {
        alg = L"UNKNOWN";
    }

    return true;
#else
    (void)alg;
    (void)err;
    return false;
#endif
}


/**
 * @brief Verifies a digital signature using the certificate's public key.
 *
 * Uses BCrypt for SHA-256 hashing and NCrypt for signature verification.
 * Supports RSA and ECC signature algorithms.
 *
 * @param data Pointer to data that was signed.
 * @param dataLen Length of data in bytes.
 * @param signature Pointer to signature bytes.
 * @param signatureLen Length of signature in bytes.
 * @param err Optional error output.
 * @return true if signature is valid, false otherwise.
 *
 * @note This uses the certificate's public key to verify, not the private key.
 *       The function name is somewhat misleading as it acquires the key differently.
 */
bool Certificate::VerifySignature(const uint8_t* data, size_t dataLen,
    const uint8_t* signature, size_t signatureLen,
    Error* err) const noexcept {
#ifdef _WIN32
    if (m_certContext == nullptr) {
        set_err(err, L"VerifySignature: no certificate loaded", ERROR_INVALID_HANDLE);
        return false;
    }

    // Validate input parameters
    if (data == nullptr || dataLen == 0) {
        set_err(err, L"VerifySignature: invalid data parameter", ERROR_INVALID_PARAMETER);
        return false;
    }

    if (signature == nullptr || signatureLen == 0) {
        set_err(err, L"VerifySignature: invalid signature parameter", ERROR_INVALID_PARAMETER);
        return false;
    }

    // Sanity check sizes to prevent integer overflow
    if (dataLen > kMaxFileSize || signatureLen > kMaxCertificateSize) {
        set_err(err, L"VerifySignature: data or signature too large", ERROR_INVALID_PARAMETER);
        return false;
    }

    // Acquire public key handle from certificate
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey = 0;
    DWORD dwKeySpec = 0;
    BOOL fCallerFree = FALSE;

    if (!CryptAcquireCertificatePrivateKey(
        m_certContext,
        CRYPT_ACQUIRE_COMPARE_KEY_FLAG | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
        nullptr,
        &hKey,
        &dwKeySpec,
        &fCallerFree)) {
        set_err(err, L"VerifySignature: failed to acquire key handle", GetLastError());
        return false;
    }

    // RAII guard for key handle
    struct KeyGuard {
        NCRYPT_KEY_HANDLE h;
        BOOL free;
        ~KeyGuard() { if (free && h != 0) NCryptFreeObject(h); }
    } keyGuard{ hKey, fCallerFree };

    // Open SHA-256 algorithm provider
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_SHA256_ALGORITHM,
        nullptr,
        0
    );

    if (status != 0 || hAlg == nullptr) {
        set_err(err, L"VerifySignature: BCryptOpenAlgorithmProvider failed", static_cast<DWORD>(status));
        return false;
    }

    // RAII guard for algorithm handle
    struct AlgGuard {
        BCRYPT_ALG_HANDLE h;
        ~AlgGuard() { if (h != nullptr) BCryptCloseAlgorithmProvider(h, 0); }
    } algGuard{ hAlg };

    // Get hash size
    DWORD cbHash = 0;
    DWORD cbResult = 0;
    status = BCryptGetProperty(
        hAlg,
        BCRYPT_HASH_LENGTH,
        reinterpret_cast<PUCHAR>(&cbHash),
        sizeof(DWORD),
        &cbResult,
        0
    );

    if (status != 0 || cbHash == 0 || cbHash > 64) {
        set_err(err, L"VerifySignature: BCryptGetProperty failed", static_cast<DWORD>(status));
        return false;
    }

    // Allocate hash buffer
    std::vector<BYTE> hash;
    try {
        hash.resize(cbHash);
    }
    catch (const std::bad_alloc&) {
        set_err(err, L"VerifySignature: allocation failed", ERROR_OUTOFMEMORY);
        return false;
    }

    // Create hash object
    BCRYPT_HASH_HANDLE hHash = nullptr;
    status = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);

    if (status != 0 || hHash == nullptr) {
        set_err(err, L"VerifySignature: BCryptCreateHash failed", static_cast<DWORD>(status));
        return false;
    }

    // RAII guard for hash handle
    struct HashGuard {
        BCRYPT_HASH_HANDLE h;
        ~HashGuard() { if (h != nullptr) BCryptDestroyHash(h); }
    } hashGuard{ hHash };

    // Hash the data
    status = BCryptHashData(
        hHash,
        const_cast<PUCHAR>(data),
        static_cast<ULONG>(dataLen),
        0
    );

    if (status != 0) {
        set_err(err, L"VerifySignature: BCryptHashData failed", static_cast<DWORD>(status));
        return false;
    }

    // Finalize hash
    status = BCryptFinishHash(hHash, hash.data(), cbHash, 0);

    if (status != 0) {
        set_err(err, L"VerifySignature: BCryptFinishHash failed", static_cast<DWORD>(status));
        return false;
    }

    // Verify signature using NCrypt
    SECURITY_STATUS secStatus = NCryptVerifySignature(
        hKey,
        nullptr,
        hash.data(),
        cbHash,
        const_cast<PUCHAR>(signature),
        static_cast<ULONG>(signatureLen),
        0
    );

    if (secStatus != ERROR_SUCCESS) {
        set_err(err, L"VerifySignature: signature verification failed", static_cast<DWORD>(secStatus));
        return false;
    }

    return true;
#else
    (void)data;
    (void)dataLen;
    (void)signature;
    (void)signatureLen;
    (void)err;
    return false;
#endif
}

/**
 * @brief Verifies the certificate chain using standard Windows trust anchors.
 *
 * Builds a certificate chain and validates it against the Authenticode policy.
 * Can optionally verify at a specific time and with additional certificate stores.
 *
 * @param err Optional error output.
 * @param hAdditionalStore Optional additional certificate store for chain building.
 * @param chainFlags Flags for CertGetCertificateChain (e.g., CERT_CHAIN_REVOCATION_CHECK_*).
 * @param verificationTime Optional time for chain verification (nullptr = current time).
 * @param requiredEkuOid Optional required Extended Key Usage OID.
 * @return true if chain is valid, false otherwise.
 */
bool Certificate::VerifyChain(Error* err,
    HCERTSTORE hAdditionalStore,
    DWORD chainFlags,
    FILETIME* verificationTime,
    const char* requiredEkuOid) const noexcept {
#ifdef _WIN32
    if (m_certContext == nullptr) {
        set_err(err, L"VerifyChain: no certificate loaded", ERROR_INVALID_HANDLE);
        return false;
    }

    // Initialize chain parameters
    CERT_CHAIN_PARA chainPara{};
    chainPara.cbSize = sizeof(chainPara);

    // If EKU required, set up requested usage
    CERT_ENHKEY_USAGE enhkeyUsage{};
    LPSTR szOidArr[1] = { nullptr };

    if (requiredEkuOid != nullptr && requiredEkuOid[0] != '\0') {
        szOidArr[0] = const_cast<LPSTR>(requiredEkuOid);
        enhkeyUsage.cUsageIdentifier = 1;
        enhkeyUsage.rgpszUsageIdentifier = szOidArr;
        chainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
        chainPara.RequestedUsage.Usage = enhkeyUsage;
    }

    // Build certificate chain
    PCCERT_CHAIN_CONTEXT chainCtx = nullptr;
    if (!CertGetCertificateChain(
        nullptr,                // Use default chain engine
        m_certContext,
        verificationTime,
        hAdditionalStore,
        &chainPara,
        chainFlags,
        nullptr,                // Reserved
        &chainCtx)) {
        set_err(err, L"VerifyChain: CertGetCertificateChain failed", GetLastError());
        return false;
    }

    // RAII guard for chain context
    struct ChainGuard {
        PCCERT_CHAIN_CONTEXT ctx;
        ~ChainGuard() { if (ctx != nullptr) CertFreeCertificateChain(ctx); }
    } chainGuard{ chainCtx };

    // Verify chain trust status first
    if (chainCtx->TrustStatus.dwErrorStatus != CERT_TRUST_NO_ERROR) {
        // Detailed error message based on trust status
        if (chainCtx->TrustStatus.dwErrorStatus & CERT_TRUST_IS_NOT_TIME_VALID) {
            set_err(err, L"VerifyChain: certificate expired or not yet valid",
                static_cast<DWORD>(chainCtx->TrustStatus.dwErrorStatus));
        }
        else if (chainCtx->TrustStatus.dwErrorStatus & CERT_TRUST_IS_REVOKED) {
            set_err(err, L"VerifyChain: certificate has been revoked",
                static_cast<DWORD>(chainCtx->TrustStatus.dwErrorStatus));
        }
        else if (chainCtx->TrustStatus.dwErrorStatus & CERT_TRUST_IS_NOT_SIGNATURE_VALID) {
            set_err(err, L"VerifyChain: certificate signature is invalid",
                static_cast<DWORD>(chainCtx->TrustStatus.dwErrorStatus));
        }
        else if (chainCtx->TrustStatus.dwErrorStatus & CERT_TRUST_IS_UNTRUSTED_ROOT) {
            set_err(err, L"VerifyChain: untrusted root certificate",
                static_cast<DWORD>(chainCtx->TrustStatus.dwErrorStatus));
        }
        else {
            set_err(err, L"VerifyChain: chain trust status error",
                static_cast<DWORD>(chainCtx->TrustStatus.dwErrorStatus));
        }
        return false;
    }

    // Verify against Authenticode policy
    CERT_CHAIN_POLICY_PARA policyPara{};
    policyPara.cbSize = sizeof(policyPara);

    CERT_CHAIN_POLICY_STATUS policyStatus{};
    policyStatus.cbSize = sizeof(policyStatus);

    BOOL ok = CertVerifyCertificateChainPolicy(
        CERT_CHAIN_POLICY_AUTHENTICODE,
        chainCtx,
        &policyPara,
        &policyStatus
    );

    if (ok == FALSE || policyStatus.dwError != 0) {
        set_err(err, L"VerifyChain: Authenticode policy verification failed", policyStatus.dwError);
        return false;
    }

    return true;
#else
    (void)err;
    (void)hAdditionalStore;
    (void)chainFlags;
    (void)verificationTime;
    (void)requiredEkuOid;
    return false;
#endif
}

/**
 * @brief Verifies the certificate chain at a specific point in time.
 *
 * Convenience wrapper around VerifyChain() for time-based verification.
 *
 * @param verifyTime The time at which to verify the chain.
 * @param err Optional error output.
 * @param hAdditionalStore Optional additional certificate store.
 * @param chainFlags Chain building flags.
 * @param requiredEkuOid Optional required EKU OID.
 * @return true if chain is valid at the specified time, false otherwise.
 */
bool Certificate::VerifyChainAtTime(const FILETIME& verifyTime,
    Error* err,
    HCERTSTORE hAdditionalStore,
    DWORD chainFlags,
    const char* requiredEkuOid) const noexcept {
    // Use const_cast here as CertGetCertificateChain takes non-const FILETIME*
    // but does not modify it
    return VerifyChain(
        err,
        hAdditionalStore,
        chainFlags,
        const_cast<FILETIME*>(&verifyTime),
        requiredEkuOid
    );
}

/**
 * @brief Verifies the certificate chain using explicit trust anchors.
 *
 * Creates a custom chain engine with specified root and intermediate
 * certificate stores, useful for custom PKI deployments.
 *
 * @param hRootStore Certificate store containing trusted root certificates.
 * @param hIntermediateStore Certificate store containing intermediate CAs.
 * @param err Optional error output.
 * @param chainFlags Chain building flags.
 * @param verificationTime Optional verification time point.
 * @param requiredEkuOid Optional required Extended Key Usage OID.
 * @return true if chain is valid against the specified stores, false otherwise.
 */
bool Certificate::VerifyChainWithStore(HCERTSTORE hRootStore,
    HCERTSTORE hIntermediateStore,
    Error* err,
    DWORD chainFlags,
    const FILETIME* verificationTime,
    const char* requiredEkuOid) const noexcept {
#ifdef _WIN32
    if (m_certContext == nullptr) {
        set_err(err, L"VerifyChainWithStore: no certificate loaded", ERROR_INVALID_HANDLE);
        return false;
    }

    // At least one store should be provided
    if (hRootStore == nullptr && hIntermediateStore == nullptr) {
        set_err(err, L"VerifyChainWithStore: no stores provided", ERROR_INVALID_PARAMETER);
        return false;
    }

    // Configure custom chain engine
    CERT_CHAIN_ENGINE_CONFIG config{};
    config.cbSize = sizeof(config);
    config.hExclusiveRoot = hRootStore;

    // hExclusiveTrustStore is preferred over hExclusiveIntermediate in newer Windows
    // but we use what's available for compatibility
    if (hIntermediateStore != nullptr) {
        config.hExclusiveTrustedPeople = hIntermediateStore;
    }

    // Create custom chain engine
    HCERTCHAINENGINE hEngine = nullptr;
    if (CertCreateCertificateChainEngine(&config, &hEngine) != TRUE) {
        set_err(err, L"VerifyChainWithStore: CertCreateCertificateChainEngine failed", GetLastError());
        return false;
    }

    // RAII guard for chain engine
    struct EngineGuard {
        HCERTCHAINENGINE h;
        ~EngineGuard() { if (h != nullptr) CertFreeCertificateChainEngine(h); }
    } engineGuard{ hEngine };

    // Set up chain parameters with EKU if specified
    CERT_CHAIN_PARA chainPara{};
    chainPara.cbSize = sizeof(chainPara);

    CERT_ENHKEY_USAGE enhkeyUsage{};
    LPSTR szOidArr[1] = { nullptr };

    if (requiredEkuOid != nullptr && requiredEkuOid[0] != '\0') {
        szOidArr[0] = const_cast<LPSTR>(requiredEkuOid);
        enhkeyUsage.cUsageIdentifier = 1;
        enhkeyUsage.rgpszUsageIdentifier = szOidArr;
        chainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
        chainPara.RequestedUsage.Usage = enhkeyUsage;
    }

    // Build certificate chain
    PCCERT_CHAIN_CONTEXT chainCtx = nullptr;
    BOOL okChain = CertGetCertificateChain(
        hEngine,
        m_certContext,
        const_cast<LPFILETIME>(verificationTime),
        nullptr,                // No additional store (using engine stores)
        &chainPara,
        chainFlags,
        nullptr,                // Reserved
        &chainCtx
    );

    if (okChain == FALSE || chainCtx == nullptr) {
        set_err(err, L"VerifyChainWithStore: CertGetCertificateChain failed", GetLastError());
        return false;
    }

    // RAII guard for chain context
    struct ChainGuard {
        PCCERT_CHAIN_CONTEXT ctx;
        ~ChainGuard() { if (ctx != nullptr) CertFreeCertificateChain(ctx); }
    } chainGuard{ chainCtx };

    // Check trust status
    if (chainCtx->TrustStatus.dwErrorStatus != CERT_TRUST_NO_ERROR) {
        if (chainCtx->TrustStatus.dwErrorStatus & CERT_TRUST_IS_NOT_TIME_VALID) {
            set_err(err, L"VerifyChainWithStore: certificate expired or not yet valid",
                static_cast<DWORD>(chainCtx->TrustStatus.dwErrorStatus));
        }
        else if (chainCtx->TrustStatus.dwErrorStatus & CERT_TRUST_IS_REVOKED) {
            set_err(err, L"VerifyChainWithStore: certificate has been revoked",
                static_cast<DWORD>(chainCtx->TrustStatus.dwErrorStatus));
        }
        else if (chainCtx->TrustStatus.dwErrorStatus & CERT_TRUST_IS_UNTRUSTED_ROOT) {
            set_err(err, L"VerifyChainWithStore: untrusted root certificate",
                static_cast<DWORD>(chainCtx->TrustStatus.dwErrorStatus));
        }
        else {
            set_err(err, L"VerifyChainWithStore: chain trust status error",
                static_cast<DWORD>(chainCtx->TrustStatus.dwErrorStatus));
        }
        return false;
    }

    // Verify against Authenticode policy
    CERT_CHAIN_POLICY_PARA policyPara{};
    policyPara.cbSize = sizeof(policyPara);

    CERT_CHAIN_POLICY_STATUS policyStatus{};
    policyStatus.cbSize = sizeof(policyStatus);

    BOOL okPolicy = CertVerifyCertificateChainPolicy(
        CERT_CHAIN_POLICY_AUTHENTICODE,
        chainCtx,
        &policyPara,
        &policyStatus
    );

    if (okPolicy == FALSE || policyStatus.dwError != 0) {
        set_err(err, L"VerifyChainWithStore: Authenticode policy verification failed", policyStatus.dwError);
        return false;
    }

    return true;
#else
    (void)hRootStore;
    (void)hIntermediateStore;
    (void)err;
    (void)chainFlags;
    (void)verificationTime;
    (void)requiredEkuOid;
    return false;
#endif
}



/**
 * @brief Checks if the certificate has a specific Extended Key Usage.
 *
 * Searches the EKU extension for the specified OID.
 *
 * @param oid The OID string to search for (e.g., szOID_PKIX_KP_CODE_SIGNING).
 * @param err Optional error output.
 * @return true if the EKU is present, false otherwise.
 */
bool Certificate::HasEKU(const char* oid, Error* err) const noexcept {
#ifdef _WIN32
    if (m_certContext == nullptr) {
        set_err(err, L"HasEKU: no certificate loaded", ERROR_INVALID_HANDLE);
        return false;
    }

    if (oid == nullptr || oid[0] == '\0') {
        set_err(err, L"HasEKU: invalid OID parameter", ERROR_INVALID_PARAMETER);
        return false;
    }

    // Query required buffer size
    DWORD cbNeeded = 0;
    if (!CertGetEnhancedKeyUsage(m_certContext, 0, nullptr, &cbNeeded)) {
        const DWORD lastError = GetLastError();
        // CRYPT_E_NOT_FOUND means no EKU extension (common case)
        if (lastError == CRYPT_E_NOT_FOUND) {
            // No EKU extension means certificate allows any use
            return true;
        }
        set_err(err, L"HasEKU: size query failed", lastError);
        return false;
    }

    if (cbNeeded == 0 || cbNeeded > kMaxDecodedStructureSize) {
        set_err(err, L"HasEKU: invalid EKU data size", ERROR_INVALID_DATA);
        return false;
    }

    // Allocate buffer
    std::vector<BYTE> buf;
    try {
        buf.resize(cbNeeded);
    }
    catch (const std::bad_alloc&) {
        set_err(err, L"HasEKU: allocation failed", ERROR_OUTOFMEMORY);
        return false;
    }

    auto* pUsage = reinterpret_cast<PCERT_ENHKEY_USAGE>(buf.data());

    // Retrieve EKU data
    if (!CertGetEnhancedKeyUsage(m_certContext, 0, pUsage, &cbNeeded)) {
        set_err(err, L"HasEKU: retrieval failed", GetLastError());
        return false;
    }

    // Search for specified OID
    for (DWORD i = 0; i < pUsage->cUsageIdentifier; ++i) {
        if (pUsage->rgpszUsageIdentifier != nullptr &&
            pUsage->rgpszUsageIdentifier[i] != nullptr &&
            std::strcmp(pUsage->rgpszUsageIdentifier[i], oid) == 0) {
            return true;
        }
    }

    return false;
#else
    (void)oid;
    (void)err;
    return false;
#endif
}

/**
 * @brief Checks if the certificate has specific Key Usage bits set.
 *
 * The Key Usage extension defines the purpose of the public key.
 *
 * @param flags Key usage flags to check (e.g., CERT_DIGITAL_SIGNATURE_KEY_USAGE).
 * @param err Optional error output.
 * @return true if all specified usage bits are set, false otherwise.
 */
bool Certificate::HasKeyUsage(DWORD flags, Error* err) const noexcept {
#ifdef _WIN32
    if (m_certContext == nullptr) {
        set_err(err, L"HasKeyUsage: no certificate loaded", ERROR_INVALID_HANDLE);
        return false;
    }

    if (m_certContext->pCertInfo == nullptr) {
        set_err(err, L"HasKeyUsage: invalid certificate structure", ERROR_INVALID_DATA);
        return false;
    }

    if (flags == 0) {
        // No flags to check - trivially true
        return true;
    }

    // Get intended key usage (combines extension and cert policy)
    BYTE usage[2] = { 0, 0 };
    if (!CertGetIntendedKeyUsage(
        X509_ASN_ENCODING,
        m_certContext->pCertInfo,
        usage,
        sizeof(usage))) {
        const DWORD lastError = GetLastError();
        // No key usage extension means any use is allowed
        if (lastError == 0 || lastError == ERROR_SUCCESS) {
            return true;
        }
        set_err(err, L"HasKeyUsage: retrieval failed", lastError);
        return false;
    }

    // Key usage is a bit field (first byte contains most common bits)
    // Check if all requested bits are set
    const BYTE requestedBits = static_cast<BYTE>(flags & 0xFF);
    return (usage[0] & requestedBits) == requestedBits;
#else
    (void)flags;
    (void)err;
    return false;
#endif
}

/**
 * @brief Verifies that this certificate was signed by a specific CA certificate.
 *
 * Creates a temporary certificate store containing the CA certificate,
 * then builds a chain to verify the signing relationship.
 *
 * @param caCert The CA certificate that should have signed this certificate.
 * @param err Optional error output.
 * @return true if this certificate was signed by the CA, false otherwise.
 */
bool Certificate::VerifyAgainstCA(const Certificate& caCert, Error* err) const noexcept {
#ifdef _WIN32
    if (m_certContext == nullptr) {
        set_err(err, L"VerifyAgainstCA: no certificate loaded", ERROR_INVALID_HANDLE);
        return false;
    }

    if (caCert.m_certContext == nullptr) {
        set_err(err, L"VerifyAgainstCA: CA certificate not loaded", ERROR_INVALID_PARAMETER);
        return false;
    }

    // Create temporary in-memory certificate store
    HCERTSTORE hStore = CertOpenStore(
        CERT_STORE_PROV_MEMORY,
        0,
        0,
        CERT_STORE_CREATE_NEW_FLAG,
        nullptr
    );

    if (hStore == nullptr) {
        set_err(err, L"VerifyAgainstCA: CertOpenStore failed", GetLastError());
        return false;
    }

    // RAII guard for store
    struct StoreGuard {
        HCERTSTORE h;
        ~StoreGuard() { if (h != nullptr) CertCloseStore(h, 0); }
    } storeGuard{ hStore };

    // Add CA certificate to store as trusted root
    if (!CertAddCertificateContextToStore(
        hStore,
        caCert.m_certContext,
        CERT_STORE_ADD_ALWAYS,
        nullptr)) {
        set_err(err, L"VerifyAgainstCA: failed to add CA to store", GetLastError());
        return false;
    }

    // Configure chain engine to use our store as exclusive root
    CERT_CHAIN_ENGINE_CONFIG engineConfig{};
    engineConfig.cbSize = sizeof(engineConfig);
    engineConfig.hExclusiveRoot = hStore;

    HCERTCHAINENGINE hEngine = nullptr;
    if (CertCreateCertificateChainEngine(&engineConfig, &hEngine) != TRUE) {
        set_err(err, L"VerifyAgainstCA: CertCreateCertificateChainEngine failed", GetLastError());
        return false;
    }

    // RAII guard for chain engine
    struct EngineGuard {
        HCERTCHAINENGINE h;
        ~EngineGuard() { if (h != nullptr) CertFreeCertificateChainEngine(h); }
    } engineGuard{ hEngine };

    // Build certificate chain
    CERT_CHAIN_PARA chainPara{};
    chainPara.cbSize = sizeof(chainPara);

    PCCERT_CHAIN_CONTEXT chainCtx = nullptr;
    BOOL ok = CertGetCertificateChain(
        hEngine,
        m_certContext,
        nullptr,    // Current time
        nullptr,    // Additional store (not needed, using engine)
        &chainPara,
        0,          // No revocation checking for simple CA verification
        nullptr,    // Reserved
        &chainCtx
    );

    if (ok == FALSE || chainCtx == nullptr) {
        set_err(err, L"VerifyAgainstCA: chain build failed", GetLastError());
        return false;
    }

    // RAII guard for chain context
    struct ChainGuard {
        PCCERT_CHAIN_CONTEXT ctx;
        ~ChainGuard() { if (ctx != nullptr) CertFreeCertificateChain(ctx); }
    } chainGuard{ chainCtx };

    // Check trust status
    if (chainCtx->TrustStatus.dwErrorStatus != CERT_TRUST_NO_ERROR) {
        // Provide specific error information
        if (chainCtx->TrustStatus.dwErrorStatus & CERT_TRUST_IS_PARTIAL_CHAIN) {
            set_err(err, L"VerifyAgainstCA: certificate not signed by specified CA",
                static_cast<DWORD>(chainCtx->TrustStatus.dwErrorStatus));
        }
        else if (chainCtx->TrustStatus.dwErrorStatus & CERT_TRUST_IS_UNTRUSTED_ROOT) {
            set_err(err, L"VerifyAgainstCA: CA certificate not trusted as root",
                static_cast<DWORD>(chainCtx->TrustStatus.dwErrorStatus));
        }
        else if (chainCtx->TrustStatus.dwErrorStatus & CERT_TRUST_IS_NOT_SIGNATURE_VALID) {
            set_err(err, L"VerifyAgainstCA: signature verification failed",
                static_cast<DWORD>(chainCtx->TrustStatus.dwErrorStatus));
        }
        else {
            set_err(err, L"VerifyAgainstCA: chain verification failed",
                static_cast<DWORD>(chainCtx->TrustStatus.dwErrorStatus));
        }
        return false;
    }

    return true;
#else
    (void)caCert;
    (void)err;
    return false;
#endif
}

/**
 * @brief Checks the revocation status of the certificate.
 *
 * Attempts to verify revocation using CRL or OCSP depending on what
 * is available in the certificate's extensions.
 *
 * @param isRevoked Output: true if certificate is confirmed revoked.
 * @param reason Output: Human-readable status description.
 * @param err Optional error output.
 * @return true if revocation status was determined, false on check failure.
 *
 * @note May require network access for online revocation checking.
 */
bool Certificate::GetRevocationStatus(bool& isRevoked, std::wstring& reason, Error* err) const noexcept {
#ifdef _WIN32
    // Initialize outputs
    isRevoked = false;
    reason.clear();

    if (m_certContext == nullptr) {
        set_err(err, L"GetRevocationStatus: no certificate loaded", ERROR_INVALID_HANDLE);
        return false;
    }

    // Set up revocation check parameters
    CERT_REVOCATION_PARA revPara{};
    revPara.cbSize = sizeof(revPara);
    // Use default timeout and freshness settings

    // Set up revocation status structure
    CERT_REVOCATION_STATUS revStatus{};
    revStatus.cbSize = sizeof(revStatus);

    // CertVerifyRevocation expects void** for the certificate array
    // PCCERT_CONTEXT is const CERT_CONTEXT*, so we need to cast carefully
    void* certPtrs[1] = { const_cast<CERT_CONTEXT*>(m_certContext) };

    // Perform revocation check
    BOOL ok = CertVerifyRevocation(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        CERT_CONTEXT_REVOCATION_TYPE,
        1,
        certPtrs,
        CERT_VERIFY_REV_CHAIN_FLAG,
        &revPara,
        &revStatus
    );

    // Interpret results
    if (ok != FALSE) {
        // Check completed successfully
        if (revStatus.dwError == ERROR_SUCCESS) {
            reason = L"Certificate is not revoked";
            return true;
        }
    }

    // Handle specific revocation statuses
    switch (revStatus.dwError) {
    case CRYPT_E_REVOKED:
        isRevoked = true;
        reason = L"Certificate has been revoked";
        // Try to get more specific reason from dwReason field
        if (revStatus.dwReason != 0) {
            try {
                reason += L" (Reason: ";
                switch (revStatus.dwReason) {
                case CRL_REASON_KEY_COMPROMISE:
                    reason += L"Key Compromise";
                    break;
                case CRL_REASON_CA_COMPROMISE:
                    reason += L"CA Compromise";
                    break;
                case CRL_REASON_AFFILIATION_CHANGED:
                    reason += L"Affiliation Changed";
                    break;
                case CRL_REASON_SUPERSEDED:
                    reason += L"Superseded";
                    break;
                case CRL_REASON_CESSATION_OF_OPERATION:
                    reason += L"Cessation of Operation";
                    break;
                case CRL_REASON_CERTIFICATE_HOLD:
                    reason += L"Certificate Hold";
                    break;
                default:
                    reason += std::to_wstring(revStatus.dwReason);
                    break;
                }
                reason += L")";
            }
            catch (const std::bad_alloc&) {
                // Continue without reason detail
            }
        }
        return true;

    case CRYPT_E_NO_REVOCATION_CHECK:
        reason = L"No revocation information available (no CRL/OCSP endpoint)";
        return true;

    case CRYPT_E_REVOCATION_OFFLINE:
        reason = L"Revocation server is offline or unreachable";
        set_err(err, L"GetRevocationStatus: revocation server offline", revStatus.dwError);
        return false;

    case CRYPT_E_NO_REVOCATION_DLL:
        reason = L"No revocation handler available";
        return true;

    case CRYPT_E_NOT_IN_REVOCATION_DATABASE:
        reason = L"Certificate not found in revocation database";
        return true;

    default:
        // Unknown error during revocation check
        try {
            reason = L"Revocation check failed (error: 0x" +
                     std::to_wstring(revStatus.dwError) + L")";
        }
        catch (const std::bad_alloc&) {
            reason = L"Revocation check failed";
        }
        set_err(err, L"GetRevocationStatus: check failed", revStatus.dwError);
        return false;
    }
#else
    (void)isRevoked;
    (void)reason;
    (void)err;
    return false;
#endif
}


/**
 * @brief Parses and extracts the generation time from an RFC 3161 timestamp token.
 *
 * Decodes the PKCS#7 SignedData structure containing the TSTInfo to extract
 * the genTime field representing when the timestamp was created.
 *
 * @param tsToken Pointer to the RFC 3161 timestamp token (PKCS#7 SignedData).
 * @param len Length of the timestamp token in bytes.
 * @param outGenTime Output FILETIME for the extracted generation time.
 * @param err Optional error output.
 * @return true if timestamp was successfully parsed, false otherwise.
 *
 * @note This provides basic parsing; full RFC 3161 verification would require
 *       additional checks including TSA certificate validation and hash matching.
 */
bool Certificate::VerifyTimestampToken(const uint8_t* tsToken, size_t len,
    FILETIME& outGenTime, Error* err) const noexcept {
#ifdef _WIN32
    // Initialize output
    outGenTime = FILETIME{};

    // Validate input parameters
    if (tsToken == nullptr) {
        set_err(err, L"VerifyTimestampToken: null token pointer", ERROR_INVALID_PARAMETER);
        return false;
    }

    if (len == 0) {
        set_err(err, L"VerifyTimestampToken: empty token", ERROR_INVALID_PARAMETER);
        return false;
    }

    // Sanity check size (timestamp tokens shouldn't be huge)
    constexpr size_t kMaxTimestampTokenSize = 64 * 1024; // 64 KB
    if (len > kMaxTimestampTokenSize) {
        set_err(err, L"VerifyTimestampToken: token too large", ERROR_INVALID_PARAMETER);
        return false;
    }

    // Open cryptographic message for decoding
    HCRYPTMSG hMsg = CryptMsgOpenToDecode(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        0,
        0,
        nullptr,
        nullptr
    );

    if (hMsg == nullptr) {
        set_err(err, L"VerifyTimestampToken: CryptMsgOpenToDecode failed", GetLastError());
        return false;
    }

    // RAII guard for message handle
    struct MsgGuard {
        HCRYPTMSG h;
        ~MsgGuard() { if (h != nullptr) CryptMsgClose(h); }
    } msgGuard{ hMsg };

    // Feed the token data into the message
    BOOL updateOk = CryptMsgUpdate(
        hMsg,
        tsToken,
        static_cast<DWORD>(len),
        TRUE    // Final update
    );

    if (updateOk == FALSE) {
        set_err(err, L"VerifyTimestampToken: CryptMsgUpdate failed", GetLastError());
        return false;
    }

    // Get the inner content (TSTInfo structure)
    DWORD cbContent = 0;
    if (!CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, nullptr, &cbContent)) {
        set_err(err, L"VerifyTimestampToken: content size query failed", GetLastError());
        return false;
    }

    if (cbContent == 0 || cbContent > kMaxDecodedStructureSize) {
        set_err(err, L"VerifyTimestampToken: invalid content size", ERROR_INVALID_DATA);
        return false;
    }

    // Allocate buffer for content
    std::vector<BYTE> content;
    try {
        content.resize(cbContent);
    }
    catch (const std::bad_alloc&) {
        set_err(err, L"VerifyTimestampToken: allocation failed", ERROR_OUTOFMEMORY);
        return false;
    }

    // Retrieve the content
    if (!CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, content.data(), &cbContent)) {
        set_err(err, L"VerifyTimestampToken: content retrieval failed", GetLastError());
        return false;
    }

    // Decode the genTime from TSTInfo
    // Note: This is a simplified approach - full TSTInfo parsing would use
    // ASN.1 decoding of the SEQUENCE structure
    DWORD cbDecoded = 0;
    if (!CryptDecodeObject(
        X509_ASN_ENCODING,
        X509_CHOICE_OF_TIME,
        content.data(),
        cbContent,
        0,
        nullptr,
        &cbDecoded)) {
        set_err(err, L"VerifyTimestampToken: time decode size query failed", GetLastError());
        return false;
    }

    if (cbDecoded < sizeof(SYSTEMTIME) || cbDecoded > kMaxDecodedStructureSize) {
        set_err(err, L"VerifyTimestampToken: invalid decoded time size", ERROR_INVALID_DATA);
        return false;
    }

    // Allocate buffer for decoded time
    std::vector<BYTE> timeBuf;
    try {
        timeBuf.resize(cbDecoded);
    }
    catch (const std::bad_alloc&) {
        set_err(err, L"VerifyTimestampToken: time buffer allocation failed", ERROR_OUTOFMEMORY);
        return false;
    }

    // Decode the time
    if (!CryptDecodeObject(
        X509_ASN_ENCODING,
        X509_CHOICE_OF_TIME,
        content.data(),
        cbContent,
        0,
        timeBuf.data(),
        &cbDecoded)) {
        set_err(err, L"VerifyTimestampToken: time decode failed", GetLastError());
        return false;
    }

    // Convert SYSTEMTIME to FILETIME
    auto* st = reinterpret_cast<SYSTEMTIME*>(timeBuf.data());

    // Validate SYSTEMTIME before conversion
    if (st->wYear < 1601 || st->wYear > 9999 ||
        st->wMonth < 1 || st->wMonth > 12 ||
        st->wDay < 1 || st->wDay > 31 ||
        st->wHour > 23 || st->wMinute > 59 || st->wSecond > 59) {
        set_err(err, L"VerifyTimestampToken: invalid time values", ERROR_INVALID_DATA);
        return false;
    }

    if (!SystemTimeToFileTime(st, &outGenTime)) {
        set_err(err, L"VerifyTimestampToken: SystemTimeToFileTime failed", GetLastError());
        return false;
    }

    return true;
#else
    (void)tsToken;
    (void)len;
    (void)outGenTime;
    (void)err;
    return false;
#endif
}

/**
 * @brief Extracts the public key from the certificate.
 *
 * Exports the certificate's public key in CNG blob format for use
 * with cryptographic operations.
 *
 * @param outKey Output structure to receive the public key data.
 * @param err Optional error output.
 * @return true on success, false on failure.
 */
bool Certificate::ExtractPublicKey(ShadowStrike::Utils::CryptoUtils::PublicKey& outKey,
    Error* err) const noexcept {
#ifdef _WIN32
    if (m_certContext == nullptr) {
        set_err(err, L"ExtractPublicKey: no certificate loaded", ERROR_INVALID_HANDLE);
        return false;
    }

    // Acquire key handle from certificate
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey = 0;
    DWORD dwKeySpec = 0;
    BOOL fCallerFree = FALSE;

    if (!CryptAcquireCertificatePrivateKey(
        m_certContext,
        CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_COMPARE_KEY_FLAG,
        nullptr,
        &hKey,
        &dwKeySpec,
        &fCallerFree)) {
        set_err(err, L"ExtractPublicKey: failed to acquire key handle", GetLastError());
        return false;
    }

    // RAII guard for key handle
    struct KeyGuard {
        NCRYPT_KEY_HANDLE h;
        BOOL free;
        ~KeyGuard() { if (free && h != 0) NCryptFreeObject(h); }
    } keyGuard{ hKey, fCallerFree };

    // Query required buffer size for public key export
    DWORD cbBlob = 0;
    SECURITY_STATUS status = NCryptExportKey(
        hKey,
        0,
        BCRYPT_PUBLIC_KEY_BLOB,
        nullptr,
        nullptr,
        0,
        &cbBlob,
        0
    );

    if (status != ERROR_SUCCESS) {
        set_err(err, L"ExtractPublicKey: size query failed", static_cast<DWORD>(status));
        return false;
    }

    // Validate blob size
    if (cbBlob == 0 || cbBlob > kMaxDecodedStructureSize) {
        set_err(err, L"ExtractPublicKey: invalid key blob size", ERROR_INVALID_DATA);
        return false;
    }

    // Allocate buffer
    std::vector<BYTE> blob;
    try {
        blob.resize(cbBlob);
    }
    catch (const std::bad_alloc&) {
        set_err(err, L"ExtractPublicKey: allocation failed", ERROR_OUTOFMEMORY);
        return false;
    }

    // Export the public key
    status = NCryptExportKey(
        hKey,
        0,
        BCRYPT_PUBLIC_KEY_BLOB,
        nullptr,
        blob.data(),
        cbBlob,
        &cbBlob,
        0
    );

    if (status != ERROR_SUCCESS) {
        set_err(err, L"ExtractPublicKey: export failed", static_cast<DWORD>(status));
        return false;
    }

    // Transfer to output structure
    // Note: PublicKey::Import expects CryptoUtils::Error, but we have CertUtils::Error
    // We call Import without error output and handle failure generically
    ShadowStrike::Utils::CryptoUtils::Error cryptoErr;
    if (!ShadowStrike::Utils::CryptoUtils::PublicKey::Import(blob.data(), cbBlob, outKey, &cryptoErr)) {
        set_err(err, L"ExtractPublicKey: failed to import key data", ERROR_INVALID_DATA);
        return false;
    }

    return true;
#else
    (void)outKey;
    (void)err;
    return false;
#endif
}

/**
 * @brief Adopts an external certificate context.
 *
 * Duplicates the provided certificate context and takes ownership.
 * Any previously loaded certificate is released first.
 *
 * @param ctx The certificate context to adopt.
 * @return true if successfully attached, false if ctx was null or duplication failed.
 */
bool Certificate::Attach(PCCERT_CONTEXT ctx) noexcept {
#ifdef _WIN32
    // Release any existing certificate
    cleanup();

    if (ctx == nullptr) {
        return false;
    }

    // Duplicate the context (increases reference count)
    m_certContext = CertDuplicateCertificateContext(ctx);
    return m_certContext != nullptr;
#else
    (void)ctx;
    return false;
#endif
}

/**
 * @brief Releases ownership of the certificate context to the caller.
 *
 * The caller is responsible for calling CertFreeCertificateContext on
 * the returned pointer when done.
 *
 * @return The certificate context pointer (caller takes ownership), or nullptr.
 */
PCCERT_CONTEXT Certificate::Detach() noexcept {
#ifdef _WIN32
    PCCERT_CONTEXT ctx = m_certContext;
    m_certContext = nullptr;
    return ctx;
#else
    return nullptr;
#endif
}

/**
 * @brief Sets the revocation checking mode for chain verification.
 *
 * @param m The revocation mode to use.
 */
void Certificate::SetRevocationMode(RevocationMode m) noexcept {
    revocationMode_ = m;
}

/**
 * @brief Gets the current revocation checking mode.
 *
 * @return The current revocation mode.
 */
RevocationMode Certificate::GetRevocationMode() const noexcept {
    return revocationMode_;
}

/**
 * @brief Sets whether SHA-1 signatures are allowed in chain verification.
 *
 * SHA-1 has known weaknesses but may be required for compatibility
 * with older certificates.
 *
 * @param v true to allow SHA-1, false to reject (default).
 */
void Certificate::SetAllowSha1Weak(bool v) noexcept {
    allowSha1Weak_ = v;
}

/**
 * @brief Gets whether SHA-1 signatures are allowed.
 *
 * @return true if SHA-1 is allowed, false otherwise.
 */
bool Certificate::GetAllowSha1Weak() const noexcept {
    return allowSha1Weak_;
}
