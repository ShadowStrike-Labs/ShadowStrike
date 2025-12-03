/**
 * @file CertUtils.hpp
 * @brief X.509 Certificate Utilities for ShadowStrike Security Suite.
 *
 * Provides comprehensive X.509 certificate handling capabilities including:
 * - Loading certificates from files, memory, PEM strings, and Windows stores
 * - Certificate chain validation with configurable revocation checking
 * - Signature verification using certificate public keys
 * - Certificate metadata extraction (subject, issuer, SANs, EKUs, etc.)
 * - Timestamp token (RFC3161) verification
 * - Public key extraction for cryptographic operations
 *
 * @note Windows-only implementation using CryptoAPI and CNG.
 *
 * @copyright Copyright (c) 2025 ShadowStrike Security
 * @license Proprietary - All rights reserved
 *
 * SECURITY CONSIDERATIONS:
 * - All certificate operations use Windows CryptoAPI for trustworthiness
 * - Chain validation enforces revocation checks by default
 * - SHA-1 signatures are deprecated but can be explicitly allowed
 * - Memory is securely cleared where sensitive data is handled
 */

#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <cstdint>
#include <cstring>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#  include <bcrypt.h>
#  include <ncrypt.h>
#  include <wincrypt.h>
#  pragma comment(lib, "bcrypt.lib")
#  pragma comment(lib, "ncrypt.lib")
#  pragma comment(lib, "crypt32.lib")
#endif

#include "HashUtils.hpp"
#include "Logger.hpp"
#include "CryptoUtils.hpp"

namespace ShadowStrike {
    namespace Utils {
        namespace CertUtils {

            // ============================================================================
            // Error Reporting
            // ============================================================================

            /**
             * @brief Error information structure for certificate operations.
             *
             * Captures both Win32 and NTSTATUS error codes along with
             * descriptive messages for debugging and logging purposes.
             */
            struct Error {
                DWORD win32 = ERROR_SUCCESS;       ///< Win32 error code
                LONG ntstatus = 0;                 ///< NTSTATUS error code (if applicable)
                std::wstring message;              ///< Human-readable error message
                std::wstring context;              ///< Additional context information

                /**
                 * @brief Checks if an error has occurred.
                 * @return true if either win32 or ntstatus indicates an error.
                 */
                [[nodiscard]] bool HasError() const noexcept {
                    return win32 != ERROR_SUCCESS || ntstatus != 0;
                }

                /**
                 * @brief Clears all error information.
                 */
                void Clear() noexcept {
                    win32 = ERROR_SUCCESS;
                    ntstatus = 0;
                    message.clear();
                    context.clear();
                }
            };

            // ============================================================================
            // Policy Configuration
            // ============================================================================

            /**
             * @brief Certificate revocation checking mode.
             *
             * Controls how revocation status is verified during chain validation.
             */
            enum class RevocationMode {
                OnlineOnly,      ///< Enforce OCSP/CRL online checks (most secure)
                OfflineAllowed,  ///< Use cached data if online checks fail
                Disabled         ///< Skip revocation checks (NOT RECOMMENDED for production)
            };

            // ============================================================================
            // Certificate Metadata
            // ============================================================================

            /**
             * @brief Comprehensive certificate information structure.
             *
             * Contains all relevant metadata extracted from an X.509 certificate
             * for display, logging, and validation purposes.
             */
            struct CertificateInfo {
                std::wstring subject;                      ///< Subject distinguished name
                std::wstring issuer;                       ///< Issuer distinguished name
                std::wstring serialNumber;                 ///< Certificate serial number (hex)
                std::wstring thumbprint;                   ///< SHA-256 thumbprint by default
                FILETIME notBefore{};                      ///< Validity start time
                FILETIME notAfter{};                       ///< Validity end time
                std::vector<std::wstring> subjectAltNames; ///< Flattened SANs (DNS/IP/URL)
                bool isCA = false;                         ///< Is this a CA certificate?
                bool isExpired = false;                    ///< Has the certificate expired?
                bool isRevoked = false;                    ///< Is the certificate revoked?

                // Extended diagnostics
                bool isSelfSigned = false;                 ///< Self-signed certificate?
                int pathLenConstraint = -1;                ///< Basic Constraints pathLen (-1 if absent)
                std::wstring signatureAlgorithm;           ///< Signature algorithm (e.g., "sha256RSA")

                /**
                 * @brief Resets all fields to default values.
                 */
                void Clear() noexcept {
                    subject.clear();
                    issuer.clear();
                    serialNumber.clear();
                    thumbprint.clear();
                    notBefore = FILETIME{};
                    notAfter = FILETIME{};
                    subjectAltNames.clear();
                    isCA = false;
                    isExpired = false;
                    isRevoked = false;
                    isSelfSigned = false;
                    pathLenConstraint = -1;
                    signatureAlgorithm.clear();
                }
            };

            // ============================================================================
            // Certificate Class
            // ============================================================================

            /**
             * @brief RAII wrapper for X.509 certificate operations.
             *
             * Provides a comprehensive interface for loading, validating, and
             * extracting information from X.509 certificates using Windows CryptoAPI.
             *
             * Thread Safety: Instance methods are NOT thread-safe. Use external
             * synchronization if sharing Certificate objects between threads.
             *
             * @example
             * @code
             * Certificate cert;
             * CertUtils::Error err;
             * if (cert.LoadFromFile(L"server.crt", &err)) {
             *     CertificateInfo info;
             *     cert.GetInfo(info);
             *     // Use certificate...
             * }
             * @endcode
             */
            class Certificate final {
            public:
                /**
                 * @brief Default constructor - creates an empty certificate object.
                 */
                Certificate() noexcept = default;

                /**
                 * @brief Destructor - releases certificate context.
                 */
                ~Certificate();

                // Non-copyable
                Certificate(const Certificate&) = delete;
                Certificate& operator=(const Certificate&) = delete;

                // Movable
                Certificate(Certificate&& other) noexcept;
                Certificate& operator=(Certificate&& other) noexcept;

                // =================================================================
                // Loading Methods
                // =================================================================

                /**
                 * @brief Loads a certificate from a file (DER, PEM, or PKCS#7).
                 *
                 * @param path Path to the certificate file.
                 * @param err Optional error output.
                 * @return true on success, false on failure.
                 */
                [[nodiscard]] bool LoadFromFile(std::wstring_view path, Error* err = nullptr) noexcept;

                /**
                 * @brief Loads a certificate from memory (DER or PEM format).
                 *
                 * @param data Pointer to certificate data.
                 * @param len Length of data in bytes.
                 * @param err Optional error output.
                 * @return true on success, false on failure.
                 */
                [[nodiscard]] bool LoadFromMemory(const uint8_t* data, size_t len, Error* err = nullptr) noexcept;

                /**
                 * @brief Loads a certificate from Windows Certificate Store.
                 *
                 * @param storeName Store name (e.g., L"MY", L"ROOT", L"CA").
                 * @param thumbprint Certificate thumbprint (hex string, SHA-1).
                 * @param err Optional error output.
                 * @return true on success, false on failure.
                 */
                [[nodiscard]] bool LoadFromStore(std::wstring_view storeName, std::wstring_view thumbprint, Error* err = nullptr) noexcept;

                /**
                 * @brief Loads a certificate from a PEM-encoded string.
                 *
                 * @param pem PEM string containing the certificate.
                 * @param err Optional error output.
                 * @return true on success, false on failure.
                 */
                [[nodiscard]] bool LoadFromPEM(std::string_view pem, Error* err = nullptr) noexcept;

                // =================================================================
                // Export Methods
                // =================================================================

                /**
                 * @brief Exports the certificate in DER format.
                 *
                 * @param out Output buffer for DER-encoded certificate.
                 * @param err Optional error output.
                 * @return true on success, false on failure.
                 */
                [[nodiscard]] bool Export(std::vector<uint8_t>& out, Error* err = nullptr) const noexcept;

                /**
                 * @brief Exports the certificate in PEM format.
                 *
                 * @param out Output string for PEM-encoded certificate.
                 * @param err Optional error output.
                 * @return true on success, false on failure.
                 */
                [[nodiscard]] bool ExportPEM(std::string& out, Error* err = nullptr) const noexcept;

                /**
                 * @brief Gets the raw DER-encoded certificate (alias for Export).
                 *
                 * @param out Output buffer for DER-encoded certificate.
                 * @param err Optional error output.
                 * @return true on success, false on failure.
                 */
                [[nodiscard]] bool GetRawDER(std::vector<uint8_t>& out, Error* err = nullptr) const noexcept;

                // =================================================================
                // Property Methods
                // =================================================================

                /**
                 * @brief Retrieves comprehensive certificate information.
                 *
                 * @param info Output structure to receive certificate info.
                 * @param err Optional error output.
                 * @return true on success, false on failure.
                 */
                [[nodiscard]] bool GetInfo(CertificateInfo& info, Error* err = nullptr) const noexcept;

                /**
                 * @brief Gets the certificate thumbprint (hash).
                 *
                 * @param outHex Output string for hex-encoded thumbprint.
                 * @param sha256 If true, use SHA-256; otherwise SHA-1.
                 * @param err Optional error output.
                 * @return true on success, false on failure.
                 */
                [[nodiscard]] bool GetThumbprint(std::wstring& outHex, bool sha256 = true, Error* err = nullptr) const noexcept;

                /**
                 * @brief Extracts Subject Alternative Names from the certificate.
                 *
                 * @param dns Output vector for DNS names.
                 * @param ips Output vector for IP addresses.
                 * @param urls Output vector for URLs.
                 * @param err Optional error output.
                 * @return true on success, false on failure.
                 */
                [[nodiscard]] bool GetSubjectAltNames(
                    std::vector<std::wstring>& dns,
                    std::vector<std::wstring>& ips,
                    std::vector<std::wstring>& urls,
                    Error* err = nullptr) const noexcept;

                /**
                 * @brief Checks if the certificate is self-signed.
                 * @return true if self-signed, false otherwise.
                 */
                [[nodiscard]] bool IsSelfSigned() const noexcept;

                /**
                 * @brief Gets the Basic Constraints path length.
                 * @return Path length constraint, or -1 if not present.
                 */
                [[nodiscard]] int GetBasicConstraintsPathLen() const noexcept;

                /**
                 * @brief Checks if the certificate uses a strong signature algorithm.
                 *
                 * @param allowSha1 If true, SHA-1 is considered acceptable.
                 * @return true if strong algorithm, false otherwise.
                 */
                [[nodiscard]] bool IsStrongSignatureAlgo(bool allowSha1 = false) const noexcept;

                /**
                 * @brief Gets the signature algorithm name.
                 *
                 * @param alg Output string for algorithm name.
                 * @param err Optional error output.
                 * @return true on success, false on failure.
                 */
                [[nodiscard]] bool GetSignatureAlgorithm(std::wstring& alg, Error* err = nullptr) const noexcept;

                // =================================================================
                // Verification Methods
                // =================================================================

                /**
                 * @brief Verifies a signature using the certificate's public key.
                 *
                 * @param data Data that was signed.
                 * @param dataLen Length of data in bytes.
                 * @param signature Signature to verify.
                 * @param signatureLen Length of signature in bytes.
                 * @param err Optional error output.
                 * @return true if signature is valid, false otherwise.
                 */
                [[nodiscard]] bool VerifySignature(
                    const uint8_t* data, size_t dataLen,
                    const uint8_t* signature, size_t signatureLen,
                    Error* err = nullptr) const noexcept;

                /**
                 * @brief Verifies the certificate chain.
                 *
                 * @param err Optional error output.
                 * @param hAdditionalStore Additional certificate store (optional).
                 * @param chainFlags Chain building flags.
                 * @param verificationTime Time to verify at (nullptr = now).
                 * @param requiredEkuOid Required EKU OID (optional).
                 * @return true if chain is valid, false otherwise.
                 */
                [[nodiscard]] bool VerifyChain(
                    Error* err,
                    HCERTSTORE hAdditionalStore,
                    DWORD chainFlags,
                    FILETIME* verificationTime,
                    const char* requiredEkuOid) const noexcept;

                /**
                 * @brief Verifies the certificate chain at a specific time.
                 *
                 * @param verifyTime Time to verify the chain at.
                 * @param err Optional error output.
                 * @param hAdditionalStore Additional certificate store.
                 * @param chainFlags Chain building flags.
                 * @param requiredEkuOid Required EKU OID.
                 * @return true if chain is valid, false otherwise.
                 */
                [[nodiscard]] bool VerifyChainAtTime(
                    const FILETIME& verifyTime,
                    Error* err,
                    HCERTSTORE hAdditionalStore,
                    DWORD chainFlags,
                    const char* requiredEkuOid) const noexcept;

                /**
                 * @brief Verifies chain with explicit root and intermediate stores.
                 *
                 * @param hRootStore Store containing trusted root certificates.
                 * @param hIntermediateStore Store containing intermediate certificates.
                 * @param err Optional error output.
                 * @param chainFlags Chain building flags.
                 * @param verificationTime Time to verify at.
                 * @param requiredEkuOid Required EKU OID.
                 * @return true if chain is valid, false otherwise.
                 */
                [[nodiscard]] bool VerifyChainWithStore(
                    HCERTSTORE hRootStore,
                    HCERTSTORE hIntermediateStore,
                    Error* err,
                    DWORD chainFlags,
                    const FILETIME* verificationTime,
                    const char* requiredEkuOid) const noexcept;

                /**
                 * @brief Checks if the certificate has a specific Enhanced Key Usage.
                 *
                 * @param oid EKU OID string (e.g., "1.3.6.1.5.5.7.3.3" for Code Signing).
                 * @param err Optional error output.
                 * @return true if EKU is present, false otherwise.
                 */
                [[nodiscard]] bool HasEKU(const char* oid, Error* err = nullptr) const noexcept;

                /**
                 * @brief Checks if the certificate has specific Key Usage flags.
                 *
                 * @param flags Key usage flags (e.g., CERT_DIGITAL_SIGNATURE_KEY_USAGE).
                 * @param err Optional error output.
                 * @return true if all specified flags are present, false otherwise.
                 */
                [[nodiscard]] bool HasKeyUsage(DWORD flags, Error* err = nullptr) const noexcept;

                /**
                 * @brief Verifies this certificate against a CA certificate.
                 *
                 * @param caCert The CA certificate to verify against.
                 * @param err Optional error output.
                 * @return true if verification succeeds, false otherwise.
                 */
                [[nodiscard]] bool VerifyAgainstCA(const Certificate& caCert, Error* err = nullptr) const noexcept;

                /**
                 * @brief Gets the revocation status of the certificate.
                 *
                 * @param isRevoked Output: true if revoked.
                 * @param reason Output: revocation reason string.
                 * @param err Optional error output.
                 * @return true on successful query, false on failure.
                 */
                [[nodiscard]] bool GetRevocationStatus(bool& isRevoked, std::wstring& reason, Error* err = nullptr) const noexcept;

                /**
                 * @brief Verifies an RFC3161 timestamp token.
                 *
                 * @param tsToken DER-encoded PKCS#7 timestamp token.
                 * @param len Length of token in bytes.
                 * @param outGenTime Output: generation time from token.
                 * @param err Optional error output.
                 * @return true if token is valid, false otherwise.
                 */
                [[nodiscard]] bool VerifyTimestampToken(
                    const uint8_t* tsToken, size_t len,
                    FILETIME& outGenTime,
                    Error* err = nullptr) const noexcept;

                // =================================================================
                // Key Extraction
                // =================================================================

                /**
                 * @brief Extracts the public key from the certificate.
                 *
                 * @param outKey Output: public key object.
                 * @param err Optional error output.
                 * @return true on success, false on failure.
                 */
                [[nodiscard]] bool ExtractPublicKey(
                    ShadowStrike::Utils::CryptoUtils::PublicKey& outKey,
                    Error* err = nullptr) const noexcept;

                // =================================================================
                // State Management
                // =================================================================

                /**
                 * @brief Checks if the certificate object holds a valid certificate.
                 * @return true if a certificate is loaded, false otherwise.
                 */
                [[nodiscard]] bool IsValid() const noexcept {
#ifdef _WIN32
                    return m_certContext != nullptr;
#else
                    return false;
#endif
                }

#ifdef _WIN32
                /**
                 * @brief Attaches an external certificate context.
                 *
                 * Takes ownership by duplicating the reference count.
                 *
                 * @param ctx Certificate context to attach.
                 * @return true on success, false on failure.
                 */
                [[nodiscard]] bool Attach(PCCERT_CONTEXT ctx) noexcept;

                /**
                 * @brief Detaches and returns the certificate context.
                 *
                 * Caller takes ownership and must call CertFreeCertificateContext.
                 *
                 * @return The certificate context, or nullptr if none.
                 */
                [[nodiscard]] PCCERT_CONTEXT Detach() noexcept;

                /**
                 * @brief Gets the raw certificate context (does NOT transfer ownership).
                 * @return The certificate context, or nullptr if none.
                 */
                [[nodiscard]] PCCERT_CONTEXT GetContext() const noexcept {
                    return m_certContext;
                }
#endif

                // =================================================================
                // Policy Configuration
                // =================================================================

                /**
                 * @brief Sets the revocation checking mode.
                 * @param mode The revocation mode to use.
                 */
                void SetRevocationMode(RevocationMode mode) noexcept {
                    revocationMode_ = mode;
                }

                /**
                 * @brief Gets the current revocation checking mode.
                 * @return Current revocation mode.
                 */
                [[nodiscard]] RevocationMode GetRevocationMode() const noexcept {
                    return revocationMode_;
                }

                /**
                 * @brief Sets whether SHA-1 signatures are allowed.
                 * @param allow true to allow SHA-1, false to reject.
                 */
                void SetAllowSha1Weak(bool allow) noexcept {
                    allowSha1Weak_ = allow;
                }

                /**
                 * @brief Gets whether SHA-1 signatures are allowed.
                 * @return true if SHA-1 is allowed, false otherwise.
                 */
                [[nodiscard]] bool GetAllowSha1Weak() const noexcept {
                    return allowSha1Weak_;
                }

            private:
#ifdef _WIN32
                PCCERT_CONTEXT m_certContext = nullptr;  ///< Windows certificate context
#endif
                RevocationMode revocationMode_{ RevocationMode::OnlineOnly };  ///< Revocation check mode
                bool allowSha1Weak_{ false };  ///< Allow weak SHA-1 signatures

                /**
                 * @brief Releases the certificate context and resets state.
                 */
                void cleanup() noexcept;
            };

        } // namespace CertUtils
    } // namespace Utils
} // namespace ShadowStrike
