#pragma once

#include <string>
#include <vector>
#include <cstdint>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
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
            // Errors and policy
            // ============================================================================

            struct Error {
                DWORD win32 = ERROR_SUCCESS;
                LONG ntstatus = 0;
                std::wstring message;
                std::wstring context;

                bool HasError() const noexcept { return win32 != ERROR_SUCCESS || ntstatus != 0; }
                void Clear() noexcept { win32 = ERROR_SUCCESS; ntstatus = 0; message.clear(); context.clear(); }
            };

            enum class RevocationMode {
                OnlineOnly,      // Enforce OCSP/CRL online checks
                OfflineAllowed,  // Use cache/offline if online unavailable
                Disabled         // Skip revocation checks (not recommended)
            };

            // ============================================================================
            // Metadata
            // ============================================================================

            struct CertificateInfo {
                std::wstring subject;
                std::wstring issuer;
                std::wstring serialNumber;
                std::wstring thumbprint; // SHA-256 by default
                FILETIME notBefore{};
                FILETIME notAfter{};
                std::vector<std::wstring> subjectAltNames; // Flattened view (DNS/IP/URL merged)
                bool isCA = false;
                bool isExpired = false;
                bool isRevoked = false;

                // Optional diagnostics
                bool isSelfSigned = false;
                int  pathLenConstraint = -1; // -1 if absent
                std::wstring signatureAlgorithm; // e.g., RSA-PSS, ECDSA P-256, etc.
            };

            // ============================================================================
            // Certificate object
            // ============================================================================

            class Certificate {
            public:
                Certificate() noexcept = default;
                ~Certificate();

                // No copy, allow move
                Certificate(const Certificate&) = delete;
                Certificate& operator=(const Certificate&) = delete;
                Certificate(Certificate&&) noexcept;
                Certificate& operator=(Certificate&&) noexcept;

                // -----------------------
                // Load / Export
                // -----------------------
                bool LoadFromFile(std::wstring_view path, Error* err = nullptr) noexcept;
                bool LoadFromMemory(const uint8_t* data, size_t len, Error* err = nullptr) noexcept;
                bool LoadFromStore(std::wstring_view storeName, std::wstring_view thumbprint, Error* err = nullptr) noexcept;
                bool LoadFromPEM(std::string_view pem, Error* err = nullptr) noexcept;

                bool Export(std::vector<uint8_t>& out, Error* err = nullptr) const noexcept;      // DER
                bool ExportPEM(std::string& out, Error* err = nullptr) const noexcept;            // PEM
                bool GetRawDER(std::vector<uint8_t>& out, Error* err = nullptr) const noexcept;   // Alias of Export

                // -----------------------
                // Properties / Info
                // -----------------------
                bool GetInfo(CertificateInfo& info, Error* err = nullptr) const noexcept;
                bool GetThumbprint(std::wstring& outHex, bool sha256 = true, Error* err = nullptr) const noexcept;
                bool GetSubjectAltNames(std::vector<std::wstring>& dns,
                    std::vector<std::wstring>& ips,
                    std::vector<std::wstring>& urls,
                    Error* err = nullptr) const noexcept;

                bool IsSelfSigned() const noexcept;
                int  GetBasicConstraintsPathLen() const noexcept;
                bool IsStrongSignatureAlgo(bool allowSha1 = false) const noexcept;
                bool GetSignatureAlgorithm(std::wstring& alg, Error* err = nullptr) const noexcept;

                // -----------------------
                // Verification (raw and chain)
                // -----------------------
                bool VerifySignature(const uint8_t* data, size_t dataLen,
                    const uint8_t* signature, size_t signatureLen,
                    Error* err = nullptr) const noexcept;

                // Chain verification (current time)
                bool VerifyChain(Error* err,
                    HCERTSTORE hAdditionalStore /*= nullptr*/,
                    DWORD chainFlags /*= CERT_CHAIN_REVOCATION_CHECK_CHAIN*/,
                    FILETIME* verificationTime /*= nullptr*/,
                    const char* requiredEkuOid /*= nullptr*/) const noexcept;

                // Policy-aware chain verification at a specific time
                bool VerifyChainAtTime(const FILETIME& verifyTime,
                    Error* err,
                    HCERTSTORE hAdditionalStore /*= nullptr*/,
                    DWORD chainFlags /*= CERT_CHAIN_REVOCATION_CHECK_CHAIN*/,
                    const char* requiredEkuOid /*= nullptr*/) const noexcept;

                // Rich store control: explicit roots/intermediates
                bool VerifyChainWithStore(HCERTSTORE hRootStore,
                    HCERTSTORE hIntermediateStore,
                    Error* err,
                    DWORD chainFlags /*= CERT_CHAIN_REVOCATION_CHECK_CHAIN*/,
                    const FILETIME* verificationTime /*= nullptr*/,
                    const char* requiredEkuOid /*= nullptr*/) const noexcept;

                // EKU / KeyUsage
                bool HasEKU(const char* oid, Error* err = nullptr) const noexcept; // e.g., "1.3.6.1.5.5.7.3.3" for Code Signing
                bool HasKeyUsage(DWORD flags, Error* err = nullptr) const noexcept; // e.g., CERT_DIGITAL_SIGNATURE_KEY_USAGE

                // CA verification
                bool VerifyAgainstCA(const Certificate& caCert, Error* err = nullptr) const noexcept;

                // Revocation diagnostics (best effort)
                bool GetRevocationStatus(bool& isRevoked, std::wstring& reason, Error* err = nullptr) const noexcept;

                // Timestamp token verify (RFC3161) — extracts genTime; token is DER-encoded PKCS#7
                bool VerifyTimestampToken(const uint8_t* tsToken, size_t len, FILETIME& outGenTime, Error* err = nullptr) const noexcept;

                // -----------------------
                // Public key extraction
                // -----------------------
                bool ExtractPublicKey(ShadowStrike::Utils::CryptoUtils::PublicKey& outKey, Error* err = nullptr) const noexcept;

                // -----------------------
                // Context management / Policy
                // -----------------------
                bool IsValid() const noexcept { return m_certContext != nullptr; }

#ifdef _WIN32
                bool Attach(PCCERT_CONTEXT ctx) noexcept; // Attach without taking ownership (or with refcount bump)
                PCCERT_CONTEXT Detach() noexcept;         // Detach and return raw context (caller owns)
#endif

                void SetRevocationMode(RevocationMode m) noexcept { revocationMode_ = m; }
                RevocationMode GetRevocationMode() const noexcept { return revocationMode_; }

                void SetAllowSha1Weak(bool v) noexcept { allowSha1Weak_ = v; }
                bool GetAllowSha1Weak() const noexcept { return allowSha1Weak_; }

            private:
#ifdef _WIN32
                PCCERT_CONTEXT m_certContext = nullptr;
#endif
                RevocationMode revocationMode_{ RevocationMode::OnlineOnly };
                bool allowSha1Weak_{ false };

                void cleanup() noexcept;
            };

        } // namespace CertUtils
    } // namespace Utils
} // namespace ShadowStrike
