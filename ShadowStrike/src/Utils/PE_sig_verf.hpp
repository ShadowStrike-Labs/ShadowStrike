/**
 * @file PE_sig_verf.hpp
 * @brief PE (Portable Executable) digital signature verification utilities.
 *
 * Provides enterprise-grade Authenticode signature verification for PE files,
 * including:
 * - Embedded signature verification (PKCS#7/Authenticode)
 * - Catalog signature verification (Windows catalog files)
 * - Certificate chain validation with revocation checking
 * - EKU (Extended Key Usage) validation for code signing
 * - Timestamp/countersignature validation
 * - Nested/dual signature support
 *
 * This module is critical for:
 * - Whitelisting trusted software based on digital signatures
 * - Detecting unsigned or tampered executables
 * - Validating publisher identity before execution
 *
 * @note Windows-specific implementation using WinTrust, CryptoAPI, and related APIs.
 * @note All verification functions are noexcept with error reporting via Error*.
 *
 * @copyright ShadowStrike Security Suite
 * @author ShadowStrike Security Team
 */

#pragma once

#include <string>
#include <vector>
#include <cstdint>

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
#  include <winsafer.h>
#  include <WinTrust.h>
#  include <SoftPub.h>
#  include <mscat.h>
#  pragma comment(lib, "bcrypt.lib")
#  pragma comment(lib, "ncrypt.lib")
#  pragma comment(lib, "crypt32.lib")
#  pragma comment(lib, "wintrust.lib")
#endif

#include "Logger.hpp"
#include "CertUtils.hpp"

namespace ShadowStrike {
	namespace Utils {
		namespace pe_sig_utils {

			// ============================================================================
			// Digital Signature Verification Structures
			// ============================================================================

			/**
			 * @brief Information about a digital signature on a PE file.
			 *
			 * Contains metadata extracted from Authenticode signatures including
			 * signer identity, verification status, and certificate chain.
			 */
			struct SignatureInfo {
				bool isSigned = false;           ///< File has a signature (may not be valid)
				bool isVerified = false;         ///< Signature is cryptographically valid
				bool isChainTrusted = false;     ///< Certificate chain is trusted
				bool isEKUValid = false;         ///< Code signing EKU is present
				bool isTimestampValid = false;   ///< Timestamp is valid
				bool isRevocationChecked = false; ///< Revocation status was checked
				std::wstring signerName;         ///< Signer display name
				std::wstring signerEmail;        ///< Signer email (if available)
				std::wstring issuerName;         ///< Certificate issuer name
				std::wstring thumbprint;         ///< Certificate thumbprint (SHA-256 hex)
				FILETIME signTime{};             ///< Signing timestamp
				std::vector<ShadowStrike::Utils::CertUtils::CertificateInfo> certificateChain; ///< Full chain
			};

			/**
			 * @brief Error information for signature verification operations.
			 */
			struct Error {
				DWORD win32 = ERROR_SUCCESS;     ///< Win32 error code
				LONG ntstatus = 0;               ///< NTSTATUS code (if applicable)
				std::wstring message;            ///< Human-readable error message
				std::wstring context;            ///< Context where error occurred

				/**
				 * @brief Checks if an error occurred.
				 * @return true if either win32 or ntstatus indicates an error
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

			/**
			 * @brief Certificate revocation checking mode.
			 */
			enum class RevocationMode {
				OnlineOnly,      ///< Require online OCSP/CRL check (strictest)
				OfflineAllowed,  ///< Allow cached CRL if online check fails
				Disabled         ///< Skip revocation checking (not recommended)
			};


			// ============================================================================
			// PE File Signature Verifier Class
			// ============================================================================

			/**
			 * @brief Enterprise-grade PE file digital signature verifier.
			 *
			 * Provides comprehensive Authenticode signature verification with
			 * configurable policies for revocation, timestamps, and algorithm strength.
			 *
			 * Usage:
			 * @code
			 * PEFileSignatureVerifier verifier;
			 * verifier.SetRevocationMode(RevocationMode::OnlineOnly);
			 * SignatureInfo info;
			 * Error err;
			 * if (verifier.VerifyPESignature(L"C:\\path\\to\\file.exe", info, &err)) {
			 *     // Signature is valid and trusted
			 * }
			 * @endcode
			 */
            class PEFileSignatureVerifier {
            public:
				// --- Primary Verification Methods ---

                /**
				 * @brief Verifies PE file signature (embedded Authenticode).
				 * @param filePath Path to the PE file
				 * @param info Output signature information
				 * @param err Optional error output
				 * @return true if signature is valid and trusted
				 */
                [[nodiscard]] bool VerifyPESignature(std::wstring_view filePath,
                    SignatureInfo& info,
                    Error* err = nullptr) noexcept;

                /**
				 * @brief Verifies catalog signature for a file hash.
				 * @param catalogPath Path to the catalog file
				 * @param fileHash Hex hash of the file to verify
				 * @param info Output signature information
				 * @param err Optional error output
				 * @return true if catalog signature is valid
				 */
                [[nodiscard]] bool VerifyCatalogSignature(std::wstring_view catalogPath,
                    std::wstring_view fileHash,
                    SignatureInfo& info,
                    Error* err = nullptr) noexcept;

				// --- Validation Helper Methods ---

                /**
				 * @brief Checks if certificate has code signing EKU.
				 * @param cert Certificate context to check
				 * @param err Optional error output
				 * @return true if code signing EKU is present
				 */
                [[nodiscard]] bool CheckCodeSigningEKU(PCCERT_CONTEXT cert, Error* err) noexcept;

                /**
				 * @brief Validates timestamp against certificate validity period.
				 * @param signTime Signing timestamp to validate
				 * @param cert Certificate context
				 * @param err Optional error output
				 * @return true if timestamp is within validity window (with grace)
				 */
                [[nodiscard]] bool ValidateTimestamp(const FILETIME& signTime,
                    PCCERT_CONTEXT cert,
                    Error* err) noexcept;

                /**
				 * @brief Performs online revocation check via OCSP/CRL.
				 * @param cert Certificate to check
				 * @param err Optional error output
				 * @return true if certificate is not revoked
				 */
                [[nodiscard]] bool CheckRevocationOnline(PCCERT_CONTEXT cert, Error* err) noexcept;

                /**
				 * @brief Validates certificate chain against Authenticode policy.
				 * @param cert Leaf certificate to validate
				 * @param err Optional error output
				 * @return true if chain is valid and trusted
				 */
                [[nodiscard]] bool ValidateCertificateChain(PCCERT_CONTEXT cert, Error* err) noexcept;

                /**
				 * @brief Verifies embedded Authenticode signature only.
				 * @param filePath Path to the PE file
				 * @param info Output signature information
				 * @param err Optional error output
				 * @return true if embedded signature is valid
				 */
                [[nodiscard]] bool VerifyEmbeddedSignature(std::wstring_view filePath,
                    SignatureInfo& info,
                    Error* err = nullptr) noexcept;

                /**
				 * @brief Validates catalog file's signer chain.
				 * @param catalogPath Path to catalog file
				 * @param fileHash Hash of member file (unused in chain validation)
				 * @param err Optional error output
				 * @return true if catalog signer chain is valid
				 */
                [[nodiscard]] bool ValidateCatalogChain(std::wstring_view catalogPath,
                    std::wstring_view fileHash,
                    Error* err = nullptr) noexcept;

				// --- Certificate Information Extraction ---

                /**
				 * @brief Extracts signer display name from certificate.
				 * @param cert Certificate context
				 * @param outName Output signer name
				 * @param err Optional error output
				 * @return true if name was extracted
				 */
                [[nodiscard]] bool GetSignerName(PCCERT_CONTEXT cert,
                    std::wstring& outName,
                    Error* err = nullptr) noexcept;

                /**
				 * @brief Extracts issuer display name from certificate.
				 * @param cert Certificate context
				 * @param outIssuer Output issuer name
				 * @param err Optional error output
				 * @return true if issuer was extracted
				 */
                [[nodiscard]] bool GetIssuerName(PCCERT_CONTEXT cert,
                    std::wstring& outIssuer,
                    Error* err = nullptr) noexcept;

                /**
				 * @brief Computes certificate thumbprint.
				 * @param cert Certificate context
				 * @param outHex Output hex-encoded thumbprint
				 * @param err Optional error output
				 * @param useSha256 Use SHA-256 (true) or SHA-1 (false)
				 * @return true if thumbprint was computed
				 */
                [[nodiscard]] bool GetCertThumbprint(PCCERT_CONTEXT cert,
                    std::wstring& outHex,
                    Error* err = nullptr,
                    bool useSha256 = true) noexcept;

				// --- Advanced Signature Operations ---

                /**
				 * @brief Verifies nested/dual signatures in PE file.
				 * @param filePath Path to PE file
				 * @param infos Output vector of signature information
				 * @param err Optional error output
				 * @return true if at least one signature is fully trusted
				 */
                [[nodiscard]] bool VerifyNestedSignatures(std::wstring_view filePath,
                    std::vector<SignatureInfo>& infos,
                    Error* err = nullptr) noexcept;

                /**
				 * @brief Extracts all signatures as metadata (no trust decision).
				 * @param filePath Path to PE file
				 * @param err Optional error output
				 * @return Vector of signature information
				 */
                [[nodiscard]] std::vector<SignatureInfo> ExtractAllSignatures(
					std::wstring_view filePath,
					Error* err = nullptr) noexcept;

				// --- Policy Configuration ---

                /**
				 * @brief Sets revocation checking mode.
				 */
                void SetRevocationMode(RevocationMode mode) noexcept;
				
				/**
				 * @brief Gets current revocation checking mode.
				 */
                [[nodiscard]] RevocationMode GetRevocationMode() const noexcept;

                /**
				 * @brief Sets timestamp grace period in seconds.
				 * @param seconds Grace period (default 300 = 5 minutes)
				 */
                void SetTimestampGraceSeconds(uint32_t seconds) noexcept;
				
				/**
				 * @brief Gets current timestamp grace period.
				 */
                [[nodiscard]] uint32_t GetTimestampGraceSeconds() const noexcept;

                /**
				 * @brief Enables/disables catalog fallback when embedded signature missing.
				 */
                void SetAllowCatalogFallback(bool v) noexcept;
				
				/**
				 * @brief Gets catalog fallback setting.
				 */
                [[nodiscard]] bool GetAllowCatalogFallback() const noexcept;

                /**
				 * @brief Enables/disables multiple signature verification.
				 */
                void SetAllowMultipleSignatures(bool v) noexcept;
				
				/**
				 * @brief Gets multiple signature setting.
				 */
                [[nodiscard]] bool GetAllowMultipleSignatures() const noexcept;

                /**
				 * @brief Enables/disables weak algorithms (SHA-1).
				 * @note Default is false for security - SHA-1 is deprecated.
				 */
                void SetAllowWeakAlgos(bool v) noexcept;
				
				/**
				 * @brief Gets weak algorithm setting.
				 */
                [[nodiscard]] bool GetAllowWeakAlgos() const noexcept;

            private:
				// --- Internal Helper Methods ---

                [[nodiscard]] bool LoadPrimarySigner(std::wstring_view filePath,
                    PCCERT_CONTEXT& outCert,
                    FILETIME* outSignTime,
                    Error* err = nullptr) noexcept;

                [[nodiscard]] bool LoadCatalogSigner(std::wstring_view catalogPath,
                    PCCERT_CONTEXT& outCert,
                    Error* err = nullptr) noexcept;

                [[nodiscard]] bool CheckEKUCodeSigningOid(PCCERT_CONTEXT cert) noexcept;

                [[nodiscard]] bool CheckTimestampCounterSignatureFromMessage(HCRYPTMSG hMsg,
                    DWORD signerIndex,
                    FILETIME& outSignTime,
                    Error* err) noexcept;

                [[nodiscard]] bool IsTimeValidWithGrace(const FILETIME& signTime) const noexcept;

				// --- Configuration State ---
                RevocationMode revocationMode_{ RevocationMode::OnlineOnly };
                uint32_t tsGraceSeconds_{ 300 };        ///< Timestamp grace (5 min default)
                bool allowCatalogFallback_{ true };     ///< Allow catalog when no embedded sig
                bool allowMultipleSignatures_{ false }; ///< Verify all nested signatures
                bool allowWeakAlgos_{ false };          ///< Allow SHA-1 (not recommended)
            };

		} // namespace pe_sig_utils
	} // namespace Utils
} // namespace ShadowStrike