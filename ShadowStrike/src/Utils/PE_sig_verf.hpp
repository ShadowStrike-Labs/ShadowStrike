#pragma once


#include <string>
#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#  include <bcrypt.h>
#  include <ncrypt.h>
#  include <wincrypt.h>
#include<winsafer.h>
#include<WinTrust.h>
#include<SoftPub.h>
#include<mscat.h>
#  pragma comment(lib, "bcrypt.lib")
#  pragma comment(lib, "ncrypt.lib")
#  pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")

#endif

#include"Logger.hpp"
#include"PE_sig_verf.hpp"
#include"CertUtils.hpp"

namespace ShadowStrike {
	namespace Utils {
		namespace pe_sig_utils {
			// ============================================================================
			// Digital Signature Verification (for malware detection)
			// ============================================================================

			struct SignatureInfo {
				bool isSigned = false;
				bool isVerified = false;
				std::wstring signerName;
				std::wstring signerEmail;
				std::wstring issuerName;
				std::wstring thumbprint;
				FILETIME signTime{};
				std::vector<ShadowStrike::Utils::CertUtils::CertificateInfo> certificateChain;
			};


			struct Error {
				DWORD win32 = ERROR_SUCCESS;
				LONG ntstatus = 0;
				std::wstring message;
				std::wstring context;

				bool HasError() const noexcept { return win32 != ERROR_SUCCESS || ntstatus != 0; }
				void Clear() noexcept { win32 = ERROR_SUCCESS; ntstatus = 0; message.clear(); context.clear(); }
			};

			enum class RevocationMode {
				OnlineOnly,
				OfflineAllowed,
				Disabled
			};


            class PEFileSignatureVerifier {
            public:
                // Verify PE file signature (for whitelisting trusted software)
                bool VerifyPESignature(std::wstring_view filePath,
                    SignatureInfo& info,
                    Error* err = nullptr) noexcept;

                // Verify catalog signature
                bool VerifyCatalogSignature(std::wstring_view catalogPath,
                    std::wstring_view fileHash,
                    SignatureInfo& info,
                    Error* err = nullptr) noexcept;

                // EKU checking helper
                bool CheckCodeSigningEKU(PCCERT_CONTEXT cert, Error* err) noexcept;

                // Validate signature timestamp
                bool ValidateTimestamp(const FILETIME& signTime,
                    PCCERT_CONTEXT cert,
                    Error* err) noexcept;

                // Online revocation check via OCSP/CRL (policy depends on revocationMode)
                bool CheckRevocationOnline(PCCERT_CONTEXT cert, Error* err) noexcept;

                // Chain validation against Authenticode policy (root trust, usage, time)
                bool ValidateCertificateChain(PCCERT_CONTEXT cert, Error* err) noexcept;

                // Verify embedded Authenticode signature (non-catalog)
                bool VerifyEmbeddedSignature(std::wstring_view filePath,
                    SignatureInfo& info,
                    Error* err = nullptr) noexcept;

                // Check catalog chain trust/policy for a given file hash
                bool ValidateCatalogChain(std::wstring_view catalogPath,
                    std::wstring_view fileHash,
                    Error* err = nullptr) noexcept;

                // Extract signer display name from cert
                bool GetSignerName(PCCERT_CONTEXT cert,
                    std::wstring& outName,
                    Error* err = nullptr) noexcept;

                // Extract issuer display name from cert
                bool GetIssuerName(PCCERT_CONTEXT cert,
                    std::wstring& outIssuer,
                    Error* err = nullptr) noexcept;

                // Compute SHA-1/256 thumbprint of cert (for allowlist)
                bool GetCertThumbprint(PCCERT_CONTEXT cert,
                    std::wstring& outHex,
                    Error* err = nullptr,
                    bool useSha256 = true) noexcept;

                // Handle nested/dual signatures (future-proof)
                bool VerifyNestedSignatures(std::wstring_view filePath,
                    std::vector<SignatureInfo>& infos,
                    Error* err = nullptr) noexcept;

                // Extract all signatures as metadata only (no trust decision)
                std::vector<SignatureInfo> ExtractAllSignatures(std::wstring_view filePath, Error* err = nullptr) noexcept;
                  

                // Policy controls
                void SetRevocationMode(RevocationMode mode) noexcept;
                RevocationMode GetRevocationMode() const noexcept;

                // Time validation window control (e.g., allow timestamp skew/grace)
                void SetTimestampGraceSeconds(uint32_t seconds) noexcept;
                uint32_t GetTimestampGraceSeconds() const noexcept;

                // Allow catalog usage when embedded signature missing
                void SetAllowCatalogFallback(bool v) noexcept;
                bool GetAllowCatalogFallback() const noexcept;

                // Allow multiple signatures verification
                void SetAllowMultipleSignatures(bool v) noexcept;
                bool GetAllowMultipleSignatures() const noexcept;

                // Allow weak algorithms (e.g., SHA-1) — default false for security
                void SetAllowWeakAlgos(bool v) noexcept;
                bool GetAllowWeakAlgos() const noexcept;

            private:
                // Internal helpers (stubs)
                bool LoadPrimarySigner(std::wstring_view filePath,
                    PCCERT_CONTEXT& outCert,
                    FILETIME* outSignTime,
                    Error* err = nullptr) noexcept;

                bool LoadCatalogSigner(std::wstring_view catalogPath,
                    PCCERT_CONTEXT& outCert,
                    Error* err = nullptr) noexcept;

                bool CheckEKUCodeSigningOid(PCCERT_CONTEXT cert) noexcept;

                bool CheckTimestampCounterSignatureFromMessage(HCRYPTMSG hMsg,
                    DWORD signerIndex,
                    FILETIME& outSignTime,
                    Error* err) noexcept;

                bool IsTimeValidWithGrace(const FILETIME& signTime) const noexcept;

                // Configuration/state
                RevocationMode revocationMode_{ RevocationMode::OnlineOnly };
                uint32_t tsGraceSeconds_{ 300 }; // 5 min default grace
                bool allowCatalogFallback_{ true };
                bool allowMultipleSignatures_{ false };
                bool allowWeakAlgos_{ false };
            };

		}//namespace pe_sig_utils
	}//namespace Utils
}//namespace ShadowStrike