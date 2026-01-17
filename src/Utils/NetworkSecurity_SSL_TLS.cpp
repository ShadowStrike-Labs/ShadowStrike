// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

#include"pch.h"
#include"NetworkUtils.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cctype>
#include <cstring>
#include <fstream>
#include <WinInet.h>
#include <dhcpcsdk.h>
#include <wincrypt.h>

namespace ShadowStrike {
	namespace Utils {
		namespace NetworkUtils {


			// ============================================================================
			// Internal Helper Functions
			// ============================================================================

			namespace Internal {

				inline void SetError(Error* err, DWORD win32, std::wstring_view msg, std::wstring_view ctx = L"") {
					if (err) {
						err->win32 = win32;
						err->message = msg;
						err->context = ctx;
					}
				}

				inline void SetWsaError(Error* err, int wsaErr, std::wstring_view ctx = L"") {
					if (err) {
						err->wsaError = wsaErr;
						err->win32 = wsaErr;
						err->message = FormatWsaError(wsaErr);
						err->context = ctx;
					}
				}

				inline bool IsWhitespace(wchar_t c) noexcept {
					return c == L' ' || c == L'\t' || c == L'\r' || c == L'\n';
				}

				inline std::wstring_view TrimWhitespace(std::wstring_view str) noexcept {
					size_t start = 0;
					while (start < str.size() && IsWhitespace(str[start])) ++start;
					size_t end = str.size();
					while (end > start && IsWhitespace(str[end - 1])) --end;
					return str.substr(start, end - start);
				}

				inline bool EqualsIgnoreCase(std::wstring_view a, std::wstring_view b) noexcept {
					if (a.size() != b.size()) return false;
					return std::equal(a.begin(), a.end(), b.begin(), b.end(),
						[](wchar_t ca, wchar_t cb) {
							return ::towlower(ca) == ::towlower(cb);
						});
				}

				inline uint16_t NetworkToHost16(uint16_t net) noexcept {
					return ntohs(net);
				}

				inline uint32_t NetworkToHost32(uint32_t net) noexcept {
					return ntohl(net);
				}

				inline uint16_t HostToNetwork16(uint16_t host) noexcept {
					return htons(host);
				}

				inline uint32_t HostToNetwork32(uint32_t host) noexcept {
					return htonl(host);
				}

			} // namespace Internal



			// ============================================================================
			// Network Security (SSL/TLS)
			// ============================================================================
			namespace {
				// Helper to convert FILETIME to system_clock::time_point
				inline std::chrono::system_clock::time_point FileTimeToTimePoint(const FILETIME& ft) noexcept {
					ULARGE_INTEGER uli;
					uli.LowPart = ft.dwLowDateTime;
					uli.HighPart = ft.dwHighDateTime;

					// FILETIME is 100-nanosecond intervals since January 1, 1601 UTC
					// Convert to system_clock epoch (January 1, 1970 UTC)
					constexpr uint64_t EPOCH_DIFFERENCE = 116444736000000000ULL;

					if (uli.QuadPart < EPOCH_DIFFERENCE) {
						return std::chrono::system_clock::time_point{};
					}

					uint64_t microseconds = (uli.QuadPart - EPOCH_DIFFERENCE) / 10;
					return std::chrono::system_clock::time_point{
						std::chrono::microseconds(microseconds)
					};
				}

				// Helper to extract Common Name from certificate subject
				inline std::wstring ExtractCommonName(const wchar_t* subject) noexcept {
					if (!subject) return L"";

					std::wstring str(subject);
					size_t cnPos = str.find(L"CN=");
					if (cnPos == std::wstring::npos) return L"";

					cnPos += 3; // Skip "CN="
					size_t endPos = str.find(L',', cnPos);

					if (endPos == std::wstring::npos) {
						return str.substr(cnPos);
					}

					return str.substr(cnPos, endPos - cnPos);
				}

				// Helper to check if hostname matches certificate CN or SAN
				inline bool MatchesHostname(std::wstring_view certName, std::wstring_view hostname) noexcept {
					// Exact match
					if (Internal::EqualsIgnoreCase(certName, hostname)) {
						return true;
					}

					// Wildcard match (e.g., *.example.com matches www.example.com)
					if (certName.size() >= 2 && certName[0] == L'*' && certName[1] == L'.') {
						std::wstring_view wildcardDomain = certName.substr(2);

						// Find first dot in hostname
						size_t dotPos = hostname.find(L'.');
						if (dotPos != std::wstring_view::npos && dotPos + 1 < hostname.size()) {
							std::wstring_view hostDomain = hostname.substr(dotPos + 1);
							return Internal::EqualsIgnoreCase(wildcardDomain, hostDomain);
						}
					}

					return false;
				}
			}

			bool GetSslCertificate(std::wstring_view hostname, uint16_t port, SslCertificateInfo& certInfo, Error* err) noexcept {
				try {
					certInfo = SslCertificateInfo{};

					// Open WinHTTP session
					HINTERNET hSession = ::WinHttpOpen(
						L"ShadowStrike-AntiVirus/1.0",
						WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
						WINHTTP_NO_PROXY_NAME,
						WINHTTP_NO_PROXY_BYPASS,
						0
					);

					if (!hSession) {
						Internal::SetError(err, ::GetLastError(), L"WinHttpOpen failed", L"GetSslCertificate");
						return false;
					}

					// RAII cleanup for session
					struct SessionDeleter {
						void operator()(HINTERNET h) const { if (h) ::WinHttpCloseHandle(h); }
					};
					std::unique_ptr<std::remove_pointer_t<HINTERNET>, SessionDeleter> sessionGuard(hSession);

					// Connect to server
					std::wstring hostStr(hostname);
					HINTERNET hConnect = ::WinHttpConnect(hSession, hostStr.c_str(), port, 0);

					if (!hConnect) {
						Internal::SetError(err, ::GetLastError(), L"WinHttpConnect failed", L"GetSslCertificate");
						return false;
					}

					std::unique_ptr<std::remove_pointer_t<HINTERNET>, SessionDeleter> connectGuard(hConnect);

					// Open HTTPS request
					HINTERNET hRequest = ::WinHttpOpenRequest(
						hConnect,
						L"HEAD",
						L"/",
						nullptr,
						WINHTTP_NO_REFERER,
						WINHTTP_DEFAULT_ACCEPT_TYPES,
						WINHTTP_FLAG_SECURE
					);

					if (!hRequest) {
						Internal::SetError(err, ::GetLastError(), L"WinHttpOpenRequest failed", L"GetSslCertificate");
						return false;
					}

					std::unique_ptr<std::remove_pointer_t<HINTERNET>, SessionDeleter> requestGuard(hRequest);

					// Configure security options
					DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
						SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
						SECURITY_FLAG_IGNORE_CERT_CN_INVALID;

					if (!::WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
						&securityFlags, sizeof(securityFlags))) {
						Internal::SetError(err, ::GetLastError(), L"Failed to set security flags", L"GetSslCertificate");
						return false;
					}

					// Set timeouts (5 seconds for each phase)
					::WinHttpSetTimeouts(hRequest, 5000, 5000, 5000, 5000);

					// Send request
					if (!::WinHttpSendRequest(hRequest,
						WINHTTP_NO_ADDITIONAL_HEADERS, 0,
						WINHTTP_NO_REQUEST_DATA, 0,
						0, 0)) {
						Internal::SetError(err, ::GetLastError(), L"WinHttpSendRequest failed", L"GetSslCertificate");
						return false;
					}

					// Receive response
					if (!::WinHttpReceiveResponse(hRequest, nullptr)) {
						Internal::SetError(err, ::GetLastError(), L"WinHttpReceiveResponse failed", L"GetSslCertificate");
						return false;
					}

					// Query certificate info
					PCCERT_CONTEXT pCertContext = nullptr;
					DWORD certSize = static_cast<DWORD>(sizeof(PCCERT_CONTEXT));

					if (!::WinHttpQueryOption(hRequest,
						WINHTTP_OPTION_SERVER_CERT_CONTEXT,
						&pCertContext,
						&certSize)) {
						Internal::SetError(err, ::GetLastError(), L"Failed to retrieve certificate", L"GetSslCertificate");
						return false;
					}

					if (!pCertContext) {
						Internal::SetError(err, ERROR_INVALID_DATA, L"Certificate context is null", L"GetSslCertificate");
						return false;
					}

					// RAII cleanup for certificate
					struct CertDeleter {
						void operator()(PCCERT_CONTEXT p) const { if (p) ::CertFreeCertificateContext(p); }
					};
					std::unique_ptr<const CERT_CONTEXT, CertDeleter> certGuard(pCertContext);

					// Extract subject
					DWORD subjectLen = ::CertGetNameStringW(
						pCertContext,
						CERT_NAME_SIMPLE_DISPLAY_TYPE,
						0,
						nullptr,
						nullptr,
						0
					);

					if (subjectLen > 1) {
						std::vector<wchar_t> subjectBuf(subjectLen);
						::CertGetNameStringW(
							pCertContext,
							CERT_NAME_SIMPLE_DISPLAY_TYPE,
							0,
							nullptr,
							subjectBuf.data(),
							subjectLen
						);
						certInfo.subject = subjectBuf.data();
					}

					// Extract issuer
					DWORD issuerLen = ::CertGetNameStringW(
						pCertContext,
						CERT_NAME_SIMPLE_DISPLAY_TYPE,
						CERT_NAME_ISSUER_FLAG,
						nullptr,
						nullptr,
						0
					);

					if (issuerLen > 1) {
						std::vector<wchar_t> issuerBuf(issuerLen);
						::CertGetNameStringW(
							pCertContext,
							CERT_NAME_SIMPLE_DISPLAY_TYPE,
							CERT_NAME_ISSUER_FLAG,
							nullptr,
							issuerBuf.data(),
							issuerLen
						);
						certInfo.issuer = issuerBuf.data();
					}

					// Extract serial number
					DWORD serialSize = pCertContext->pCertInfo->SerialNumber.cbData;
					if (serialSize > 0) {
						std::wostringstream oss;
						oss << std::hex << std::uppercase << std::setfill(L'0');

						// Serial number is stored in little-endian, display in big-endian
						for (DWORD i = serialSize; i > 0; --i) {
							oss << std::setw(2) << static_cast<int>(pCertContext->pCertInfo->SerialNumber.pbData[i - 1]);
							if (i > 1) oss << L':';
						}

						certInfo.serialNumber = oss.str();
					}

					// Extract validity dates
					certInfo.validFrom = FileTimeToTimePoint(pCertContext->pCertInfo->NotBefore);
					certInfo.validTo = FileTimeToTimePoint(pCertContext->pCertInfo->NotAfter);

					// Check if certificate is currently valid
					auto now = std::chrono::system_clock::now();
					certInfo.isValid = (now >= certInfo.validFrom && now <= certInfo.validTo);

					// Check if self-signed
					certInfo.isSelfSigned = Internal::EqualsIgnoreCase(certInfo.subject, certInfo.issuer);

					// Extract Subject Alternative Names (SAN)
					PCERT_EXTENSION pExtension = ::CertFindExtension(
						szOID_SUBJECT_ALT_NAME2,
						pCertContext->pCertInfo->cExtension,
						pCertContext->pCertInfo->rgExtension
					);

					if (pExtension) {
						// CRYPT_DECODE_ALLOC_FLAG causes CryptDecodeObjectEx to allocate memory
						// The output is a pointer to the allocated buffer, which must be freed with LocalFree
						PCERT_ALT_NAME_INFO pAltNameInfo = nullptr;
						DWORD sanSize = 0;

						if (::CryptDecodeObjectEx(
							X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
							X509_ALTERNATE_NAME,
							pExtension->Value.pbData,
							pExtension->Value.cbData,
							CRYPT_DECODE_ALLOC_FLAG,
							nullptr,
							&pAltNameInfo,  // Output: pointer to allocated CERT_ALT_NAME_INFO
							&sanSize)) {

							// RAII guard for the allocated memory
							struct SanDeleter {
								void operator()(PCERT_ALT_NAME_INFO p) const {
									if (p) ::LocalFree(p);
								}
							};
							std::unique_ptr<CERT_ALT_NAME_INFO, SanDeleter> sanGuard(pAltNameInfo);

							for (DWORD i = 0; i < pAltNameInfo->cAltEntry; ++i) {
								const auto& entry = pAltNameInfo->rgAltEntry[i];

								if (entry.dwAltNameChoice == CERT_ALT_NAME_DNS_NAME && entry.pwszDNSName) {
									certInfo.subjectAltNames.emplace_back(entry.pwszDNSName);
								}
								else if (entry.dwAltNameChoice == CERT_ALT_NAME_IP_ADDRESS) {
									// Handle IP address SANs if needed
									if (entry.IPAddress.cbData == 4) {
										// IPv4
										IPv4Address ipv4;
										std::memcpy(ipv4.octets.data(), entry.IPAddress.pbData, 4);
										certInfo.subjectAltNames.emplace_back(ipv4.ToString());
									}
									else if (entry.IPAddress.cbData == 16) {
										// IPv6
										std::array<uint8_t, 16> bytes;
										std::memcpy(bytes.data(), entry.IPAddress.pbData, 16);
										IPv6Address ipv6(bytes);
										certInfo.subjectAltNames.emplace_back(ipv6.ToStringCompressed());
									}
								}
							}
						}
					}

					// Verify certificate chain (optional but recommended for enterprise AV)
					CERT_CHAIN_PARA chainPara = {};
					chainPara.cbSize = sizeof(chainPara);

					PCCERT_CHAIN_CONTEXT pChainContext = nullptr;

					if (::CertGetCertificateChain(
						nullptr,                    // Use default chain engine
						pCertContext,
						nullptr,                    // Use current time
						pCertContext->hCertStore,
						&chainPara,
						CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
						nullptr,
						&pChainContext)) {

						struct ChainDeleter {
							void operator()(PCCERT_CHAIN_CONTEXT p) const {
								if (p) ::CertFreeCertificateChain(p);
							}
						};
						std::unique_ptr<const CERT_CHAIN_CONTEXT, ChainDeleter> chainGuard(pChainContext);

						// Check chain status
						if (pChainContext->TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR) {
							// Certificate chain is valid
							certInfo.isValid = certInfo.isValid && true;
						}
						else {
							// Chain has errors - mark as potentially invalid
							if (pChainContext->TrustStatus.dwErrorStatus & CERT_TRUST_IS_NOT_TIME_VALID) {
								certInfo.isValid = false;
							}
							if (pChainContext->TrustStatus.dwErrorStatus & CERT_TRUST_IS_REVOKED) {
								certInfo.isValid = false;
							}
							if (pChainContext->TrustStatus.dwErrorStatus & CERT_TRUST_IS_NOT_SIGNATURE_VALID) {
								certInfo.isValid = false;
							}
							if (pChainContext->TrustStatus.dwErrorStatus & CERT_TRUST_IS_UNTRUSTED_ROOT) {
								// Self-signed or untrusted CA
								certInfo.isSelfSigned = true;
							}
						}
					}

					return true;

				}
				catch (const std::exception& ex) {
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER;
						err->message = L"Exception in GetSslCertificate: ";

						// Convert UTF-8 exception message to wstring using proper Windows API
						const char* exMsg = ex.what();
						if (exMsg && *exMsg) {
							int requiredSize = ::MultiByteToWideChar(CP_UTF8, 0, exMsg, -1, nullptr, 0);
							if (requiredSize > 0) {
								std::wstring wideMsg(static_cast<size_t>(requiredSize - 1), L'\0');
								::MultiByteToWideChar(CP_UTF8, 0, exMsg, -1, wideMsg.data(), requiredSize);
								err->message += wideMsg;
							}
						}
					}
					return false;
				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Unknown exception in GetSslCertificate");
					return false;
				}
			}

			bool ValidateSslCertificate(const SslCertificateInfo& certInfo, std::wstring_view expectedHostname) noexcept {
				try {
					// 1. Check if certificate structure is valid
					if (!certInfo.isValid) {
						return false;
					}

					// 2. Reject self-signed certificates (enterprise policy)
					if (certInfo.isSelfSigned) {
						return false;
					}

					// 3. Check temporal validity
					auto now = std::chrono::system_clock::now();

					if (now < certInfo.validFrom) {
						// Certificate not yet valid
						return false;
					}

					if (now > certInfo.validTo) {
						// Certificate expired
						return false;
					}

					// 4. Validate hostname matching (RFC 6125)
					bool hostnameMatches = false;

					// 4a. Check Subject Alternative Names (SAN) first (modern standard)
					if (!certInfo.subjectAltNames.empty()) {
						for (const auto& san : certInfo.subjectAltNames) {
							if (MatchesHostname(san, expectedHostname)) {
								hostnameMatches = true;
								break;
							}
						}
					}

					// 4b. Fallback to Common Name (deprecated but still used)
					if (!hostnameMatches && !certInfo.subject.empty()) {
						std::wstring cn = ExtractCommonName(certInfo.subject.c_str());
						if (!cn.empty() && MatchesHostname(cn, expectedHostname)) {
							hostnameMatches = true;
						}
					}

					if (!hostnameMatches) {
						// Hostname doesn't match certificate
						return false;
					}

					// 5. Additional security checks

					// 5a. Check validity period length (suspicious if > 825 days as per CA/Browser Forum)
					auto validityPeriod = std::chrono::duration_cast<std::chrono::hours>(
						certInfo.validTo - certInfo.validFrom
					).count();

					constexpr int64_t MAX_VALIDITY_HOURS = 825 * 24; // 825 days
					if (validityPeriod > MAX_VALIDITY_HOURS) {
						// Suspiciously long validity period
						return false;
					}

					// 5b. Ensure issuer is not empty
					if (certInfo.issuer.empty()) {
						return false;
					}

					// 5c. Ensure serial number exists
					if (certInfo.serialNumber.empty()) {
						return false;
					}

					// All checks passed
					return true;

				}
				catch (...) {
					// Any exception during validation = failed validation
					return false;
				}
			}



	}// namespace NetworkUtils
	}// namespace Utils
}// namespace ShadowStrike