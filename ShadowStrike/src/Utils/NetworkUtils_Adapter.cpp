
#include"NetworkUtils.hpp"
#include <wbemidl.h>
#include <comdef.h>  

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "WinInet.lib")
#pragma comment(lib, "dhcpcsvc.lib")

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
			// Network Adapter Information
			// ============================================================================

			bool GetNetworkAdapters(std::vector<NetworkAdapterInfo>& adapters, Error* err) noexcept {
				try {
					adapters.clear();

					ULONG bufferSize = 15000;
					std::vector<uint8_t> buffer(bufferSize);

					ULONG ret = ::GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS,
						nullptr, reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()), &bufferSize);

					if (ret == ERROR_BUFFER_OVERFLOW) {
						buffer.resize(bufferSize);
						ret = ::GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS,
							nullptr, reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()), &bufferSize);
					}

					if (ret != NO_ERROR) {
						Internal::SetError(err, ret, L"GetAdaptersAddresses failed");
						return false;
					}

					for (PIP_ADAPTER_ADDRESSES pAdapter = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
						pAdapter != nullptr; pAdapter = pAdapter->Next) {

						NetworkAdapterInfo info;
						info.friendlyName = pAdapter->FriendlyName ? pAdapter->FriendlyName : L"";
						info.description = pAdapter->Description ? pAdapter->Description : L"";
						info.interfaceIndex = pAdapter->IfIndex;
						info.mtu = pAdapter->Mtu;
						info.speed = pAdapter->TransmitLinkSpeed;
						info.type = static_cast<AdapterType>(pAdapter->IfType);
						info.status = static_cast<OperationalStatus>(pAdapter->OperStatus);
						info.dhcpEnabled = (pAdapter->Flags & IP_ADAPTER_DHCP_ENABLED) != 0;
						info.ipv4Enabled = (pAdapter->Flags & IP_ADAPTER_IPV4_ENABLED) != 0;
						info.ipv6Enabled = (pAdapter->Flags & IP_ADAPTER_IPV6_ENABLED) != 0;

						// MAC Address
						if (pAdapter->PhysicalAddressLength == 6) {
							std::array<uint8_t, 6> macBytes;
							std::memcpy(macBytes.data(), pAdapter->PhysicalAddress, 6);
							info.macAddress = MacAddress(macBytes);
						}

						// IP Addresses
						for (PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pAdapter->FirstUnicastAddress;
							pUnicast != nullptr; pUnicast = pUnicast->Next) {

							if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
								auto* sa = reinterpret_cast<sockaddr_in*>(pUnicast->Address.lpSockaddr);
								uint32_t addr = Internal::NetworkToHost32(sa->sin_addr.s_addr);
								info.ipAddresses.emplace_back(IPv4Address(addr));
							}
							else if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6) {
								auto* sa6 = reinterpret_cast<sockaddr_in6*>(pUnicast->Address.lpSockaddr);
								std::array<uint8_t, 16> bytes;
								std::memcpy(bytes.data(), &sa6->sin6_addr, 16);
								info.ipAddresses.emplace_back(IPv6Address(bytes));
							}
						}

						// Gateway Addresses
						for (PIP_ADAPTER_GATEWAY_ADDRESS pGateway = pAdapter->FirstGatewayAddress;
							pGateway != nullptr; pGateway = pGateway->Next) {

							if (pGateway->Address.lpSockaddr->sa_family == AF_INET) {
								auto* sa = reinterpret_cast<sockaddr_in*>(pGateway->Address.lpSockaddr);
								uint32_t addr = Internal::NetworkToHost32(sa->sin_addr.s_addr);
								info.gatewayAddresses.emplace_back(IPv4Address(addr));
							}
							else if (pGateway->Address.lpSockaddr->sa_family == AF_INET6) {
								auto* sa6 = reinterpret_cast<sockaddr_in6*>(pGateway->Address.lpSockaddr);
								std::array<uint8_t, 16> bytes;
								std::memcpy(bytes.data(), &sa6->sin6_addr, 16);
								info.gatewayAddresses.emplace_back(IPv6Address(bytes));
							}
						}

						// DNS Servers
						for (PIP_ADAPTER_DNS_SERVER_ADDRESS pDns = pAdapter->FirstDnsServerAddress;
							pDns != nullptr; pDns = pDns->Next) {

							if (pDns->Address.lpSockaddr->sa_family == AF_INET) {
								auto* sa = reinterpret_cast<sockaddr_in*>(pDns->Address.lpSockaddr);
								uint32_t addr = Internal::NetworkToHost32(sa->sin_addr.s_addr);
								info.dnsServers.emplace_back(IPv4Address(addr));
							}
							else if (pDns->Address.lpSockaddr->sa_family == AF_INET6) {
								auto* sa6 = reinterpret_cast<sockaddr_in6*>(pDns->Address.lpSockaddr);
								std::array<uint8_t, 16> bytes;
								std::memcpy(bytes.data(), &sa6->sin6_addr, 16);
								info.dnsServers.emplace_back(IPv6Address(bytes));
							}
						}

						adapters.push_back(std::move(info));
					}

					return true;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in GetNetworkAdapters");
					return false;
				}
			}

			bool GetDefaultGateway(IpAddress& gateway, Error* err) noexcept {
				std::vector<NetworkAdapterInfo> adapters;
				if (!GetNetworkAdapters(adapters, err)) {
					return false;
				}

				for (const auto& adapter : adapters) {
					if (adapter.status == OperationalStatus::Up && !adapter.gatewayAddresses.empty()) {
						gateway = adapter.gatewayAddresses[0];
						return true;
					}
				}

				Internal::SetError(err, ERROR_NOT_FOUND, L"No default gateway found");
				return false;
			}

			bool GetDnsServers(std::vector<IpAddress>& dnsServers, Error* err) noexcept {
				std::vector<NetworkAdapterInfo> adapters;
				if (!GetNetworkAdapters(adapters, err)) {
					return false;
				}

				dnsServers.clear();
				for (const auto& adapter : adapters) {
					if (adapter.status == OperationalStatus::Up) {
						for (const auto& dns : adapter.dnsServers) {
							dnsServers.push_back(dns);
						}
					}
				}

				return !dnsServers.empty();
			}

			bool GetLocalIpAddresses(std::vector<IpAddress>& addresses, bool includeLoopback, Error* err) noexcept {
				std::vector<NetworkAdapterInfo> adapters;
				if (!GetNetworkAdapters(adapters, err)) {
					return false;
				}

				addresses.clear();
				for (const auto& adapter : adapters) {
					if (adapter.status == OperationalStatus::Up) {
						for (const auto& ip : adapter.ipAddresses) {
							if (includeLoopback || !ip.IsLoopback()) {
								addresses.push_back(ip);
							}
						}
					}
				}

				return !addresses.empty();
			}


			// ============================================================================
			// Network Interface Control
			// ============================================================================

			bool EnableNetworkAdapter(const std::wstring& adapterName, Error* err) noexcept {
				try {
					// ====================================================================
					// VALIDATION: Adapter name cannot be empty
					// ====================================================================
					if (adapterName.empty()) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Adapter name cannot be empty");
						return false;
					}

					// ====================================================================
					// VALIDATION: Check for path traversal and injection attacks
					// ====================================================================
					if (adapterName.find(L"..") != std::wstring::npos ||
						adapterName.find(L'/') != std::wstring::npos ||
						adapterName.find(L'\\') != std::wstring::npos ||
						adapterName.find(L'\0') != std::wstring::npos ||
						adapterName.find(L';') != std::wstring::npos ||
						adapterName.find(L'&') != std::wstring::npos ||
						adapterName.find(L'|') != std::wstring::npos) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid characters in adapter name");
						return false;
					}

					// ====================================================================
					// VALIDATION: Length check (prevent buffer overflow)
					// ====================================================================
					
					if (adapterName.length() > MAX_ADAPTER_NAME_LENGTH) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Adapter name too long");
						return false;
					}

					// ====================================================================
					// STEP 1: Initialize COM for WMI (Windows Management Instrumentation)
					// ====================================================================
					HRESULT hr = ::CoInitializeEx(nullptr, COINIT_MULTITHREADED);
					bool comInitialized = SUCCEEDED(hr);

					// If already initialized, S_FALSE is returned - that's OK
					if (hr != S_OK && hr != S_FALSE && FAILED(hr)) {
						Internal::SetError(err, hr, L"CoInitializeEx failed");
						return false;
					}

					// RAII for COM cleanup
					struct ComUninitializer {
						bool shouldUninitialize;
						~ComUninitializer() {
							if (shouldUninitialize) {
								::CoUninitialize();
							}
						}
					} comGuard{ comInitialized };

					// ====================================================================
					// STEP 2: Set COM security levels
					// ====================================================================
					hr = ::CoInitializeSecurity(
						nullptr,
						-1,                          // COM authentication
						nullptr,                     // Authentication services
						nullptr,                     // Reserved
						RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication
						RPC_C_IMP_LEVEL_IMPERSONATE, // Impersonation level
						nullptr,                     // Authentication info
						EOAC_NONE,                   // Additional capabilities
						nullptr                      // Reserved
					);

					// S_OK or RPC_E_TOO_LATE (already initialized) are acceptable
					if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
						Internal::SetError(err, hr, L"CoInitializeSecurity failed");
						return false;
					}

					// ====================================================================
					// STEP 3: Obtain WMI locator
					// ====================================================================
					IWbemLocator* pLoc = nullptr;
					hr = ::CoCreateInstance(
						CLSID_WbemLocator,
						nullptr,
						CLSCTX_INPROC_SERVER,
						IID_IWbemLocator,
						reinterpret_cast<LPVOID*>(&pLoc)
					);

					if (FAILED(hr)) {
						Internal::SetError(err, hr, L"Failed to create IWbemLocator");
						return false;
					}

					// RAII for locator
					struct LocatorReleaser {
						IWbemLocator* locator;
						~LocatorReleaser() {
							if (locator) locator->Release();
						}
					} locatorGuard{ pLoc };

					// ====================================================================
					// STEP 4: Connect to WMI namespace
					// ====================================================================
					IWbemServices* pSvc = nullptr;
					hr = pLoc->ConnectServer(
						::SysAllocString(L"ROOT\\CIMV2"),  // WMI namespace
						nullptr,                            // User name (use current)
						nullptr,                            // Password (use current)
						nullptr,                            // Locale
						0,                                  // Security flags
						nullptr,                            // Authority
						nullptr,                            // Context object
						&pSvc                               // IWbemServices proxy
					);

					if (FAILED(hr)) {
						Internal::SetError(err, hr, L"Could not connect to WMI namespace");
						return false;
					}

					// RAII for service
					struct ServiceReleaser {
						IWbemServices* service;
						~ServiceReleaser() {
							if (service) service->Release();
						}
					} serviceGuard{ pSvc };

					// ====================================================================
					// STEP 5: Set security levels on WMI connection
					// ====================================================================
					hr = ::CoSetProxyBlanket(
						pSvc,                        // Indicates proxy to set
						RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
						RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
						nullptr,                     // Server principal name
						RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx
						RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
						nullptr,                     // client identity
						EOAC_NONE                    // proxy capabilities
					);

					if (FAILED(hr)) {
						Internal::SetError(err, hr, L"Could not set proxy blanket");
						return false;
					}

					// ====================================================================
					// STEP 6: Query for the network adapter
					// ====================================================================
					// Escape single quotes in adapter name for WQL query
					std::wstring escapedName = adapterName;
					size_t pos = 0;
					while ((pos = escapedName.find(L'\'', pos)) != std::wstring::npos) {
						escapedName.replace(pos, 1, L"''");
						pos += 2;
					}

					std::wstring query = L"SELECT * FROM Win32_NetworkAdapter WHERE NetConnectionID = '" + escapedName + L"'";

					IEnumWbemClassObject* pEnumerator = nullptr;
					hr = pSvc->ExecQuery(
						::SysAllocString(L"WQL"),
						::SysAllocString(query.c_str()),
						WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
						nullptr,
						&pEnumerator
					);

					if (FAILED(hr)) {
						Internal::SetError(err, hr, L"WMI query failed");
						return false;
					}

					// RAII for enumerator
					struct EnumeratorReleaser {
						IEnumWbemClassObject* enumerator;
						~EnumeratorReleaser() {
							if (enumerator) enumerator->Release();
						}
					} enumGuard{ pEnumerator };

					// ====================================================================
					// STEP 7: Get the adapter object
					// ====================================================================
					IWbemClassObject* pclsObj = nullptr;
					ULONG uReturn = 0;

					hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

					if (FAILED(hr) || uReturn == 0) {
						Internal::SetError(err, ERROR_NOT_FOUND, L"Network adapter not found");
						return false;
					}

					// RAII for class object
					struct ClassObjectReleaser {
						IWbemClassObject* obj;
						~ClassObjectReleaser() {
							if (obj) obj->Release();
						}
					} objGuard{ pclsObj };

					// ====================================================================
					// STEP 8: Check if adapter is already enabled
					// ====================================================================
					VARIANT vtProp;
					::VariantInit(&vtProp);

					hr = pclsObj->Get(L"NetEnabled", 0, &vtProp, nullptr, nullptr);
					if (SUCCEEDED(hr) && vtProp.vt == VT_BOOL) {
						if (vtProp.boolVal == VARIANT_TRUE) {
							::VariantClear(&vtProp);
							// Already enabled
							return true;
						}
					}
					::VariantClear(&vtProp);

					// ====================================================================
					// STEP 9: Enable the adapter by calling Enable method
					// ====================================================================
					IWbemClassObject* pClass = nullptr;
					hr = pSvc->GetObject(
						::SysAllocString(L"Win32_NetworkAdapter"),
						0,
						nullptr,
						&pClass,
						nullptr
					);

					if (FAILED(hr)) {
						Internal::SetError(err, hr, L"Failed to get Win32_NetworkAdapter class");
						return false;
					}

					// RAII for class
					struct ClassReleaser {
						IWbemClassObject* cls;
						~ClassReleaser() {
							if (cls) cls->Release();
						}
					} classGuard{ pClass };

					IWbemClassObject* pInParamsDefinition = nullptr;
					hr = pClass->GetMethod(L"Enable", 0, &pInParamsDefinition, nullptr);

					if (FAILED(hr)) {
						Internal::SetError(err, hr, L"Failed to get Enable method");
						return false;
					}

					// RAII for input params
					struct InParamsReleaser {
						IWbemClassObject* params;
						~InParamsReleaser() {
							if (params) params->Release();
						}
					} inParamsGuard{ pInParamsDefinition };

					// Get object path
					::VariantInit(&vtProp);
					hr = pclsObj->Get(L"__PATH", 0, &vtProp, nullptr, nullptr);

					if (FAILED(hr) || vtProp.vt != VT_BSTR) {
						::VariantClear(&vtProp);
						Internal::SetError(err, hr, L"Failed to get adapter path");
						return false;
					}

					BSTR objectPath = vtProp.bstrVal;

					// Execute Enable method
					IWbemClassObject* pOutParams = nullptr;
					hr = pSvc->ExecMethod(
						objectPath,
						::SysAllocString(L"Enable"),
						0,
						nullptr,
						nullptr,
						&pOutParams,
						nullptr
					);

					::VariantClear(&vtProp);

					if (FAILED(hr)) {
						Internal::SetError(err, hr, L"Enable method execution failed");
						return false;
					}

					// RAII for output params
					struct OutParamsReleaser {
						IWbemClassObject* params;
						~OutParamsReleaser() {
							if (params) params->Release();
						}
					} outParamsGuard{ pOutParams };

					// Check return value
					if (pOutParams) {
						::VariantInit(&vtProp);
						hr = pOutParams->Get(L"ReturnValue", 0, &vtProp, nullptr, nullptr);

						if (SUCCEEDED(hr) && vtProp.vt == VT_I4) {
							LONG retVal = vtProp.lVal;
							::VariantClear(&vtProp);

							if (retVal != 0) {
								Internal::SetError(err, retVal, L"Enable operation returned error code");
								return false;
							}
						}
						else {
							::VariantClear(&vtProp);
						}
					}

					return true;

				}
				catch (const std::exception& e) {
					if (err) {
						err->win32 = ERROR_UNHANDLED_EXCEPTION;
						err->message = L"Exception in EnableNetworkAdapter";
						char buffer[256];
						std::snprintf(buffer, sizeof(buffer), "%s", e.what());
						buffer[sizeof(buffer) - 1] = '\0';
						// Convert to wstring if needed for context
					}
					return false;
				}
				catch (...) {
					Internal::SetError(err, ERROR_UNHANDLED_EXCEPTION, L"Unknown exception in EnableNetworkAdapter");
					return false;
				}
			}

			bool DisableNetworkAdapter(const std::wstring& adapterName, Error* err) noexcept {
				try {
					// ====================================================================
					// VALIDATION: Adapter name cannot be empty
					// ====================================================================
					if (adapterName.empty()) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Adapter name cannot be empty");
						return false;
					}

					// ====================================================================
					// VALIDATION: Check for path traversal and injection attacks
					// ====================================================================
					if (adapterName.find(L"..") != std::wstring::npos ||
						adapterName.find(L'/') != std::wstring::npos ||
						adapterName.find(L'\\') != std::wstring::npos ||
						adapterName.find(L'\0') != std::wstring::npos ||
						adapterName.find(L';') != std::wstring::npos ||
						adapterName.find(L'&') != std::wstring::npos ||
						adapterName.find(L'|') != std::wstring::npos) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid characters in adapter name");
						return false;
					}

					// ====================================================================
					// VALIDATION: Length check
					// ====================================================================
					
					if (adapterName.length() > MAX_ADAPTER_NAME_LENGTH) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Adapter name too long");
						return false;
					}

					// ====================================================================
					// STEP 1: Initialize COM
					// ====================================================================
					HRESULT hr = ::CoInitializeEx(nullptr, COINIT_MULTITHREADED);
					bool comInitialized = SUCCEEDED(hr);

					if (hr != S_OK && hr != S_FALSE && FAILED(hr)) {
						Internal::SetError(err, hr, L"CoInitializeEx failed");
						return false;
					}

					struct ComUninitializer {
						bool shouldUninitialize;
						~ComUninitializer() {
							if (shouldUninitialize) {
								::CoUninitialize();
							}
						}
					} comGuard{ comInitialized };

					// ====================================================================
					// STEP 2: Set COM security
					// ====================================================================
					hr = ::CoInitializeSecurity(
						nullptr,
						-1,
						nullptr,
						nullptr,
						RPC_C_AUTHN_LEVEL_DEFAULT,
						RPC_C_IMP_LEVEL_IMPERSONATE,
						nullptr,
						EOAC_NONE,
						nullptr
					);

					if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
						Internal::SetError(err, hr, L"CoInitializeSecurity failed");
						return false;
					}

					// ====================================================================
					// STEP 3: Obtain WMI locator
					// ====================================================================
					IWbemLocator* pLoc = nullptr;
					hr = ::CoCreateInstance(
						CLSID_WbemLocator,
						nullptr,
						CLSCTX_INPROC_SERVER,
						IID_IWbemLocator,
						reinterpret_cast<LPVOID*>(&pLoc)
					);

					if (FAILED(hr)) {
						Internal::SetError(err, hr, L"Failed to create IWbemLocator");
						return false;
					}

					struct LocatorReleaser {
						IWbemLocator* locator;
						~LocatorReleaser() {
							if (locator) locator->Release();
						}
					} locatorGuard{ pLoc };

					// ====================================================================
					// STEP 4: Connect to WMI
					// ====================================================================
					IWbemServices* pSvc = nullptr;
					hr = pLoc->ConnectServer(
						::SysAllocString(L"ROOT\\CIMV2"),
						nullptr,
						nullptr,
						nullptr,
						0,
						nullptr,
						nullptr,
						&pSvc
					);

					if (FAILED(hr)) {
						Internal::SetError(err, hr, L"Could not connect to WMI namespace");
						return false;
					}

					struct ServiceReleaser {
						IWbemServices* service;
						~ServiceReleaser() {
							if (service) service->Release();
						}
					} serviceGuard{ pSvc };

					// ====================================================================
					// STEP 5: Set security on WMI connection
					// ====================================================================
					hr = ::CoSetProxyBlanket(
						pSvc,
						RPC_C_AUTHN_WINNT,
						RPC_C_AUTHZ_NONE,
						nullptr,
						RPC_C_AUTHN_LEVEL_CALL,
						RPC_C_IMP_LEVEL_IMPERSONATE,
						nullptr,
						EOAC_NONE
					);

					if (FAILED(hr)) {
						Internal::SetError(err, hr, L"Could not set proxy blanket");
						return false;
					}

					// ====================================================================
					// STEP 6: Query for adapter
					// ====================================================================
					std::wstring escapedName = adapterName;
					size_t pos = 0;
					while ((pos = escapedName.find(L'\'', pos)) != std::wstring::npos) {
						escapedName.replace(pos, 1, L"''");
						pos += 2;
					}

					std::wstring query = L"SELECT * FROM Win32_NetworkAdapter WHERE NetConnectionID = '" + escapedName + L"'";

					IEnumWbemClassObject* pEnumerator = nullptr;
					hr = pSvc->ExecQuery(
						::SysAllocString(L"WQL"),
						::SysAllocString(query.c_str()),
						WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
						nullptr,
						&pEnumerator
					);

					if (FAILED(hr)) {
						Internal::SetError(err, hr, L"WMI query failed");
						return false;
					}

					struct EnumeratorReleaser {
						IEnumWbemClassObject* enumerator;
						~EnumeratorReleaser() {
							if (enumerator) enumerator->Release();
						}
					} enumGuard{ pEnumerator };

					// ====================================================================
					// STEP 7: Get adapter object
					// ====================================================================
					IWbemClassObject* pclsObj = nullptr;
					ULONG uReturn = 0;

					hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

					if (FAILED(hr) || uReturn == 0) {
						Internal::SetError(err, ERROR_NOT_FOUND, L"Network adapter not found");
						return false;
					}

					struct ClassObjectReleaser {
						IWbemClassObject* obj;
						~ClassObjectReleaser() {
							if (obj) obj->Release();
						}
					} objGuard{ pclsObj };

					// ====================================================================
					// STEP 8: Check if already disabled
					// ====================================================================
					VARIANT vtProp;
					::VariantInit(&vtProp);

					hr = pclsObj->Get(L"NetEnabled", 0, &vtProp, nullptr, nullptr);
					if (SUCCEEDED(hr) && vtProp.vt == VT_BOOL) {
						if (vtProp.boolVal == VARIANT_FALSE) {
							::VariantClear(&vtProp);
							// Already disabled
							return true;
						}
					}
					::VariantClear(&vtProp);

					// ====================================================================
					// STEP 9: Disable the adapter
					// ====================================================================
					IWbemClassObject* pClass = nullptr;
					hr = pSvc->GetObject(
						::SysAllocString(L"Win32_NetworkAdapter"),
						0,
						nullptr,
						&pClass,
						nullptr
					);

					if (FAILED(hr)) {
						Internal::SetError(err, hr, L"Failed to get Win32_NetworkAdapter class");
						return false;
					}

					struct ClassReleaser {
						IWbemClassObject* cls;
						~ClassReleaser() {
							if (cls) cls->Release();
						}
					} classGuard{ pClass };

					IWbemClassObject* pInParamsDefinition = nullptr;
					hr = pClass->GetMethod(L"Disable", 0, &pInParamsDefinition, nullptr);

					if (FAILED(hr)) {
						Internal::SetError(err, hr, L"Failed to get Disable method");
						return false;
					}

					struct InParamsReleaser {
						IWbemClassObject* params;
						~InParamsReleaser() {
							if (params) params->Release();
						}
					} inParamsGuard{ pInParamsDefinition };

					::VariantInit(&vtProp);
					hr = pclsObj->Get(L"__PATH", 0, &vtProp, nullptr, nullptr);

					if (FAILED(hr) || vtProp.vt != VT_BSTR) {
						::VariantClear(&vtProp);
						Internal::SetError(err, hr, L"Failed to get adapter path");
						return false;
					}

					BSTR objectPath = vtProp.bstrVal;

					IWbemClassObject* pOutParams = nullptr;
					hr = pSvc->ExecMethod(
						objectPath,
						::SysAllocString(L"Disable"),
						0,
						nullptr,
						nullptr,
						&pOutParams,
						nullptr
					);

					::VariantClear(&vtProp);

					if (FAILED(hr)) {
						Internal::SetError(err, hr, L"Disable method execution failed");
						return false;
					}

					struct OutParamsReleaser {
						IWbemClassObject* params;
						~OutParamsReleaser() {
							if (params) params->Release();
						}
					} outParamsGuard{ pOutParams };

					if (pOutParams) {
						::VariantInit(&vtProp);
						hr = pOutParams->Get(L"ReturnValue", 0, &vtProp, nullptr, nullptr);

						if (SUCCEEDED(hr) && vtProp.vt == VT_I4) {
							LONG retVal = vtProp.lVal;
							::VariantClear(&vtProp);

							if (retVal != 0) {
								Internal::SetError(err, retVal, L"Disable operation returned error code");
								return false;
							}
						}
						else {
							::VariantClear(&vtProp);
						}
					}

					return true;

				}
				catch (const std::exception& e) {
					if (err) {
						err->win32 = ERROR_UNHANDLED_EXCEPTION;
						err->message = L"Exception in DisableNetworkAdapter";
					}
					return false;
				}
				catch (...) {
					Internal::SetError(err, ERROR_UNHANDLED_EXCEPTION, L"Unknown exception in DisableNetworkAdapter");
					return false;
				}
			}

			bool RenewDhcpLease(const std::wstring& adapterName, Error* err) noexcept {
				try {
					// ====================================================================
					// VALIDATION: Adapter name
					// ====================================================================
					if (adapterName.empty()) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Adapter name cannot be empty");
						return false;
					}

					
					if (adapterName.length() > MAX_ADAPTER_NAME_LENGTH) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Adapter name too long");
						return false;
					}

					// Security validation
					if (adapterName.find(L'\0') != std::wstring::npos) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid null character in adapter name");
						return false;
					}

					// ====================================================================
					// STEP 1: Get adapter information to find interface index
					// ====================================================================
					std::vector<NetworkAdapterInfo> adapters;
					if (!GetNetworkAdapters(adapters, err)) {
						return false;
					}

					uint32_t interfaceIndex = 0;
					bool found = false;

					for (const auto& adapter : adapters) {
						if (Internal::EqualsIgnoreCase(adapter.friendlyName, adapterName) ||
							Internal::EqualsIgnoreCase(adapter.description, adapterName)) {
							interfaceIndex = adapter.interfaceIndex;
							found = true;
							break;
						}
					}

					if (!found) {
						Internal::SetError(err, ERROR_NOT_FOUND, L"Network adapter not found");
						return false;
					}

					// ====================================================================
					// STEP 2: Release current DHCP lease
					// ====================================================================
					DWORD result = ::IpReleaseAddress(nullptr); // Release all adapters first

					// Then specifically target our adapter
					IP_ADAPTER_INDEX_MAP adapterInfo{};
					adapterInfo.Index = interfaceIndex;

					result = ::IpReleaseAddress(&adapterInfo);
					if (result != NO_ERROR && result != ERROR_INVALID_PARAMETER) {
						Internal::SetError(err, result, L"IpReleaseAddress failed");
						return false;
					}

					// ====================================================================
					// STEP 3: Brief delay to allow release to complete
					// ====================================================================
					::Sleep(500);

					// ====================================================================
					// STEP 4: Renew DHCP lease
					// ====================================================================
					result = ::IpRenewAddress(&adapterInfo);
					if (result != NO_ERROR) {
						Internal::SetError(err, result, L"IpRenewAddress failed");
						return false;
					}

					// ====================================================================
					// STEP 5: Verify renewal by checking for valid IP
					// ====================================================================
					::Sleep(1000); // Wait for DHCP negotiation

					std::vector<NetworkAdapterInfo> updatedAdapters;
					if (GetNetworkAdapters(updatedAdapters, nullptr)) {
						for (const auto& adapter : updatedAdapters) {
							if (adapter.interfaceIndex == interfaceIndex) {
								if (adapter.ipAddresses.empty()) {
									Internal::SetError(err, ERROR_NO_DATA, L"DHCP renewal did not assign IP address");
									return false;
								}

								// Check if IP is not APIPA (169.254.x.x)
								for (const auto& ip : adapter.ipAddresses) {
									if (ip.IsIPv4()) {
										auto* ipv4 = ip.AsIPv4();
										uint32_t addr = ipv4->ToUInt32();
										uint32_t apipaPrefix = 0xA9FE0000; // 169.254.0.0
										uint32_t apipaMask = 0xFFFF0000;

										if ((addr & apipaMask) == apipaPrefix) {
											Internal::SetError(err, ERROR_DHCP_ADDRESS_CONFLICT, L"DHCP renewal resulted in APIPA address");
											return false;
										}
									}
								}

								break;
							}
						}
					}

					return true;

				}
				catch (const std::exception& e) {
					if (err) {
						err->win32 = ERROR_UNHANDLED_EXCEPTION;
						err->message = L"Exception in RenewDhcpLease";
					}
					return false;
				}
				catch (...) {
					Internal::SetError(err, ERROR_UNHANDLED_EXCEPTION, L"Unknown exception in RenewDhcpLease");
					return false;
				}
			}

			bool ReleaseDhcpLease(const std::wstring& adapterName, Error* err) noexcept {
				try {
					// ====================================================================
					// VALIDATION
					// ====================================================================
					if (adapterName.empty()) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Adapter name cannot be empty");
						return false;
					}

					
					if (adapterName.length() > MAX_ADAPTER_NAME_LENGTH) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Adapter name too long");
						return false;
					}

					if (adapterName.find(L'\0') != std::wstring::npos) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid null character in adapter name");
						return false;
					}

					// ====================================================================
					// STEP 1: Find adapter by name
					// ====================================================================
					std::vector<NetworkAdapterInfo> adapters;
					if (!GetNetworkAdapters(adapters, err)) {
						return false;
					}

					uint32_t interfaceIndex = 0;
					bool found = false;

					for (const auto& adapter : adapters) {
						if (Internal::EqualsIgnoreCase(adapter.friendlyName, adapterName) ||
							Internal::EqualsIgnoreCase(adapter.description, adapterName)) {
							interfaceIndex = adapter.interfaceIndex;
							found = true;
							break;
						}
					}

					if (!found) {
						Internal::SetError(err, ERROR_NOT_FOUND, L"Network adapter not found");
						return false;
					}

					// ====================================================================
					// STEP 2: Release DHCP lease for specific adapter
					// ====================================================================
					IP_ADAPTER_INDEX_MAP adapterInfo{};
					adapterInfo.Index = interfaceIndex;

					DWORD result = ::IpReleaseAddress(&adapterInfo);
					if (result != NO_ERROR && result != ERROR_INVALID_PARAMETER) {
						Internal::SetError(err, result, L"IpReleaseAddress failed");
						return false;
					}

					// ====================================================================
					// STEP 3: Verify release by checking IP addresses
					// ====================================================================
					::Sleep(500);

					std::vector<NetworkAdapterInfo> updatedAdapters;
					if (GetNetworkAdapters(updatedAdapters, nullptr)) {
						for (const auto& adapter : updatedAdapters) {
							if (adapter.interfaceIndex == interfaceIndex) {
								// After release, adapter should either have no IP or APIPA
								bool hasValidDhcpIp = false;

								for (const auto& ip : adapter.ipAddresses) {
									if (ip.IsIPv4()) {
										auto* ipv4 = ip.AsIPv4();
										uint32_t addr = ipv4->ToUInt32();
										uint32_t apipaPrefix = 0xA9FE0000; // 169.254.0.0
										uint32_t apipaMask = 0xFFFF0000;

										// If not APIPA and not loopback, still has DHCP IP
										if ((addr & apipaMask) != apipaPrefix && !ip.IsLoopback()) {
											hasValidDhcpIp = true;
											break;
										}
									}
								}

								if (hasValidDhcpIp) {
									Internal::SetError(err, ERROR_OPERATION_ABORTED, L"DHCP lease was not fully released");
									return false;
								}

								break;
							}
						}
					}

					return true;

				}
				catch (const std::exception& e) {
					if (err) {
						err->win32 = ERROR_UNHANDLED_EXCEPTION;
						err->message = L"Exception in ReleaseDhcpLease";
					}
					return false;
				}
				catch (...) {
					Internal::SetError(err, ERROR_UNHANDLED_EXCEPTION, L"Unknown exception in ReleaseDhcpLease");
					return false;
				}
			}

			bool FlushDnsCache(Error* err) noexcept {
				// DnsFlushResolverCache may not be available on all Windows versions
				// Use ipconfig /flushdns via system command as fallback
				HMODULE hDnsapi = ::LoadLibraryW(L"dnsapi.dll");
				if (hDnsapi) {
					typedef BOOL(WINAPI* DnsFlushResolverCacheFunc)();
					auto pDnsFlushResolverCache = reinterpret_cast<DnsFlushResolverCacheFunc>(
						::GetProcAddress(hDnsapi, "DnsFlushResolverCache"));

					if (pDnsFlushResolverCache) {
						BOOL result = pDnsFlushResolverCache();
						::FreeLibrary(hDnsapi);
						if (result) {
							return true;
						}
					}
					::FreeLibrary(hDnsapi);
				}

				// Fallback: use system command
				int result = ::_wsystem(L"ipconfig /flushdns >nul 2>&1");
				if (result == 0) {
					return true;
				}

				Internal::SetError(err, ::GetLastError(), L"Failed to flush DNS cache");
				return false;
			}
			// ============================================================================
			// Routing Table
			// ============================================================================

			bool GetRoutingTable(std::vector<RouteEntry>& routes, Error* err) noexcept {
				try {
					routes.clear();

					// IPv4 Routing Table
					ULONG size = 0;
#pragma warning(suppress: 6387)
					::GetIpForwardTable(nullptr, &size, FALSE);

					std::vector<uint8_t> buffer(size);
					DWORD result = ::GetIpForwardTable(reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data()), &size, FALSE);

					if (result == NO_ERROR) {
						auto* pTable = reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data());

						for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
							const auto& row = pTable->table[i];

							RouteEntry entry;
							entry.destination = IpAddress(IPv4Address(Internal::NetworkToHost32(row.dwForwardDest)));
							entry.netmask = IpAddress(IPv4Address(Internal::NetworkToHost32(row.dwForwardMask)));
							entry.gateway = IpAddress(IPv4Address(Internal::NetworkToHost32(row.dwForwardNextHop)));
							entry.interfaceIndex = row.dwForwardIfIndex;
							entry.metric = row.dwForwardMetric1;

							routes.push_back(std::move(entry));
						}
					}

					// IPv6 Routing Table
					PMIB_IPFORWARD_TABLE2 pTable6 = nullptr;
					result = ::GetIpForwardTable2(AF_INET6, &pTable6);

					if (result != NO_ERROR) {
						// IPv4 routes varsa onlar� d�nd�r, IPv6 hata veriyorsa sorun de�il
						return !routes.empty();
					}

					// RAII wrapper for cleanup
					struct TableDeleter {
						void operator()(PMIB_IPFORWARD_TABLE2 p) const {
							if (p) ::FreeMibTable(p);
						}
					};
					std::unique_ptr<MIB_IPFORWARD_TABLE2, TableDeleter> tableGuard(pTable6);

					for (ULONG i = 0; i < pTable6->NumEntries; ++i) {
						const auto& row = pTable6->Table[i];

						RouteEntry entry;

						// Destination IPv6 address
						std::array<uint8_t, 16> destBytes;
						std::memcpy(destBytes.data(), row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte, 16);
						entry.destination = IpAddress(IPv6Address(destBytes));

						// IPv6 uses prefix length instead of netmask
						// Convert prefix length to netmask representation
						uint8_t prefixLen = row.DestinationPrefix.PrefixLength;
						std::array<uint8_t, 16> maskBytes = {};
						for (uint8_t j = 0; j < prefixLen / 8; ++j) {
							maskBytes[j] = 0xFF;
						}
						if (prefixLen % 8) {
							maskBytes[prefixLen / 8] = static_cast<uint8_t>(0xFF << (8 - (prefixLen % 8)));
						}
						entry.netmask = IpAddress(IPv6Address(maskBytes));

						// Gateway (NextHop) IPv6 address
						std::array<uint8_t, 16> gwBytes;
						std::memcpy(gwBytes.data(), row.NextHop.Ipv6.sin6_addr.u.Byte, 16);
						entry.gateway = IpAddress(IPv6Address(gwBytes));

						entry.interfaceIndex = row.InterfaceIndex;
						entry.metric = row.Metric;

						routes.push_back(std::move(entry));
					}

					return true;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in GetRoutingTable");
					return false;
				}
			}

			//routing table for specific family
			bool GetRoutingTable(std::vector<RouteEntry>& routes, ADDRESS_FAMILY family, Error* err) noexcept {
				try {
					routes.clear();

					if (family == AF_INET) {
						// IPv4 only
						ULONG size = 0;
#pragma warning(suppress: 6387)
						::GetIpForwardTable(nullptr, &size, FALSE);

						std::vector<uint8_t> buffer(size);
						DWORD result = ::GetIpForwardTable(reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data()), &size, FALSE);

						if (result != NO_ERROR) {
							Internal::SetError(err, result, L"GetIpForwardTable failed");
							return false;
						}

						auto* pTable = reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data());

						for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
							const auto& row = pTable->table[i];

							RouteEntry entry;
							entry.destination = IpAddress(IPv4Address(Internal::NetworkToHost32(row.dwForwardDest)));
							entry.netmask = IpAddress(IPv4Address(Internal::NetworkToHost32(row.dwForwardMask)));
							entry.gateway = IpAddress(IPv4Address(Internal::NetworkToHost32(row.dwForwardNextHop)));
							entry.interfaceIndex = row.dwForwardIfIndex;
							entry.metric = row.dwForwardMetric1;

							routes.push_back(std::move(entry));
						}
					}
					else if (family == AF_INET6) {
						// IPv6 only
						PMIB_IPFORWARD_TABLE2 pTable6 = nullptr;
						DWORD result = ::GetIpForwardTable2(AF_INET6, &pTable6);

						if (result != NO_ERROR) {
							Internal::SetError(err, result, L"GetIpForwardTable2 failed");
							return false;
						}

						struct TableDeleter {
							void operator()(PMIB_IPFORWARD_TABLE2 p) const {
								if (p) ::FreeMibTable(p);
							}
						};
						std::unique_ptr<MIB_IPFORWARD_TABLE2, TableDeleter> tableGuard(pTable6);

						for (ULONG i = 0; i < pTable6->NumEntries; ++i) {
							const auto& row = pTable6->Table[i];

							RouteEntry entry;

							std::array<uint8_t, 16> destBytes;
							std::memcpy(destBytes.data(), row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte, 16);
							entry.destination = IpAddress(IPv6Address(destBytes));

							uint8_t prefixLen = row.DestinationPrefix.PrefixLength;
							std::array<uint8_t, 16> maskBytes = {};
							for (uint8_t j = 0; j < prefixLen / 8; ++j) {
								maskBytes[j] = 0xFF;
							}
							if (prefixLen % 8) {
								maskBytes[prefixLen / 8] = static_cast<uint8_t>(0xFF << (8 - (prefixLen % 8)));
							}
							entry.netmask = IpAddress(IPv6Address(maskBytes));

							std::array<uint8_t, 16> gwBytes;
							std::memcpy(gwBytes.data(), row.NextHop.Ipv6.sin6_addr.u.Byte, 16);
							entry.gateway = IpAddress(IPv6Address(gwBytes));

							entry.interfaceIndex = row.InterfaceIndex;
							entry.metric = row.Metric;

							routes.push_back(std::move(entry));
						}
					}
					else {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid address family");
						return false;
					}

					return true;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in GetRoutingTable");
					return false;
				}
			}

			bool AddRoute(const IpAddress& destination, uint8_t prefixLength, const IpAddress& gateway, Error* err) noexcept {
				try {
					// Check if both addresses are same IP version
					if (destination.IsIPv4() != gateway.IsIPv4()) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Destination and gateway must be same IP version");
						return false;
					}

					if (destination.IsIPv4()) {
						// IPv4 Route Addition
						MIB_IPFORWARDROW route = {};

						auto* destIpv4 = destination.AsIPv4();
						auto* gwIpv4 = gateway.AsIPv4();

						route.dwForwardDest = Internal::HostToNetwork32(destIpv4->ToUInt32());
						route.dwForwardNextHop = Internal::HostToNetwork32(gwIpv4->ToUInt32());

						// Convert prefix length to netmask
						if (prefixLength > 32) {
							Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid prefix length for IPv4");
							return false;
						}

						uint32_t mask = prefixLength == 0 ? 0 : (~0U << (32 - prefixLength));
						route.dwForwardMask = Internal::HostToNetwork32(mask);

						route.dwForwardPolicy = 0;
						route.dwForwardIfIndex = 0; // Let system choose interface
						route.dwForwardType = MIB_IPROUTE_TYPE_INDIRECT;
						route.dwForwardProto = MIB_IPPROTO_NETMGMT;
						route.dwForwardAge = 0;
						route.dwForwardNextHopAS = 0;
						route.dwForwardMetric1 = 1;
						route.dwForwardMetric2 = static_cast<DWORD>(-1);
						route.dwForwardMetric3 = static_cast<DWORD>(-1);
						route.dwForwardMetric4 = static_cast<DWORD>(-1);
						route.dwForwardMetric5 = static_cast<DWORD>(-1);

						DWORD result = ::CreateIpForwardEntry(&route);
						if (result != NO_ERROR) {
							Internal::SetError(err, result, L"CreateIpForwardEntry failed");
							return false;
						}

						return true;
					}
					else if (destination.IsIPv6()) {
						// IPv6 Route Addition
						MIB_IPFORWARD_ROW2 route = {};
						::InitializeIpForwardEntry(&route);

						auto* destIpv6 = destination.AsIPv6();
						auto* gwIpv6 = gateway.AsIPv6();

						// Destination prefix
						route.DestinationPrefix.Prefix.si_family = AF_INET6;
						const auto& destBytes = destIpv6->bytes;
						std::memcpy(route.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte, destBytes.data(), 16);
						route.DestinationPrefix.PrefixLength = prefixLength;

						if (prefixLength > 128) {
							Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid prefix length for IPv6");
							return false;
						}

						// Next hop (gateway)
						route.NextHop.si_family = AF_INET6;
						const auto& gwBytes = gwIpv6->bytes;
						std::memcpy(route.NextHop.Ipv6.sin6_addr.u.Byte, gwBytes.data(), 16);

						route.Protocol = MIB_IPPROTO_NETMGMT;
						route.Metric = 1;
						route.ValidLifetime = 0xFFFFFFFF; // Infinite
						route.PreferredLifetime = 0xFFFFFFFF; // Infinite

						DWORD result = ::CreateIpForwardEntry2(&route);
						if (result != NO_ERROR) {
							Internal::SetError(err, result, L"CreateIpForwardEntry2 failed");
							return false;
						}

						return true;
					}

					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid IP address type");
					return false;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in AddRoute");
					return false;
				}
			}

			bool DeleteRoute(const IpAddress& destination, uint8_t prefixLength, Error* err) noexcept {
				try {
					if (destination.IsIPv4()) {
						// IPv4 Route Deletion
						MIB_IPFORWARDROW route = {};

						auto* destIpv4 = destination.AsIPv4();
						route.dwForwardDest = Internal::HostToNetwork32(destIpv4->ToUInt32());

						// Convert prefix length to netmask
						if (prefixLength > 32) {
							Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid prefix length for IPv4");
							return false;
						}

						uint32_t mask = prefixLength == 0 ? 0 : (~0U << (32 - prefixLength));
						route.dwForwardMask = Internal::HostToNetwork32(mask);

						// Find matching route in table
						ULONG size = 0;
#pragma warning(suppress: 6387)
						::GetIpForwardTable(nullptr, &size, FALSE);

						std::vector<uint8_t> buffer(size);
						DWORD result = ::GetIpForwardTable(reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data()), &size, FALSE);

						if (result != NO_ERROR) {
							Internal::SetError(err, result, L"GetIpForwardTable failed");
							return false;
						}

						auto* pTable = reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data());
						bool found = false;

						for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
							const auto& row = pTable->table[i];

							if (row.dwForwardDest == route.dwForwardDest &&
								row.dwForwardMask == route.dwForwardMask) {

								result = ::DeleteIpForwardEntry(&pTable->table[i]);
								if (result != NO_ERROR) {
									Internal::SetError(err, result, L"DeleteIpForwardEntry failed");
									return false;
								}

								found = true;
								break;
							}
						}

						if (!found) {
							Internal::SetError(err, ERROR_NOT_FOUND, L"Route not found");
							return false;
						}

						return true;
					}
					else if (destination.IsIPv6()) {
						// IPv6 Route Deletion
						MIB_IPFORWARD_ROW2 route = {};
						::InitializeIpForwardEntry(&route);

						auto* destIpv6 = destination.AsIPv6();

						route.DestinationPrefix.Prefix.si_family = AF_INET6;
						const auto& destBytes = destIpv6->bytes;
						std::memcpy(route.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte, destBytes.data(), 16);
						route.DestinationPrefix.PrefixLength = prefixLength;

						if (prefixLength > 128) {
							Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid prefix length for IPv6");
							return false;
						}

						// Find and delete the route
						PMIB_IPFORWARD_TABLE2 pTable6 = nullptr;
						DWORD result = ::GetIpForwardTable2(AF_INET6, &pTable6);

						if (result != NO_ERROR) {
							Internal::SetError(err, result, L"GetIpForwardTable2 failed");
							return false;
						}

						struct TableDeleter {
							void operator()(PMIB_IPFORWARD_TABLE2 p) const {
								if (p) ::FreeMibTable(p);
							}
						};
						std::unique_ptr<MIB_IPFORWARD_TABLE2, TableDeleter> tableGuard(pTable6);

						bool found = false;

						for (ULONG i = 0; i < pTable6->NumEntries; ++i) {
							const auto& row = pTable6->Table[i];

							if (row.DestinationPrefix.PrefixLength == prefixLength &&
								std::memcmp(row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte,
									destBytes.data(), 16) == 0) {

								result = ::DeleteIpForwardEntry2(&pTable6->Table[i]);
								if (result != NO_ERROR) {
									Internal::SetError(err, result, L"DeleteIpForwardEntry2 failed");
									return false;
								}

								found = true;
								break;
							}
						}

						if (!found) {
							Internal::SetError(err, ERROR_NOT_FOUND, L"Route not found");
							return false;
						}

						return true;
					}

					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid IP address type");
					return false;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in DeleteRoute");
					return false;
				}
			}

			//Route modification
			bool ModifyRoute(const IpAddress& destination, uint8_t prefixLength,
				const IpAddress& newGateway, uint32_t newMetric, Error* err) noexcept {
				try {
					if (destination.IsIPv4() != newGateway.IsIPv4()) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"IP version mismatch");
						return false;
					}

					if (destination.IsIPv4()) {
						// IPv4 Route Modification
						ULONG size = 0;
#pragma warning(suppress: 6387)
						::GetIpForwardTable(nullptr, &size, FALSE);

						std::vector<uint8_t> buffer(size);
						DWORD result = ::GetIpForwardTable(reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data()), &size, FALSE);

						if (result != NO_ERROR) {
							Internal::SetError(err, result, L"GetIpForwardTable failed");
							return false;
						}

						auto* pTable = reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data());
						auto* destIpv4 = destination.AsIPv4();

						uint32_t destAddr = Internal::HostToNetwork32(destIpv4->ToUInt32());
						uint32_t mask = prefixLength == 0 ? 0 : (~0U << (32 - prefixLength));
						uint32_t netmask = Internal::HostToNetwork32(mask);

						for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
							auto& row = pTable->table[i];

							if (row.dwForwardDest == destAddr && row.dwForwardMask == netmask) {
								auto* gwIpv4 = newGateway.AsIPv4();
								row.dwForwardNextHop = Internal::HostToNetwork32(gwIpv4->ToUInt32());
								row.dwForwardMetric1 = newMetric;

								result = ::SetIpForwardEntry(&row);
								if (result != NO_ERROR) {
									Internal::SetError(err, result, L"SetIpForwardEntry failed");
									return false;
								}

								return true;
							}
						}

						Internal::SetError(err, ERROR_NOT_FOUND, L"Route not found");
						return false;
					}
					else if (destination.IsIPv6()) {
						// IPv6 Route Modification
						PMIB_IPFORWARD_TABLE2 pTable6 = nullptr;
						DWORD result = ::GetIpForwardTable2(AF_INET6, &pTable6);

						if (result != NO_ERROR) {
							Internal::SetError(err, result, L"GetIpForwardTable2 failed");
							return false;
						}

						struct TableDeleter {
							void operator()(PMIB_IPFORWARD_TABLE2 p) const {
								if (p) ::FreeMibTable(p);
							}
						};
						std::unique_ptr<MIB_IPFORWARD_TABLE2, TableDeleter> tableGuard(pTable6);

						auto* destIpv6 = destination.AsIPv6();
						const auto& destBytes = destIpv6->bytes;

						for (ULONG i = 0; i < pTable6->NumEntries; ++i) {
							auto& row = pTable6->Table[i];

							if (row.DestinationPrefix.PrefixLength == prefixLength &&
								std::memcmp(row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte,
									destBytes.data(), 16) == 0) {

								auto* gwIpv6 = newGateway.AsIPv6();
								const auto& gwBytes = gwIpv6->bytes;
								std::memcpy(row.NextHop.Ipv6.sin6_addr.u.Byte, gwBytes.data(), 16);
								row.Metric = newMetric;

								result = ::SetIpForwardEntry2(&row);
								if (result != NO_ERROR) {
									Internal::SetError(err, result, L"SetIpForwardEntry2 failed");
									return false;
								}

								return true;
							}
						}

						Internal::SetError(err, ERROR_NOT_FOUND, L"Route not found");
						return false;
					}

					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid IP address type");
					return false;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in ModifyRoute");
					return false;
				}
			}

			// ============================================================================
			// ARP Table
			// ============================================================================

			bool GetArpTable(std::vector<ArpEntry>& entries, Error* err) noexcept {
				try {
					entries.clear();

					// IPv4 ARP Table
					ULONG size = 0;
#pragma warning(suppress: 6387)
					::GetIpNetTable(nullptr, &size, FALSE);

					std::vector<uint8_t> buffer(size);
					DWORD result = ::GetIpNetTable(reinterpret_cast<PMIB_IPNETTABLE>(buffer.data()), &size, FALSE);

					if (result == NO_ERROR) {
						auto* pTable = reinterpret_cast<PMIB_IPNETTABLE>(buffer.data());

						for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
							const auto& row = pTable->table[i];

							ArpEntry entry;
							entry.ipAddress = IpAddress(IPv4Address(Internal::NetworkToHost32(row.dwAddr)));
							entry.interfaceIndex = row.dwIndex;
							entry.isStatic = (row.Type == MIB_IPNET_TYPE_STATIC);

							if (row.dwPhysAddrLen == 6) {
								std::array<uint8_t, 6> macBytes;
								std::memcpy(macBytes.data(), row.bPhysAddr, 6);
								entry.macAddress = MacAddress(macBytes);
							}

							entries.push_back(std::move(entry));
						}
					}

					// IPv6 NDP Table
					PMIB_IPNET_TABLE2 pTable6 = nullptr;
					result = ::GetIpNetTable2(AF_INET6, &pTable6);

					if (result != NO_ERROR) {
						// IPv4 entries varsa onlar� d�nd�r, IPv6 yoksa sorun de�il
						return !entries.empty();
					}

					struct TableDeleter {
						void operator()(PMIB_IPNET_TABLE2 p) const {
							if (p) ::FreeMibTable(p);
						}
					};
					std::unique_ptr<MIB_IPNET_TABLE2, TableDeleter> tableGuard(pTable6);

					for (ULONG i = 0; i < pTable6->NumEntries; ++i) {
						const auto& row = pTable6->Table[i];

						ArpEntry entry;

						// IPv6 address
						std::array<uint8_t, 16> ipBytes;
						std::memcpy(ipBytes.data(), row.Address.Ipv6.sin6_addr.u.Byte, 16);
						entry.ipAddress = IpAddress(IPv6Address(ipBytes));

						entry.interfaceIndex = row.InterfaceIndex;
						entry.isStatic = (row.State == NlnsPermanent);

						// MAC address
						if (row.PhysicalAddressLength == 6) {
							std::array<uint8_t, 6> macBytes;
							std::memcpy(macBytes.data(), row.PhysicalAddress, 6);
							entry.macAddress = MacAddress(macBytes);
						}

						entries.push_back(std::move(entry));
					}

					return true;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in GetArpTable");
					return false;
				}
			}

			bool AddArpEntry(const IpAddress& ipAddress, const MacAddress& macAddress, Error* err) noexcept {
				try {
					const auto& macBytes = macAddress.bytes;

					if (macBytes.size() != 6) {
						Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid MAC address length");
						return false;
					}

					if (ipAddress.IsIPv4()) {
						// IPv4 ARP Entry
						MIB_IPNETROW row = {};

						auto* ipv4 = ipAddress.AsIPv4();
						row.dwAddr = Internal::HostToNetwork32(ipv4->ToUInt32());
						row.dwIndex = 0; // Will need to find appropriate interface
						row.dwPhysAddrLen = 6;
						std::memcpy(row.bPhysAddr, macBytes.data(), 6);
						row.Type = MIB_IPNET_TYPE_STATIC;

						// Find appropriate interface index
						ULONG tableSize = 0;
#pragma warning(suppress: 6387)
						::GetIpNetTable(nullptr, &tableSize, FALSE);

						std::vector<uint8_t> buffer(tableSize);
						if (::GetIpNetTable(reinterpret_cast<PMIB_IPNETTABLE>(buffer.data()), &tableSize, FALSE) == NO_ERROR) {
							auto* pTable = reinterpret_cast<PMIB_IPNETTABLE>(buffer.data());
							if (pTable->dwNumEntries > 0) {
								// Use first interface index as default
								row.dwIndex = pTable->table[0].dwIndex;
							}
						}

						if (row.dwIndex == 0) {
							Internal::SetError(err, ERROR_NOT_FOUND, L"No valid interface found");
							return false;
						}

						DWORD result = ::CreateIpNetEntry(&row);
						if (result != NO_ERROR) {
							Internal::SetError(err, result, L"CreateIpNetEntry failed");
							return false;
						}

						return true;
					}
					else if (ipAddress.IsIPv6()) {
						// IPv6 NDP Entry
						MIB_IPNET_ROW2 row = {};

						auto* ipv6 = ipAddress.AsIPv6();
						const auto& ipBytes = ipv6->bytes;

						row.Address.si_family = AF_INET6;
						std::memcpy(row.Address.Ipv6.sin6_addr.u.Byte, ipBytes.data(), 16);

						row.PhysicalAddressLength = 6;
						std::memcpy(row.PhysicalAddress, macBytes.data(), 6);

						row.State = NlnsPermanent;
						row.IsRouter = FALSE;
						row.IsUnreachable = FALSE;

						// Find appropriate interface
						PMIB_IPNET_TABLE2 pTable6 = nullptr;
						DWORD result = ::GetIpNetTable2(AF_INET6, &pTable6);

						if (result == NO_ERROR && pTable6 && pTable6->NumEntries > 0) {
							row.InterfaceIndex = pTable6->Table[0].InterfaceIndex;
							row.InterfaceLuid = pTable6->Table[0].InterfaceLuid;
							::FreeMibTable(pTable6);
						}
						else {
							if (pTable6) ::FreeMibTable(pTable6);
							Internal::SetError(err, ERROR_NOT_FOUND, L"No valid IPv6 interface found");
							return false;
						}

						result = ::CreateIpNetEntry2(&row);
						if (result != NO_ERROR) {
							Internal::SetError(err, result, L"CreateIpNetEntry2 failed");
							return false;
						}

						return true;
					}

					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid IP address type");
					return false;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in AddArpEntry");
					return false;
				}
			}

			bool DeleteArpEntry(const IpAddress& ipAddress, Error* err) noexcept {
				try {
					if (ipAddress.IsIPv4()) {
						// IPv4 ARP Entry Deletion
						ULONG size = 0;
#pragma warning(suppress: 6387)
						::GetIpNetTable(nullptr, &size, FALSE);

						std::vector<uint8_t> buffer(size);
						DWORD result = ::GetIpNetTable(reinterpret_cast<PMIB_IPNETTABLE>(buffer.data()), &size, FALSE);

						if (result != NO_ERROR) {
							Internal::SetError(err, result, L"GetIpNetTable failed");
							return false;
						}

						auto* pTable = reinterpret_cast<PMIB_IPNETTABLE>(buffer.data());
						auto* ipv4 = ipAddress.AsIPv4();
						uint32_t targetAddr = Internal::HostToNetwork32(ipv4->ToUInt32());

						bool found = false;

						for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
							if (pTable->table[i].dwAddr == targetAddr) {
								result = ::DeleteIpNetEntry(&pTable->table[i]);
								if (result != NO_ERROR) {
									Internal::SetError(err, result, L"DeleteIpNetEntry failed");
									return false;
								}
								found = true;
								break;
							}
						}

						if (!found) {
							Internal::SetError(err, ERROR_NOT_FOUND, L"ARP entry not found");
							return false;
						}

						return true;
					}
					else if (ipAddress.IsIPv6()) {
						// IPv6 NDP Entry Deletion
						PMIB_IPNET_TABLE2 pTable6 = nullptr;
						DWORD result = ::GetIpNetTable2(AF_INET6, &pTable6);

						if (result != NO_ERROR) {
							Internal::SetError(err, result, L"GetIpNetTable2 failed");
							return false;
						}

						struct TableDeleter {
							void operator()(PMIB_IPNET_TABLE2 p) const {
								if (p) ::FreeMibTable(p);
							}
						};
						std::unique_ptr<MIB_IPNET_TABLE2, TableDeleter> tableGuard(pTable6);

						auto* ipv6 = ipAddress.AsIPv6();
						const auto& targetBytes = ipv6->bytes;

						bool found = false;

						for (ULONG i = 0; i < pTable6->NumEntries; ++i) {
							if (std::memcmp(pTable6->Table[i].Address.Ipv6.sin6_addr.u.Byte,
								targetBytes.data(), 16) == 0) {

								result = ::DeleteIpNetEntry2(&pTable6->Table[i]);
								if (result != NO_ERROR) {
									Internal::SetError(err, result, L"DeleteIpNetEntry2 failed");
									return false;
								}
								found = true;
								break;
							}
						}

						if (!found) {
							Internal::SetError(err, ERROR_NOT_FOUND, L"NDP entry not found");
							return false;
						}

						return true;
					}

					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Invalid IP address type");
					return false;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in DeleteArpEntry");
					return false;
				}
			}

			bool FlushArpCache(Error* err) noexcept {
				try {
					bool success = true;

					// Flush IPv4 ARP Cache
					ULONG size = 0;
#pragma warning(suppress: 6387)
					::GetIpNetTable(nullptr, &size, FALSE);

					std::vector<uint8_t> buffer(size);
					DWORD result = ::GetIpNetTable(reinterpret_cast<PMIB_IPNETTABLE>(buffer.data()), &size, FALSE);

					if (result == NO_ERROR) {
						auto* pTable = reinterpret_cast<PMIB_IPNETTABLE>(buffer.data());

						// Delete all dynamic entries (keep static ones)
						for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
							if (pTable->table[i].Type != MIB_IPNET_TYPE_STATIC) {
								result = ::DeleteIpNetEntry(&pTable->table[i]);
								if (result != NO_ERROR) {
									success = false;
								}
							}
						}
					}

					// Flush IPv6 NDP Cache
					PMIB_IPNET_TABLE2 pTable6 = nullptr;
					result = ::GetIpNetTable2(AF_INET6, &pTable6);

					if (result == NO_ERROR) {
						struct TableDeleter {
							void operator()(PMIB_IPNET_TABLE2 p) const {
								if (p) ::FreeMibTable(p);
							}
						};
						std::unique_ptr<MIB_IPNET_TABLE2, TableDeleter> tableGuard(pTable6);

						// Delete all non-permanent entries
						for (ULONG i = 0; i < pTable6->NumEntries; ++i) {
							if (pTable6->Table[i].State != NlnsPermanent) {
								result = ::DeleteIpNetEntry2(&pTable6->Table[i]);
								if (result != NO_ERROR) {
									success = false;
								}
							}
						}
					}

					if (!success) {
						Internal::SetError(err, ERROR_PARTIAL_COPY, L"Some entries could not be flushed");
						return false;
					}

					return true;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in FlushArpCache");
					return false;
				}
			}


			bool FlushArpCache(uint32_t interfaceIndex, Error* err) noexcept {
				try {
					bool success = true;

					// Flush IPv4 ARP Cache for specific interface
					ULONG size = 0;
#pragma warning(suppress: 6387)
					::GetIpNetTable(nullptr, &size, FALSE);

					std::vector<uint8_t> buffer(size);
					DWORD result = ::GetIpNetTable(reinterpret_cast<PMIB_IPNETTABLE>(buffer.data()), &size, FALSE);

					if (result == NO_ERROR) {
						auto* pTable = reinterpret_cast<PMIB_IPNETTABLE>(buffer.data());

						for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
							if (pTable->table[i].dwIndex == interfaceIndex &&
								pTable->table[i].Type != MIB_IPNET_TYPE_STATIC) {

								result = ::DeleteIpNetEntry(&pTable->table[i]);
								if (result != NO_ERROR) {
									success = false;
								}
							}
						}
					}

					// Flush IPv6 NDP Cache for specific interface
					PMIB_IPNET_TABLE2 pTable6 = nullptr;
					result = ::GetIpNetTable2(AF_INET6, &pTable6);

					if (result == NO_ERROR) {
						struct TableDeleter {
							void operator()(PMIB_IPNET_TABLE2 p) const {
								if (p) ::FreeMibTable(p);
							}
						};
						std::unique_ptr<MIB_IPNET_TABLE2, TableDeleter> tableGuard(pTable6);

						for (ULONG i = 0; i < pTable6->NumEntries; ++i) {
							if (pTable6->Table[i].InterfaceIndex == interfaceIndex &&
								pTable6->Table[i].State != NlnsPermanent) {

								result = ::DeleteIpNetEntry2(&pTable6->Table[i]);
								if (result != NO_ERROR) {
									success = false;
								}
							}
						}
					}

					if (!success) {
						Internal::SetError(err, ERROR_PARTIAL_COPY, L"Some entries could not be flushed");
						return false;
					}

					return true;

				}
				catch (...) {
					Internal::SetError(err, ERROR_INVALID_PARAMETER, L"Exception in FlushArpCache");
					return false;
				}
			}

		}//namespace NetworkUtils
	}//namespace Utils
}//namespace ShadowStrike