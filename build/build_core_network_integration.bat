@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1

if not exist build\core_network_int_obj mkdir build\core_network_int_obj

cl /std:c++20 /EHsc /MDd /W4 /wd4100 /wd4189 /wd4244 /wd4267 /wd4996 /wd4834 ^
  /I. /Isrc /Isrc\Shared_modules /Iinclude /Iinclude\YARA /Ivendor /Ivendor\gtest_framework\include ^
  /nologo ^
  tests\test_main.cpp ^
  tests\integration\core_network\NetworkChain_Integration_Tests.cpp ^
  src\Shared_modules\Core\Network\NetworkMonitor.cpp ^
  src\Shared_modules\Core\Network\DNSMonitor.cpp ^
  src\Shared_modules\Core\Network\FirewallManager.cpp ^
  src\Shared_modules\PatternStore\PatternStore.cpp ^
  src\Shared_modules\PatternStore\PatternIndex.cpp ^
  src\Shared_modules\PatternStore\aho_crsck_impl.cpp ^
  src\Shared_modules\PatternStore\boyer_moore_impl.cpp ^
  src\Shared_modules\PatternStore\SIMD_matcher_impl.cpp ^
  src\Shared_modules\SignatureStore\SignatureFormat.cpp ^
  src\Shared_modules\Whitelist\WhiteListStore.cpp ^
  src\Shared_modules\Whitelist\WhiteListFormat.cpp ^
  src\Shared_modules\Whitelist\WhiteListHashIndex.cpp ^
  src\Shared_modules\Whitelist\WhiteListPatternIndex.cpp ^
  src\Shared_modules\Whitelist\WhiteListBloomFilter.cpp ^
  src\Shared_modules\Whitelist\WhiteListStringPool.cpp ^
  src\Shared_modules\ThreatIntel\ThreatIntelStore.cpp ^
  src\Shared_modules\ThreatIntel\ThreatIntelLookup.cpp ^
  src\Shared_modules\ThreatIntel\ThreatIntelIOCManager.cpp ^
  src\Shared_modules\ThreatIntel\ThreatIntelIndex_URLMatcher.cpp ^
  src\Shared_modules\ThreatIntel\ThreatIntelIndex_Trees.cpp ^
  src\Shared_modules\ThreatIntel\ThreatIntelIndex_Modifications.cpp ^
  src\Shared_modules\ThreatIntel\ThreatIntelIndex_Lookups.cpp ^
  src\Shared_modules\ThreatIntel\ThreatIntelIndex_DataStructures.cpp ^
  src\Shared_modules\ThreatIntel\ThreatIntelIndex_Core.cpp ^
  src\Shared_modules\ThreatIntel\ThreatIntelImporter.cpp ^
  src\Shared_modules\ThreatIntel\ThreatIntelFormat.cpp ^
  src\Shared_modules\ThreatIntel\ThreatIntelFeedManager_parsers.cpp ^
  src\Shared_modules\ThreatIntel\ThreatIntelFeedManager.cpp ^
  src\Shared_modules\ThreatIntel\ThreatIntelExporter.cpp ^
  src\Shared_modules\ThreatIntel\ThreatIntelDatabase.cpp ^
  src\Shared_modules\ThreatIntel\ThreatIntelBloomFilter.cpp ^
  src\Shared_modules\ThreatIntel\ReputationCache.cpp ^
  src\Shared_modules\Database\DatabaseManager.cpp ^
  src\Shared_modules\Database\ConfigurationDB.cpp ^
  src\Shared_modules\Database\LogDB.cpp ^
  src\Shared_modules\Database\QuarantineDB.cpp ^
  src\Shared_modules\External\SQLiteCpp\Statement.cpp ^
  src\Shared_modules\External\SQLiteCpp\Database.cpp ^
  src\Shared_modules\External\SQLiteCpp\Column.cpp ^
  src\Shared_modules\External\SQLiteCpp\Backup.cpp ^
  src\Shared_modules\External\SQLiteCpp\Transaction.cpp ^
  src\Shared_modules\External\SQLiteCpp\Savepoint.cpp ^
  src\Shared_modules\External\SQLiteCpp\Exception.cpp ^
  src\Shared_modules\External\SQLiteCpp\sqlite3.c ^
  src\Shared_modules\External\pugixml\pugixml.cpp ^
  src\Shared_modules\Utils\Logger.cpp ^
  src\Shared_modules\Utils\StringUtils.cpp ^
  src\Shared_modules\Utils\HashUtils.cpp ^
  src\Shared_modules\Utils\FileUtils.cpp ^
  src\Shared_modules\Utils\JSONUtils.cpp ^
  src\Shared_modules\Utils\XMLUtils.cpp ^
  src\Shared_modules\Utils\Base64Utils.cpp ^
  src\Shared_modules\Utils\CompressionUtils.cpp ^
  src\Shared_modules\Utils\RegistryUtils.cpp ^
  src\Shared_modules\Utils\MemoryUtils.cpp ^
  src\Shared_modules\Utils\ProcessUtils.cpp ^
  src\Shared_modules\Utils\SystemUtils.cpp ^
  src\Shared_modules\Utils\Timer.cpp ^
  src\Shared_modules\Utils\ThreadPool.cpp ^
  src\Shared_modules\Utils\NetworkUtils.cpp ^
  src\Shared_modules\Utils\NetworkUtils_http_https.cpp ^
  src\Shared_modules\Utils\NetworkUtils_DNS.cpp ^
  src\Shared_modules\Utils\NetworkUtils_Adapter.cpp ^
  src\Shared_modules\Utils\NetworkUtilsIpAddress.cpp ^
  src\Shared_modules\Utils\NetworkUtilsMacAdress.cpp ^
  src\Shared_modules\Utils\NetworkUtils_URL.cpp ^
  src\Shared_modules\Utils\NetworkUtils_proxy.cpp ^
  src\Shared_modules\Utils\NetworkSecurity_SSL_TLS.cpp ^
  src\Shared_modules\Utils\CryptoUtils.cpp ^
  src\Shared_modules\Utils\CryptoUtilsCommon.cpp ^
  src\Shared_modules\Utils\CryptoUtils_SymmetricCipher.cpp ^
  src\Shared_modules\Utils\CryptoUtils_AsymmetricCipher.cpp ^
  src\Shared_modules\Utils\CryptoUtils_SecureBuffer.cpp ^
  src\Shared_modules\Utils\CryptoUtils_Secure_Random.cpp ^
  src\Shared_modules\Utils\CryptoUtils_private_key.cpp ^
  src\Shared_modules\Utils\CacheManager.cpp ^
  src\Shared_modules\Utils\CertUtils.cpp ^
  /Fobuild\core_network_int_obj\ ^
  /Fe:build\core_network_integration_tests.exe ^
  /link /LIBPATH:vendor\gtest_framework gtest.lib gmock.lib ^
  /LIBPATH:vendor\yara_lib libyara.lib ^
  advapi32.lib ws2_32.lib crypt32.lib shell32.lib ole32.lib shlwapi.lib user32.lib ^
  iphlpapi.lib winhttp.lib wintrust.lib wbemuuid.lib oleaut32.lib ^
  SetupAPI.lib Cfgmgr32.lib psapi.lib ntdll.lib kernel32.lib fwpuclnt.lib bcrypt.lib

endlocal
