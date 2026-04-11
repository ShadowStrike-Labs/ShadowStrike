@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1

if not exist build\core_network_int_obj mkdir build\core_network_int_obj

cl /std:c++20 /EHsc /MDd /W4 /wd4100 /wd4189 /wd4244 /wd4267 /wd4996 /wd4834 ^
  /I. /Isrc /Isrc\PhantomCore /Iinclude /Iinclude\YARA /Ivendor /Ivendor\gtest_framework\include ^
  /nologo ^
  tests\test_main.cpp ^
  tests\integration\core_network\NetworkChain_Integration_Tests.cpp ^
  src\PhantomCore\Core\Network\NetworkMonitor.cpp ^
  src\PhantomCore\Core\Network\DNSMonitor.cpp ^
  src\PhantomCore\Core\Network\FirewallManager.cpp ^
  src\PhantomCore\PatternStore\PatternStore.cpp ^
  src\PhantomCore\PatternStore\PatternIndex.cpp ^
  src\PhantomCore\PatternStore\aho_crsck_impl.cpp ^
  src\PhantomCore\PatternStore\boyer_moore_impl.cpp ^
  src\PhantomCore\PatternStore\SIMD_matcher_impl.cpp ^
  src\PhantomCore\SignatureStore\SignatureFormat.cpp ^
  src\PhantomCore\Whitelist\WhiteListStore.cpp ^
  src\PhantomCore\Whitelist\WhiteListFormat.cpp ^
  src\PhantomCore\Whitelist\WhiteListHashIndex.cpp ^
  src\PhantomCore\Whitelist\WhiteListPatternIndex.cpp ^
  src\PhantomCore\Whitelist\WhiteListBloomFilter.cpp ^
  src\PhantomCore\Whitelist\WhiteListStringPool.cpp ^
  src\PhantomCore\ThreatIntel\ThreatIntelStore.cpp ^
  src\PhantomCore\ThreatIntel\ThreatIntelLookup.cpp ^
  src\PhantomCore\ThreatIntel\ThreatIntelIOCManager.cpp ^
  src\PhantomCore\ThreatIntel\ThreatIntelIndex_URLMatcher.cpp ^
  src\PhantomCore\ThreatIntel\ThreatIntelIndex_Trees.cpp ^
  src\PhantomCore\ThreatIntel\ThreatIntelIndex_Modifications.cpp ^
  src\PhantomCore\ThreatIntel\ThreatIntelIndex_Lookups.cpp ^
  src\PhantomCore\ThreatIntel\ThreatIntelIndex_DataStructures.cpp ^
  src\PhantomCore\ThreatIntel\ThreatIntelIndex_Core.cpp ^
  src\PhantomCore\ThreatIntel\ThreatIntelImporter.cpp ^
  src\PhantomCore\ThreatIntel\ThreatIntelFormat.cpp ^
  src\PhantomCore\ThreatIntel\ThreatIntelFeedManager_parsers.cpp ^
  src\PhantomCore\ThreatIntel\ThreatIntelFeedManager.cpp ^
  src\PhantomCore\ThreatIntel\ThreatIntelExporter.cpp ^
  src\PhantomCore\ThreatIntel\ThreatIntelDatabase.cpp ^
  src\PhantomCore\ThreatIntel\ThreatIntelBloomFilter.cpp ^
  src\PhantomCore\ThreatIntel\ReputationCache.cpp ^
  src\PhantomCore\Database\DatabaseManager.cpp ^
  src\PhantomCore\Database\ConfigurationDB.cpp ^
  src\PhantomCore\Database\LogDB.cpp ^
  src\PhantomCore\Database\QuarantineDB.cpp ^
  src\PhantomCore\External\SQLiteCpp\Statement.cpp ^
  src\PhantomCore\External\SQLiteCpp\Database.cpp ^
  src\PhantomCore\External\SQLiteCpp\Column.cpp ^
  src\PhantomCore\External\SQLiteCpp\Backup.cpp ^
  src\PhantomCore\External\SQLiteCpp\Transaction.cpp ^
  src\PhantomCore\External\SQLiteCpp\Savepoint.cpp ^
  src\PhantomCore\External\SQLiteCpp\Exception.cpp ^
  src\PhantomCore\External\SQLiteCpp\sqlite3.c ^
  src\PhantomCore\External\pugixml\pugixml.cpp ^
  src\PhantomCore\Utils\Logger.cpp ^
  src\PhantomCore\Utils\StringUtils.cpp ^
  src\PhantomCore\Utils\HashUtils.cpp ^
  src\PhantomCore\Utils\FileUtils.cpp ^
  src\PhantomCore\Utils\JSONUtils.cpp ^
  src\PhantomCore\Utils\XMLUtils.cpp ^
  src\PhantomCore\Utils\Base64Utils.cpp ^
  src\PhantomCore\Utils\CompressionUtils.cpp ^
  src\PhantomCore\Utils\RegistryUtils.cpp ^
  src\PhantomCore\Utils\MemoryUtils.cpp ^
  src\PhantomCore\Utils\ProcessUtils.cpp ^
  src\PhantomCore\Utils\SystemUtils.cpp ^
  src\PhantomCore\Utils\Timer.cpp ^
  src\PhantomCore\Utils\ThreadPool.cpp ^
  src\PhantomCore\Utils\NetworkUtils.cpp ^
  src\PhantomCore\Utils\NetworkUtils_http_https.cpp ^
  src\PhantomCore\Utils\NetworkUtils_DNS.cpp ^
  src\PhantomCore\Utils\NetworkUtils_Adapter.cpp ^
  src\PhantomCore\Utils\NetworkUtilsIpAddress.cpp ^
  src\PhantomCore\Utils\NetworkUtilsMacAdress.cpp ^
  src\PhantomCore\Utils\NetworkUtils_URL.cpp ^
  src\PhantomCore\Utils\NetworkUtils_proxy.cpp ^
  src\PhantomCore\Utils\NetworkSecurity_SSL_TLS.cpp ^
  src\PhantomCore\Utils\CryptoUtils.cpp ^
  src\PhantomCore\Utils\CryptoUtilsCommon.cpp ^
  src\PhantomCore\Utils\CryptoUtils_SymmetricCipher.cpp ^
  src\PhantomCore\Utils\CryptoUtils_AsymmetricCipher.cpp ^
  src\PhantomCore\Utils\CryptoUtils_SecureBuffer.cpp ^
  src\PhantomCore\Utils\CryptoUtils_Secure_Random.cpp ^
  src\PhantomCore\Utils\CryptoUtils_private_key.cpp ^
  src\PhantomCore\Utils\CacheManager.cpp ^
  src\PhantomCore\Utils\CertUtils.cpp ^
  /Fobuild\core_network_int_obj\ ^
  /Fe:build\core_network_integration_tests.exe ^
  /link /LIBPATH:vendor\gtest_framework gtest.lib gmock.lib ^
  /LIBPATH:vendor\yara_lib libyara.lib ^
  advapi32.lib ws2_32.lib crypt32.lib shell32.lib ole32.lib shlwapi.lib user32.lib ^
  iphlpapi.lib winhttp.lib wintrust.lib wbemuuid.lib oleaut32.lib ^
  SetupAPI.lib Cfgmgr32.lib psapi.lib ntdll.lib kernel32.lib fwpuclnt.lib bcrypt.lib

endlocal
