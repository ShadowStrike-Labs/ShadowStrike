@echo off
setlocal

call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
if %errorlevel% neq 0 exit /b 1

if not exist build\spi_obj mkdir build\spi_obj

cl /std:c++20 /EHsc /MDd /W4 /wd4100 /wd4189 /wd4244 /wd4267 /wd4996 /wd4834 ^
  /DSHADOWSTRIKE_HAS_YARA ^
  /I. /Isrc /Isrc\PhantomCore /Iinclude /Iinclude\YARA /Ivendor /Ivendor\gtest_framework\include ^
  /nologo ^
  tests\test_main.cpp ^
  tests\integration\scan_pipeline\ScanPipeline_Integration_Tests.cpp ^
  src\PhantomCore\FuzzyHasher\FuzzyHasher.cpp ^
  src\PhantomCore\FuzzyHasher\DigestGenerator.cpp ^
  src\PhantomCore\FuzzyHasher\DigestComparer.cpp ^
  src\PhantomCore\External\tlsh\tlsh.cpp ^
  src\PhantomCore\External\tlsh\tlsh_impl.cpp ^
  src\PhantomCore\External\tlsh\tlsh_util.cpp ^
  src\PhantomCore\External\tlsh\shared_file_functions.cpp ^
  src\PhantomCore\External\tlsh\input_desc.cpp ^
  src\PhantomCore\HashStore\HashStore.cpp ^
  src\PhantomCore\HashStore\HashStore_mgnmnt.cpp ^
  src\PhantomCore\HashStore\HashStore_query_operations.cpp ^
  src\PhantomCore\HashStore\HashStore_import_export.cpp ^
  src\PhantomCore\HashStore\BloomFilter_impl.cpp ^
  src\PhantomCore\HashStore\HashBucket_impl.cpp ^
  src\PhantomCore\PatternStore\PatternIndex.cpp ^
  src\PhantomCore\PatternStore\PatternStore.cpp ^
  src\PhantomCore\PatternStore\SIMD_matcher_impl.cpp ^
  src\PhantomCore\PatternStore\aho_crsck_impl.cpp ^
  src\PhantomCore\PatternStore\boyer_moore_impl.cpp ^
  src\PhantomCore\Whitelist\WhiteListStore.cpp ^
  src\PhantomCore\Whitelist\WhiteListFormat.cpp ^
  src\PhantomCore\Whitelist\WhiteListHashIndex.cpp ^
  src\PhantomCore\Whitelist\WhiteListPatternIndex.cpp ^
  src\PhantomCore\Whitelist\WhiteListBloomFilter.cpp ^
  src\PhantomCore\Whitelist\WhiteListStringPool.cpp ^
  src\PhantomCore\SignatureStore\SignatureFormat.cpp ^
  src\PhantomCore\SignatureStore\SignatureBuilder.cpp ^
  src\PhantomCore\SignatureStore\batch_sig_builder.cpp ^
  src\PhantomCore\SignatureStore\SignatureIndex.cpp ^
  src\PhantomCore\SignatureStore\SignatureIndex_COW.cpp ^
  src\PhantomCore\SignatureStore\SignatureIndex_Cache_mngmnt.cpp ^
  src\PhantomCore\SignatureStore\SignatureIndex_modification.cpp ^
  src\PhantomCore\SignatureStore\SignatureIndex_Query.cpp ^
  src\PhantomCore\SignatureStore\SignatureIndex_stat_maintenance.cpp ^
  src\PhantomCore\SignatureStore\SignatureStore.cpp ^
  src\PhantomCore\SignatureStore\SignatureStore_mngmnt.cpp ^
  src\PhantomCore\SignatureStore\SignatureStore_Query.cpp ^
  src\PhantomCore\SignatureStore\SignatureStore_scan.cpp ^
  src\PhantomCore\SignatureStore\sig_builder_import_methods.cpp ^
  src\PhantomCore\SignatureStore\sig_builder_input_methods.cpp ^
  src\PhantomCore\SignatureStore\sig_builder_serialization.cpp ^
  src\PhantomCore\SignatureStore\sig_builder_utils.cpp ^
  src\PhantomCore\SignatureStore\sig_indx_internal_node_mng.cpp ^
  src\PhantomCore\SignatureStore\YaraRuleStore.cpp ^
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
  src\PhantomCore\PEParser\PEParser.cpp ^
  src\PhantomCore\PEParser\PEValidation.cpp ^
  src\PhantomCore\Utils\Logger.cpp ^
  src\PhantomCore\Utils\StringUtils.cpp ^
  src\PhantomCore\Utils\HashUtils.cpp ^
  src\PhantomCore\Utils\FileUtils.cpp ^
  src\PhantomCore\Utils\JSONUtils.cpp ^
  src\PhantomCore\Utils\RegistryUtils.cpp ^
  src\PhantomCore\Utils\MemoryUtils.cpp ^
  src\PhantomCore\Utils\ProcessUtils.cpp ^
  src\PhantomCore\Utils\SystemUtils.cpp ^
  src\PhantomCore\Utils\Timer.cpp ^
  src\PhantomCore\Utils\ThreadPool.cpp ^
  src\PhantomCore\Utils\CacheManager.cpp ^
  src\PhantomCore\Utils\CryptoUtils.cpp ^
  src\PhantomCore\Utils\CryptoUtilsCommon.cpp ^
  src\PhantomCore\Utils\CryptoUtils_AsymmetricCipher.cpp ^
  src\PhantomCore\Utils\CryptoUtils_SecureBuffer.cpp ^
  src\PhantomCore\Utils\CryptoUtils_Secure_Random.cpp ^
  src\PhantomCore\Utils\CryptoUtils_SymmetricCipher.cpp ^
  src\PhantomCore\Utils\CryptoUtils_private_key.cpp ^
  src\PhantomCore\Utils\CertUtils.cpp ^
  src\PhantomCore\Utils\Base64Utils.cpp ^
  src\PhantomCore\Utils\NetworkUtils.cpp ^
  src\PhantomCore\Utils\NetworkUtils_http_https.cpp ^
  src\PhantomCore\Utils\NetworkUtils_DNS.cpp ^
  src\PhantomCore\Utils\NetworkUtils_Adapter.cpp ^
  src\PhantomCore\Utils\NetworkUtilsIpAddress.cpp ^
  src\PhantomCore\Utils\NetworkUtilsMacAdress.cpp ^
  src\PhantomCore\Utils\NetworkUtils_URL.cpp ^
  src\PhantomCore\Utils\NetworkUtils_proxy.cpp ^
  src\PhantomCore\Utils\NetworkSecurity_SSL_TLS.cpp ^
  src\PhantomCore\Utils\PE_sig_verf.cpp ^
  src\PhantomCore\Utils\XMLUtils.cpp ^
  src\PhantomCore\External\pugixml\pugixml.cpp ^
  /Fobuild\spi_obj\ ^
  /Fe:build\scan_pipeline_integration_tests.exe ^
  /link /LIBPATH:vendor\gtest_framework gtest.lib gmock.lib ^
  /LIBPATH:vendor\yara_lib libyara.lib ^
  /LIBPATH:vendor\openssl_lib libcrypto.lib libssl.lib ^
  advapi32.lib ws2_32.lib crypt32.lib shell32.lib ole32.lib shlwapi.lib user32.lib ^
  iphlpapi.lib winhttp.lib wintrust.lib wbemuuid.lib oleaut32.lib ^
  SetupAPI.lib Cfgmgr32.lib psapi.lib ntdll.lib kernel32.lib

endlocal
