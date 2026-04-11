@echo off
setlocal

call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
if %errorlevel% neq 0 exit /b 1

if not exist build\spi_obj mkdir build\spi_obj

cl /std:c++20 /EHsc /MDd /W4 /wd4100 /wd4189 /wd4244 /wd4267 /wd4996 /wd4834 ^
  /DSHADOWSTRIKE_HAS_YARA ^
  /I. /Isrc /Isrc\Shared_modules /Iinclude /Iinclude\YARA /Ivendor /Ivendor\gtest_framework\include ^
  /nologo ^
  tests\test_main.cpp ^
  tests\integration\scan_pipeline\ScanPipeline_Integration_Tests.cpp ^
  src\Shared_modules\FuzzyHasher\FuzzyHasher.cpp ^
  src\Shared_modules\FuzzyHasher\DigestGenerator.cpp ^
  src\Shared_modules\FuzzyHasher\DigestComparer.cpp ^
  src\Shared_modules\External\tlsh\tlsh.cpp ^
  src\Shared_modules\External\tlsh\tlsh_impl.cpp ^
  src\Shared_modules\External\tlsh\tlsh_util.cpp ^
  src\Shared_modules\External\tlsh\shared_file_functions.cpp ^
  src\Shared_modules\External\tlsh\input_desc.cpp ^
  src\Shared_modules\HashStore\HashStore.cpp ^
  src\Shared_modules\HashStore\HashStore_mgnmnt.cpp ^
  src\Shared_modules\HashStore\HashStore_query_operations.cpp ^
  src\Shared_modules\HashStore\HashStore_import_export.cpp ^
  src\Shared_modules\HashStore\BloomFilter_impl.cpp ^
  src\Shared_modules\HashStore\HashBucket_impl.cpp ^
  src\Shared_modules\PatternStore\PatternIndex.cpp ^
  src\Shared_modules\PatternStore\PatternStore.cpp ^
  src\Shared_modules\PatternStore\SIMD_matcher_impl.cpp ^
  src\Shared_modules\PatternStore\aho_crsck_impl.cpp ^
  src\Shared_modules\PatternStore\boyer_moore_impl.cpp ^
  src\Shared_modules\Whitelist\WhiteListStore.cpp ^
  src\Shared_modules\Whitelist\WhiteListFormat.cpp ^
  src\Shared_modules\Whitelist\WhiteListHashIndex.cpp ^
  src\Shared_modules\Whitelist\WhiteListPatternIndex.cpp ^
  src\Shared_modules\Whitelist\WhiteListBloomFilter.cpp ^
  src\Shared_modules\Whitelist\WhiteListStringPool.cpp ^
  src\Shared_modules\SignatureStore\SignatureFormat.cpp ^
  src\Shared_modules\SignatureStore\SignatureBuilder.cpp ^
  src\Shared_modules\SignatureStore\batch_sig_builder.cpp ^
  src\Shared_modules\SignatureStore\SignatureIndex.cpp ^
  src\Shared_modules\SignatureStore\SignatureIndex_COW.cpp ^
  src\Shared_modules\SignatureStore\SignatureIndex_Cache_mngmnt.cpp ^
  src\Shared_modules\SignatureStore\SignatureIndex_modification.cpp ^
  src\Shared_modules\SignatureStore\SignatureIndex_Query.cpp ^
  src\Shared_modules\SignatureStore\SignatureIndex_stat_maintenance.cpp ^
  src\Shared_modules\SignatureStore\SignatureStore.cpp ^
  src\Shared_modules\SignatureStore\SignatureStore_mngmnt.cpp ^
  src\Shared_modules\SignatureStore\SignatureStore_Query.cpp ^
  src\Shared_modules\SignatureStore\SignatureStore_scan.cpp ^
  src\Shared_modules\SignatureStore\sig_builder_import_methods.cpp ^
  src\Shared_modules\SignatureStore\sig_builder_input_methods.cpp ^
  src\Shared_modules\SignatureStore\sig_builder_serialization.cpp ^
  src\Shared_modules\SignatureStore\sig_builder_utils.cpp ^
  src\Shared_modules\SignatureStore\sig_indx_internal_node_mng.cpp ^
  src\Shared_modules\SignatureStore\YaraRuleStore.cpp ^
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
  src\Shared_modules\PEParser\PEParser.cpp ^
  src\Shared_modules\PEParser\PEValidation.cpp ^
  src\Shared_modules\Utils\Logger.cpp ^
  src\Shared_modules\Utils\StringUtils.cpp ^
  src\Shared_modules\Utils\HashUtils.cpp ^
  src\Shared_modules\Utils\FileUtils.cpp ^
  src\Shared_modules\Utils\JSONUtils.cpp ^
  src\Shared_modules\Utils\RegistryUtils.cpp ^
  src\Shared_modules\Utils\MemoryUtils.cpp ^
  src\Shared_modules\Utils\ProcessUtils.cpp ^
  src\Shared_modules\Utils\SystemUtils.cpp ^
  src\Shared_modules\Utils\Timer.cpp ^
  src\Shared_modules\Utils\ThreadPool.cpp ^
  src\Shared_modules\Utils\CacheManager.cpp ^
  src\Shared_modules\Utils\CryptoUtils.cpp ^
  src\Shared_modules\Utils\CryptoUtilsCommon.cpp ^
  src\Shared_modules\Utils\CryptoUtils_AsymmetricCipher.cpp ^
  src\Shared_modules\Utils\CryptoUtils_SecureBuffer.cpp ^
  src\Shared_modules\Utils\CryptoUtils_Secure_Random.cpp ^
  src\Shared_modules\Utils\CryptoUtils_SymmetricCipher.cpp ^
  src\Shared_modules\Utils\CryptoUtils_private_key.cpp ^
  src\Shared_modules\Utils\CertUtils.cpp ^
  src\Shared_modules\Utils\Base64Utils.cpp ^
  src\Shared_modules\Utils\NetworkUtils.cpp ^
  src\Shared_modules\Utils\NetworkUtils_http_https.cpp ^
  src\Shared_modules\Utils\NetworkUtils_DNS.cpp ^
  src\Shared_modules\Utils\NetworkUtils_Adapter.cpp ^
  src\Shared_modules\Utils\NetworkUtilsIpAddress.cpp ^
  src\Shared_modules\Utils\NetworkUtilsMacAdress.cpp ^
  src\Shared_modules\Utils\NetworkUtils_URL.cpp ^
  src\Shared_modules\Utils\NetworkUtils_proxy.cpp ^
  src\Shared_modules\Utils\NetworkSecurity_SSL_TLS.cpp ^
  src\Shared_modules\Utils\PE_sig_verf.cpp ^
  src\Shared_modules\Utils\XMLUtils.cpp ^
  src\Shared_modules\External\pugixml\pugixml.cpp ^
  /Fobuild\spi_obj\ ^
  /Fe:build\scan_pipeline_integration_tests.exe ^
  /link /LIBPATH:vendor\gtest_framework gtest.lib gmock.lib ^
  /LIBPATH:vendor\yara_lib libyara.lib ^
  /LIBPATH:vendor\openssl_lib libcrypto.lib libssl.lib ^
  advapi32.lib ws2_32.lib crypt32.lib shell32.lib ole32.lib shlwapi.lib user32.lib ^
  iphlpapi.lib winhttp.lib wintrust.lib wbemuuid.lib oleaut32.lib ^
  SetupAPI.lib Cfgmgr32.lib psapi.lib ntdll.lib kernel32.lib

endlocal
