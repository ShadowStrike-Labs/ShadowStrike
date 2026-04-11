@echo off
setlocal

call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1

set CFLAGS=/std:c++20 /EHsc /MDd /W4 /wd4100 /wd4189 /wd4244 /wd4267 /wd4996 /wd4834 ^
  /DSHADOWSTRIKE_HAS_YARA ^
  /I. /Isrc /Isrc\Shared_modules /Iinclude /Iinclude\YARA /Ivendor /Ivendor\gtest_framework\include ^
  /nologo

if not exist build\cfs_obj mkdir build\cfs_obj

:: ============================================================================
:: Step 1: Compile all C/C++ translation units (compile-only, /c)
:: ============================================================================

cl %CFLAGS% /c tests\test_main.cpp                                                        /Fobuild\cfs_obj\test_main.obj
if %errorlevel% neq 0 ( echo [ERROR] test_main.cpp & exit /b 1 )

cl %CFLAGS% /c tests\integration\core_filesystem\FileSystemChain_Integration_Tests.cpp    /Fobuild\cfs_obj\FileSystemChain_Integration_Tests.obj
if %errorlevel% neq 0 ( echo [ERROR] FileSystemChain_Integration_Tests.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Core\FileSystem\FileHasher.cpp                          /Fobuild\cfs_obj\FileHasher.obj
if %errorlevel% neq 0 ( echo [ERROR] FileHasher.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Core\FileSystem\FileTypeAnalyzer.cpp                    /Fobuild\cfs_obj\FileTypeAnalyzer.obj
if %errorlevel% neq 0 ( echo [ERROR] FileTypeAnalyzer.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Core\FileSystem\FileReputation.cpp                      /Fobuild\cfs_obj\FileReputation.obj
if %errorlevel% neq 0 ( echo [ERROR] FileReputation.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\FuzzyHasher\FuzzyHasher.cpp                             /Fobuild\cfs_obj\FuzzyHasher.obj
if %errorlevel% neq 0 ( echo [ERROR] FuzzyHasher.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\FuzzyHasher\DigestGenerator.cpp                         /Fobuild\cfs_obj\DigestGenerator.obj
if %errorlevel% neq 0 ( echo [ERROR] DigestGenerator.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\FuzzyHasher\DigestComparer.cpp                          /Fobuild\cfs_obj\DigestComparer.obj
if %errorlevel% neq 0 ( echo [ERROR] DigestComparer.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\External\tlsh\tlsh.cpp                                 /Fobuild\cfs_obj\tlsh.obj
if %errorlevel% neq 0 ( echo [ERROR] tlsh.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\External\tlsh\tlsh_impl.cpp                            /Fobuild\cfs_obj\tlsh_impl.obj
if %errorlevel% neq 0 ( echo [ERROR] tlsh_impl.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\External\tlsh\tlsh_util.cpp                            /Fobuild\cfs_obj\tlsh_util.obj
if %errorlevel% neq 0 ( echo [ERROR] tlsh_util.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\External\tlsh\shared_file_functions.cpp                /Fobuild\cfs_obj\shared_file_functions.obj
if %errorlevel% neq 0 ( echo [ERROR] shared_file_functions.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\External\tlsh\input_desc.cpp                           /Fobuild\cfs_obj\input_desc.obj
if %errorlevel% neq 0 ( echo [ERROR] input_desc.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\HashStore\HashStore.cpp                                 /Fobuild\cfs_obj\HashStore.obj
if %errorlevel% neq 0 ( echo [ERROR] HashStore.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\HashStore\HashStore_mgnmnt.cpp                          /Fobuild\cfs_obj\HashStore_mgnmnt.obj
if %errorlevel% neq 0 ( echo [ERROR] HashStore_mgnmnt.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\HashStore\HashStore_query_operations.cpp                /Fobuild\cfs_obj\HashStore_query_operations.obj
if %errorlevel% neq 0 ( echo [ERROR] HashStore_query_operations.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\HashStore\HashStore_import_export.cpp                   /Fobuild\cfs_obj\HashStore_import_export.obj
if %errorlevel% neq 0 ( echo [ERROR] HashStore_import_export.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\HashStore\BloomFilter_impl.cpp                          /Fobuild\cfs_obj\BloomFilter_impl.obj
if %errorlevel% neq 0 ( echo [ERROR] BloomFilter_impl.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\HashStore\HashBucket_impl.cpp                           /Fobuild\cfs_obj\HashBucket_impl.obj
if %errorlevel% neq 0 ( echo [ERROR] HashBucket_impl.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\PatternStore\PatternIndex.cpp                          /Fobuild\cfs_obj\PatternIndex.obj
if %errorlevel% neq 0 ( echo [ERROR] PatternIndex.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\PatternStore\PatternStore.cpp                          /Fobuild\cfs_obj\PatternStore.obj
if %errorlevel% neq 0 ( echo [ERROR] PatternStore.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\PatternStore\SIMD_matcher_impl.cpp                     /Fobuild\cfs_obj\SIMD_matcher_impl.obj
if %errorlevel% neq 0 ( echo [ERROR] SIMD_matcher_impl.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\PatternStore\aho_crsck_impl.cpp                        /Fobuild\cfs_obj\aho_crsck_impl.obj
if %errorlevel% neq 0 ( echo [ERROR] aho_crsck_impl.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\PatternStore\boyer_moore_impl.cpp                      /Fobuild\cfs_obj\boyer_moore_impl.obj
if %errorlevel% neq 0 ( echo [ERROR] boyer_moore_impl.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Whitelist\WhiteListStore.cpp                            /Fobuild\cfs_obj\WhiteListStore.obj
if %errorlevel% neq 0 ( echo [ERROR] WhiteListStore.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Whitelist\WhiteListFormat.cpp                           /Fobuild\cfs_obj\WhiteListFormat.obj
if %errorlevel% neq 0 ( echo [ERROR] WhiteListFormat.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Whitelist\WhiteListHashIndex.cpp                        /Fobuild\cfs_obj\WhiteListHashIndex.obj
if %errorlevel% neq 0 ( echo [ERROR] WhiteListHashIndex.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Whitelist\WhiteListPatternIndex.cpp                     /Fobuild\cfs_obj\WhiteListPatternIndex.obj
if %errorlevel% neq 0 ( echo [ERROR] WhiteListPatternIndex.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Whitelist\WhiteListBloomFilter.cpp                      /Fobuild\cfs_obj\WhiteListBloomFilter.obj
if %errorlevel% neq 0 ( echo [ERROR] WhiteListBloomFilter.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Whitelist\WhiteListStringPool.cpp                       /Fobuild\cfs_obj\WhiteListStringPool.obj
if %errorlevel% neq 0 ( echo [ERROR] WhiteListStringPool.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\SignatureStore\SignatureFormat.cpp                       /Fobuild\cfs_obj\SignatureFormat.obj
if %errorlevel% neq 0 ( echo [ERROR] SignatureFormat.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\SignatureStore\SignatureBuilder.cpp                      /Fobuild\cfs_obj\SignatureBuilder.obj
if %errorlevel% neq 0 ( echo [ERROR] SignatureBuilder.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\SignatureStore\batch_sig_builder.cpp                    /Fobuild\cfs_obj\batch_sig_builder.obj
if %errorlevel% neq 0 ( echo [ERROR] batch_sig_builder.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\SignatureStore\SignatureIndex.cpp                        /Fobuild\cfs_obj\SignatureIndex.obj
if %errorlevel% neq 0 ( echo [ERROR] SignatureIndex.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\SignatureStore\SignatureIndex_COW.cpp                    /Fobuild\cfs_obj\SignatureIndex_COW.obj
if %errorlevel% neq 0 ( echo [ERROR] SignatureIndex_COW.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\SignatureStore\SignatureIndex_Cache_mngmnt.cpp           /Fobuild\cfs_obj\SignatureIndex_Cache_mngmnt.obj
if %errorlevel% neq 0 ( echo [ERROR] SignatureIndex_Cache_mngmnt.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\SignatureStore\SignatureIndex_modification.cpp           /Fobuild\cfs_obj\SignatureIndex_modification.obj
if %errorlevel% neq 0 ( echo [ERROR] SignatureIndex_modification.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\SignatureStore\SignatureIndex_Query.cpp                  /Fobuild\cfs_obj\SignatureIndex_Query.obj
if %errorlevel% neq 0 ( echo [ERROR] SignatureIndex_Query.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\SignatureStore\SignatureIndex_stat_maintenance.cpp       /Fobuild\cfs_obj\SignatureIndex_stat_maintenance.obj
if %errorlevel% neq 0 ( echo [ERROR] SignatureIndex_stat_maintenance.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\SignatureStore\SignatureStore.cpp                        /Fobuild\cfs_obj\SignatureStore.obj
if %errorlevel% neq 0 ( echo [ERROR] SignatureStore.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\SignatureStore\SignatureStore_mngmnt.cpp                 /Fobuild\cfs_obj\SignatureStore_mngmnt.obj
if %errorlevel% neq 0 ( echo [ERROR] SignatureStore_mngmnt.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\SignatureStore\SignatureStore_Query.cpp                  /Fobuild\cfs_obj\SignatureStore_Query.obj
if %errorlevel% neq 0 ( echo [ERROR] SignatureStore_Query.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\SignatureStore\SignatureStore_scan.cpp                   /Fobuild\cfs_obj\SignatureStore_scan.obj
if %errorlevel% neq 0 ( echo [ERROR] SignatureStore_scan.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\SignatureStore\sig_builder_import_methods.cpp            /Fobuild\cfs_obj\sig_builder_import_methods.obj
if %errorlevel% neq 0 ( echo [ERROR] sig_builder_import_methods.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\SignatureStore\sig_builder_input_methods.cpp             /Fobuild\cfs_obj\sig_builder_input_methods.obj
if %errorlevel% neq 0 ( echo [ERROR] sig_builder_input_methods.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\SignatureStore\sig_builder_serialization.cpp             /Fobuild\cfs_obj\sig_builder_serialization.obj
if %errorlevel% neq 0 ( echo [ERROR] sig_builder_serialization.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\SignatureStore\sig_builder_utils.cpp                    /Fobuild\cfs_obj\sig_builder_utils.obj
if %errorlevel% neq 0 ( echo [ERROR] sig_builder_utils.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\SignatureStore\sig_indx_internal_node_mng.cpp           /Fobuild\cfs_obj\sig_indx_internal_node_mng.obj
if %errorlevel% neq 0 ( echo [ERROR] sig_indx_internal_node_mng.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\SignatureStore\YaraRuleStore.cpp                         /Fobuild\cfs_obj\YaraRuleStore.obj
if %errorlevel% neq 0 ( echo [ERROR] YaraRuleStore.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\ThreatIntel\ThreatIntelStore.cpp                        /Fobuild\cfs_obj\ThreatIntelStore.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelStore.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\ThreatIntel\ThreatIntelLookup.cpp                       /Fobuild\cfs_obj\ThreatIntelLookup.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelLookup.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\ThreatIntel\ThreatIntelIOCManager.cpp                   /Fobuild\cfs_obj\ThreatIntelIOCManager.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelIOCManager.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\ThreatIntel\ThreatIntelIndex_URLMatcher.cpp             /Fobuild\cfs_obj\ThreatIntelIndex_URLMatcher.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelIndex_URLMatcher.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\ThreatIntel\ThreatIntelIndex_Trees.cpp                  /Fobuild\cfs_obj\ThreatIntelIndex_Trees.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelIndex_Trees.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\ThreatIntel\ThreatIntelIndex_Modifications.cpp          /Fobuild\cfs_obj\ThreatIntelIndex_Modifications.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelIndex_Modifications.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\ThreatIntel\ThreatIntelIndex_Lookups.cpp                /Fobuild\cfs_obj\ThreatIntelIndex_Lookups.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelIndex_Lookups.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\ThreatIntel\ThreatIntelIndex_DataStructures.cpp         /Fobuild\cfs_obj\ThreatIntelIndex_DataStructures.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelIndex_DataStructures.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\ThreatIntel\ThreatIntelIndex_Core.cpp                   /Fobuild\cfs_obj\ThreatIntelIndex_Core.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelIndex_Core.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\ThreatIntel\ThreatIntelImporter.cpp                     /Fobuild\cfs_obj\ThreatIntelImporter.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelImporter.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\ThreatIntel\ThreatIntelFormat.cpp                       /Fobuild\cfs_obj\ThreatIntelFormat.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelFormat.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\ThreatIntel\ThreatIntelFeedManager_parsers.cpp          /Fobuild\cfs_obj\ThreatIntelFeedManager_parsers.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelFeedManager_parsers.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\ThreatIntel\ThreatIntelFeedManager.cpp                  /Fobuild\cfs_obj\ThreatIntelFeedManager.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelFeedManager.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\ThreatIntel\ThreatIntelExporter.cpp                     /Fobuild\cfs_obj\ThreatIntelExporter.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelExporter.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\ThreatIntel\ThreatIntelDatabase.cpp                     /Fobuild\cfs_obj\ThreatIntelDatabase.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelDatabase.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\ThreatIntel\ThreatIntelBloomFilter.cpp                  /Fobuild\cfs_obj\ThreatIntelBloomFilter.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelBloomFilter.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\ThreatIntel\ReputationCache.cpp                         /Fobuild\cfs_obj\ReputationCache.obj
if %errorlevel% neq 0 ( echo [ERROR] ReputationCache.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\PEParser\PEParser.cpp                                   /Fobuild\cfs_obj\PEParser.obj
if %errorlevel% neq 0 ( echo [ERROR] PEParser.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\PEParser\PEValidation.cpp                               /Fobuild\cfs_obj\PEValidation.obj
if %errorlevel% neq 0 ( echo [ERROR] PEValidation.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\Logger.cpp                                        /Fobuild\cfs_obj\Logger.obj
if %errorlevel% neq 0 ( echo [ERROR] Logger.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\StringUtils.cpp                                   /Fobuild\cfs_obj\StringUtils.obj
if %errorlevel% neq 0 ( echo [ERROR] StringUtils.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\HashUtils.cpp                                     /Fobuild\cfs_obj\HashUtils.obj
if %errorlevel% neq 0 ( echo [ERROR] HashUtils.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\FileUtils.cpp                                     /Fobuild\cfs_obj\FileUtils.obj
if %errorlevel% neq 0 ( echo [ERROR] FileUtils.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\JSONUtils.cpp                                     /Fobuild\cfs_obj\JSONUtils.obj
if %errorlevel% neq 0 ( echo [ERROR] JSONUtils.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\RegistryUtils.cpp                                 /Fobuild\cfs_obj\RegistryUtils.obj
if %errorlevel% neq 0 ( echo [ERROR] RegistryUtils.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\MemoryUtils.cpp                                   /Fobuild\cfs_obj\MemoryUtils.obj
if %errorlevel% neq 0 ( echo [ERROR] MemoryUtils.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\ProcessUtils.cpp                                  /Fobuild\cfs_obj\ProcessUtils.obj
if %errorlevel% neq 0 ( echo [ERROR] ProcessUtils.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\SystemUtils.cpp                                   /Fobuild\cfs_obj\SystemUtils.obj
if %errorlevel% neq 0 ( echo [ERROR] SystemUtils.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\Timer.cpp                                         /Fobuild\cfs_obj\Timer.obj
if %errorlevel% neq 0 ( echo [ERROR] Timer.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\ThreadPool.cpp                                    /Fobuild\cfs_obj\ThreadPool.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreadPool.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\CacheManager.cpp                                  /Fobuild\cfs_obj\CacheManager.obj
if %errorlevel% neq 0 ( echo [ERROR] CacheManager.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\CryptoUtils.cpp                                   /Fobuild\cfs_obj\CryptoUtils.obj
if %errorlevel% neq 0 ( echo [ERROR] CryptoUtils.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\CryptoUtilsCommon.cpp                             /Fobuild\cfs_obj\CryptoUtilsCommon.obj
if %errorlevel% neq 0 ( echo [ERROR] CryptoUtilsCommon.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\CryptoUtils_AsymmetricCipher.cpp                  /Fobuild\cfs_obj\CryptoUtils_AsymmetricCipher.obj
if %errorlevel% neq 0 ( echo [ERROR] CryptoUtils_AsymmetricCipher.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\CryptoUtils_SecureBuffer.cpp                      /Fobuild\cfs_obj\CryptoUtils_SecureBuffer.obj
if %errorlevel% neq 0 ( echo [ERROR] CryptoUtils_SecureBuffer.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\CryptoUtils_Secure_Random.cpp                     /Fobuild\cfs_obj\CryptoUtils_Secure_Random.obj
if %errorlevel% neq 0 ( echo [ERROR] CryptoUtils_Secure_Random.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\CryptoUtils_SymmetricCipher.cpp                   /Fobuild\cfs_obj\CryptoUtils_SymmetricCipher.obj
if %errorlevel% neq 0 ( echo [ERROR] CryptoUtils_SymmetricCipher.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\CryptoUtils_private_key.cpp                       /Fobuild\cfs_obj\CryptoUtils_private_key.obj
if %errorlevel% neq 0 ( echo [ERROR] CryptoUtils_private_key.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\CertUtils.cpp                                     /Fobuild\cfs_obj\CertUtils.obj
if %errorlevel% neq 0 ( echo [ERROR] CertUtils.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\Base64Utils.cpp                                   /Fobuild\cfs_obj\Base64Utils.obj
if %errorlevel% neq 0 ( echo [ERROR] Base64Utils.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\NetworkUtils.cpp                                  /Fobuild\cfs_obj\NetworkUtils.obj
if %errorlevel% neq 0 ( echo [ERROR] NetworkUtils.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\NetworkUtils_http_https.cpp                       /Fobuild\cfs_obj\NetworkUtils_http_https.obj
if %errorlevel% neq 0 ( echo [ERROR] NetworkUtils_http_https.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\NetworkUtils_DNS.cpp                              /Fobuild\cfs_obj\NetworkUtils_DNS.obj
if %errorlevel% neq 0 ( echo [ERROR] NetworkUtils_DNS.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\NetworkUtils_Adapter.cpp                          /Fobuild\cfs_obj\NetworkUtils_Adapter.obj
if %errorlevel% neq 0 ( echo [ERROR] NetworkUtils_Adapter.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\NetworkUtilsIpAddress.cpp                         /Fobuild\cfs_obj\NetworkUtilsIpAddress.obj
if %errorlevel% neq 0 ( echo [ERROR] NetworkUtilsIpAddress.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\NetworkUtilsMacAdress.cpp                         /Fobuild\cfs_obj\NetworkUtilsMacAdress.obj
if %errorlevel% neq 0 ( echo [ERROR] NetworkUtilsMacAdress.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\NetworkUtils_URL.cpp                              /Fobuild\cfs_obj\NetworkUtils_URL.obj
if %errorlevel% neq 0 ( echo [ERROR] NetworkUtils_URL.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\NetworkUtils_proxy.cpp                            /Fobuild\cfs_obj\NetworkUtils_proxy.obj
if %errorlevel% neq 0 ( echo [ERROR] NetworkUtils_proxy.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\NetworkSecurity_SSL_TLS.cpp                       /Fobuild\cfs_obj\NetworkSecurity_SSL_TLS.obj
if %errorlevel% neq 0 ( echo [ERROR] NetworkSecurity_SSL_TLS.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\PE_sig_verf.cpp                                   /Fobuild\cfs_obj\PE_sig_verf.obj
if %errorlevel% neq 0 ( echo [ERROR] PE_sig_verf.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\Utils\XMLUtils.cpp                                      /Fobuild\cfs_obj\XMLUtils.obj
if %errorlevel% neq 0 ( echo [ERROR] XMLUtils.cpp & exit /b 1 )

cl %CFLAGS% /c src\Shared_modules\External\pugixml\pugixml.cpp                            /Fobuild\cfs_obj\pugixml.obj
if %errorlevel% neq 0 ( echo [ERROR] pugixml.cpp & exit /b 1 )

:: ============================================================================
:: Step 2: Link all object files into the test executable
:: ============================================================================
link /nologo /OUT:build\core_filesystem_integration_tests.exe ^
  build\cfs_obj\test_main.obj ^
  build\cfs_obj\FileSystemChain_Integration_Tests.obj ^
  build\cfs_obj\FileHasher.obj ^
  build\cfs_obj\FileTypeAnalyzer.obj ^
  build\cfs_obj\FileReputation.obj ^
  build\cfs_obj\FuzzyHasher.obj ^
  build\cfs_obj\DigestGenerator.obj ^
  build\cfs_obj\DigestComparer.obj ^
  build\cfs_obj\tlsh.obj ^
  build\cfs_obj\tlsh_impl.obj ^
  build\cfs_obj\tlsh_util.obj ^
  build\cfs_obj\shared_file_functions.obj ^
  build\cfs_obj\input_desc.obj ^
  build\cfs_obj\HashStore.obj ^
  build\cfs_obj\HashStore_mgnmnt.obj ^
  build\cfs_obj\HashStore_query_operations.obj ^
  build\cfs_obj\HashStore_import_export.obj ^
  build\cfs_obj\BloomFilter_impl.obj ^
  build\cfs_obj\HashBucket_impl.obj ^
  build\cfs_obj\PatternIndex.obj ^
  build\cfs_obj\PatternStore.obj ^
  build\cfs_obj\SIMD_matcher_impl.obj ^
  build\cfs_obj\aho_crsck_impl.obj ^
  build\cfs_obj\boyer_moore_impl.obj ^
  build\cfs_obj\WhiteListStore.obj ^
  build\cfs_obj\WhiteListFormat.obj ^
  build\cfs_obj\WhiteListHashIndex.obj ^
  build\cfs_obj\WhiteListPatternIndex.obj ^
  build\cfs_obj\WhiteListBloomFilter.obj ^
  build\cfs_obj\WhiteListStringPool.obj ^
  build\cfs_obj\SignatureFormat.obj ^
  build\cfs_obj\SignatureBuilder.obj ^
  build\cfs_obj\batch_sig_builder.obj ^
  build\cfs_obj\SignatureIndex.obj ^
  build\cfs_obj\SignatureIndex_COW.obj ^
  build\cfs_obj\SignatureIndex_Cache_mngmnt.obj ^
  build\cfs_obj\SignatureIndex_modification.obj ^
  build\cfs_obj\SignatureIndex_Query.obj ^
  build\cfs_obj\SignatureIndex_stat_maintenance.obj ^
  build\cfs_obj\SignatureStore.obj ^
  build\cfs_obj\SignatureStore_mngmnt.obj ^
  build\cfs_obj\SignatureStore_Query.obj ^
  build\cfs_obj\SignatureStore_scan.obj ^
  build\cfs_obj\sig_builder_import_methods.obj ^
  build\cfs_obj\sig_builder_input_methods.obj ^
  build\cfs_obj\sig_builder_serialization.obj ^
  build\cfs_obj\sig_builder_utils.obj ^
  build\cfs_obj\sig_indx_internal_node_mng.obj ^
  build\cfs_obj\YaraRuleStore.obj ^
  build\cfs_obj\ThreatIntelStore.obj ^
  build\cfs_obj\ThreatIntelLookup.obj ^
  build\cfs_obj\ThreatIntelIOCManager.obj ^
  build\cfs_obj\ThreatIntelIndex_URLMatcher.obj ^
  build\cfs_obj\ThreatIntelIndex_Trees.obj ^
  build\cfs_obj\ThreatIntelIndex_Modifications.obj ^
  build\cfs_obj\ThreatIntelIndex_Lookups.obj ^
  build\cfs_obj\ThreatIntelIndex_DataStructures.obj ^
  build\cfs_obj\ThreatIntelIndex_Core.obj ^
  build\cfs_obj\ThreatIntelImporter.obj ^
  build\cfs_obj\ThreatIntelFormat.obj ^
  build\cfs_obj\ThreatIntelFeedManager_parsers.obj ^
  build\cfs_obj\ThreatIntelFeedManager.obj ^
  build\cfs_obj\ThreatIntelExporter.obj ^
  build\cfs_obj\ThreatIntelDatabase.obj ^
  build\cfs_obj\ThreatIntelBloomFilter.obj ^
  build\cfs_obj\ReputationCache.obj ^
  build\cfs_obj\PEParser.obj ^
  build\cfs_obj\PEValidation.obj ^
  build\cfs_obj\Logger.obj ^
  build\cfs_obj\StringUtils.obj ^
  build\cfs_obj\HashUtils.obj ^
  build\cfs_obj\FileUtils.obj ^
  build\cfs_obj\JSONUtils.obj ^
  build\cfs_obj\RegistryUtils.obj ^
  build\cfs_obj\MemoryUtils.obj ^
  build\cfs_obj\ProcessUtils.obj ^
  build\cfs_obj\SystemUtils.obj ^
  build\cfs_obj\Timer.obj ^
  build\cfs_obj\ThreadPool.obj ^
  build\cfs_obj\CacheManager.obj ^
  build\cfs_obj\CryptoUtils.obj ^
  build\cfs_obj\CryptoUtilsCommon.obj ^
  build\cfs_obj\CryptoUtils_AsymmetricCipher.obj ^
  build\cfs_obj\CryptoUtils_SecureBuffer.obj ^
  build\cfs_obj\CryptoUtils_Secure_Random.obj ^
  build\cfs_obj\CryptoUtils_SymmetricCipher.obj ^
  build\cfs_obj\CryptoUtils_private_key.obj ^
  build\cfs_obj\CertUtils.obj ^
  build\cfs_obj\Base64Utils.obj ^
  build\cfs_obj\NetworkUtils.obj ^
  build\cfs_obj\NetworkUtils_http_https.obj ^
  build\cfs_obj\NetworkUtils_DNS.obj ^
  build\cfs_obj\NetworkUtils_Adapter.obj ^
  build\cfs_obj\NetworkUtilsIpAddress.obj ^
  build\cfs_obj\NetworkUtilsMacAdress.obj ^
  build\cfs_obj\NetworkUtils_URL.obj ^
  build\cfs_obj\NetworkUtils_proxy.obj ^
  build\cfs_obj\NetworkSecurity_SSL_TLS.obj ^
  build\cfs_obj\PE_sig_verf.obj ^
  build\cfs_obj\XMLUtils.obj ^
  build\cfs_obj\pugixml.obj ^
  /LIBPATH:vendor\gtest_framework gtest.lib gmock.lib ^
  /LIBPATH:vendor\yara_lib libyara.lib ^
  /LIBPATH:vendor\openssl_lib libcrypto.lib libssl.lib ^
  advapi32.lib ws2_32.lib crypt32.lib shell32.lib ole32.lib shlwapi.lib user32.lib ^
  iphlpapi.lib winhttp.lib wintrust.lib wbemuuid.lib oleaut32.lib ^
  SetupAPI.lib Cfgmgr32.lib psapi.lib ntdll.lib kernel32.lib

if %errorlevel% neq 0 ( echo [ERROR] Link failed & exit /b 1 )

echo [OK] Build succeeded: build\core_filesystem_integration_tests.exe
endlocal
