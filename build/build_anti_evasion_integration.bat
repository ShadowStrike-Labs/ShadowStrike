@echo off
setlocal

call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1

set CFLAGS=/std:c++20 /EHsc /MDd /W4 /wd4100 /wd4189 /wd4244 /wd4267 /wd4996 /wd4834 ^
  /DSHADOWSTRIKE_HAS_YARA ^
  /I. /Isrc /Isrc\PhantomCore /Iinclude /Iinclude\YARA /Ivendor /Ivendor\gtest_framework\include ^
  /nologo

if not exist build\ae_obj mkdir build\ae_obj

:: ============================================================================
:: Step 1: Assemble x64 ASM modules
:: ============================================================================
ml64.exe /nologo /c /Fobuild\ae_obj\VMEvasionDetector_x64.obj ^
  src\PhantomCore\AntiEvasion\VMEvasionDetector_x64.asm
if %errorlevel% neq 0 ( echo [ERROR] ASM: VMEvasionDetector_x64.asm & exit /b 1 )

ml64.exe /nologo /c /Fobuild\ae_obj\DebuggerEvasionDetector_x64.obj ^
  src\PhantomCore\AntiEvasion\DebuggerEvasionDetector_x64.asm
if %errorlevel% neq 0 ( echo [ERROR] ASM: DebuggerEvasionDetector_x64.asm & exit /b 1 )

:: ============================================================================
:: Step 2: Compile all C/C++ translation units (compile-only, /c)
:: Each file gets its own /Fo path under build\ae_obj\
:: ============================================================================

cl %CFLAGS% /c tests\test_main.cpp                                           /Fobuild\ae_obj\test_main.obj
if %errorlevel% neq 0 ( echo [ERROR] test_main.cpp & exit /b 1 )

cl %CFLAGS% /c tests\integration\anti_evasion\AntiEvasion_Integration_Tests.cpp /Fobuild\ae_obj\AntiEvasion_Integration_Tests.obj
if %errorlevel% neq 0 ( echo [ERROR] AntiEvasion_Integration_Tests.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\AntiEvasion\DebuggerEvasionDetector.cpp    /Fobuild\ae_obj\DebuggerEvasionDetector.obj
if %errorlevel% neq 0 ( echo [ERROR] DebuggerEvasionDetector.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\AntiEvasion\VMEvasionDetector.cpp          /Fobuild\ae_obj\VMEvasionDetector.obj
if %errorlevel% neq 0 ( echo [ERROR] VMEvasionDetector.cpp & exit /b 1 )

cl %CFLAGS% /c PhantomDisassembler\Decoder.cpp                               /Fobuild\ae_obj\Decoder.obj
if %errorlevel% neq 0 ( echo [ERROR] Decoder.cpp & exit /b 1 )

cl %CFLAGS% /c PhantomDisassembler\Formatter.cpp                             /Fobuild\ae_obj\Formatter.obj
if %errorlevel% neq 0 ( echo [ERROR] Formatter.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\PEParser\PEParser.cpp                      /Fobuild\ae_obj\PEParser.obj
if %errorlevel% neq 0 ( echo [ERROR] PEParser.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\PEParser\PEValidation.cpp                  /Fobuild\ae_obj\PEValidation.obj
if %errorlevel% neq 0 ( echo [ERROR] PEValidation.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\HashStore\HashStore.cpp                    /Fobuild\ae_obj\HashStore.obj
if %errorlevel% neq 0 ( echo [ERROR] HashStore.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\HashStore\BloomFilter_impl.cpp             /Fobuild\ae_obj\BloomFilter_impl.obj
if %errorlevel% neq 0 ( echo [ERROR] BloomFilter_impl.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\HashStore\HashBucket_impl.cpp              /Fobuild\ae_obj\HashBucket_impl.obj
if %errorlevel% neq 0 ( echo [ERROR] HashBucket_impl.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\HashStore\HashStore_import_export.cpp      /Fobuild\ae_obj\HashStore_import_export.obj
if %errorlevel% neq 0 ( echo [ERROR] HashStore_import_export.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\HashStore\HashStore_mgnmnt.cpp             /Fobuild\ae_obj\HashStore_mgnmnt.obj
if %errorlevel% neq 0 ( echo [ERROR] HashStore_mgnmnt.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\HashStore\HashStore_query_operations.cpp   /Fobuild\ae_obj\HashStore_query_operations.obj
if %errorlevel% neq 0 ( echo [ERROR] HashStore_query_operations.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\PatternStore\PatternIndex.cpp              /Fobuild\ae_obj\PatternIndex.obj
if %errorlevel% neq 0 ( echo [ERROR] PatternIndex.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\PatternStore\PatternStore.cpp              /Fobuild\ae_obj\PatternStore.obj
if %errorlevel% neq 0 ( echo [ERROR] PatternStore.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\PatternStore\SIMD_matcher_impl.cpp         /Fobuild\ae_obj\SIMD_matcher_impl.obj
if %errorlevel% neq 0 ( echo [ERROR] SIMD_matcher_impl.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\PatternStore\aho_crsck_impl.cpp            /Fobuild\ae_obj\aho_crsck_impl.obj
if %errorlevel% neq 0 ( echo [ERROR] aho_crsck_impl.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\PatternStore\boyer_moore_impl.cpp          /Fobuild\ae_obj\boyer_moore_impl.obj
if %errorlevel% neq 0 ( echo [ERROR] boyer_moore_impl.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\FuzzyHasher\FuzzyHasher.cpp                /Fobuild\ae_obj\FuzzyHasher.obj
if %errorlevel% neq 0 ( echo [ERROR] FuzzyHasher.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\FuzzyHasher\DigestGenerator.cpp            /Fobuild\ae_obj\DigestGenerator.obj
if %errorlevel% neq 0 ( echo [ERROR] DigestGenerator.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\FuzzyHasher\DigestComparer.cpp             /Fobuild\ae_obj\DigestComparer.obj
if %errorlevel% neq 0 ( echo [ERROR] DigestComparer.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\External\tlsh\tlsh.cpp                     /Fobuild\ae_obj\tlsh.obj
if %errorlevel% neq 0 ( echo [ERROR] tlsh.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\External\tlsh\tlsh_impl.cpp                /Fobuild\ae_obj\tlsh_impl.obj
if %errorlevel% neq 0 ( echo [ERROR] tlsh_impl.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\External\tlsh\tlsh_util.cpp                /Fobuild\ae_obj\tlsh_util.obj
if %errorlevel% neq 0 ( echo [ERROR] tlsh_util.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\External\tlsh\shared_file_functions.cpp    /Fobuild\ae_obj\shared_file_functions.obj
if %errorlevel% neq 0 ( echo [ERROR] shared_file_functions.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\External\tlsh\input_desc.cpp               /Fobuild\ae_obj\input_desc.obj
if %errorlevel% neq 0 ( echo [ERROR] input_desc.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\External\pugixml\pugixml.cpp               /Fobuild\ae_obj\pugixml.obj
if %errorlevel% neq 0 ( echo [ERROR] pugixml.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\SignatureStore\SignatureFormat.cpp          /Fobuild\ae_obj\SignatureFormat.obj
if %errorlevel% neq 0 ( echo [ERROR] SignatureFormat.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\SignatureStore\SignatureBuilder.cpp         /Fobuild\ae_obj\SignatureBuilder.obj
if %errorlevel% neq 0 ( echo [ERROR] SignatureBuilder.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\SignatureStore\batch_sig_builder.cpp        /Fobuild\ae_obj\batch_sig_builder.obj
if %errorlevel% neq 0 ( echo [ERROR] batch_sig_builder.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\SignatureStore\SignatureIndex.cpp           /Fobuild\ae_obj\SignatureIndex.obj
if %errorlevel% neq 0 ( echo [ERROR] SignatureIndex.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\SignatureStore\SignatureIndex_COW.cpp       /Fobuild\ae_obj\SignatureIndex_COW.obj
if %errorlevel% neq 0 ( echo [ERROR] SignatureIndex_COW.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\SignatureStore\SignatureIndex_Cache_mngmnt.cpp /Fobuild\ae_obj\SignatureIndex_Cache_mngmnt.obj
if %errorlevel% neq 0 ( echo [ERROR] SignatureIndex_Cache_mngmnt.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\SignatureStore\SignatureIndex_modification.cpp /Fobuild\ae_obj\SignatureIndex_modification.obj
if %errorlevel% neq 0 ( echo [ERROR] SignatureIndex_modification.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\SignatureStore\SignatureIndex_Query.cpp     /Fobuild\ae_obj\SignatureIndex_Query.obj
if %errorlevel% neq 0 ( echo [ERROR] SignatureIndex_Query.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\SignatureStore\SignatureIndex_stat_maintenance.cpp /Fobuild\ae_obj\SignatureIndex_stat_maintenance.obj
if %errorlevel% neq 0 ( echo [ERROR] SignatureIndex_stat_maintenance.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\SignatureStore\SignatureStore.cpp           /Fobuild\ae_obj\SignatureStore.obj
if %errorlevel% neq 0 ( echo [ERROR] SignatureStore.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\SignatureStore\SignatureStore_mngmnt.cpp    /Fobuild\ae_obj\SignatureStore_mngmnt.obj
if %errorlevel% neq 0 ( echo [ERROR] SignatureStore_mngmnt.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\SignatureStore\SignatureStore_Query.cpp     /Fobuild\ae_obj\SignatureStore_Query.obj
if %errorlevel% neq 0 ( echo [ERROR] SignatureStore_Query.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\SignatureStore\SignatureStore_scan.cpp      /Fobuild\ae_obj\SignatureStore_scan.obj
if %errorlevel% neq 0 ( echo [ERROR] SignatureStore_scan.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\SignatureStore\sig_builder_import_methods.cpp /Fobuild\ae_obj\sig_builder_import_methods.obj
if %errorlevel% neq 0 ( echo [ERROR] sig_builder_import_methods.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\SignatureStore\sig_builder_input_methods.cpp /Fobuild\ae_obj\sig_builder_input_methods.obj
if %errorlevel% neq 0 ( echo [ERROR] sig_builder_input_methods.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\SignatureStore\sig_builder_serialization.cpp /Fobuild\ae_obj\sig_builder_serialization.obj
if %errorlevel% neq 0 ( echo [ERROR] sig_builder_serialization.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\SignatureStore\sig_builder_utils.cpp        /Fobuild\ae_obj\sig_builder_utils.obj
if %errorlevel% neq 0 ( echo [ERROR] sig_builder_utils.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\SignatureStore\sig_indx_internal_node_mng.cpp /Fobuild\ae_obj\sig_indx_internal_node_mng.obj
if %errorlevel% neq 0 ( echo [ERROR] sig_indx_internal_node_mng.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\SignatureStore\YaraRuleStore.cpp            /Fobuild\ae_obj\YaraRuleStore.obj
if %errorlevel% neq 0 ( echo [ERROR] YaraRuleStore.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\ThreatIntel\ThreatIntelStore.cpp           /Fobuild\ae_obj\ThreatIntelStore.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelStore.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\ThreatIntel\ThreatIntelLookup.cpp          /Fobuild\ae_obj\ThreatIntelLookup.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelLookup.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\ThreatIntel\ThreatIntelIOCManager.cpp      /Fobuild\ae_obj\ThreatIntelIOCManager.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelIOCManager.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\ThreatIntel\ThreatIntelIndex_URLMatcher.cpp /Fobuild\ae_obj\ThreatIntelIndex_URLMatcher.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelIndex_URLMatcher.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\ThreatIntel\ThreatIntelIndex_Trees.cpp     /Fobuild\ae_obj\ThreatIntelIndex_Trees.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelIndex_Trees.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\ThreatIntel\ThreatIntelIndex_Modifications.cpp /Fobuild\ae_obj\ThreatIntelIndex_Modifications.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelIndex_Modifications.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\ThreatIntel\ThreatIntelIndex_Lookups.cpp   /Fobuild\ae_obj\ThreatIntelIndex_Lookups.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelIndex_Lookups.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\ThreatIntel\ThreatIntelIndex_DataStructures.cpp /Fobuild\ae_obj\ThreatIntelIndex_DataStructures.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelIndex_DataStructures.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\ThreatIntel\ThreatIntelIndex_Core.cpp      /Fobuild\ae_obj\ThreatIntelIndex_Core.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelIndex_Core.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\ThreatIntel\ThreatIntelImporter.cpp        /Fobuild\ae_obj\ThreatIntelImporter.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelImporter.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\ThreatIntel\ThreatIntelFormat.cpp          /Fobuild\ae_obj\ThreatIntelFormat.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelFormat.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\ThreatIntel\ThreatIntelFeedManager_parsers.cpp /Fobuild\ae_obj\ThreatIntelFeedManager_parsers.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelFeedManager_parsers.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\ThreatIntel\ThreatIntelFeedManager.cpp     /Fobuild\ae_obj\ThreatIntelFeedManager.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelFeedManager.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\ThreatIntel\ThreatIntelExporter.cpp        /Fobuild\ae_obj\ThreatIntelExporter.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelExporter.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\ThreatIntel\ThreatIntelDatabase.cpp        /Fobuild\ae_obj\ThreatIntelDatabase.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelDatabase.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\ThreatIntel\ThreatIntelBloomFilter.cpp     /Fobuild\ae_obj\ThreatIntelBloomFilter.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreatIntelBloomFilter.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\ThreatIntel\ReputationCache.cpp            /Fobuild\ae_obj\ReputationCache.obj
if %errorlevel% neq 0 ( echo [ERROR] ReputationCache.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\Utils\Logger.cpp                           /Fobuild\ae_obj\Logger.obj
if %errorlevel% neq 0 ( echo [ERROR] Logger.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\Utils\StringUtils.cpp                      /Fobuild\ae_obj\StringUtils.obj
if %errorlevel% neq 0 ( echo [ERROR] StringUtils.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\Utils\HashUtils.cpp                        /Fobuild\ae_obj\HashUtils.obj
if %errorlevel% neq 0 ( echo [ERROR] HashUtils.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\Utils\FileUtils.cpp                        /Fobuild\ae_obj\FileUtils.obj
if %errorlevel% neq 0 ( echo [ERROR] FileUtils.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\Utils\JSONUtils.cpp                        /Fobuild\ae_obj\JSONUtils.obj
if %errorlevel% neq 0 ( echo [ERROR] JSONUtils.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\Utils\RegistryUtils.cpp                    /Fobuild\ae_obj\RegistryUtils.obj
if %errorlevel% neq 0 ( echo [ERROR] RegistryUtils.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\Utils\MemoryUtils.cpp                      /Fobuild\ae_obj\MemoryUtils.obj
if %errorlevel% neq 0 ( echo [ERROR] MemoryUtils.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\Utils\ProcessUtils.cpp                     /Fobuild\ae_obj\ProcessUtils.obj
if %errorlevel% neq 0 ( echo [ERROR] ProcessUtils.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\Utils\SystemUtils.cpp                      /Fobuild\ae_obj\SystemUtils.obj
if %errorlevel% neq 0 ( echo [ERROR] SystemUtils.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\Utils\Timer.cpp                            /Fobuild\ae_obj\Timer.obj
if %errorlevel% neq 0 ( echo [ERROR] Timer.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\Utils\ThreadPool.cpp                       /Fobuild\ae_obj\ThreadPool.obj
if %errorlevel% neq 0 ( echo [ERROR] ThreadPool.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\Utils\Base64Utils.cpp                      /Fobuild\ae_obj\Base64Utils.obj
if %errorlevel% neq 0 ( echo [ERROR] Base64Utils.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\Utils\NetworkUtils.cpp                     /Fobuild\ae_obj\NetworkUtils.obj
if %errorlevel% neq 0 ( echo [ERROR] NetworkUtils.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\Utils\NetworkUtils_http_https.cpp          /Fobuild\ae_obj\NetworkUtils_http_https.obj
if %errorlevel% neq 0 ( echo [ERROR] NetworkUtils_http_https.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\Utils\NetworkUtils_DNS.cpp                 /Fobuild\ae_obj\NetworkUtils_DNS.obj
if %errorlevel% neq 0 ( echo [ERROR] NetworkUtils_DNS.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\Utils\NetworkUtils_Adapter.cpp             /Fobuild\ae_obj\NetworkUtils_Adapter.obj
if %errorlevel% neq 0 ( echo [ERROR] NetworkUtils_Adapter.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\Utils\NetworkUtilsIpAddress.cpp            /Fobuild\ae_obj\NetworkUtilsIpAddress.obj
if %errorlevel% neq 0 ( echo [ERROR] NetworkUtilsIpAddress.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\Utils\NetworkUtilsMacAdress.cpp            /Fobuild\ae_obj\NetworkUtilsMacAdress.obj
if %errorlevel% neq 0 ( echo [ERROR] NetworkUtilsMacAdress.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\Utils\NetworkUtils_URL.cpp                 /Fobuild\ae_obj\NetworkUtils_URL.obj
if %errorlevel% neq 0 ( echo [ERROR] NetworkUtils_URL.cpp & exit /b 1 )

cl %CFLAGS% /c src\PhantomCore\Utils\NetworkUtils_proxy.cpp               /Fobuild\ae_obj\NetworkUtils_proxy.obj
if %errorlevel% neq 0 ( echo [ERROR] NetworkUtils_proxy.cpp & exit /b 1 )

:: ============================================================================
:: Step 3: Link all object files into the test executable
:: ============================================================================
link /nologo /OUT:build\anti_evasion_integration_tests.exe ^
  build\ae_obj\test_main.obj ^
  build\ae_obj\AntiEvasion_Integration_Tests.obj ^
  build\ae_obj\DebuggerEvasionDetector.obj ^
  build\ae_obj\VMEvasionDetector.obj ^
  build\ae_obj\VMEvasionDetector_x64.obj ^
  build\ae_obj\DebuggerEvasionDetector_x64.obj ^
  build\ae_obj\Decoder.obj ^
  build\ae_obj\Formatter.obj ^
  build\ae_obj\PEParser.obj ^
  build\ae_obj\PEValidation.obj ^
  build\ae_obj\HashStore.obj ^
  build\ae_obj\BloomFilter_impl.obj ^
  build\ae_obj\HashBucket_impl.obj ^
  build\ae_obj\HashStore_import_export.obj ^
  build\ae_obj\HashStore_mgnmnt.obj ^
  build\ae_obj\HashStore_query_operations.obj ^
  build\ae_obj\PatternIndex.obj ^
  build\ae_obj\PatternStore.obj ^
  build\ae_obj\SIMD_matcher_impl.obj ^
  build\ae_obj\aho_crsck_impl.obj ^
  build\ae_obj\boyer_moore_impl.obj ^
  build\ae_obj\FuzzyHasher.obj ^
  build\ae_obj\DigestGenerator.obj ^
  build\ae_obj\DigestComparer.obj ^
  build\ae_obj\tlsh.obj ^
  build\ae_obj\tlsh_impl.obj ^
  build\ae_obj\tlsh_util.obj ^
  build\ae_obj\shared_file_functions.obj ^
  build\ae_obj\input_desc.obj ^
  build\ae_obj\pugixml.obj ^
  build\ae_obj\SignatureFormat.obj ^
  build\ae_obj\SignatureBuilder.obj ^
  build\ae_obj\batch_sig_builder.obj ^
  build\ae_obj\SignatureIndex.obj ^
  build\ae_obj\SignatureIndex_COW.obj ^
  build\ae_obj\SignatureIndex_Cache_mngmnt.obj ^
  build\ae_obj\SignatureIndex_modification.obj ^
  build\ae_obj\SignatureIndex_Query.obj ^
  build\ae_obj\SignatureIndex_stat_maintenance.obj ^
  build\ae_obj\SignatureStore.obj ^
  build\ae_obj\SignatureStore_mngmnt.obj ^
  build\ae_obj\SignatureStore_Query.obj ^
  build\ae_obj\SignatureStore_scan.obj ^
  build\ae_obj\sig_builder_import_methods.obj ^
  build\ae_obj\sig_builder_input_methods.obj ^
  build\ae_obj\sig_builder_serialization.obj ^
  build\ae_obj\sig_builder_utils.obj ^
  build\ae_obj\sig_indx_internal_node_mng.obj ^
  build\ae_obj\YaraRuleStore.obj ^
  build\ae_obj\ThreatIntelStore.obj ^
  build\ae_obj\ThreatIntelLookup.obj ^
  build\ae_obj\ThreatIntelIOCManager.obj ^
  build\ae_obj\ThreatIntelIndex_URLMatcher.obj ^
  build\ae_obj\ThreatIntelIndex_Trees.obj ^
  build\ae_obj\ThreatIntelIndex_Modifications.obj ^
  build\ae_obj\ThreatIntelIndex_Lookups.obj ^
  build\ae_obj\ThreatIntelIndex_DataStructures.obj ^
  build\ae_obj\ThreatIntelIndex_Core.obj ^
  build\ae_obj\ThreatIntelImporter.obj ^
  build\ae_obj\ThreatIntelFormat.obj ^
  build\ae_obj\ThreatIntelFeedManager_parsers.obj ^
  build\ae_obj\ThreatIntelFeedManager.obj ^
  build\ae_obj\ThreatIntelExporter.obj ^
  build\ae_obj\ThreatIntelDatabase.obj ^
  build\ae_obj\ThreatIntelBloomFilter.obj ^
  build\ae_obj\ReputationCache.obj ^
  build\ae_obj\Logger.obj ^
  build\ae_obj\StringUtils.obj ^
  build\ae_obj\HashUtils.obj ^
  build\ae_obj\FileUtils.obj ^
  build\ae_obj\JSONUtils.obj ^
  build\ae_obj\RegistryUtils.obj ^
  build\ae_obj\MemoryUtils.obj ^
  build\ae_obj\ProcessUtils.obj ^
  build\ae_obj\SystemUtils.obj ^
  build\ae_obj\Timer.obj ^
  build\ae_obj\ThreadPool.obj ^
  build\ae_obj\Base64Utils.obj ^
  build\ae_obj\NetworkUtils.obj ^
  build\ae_obj\NetworkUtils_http_https.obj ^
  build\ae_obj\NetworkUtils_DNS.obj ^
  build\ae_obj\NetworkUtils_Adapter.obj ^
  build\ae_obj\NetworkUtilsIpAddress.obj ^
  build\ae_obj\NetworkUtilsMacAdress.obj ^
  build\ae_obj\NetworkUtils_URL.obj ^
  build\ae_obj\NetworkUtils_proxy.obj ^
  /LIBPATH:vendor\gtest_framework gtest.lib gmock.lib ^
  /LIBPATH:vendor\yara_lib libyara.lib ^
  /LIBPATH:vendor\openssl_lib libcrypto.lib libssl.lib ^
  advapi32.lib ws2_32.lib crypt32.lib shell32.lib ole32.lib shlwapi.lib user32.lib ^
  iphlpapi.lib winhttp.lib wintrust.lib wbemuuid.lib oleaut32.lib ^
  SetupAPI.lib Cfgmgr32.lib psapi.lib ntdll.lib kernel32.lib

if %errorlevel% neq 0 ( echo [ERROR] Link failed & exit /b 1 )

echo [OK] Build succeeded: build\anti_evasion_integration_tests.exe
endlocal
