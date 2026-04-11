@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
if not exist build\ai_integration_obj mkdir build\ai_integration_obj
cl /std:c++20 /EHsc /MDd /W4 /wd4100 /wd4189 /wd4244 /wd4267 /wd4996 /I. /Isrc /Isrc\Shared_modules /Iinclude /Ivendor /nologo ^
  tests\test_main.cpp ^
  tests\integration\ai_pipeline\AIPipeline_Integration_Tests.cpp ^
  src\Shared_modules\AI\CortexConfig.cpp ^
  src\Shared_modules\AI\FeatureExtractor.cpp ^
  src\Shared_modules\AI\ModelCache.cpp ^
  src\Shared_modules\AI\ModelInference.cpp ^
  src\Shared_modules\AI\PhantomCortex.cpp ^
  src\Shared_modules\PEParser\PEParser.cpp ^
  src\Shared_modules\PEParser\PEValidation.cpp ^
  src\Shared_modules\Utils\StringUtils.cpp ^
  src\Shared_modules\Utils\FileUtils.cpp ^
  src\Shared_modules\Utils\HashUtils.cpp ^
  src\Shared_modules\Utils\JSONUtils.cpp ^
  src\Shared_modules\Utils\NetworkUtils.cpp ^
  src\Shared_modules\Utils\NetworkUtils_http_https.cpp ^
  src\Shared_modules\Utils\NetworkUtils_DNS.cpp ^
  src\Shared_modules\Utils\NetworkUtils_Adapter.cpp ^
  src\Shared_modules\Utils\NetworkUtilsIpAddress.cpp ^
  src\Shared_modules\Utils\NetworkUtilsMacAdress.cpp ^
  src\Shared_modules\Utils\NetworkUtils_URL.cpp ^
  src\Shared_modules\Utils\NetworkUtils_proxy.cpp ^
  src\Shared_modules\Utils\Logger.cpp ^
  src\Shared_modules\Utils\RegistryUtils.cpp ^
  src\Shared_modules\Utils\MemoryUtils.cpp ^
  src\Shared_modules\Utils\SystemUtils.cpp ^
  /Fobuild\ai_integration_obj\ ^
  /Fe:build\ai_integration_tests.exe ^
  /link /LIBPATH:vendor\gtest_framework gtest.lib gmock.lib ^
  advapi32.lib ws2_32.lib crypt32.lib shell32.lib ole32.lib shlwapi.lib user32.lib ^
  iphlpapi.lib winhttp.lib wintrust.lib wbemuuid.lib oleaut32.lib
endlocal
