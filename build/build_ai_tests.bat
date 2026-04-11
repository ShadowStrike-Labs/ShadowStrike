@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
if not exist build\ai_unit_obj mkdir build\ai_unit_obj
cl /std:c++20 /EHsc /MDd /W4 /wd4100 /wd4189 /wd4244 /wd4267 /wd4996 /I. /Isrc /Isrc\PhantomCore /Iinclude /Ivendor /nologo ^
  tests\test_main.cpp ^
  tests\unit\ai_unit\CortexConfig_Tests.cpp ^
  tests\unit\ai_unit\FeatureExtractor_Tests.cpp ^
  tests\unit\ai_unit\ModelCache_Tests.cpp ^
  tests\unit\ai_unit\ModelInference_Tests.cpp ^
  tests\unit\ai_unit\PhantomCortex_Tests.cpp ^
  src\PhantomCore\AI\CortexConfig.cpp ^
  src\PhantomCore\AI\FeatureExtractor.cpp ^
  src\PhantomCore\AI\ModelCache.cpp ^
  src\PhantomCore\AI\ModelInference.cpp ^
  src\PhantomCore\AI\PhantomCortex.cpp ^
  src\PhantomCore\Utils\StringUtils.cpp ^
  src\PhantomCore\Utils\FileUtils.cpp ^
  src\PhantomCore\Utils\HashUtils.cpp ^
  src\PhantomCore\Utils\JSONUtils.cpp ^
  src\PhantomCore\Utils\NetworkUtils.cpp ^
  src\PhantomCore\Utils\NetworkUtils_http_https.cpp ^
  src\PhantomCore\Utils\NetworkUtils_DNS.cpp ^
  src\PhantomCore\Utils\NetworkUtils_Adapter.cpp ^
  src\PhantomCore\Utils\NetworkUtilsIpAddress.cpp ^
  src\PhantomCore\Utils\NetworkUtilsMacAdress.cpp ^
  src\PhantomCore\Utils\NetworkUtils_URL.cpp ^
  src\PhantomCore\Utils\NetworkUtils_proxy.cpp ^
  src\PhantomCore\Utils\Logger.cpp ^
  src\PhantomCore\Utils\RegistryUtils.cpp ^
  /Fobuild\ai_unit_obj\ ^
  /Fe:build\ai_unit_tests.exe ^
  /link /LIBPATH:vendor\gtest_framework gtest.lib gmock.lib ^
  advapi32.lib ws2_32.lib crypt32.lib shell32.lib ole32.lib shlwapi.lib user32.lib ^
  iphlpapi.lib winhttp.lib wintrust.lib wbemuuid.lib oleaut32.lib
endlocal
