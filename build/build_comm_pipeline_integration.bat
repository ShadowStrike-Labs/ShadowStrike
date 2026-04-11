@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
if not exist build\comm_pipeline_obj mkdir build\comm_pipeline_obj
cl /std:c++20 /EHsc /MDd /W4 /wd4100 /wd4189 /wd4244 /wd4267 /wd4996 /I. /Isrc /Isrc\Shared_modules /Iinclude /Iinclude\YARA /Ivendor /nologo ^
  tests\test_main.cpp ^
  tests\integration\communication_pipeline\CommunicationPipeline_Integration_Tests.cpp ^
  src\Shared_modules\Communication\AlertSystem.cpp ^
  src\Shared_modules\Communication\TelemetryCollector.cpp ^
  src\Shared_modules\Communication\MessageDispatcher.cpp ^
  src\Shared_modules\Communication\FilterConnection.cpp ^
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
  src\Shared_modules\Utils\Base64Utils.cpp ^
  src\Shared_modules\Utils\CryptoUtils.cpp ^
  src\Shared_modules\Utils\CryptoUtilsCommon.cpp ^
  src\Shared_modules\Utils\CryptoUtils_SymmetricCipher.cpp ^
  src\Shared_modules\Utils\CryptoUtils_AsymmetricCipher.cpp ^
  src\Shared_modules\Utils\CryptoUtils_SecureBuffer.cpp ^
  src\Shared_modules\Utils\CryptoUtils_Secure_Random.cpp ^
  src\Shared_modules\Utils\CryptoUtils_private_key.cpp ^
  src\Shared_modules\SelfProtection\CryptoManager.cpp ^
  /Fobuild\comm_pipeline_obj\ ^
  /Fe:build\comm_pipeline_integration_tests.exe ^
  /link /LIBPATH:vendor\gtest_framework gtest.lib gmock.lib ^
  advapi32.lib bcrypt.lib crypt32.lib fltlib.lib iphlpapi.lib ncrypt.lib ole32.lib ^
  oleaut32.lib psapi.lib shell32.lib shlwapi.lib user32.lib version.lib ^
  wbemuuid.lib wintrust.lib ws2_32.lib rpcrt4.lib
endlocal
