@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
if not exist build\comm_pipeline_obj mkdir build\comm_pipeline_obj
cl /std:c++20 /EHsc /MDd /W4 /wd4100 /wd4189 /wd4244 /wd4267 /wd4996 /I. /Isrc /Isrc\PhantomCore /Iinclude /Iinclude\YARA /Ivendor /nologo ^
  tests\test_main.cpp ^
  tests\integration\communication_pipeline\CommunicationPipeline_Integration_Tests.cpp ^
  src\PhantomCore\Communication\AlertSystem.cpp ^
  src\PhantomCore\Communication\TelemetryCollector.cpp ^
  src\PhantomCore\Communication\MessageDispatcher.cpp ^
  src\PhantomCore\Communication\FilterConnection.cpp ^
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
  src\PhantomCore\Utils\MemoryUtils.cpp ^
  src\PhantomCore\Utils\SystemUtils.cpp ^
  src\PhantomCore\Utils\Base64Utils.cpp ^
  src\PhantomCore\Utils\CryptoUtils.cpp ^
  src\PhantomCore\Utils\CryptoUtilsCommon.cpp ^
  src\PhantomCore\Utils\CryptoUtils_SymmetricCipher.cpp ^
  src\PhantomCore\Utils\CryptoUtils_AsymmetricCipher.cpp ^
  src\PhantomCore\Utils\CryptoUtils_SecureBuffer.cpp ^
  src\PhantomCore\Utils\CryptoUtils_Secure_Random.cpp ^
  src\PhantomCore\Utils\CryptoUtils_private_key.cpp ^
  src\PhantomCore\SelfProtection\CryptoManager.cpp ^
  /Fobuild\comm_pipeline_obj\ ^
  /Fe:build\comm_pipeline_integration_tests.exe ^
  /link /LIBPATH:vendor\gtest_framework gtest.lib gmock.lib ^
  advapi32.lib bcrypt.lib crypt32.lib fltlib.lib iphlpapi.lib ncrypt.lib ole32.lib ^
  oleaut32.lib psapi.lib shell32.lib shlwapi.lib user32.lib version.lib ^
  wbemuuid.lib wintrust.lib ws2_32.lib rpcrt4.lib
endlocal
