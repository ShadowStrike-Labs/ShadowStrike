@echo off
setlocal

call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=amd64
if errorlevel 1 exit /b 1

set "OBJ_DIR=build\self_protection_int_obj"
if exist "%OBJ_DIR%" rmdir /s /q "%OBJ_DIR%"
mkdir "%OBJ_DIR%"
if errorlevel 1 exit /b 1

set "CL_FLAGS=/nologo /std:c++20 /EHsc /MDd /Gy /DWIN32 /D_WINDOWS /DUNICODE /D_UNICODE /DGTEST_LINKED_AS_SHARED_LIBRARY=1 /I. /Isrc /Isrc\PhantomCore /Iinclude /Iinclude\YARA /Ivendor"

cl %CL_FLAGS% /c /Fo"%OBJ_DIR%\Logger.obj" "src\PhantomCore\Utils\Logger.cpp" || exit /b 1
cl %CL_FLAGS% /c /Fo"%OBJ_DIR%\StringUtils.obj" "src\PhantomCore\Utils\StringUtils.cpp" || exit /b 1
cl %CL_FLAGS% /c /Fo"%OBJ_DIR%\FileUtils.obj" "src\PhantomCore\Utils\FileUtils.cpp" || exit /b 1
cl %CL_FLAGS% /c /Fo"%OBJ_DIR%\CryptoManager.obj" "src\PhantomCore\SelfProtection\CryptoManager.cpp" || exit /b 1
cl %CL_FLAGS% /c /Fo"%OBJ_DIR%\CertificateValidator.obj" "src\PhantomCore\SelfProtection\CertificateValidator.cpp" || exit /b 1
cl %CL_FLAGS% /c /Fo"%OBJ_DIR%\TamperProtection.obj" "src\PhantomCore\SelfProtection\TamperProtection.cpp" || exit /b 1
cl %CL_FLAGS% /c /Fo"%OBJ_DIR%\SelfDefense.obj" "src\PhantomCore\SelfProtection\SelfDefense.cpp" || exit /b 1
cl %CL_FLAGS% /c /Fo"%OBJ_DIR%\SelfProtection_DependencyStubs.obj" "tests\integration\self_protection\SelfProtection_DependencyStubs.cpp" || exit /b 1
cl %CL_FLAGS% /c /Fo"%OBJ_DIR%\test_main.obj" "tests\test_main.cpp" || exit /b 1
cl %CL_FLAGS% /c /Fo"%OBJ_DIR%\SelfProtectionStack_Integration_Tests.obj" "tests\integration\self_protection\SelfProtectionStack_Integration_Tests.cpp" || exit /b 1

link /nologo /OPT:REF /OPT:ICF ^
  /OUT:"build\self_protection_integration_tests.exe" ^
  "%OBJ_DIR%\Logger.obj" ^
  "%OBJ_DIR%\StringUtils.obj" ^
  "%OBJ_DIR%\FileUtils.obj" ^
  "%OBJ_DIR%\CryptoManager.obj" ^
  "%OBJ_DIR%\CertificateValidator.obj" ^
  "%OBJ_DIR%\TamperProtection.obj" ^
  "%OBJ_DIR%\SelfDefense.obj" ^
  "%OBJ_DIR%\SelfProtection_DependencyStubs.obj" ^
  "%OBJ_DIR%\test_main.obj" ^
  "%OBJ_DIR%\SelfProtectionStack_Integration_Tests.obj" ^
  /LIBPATH:vendor\gtest_framework gtest.lib gmock.lib ^
  advapi32.lib bcrypt.lib crypt32.lib fltlib.lib imagehlp.lib iphlpapi.lib ^
  ncrypt.lib ole32.lib oleaut32.lib psapi.lib rpcrt4.lib shell32.lib ^
  shlwapi.lib user32.lib version.lib wbemuuid.lib wintrust.lib ws2_32.lib ^
  || exit /b 1

echo [OK] Build succeeded: build\self_protection_integration_tests.exe
exit /b 0
