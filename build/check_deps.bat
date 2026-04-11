@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
dumpbin /dependents C:\ShadowStrike\ShadowStrike\build\ai_integration_tests.exe
