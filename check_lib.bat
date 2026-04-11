@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
dumpbin /archivemembers "C:\ShadowStrike\ShadowStrike\vendor\gtest_framework\gtest.lib" 2>&1 | head -5
