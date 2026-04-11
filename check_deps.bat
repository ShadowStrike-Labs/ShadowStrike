@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
dumpbin /dependents "C:\ShadowStrike\ShadowStrike\bin\exploit_harness\exploit_clean.exe"
