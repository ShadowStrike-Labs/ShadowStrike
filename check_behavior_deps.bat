@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
dumpbin /dependents "C:\Users\RTX40\AppData\Local\Temp\shadowstrike-realtime-behavior\behavior_clean.exe"
