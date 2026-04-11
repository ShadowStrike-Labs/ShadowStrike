@echo off
call VsDevCmd.bat -arch=amd64 2>NUL
if not exist build\scan_test_obj mkdir build\scan_test_obj
cl /nologo /std:c++20 /EHsc /c /I. /Isrc /Iinclude /Iinclude\YARA tests\integration\scan_pipeline\ScanPipeline_Integration_Tests.cpp /Fobuild\scan_test_obj\ScanPipeline_Integration_Tests.obj 2>&1
