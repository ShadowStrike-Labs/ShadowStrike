@echo off
call VsDevCmd.bat -arch=amd64 2>NUL
cl /nologo /std:c++20 /EHsc /c /I. /Isrc /Iinclude /Iinclude\YARA tests\integration\scan_pipeline\ScanPipeline_Integration_Tests.cpp /FoScanPipeline_Integration_Tests.obj 2>&1
