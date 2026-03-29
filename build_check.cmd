@call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
cl.exe /Zs /std:c++20 /EHsc /W4 /I "src" /I "include" /I "vendor" /DNOMINMAX /DWIN32_LEAN_AND_MEAN /D_WIN32_WINNT=0x0A00 "src\Shared_modules\Security\RegistryProtection.cpp" 2>&1
