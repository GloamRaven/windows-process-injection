@echo off
ml64 /nologo /c /Fo shell.obj sc.asm || exit /b 1
cl /nologo extractor.c shell.obj || exit /b 1
extractor.exe > shellcode.h || exit /b 1
cl /nologo injector.c || exit /b 1
echo Build complete.