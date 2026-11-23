@echo off
echo ============================================================
echo   Bien dich Bo Cai Dat Setup_PassportScanner_ID_Capture.exe
echo ============================================================

set CSC=C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe

%CSC% /nologo /platform:x86 /target:winexe /win32icon:app.ico /win32manifest:installer.manifest /resource:app_payload.zip /resource:app.ico /out:Setup_PassportScanner_ID_Capture.exe SetupProgram.cs /r:System.Windows.Forms.dll,System.Drawing.dll,System.IO.Compression.dll,System.IO.Compression.FileSystem.dll,Microsoft.CSharp.dll

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [THANH CONG] Da tao thanh cong file Setup_PassportScanner_ID_Capture.exe!
) else (
    echo.
    echo [THAT BAI] Co loi trong qua trinh bien dich bo cai dat!
)
