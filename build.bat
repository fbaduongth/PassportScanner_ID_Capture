@echo off
echo ============================================================
echo   Bien dich Passport Scanner (ID-Capture) (x86 - Syscan + Win11 OCR + AntdUI)
echo ============================================================

set CSC=C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe
set WINMD=C:\Windows\System32\WinMetadata
set NET4=C:\Windows\Microsoft.NET\Framework\v4.0.30319

taskkill /f /im PassportScannerApp.exe 2>nul

%CSC% /nologo /platform:x86 /target:winexe /win32icon:app.ico /resource:app.ico /out:PassportScannerApp.exe PassportScannerApp.cs ^
  /r:System.Windows.Forms.dll,System.Drawing.dll,System.Xml.dll,System.Data.dll,AntdUI.dll ^
  /r:"%WINMD%\Windows.Foundation.winmd","%WINMD%\Windows.Media.winmd","%WINMD%\Windows.Graphics.winmd","%WINMD%\Windows.Storage.winmd","%WINMD%\Windows.Globalization.winmd","%NET4%\System.Runtime.dll"

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [THANH CONG] Da tao thanh cong file PassportScannerApp.exe!
) else (
    echo.
    echo [THAT BAI] Co loi trong qua trinh bien dich!
)
