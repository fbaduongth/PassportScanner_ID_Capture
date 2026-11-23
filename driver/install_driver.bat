@echo off
title Cai dat Driver Syscan IDC-V USB Driver
echo ============================================================
echo   Cai dat Driver may quet Syscan IDC-V (ID-Capture)
echo ============================================================
cd /d "%~dp0"

:: Kiem tra quyen Administrator va tu dong yeu cau Run as Administrator neu chua co
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Dang yeu cau quyen Administrator de cai dat driver...
    powershell -Command "Start-Process cmd.exe -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

echo [1/3] Dang them chung chi xac thuc vao he thong Windows...
certutil.exe -addstore -f "TrustedPublisher" SyscanIDC_V.cer >nul 2>&1
certutil.exe -addstore -f "Root" SyscanIDC_V.cer >nul 2>&1

echo [2/3] Dang nap Driver syscanidc_v.inf vao Windows Driver Store...
pnputil.exe /add-driver syscanidc_v.inf /install

echo [3/3] Dang quet lai cac thiet bi USB ket noi...
pnputil.exe /scan-devices >nul 2>&1

echo.
echo ============================================================
echo   HOAN TAT XU LY CAI DAT DRIVER!
echo   - Neu may quet dang cam USB, ban hay rut ra va cam lai.
echo   - Luu y Windows 11: Neu van bao loi Driver cham than vang,
echo     vui long vao Windows Security ^> Device Security ^>
echo     Core Isolation ^> Tat "Memory Integrity", sau do khoi dong lai.
echo ============================================================
pause
