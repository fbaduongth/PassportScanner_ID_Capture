$res = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
    CommandLine = '"c:\Users\ITPC\Documents\ID_Capture\PassportScannerApp.exe"'
    CurrentDirectory = 'c:\Users\ITPC\Documents\ID_Capture'
}
Write-Host "Process launched: PID=$($res.ProcessId), ReturnValue=$($res.ReturnValue)"
