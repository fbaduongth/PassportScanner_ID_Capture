$ErrorActionPreference = "Stop"

Write-Host "=== 0. Chuyen doi icon.png sang app.ico chuan Windows da kich thuoc ===" -ForegroundColor Cyan
$convCode = @'
using System;
using System.IO;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Collections.Generic;

public class PngToIcoConverter
{
    public static void Convert(string pngPath, string icoPath)
    {
        using (Bitmap sourceBmp = new Bitmap(pngPath))
        {
            int[] sizes = new int[] { 256, 128, 64, 48, 32, 16 };
            List<byte[]> imageBytesList = new List<byte[]>();
            List<int> sizeList = new List<int>();

            foreach (int size in sizes)
            {
                using (Bitmap resized = new Bitmap(size, size, PixelFormat.Format32bppArgb))
                {
                    using (Graphics g = Graphics.FromImage(resized))
                    {
                        g.InterpolationMode = InterpolationMode.HighQualityBicubic;
                        g.SmoothingMode = SmoothingMode.HighQuality;
                        g.PixelOffsetMode = PixelOffsetMode.HighQuality;
                        g.CompositingQuality = CompositingQuality.HighQuality;
                        g.Clear(Color.Transparent);
                        g.DrawImage(sourceBmp, 0, 0, size, size);
                    }

                    if (size == 256)
                    {
                        using (MemoryStream ms = new MemoryStream())
                        {
                            resized.Save(ms, ImageFormat.Png);
                            imageBytesList.Add(ms.ToArray());
                            sizeList.Add(size);
                        }
                    }
                    else
                    {
                        byte[] dib = CreateDibBytes(resized);
                        imageBytesList.Add(dib);
                        sizeList.Add(size);
                    }
                }
            }

            using (FileStream fs = new FileStream(icoPath, FileMode.Create, FileAccess.Write))
            using (BinaryWriter bw = new BinaryWriter(fs))
            {
                bw.Write((ushort)0);
                bw.Write((ushort)1);
                bw.Write((ushort)imageBytesList.Count);

                int offset = 6 + (16 * imageBytesList.Count);

                for (int i = 0; i < imageBytesList.Count; i++)
                {
                    int sz = sizeList[i];
                    byte bW = (byte)(sz >= 256 ? 0 : sz);
                    byte bH = (byte)(sz >= 256 ? 0 : sz);
                    bw.Write(bW);
                    bw.Write(bH);
                    bw.Write((byte)0);
                    bw.Write((byte)0);
                    bw.Write((ushort)1);
                    bw.Write((ushort)32);
                    bw.Write((uint)imageBytesList[i].Length);
                    bw.Write((uint)offset);

                    offset += imageBytesList[i].Length;
                }

                for (int i = 0; i < imageBytesList.Count; i++)
                {
                    bw.Write(imageBytesList[i]);
                }
            }
        }
    }

    private static byte[] CreateDibBytes(Bitmap bmp)
    {
        int width = bmp.Width;
        int height = bmp.Height;
        int xorStride = width * 4;
        int andStride = ((width + 31) / 32) * 4;
        int xorSize = xorStride * height;
        int andSize = andStride * height;
        int headerSize = 40;
        int totalSize = headerSize + xorSize + andSize;

        byte[] dib = new byte[totalSize];

        using (MemoryStream ms = new MemoryStream(dib))
        using (BinaryWriter bw = new BinaryWriter(ms))
        {
            bw.Write((uint)40);
            bw.Write((int)width);
            bw.Write((int)(height * 2));
            bw.Write((ushort)1);
            bw.Write((ushort)32);
            bw.Write((uint)0);
            bw.Write((uint)(xorSize + andSize));
            bw.Write((int)0);
            bw.Write((int)0);
            bw.Write((uint)0);
            bw.Write((uint)0);

            BitmapData data = bmp.LockBits(new Rectangle(0, 0, width, height), ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
            try
            {
                byte[] row = new byte[xorStride];
                for (int y = height - 1; y >= 0; y--)
                {
                    IntPtr srcPtr = new IntPtr(data.Scan0.ToInt64() + (y * data.Stride));
                    System.Runtime.InteropServices.Marshal.Copy(srcPtr, row, 0, xorStride);
                    bw.Write(row);
                }
            }
            finally
            {
                bmp.UnlockBits(data);
            }

            byte[] andMask = new byte[andSize];
            bw.Write(andMask);
        }

        return dib;
    }
}
'@

if (-not ([System.Management.Automation.PSTypeName]'PngToIcoConverter').Type) {
    Add-Type -TypeDefinition $convCode -ReferencedAssemblies "System.Drawing.dll" -Language CSharp
}
[PngToIcoConverter]::Convert((Resolve-Path "icon.png").Path, (Join-Path (Get-Location) "app.ico"))
Write-Host "Da tao thanh cong file app.ico tu icon.png!" -ForegroundColor Green

Write-Host "=== 1. Bien dich PassportScannerApp.exe ===" -ForegroundColor Cyan
& cmd /c build.bat
if ($LASTEXITCODE -ne 0) {
    throw "Loi khi bien dich PassportScannerApp.exe"
}

Write-Host "=== 2. Chuan bi thu muc publish_payload ===" -ForegroundColor Cyan
if (Test-Path "publish_payload") {
    Remove-Item "publish_payload" -Recurse -Force
}
if (Test-Path "app_payload.zip") {
    Remove-Item "app_payload.zip" -Force
}

New-Item -ItemType Directory -Path "publish_payload" | Out-Null
New-Item -ItemType Directory -Path "publish_payload\docs" | Out-Null
New-Item -ItemType Directory -Path "publish_payload\images" | Out-Null

$filesToCopy = @(
    "PassportScannerApp.exe",
    "AntdUI.dll",
    "ScanDll.dll",
    "FreeImage.dll",
    "uw_dib.dll",
    "uw_idc.dll",
    "uw_misc.dll",
    "IDC_Image_Process.dll",
    "IDC_Image_Process.dll.bak",
    "IDC_Image_Process.ini",
    "IDC_Focus_Tune.ini",
    "WltRS.dll",
    "XNCLib.dll",
    "IDCVActivex.dll",
    "asdqwetq231623634@#%1.dat",
    "barcode_data.dat",
    "brain.dat",
    "brightness_data.dat",
    "calibrate_data.dat",
    "catftr.dat",
    "catleg.dat",
    "dragon.dat",
    "Dst1.dat",
    "Dst2.dat",
    "hitking.dat",
    "idcdic.dat",
    "legindex.dat",
    "BeVietnamPro-Bold.ttf",
    "BeVietnamPro-Medium.ttf",
    "BeVietnamPro-Regular.ttf",
    "BeVietnamPro-SemiBold.ttf",
    "ui_text.ini",
    "app.ico",
    "icon.png"
)

foreach ($f in $filesToCopy) {
    if (Test-Path $f) {
        Copy-Item $f "publish_payload\" -Force
    } else {
        Write-Warning "Khong tim thay file: $f"
    }
}

if (Test-Path "driver") {
    Copy-Item "driver" "publish_payload\driver" -Recurse -Force
}

Write-Host "=== 3. Nen tap tin app_payload.zip ===" -ForegroundColor Cyan
& tar.exe -a -cf app_payload.zip -C publish_payload .
if ($LASTEXITCODE -ne 0) {
    throw "Loi khi tao file app_payload.zip bang tar.exe"
}

Write-Host "=== 4. Bien dich bo cai dat Setup_PassportScanner_ID_Capture.exe ===" -ForegroundColor Cyan
$csc = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
$argsList = @(
    "/nologo",
    "/platform:anycpu",
    "/target:winexe",
    "/win32icon:app.ico",
    "/win32manifest:installer.manifest",
    "/resource:app_payload.zip",
    "/resource:app.ico",
    "/resource:icon.png",
    "/out:Setup_PassportScanner_ID_Capture.exe",
    "SetupProgram.cs",
    "/r:System.Windows.Forms.dll,System.Drawing.dll,System.IO.Compression.dll,System.IO.Compression.FileSystem.dll"
)

& $csc $argsList
if ($LASTEXITCODE -ne 0) {
    throw "Loi khi bien dich Setup_PassportScanner_ID_Capture.exe"
}

Write-Host "=== 5. Sao chep bo cai dat ra Desktop ===" -ForegroundColor Cyan
Copy-Item "Setup_PassportScanner_ID_Capture.exe" "C:\Users\ITPC\Desktop\Setup_PassportScanner_ID_Capture.exe" -Force

Write-Host "=== 6. Cap nhat ban cai dat hien tai trong Program Files va ProgramData ===" -ForegroundColor Cyan
$progFilesDir = "C:\Program Files (x86)\Viettechsoft\ID_Capture"
if (Test-Path $progFilesDir) {
    try {
        Copy-Item "app.ico" "$progFilesDir\app.ico" -Force
        Copy-Item "icon.png" "$progFilesDir\icon.png" -Force
        Copy-Item "PassportScannerApp.exe" "$progFilesDir\PassportScannerApp.exe" -Force
        Copy-Item "ui_text.ini" "$progFilesDir\ui_text.ini" -Force
        Write-Host "Da cap nhat app.ico, PassportScannerApp.exe vao thu muc $progFilesDir" -ForegroundColor Green
    } catch {
        Write-Warning ("Khong the ghi truc tiep vao " + $progFilesDir + ": " + $_)
    }
}

$progDataDir = "$env:ProgramData\ID_Capture"
if (-not (Test-Path $progDataDir)) {
    New-Item -ItemType Directory -Path $progDataDir -Force | Out-Null
}
Get-ChildItem "publish_payload\*.dat" | ForEach-Object {
    Copy-Item $_.FullName "$progDataDir\" -Force
}
if (Test-Path "publish_payload\IDC_Image_Process.ini") { Copy-Item "publish_payload\IDC_Image_Process.ini" "$progDataDir\" -Force }
if (Test-Path "publish_payload\IDC_Focus_Tune.ini") { Copy-Item "publish_payload\IDC_Focus_Tune.ini" "$progDataDir\" -Force }
if (Test-Path "publish_payload\IDC_Image_Process.dll") { Copy-Item "publish_payload\IDC_Image_Process.dll" "$progDataDir\" -Force }
Write-Host "Da dong bo toan bo du lieu cam bien ProgramData\ID_Capture" -ForegroundColor Green

Write-Host "=== 7. Cap nhat cac Shortcut tren Desktop sang Icon moi ===" -ForegroundColor Cyan
$sh = New-Object -ComObject WScript.Shell
$userLnk = "C:\Users\ITPC\Desktop\Passport Scanner (ID-Capture).lnk"
$publicLnk = "C:\Users\Public\Desktop\Passport Scanner (ID-Capture).lnk"

# Xoa shortcut duplicate o User Desktop neu da ton tai o Public Desktop
if ((Test-Path $userLnk) -and (Test-Path $publicLnk)) {
    Remove-Item $userLnk -Force -ErrorAction SilentlyContinue
    Write-Host "Da xoa shortcut trung lap tai $userLnk" -ForegroundColor Yellow
}

$targetLnk = if (Test-Path $publicLnk) { $publicLnk } else { $userLnk }
if (Test-Path $targetLnk) {
    try {
        $lnk = $sh.CreateShortcut($targetLnk)
        $lnk.IconLocation = "$progFilesDir\app.ico,0"
        $lnk.Save()
        Write-Host "Da cap nhat Icon cho $targetLnk" -ForegroundColor Green
    } catch { }
}

Write-Host "=== 8. Don dep tap tin trung gian ===" -ForegroundColor Cyan
Remove-Item "publish_payload" -Recurse -Force
Remove-Item "app_payload.zip" -Force

Write-Host "=== 9. Lam moi Icon cache cua Windows Explorer ===" -ForegroundColor Cyan
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class ShellIconHelper {
    [DllImport("shell32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern void SHChangeNotify(int wEventId, int uFlags, IntPtr dwItem1, IntPtr dwItem2);
    public static void Refresh() {
        SHChangeNotify(0x08000000, 0x0000, IntPtr.Zero, IntPtr.Zero);
    }
}
"@ -ErrorAction SilentlyContinue
try {
    [ShellIconHelper]::Refresh()
} catch { }

# Thuc hien khoi dong lai nhe Icon Cache
try {
    & ie4uinit.exe -show
} catch { }

$setupItem = Get-Item "C:\Users\ITPC\Desktop\Setup_PassportScanner_ID_Capture.exe"
Write-Host "HOAN TAT DONG GOI! Kich thuoc bo cai dat: $([math]::Round($setupItem.Length / 1MB, 2)) MB" -ForegroundColor Green
